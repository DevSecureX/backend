"""
Issue Tracking Service for DevSecureX

This service handles the lifecycle of security issues across scans,
tracking when they are detected, resolved, or marked as false positives.
It provides accurate metrics for resolved issues and integrates with
the AI auto-fix system.
"""

import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.orm import selectinload

from scans.models import IssueStatusTracking, AutoFixResults, Scan
from core.database import get_db

logger = logging.getLogger(__name__)

class IssueTrackingService:
    """Service for tracking security issues across scan lifecycle."""
    
    @staticmethod
    def generate_issue_hash(
        file_path: str, 
        line_number: int, 
        rule_id: str, 
        description: str,
        repo_full_name: str
    ) -> str:
        """
        Generate a consistent hash for an issue to track it across scans.
        
        Args:
            file_path: Path to the file containing the issue
            line_number: Line number where the issue occurs
            rule_id: Security rule that detected the issue
            description: Issue description/message
            repo_full_name: Repository full name for context
            
        Returns:
            64-character SHA256 hash string
        """
        # Normalize file path (remove leading slashes, standardize separators)
        normalized_path = file_path.lstrip('./').replace('\\', '/')
        
        # Create a composite string for hashing
        composite = f"{repo_full_name}:{normalized_path}:{line_number}:{rule_id}:{description}"
        
        # Generate SHA256 hash
        return hashlib.sha256(composite.encode('utf-8')).hexdigest()

    async def track_scan_issues(
        self, 
        session: AsyncSession,
        scan_id: str, 
        issues: List[Dict[str, Any]], 
        repo_full_name: str
    ) -> Dict[str, int]:
        """
        Process issues from a new scan and update tracking status.
        
        Args:
            session: Database session
            scan_id: ID of the current scan
            issues: List of detected issues
            repo_full_name: Repository full name
            
        Returns:
            Dictionary with counts of new, updated, and resolved issues
        """
        try:
            stats = {"new_issues": 0, "updated_issues": 0, "resolved_issues": 0}
            current_issue_hashes = set()
            
            # Process current scan issues
            for issue in issues:
                # Use consistent field names - check both possible field names
                file_path = issue.get('file_path') or issue.get('file', '')
                line_number = issue.get('line_start') or issue.get('line', 0)
                
                issue_hash = self.generate_issue_hash(
                    file_path=file_path,
                    line_number=line_number,
                    rule_id=issue.get('rule_id', ''),
                    description=issue.get('message', ''),
                    repo_full_name=repo_full_name
                )
                current_issue_hashes.add(issue_hash)
                
                # Check if issue already exists
                existing_issue = await session.execute(
                    select(IssueStatusTracking).where(
                        IssueStatusTracking.issue_hash == issue_hash
                    )
                )
                existing_issue = existing_issue.scalar_one_or_none()
                
                if existing_issue:
                    # Update existing issue - it's still present
                    if existing_issue.status in ['fixed_auto', 'fixed_manual', 'fixed_dependency']:
                        # Issue has regressed - reopen it
                        existing_issue.status = 'open'
                        existing_issue.fixed_at = None
                        existing_issue.fixed_by = None
                        existing_issue.fixed_in_pr_number = None
                        existing_issue.resolution_method = None
                        logger.info(f"Issue regressed: {issue_hash}")
                    
                    existing_issue.last_seen_scan_id = scan_id
                    existing_issue.updated_at = datetime.now(timezone.utc)
                    stats["updated_issues"] += 1
                    
                else:
                    # Create new issue tracking record with proper truncation
                    # Truncate issue_type to fit database column constraint (100 chars max)
                    rule_id = issue.get('rule_id', 'unknown')
                    issue_type = rule_id[:100] if len(rule_id) > 100 else rule_id
                    
                    # Truncate description to fit VARCHAR(100) constraint
                    description = issue.get('message', '')
                    if len(description) > 97:  # Leave room for "..."
                        description = description[:97] + "..."
                    
                    new_issue = IssueStatusTracking(
                        issue_hash=issue_hash,
                        repo_full_name=repo_full_name,
                        first_detected_scan_id=scan_id,
                        last_seen_scan_id=scan_id,
                        status='open',
                        issue_type=issue_type,
                        severity=issue.get('severity', 'medium').lower(),
                        file_path=file_path,
                        line_number=line_number,
                        description=description
                    )
                    session.add(new_issue)
                    stats["new_issues"] += 1
            
            # Find issues that are no longer present (potentially resolved)
            resolved_count = await self._detect_resolved_issues(
                session, repo_full_name, current_issue_hashes, scan_id
            )
            stats["resolved_issues"] = resolved_count
            
            await session.commit()
            logger.info(f"Issue tracking updated for {repo_full_name}: {stats}")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error tracking issues for scan {scan_id}: {str(e)}")
            await session.rollback()
            raise

    async def _detect_resolved_issues(
        self, 
        session: AsyncSession,
        repo_full_name: str, 
        current_issue_hashes: set, 
        scan_id: str
    ) -> int:
        """
        Detect issues that are no longer present in the current scan.
        
        Args:
            session: Database session
            repo_full_name: Repository full name
            current_issue_hashes: Set of issue hashes found in current scan
            scan_id: Current scan ID
            
        Returns:
            Number of issues marked as resolved
        """
        # Find open issues for this repo that are not in current scan
        open_issues = await session.execute(
            select(IssueStatusTracking).where(
                and_(
                    IssueStatusTracking.repo_full_name == repo_full_name,
                    IssueStatusTracking.status == 'open',
                    ~IssueStatusTracking.issue_hash.in_(current_issue_hashes)
                )
            )
        )
        open_issues = open_issues.scalars().all()
        
        resolved_count = 0
        for issue in open_issues:
            # Mark as manually fixed (since it disappeared without auto-fix)
            issue.status = 'fixed_manual'
            issue.resolution_method = 'manual_fix'
            issue.fixed_at = datetime.now(timezone.utc)
            issue.fixed_by = 'unknown'  # Manual resolution, unknown user
            issue.updated_at = datetime.now(timezone.utc)
            resolved_count += 1
            
        return resolved_count

    async def mark_issue_fixed_by_autofix(
        self, 
        session: AsyncSession,
        issue_hash: str, 
        pr_number: int, 
        repo_full_name: str,
        fix_content: str = None,
        confidence_score: float = None
    ) -> bool:
        """
        Mark an issue as fixed by AI auto-fix and record the fix details.
        
        Args:
            session: Database session
            issue_hash: Hash of the resolved issue
            pr_number: PR number where the fix was applied
            repo_full_name: Repository full name
            fix_content: The actual code fix applied
            confidence_score: AI confidence in the fix
            
        Returns:
            True if issue was marked as fixed, False if issue not found
        """
        try:
            # Find the issue
            issue = await session.execute(
                select(IssueStatusTracking).where(
                    and_(
                        IssueStatusTracking.issue_hash == issue_hash,
                        IssueStatusTracking.repo_full_name == repo_full_name
                    )
                )
            )
            issue = issue.scalar_one_or_none()
            
            if not issue:
                logger.warning(f"Issue not found for auto-fix: {issue_hash}")
                return False
            
            # Update issue status
            issue.status = 'fixed_auto'
            issue.resolution_method = 'ai_autofix'
            issue.fixed_at = datetime.now(timezone.utc)
            issue.fixed_by = 'ai_autofix'
            issue.fixed_in_pr_number = pr_number
            issue.updated_at = datetime.now(timezone.utc)
            
            # Create auto-fix result record
            autofix_result = AutoFixResults(
                issue_hash=issue_hash,
                pr_number=pr_number,
                repo_full_name=repo_full_name,
                fix_applied=True,
                fix_content=fix_content,
                ai_confidence_score=confidence_score
            )
            session.add(autofix_result)
            
            await session.commit()
            logger.info(f"Issue marked as auto-fixed: {issue_hash} in PR #{pr_number}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error marking issue as auto-fixed: {str(e)}")
            await session.rollback()
            raise

    async def verify_autofix_with_scan(
        self, 
        session: AsyncSession,
        verification_scan_id: str, 
        repo_full_name: str
    ) -> int:
        """
        Update auto-fix results with verification scan data.
        
        Args:
            session: Database session
            verification_scan_id: ID of the scan that verified the fixes
            repo_full_name: Repository full name
            
        Returns:
            Number of auto-fixes verified
        """
        try:
            # Find auto-fix results without verification
            unverified_fixes = await session.execute(
                select(AutoFixResults).where(
                    and_(
                        AutoFixResults.repo_full_name == repo_full_name,
                        AutoFixResults.verification_scan_id.is_(None)
                    )
                )
            )
            unverified_fixes = unverified_fixes.scalars().all()
            
            verified_count = 0
            for fix_result in unverified_fixes:
                fix_result.verification_scan_id = verification_scan_id
                verified_count += 1
            
            await session.commit()
            logger.info(f"Verified {verified_count} auto-fixes with scan {verification_scan_id}")
            
            return verified_count
            
        except Exception as e:
            logger.error(f"Error verifying auto-fixes: {str(e)}")
            await session.rollback()
            raise

    async def get_fixed_issues_count(
        self, 
        session: AsyncSession,
        repo_full_name: str = None,
        start_date: datetime = None,
        end_date: datetime = None,
        resolution_method: str = None
    ) -> int:
        """
        Get count of resolved issues with optional filters.
        
        Args:
            session: Database session
            repo_full_name: Optional repository filter
            start_date: Optional start date filter
            end_date: Optional end date filter
            resolution_method: Optional resolution method filter
            
        Returns:
            Count of resolved issues matching filters
        """
        try:
            query = select(func.count(IssueStatusTracking.id)).where(
                IssueStatusTracking.status.in_(['fixed_auto', 'fixed_manual', 'fixed_dependency'])
            )
            
            if repo_full_name:
                query = query.where(IssueStatusTracking.repo_full_name == repo_full_name)
            
            if start_date:
                query = query.where(IssueStatusTracking.fixed_at >= start_date)
            
            if end_date:
                query = query.where(IssueStatusTracking.fixed_at <= end_date)
            
            if resolution_method:
                query = query.where(IssueStatusTracking.resolution_method == resolution_method)
            
            result = await session.execute(query)
            return result.scalar() or 0
            
        except Exception as e:
            logger.error(f"Error getting fixed issues count: {str(e)}")
            raise

    async def get_issue_resolution_stats(
        self, 
        session: AsyncSession,
        repo_full_name: str = None,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get comprehensive issue resolution statistics.
        
        Args:
            session: Database session
            repo_full_name: Optional repository filter
            days: Number of days to look back
            
        Returns:
            Dictionary with resolution statistics
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            base_query = select(IssueStatusTracking)
            if repo_full_name:
                base_query = base_query.where(IssueStatusTracking.repo_full_name == repo_full_name)
            
            # Get overall stats
            total_query = base_query.with_only_columns(
                func.count(IssueStatusTracking.id).label('total'),
                func.count(IssueStatusTracking.id).filter(
                    IssueStatusTracking.status == 'open'
                ).label('open'),
                func.count(IssueStatusTracking.id).filter(
                    IssueStatusTracking.status.in_(['fixed_auto', 'fixed_manual', 'fixed_dependency'])
                ).label('resolved'),
                func.count(IssueStatusTracking.id).filter(
                    IssueStatusTracking.status == 'false_positive'
                ).label('false_positives')
            )
            
            total_stats = await session.execute(total_query)
            total_stats = total_stats.fetchone()
            
            # Get resolution method breakdown
            resolution_query = base_query.where(
                and_(
                    IssueStatusTracking.fixed_at >= cutoff_date,
                    IssueStatusTracking.status.in_(['fixed_auto', 'fixed_manual', 'fixed_dependency'])
                )
            ).with_only_columns(
                IssueStatusTracking.resolution_method,
                func.count(IssueStatusTracking.id).label('count')
            ).group_by(IssueStatusTracking.resolution_method)
            
            resolution_stats = await session.execute(resolution_query)
            resolution_breakdown = {row.resolution_method: row.count for row in resolution_stats}
            
            # Get severity breakdown for resolved issues
            severity_query = base_query.where(
                and_(
                    IssueStatusTracking.fixed_at >= cutoff_date,
                    IssueStatusTracking.status.in_(['fixed_auto', 'fixed_manual', 'fixed_dependency'])
                )
            ).with_only_columns(
                IssueStatusTracking.severity,
                func.count(IssueStatusTracking.id).label('count')
            ).group_by(IssueStatusTracking.severity)
            
            severity_stats = await session.execute(severity_query)
            severity_breakdown = {row.severity: row.count for row in severity_stats}
            
            # Calculate resolution rate
            resolution_rate = 0.0
            if total_stats.total > 0:
                resolution_rate = (total_stats.resolved / total_stats.total) * 100
            
            return {
                "total_issues": total_stats.total or 0,
                "open_issues": total_stats.open or 0,
                "resolved_issues": total_stats.resolved or 0,
                "false_positives": total_stats.false_positives or 0,
                "resolution_rate_percent": round(resolution_rate, 2),
                "resolution_methods": resolution_breakdown,
                "resolved_by_severity": severity_breakdown,
                "period_days": days,
                "repository": repo_full_name or "all"
            }
            
        except Exception as e:
            logger.error(f"Error getting resolution stats: {str(e)}")
            raise

    async def update_issue_status(
        self, 
        session: AsyncSession,
        issue_hash: str, 
        new_status: str, 
        user_id: str = None,
        reason: str = None
    ) -> bool:
        """
        Manually update an issue's status.
        
        Args:
            session: Database session
            issue_hash: Hash of the issue to update
            new_status: New status (open, fixed_manual, false_positive)
            user_id: User making the change
            reason: Reason for the status change
            
        Returns:
            True if update was successful, False if issue not found
        """
        try:
            issue = await session.execute(
                select(IssueStatusTracking).where(
                    IssueStatusTracking.issue_hash == issue_hash
                )
            )
            issue = issue.scalar_one_or_none()
            
            if not issue:
                return False
            
            # Update status
            old_status = issue.status
            issue.status = new_status
            issue.updated_at = datetime.now(timezone.utc)
            
            # Handle specific status changes
            if new_status == 'false_positive':
                issue.resolution_method = 'false_positive'
                issue.fixed_at = datetime.now(timezone.utc)
                issue.fixed_by = user_id or 'manual'
            elif new_status in ['fixed_manual', 'fixed_dependency']:
                if old_status == 'open':
                    issue.resolution_method = 'manual_fix' if new_status == 'fixed_manual' else 'dependency_update'
                    issue.fixed_at = datetime.now(timezone.utc)
                    issue.fixed_by = user_id or 'manual'
            elif new_status == 'open':
                # Reopening issue
                issue.resolution_method = None
                issue.fixed_at = None
                issue.fixed_by = None
                issue.fixed_in_pr_number = None
            
            await session.commit()
            logger.info(f"Issue status updated: {issue_hash} from {old_status} to {new_status}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating issue status: {str(e)}")
            await session.rollback()
            raise

    async def get_issues_for_repository(
        self, 
        session: AsyncSession,
        repo_full_name: str, 
        status: str = None,
        severity: str = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get paginated list of issues for a repository.
        
        Args:
            session: Database session
            repo_full_name: Repository full name
            status: Optional status filter
            severity: Optional severity filter
            limit: Maximum number of issues to return
            offset: Number of issues to skip
            
        Returns:
            List of issue dictionaries
        """
        try:
            query = select(IssueStatusTracking).where(
                IssueStatusTracking.repo_full_name == repo_full_name
            )
            
            if status:
                query = query.where(IssueStatusTracking.status == status)
            
            if severity:
                query = query.where(IssueStatusTracking.severity == severity)
            
            query = query.order_by(IssueStatusTracking.created_at.desc()).limit(limit).offset(offset)
            
            result = await session.execute(query)
            issues = result.scalars().all()
            
            return [
                {
                    "issue_hash": issue.issue_hash,
                    "repo_full_name": issue.repo_full_name,
                    "status": issue.status,
                    "issue_type": issue.issue_type,
                    "severity": issue.severity,
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "description": issue.description,
                    "resolution_method": issue.resolution_method,
                    "fixed_at": issue.fixed_at.isoformat() if issue.fixed_at else None,
                    "fixed_by": issue.fixed_by,
                    "fixed_in_pr_number": issue.fixed_in_pr_number,
                    "created_at": issue.created_at.isoformat(),
                    "updated_at": issue.updated_at.isoformat()
                }
                for issue in issues
            ]
            
        except Exception as e:
            logger.error(f"Error getting issues for repository: {str(e)}")
            raise