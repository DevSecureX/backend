"""
CLI Scan Services - Business logic for enterprise-grade CLI functionality
"""

import logging
import uuid
import json
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, update, delete, and_, func, desc, asc
from sqlalchemy.orm import selectinload

from cli_scan.models import CLIScanResult, CLIActivityLog, CLIUsageStats, ScanStatus, ActivityType
from auth.models import User
from core.cache import cache

logger = logging.getLogger(__name__)


class CLIScanResultService:
    """Service for managing CLI scan results with enterprise features"""

    @staticmethod
    async def store_scan_result(
        scan_id: str,
        user_id: int,
        scan_metadata: Dict[str, Any],
        results_data: Dict[str, Any],
        db: AsyncSession
    ) -> CLIScanResult:
        """Store comprehensive CLI scan results in database"""
        
        try:
            # Extract key metrics from results
            issues = results_data.get('issues', [])
            scores = results_data.get('scores', {})
            
            # Calculate issue counts by severity
            issue_counts = {
                'critical': len([i for i in issues if i.get('severity') == 'critical']),
                'high': len([i for i in issues if i.get('severity') == 'high']),
                'medium': len([i for i in issues if i.get('severity') == 'medium']),
                'low': len([i for i in issues if i.get('severity') == 'low']),
                'info': len([i for i in issues if i.get('severity') == 'info'])
            }
            
            # Extract tools used and languages detected
            tools_used = scan_metadata.get('tools_used', [])
            languages_detected = results_data.get('statistics', {}).get('languages_detected', [])
            
            # Store scan result - Ensure proper enum value handling
            scan_result = CLIScanResult(
                scan_id=scan_id,
                user_id=user_id,
                scan_metadata=scan_metadata,
                results_data=results_data,
                file_count=results_data.get('statistics', {}).get('files_scanned', 0),
                total_score=scores.get('total_score', 0.0),
                issue_counts=issue_counts,
                total_issues=len(issues),
                tools_used=tools_used,
                scan_duration=results_data.get('statistics', {}).get('scan_duration_seconds', 0.0),
                status=ScanStatus.COMPLETED,  # Use enum properly to ensure correct value handling
                compliance_data=results_data.get('compliance_mapping'),
                risk_assessment=results_data.get('risk_assessment'),
                languages_detected=languages_detected,
                dependency_files_count=results_data.get('statistics', {}).get('dependency_files_found', 0)
            )
            
            db.add(scan_result)
            await db.commit()
            await db.refresh(scan_result)
            
            logger.info(f"Stored CLI scan result: {scan_id} for user {user_id}")
            
            # Update usage statistics asynchronously
            await CLIUsageStatsService.update_user_stats(user_id, db)
            
            return scan_result
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error storing CLI scan result {scan_id}: {str(e)}")
            raise

    @staticmethod
    async def get_scan_result(
        scan_id: str, 
        user_id: int,
        db: AsyncSession
    ) -> Optional[CLIScanResult]:
        """Retrieve CLI scan result by ID with user validation"""
        
        try:
            result = await db.execute(
                select(CLIScanResult).where(
                    and_(
                        CLIScanResult.scan_id == scan_id,
                        CLIScanResult.user_id == user_id
                    )
                ).options(selectinload(CLIScanResult.user))
            )
            
            scan_result = result.scalar_one_or_none()
            
            if scan_result:
                # Log result retrieval activity
                await CLIActivityService.log_activity(
                    user_id=user_id,
                    scan_id=scan_id,
                    activity_type=ActivityType.RESULTS_RETRIEVED,
                    endpoint="/cli-scan/results",
                    response_status="success",
                    db=db
                )
                
                logger.info(f"Retrieved CLI scan result: {scan_id} for user {user_id}")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error retrieving CLI scan result {scan_id}: {str(e)}")
            raise

    @staticmethod
    async def get_user_scan_results(
        user_id: int,
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        status_filter: Optional[str] = None
    ) -> Tuple[List[CLIScanResult], int]:
        """Get paginated scan results for a user with filtering"""
        
        try:
            query = select(CLIScanResult).where(CLIScanResult.user_id == user_id)
            
            if status_filter:
                # Convert string status filter to enum if needed
                if isinstance(status_filter, str):
                    try:
                        status_enum = ScanStatus(status_filter)
                        query = query.where(CLIScanResult.status == status_enum)
                    except ValueError:
                        # Invalid status filter, ignore it
                        pass
                else:
                    # If it's already an enum, use it directly
                    query = query.where(CLIScanResult.status == status_filter)
            
            # Get total count
            count_result = await db.execute(
                select(func.count(CLIScanResult.id)).where(
                    CLIScanResult.user_id == user_id
                )
            )
            total_count = count_result.scalar()
            
            # Get paginated results
            query = query.order_by(desc(CLIScanResult.created_at)).limit(limit).offset(offset)
            result = await db.execute(query)
            scan_results = result.scalars().all()
            
            logger.info(f"Retrieved {len(scan_results)} CLI scan results for user {user_id}")
            return scan_results, total_count
            
        except Exception as e:
            logger.error(f"Error retrieving user scan results: {str(e)}")
            raise

    @staticmethod
    async def update_scan_status(
        scan_id: str,
        user_id: int,
        status: ScanStatus,
        db: AsyncSession,
        error_message: Optional[str] = None
    ) -> bool:
        """Update scan status and error message with user validation"""
        
        try:
            result = await db.execute(
                update(CLIScanResult)
                .where(and_(
                    CLIScanResult.scan_id == scan_id,
                    CLIScanResult.user_id == user_id
                ))
                .values(
                    status=status,  # Use enum directly since column is now Enum type
                    error_message=error_message,
                    updated_at=datetime.now(timezone.utc)
                )
            )
            await db.commit()
            
            # Check if any rows were actually updated
            if result.rowcount > 0:
                logger.info(f"Updated scan {scan_id} status to {status} for user {user_id}")
                return True
            else:
                logger.warning(f"No scan found with ID {scan_id} for user {user_id}")
                return False
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error updating scan status: {str(e)}")
            return False


class CLIActivityService:
    """Service for managing CLI activity logging"""

    @staticmethod
    async def log_activity(
        user_id: int,
        activity_type: ActivityType,
        db: AsyncSession,
        scan_id: Optional[str] = None,
        command: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
        endpoint: Optional[str] = None,
        response_status: Optional[str] = None,
        http_status_code: Optional[int] = None,
        duration: Optional[float] = None,
        error_details: Optional[Dict[str, Any]] = None,
        error_type: Optional[str] = None,
        client_info: Optional[Dict[str, Any]] = None
    ) -> CLIActivityLog:
        """Log comprehensive CLI activity for analytics and monitoring"""
        
        try:
            # Handle scan_id foreign key constraint - set to None if scan doesn't exist
            validated_scan_id = None
            if scan_id:
                # Check if scan exists in database
                try:
                    result = await db.execute(
                        select(CLIScanResult.scan_id).where(CLIScanResult.scan_id == scan_id)
                    )
                    if result.scalar_one_or_none():
                        validated_scan_id = scan_id
                    else:
                        logger.warning(f"Scan ID {scan_id} not found, setting to None for activity log")
                except:
                    # If we can't check, set to None to avoid foreign key errors
                    logger.warning(f"Could not validate scan ID {scan_id}, setting to None")
            
            activity_log = CLIActivityLog(
                user_id=user_id,
                scan_id=validated_scan_id,  # Use validated scan_id
                activity_type=activity_type,
                command=command,
                parameters=parameters,
                endpoint=endpoint,
                response_status=response_status,
                http_status_code=http_status_code,
                duration=duration,
                error_details=error_details,
                error_type=error_type,
                client_info=client_info
            )
            
            db.add(activity_log)
            await db.commit()
            await db.refresh(activity_log)
            
            logger.debug(f"Logged CLI activity: {activity_type} for user {user_id}")
            return activity_log
            
        except Exception as e:
            await db.rollback()
            error_msg = str(e)
            logger.error(f"Error logging CLI activity: {error_msg}")
            
            # Check for common database constraint violations
            if "value too long for type" in error_msg:
                # This is a data validation error that should be reported
                raise ValueError(f"Activity data exceeds field length limits: {error_msg}")
            elif "violates check constraint" in error_msg:
                # This is a constraint violation that should be reported
                raise ValueError(f"Activity data violates database constraints: {error_msg}")
            elif "violates foreign key constraint" in error_msg:
                # Foreign key constraint violations should be handled gracefully
                logger.warning(f"Foreign key constraint in activity logging: {error_msg}")
                return None
            else:
                # Other database errors should not fail CLI operations
                logger.error(f"Unexpected database error in activity logging: {error_msg}")
                return None

    @staticmethod
    async def get_user_activity_logs(
        user_id: int,
        db: AsyncSession,
        limit: int = 100,
        offset: int = 0,
        activity_type_filter: Optional[str] = None,
        days: int = 30
    ) -> Tuple[List[CLIActivityLog], int]:
        """Get paginated user activity logs with filtering"""
        
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            query = select(CLIActivityLog).where(
                and_(
                    CLIActivityLog.user_id == user_id,
                    CLIActivityLog.created_at >= cutoff_date
                )
            )
            
            if activity_type_filter:
                query = query.where(CLIActivityLog.activity_type == activity_type_filter)
            
            # Get total count
            count_result = await db.execute(
                select(func.count(CLIActivityLog.id)).where(
                    and_(
                        CLIActivityLog.user_id == user_id,
                        CLIActivityLog.created_at >= cutoff_date
                    )
                )
            )
            total_count = count_result.scalar()
            
            # Get paginated results
            query = query.order_by(desc(CLIActivityLog.created_at)).limit(limit).offset(offset)
            result = await db.execute(query)
            activity_logs = result.scalars().all()
            
            return activity_logs, total_count
            
        except Exception as e:
            logger.error(f"Error retrieving user activity logs: {str(e)}")
            raise


class CLIUsageStatsService:
    """Service for managing CLI usage statistics and analytics"""

    @staticmethod
    async def get_user_usage_stats(
        user_id: int,
        db: AsyncSession,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get comprehensive CLI usage statistics for a user"""
        
        try:
            # Try to get cached stats first
            cache_key = f"cli_usage_stats:{user_id}:{days}"
            cached_stats = await cache.get(cache_key)
            if cached_stats:
                logger.debug(f"Retrieved cached CLI usage stats for user {user_id}")
                return cached_stats
            
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Get aggregated statistics from database
            stats_result = await db.execute(
                select(
                    func.count(CLIScanResult.id).label('total_scans'),
                    func.count(CLIScanResult.id).filter(CLIScanResult.status == ScanStatus.COMPLETED).label('successful_scans'),
                    func.count(CLIScanResult.id).filter(CLIScanResult.status == ScanStatus.FAILED).label('failed_scans'),
                    func.count(CLIScanResult.id).filter(CLIScanResult.status == ScanStatus.TIMEOUT).label('timeout_scans'),
                    func.coalesce(func.sum(CLIScanResult.total_issues), 0).label('total_issues'),
                    func.coalesce(func.sum(CLIScanResult.scan_duration), 0.0).label('total_duration'),
                    func.coalesce(func.avg(CLIScanResult.scan_duration), 0.0).label('avg_duration'),
                    func.coalesce(func.sum(CLIScanResult.file_count), 0).label('total_files'),
                    func.coalesce(func.avg(CLIScanResult.file_count), 0.0).label('avg_files_per_scan'),
                    func.coalesce(func.avg(CLIScanResult.total_score), 0.0).label('avg_total_score')
                ).where(
                    and_(
                        CLIScanResult.user_id == user_id,
                        CLIScanResult.created_at >= cutoff_date
                    )
                )
            )
            
            stats = stats_result.first()
            
            # Calculate success rate
            success_rate = 0.0
            if stats.total_scans > 0:
                success_rate = (stats.successful_scans / stats.total_scans) * 100
            
            # Get issue severity breakdown
            issue_breakdown = await db.execute(
                select(
                    func.coalesce(func.sum((CLIScanResult.issue_counts['critical']).astext.cast(func.INTEGER)), 0).label('critical'),
                    func.coalesce(func.sum((CLIScanResult.issue_counts['high']).astext.cast(func.INTEGER)), 0).label('high'),
                    func.coalesce(func.sum((CLIScanResult.issue_counts['medium']).astext.cast(func.INTEGER)), 0).label('medium'),
                    func.coalesce(func.sum((CLIScanResult.issue_counts['low']).astext.cast(func.INTEGER)), 0).label('low'),
                    func.coalesce(func.sum((CLIScanResult.issue_counts['info']).astext.cast(func.INTEGER)), 0).label('info')
                ).where(
                    and_(
                        CLIScanResult.user_id == user_id,
                        CLIScanResult.created_at >= cutoff_date
                    )
                )
            )
            
            issue_stats = issue_breakdown.first()
            
            # Get most used tools and languages
            tools_stats = {}
            languages_stats = {}
            
            # Aggregate tools and languages from recent scans
            recent_scans = await db.execute(
                select(CLIScanResult.tools_used, CLIScanResult.languages_detected)
                .where(
                    and_(
                        CLIScanResult.user_id == user_id,
                        CLIScanResult.created_at >= cutoff_date
                    )
                )
            )
            
            for scan in recent_scans:
                # Count tools
                for tool in scan.tools_used or []:
                    tools_stats[tool] = tools_stats.get(tool, 0) + 1
                
                # Count languages
                for lang in scan.languages_detected or []:
                    languages_stats[lang] = languages_stats.get(lang, 0) + 1
            
            # Compile comprehensive statistics
            usage_stats = {
                'period_days': days,
                'total_scans': int(stats.total_scans or 0),
                'successful_scans': int(stats.successful_scans or 0),
                'failed_scans': int(stats.failed_scans or 0),
                'timeout_scans': int(stats.timeout_scans or 0),
                'success_rate': round(success_rate, 2),
                'total_issues_found': int(stats.total_issues or 0),
                'avg_issues_per_scan': round((stats.total_issues or 0) / max(stats.total_scans or 1, 1), 2),
                'total_scan_duration_seconds': round(stats.total_duration or 0.0, 2),
                'avg_scan_duration_seconds': round(stats.avg_duration or 0.0, 2),
                'total_files_scanned': int(stats.total_files or 0),
                'avg_files_per_scan': round(stats.avg_files_per_scan or 0.0, 2),
                'avg_total_score': round(stats.avg_total_score or 0.0, 2),
                'issue_severity_breakdown': {
                    'critical': int(issue_stats.critical or 0),
                    'high': int(issue_stats.high or 0),
                    'medium': int(issue_stats.medium or 0),
                    'low': int(issue_stats.low or 0),
                    'info': int(issue_stats.info or 0)
                },
                'most_used_tools': dict(sorted(tools_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
                'languages_detected': dict(sorted(languages_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
            
            # Cache the results for 5 minutes
            await cache.set(cache_key, usage_stats, ttl=300)
            
            logger.info(f"Generated CLI usage stats for user {user_id}: {stats.total_scans} scans in {days} days")
            return usage_stats
            
        except Exception as e:
            logger.error(f"Error getting CLI usage stats for user {user_id}: {str(e)}")
            # Return empty stats structure on error
            return {
                'period_days': days,
                'total_scans': 0,
                'successful_scans': 0,
                'failed_scans': 0,
                'timeout_scans': 0,
                'success_rate': 0.0,
                'total_issues_found': 0,
                'avg_issues_per_scan': 0.0,
                'total_scan_duration_seconds': 0.0,
                'avg_scan_duration_seconds': 0.0,
                'total_files_scanned': 0,
                'avg_files_per_scan': 0.0,
                'avg_total_score': 0.0,
                'issue_severity_breakdown': {
                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
                },
                'most_used_tools': {},
                'languages_detected': {},
                'error': 'Failed to retrieve statistics',
                'generated_at': datetime.now(timezone.utc).isoformat()
            }

    @staticmethod
    async def update_user_stats(user_id: int, db: AsyncSession) -> None:
        """Update daily usage statistics for a user (called after scan completion)"""
        
        try:
            today = datetime.now(timezone.utc).date()
            
            # Call the PostgreSQL function to calculate and update stats
            await db.execute(
                func.calculate_cli_usage_stats(user_id, today)
            )
            await db.commit()
            
            # Clear cached stats
            cache_keys = [
                f"cli_usage_stats:{user_id}:7",
                f"cli_usage_stats:{user_id}:30",
                f"cli_usage_stats:{user_id}:90"
            ]
            for cache_key in cache_keys:
                await cache.delete(cache_key)
            
            logger.debug(f"Updated CLI usage stats for user {user_id}")
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error updating CLI usage stats for user {user_id}: {str(e)}")

    @staticmethod
    async def get_user_trends(
        user_id: int,
        db: AsyncSession,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get user trends and analytics over time"""
        
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
            
            # Get daily scan counts and scores
            daily_stats = await db.execute(
                select(
                    func.date(CLIScanResult.created_at).label('date'),
                    func.count(CLIScanResult.id).label('scan_count'),
                    func.coalesce(func.avg(CLIScanResult.total_score), 0.0).label('avg_score'),
                    func.coalesce(func.sum(CLIScanResult.total_issues), 0).label('total_issues')
                ).where(
                    and_(
                        CLIScanResult.user_id == user_id,
                        CLIScanResult.created_at >= cutoff_date
                    )
                ).group_by(func.date(CLIScanResult.created_at))
                .order_by(func.date(CLIScanResult.created_at))
            )
            
            trends = {
                'daily_scans': [],
                'daily_scores': [],
                'daily_issues': [],
                'scan_frequency_trend': 'stable',
                'score_trend': 'stable',
                'issue_trend': 'stable'
            }
            
            daily_data = daily_stats.all()
            
            for row in daily_data:
                trends['daily_scans'].append({
                    'date': row.date.isoformat(),
                    'count': int(row.scan_count)
                })
                trends['daily_scores'].append({
                    'date': row.date.isoformat(),
                    'score': round(float(row.avg_score), 2)
                })
                trends['daily_issues'].append({
                    'date': row.date.isoformat(),
                    'issues': int(row.total_issues)
                })
            
            # Calculate trends (basic linear regression could be added here)
            if len(daily_data) >= 2:
                first_half_scans = sum(row.scan_count for row in daily_data[:len(daily_data)//2])
                second_half_scans = sum(row.scan_count for row in daily_data[len(daily_data)//2:])
                
                if second_half_scans > first_half_scans * 1.1:
                    trends['scan_frequency_trend'] = 'increasing'
                elif second_half_scans < first_half_scans * 0.9:
                    trends['scan_frequency_trend'] = 'decreasing'
            
            return trends
            
        except Exception as e:
            logger.error(f"Error getting CLI trends for user {user_id}: {str(e)}")
            return {
                'daily_scans': [],
                'daily_scores': [],
                'daily_issues': [],
                'scan_frequency_trend': 'unknown',
                'score_trend': 'unknown',
                'issue_trend': 'unknown',
                'error': 'Failed to retrieve trends'
            }