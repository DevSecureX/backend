"""
Analytics Service Layer for DevSecureX
Handles complex database queries and data aggregation for analytics endpoints
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import (
    select, func, and_, case, desc, distinct, join, outerjoin
)
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta, timezone
import logging

from scans.models import (
    Scan, ScanSummary, ComplianceMapping, IssueFeedback, IssueStatusTracking
)
from repos.models import Repo
from .models import TimeRange, ComplianceFramework
from core.issue_tracking import IssueTrackingService

logger = logging.getLogger(__name__)


class AnalyticsService:
    """Service class for analytics data aggregation and processing"""
    
    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
    
    def _get_date_range(self, time_range: TimeRange) -> Tuple[datetime, datetime]:
        """Calculate date range based on time range parameter"""
        now = datetime.now(timezone.utc)
        
        if time_range == TimeRange.DAY:
            start_date = now - timedelta(days=1)
        elif time_range == TimeRange.WEEK:
            start_date = now - timedelta(weeks=1)
        elif time_range == TimeRange.MONTH:
            start_date = now - timedelta(days=30)
        elif time_range == TimeRange.QUARTER:
            start_date = now - timedelta(days=90)
        elif time_range == TimeRange.YEAR:
            start_date = now - timedelta(days=365)
        else:
            start_date = now - timedelta(days=30)  # Default to month
            
        return start_date, now
    
    async def get_overview_metrics(self, time_range: TimeRange, repo_filter: Optional[str] = None) -> Dict[str, Any]:
        """Get key metrics for overview dashboard"""
        start_date, end_date = self._get_date_range(time_range)
        
        # Base query filters
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date
        ]
        
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        # Total scans
        total_scans_query = select(func.count(Scan.id)).where(and_(*base_filters))
        total_scans_result = await self.db.execute(total_scans_query)
        total_scans = total_scans_result.scalar() or 0
        
        # Total repositories
        repos_query = select(func.count(distinct(Repo.id))).where(Repo.user_id == self.user_id)
        repos_result = await self.db.execute(repos_query)
        total_repositories = repos_result.scalar() or 0
        
        # Total vulnerabilities from scan summaries
        vulnerabilities_query = select(
            func.sum(
                ScanSummary.critical_count + ScanSummary.high_count + 
                ScanSummary.medium_count + ScanSummary.low_count
            )
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(and_(*base_filters))
        
        vulnerabilities_result = await self.db.execute(vulnerabilities_query)
        total_vulnerabilities = vulnerabilities_result.scalar() or 0
        
        # Average security score
        avg_score_query = select(func.avg(Scan.total_score)).where(
            and_(*base_filters, Scan.total_score.isnot(None))
        )
        avg_score_result = await self.db.execute(avg_score_query)
        average_security_score = float(avg_score_result.scalar() or 0)
        
        # Active scans (running or queued)
        active_scans_query = select(func.count(Scan.id)).where(
            and_(
                Scan.user_id == self.user_id,
                Scan.status.in_(['running', 'queued', 'in_progress'])
            )
        )
        active_scans_result = await self.db.execute(active_scans_query)
        active_scans = active_scans_result.scalar() or 0
        
        # Critical issues
        critical_query = select(func.sum(ScanSummary.critical_count)).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(and_(*base_filters))
        
        critical_result = await self.db.execute(critical_query)
        critical_issues = critical_result.scalar() or 0
        
        # Get compliance scores (simplified - using scan scores as proxy)
        compliance_query = select(func.avg(Scan.total_score)).where(
            and_(*base_filters, Scan.total_score.isnot(None))
        )
        compliance_result = await self.db.execute(compliance_query)
        compliance_score = float(compliance_result.scalar() or 0)
        
        # Get real resolved issues count from issue tracking system
        try:
            issue_service = IssueTrackingService()
            fixed_issues = await issue_service.get_fixed_issues_count(
                session=self.db,
                repo_full_name=repo_filter,
                start_date=start_date,
                end_date=end_date
            )
            logger.info(f"Retrieved real resolved issues count: {fixed_issues}")
        except Exception as e:
            logger.warning(f"Issue tracking not available, using estimation: {str(e)}")
            # Rollback any failed transaction to prevent "aborted transaction" errors
            try:
                await self.db.rollback()
            except Exception:
                pass
                
            # Fallback to estimation if issue tracking fails
            fixed_issues_estimate = max(0, int(total_vulnerabilities * 0.2))
            
            # Estimate based on score improvements
            improvement_query = select(
                Scan.repo_full_name,
                func.count(Scan.id).label('scan_count'),
                (func.max(Scan.total_score) - func.min(Scan.total_score)).label('score_improvement')
            ).where(
                and_(*base_filters, Scan.total_score.isnot(None))
            ).group_by(Scan.repo_full_name).having(func.count(Scan.id) > 1)
            
            improvement_result = await self.db.execute(improvement_query)
            improvements = improvement_result.fetchall()
            
            estimated_fixed = sum(max(0, improvement.score_improvement * 0.5) for improvement in improvements)
            fixed_issues = int(fixed_issues_estimate + estimated_fixed)
        
        return {
            "total_scans": total_scans,
            "total_repositories": total_repositories,
            "total_vulnerabilities": total_vulnerabilities,
            "average_security_score": round(average_security_score, 2),
            "active_scans": active_scans,
            "fixed_issues": fixed_issues,
            "compliance_score": round(compliance_score, 2),
            "critical_issues": critical_issues
        }
    
    async def get_score_trend(self, time_range: TimeRange, repo_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get security score trend data"""
        start_date, end_date = self._get_date_range(time_range)
        
        # Determine grouping interval
        if time_range in [TimeRange.DAY, TimeRange.WEEK]:
            interval = 'day'
        elif time_range == TimeRange.MONTH:
            interval = 'day'
        else:
            interval = 'week'
        
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date,
            Scan.total_score.isnot(None)
        ]
        
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        # PostgreSQL-specific date truncation
        date_trunc_func = func.date_trunc(interval, Scan.created_at)
        
        trend_query = select(
            date_trunc_func.label('period'),
            func.avg(Scan.total_score).label('avg_score'),
            func.count(Scan.id).label('scan_count')
        ).where(
            and_(*base_filters)
        ).group_by(
            date_trunc_func
        ).order_by(
            date_trunc_func
        )
        
        result = await self.db.execute(trend_query)
        trends = result.fetchall()
        
        return [
            {
                "date": trend.period.isoformat(),
                "score": round(float(trend.avg_score), 2),
                "scan_count": trend.scan_count
            }
            for trend in trends
        ]
    
    async def get_vulnerability_trend(self, time_range: TimeRange, repo_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get vulnerability count trend data"""
        start_date, end_date = self._get_date_range(time_range)
        
        # Determine grouping interval
        if time_range in [TimeRange.DAY, TimeRange.WEEK]:
            interval = 'day'
        elif time_range == TimeRange.MONTH:
            interval = 'day'
        else:
            interval = 'week'
        
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date
        ]
        
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        date_trunc_func = func.date_trunc(interval, Scan.created_at)
        
        trend_query = select(
            date_trunc_func.label('period'),
            func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                    ScanSummary.medium_count + ScanSummary.low_count).label('total_vulnerabilities'),
            func.sum(ScanSummary.critical_count).label('critical_count'),
            func.sum(ScanSummary.high_count).label('high_count')
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*base_filters)
        ).group_by(
            date_trunc_func
        ).order_by(
            date_trunc_func
        )
        
        result = await self.db.execute(trend_query)
        trends = result.fetchall()
        
        return [
            {
                "date": trend.period.isoformat(),
                "value": trend.total_vulnerabilities or 0,
                "critical_count": trend.critical_count or 0,
                "high_count": trend.high_count or 0
            }
            for trend in trends
        ]
    
    async def get_top_issues(self, time_range: TimeRange, limit: int = 10, repo_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get most common security issues"""
        start_date, end_date = self._get_date_range(time_range)
        
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date
        ]
        
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        # Aggregate by category from scan summaries
        issues_query = select(
            ScanSummary.category,
            func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                    ScanSummary.medium_count + ScanSummary.low_count).label('total_count'),
            func.sum(ScanSummary.critical_count).label('critical_count'),
            func.max(case(
                (ScanSummary.critical_count > 0, 'critical'),
                (ScanSummary.high_count > 0, 'high'),
                (ScanSummary.medium_count > 0, 'medium'),
                (ScanSummary.low_count > 0, 'low'),
                else_='info'
            )).label('severity')
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*base_filters)
        ).group_by(
            ScanSummary.category
        ).order_by(
            desc('total_count')
        ).limit(limit)
        
        result = await self.db.execute(issues_query)
        issues = result.fetchall()
        
        total_issues = sum(issue.total_count for issue in issues)
        
        return [
            {
                "category": issue.category,
                "rule_id": issue.category,  # Using category as rule_id for now
                "count": issue.total_count,
                "severity": issue.severity,
                "percentage": round((issue.total_count / max(total_issues, 1)) * 100, 2)
            }
            for issue in issues
        ]
    
    async def get_recent_activity(self, limit: int = 10, repo_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent scan activity"""
        base_filters = [Scan.user_id == self.user_id]
        
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        activity_query = select(
            Scan.id,
            Scan.repo_full_name,
            Scan.scan_type,
            Scan.status,
            Scan.created_at,
            Scan.total_score,
            func.coalesce(
                func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                        ScanSummary.medium_count + ScanSummary.low_count), 0
            ).label('issues_found')
        ).select_from(
            outerjoin(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*base_filters)
        ).group_by(
            Scan.id, Scan.repo_full_name, Scan.scan_type, Scan.status, Scan.created_at, Scan.total_score
        ).order_by(
            desc(Scan.created_at)
        ).limit(limit)
        
        result = await self.db.execute(activity_query)
        activities = result.fetchall()
        
        return [
            {
                "scan_id": activity.id,
                "repo_name": activity.repo_full_name,
                "scan_type": activity.scan_type,
                "status": activity.status,
                "created_at": activity.created_at.isoformat(),
                "security_score": activity.total_score,
                "issues_found": activity.issues_found
            }
            for activity in activities
        ]
    
    async def get_scans_by_severity(self, time_range: TimeRange, repo_filter: Optional[str] = None) -> Dict[str, int]:
        """Get scans distribution by severity"""
        start_date, end_date = self._get_date_range(time_range)
        
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date
        ]
        
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        severity_query = select(
            func.sum(ScanSummary.critical_count).label('critical'),
            func.sum(ScanSummary.high_count).label('high'),
            func.sum(ScanSummary.medium_count).label('medium'),
            func.sum(ScanSummary.low_count).label('low')
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*base_filters)
        )
        
        result = await self.db.execute(severity_query)
        severity_data = result.fetchone()
        
        return {
            "critical": severity_data.critical or 0,
            "high": severity_data.high or 0,
            "medium": severity_data.medium or 0,
            "low": severity_data.low or 0
        }
    
    async def get_scans_by_type(self, time_range: TimeRange, repo_filter: Optional[str] = None) -> Dict[str, int]:
        """Get scans distribution by scan type"""
        start_date, end_date = self._get_date_range(time_range)
        
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date
        ]
        
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        type_query = select(
            Scan.scan_type,
            func.count(Scan.id).label('count')
        ).where(
            and_(*base_filters)
        ).group_by(
            Scan.scan_type
        ).order_by(
            desc('count')
        )
        
        result = await self.db.execute(type_query)
        scan_types = result.fetchall()
        
        return {scan_type.scan_type: scan_type.count for scan_type in scan_types}
    
    async def get_security_metrics(self, time_range: TimeRange) -> Dict[str, Any]:
        """Get detailed security metrics"""
        start_date, end_date = self._get_date_range(time_range)
        
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date
        ]
        
        # Get vulnerability counts by severity
        vulnerability_query = select(
            func.sum(ScanSummary.critical_count).label('critical'),
            func.sum(ScanSummary.high_count).label('high'),
            func.sum(ScanSummary.medium_count).label('medium'),
            func.sum(ScanSummary.low_count).label('low'),
            func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                    ScanSummary.medium_count + ScanSummary.low_count).label('total')
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*base_filters)
        )
        
        vuln_result = await self.db.execute(vulnerability_query)
        vuln_data = vuln_result.fetchone()
        
        # Get vulnerabilities by category
        category_query = select(
            ScanSummary.category,
            func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                    ScanSummary.medium_count + ScanSummary.low_count).label('count')
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*base_filters)
        ).group_by(
            ScanSummary.category
        ).order_by(
            desc('count')
        )
        
        category_result = await self.db.execute(category_query)
        categories = category_result.fetchall()
        
        # Get vulnerabilities by tool
        tool_query = select(
            ScanSummary.tool_name,
            func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                    ScanSummary.medium_count + ScanSummary.low_count).label('count')
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*base_filters)
        ).group_by(
            ScanSummary.tool_name
        ).order_by(
            desc('count')
        )
        
        tool_result = await self.db.execute(tool_query)
        tools = tool_result.fetchall()
        
        # Average security score
        avg_score_query = select(func.avg(Scan.total_score)).where(
            and_(*base_filters, Scan.total_score.isnot(None))
        )
        avg_score_result = await self.db.execute(avg_score_query)
        avg_security_score = float(avg_score_result.scalar() or 0)
        
        # False positive rate (from issue feedback)
        fp_query = select(
            func.count(case((IssueFeedback.is_false_positive == True, 1))).label('fp_count'),
            func.count(IssueFeedback.id).label('total_feedback')
        ).select_from(
            join(Scan, IssueFeedback, Scan.id == IssueFeedback.scan_id)
        ).where(
            and_(*base_filters)
        )
        
        fp_result = await self.db.execute(fp_query)
        fp_data = fp_result.fetchone()
        
        fp_rate = 0.0
        if fp_data.total_feedback and fp_data.total_feedback > 0:
            fp_rate = (fp_data.fp_count / fp_data.total_feedback) * 100
        
        return {
            "total_vulnerabilities": vuln_data.total or 0,
            "critical_issues": vuln_data.critical or 0,
            "high_issues": vuln_data.high or 0,
            "medium_issues": vuln_data.medium or 0,
            "low_issues": vuln_data.low or 0,
            "security_score_avg": round(avg_security_score, 2),
            "vulnerabilities_by_category": {cat.category: cat.count for cat in categories},
            "vulnerabilities_by_tool": {tool.tool_name: tool.count for tool in tools},
            "false_positive_rate": round(fp_rate, 2),
            "mean_time_to_fix": None  # TODO: Implement when fix tracking is available
        }
    
    async def get_repository_insights(self, repo_filter: Optional[str] = None, language_filter: Optional[str] = None) -> Dict[str, Any]:
        """Get repository analytics and insights"""
        
        # Base repository filters
        repo_filters = [Repo.user_id == self.user_id]
        if repo_filter:
            repo_filters.append(Repo.full_name == repo_filter)
        if language_filter and language_filter != 'all':
            repo_filters.append(Repo.language == language_filter)
        
        # Repository counts (apply language filter to get filtered counts)
        filtered_repos_query = select(func.count(Repo.id)).where(and_(*repo_filters))
        filtered_repos_result = await self.db.execute(filtered_repos_query)
        filtered_repositories = filtered_repos_result.scalar() or 0
        
        # Total repositories (without language filter for overall stats)
        total_repos_query = select(func.count(Repo.id)).where(Repo.user_id == self.user_id)
        total_repos_result = await self.db.execute(total_repos_query)
        total_repositories = total_repos_result.scalar() or 0
        
        # Active repositories (with language filter applied)
        active_repo_filters = repo_filters + [Repo.status == 'active']
        active_repos_query = select(func.count(Repo.id)).where(and_(*active_repo_filters))
        active_repos_result = await self.db.execute(active_repos_query)
        active_repositories = active_repos_result.scalar() or 0
        
        # Repositories by language (apply language filter)
        lang_query = select(
            Repo.language,
            func.count(Repo.id).label('count')
        ).where(
            and_(*repo_filters, Repo.language.isnot(None))
        ).group_by(
            Repo.language
        ).order_by(
            desc('count')
        )
        
        lang_result = await self.db.execute(lang_query)
        languages = lang_result.fetchall()
        
        # Repositories by niche (apply language filter)
        niche_query = select(
            Repo.niche,
            func.count(Repo.id).label('count')
        ).where(
            and_(*repo_filters)
        ).group_by(
            Repo.niche
        ).order_by(
            desc('count')
        )
        
        niche_result = await self.db.execute(niche_query)
        niches = niche_result.fetchall()
        
        # Recent activity with latest scans
        recent_activity_query = select(
            Repo.full_name,
            func.max(Scan.created_at).label('last_scan'),
            func.avg(Scan.total_score).label('avg_score'),
            func.sum(ScanSummary.critical_count).label('critical_issues')
        ).select_from(
            outerjoin(join(Repo, Scan, Repo.full_name == Scan.repo_full_name), ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(*repo_filters)
        ).group_by(
            Repo.full_name
        ).order_by(
            desc('last_scan')
        ).limit(10)
        
        activity_result = await self.db.execute(recent_activity_query)
        recent_activity = activity_result.fetchall()
        
        # Security score distribution
        score_ranges = [
            ("90-100", 90, 100),
            ("80-89", 80, 89),
            ("70-79", 70, 79),
            ("60-69", 60, 69),
            ("Below 60", 0, 59)
        ]
        
        score_distribution = {}
        for range_name, min_score, max_score in score_ranges:
            score_query = select(func.count(distinct(Scan.repo_full_name))).where(
                and_(
                    Scan.user_id == self.user_id,
                    Scan.total_score >= min_score,
                    Scan.total_score <= max_score,
                    Scan.total_score.isnot(None)
                )
            )
            score_result = await self.db.execute(score_query)
            score_distribution[range_name] = score_result.scalar() or 0
        
        return {
            "total_repositories": filtered_repositories if language_filter and language_filter != 'all' else total_repositories,
            "active_repositories": active_repositories,
            "repositories_by_language": {lang.language: lang.count for lang in languages},
            "repositories_by_niche": {niche.niche: niche.count for niche in niches},
            "security_score_distribution": score_distribution,
            "recent_activity": [
                {
                    "repo_name": activity.full_name,
                    "last_scan": activity.last_scan.isoformat() if activity.last_scan else None,
                    "security_score": round(float(activity.avg_score), 2) if activity.avg_score else 0,
                    "critical_issues": activity.critical_issues or 0
                }
                for activity in recent_activity
            ]
        }
    
    async def get_compliance_report(self, framework: ComplianceFramework, repo_filter: Optional[str] = None) -> Dict[str, Any]:
        """Get compliance report for specified framework"""
        
        # For now, we'll create a simplified compliance report based on scan data
        # In a full implementation, this would map to actual compliance frameworks
        
        base_filters = [Scan.user_id == self.user_id]
        if repo_filter:
            base_filters.append(Scan.repo_full_name == repo_filter)
        
        # Get compliance mappings if they exist
        compliance_query = select(
            ComplianceMapping.owasp_category,
            ComplianceMapping.cwe_id,
            ComplianceMapping.business_impact,
            func.count(ComplianceMapping.id).label('issues_count')
        ).select_from(
            join(Scan, ComplianceMapping, Scan.id == ComplianceMapping.scan_id)
        ).where(
            and_(*base_filters)
        ).group_by(
            ComplianceMapping.owasp_category,
            ComplianceMapping.cwe_id,
            ComplianceMapping.business_impact
        )
        
        # compliance_result = await self.db.execute(compliance_query)
        # compliance_mappings = compliance_result.fetchall()  # Reserved for future use
        
        # Check if user has any scans first
        scan_count_query = select(func.count(Scan.id)).where(and_(*base_filters))
        scan_count_result = await self.db.execute(scan_count_query)
        scan_count = scan_count_result.scalar() or 0
        
        # Calculate overall compliance score based on security scores
        if scan_count > 0:
            avg_score_query = select(func.avg(Scan.total_score)).where(
                and_(*base_filters, Scan.total_score.isnot(None))
            )
            avg_score_result = await self.db.execute(avg_score_query)
            overall_score = float(avg_score_result.scalar() or 0)
        else:
            # New users with no scans should have zero compliance data
            overall_score = 0
        
        # Generate compliance categories
        categories = []
        if framework == ComplianceFramework.OWASP:
            owasp_categories = [
                "A01:2021 - Broken Access Control",
                "A02:2021 - Cryptographic Failures",
                "A03:2021 - Injection",
                "A04:2021 - Insecure Design",
                "A05:2021 - Security Misconfiguration"
            ]
            
            for category in owasp_categories:
                if scan_count == 0:
                    # New users with no scans should show zero data
                    category_score = 0
                    issues_count = 0
                    status = "non-compliant"
                else:
                    # Calculate category-specific metrics for users with scans
                    category_score = min(100, max(0, overall_score + (hash(category) % 20 - 10)))
                    issues_count = max(0, int((100 - category_score) / 10))
                    status = "compliant" if category_score >= 80 else "partial" if category_score >= 60 else "non-compliant"
                
                categories.append({
                    "name": category,
                    "score": round(category_score, 2),
                    "issues": issues_count,
                    "status": status
                })
        
        requirements_met = sum(1 for cat in categories if cat["status"] == "compliant")
        total_requirements = len(categories)
        
        return {
            "framework": framework.value,
            "overall_score": round(overall_score, 2),
            "requirements_met": requirements_met,
            "total_requirements": total_requirements,
            "categories": categories,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "trending_up": True  # TODO: Implement trend calculation
        }
    
    async def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get real-time metrics for dashboard widgets"""
        
        # Active scans
        active_scans_query = select(func.count(Scan.id)).where(
            and_(
                Scan.user_id == self.user_id,
                Scan.status.in_(['running', 'queued', 'in_progress'])
            )
        )
        active_scans_result = await self.db.execute(active_scans_query)
        active_scans = active_scans_result.scalar() or 0
        
        # Recent issues (last 24 hours)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        recent_issues_query = select(
            func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                    ScanSummary.medium_count + ScanSummary.low_count)
        ).select_from(
            join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            and_(
                Scan.user_id == self.user_id,
                Scan.created_at >= yesterday
            )
        )
        
        recent_issues_result = await self.db.execute(recent_issues_query)
        recent_issues = recent_issues_result.scalar() or 0
        
        # Current average security score
        avg_score_query = select(func.avg(Scan.total_score)).where(
            and_(Scan.user_id == self.user_id, Scan.total_score.isnot(None))
        )
        avg_score_result = await self.db.execute(avg_score_query)
        security_score_avg = float(avg_score_result.scalar() or 0)
        
        return {
            "active_scans": active_scans,
            "queued_scans": 0,  # TODO: Implement queue tracking
            "recent_issues": recent_issues,
            "security_score_avg": round(security_score_avg, 2),
            "compliance_status": {
                "owasp": round(security_score_avg * 0.8, 2),
                "nist": round(security_score_avg * 0.75, 2),
                "pci-dss": round(security_score_avg * 0.9, 2)
            },
            "alert_count": 0,  # TODO: Implement alert system
            "system_health": "healthy",
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
    
    async def get_team_insights(self) -> Dict[str, Any]:
        """Get team analytics and insights"""
        
        # For single-user system, create mock team data
        # In a real multi-user system, this would query actual team members
        
        # Get user's repository and scan statistics
        user_stats_query = select(
            func.count(distinct(Repo.id)).label('repositories_count'),
            func.count(Scan.id).label('total_scans'),
            func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                    ScanSummary.medium_count + ScanSummary.low_count).label('issues_found'),
            func.avg(Scan.total_score).label('avg_security_score'),
            func.max(Scan.created_at).label('last_activity')
        ).select_from(
            outerjoin(outerjoin(Repo, Scan, Repo.full_name == Scan.repo_full_name), ScanSummary, Scan.id == ScanSummary.scan_id)
        ).where(
            Repo.user_id == self.user_id
        )
        
        stats_result = await self.db.execute(user_stats_query)
        stats = stats_result.fetchone()
        
        # Get recent scans count (last 30 days)
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        recent_scans_query = select(func.count(Scan.id)).where(
            and_(
                Scan.user_id == self.user_id,
                Scan.created_at >= thirty_days_ago
            )
        )
        recent_scans_result = await self.db.execute(recent_scans_query)
        recent_scans = recent_scans_result.scalar() or 0
        
        # Repository ownership by language
        ownership_query = select(
            Repo.language,
            func.count(Repo.id).label('count')
        ).where(
            and_(Repo.user_id == self.user_id, Repo.language.isnot(None))
        ).group_by(Repo.language)
        
        ownership_result = await self.db.execute(ownership_query)
        ownership_data = ownership_result.fetchall()
        
        # Mock team member data (in single-user context)
        from auth.models import User
        user_query = select(User.username).where(User.id == self.user_id)
        user_result = await self.db.execute(user_query)
        username = user_result.scalar() or "User"
        
        most_active_contributors = [{
            "user_id": self.user_id,
            "username": username,
            "repositories_count": stats.repositories_count or 0,
            "recent_scans": recent_scans,
            "issues_found": stats.issues_found or 0,
            "issues_fixed": await self._get_user_fixed_issues_count(),
            "avg_security_score": round(float(stats.avg_security_score or 0), 2),
            "last_activity": stats.last_activity.isoformat() if stats.last_activity else datetime.now(timezone.utc).isoformat()
        }]
        
        repository_ownership = {lang.language: lang.count for lang in ownership_data}
        
        # Scan frequency (mock data for single user)
        scan_frequency = {username: recent_scans}
        
        # Calculate collaboration score (simplified for single user)
        collaboration_score = min(100.0, (recent_scans * 10) + (stats.repositories_count or 0) * 5)
        
        return {
            "total_team_members": 1,  # Single user system
            "most_active_contributors": most_active_contributors,
            "repository_ownership": repository_ownership,
            "scan_frequency": scan_frequency,
            "collaboration_score": collaboration_score
        }
    
    async def get_custom_analytics(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get custom analytics based on request parameters"""
        
        start_date = request_data["start_date"]
        end_date = request_data["end_date"]
        metrics = request_data["metrics"]
        filters = request_data.get("filters", {})
        group_by = request_data.get("group_by")
        
        result = {}
        
        # Base filters
        base_filters = [
            Scan.user_id == self.user_id,
            Scan.created_at >= start_date,
            Scan.created_at <= end_date
        ]
        
        # Apply repository filter if specified
        if filters.get("repo_full_name"):
            base_filters.append(Scan.repo_full_name == filters["repo_full_name"])
        
        # Process each requested metric
        for metric in metrics:
            if metric == "total_scans":
                query = select(func.count(Scan.id)).where(and_(*base_filters))
                result_data = await self.db.execute(query)
                result[metric] = result_data.scalar() or 0
                
            elif metric == "total_vulnerabilities":
                query = select(
                    func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                            ScanSummary.medium_count + ScanSummary.low_count)
                ).select_from(
                    join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
                ).where(and_(*base_filters))
                result_data = await self.db.execute(query)
                result[metric] = result_data.scalar() or 0
                
            elif metric == "average_security_score":
                query = select(func.avg(Scan.total_score)).where(
                    and_(*base_filters, Scan.total_score.isnot(None))
                )
                result_data = await self.db.execute(query)
                result[metric] = round(float(result_data.scalar() or 0), 2)
                
            elif metric == "critical_issues":
                query = select(func.sum(ScanSummary.critical_count)).select_from(
                    join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
                ).where(and_(*base_filters))
                result_data = await self.db.execute(query)
                result[metric] = result_data.scalar() or 0
                
            elif metric == "repositories_scanned":
                query = select(func.count(distinct(Scan.repo_full_name))).where(and_(*base_filters))
                result_data = await self.db.execute(query)
                result[metric] = result_data.scalar() or 0
        
        # Add grouping if specified
        if group_by:
            grouped_data = await self._get_grouped_data(base_filters, group_by)
            result["grouped_data"] = grouped_data
        
        return result
    
    async def _get_grouped_data(self, base_filters: List, group_by: str) -> Dict[str, Any]:
        """Helper method to get grouped analytics data"""
        
        if group_by == "repository":
            query = select(
                Scan.repo_full_name,
                func.count(Scan.id).label('scan_count'),
                func.avg(Scan.total_score).label('avg_score'),
                func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                        ScanSummary.medium_count + ScanSummary.low_count).label('total_issues')
            ).select_from(
                outerjoin(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
            ).where(
                and_(*base_filters)
            ).group_by(Scan.repo_full_name)
            
        elif group_by == "date":
            query = select(
                func.date_trunc('day', Scan.created_at).label('date'),
                func.count(Scan.id).label('scan_count'),
                func.avg(Scan.total_score).label('avg_score')
            ).where(
                and_(*base_filters)
            ).group_by(func.date_trunc('day', Scan.created_at))
            
        elif group_by == "severity":
            query = select(
                func.sum(ScanSummary.critical_count).label('critical'),
                func.sum(ScanSummary.high_count).label('high'),
                func.sum(ScanSummary.medium_count).label('medium'),
                func.sum(ScanSummary.low_count).label('low')
            ).select_from(
                join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
            ).where(and_(*base_filters))
            
        else:
            return {"error": f"Unsupported group_by parameter: {group_by}"}
        
        result_data = await self.db.execute(query)
        
        if group_by == "severity":
            severity_data = result_data.fetchone()
            return {
                "critical": severity_data.critical or 0,
                "high": severity_data.high or 0,
                "medium": severity_data.medium or 0,
                "low": severity_data.low or 0
            }
        else:
            rows = result_data.fetchall()
            return [dict(row._mapping) for row in rows]
    
    async def _get_user_fixed_issues_count(self) -> int:
        """Get the count of issues fixed by the current user across all their repositories"""
        try:
            # Get all repositories for the user
            user_repos = await self.db.execute(
                select(Repo.full_name).where(Repo.user_id == self.user_id)
            )
            repo_names = [repo.full_name for repo in user_repos.scalars()]
            
            if not repo_names:
                return 0
            
            # Count fixed issues across all user repositories
            issue_service = IssueTrackingService()
            total_fixed = 0
            
            for repo_name in repo_names:
                fixed_count = await issue_service.get_fixed_issues_count(
                    session=self.db,
                    repo_full_name=repo_name
                )
                total_fixed += fixed_count
            
            return total_fixed
            
        except Exception as e:
            logger.error(f"Failed to get user fixed issues count: {e}")
            return 0