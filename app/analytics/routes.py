"""
Analytics API Routes for DevSecureX Security Scanning Platform
Provides comprehensive analytics endpoints for security insights
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, desc, join
from typing import Optional, List
import logging
from datetime import datetime, timezone
from core.utils import format_datetime_response, utc_now
import json
import csv
import io
import uuid
from pathlib import Path

from core.database import get_db
from core.cache import cached
from auth.dependencies import get_current_user
from auth.models import User
from repos.models import Repo
from scans.models import Scan, ScanSummary
from .services import AnalyticsService
from .models import (
    TimeRange, ComplianceFramework, OverviewResponse, SecurityResponse,
    ComplianceReport, TrendsResponse, RepositoriesResponse, RealTimeMetrics,
    ExportRequest, ExportJob, CustomMetricRequest, CustomAnalyticsResponse,
    TeamInsights, OverviewMetrics, TrendPoint, TopIssue, RecentActivity,
    SecurityMetrics, VulnerabilityTrend, RiskAssessment, ComplianceCategory,
    RepositoryInsight, TrendMetric, PerformanceMetrics
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analytics", tags=["Analytics"])

logger.info("🚀 ANALYTICS ROUTES MODULE LOADED!")

# Cache configurations for different endpoint types
CACHE_SHORT = 300  # 5 minutes for frequently changing data
CACHE_MEDIUM = 900  # 15 minutes for moderately stable data
CACHE_LONG = 3600  # 1 hour for stable data


@router.get("/overview", response_model=OverviewResponse)
# @cached(ttl=CACHE_MEDIUM)  # Temporarily disabled to fix user data isolation
async def get_overview_analytics(
    time_range: TimeRange = Query(TimeRange.MONTH, description="Time range for analytics"),
    repo_full_name: Optional[str] = Query(None, description="Filter by specific repository"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get overview analytics dashboard data
    
    Provides key metrics, trends, and insights for the dashboard overview:
    - Total scans, repositories, vulnerabilities
    - Security score trends
    - Most common issues
    - Recent activity
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        # Get overview metrics
        metrics_data = await analytics_service.get_overview_metrics(time_range, repo_full_name)
        metrics = OverviewMetrics(**metrics_data)
        
        # Get score trend
        score_trend_data = await analytics_service.get_score_trend(time_range, repo_full_name)
        score_trend = [TrendPoint(date=datetime.fromisoformat(item["date"]), value=item["score"]) 
                      for item in score_trend_data]
        
        # Get vulnerability trend
        vuln_trend_data = await analytics_service.get_vulnerability_trend(time_range, repo_full_name)
        vulnerability_trend = [TrendPoint(date=datetime.fromisoformat(item["date"]), value=item["value"]) 
                              for item in vuln_trend_data]
        
        # Get top issues
        top_issues_data = await analytics_service.get_top_issues(time_range, limit=10, repo_filter=repo_full_name)
        top_issues = [TopIssue(**issue) for issue in top_issues_data]
        
        # Get recent activity
        recent_activity_data = await analytics_service.get_recent_activity(limit=10, repo_filter=repo_full_name)
        recent_activity = [RecentActivity(
            scan_id=activity["scan_id"],
            repo_name=activity["repo_name"],
            scan_type=activity["scan_type"],
            status=activity["status"],
            created_at=datetime.fromisoformat(activity["created_at"]),
            security_score=activity["security_score"],
            issues_found=activity["issues_found"]
        ) for activity in recent_activity_data]
        
        # Get distributions
        scans_by_severity = await analytics_service.get_scans_by_severity(time_range, repo_full_name)
        scans_by_type = await analytics_service.get_scans_by_type(time_range, repo_full_name)
        
        return OverviewResponse(
            metrics=metrics,
            score_trend=score_trend,
            vulnerability_trend=vulnerability_trend,
            top_issues=top_issues,
            recent_activity=recent_activity,
            scans_by_severity=scans_by_severity,
            scans_by_type=scans_by_type
        )
        
    except Exception as e:
        logger.error(f"Error getting overview analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve overview analytics"
        )


@router.get("/security", response_model=SecurityResponse)
# @cached(ttl=CACHE_MEDIUM)  # Temporarily disabled to fix user data isolation
async def get_security_analytics(
    time_range: TimeRange = Query(TimeRange.MONTH, description="Time range for analytics"),
    repo_full_name: Optional[str] = Query(None, description="Filter by specific repository"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed security analytics
    
    Provides comprehensive security metrics including:
    - Vulnerability counts by severity
    - Security trend analysis
    - Risk assessment
    - Critical issues breakdown
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        # Get security metrics
        security_data = await analytics_service.get_security_metrics(time_range)
        metrics = SecurityMetrics(**security_data)
        
        # Get vulnerability trend data
        vuln_trend_data = await analytics_service.get_vulnerability_trend(time_range, repo_full_name)
        trend_data = [VulnerabilityTrend(
            date=datetime.fromisoformat(item["date"]),
            vulnerabilities=item["value"],
            critical_count=item.get("critical_count", 0),
            high_count=item.get("high_count", 0),
            security_score=75.0,  # TODO: Add security score to trend data
            scans_completed=1  # TODO: Add scans completed to trend data
        ) for item in vuln_trend_data]
        
        # Calculate risk assessment
        total_critical = metrics.critical_issues
        total_high = metrics.high_issues
        
        if total_critical > 10:
            risk_level = "critical"
            risk_score = 90.0
        elif total_critical > 5 or total_high > 20:
            risk_level = "high"
            risk_score = 70.0
        elif total_high > 10:
            risk_level = "medium"
            risk_score = 50.0
        else:
            risk_level = "low"
            risk_score = 25.0
        
        risk_factors = []
        if total_critical > 0:
            risk_factors.append(f"{total_critical} critical vulnerabilities found")
        if total_high > 0:
            risk_factors.append(f"{total_high} high severity vulnerabilities")
        if metrics.false_positive_rate > 20:
            risk_factors.append(f"High false positive rate ({metrics.false_positive_rate}%)")
        
        recommendations = []
        if total_critical > 0:
            recommendations.append("Address critical vulnerabilities immediately")
        if total_high > 5:
            recommendations.append("Prioritize high severity vulnerability remediation")
        if metrics.false_positive_rate > 15:
            recommendations.append("Review and tune security scanning rules")
        
        risk_assessment = RiskAssessment(
            overall_risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors or ["No significant risks identified"],
            recommendations=recommendations or ["Maintain current security practices"]
        )
        
        # Get critical issues details
        critical_issues_data = await analytics_service.get_top_issues(
            time_range, limit=10, repo_filter=repo_full_name
        )
        critical_issues = [TopIssue(**issue) for issue in critical_issues_data if issue.get("severity") == "critical"]
        
        return SecurityResponse(
            metrics=metrics,
            trend_data=trend_data,
            risk_assessment=risk_assessment,
            critical_issues_details=critical_issues
        )
        
    except Exception as e:
        logger.error(f"Error getting security analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve security analytics"
        )


@router.get("/compliance", response_model=ComplianceReport)
@cached(ttl=CACHE_LONG)
async def get_compliance_report(
    framework: ComplianceFramework = Query(ComplianceFramework.OWASP, description="Compliance framework"),
    repo_full_name: Optional[str] = Query(None, description="Filter by specific repository"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get compliance analytics report
    
    Provides compliance assessment against various frameworks:
    - OWASP Top 10
    - NIST Cybersecurity Framework
    - PCI DSS
    - HIPAA
    - GDPR
    - ISO 27001
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        compliance_data = await analytics_service.get_compliance_report(framework, repo_full_name)
        
        # Convert categories to proper model format
        categories = []
        for cat_data in compliance_data["categories"]:
            categories.append(ComplianceCategory(
                category_id=cat_data["name"].lower().replace(" ", "_"),
                name=cat_data["name"],
                score=cat_data["score"],
                status=cat_data["status"],
                requirements=[],  # TODO: Add detailed requirements
                issues_count=cat_data["issues"]
            ))
        
        return ComplianceReport(
            framework=framework,
            overall_score=compliance_data["overall_score"],
            requirements_met=compliance_data["requirements_met"],
            total_requirements=compliance_data["total_requirements"],
            categories=categories,
            last_updated=datetime.fromisoformat(compliance_data["last_updated"]),
            trending_up=compliance_data["trending_up"]
        )
        
    except Exception as e:
        logger.error(f"Error getting compliance report for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve compliance report"
        )


@router.get("/trends", response_model=TrendsResponse)
@cached(ttl=CACHE_MEDIUM)
async def get_trends_analytics(
    time_range: TimeRange = Query(TimeRange.MONTH, description="Time range for trends"),
    metric: str = Query("vulnerabilities", description="Primary metric to analyze"),
    repo_full_name: Optional[str] = Query(None, description="Filter by specific repository"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed trend analysis
    
    Provides comprehensive trend analytics:
    - Security score trends
    - Vulnerability trends
    - Compliance trends
    - Performance metrics
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        # Get security trends
        security_trend_data = await analytics_service.get_score_trend(time_range, repo_full_name)
        security_points = [TrendPoint(date=datetime.fromisoformat(item["date"]), value=item["score"]) 
                          for item in security_trend_data]
        
        current_security = security_points[-1].value if security_points else 0
        previous_security = security_points[-2].value if len(security_points) > 1 else current_security
        security_change = ((current_security - previous_security) / max(previous_security, 1)) * 100
        
        security_trends = TrendMetric(
            metric_name="Security Score",
            current_value=current_security,
            previous_value=previous_security,
            change_percentage=round(security_change, 2),
            trend_direction="up" if security_change > 5 else "down" if security_change < -5 else "stable",
            data_points=security_points
        )
        
        # Get vulnerability trends
        vuln_trend_data = await analytics_service.get_vulnerability_trend(time_range, repo_full_name)
        vuln_points = [TrendPoint(date=datetime.fromisoformat(item["date"]), value=item["value"]) 
                      for item in vuln_trend_data]
        
        current_vulns = vuln_points[-1].value if vuln_points else 0
        previous_vulns = vuln_points[-2].value if len(vuln_points) > 1 else current_vulns
        vuln_change = ((current_vulns - previous_vulns) / max(previous_vulns, 1)) * 100
        
        vulnerability_trends = TrendMetric(
            metric_name="Vulnerabilities",
            current_value=current_vulns,
            previous_value=previous_vulns,
            change_percentage=round(vuln_change, 2),
            trend_direction="down" if vuln_change < -5 else "up" if vuln_change > 5 else "stable",
            data_points=vuln_points
        )
        
        # Mock compliance trends (would be calculated from actual compliance data)
        compliance_trends = TrendMetric(
            metric_name="Compliance Score",
            current_value=current_security * 0.8,
            previous_value=previous_security * 0.8,
            change_percentage=round(security_change * 0.8, 2),
            trend_direction=security_trends.trend_direction,
            data_points=[TrendPoint(date=p.date, value=p.value * 0.8) for p in security_points]
        )
        
        # Mock scan volume trends
        scan_volume_trends = TrendMetric(
            metric_name="Scan Volume",
            current_value=len(security_points),
            previous_value=max(1, len(security_points) - 1),
            change_percentage=10.0,
            trend_direction="up",
            data_points=[TrendPoint(date=p.date, value=float(i+1)) for i, p in enumerate(security_points)]
        )
        
        # Performance metrics
        performance_metrics = PerformanceMetrics(
            avg_scan_duration=15.5,  # TODO: Calculate from actual scan data
            scan_success_rate=95.0,   # TODO: Calculate from scan statuses
            issue_resolution_rate=75.0,  # TODO: Calculate from fix tracking
            new_issues_trend=vuln_points,
            fixed_issues_trend=[TrendPoint(date=p.date, value=max(0, p.value * 0.3)) for p in vuln_points]
        )
        
        return TrendsResponse(
            security_trends=security_trends,
            vulnerability_trends=vulnerability_trends,
            compliance_trends=compliance_trends,
            scan_volume_trends=scan_volume_trends,
            performance_metrics=performance_metrics,
            period_comparison={
                "current_period": time_range.value,
                "security_improvement": security_change > 0,
                "vulnerability_reduction": vuln_change < 0,
                "overall_trend": "positive" if security_change > 0 and vuln_change <= 0 else "negative"
            }
        )
        
    except Exception as e:
        logger.error(f"Error getting trends analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve trends analytics"
        )


@router.get("/repositories", response_model=RepositoriesResponse)
# @cached(ttl=CACHE_MEDIUM)  # Temporarily disabled to fix user data isolation
async def get_repositories_analytics(
    repo_full_name: Optional[str] = Query(None, description="Filter by specific repository"),
    language: Optional[str] = Query(None, description="Filter by programming language"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get repository-level analytics
    
    Provides detailed repository insights:
    - Repository performance rankings
    - Language and niche statistics
    - Security score distributions
    - Activity metrics
    """
    try:
        logger.info(f"🔍 REPOSITORY ANALYTICS CALLED FOR USER {current_user.id} - repo_filter: {repo_full_name}, language_filter: {language}")
        analytics_service = AnalyticsService(db, current_user.id)
        
        repository_data = await analytics_service.get_repository_insights(repo_full_name, language)
        
        # Get detailed repository insights with actual data  
        # First, get repository data to map languages and scan counts
        
        repository_insights = []
        try:
            logger.info(f"Starting repository insights generation for user {current_user.id}")
            
            # Get repositories with language filter applied
            repo_query_filters = [Repo.user_id == current_user.id]
            if language and language != 'all':
                repo_query_filters.append(Repo.language == language)
                
            repos_query = select(
                Repo.id,
                Repo.full_name,
                Repo.language,
                Repo.niche
            ).where(
                and_(*repo_query_filters)
            ).order_by(Repo.id.desc())
            
            repos_result = await db.execute(repos_query)
            repos = repos_result.fetchall()
            
            logger.info(f"Found {len(repos)} repositories for user {current_user.id}")
            
            # Get scan statistics for each repository
            for repo in repos:
                # Get scan count for this repository
                scan_count_query = select(func.count(Scan.id)).where(
                    and_(Scan.repo_full_name == repo.full_name, Scan.user_id == current_user.id)
                )
                scan_count_result = await db.execute(scan_count_query)
                total_scans = scan_count_result.scalar() or 0
                
                # Get latest scan date
                latest_scan_query = select(func.max(Scan.created_at)).where(
                    and_(Scan.repo_full_name == repo.full_name, Scan.user_id == current_user.id)
                )
                latest_scan_result = await db.execute(latest_scan_query)
                last_scan_date = latest_scan_result.scalar()
                
                # Get average security score
                avg_score_query = select(func.avg(Scan.total_score)).where(
                    and_(
                        Scan.repo_full_name == repo.full_name,
                        Scan.user_id == current_user.id,
                        Scan.total_score.isnot(None)
                    )
                )
                avg_score_result = await db.execute(avg_score_query)
                avg_security_score = avg_score_result.scalar()
                
                # Get vulnerability counts
                vuln_query = select(
                    func.sum(ScanSummary.critical_count + ScanSummary.high_count + 
                            ScanSummary.medium_count + ScanSummary.low_count),
                    func.sum(ScanSummary.critical_count)
                ).select_from(
                    join(Scan, ScanSummary, Scan.id == ScanSummary.scan_id)
                ).where(
                    and_(Scan.repo_full_name == repo.full_name, Scan.user_id == current_user.id)
                )
                vuln_result = await db.execute(vuln_query)
                vuln_data = vuln_result.fetchone()
                
                total_vulnerabilities = vuln_data[0] or 0 if vuln_data else 0
                critical_issues_count = vuln_data[1] or 0 if vuln_data else 0
                
                # Create repository insight
                repository_insights.append(
                    RepositoryInsight(
                        repo_id=repo.id,
                        full_name=repo.full_name,
                        language=repo.language or "Unknown",
                        niche=repo.niche or "general",
                        security_score=round(float(avg_security_score), 2) if avg_security_score else 0.0,
                        last_scan=last_scan_date,
                        total_scans=total_scans,
                        vulnerabilities_count=total_vulnerabilities,
                        critical_issues=critical_issues_count,
                        compliance_score=round(float(avg_security_score) * 0.8, 2) if avg_security_score else 0.0,
                        risk_level="critical" if critical_issues_count > 10 else 
                                  "high" if critical_issues_count > 5 else 
                                  "medium" if critical_issues_count > 2 else "low",
                        activity_score=min(100, (avg_security_score or 0) + 10)
                    )
                )
        
            # Debug logging to understand the data being returned
            logger.info(f"Repository query returned {len(repos)} repositories for user {current_user.id}")
            logger.info(f"Generated {len(repository_insights)} repository insights")
            for insight in repository_insights[:3]:  # Log first 3 insights for debugging
                logger.info(f"Repo: {insight.full_name}, Language: {insight.language}, Total Scans: {insight.total_scans}")
                
        except Exception as e:
            logger.error(f"Error in new repository insights generation: {str(e)}")
            logger.info("Falling back to old repository insights generation from recent_activity")
            
            # Fallback to old implementation using recent_activity data
            repository_insights = [
                RepositoryInsight(
                    repo_id=i,
                    full_name=activity["repo_name"],
                    language="Python",  # TODO: Get from repo data
                    niche="web",        # TODO: Get from repo data
                    security_score=activity["security_score"],
                    last_scan=datetime.fromisoformat(activity["last_scan"]) if activity["last_scan"] else None,
                    total_scans=10,     # TODO: Calculate actual count
                    vulnerabilities_count=activity["critical_issues"] * 3,  # Estimated
                    critical_issues=activity["critical_issues"],
                    compliance_score=activity["security_score"] * 0.8,
                    risk_level="high" if activity["critical_issues"] > 5 else "medium" if activity["critical_issues"] > 2 else "low",
                    activity_score=min(100, activity["security_score"] + 10)
                )
                for i, activity in enumerate(repository_data["recent_activity"][:10])
            ]
        
        # Create top performers and attention needed lists
        sorted_insights = sorted(repository_insights, key=lambda x: x.security_score, reverse=True)
        
        top_performers = [
            {
                "rank": i + 1,
                "repo_name": insight.full_name,
                "security_score": insight.security_score,
                "improvement_trend": 5.0  # Mock improvement
            }
            for i, insight in enumerate(sorted_insights[:5])
        ]
        
        needs_attention = [
            {
                "rank": len(sorted_insights) - i,
                "repo_name": insight.full_name,
                "security_score": insight.security_score,
                "improvement_trend": -2.0  # Mock decline
            }
            for i, insight in enumerate(reversed(sorted_insights[-5:]))
        ]
        
        # Language and niche statistics (mock data based on actual counts)
        language_stats = [
            {
                "language": lang,
                "repository_count": count,
                "avg_security_score": 75.0 + (hash(lang) % 20),  # Mock average
                "common_issues": ["SQL Injection", "XSS", "CSRF"]  # Mock issues
            }
            for lang, count in repository_data["repositories_by_language"].items()
        ]
        
        niche_stats = [
            {
                "niche": niche,
                "repository_count": count,
                "avg_security_score": 70.0 + (hash(niche) % 25),  # Mock average
                "top_risks": ["Authentication", "Authorization", "Input Validation"]  # Mock risks
            }
            for niche, count in repository_data["repositories_by_niche"].items()
        ]
        
        return RepositoriesResponse(
            total_repositories=repository_data["total_repositories"],
            active_repositories=repository_data["active_repositories"],
            repositories_by_language=repository_data["repositories_by_language"],
            repositories_by_niche=repository_data["repositories_by_niche"],
            security_score_distribution=repository_data["security_score_distribution"],
            repository_insights=repository_insights,
            top_performers=top_performers,
            needs_attention=needs_attention,
            language_stats=language_stats,
            niche_stats=niche_stats,
            recent_activity=[RecentActivity(
                scan_id=str(uuid.uuid4()),
                repo_name=activity["repo_name"],
                scan_type="manual",
                status="completed",
                created_at=datetime.fromisoformat(activity["last_scan"]) if activity["last_scan"] else utc_now(),
                security_score=int(activity["security_score"]),
                issues_found=activity["critical_issues"] * 3
            ) for activity in repository_data["recent_activity"]]
        )
        
    except Exception as e:
        logger.error(f"Error getting repository analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve repository analytics"
        )


@router.get("/realtime", response_model=RealTimeMetrics)
# @cached(ttl=CACHE_SHORT)  # Temporarily disabled to fix user data isolation
async def get_realtime_metrics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get real-time metrics for dashboard widgets
    
    Provides live system status and key metrics:
    - Active and queued scans
    - Recent issues
    - System health
    - Alert counts
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        real_time_data = await analytics_service.get_real_time_metrics()
        
        return RealTimeMetrics(
            active_scans=real_time_data["active_scans"],
            queued_scans=real_time_data["queued_scans"],
            recent_issues=real_time_data["recent_issues"],
            security_score_avg=real_time_data["security_score_avg"],
            compliance_status=real_time_data["compliance_status"],
            alert_count=real_time_data["alert_count"],
            system_health=real_time_data["system_health"],
            last_updated=datetime.fromisoformat(real_time_data["last_updated"])
        )
        
    except Exception as e:
        logger.error(f"Error getting real-time metrics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve real-time metrics"
        )


@router.get("/export")
async def export_analytics(
    format: str = Query("csv", description="Export format (csv, json, pdf)"),
    report_type: str = Query("overview", description="Report type"),
    time_range: TimeRange = Query(TimeRange.MONTH, description="Time range"),
    repo_full_name: Optional[str] = Query(None, description="Repository filter"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Export analytics data in various formats
    
    Supports multiple export formats:
    - CSV for spreadsheet analysis
    - JSON for programmatic use
    - PDF for reports (future implementation)
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        # Get data based on report type
        if report_type == "overview":
            metrics_data = await analytics_service.get_overview_metrics(time_range, repo_full_name)
            data = metrics_data
        elif report_type == "security":
            security_data = await analytics_service.get_security_metrics(time_range)
            data = security_data
        elif report_type == "repositories":
            repo_data = await analytics_service.get_repository_insights(repo_full_name)
            data = repo_data
        else:
            data = {"message": "Report type not supported"}
        
        # Export based on format
        if format == "json":
            json_data = json.dumps(data, indent=2, default=str)
            
            def generate():
                yield json_data
            
            return StreamingResponse(
                generate(),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=analytics_{report_type}_{time_range.value}.json"}
            )
            
        elif format == "csv":
            output = io.StringIO()
            
            if report_type == "overview" and isinstance(data, dict):
                writer = csv.writer(output)
                writer.writerow(["Metric", "Value"])
                for key, value in data.items():
                    writer.writerow([key, value])
            else:
                writer = csv.writer(output)
                writer.writerow(["Data"])
                writer.writerow([json.dumps(data)])
            
            def generate():
                output.seek(0)
                yield output.getvalue()
            
            return StreamingResponse(
                generate(),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=analytics_{report_type}_{time_range.value}.csv"}
            )
            
        elif format == "pdf":
            # PDF export would be implemented here
            # For now, return JSON as placeholder
            json_data = json.dumps(data, indent=2, default=str)
            
            def generate():
                yield json_data
            
            return StreamingResponse(
                generate(),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=analytics_{report_type}_{time_range.value}.json"}
            )
        
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported export format"
            )
            
    except Exception as e:
        logger.error(f"Error exporting analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export analytics data"
        )


# Legacy endpoints for backward compatibility (matching frontend expectations)
@router.get("/scan-analytics")
async def get_scan_analytics(
    repo_full_name: Optional[str] = Query(None),
    time_range: TimeRange = Query(TimeRange.WEEK),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Legacy endpoint - redirects to overview analytics"""
    return await get_overview_analytics(time_range, repo_full_name, db, current_user)


@router.get("/security-metrics") 
async def get_security_metrics_legacy(
    time_range: TimeRange = Query(TimeRange.MONTH),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Legacy endpoint - redirects to security analytics"""
    return await get_security_analytics(time_range, None, db, current_user)


@router.get("/team", response_model=TeamInsights)
@cached(ttl=CACHE_LONG)
async def get_team_analytics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get team analytics and insights
    
    Provides team-level analytics including:
    - Active contributors
    - Repository ownership distribution
    - Collaboration metrics
    - Scan frequency by team members
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        # Get team insights data
        team_data = await analytics_service.get_team_insights()
        
        # Convert to proper response format
        most_active = []
        for member_data in team_data["most_active_contributors"]:
            most_active.append({
                "user_id": member_data["user_id"],
                "username": member_data["username"],
                "repositories_count": member_data["repositories_count"],
                "recent_scans": member_data["recent_scans"],
                "issues_found": member_data["issues_found"],
                "issues_fixed": member_data["issues_fixed"],
                "avg_security_score": member_data["avg_security_score"],
                "last_activity": member_data["last_activity"]
            })
        
        return TeamInsights(
            total_team_members=team_data["total_team_members"],
            most_active_contributors=most_active,
            repository_ownership=team_data["repository_ownership"],
            scan_frequency=team_data["scan_frequency"],
            collaboration_score=team_data["collaboration_score"]
        )
        
    except Exception as e:
        logger.error(f"Error getting team analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve team analytics"
        )


@router.get("/custom", response_model=CustomAnalyticsResponse)
async def get_custom_analytics(
    start_date: datetime = Query(description="Analysis start date"),
    end_date: datetime = Query(description="Analysis end date"),
    metrics: str = Query(description="Comma-separated list of metrics"),
    repo_full_name: Optional[str] = Query(None, description="Repository filter"),
    group_by: Optional[str] = Query(None, description="Grouping dimension"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get custom analytics with flexible parameters
    
    Allows for custom date ranges, metric selection, and grouping:
    - Flexible time range selection
    - Custom metric combinations
    - Repository-specific or global analysis
    - Various grouping options
    """
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        # Parse metrics list
        metrics_list = [m.strip() for m in metrics.split(',')]
        
        # Create custom request
        request_data = {
            "start_date": start_date,
            "end_date": end_date,
            "metrics": metrics_list,
            "filters": {"repo_full_name": repo_full_name} if repo_full_name else {},
            "group_by": group_by
        }
        
        # Get custom analytics data
        custom_data = await analytics_service.get_custom_analytics(request_data)
        
        import uuid
        request_id = str(uuid.uuid4())
        
        return CustomAnalyticsResponse(
            request_id=request_id,
            data=custom_data,
            metadata={
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "metrics_requested": metrics_list,
                "repository_filter": repo_full_name,
                "group_by": group_by
            },
            generated_at=utc_now()
        )
        
    except Exception as e:
        logger.error(f"Error getting custom analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve custom analytics"
        )


@router.get("/issues")
async def get_issue_analytics(
    time_range: TimeRange = Query(TimeRange.MONTH),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get issue analytics (legacy endpoint)"""
    try:
        analytics_service = AnalyticsService(db, current_user.id)
        
        security_data = await analytics_service.get_security_metrics(time_range)
        top_issues_data = await analytics_service.get_top_issues(time_range, limit=20)
        
        return {
            "total_issues": security_data["total_vulnerabilities"],
            "issues_by_severity": {
                "critical": security_data["critical_issues"],
                "high": security_data["high_issues"],
                "medium": security_data["medium_issues"],
                "low": security_data["low_issues"]
            },
            "issues_by_category": security_data["vulnerabilities_by_category"],
            "issues_by_tool": security_data["vulnerabilities_by_tool"],
            "resolution_time_avg": security_data["mean_time_to_fix"],
            "most_common_issues": top_issues_data,
            "false_positive_rate": security_data["false_positive_rate"] / 100  # Convert to decimal
        }
        
    except Exception as e:
        logger.error(f"Error getting issue analytics for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve issue analytics"
        )