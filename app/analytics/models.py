"""
Analytics Response Models for DevSecureX API
Defines Pydantic models for analytics API responses
"""

from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any, Literal
from datetime import datetime
from enum import Enum


class TimeRange(str, Enum):
    """Supported time range filters"""
    DAY = "day"
    WEEK = "week" 
    MONTH = "month"
    QUARTER = "quarter"
    YEAR = "year"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    OWASP = "owasp"
    NIST = "nist"
    PCI_DSS = "pci-dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    ISO_27001 = "iso-27001"


class SeverityLevel(str, Enum):
    """Security issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Overview Analytics Models
class OverviewMetrics(BaseModel):
    """Key metrics for overview dashboard"""
    total_scans: int = Field(description="Total number of scans")
    total_repositories: int = Field(description="Total repositories connected")
    total_vulnerabilities: int = Field(description="Total vulnerabilities found")
    average_security_score: float = Field(description="Average security score across all repos")
    active_scans: int = Field(description="Currently running scans")
    fixed_issues: int = Field(description="Total resolved issues")
    compliance_score: float = Field(description="Overall compliance percentage")
    critical_issues: int = Field(description="Critical severity issues")


class TrendPoint(BaseModel):
    """Single data point for trend analysis"""
    date: datetime = Field(description="Date of the data point")
    value: float = Field(description="Metric value")
    secondary_value: Optional[float] = Field(None, description="Secondary metric value")


class TopIssue(BaseModel):
    """Top security issue information"""
    category: str = Field(description="Issue category")
    rule_id: str = Field(description="Security rule identifier")
    count: int = Field(description="Number of occurrences")
    severity: SeverityLevel = Field(description="Issue severity level")
    percentage: float = Field(description="Percentage of total issues")


class RecentActivity(BaseModel):
    """Recent scan activity"""
    scan_id: str = Field(description="Scan identifier")
    repo_name: str = Field(description="Repository name")
    scan_type: str = Field(description="Type of scan performed")
    status: str = Field(description="Scan status")
    created_at: datetime = Field(description="Scan creation timestamp")
    security_score: Optional[int] = Field(None, description="Security score achieved")
    issues_found: int = Field(description="Number of issues found")


class OverviewResponse(BaseModel):
    """Complete overview analytics response"""
    metrics: OverviewMetrics = Field(description="Key overview metrics")
    score_trend: List[TrendPoint] = Field(description="Security score trend over time")
    vulnerability_trend: List[TrendPoint] = Field(description="Vulnerability count trend")
    top_issues: List[TopIssue] = Field(description="Most common security issues")
    recent_activity: List[RecentActivity] = Field(description="Recent scan activity")
    scans_by_severity: Dict[str, int] = Field(description="Scan results by severity")
    scans_by_type: Dict[str, int] = Field(description="Scans by type distribution")


# Security Analytics Models
class SecurityMetrics(BaseModel):
    """Detailed security metrics"""
    total_vulnerabilities: int = Field(description="Total vulnerabilities found")
    critical_issues: int = Field(description="Critical severity issues")
    high_issues: int = Field(description="High severity issues")
    medium_issues: int = Field(description="Medium severity issues")
    low_issues: int = Field(description="Low severity issues")
    security_score_avg: float = Field(description="Average security score")
    vulnerabilities_by_category: Dict[str, int] = Field(description="Vulnerabilities by category")
    vulnerabilities_by_tool: Dict[str, int] = Field(description="Vulnerabilities by scanning tool")
    false_positive_rate: float = Field(description="False positive percentage")
    mean_time_to_fix: Optional[float] = Field(None, description="Average time to fix issues (days)")


class VulnerabilityTrend(BaseModel):
    """Vulnerability trend data point"""
    date: datetime = Field(description="Date of measurement")
    vulnerabilities: int = Field(description="Number of vulnerabilities")
    critical_count: int = Field(description="Critical vulnerabilities")
    high_count: int = Field(description="High severity vulnerabilities")
    security_score: float = Field(description="Security score at this point")
    scans_completed: int = Field(description="Scans completed")


class RiskAssessment(BaseModel):
    """Security risk assessment"""
    overall_risk_score: float = Field(description="Overall risk score (0-100)")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(description="Risk level classification")
    risk_factors: List[str] = Field(description="Key risk factors identified")
    recommendations: List[str] = Field(description="Security recommendations")


class SecurityResponse(BaseModel):
    """Complete security analytics response"""
    metrics: SecurityMetrics = Field(description="Security metrics summary")
    trend_data: List[VulnerabilityTrend] = Field(description="Historical vulnerability trends")
    risk_assessment: RiskAssessment = Field(description="Current risk assessment")
    critical_issues_details: List[TopIssue] = Field(description="Critical issues breakdown")


# Compliance Analytics Models
class ComplianceRequirement(BaseModel):
    """Individual compliance requirement"""
    requirement_id: str = Field(description="Requirement identifier")
    name: str = Field(description="Requirement name")
    description: str = Field(description="Requirement description")
    status: Literal["compliant", "partial", "non-compliant", "not-applicable"] = Field(description="Compliance status")
    score: float = Field(description="Compliance score percentage")
    issues_count: int = Field(description="Number of related issues")
    last_assessed: datetime = Field(description="Last assessment date")


class ComplianceCategory(BaseModel):
    """Compliance framework category"""
    category_id: str = Field(description="Category identifier")
    name: str = Field(description="Category name")
    score: float = Field(description="Category compliance score")
    status: Literal["compliant", "partial", "non-compliant"] = Field(description="Category status")
    requirements: List[ComplianceRequirement] = Field(description="Individual requirements")
    issues_count: int = Field(description="Total issues in category")


class ComplianceReport(BaseModel):
    """Complete compliance report"""
    framework: ComplianceFramework = Field(description="Compliance framework")
    overall_score: float = Field(description="Overall compliance percentage")
    requirements_met: int = Field(description="Number of requirements met")
    total_requirements: int = Field(description="Total number of requirements")
    categories: List[ComplianceCategory] = Field(description="Compliance categories breakdown")
    last_updated: datetime = Field(description="Last compliance assessment")
    trending_up: bool = Field(description="Whether compliance is improving")


# Trends Analytics Models
class TrendMetric(BaseModel):
    """Trend analysis for a specific metric"""
    metric_name: str = Field(description="Name of the metric")
    current_value: float = Field(description="Current metric value")
    previous_value: float = Field(description="Previous period value")
    change_percentage: float = Field(description="Percentage change")
    trend_direction: Literal["up", "down", "stable"] = Field(description="Trend direction")
    data_points: List[TrendPoint] = Field(description="Historical data points")


class PerformanceMetrics(BaseModel):
    """Performance and efficiency metrics"""
    avg_scan_duration: float = Field(description="Average scan duration in minutes")
    scan_success_rate: float = Field(description="Percentage of successful scans")
    issue_resolution_rate: float = Field(description="Percentage of resolved issues")
    new_issues_trend: List[TrendPoint] = Field(description="New issues over time")
    fixed_issues_trend: List[TrendPoint] = Field(description="Fixed issues over time")


class TrendsResponse(BaseModel):
    """Complete trends analytics response"""
    security_trends: TrendMetric = Field(description="Security score trends")
    vulnerability_trends: TrendMetric = Field(description="Vulnerability count trends")
    compliance_trends: TrendMetric = Field(description="Compliance score trends")
    scan_volume_trends: TrendMetric = Field(description="Scan volume trends")
    performance_metrics: PerformanceMetrics = Field(description="Performance metrics")
    period_comparison: Dict[str, Any] = Field(description="Period-over-period comparison")


# Repository Analytics Models
class RepositoryInsight(BaseModel):
    """Individual repository analytics"""
    repo_id: int = Field(description="Repository ID")
    full_name: str = Field(description="Repository full name")
    language: Optional[str] = Field(None, description="Primary programming language")
    niche: str = Field(description="Repository niche/category")
    security_score: float = Field(description="Current security score")
    last_scan: Optional[datetime] = Field(None, description="Last scan timestamp")
    total_scans: int = Field(description="Total number of scans")
    vulnerabilities_count: int = Field(description="Current vulnerabilities count")
    critical_issues: int = Field(description="Critical issues count")
    compliance_score: float = Field(description="Compliance score")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(description="Risk level")
    activity_score: float = Field(description="Repository activity score")


class RepositoryRanking(BaseModel):
    """Repository ranking information"""
    rank: int = Field(description="Repository rank")
    repo_name: str = Field(description="Repository name")
    security_score: float = Field(description="Security score")
    improvement_trend: float = Field(description="Score improvement percentage")


class LanguageStats(BaseModel):
    """Programming language statistics"""
    language: str = Field(description="Programming language")
    repository_count: int = Field(description="Number of repositories")
    avg_security_score: float = Field(description="Average security score")
    common_issues: List[str] = Field(description="Most common issues for this language")


class NicheStats(BaseModel):
    """Repository niche statistics"""
    niche: str = Field(description="Repository niche/category")
    repository_count: int = Field(description="Number of repositories")
    avg_security_score: float = Field(description="Average security score")
    top_risks: List[str] = Field(description="Top security risks for this niche")


class RepositoriesResponse(BaseModel):
    """Complete repositories analytics response"""
    total_repositories: int = Field(description="Total repositories count")
    active_repositories: int = Field(description="Active repositories count")
    repositories_by_language: Dict[str, int] = Field(description="Repositories by language")
    repositories_by_niche: Dict[str, int] = Field(description="Repositories by niche")
    security_score_distribution: Dict[str, int] = Field(description="Security score distribution")
    repository_insights: List[RepositoryInsight] = Field(description="Individual repository details")
    top_performers: List[RepositoryRanking] = Field(description="Top performing repositories")
    needs_attention: List[RepositoryRanking] = Field(description="Repositories needing attention")
    language_stats: List[LanguageStats] = Field(description="Programming language statistics")
    niche_stats: List[NicheStats] = Field(description="Repository niche statistics")
    recent_activity: List[RecentActivity] = Field(description="Recent repository activity")


# Export Models
class ExportRequest(BaseModel):
    """Analytics export request parameters"""
    format: Literal["csv", "json", "pdf"] = Field(description="Export format")
    report_type: Literal["overview", "security", "compliance", "trends", "repositories"] = Field(description="Report type")
    time_range: TimeRange = Field(description="Time range for data")
    repo_full_name: Optional[str] = Field(None, description="Specific repository filter")
    include_raw_data: bool = Field(False, description="Include raw data in export")


class ExportJob(BaseModel):
    """Export job status"""
    job_id: str = Field(description="Export job identifier")
    status: Literal["queued", "processing", "completed", "failed"] = Field(description="Job status")
    progress: float = Field(description="Export progress percentage")
    download_url: Optional[str] = Field(None, description="Download URL when ready")
    created_at: datetime = Field(description="Job creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Download expiration")
    error_message: Optional[str] = Field(None, description="Error message if failed")


# Real-time Analytics Models
class RealTimeMetrics(BaseModel):
    """Real-time metrics for dashboard widgets"""
    active_scans: int = Field(description="Currently running scans")
    queued_scans: int = Field(description="Scans in queue")
    recent_issues: int = Field(description="Issues found in last 24 hours")
    security_score_avg: float = Field(description="Current average security score")
    compliance_status: Dict[str, float] = Field(description="Compliance scores by framework")
    alert_count: int = Field(description="Active alerts count")
    system_health: Literal["healthy", "warning", "critical"] = Field(description="Overall system health")
    last_updated: datetime = Field(description="Last metrics update timestamp")


# Team Analytics Models (for multi-user insights)
class TeamMemberInsight(BaseModel):
    """Individual team member analytics"""
    user_id: int = Field(description="User identifier")
    username: str = Field(description="Username")
    repositories_count: int = Field(description="Number of repositories owned")
    recent_scans: int = Field(description="Recent scans performed")
    issues_found: int = Field(description="Total issues found")
    issues_fixed: int = Field(description="Issues resolved")
    avg_security_score: float = Field(description="Average security score")
    last_activity: datetime = Field(description="Last activity timestamp")


class TeamInsights(BaseModel):
    """Team-wide analytics"""
    total_team_members: int = Field(description="Total team members")
    most_active_contributors: List[TeamMemberInsight] = Field(description="Most active team members")
    repository_ownership: Dict[str, int] = Field(description="Repository ownership distribution")
    scan_frequency: Dict[str, int] = Field(description="Scan frequency by user")
    collaboration_score: float = Field(description="Team collaboration score")


# Custom Analytics Models
class CustomMetricRequest(BaseModel):
    """Custom analytics request"""
    start_date: datetime = Field(description="Analysis start date")
    end_date: datetime = Field(description="Analysis end date")
    metrics: List[str] = Field(description="Requested metrics")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Additional filters")
    group_by: Optional[str] = Field(None, description="Grouping dimension")


class CustomAnalyticsResponse(BaseModel):
    """Custom analytics response"""
    request_id: str = Field(description="Request identifier")
    data: Dict[str, Any] = Field(description="Analytics data")
    metadata: Dict[str, Any] = Field(description="Response metadata")
    generated_at: datetime = Field(description="Response generation timestamp")