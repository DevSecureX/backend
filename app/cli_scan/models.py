"""
CLI Scan Database Models - Enterprise-grade data persistence for DevSecureX CLI
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON, Float, Index, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from core.database import Base
from datetime import datetime, timezone
import enum


class ScanStatus(str, enum.Enum):
    """Enum for CLI scan status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ActivityType(str, enum.Enum):
    """Enum for CLI activity types"""
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_ERROR = "scan_error"
    SCAN_TIMEOUT = "scan_timeout"
    SCAN_CANCELLED = "scan_cancelled"
    COMMAND_EXECUTED = "command_executed"
    RESULTS_RETRIEVED = "results_retrieved"
    USAGE_STATS_ACCESSED = "usage_stats_accessed"
    API_ERROR = "api_error"


class CLIScanResult(Base):
    """
    Comprehensive CLI scan results storage with full data persistence
    
    This table stores complete scan results with metadata, issues, scores,
    compliance mappings, and performance metrics for enterprise-grade
    data synchronization across systems.
    """
    __tablename__ = "cli_scan_results"
    
    # Primary identifiers
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(64), unique=True, nullable=False, index=True)  # Format: cli-{uuid}-{timestamp}
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Scan metadata (comprehensive scan information)
    scan_metadata = Column(JSON, nullable=False)  # scan_type, mode, scope, tools_used, etc.
    
    # Results data (full scan results with issues, scores, compliance)
    results_data = Column(JSON, nullable=False)  # Complete scan output including issues array
    
    # Key metrics (indexed for fast querying)
    file_count = Column(Integer, nullable=False, default=0, index=True)
    total_score = Column(Float, nullable=False, default=0.0, index=True)
    
    # Issue statistics (stored as JSON for flexibility)
    issue_counts = Column(JSON, nullable=False)  # {critical: 5, high: 10, medium: 15, low: 20, info: 5}
    total_issues = Column(Integer, nullable=False, default=0, index=True)  # Denormalized for fast queries
    
    # Tool and performance data
    tools_used = Column(JSON, nullable=False)  # ["semgrep", "bandit", "trivy", ...]
    scan_duration = Column(Float, nullable=False, default=0.0)  # Duration in seconds
    
    # Status and error tracking
    status = Column(Enum(ScanStatus, values_callable=lambda obj: [e.value for e in obj]), nullable=False, default=ScanStatus.COMPLETED, index=True)
    error_message = Column(Text, nullable=True)
    
    # Compliance and risk data
    compliance_data = Column(JSON, nullable=True)  # OWASP, PCI, SOX compliance mappings
    risk_assessment = Column(JSON, nullable=True)  # Risk scores by category
    
    # File and language analysis
    languages_detected = Column(JSON, nullable=True)  # ["python", "javascript", "go"]
    dependency_files_count = Column(Integer, nullable=False, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="cli_scan_results")
    activity_logs = relationship("CLIActivityLog", back_populates="scan_result", cascade="all, delete-orphan")
    
    # Composite indexes for performance optimization
    __table_args__ = (
        Index('idx_cli_scan_user_date', 'user_id', 'created_at'),
        Index('idx_cli_scan_status_date', 'status', 'created_at'),
        Index('idx_cli_scan_score_issues', 'total_score', 'total_issues'),
        Index('idx_cli_scan_user_status', 'user_id', 'status'),
        Index('idx_cli_scan_duration_performance', 'scan_duration', 'file_count'),
        Index('idx_cli_scan_cleanup', 'created_at', 'status'),  # For data retention cleanup
    )


class CLIActivityLog(Base):
    """
    Comprehensive CLI activity logging for analytics and monitoring
    
    Tracks all CLI operations including commands, scan activities, errors,
    and system interactions for enterprise audit trails and user behavior analysis.
    """
    __tablename__ = "cli_activity_logs"
    
    # Primary identifiers
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("cli_scan_results.scan_id"), nullable=True, index=True)
    
    # Activity classification
    activity_type = Column(Enum(ActivityType, values_callable=lambda obj: [e.value for e in obj]), nullable=False, index=True)
    
    # Command and operation details
    command = Column(String(500), nullable=True)  # CLI command executed
    parameters = Column(JSON, nullable=True)  # Command parameters and options
    endpoint = Column(String(100), nullable=True)  # API endpoint accessed
    
    # Response and status information
    response_status = Column(String(20), nullable=True)  # success, error, timeout
    http_status_code = Column(Integer, nullable=True)  # HTTP response code
    duration = Column(Float, nullable=True)  # Operation duration in seconds
    
    # Error tracking
    error_details = Column(JSON, nullable=True)  # Detailed error information
    error_type = Column(String(100), nullable=True, index=True)  # Error classification
    
    # Client environment information
    client_info = Column(JSON, nullable=True)  # OS, CLI version, IP address, user agent
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    user = relationship("User", back_populates="cli_activity_logs")
    scan_result = relationship("CLIScanResult", back_populates="activity_logs")
    
    # Composite indexes for analytics and monitoring
    __table_args__ = (
        Index('idx_cli_activity_user_type_date', 'user_id', 'activity_type', 'created_at'),
        Index('idx_cli_activity_scan_type', 'scan_id', 'activity_type'),
        Index('idx_cli_activity_error_analysis', 'error_type', 'created_at'),
        Index('idx_cli_activity_performance', 'duration', 'activity_type'),
        Index('idx_cli_activity_cleanup', 'created_at'),  # For log retention
    )


class CLIUsageStats(Base):
    """
    Aggregated CLI usage statistics for performance analytics and insights
    
    Pre-calculated statistics by user and date for fast dashboard queries
    and trend analysis. Updated via background jobs and real-time aggregation.
    """
    __tablename__ = "cli_usage_stats"
    
    # Primary identifiers
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    date = Column(DateTime(timezone=True), nullable=False, index=True)  # Date for aggregation (daily/weekly/monthly)
    
    # Scan statistics
    total_scans = Column(Integer, nullable=False, default=0)
    successful_scans = Column(Integer, nullable=False, default=0)
    failed_scans = Column(Integer, nullable=False, default=0)
    timeout_scans = Column(Integer, nullable=False, default=0)
    cancelled_scans = Column(Integer, nullable=False, default=0)
    
    # Issue and security metrics
    total_issues_found = Column(Integer, nullable=False, default=0)
    critical_issues = Column(Integer, nullable=False, default=0)
    high_issues = Column(Integer, nullable=False, default=0)
    medium_issues = Column(Integer, nullable=False, default=0)
    low_issues = Column(Integer, nullable=False, default=0)
    
    # Performance metrics
    total_scan_duration = Column(Float, nullable=False, default=0.0)  # Total time in seconds
    avg_scan_duration = Column(Float, nullable=False, default=0.0)
    min_scan_duration = Column(Float, nullable=True)
    max_scan_duration = Column(Float, nullable=True)
    
    # File and language analysis
    total_files_scanned = Column(Integer, nullable=False, default=0)
    avg_files_per_scan = Column(Float, nullable=False, default=0.0)
    
    # Tool usage statistics (JSON for flexibility)
    tools_usage_count = Column(JSON, nullable=False)  # {"semgrep": 15, "bandit": 12, ...}
    
    # Language and file type analysis
    file_types_scanned = Column(JSON, nullable=False)  # {"python": 25, "javascript": 18, ...}
    languages_detected = Column(JSON, nullable=False)  # Language frequency analysis
    
    # Compliance and risk trends
    compliance_scores = Column(JSON, nullable=True)  # Average compliance scores by framework
    risk_trends = Column(JSON, nullable=True)  # Risk assessment trends
    
    # Success and efficiency metrics
    success_rate = Column(Float, nullable=False, default=0.0)  # Percentage of successful scans
    avg_issues_per_scan = Column(Float, nullable=False, default=0.0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    user = relationship("User", back_populates="cli_usage_stats")
    
    # Composite indexes for analytics performance
    __table_args__ = (
        Index('idx_cli_stats_user_date', 'user_id', 'date'),
        Index('idx_cli_stats_success_rate', 'success_rate', 'total_scans'),
        Index('idx_cli_stats_performance', 'avg_scan_duration', 'avg_files_per_scan'),
        Index('idx_cli_stats_issues', 'total_issues_found', 'critical_issues'),
        Index('idx_cli_stats_date_range', 'date'),  # For date range queries
        Index('idx_cli_stats_cleanup', 'created_at'),  # For data retention
    )


class CLIScanSession(Base):
    """
    CLI scan session tracking for multi-step operations and state management
    
    Tracks ongoing scan sessions, temporary states, and multi-part operations
    for enterprise-grade CLI workflow management.
    """
    __tablename__ = "cli_scan_sessions"
    
    # Primary identifiers
    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Session identification and metadata
    name = Column(String(255), nullable=False, default="Unnamed Session")  # User-provided session name
    status = Column(String(20), nullable=False, default="active", index=True)  # active, completed, expired, cancelled
    session_data = Column(JSON, nullable=True)  # Temporary session state
    
    # Operation tracking
    current_operation = Column(String(100), nullable=True)  # Current operation in progress
    operations_completed = Column(JSON, nullable=False)  # List of completed operations
    total_operations = Column(Integer, nullable=False, default=1)
    
    # Progress and timing
    progress_percentage = Column(Float, nullable=False, default=0.0)
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_activity = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)  # Session expiration
    
    # Client information
    client_info = Column(JSON, nullable=True)  # Client details for session management
    
    # Relationships
    user = relationship("User", back_populates="cli_scan_sessions")
    
    # Indexes for session management
    __table_args__ = (
        Index('idx_cli_session_user_status', 'user_id', 'status'),
        Index('idx_cli_session_activity', 'last_activity', 'status'),
        Index('idx_cli_session_cleanup', 'expires_at', 'status'),
    )