"""
CLI Scan Pydantic Schemas - Request/Response models for DevSecureX CLI API
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from enum import Enum


class ScanMode(str, Enum):
    """Scan mode enumeration"""
    FAST = "fast"
    COMPREHENSIVE = "comprehensive"


class ScanScope(str, Enum):
    """Scan scope enumeration"""
    CODE_ONLY = "code-only"
    DEPS = "deps"
    CODE_DEPS = "code+deps"
    FULL = "full"


class CLIScanRequest(BaseModel):
    """
    CLI scan request model with comprehensive validation
    
    MAXIMUM SECURITY COVERAGE: All CLI scans now run with comprehensive mode and full scope
    to ensure complete A-to-Z security analysis with ALL available 12+ security tools.
    
    Legacy parameters scan_mode and scan_scope are maintained for backward compatibility
    but are internally overridden to guarantee maximum security coverage:
    - mode: Always forced to 'comprehensive' 
    - scope: Always forced to 'full' (code + dependencies + infrastructure)
    """
    code_files: Dict[str, str] = Field(
        ..., 
        description="Dictionary of file paths to their content",
        example={"vulnerable_code.py": "exec(user_input)"}
    )
    scan_mode: Optional[ScanMode] = Field(
        default=ScanMode.COMPREHENSIVE,
        description="DEPRECATED: All CLI scans now run in comprehensive mode for maximum security coverage. This parameter is ignored."
    )
    scan_scope: Optional[ScanScope] = Field(
        default=ScanScope.FULL, 
        description="DEPRECATED: All CLI scans now run with full scope (code+deps+infrastructure). This parameter is ignored."
    )
    include_custom_rules: bool = Field(
        default=False,
        description="Include user's custom rules"
    )
    include_community_rules: bool = Field(
        default=False,
        description="Include community rules"
    )
    selected_tools: Optional[List[str]] = Field(
        default=None,
        description="Specific tools to run (if None, auto-select based on languages)",
        example=["semgrep", "bandit", "eslint"]
    )
    selected_custom_rule_ids: Optional[List[str]] = Field(
        default=None,
        description="Specific custom rule IDs to include",
        example=["rule-123", "rule-456"]
    )
    selected_community_rule_ids: Optional[List[str]] = Field(
        default=None,
        description="Specific community rule IDs to include", 
        example=["community-rule-789"]
    )
    niche: Optional[str] = Field(
        default="all",
        description="Security niche for specialized rule loading (ai, blockchain, iot, web3, cloud, api, etc.)",
        example="ai"
    )
    timeout_per_tool: Optional[int] = Field(
        default=600,
        description="Timeout per tool in seconds (default: 600s/10min)",
        ge=60,
        le=1800
    )
    max_concurrent_tools: Optional[int] = Field(
        default=None,
        description="Maximum number of tools to run concurrently (if None, auto-detect based on system)",
        ge=1,
        le=8
    )
    compliance_frameworks: Optional[List[str]] = Field(
        default=None,
        description="Compliance frameworks to check against (owasp, pci, sox, etc.)",
        example=["owasp", "pci"]
    )
    
    @field_validator('code_files')
    @classmethod
    def validate_code_files(cls, v):
        if not v:
            raise ValueError("At least one code file must be provided")
        if len(v) > 100:
            raise ValueError("Maximum 100 files allowed per scan")
        
        total_size = sum(len(content) for content in v.values())
        if total_size > 50 * 1024 * 1024:  # 50MB limit
            raise ValueError("Total code size exceeds 50MB limit")
        
        return v


class CLIScanResponse(BaseModel):
    """CLI scan response model with full parity to main scan output plus enterprise enhancements"""
    scan_id: str
    total_score: float
    scores: Dict[str, float]
    issues: List[Dict[str, Any]]
    scan_metadata: Dict[str, Any]
    statistics: Dict[str, Any]
    compliance: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Compliance mappings (OWASP, CWE, etc.)"
    )
    sbom: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Software Bill of Materials (for full scope scans)"
    )
    performance_metrics: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Performance metrics including tool execution times"
    )
    risk_assessment: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Risk assessment and scoring details"
    )


class CLIScanResultResponse(BaseModel):
    """Response model for CLI scan result retrieval"""
    scan_id: str
    user_id: int
    scan_metadata: Dict[str, Any]
    results_data: Dict[str, Any]
    file_count: int
    total_score: float
    issue_counts: Dict[str, int]
    total_issues: int
    tools_used: List[str]
    scan_duration: float
    status: str
    compliance_data: Optional[Dict[str, Any]] = None
    risk_assessment: Optional[Dict[str, Any]] = None
    languages_detected: Optional[List[str]] = None
    dependency_files_count: int
    created_at: datetime
    updated_at: Optional[datetime] = None


class CLIActivityLogRequest(BaseModel):
    """Request model for CLI activity logging"""
    activity_type: str = Field(
        ...,
        description="Type of activity being logged",
        example="scan_start"
    )
    command: Optional[str] = Field(
        None,
        description="CLI command executed",
        max_length=500
    )
    parameters: Optional[Dict[str, Any]] = Field(
        None,
        description="Command parameters and options"
    )
    endpoint: Optional[str] = Field(
        None,
        description="API endpoint accessed",
        max_length=100
    )
    scan_id: Optional[str] = Field(
        None,
        description="Associated scan ID if applicable"
    )
    response_status: Optional[str] = Field(
        None,
        description="Response status (success, error, timeout)",
        max_length=20
    )
    http_status_code: Optional[int] = Field(
        None,
        description="HTTP response code"
    )
    duration: Optional[float] = Field(
        None,
        description="Operation duration in seconds"
    )
    error_details: Optional[Dict[str, Any]] = Field(
        None,
        description="Detailed error information"
    )
    error_type: Optional[str] = Field(
        None,
        description="Error classification",
        max_length=100
    )
    client_info: Optional[Dict[str, Any]] = Field(
        None,
        description="OS, CLI version, IP address, user agent"
    )


class CLIUsageStatsResponse(BaseModel):
    """Response model for CLI usage statistics"""
    user_id: int
    date_range: str
    total_scans: int
    successful_scans: int
    failed_scans: int
    timeout_scans: int
    cancelled_scans: int
    total_issues_found: int
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    total_scan_duration: float
    avg_scan_duration: float
    min_scan_duration: Optional[float]
    max_scan_duration: Optional[float]
    total_files_scanned: int
    avg_files_per_scan: float
    tools_usage_count: Dict[str, int]
    file_types_scanned: Dict[str, int]
    languages_detected: Dict[str, int]
    compliance_scores: Optional[Dict[str, float]]
    risk_trends: Optional[Dict[str, Any]]
    success_rate: float
    avg_issues_per_scan: float


class CLIScanHistoryResponse(BaseModel):
    """Response model for scan history with pagination"""
    scans: List[CLIScanResultResponse]
    total_count: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_previous: bool


class CLIUserStatsRequest(BaseModel):
    """Request model for user statistics with date filtering"""
    start_date: Optional[datetime] = Field(
        None,
        description="Start date for statistics (ISO format)"
    )
    end_date: Optional[datetime] = Field(
        None,
        description="End date for statistics (ISO format)"
    )
    aggregation: Optional[str] = Field(
        default="daily",
        description="Aggregation level (daily, weekly, monthly)",
        pattern="^(daily|weekly|monthly)$"
    )


class CLIStoreResultsRequest(BaseModel):
    """Request model for storing scan results"""
    scan_id: str = Field(
        ...,
        description="Unique scan identifier"
    )
    scan_metadata: Dict[str, Any] = Field(
        ...,
        description="Scan metadata including tools, mode, scope"
    )
    results_data: Dict[str, Any] = Field(
        ...,
        description="Complete scan results data"
    )


class CLIErrorResponse(BaseModel):
    """Standard error response model"""
    error: str
    detail: str
    timestamp: datetime
    scan_id: Optional[str] = None


class CLIHealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: datetime
    services: Dict[str, Any]
    version: str


class CLIScanSessionRequest(BaseModel):
    """Request model for creating scan sessions"""
    name: Optional[str] = Field(
        default=None,
        description="Optional session name for identification",
        max_length=255,
        example="Final Test Session"
    )
    operation_type: str = Field(
        default="general",
        description="Type of operation to track"
    )
    total_operations: int = Field(
        default=1,
        description="Total number of operations expected"
    )
    session_data: Optional[Dict[str, Any]] = Field(
        None,
        description="Temporary session state data"
    )
    client_info: Optional[Dict[str, Any]] = Field(
        None,
        description="Client environment information"
    )


class CLIScanSessionResponse(BaseModel):
    """Response model for scan sessions"""
    session_id: str
    name: str
    user_id: int
    status: str
    current_operation: Optional[str]
    operations_completed: List[str]
    total_operations: int
    progress_percentage: float
    started_at: datetime
    last_activity: datetime
    expires_at: datetime


class CLIBatchOperationRequest(BaseModel):
    """Request model for batch operations"""
    operation_type: str = Field(
        ...,
        description="Type of batch operation"
    )
    items: List[Dict[str, Any]] = Field(
        ...,
        description="List of items to process in batch"
    )
    batch_options: Optional[Dict[str, Any]] = Field(
        None,
        description="Batch processing options"
    )

    @field_validator('items')
    @classmethod
    def validate_items(cls, v):
        if not v:
            raise ValueError("At least one item must be provided for batch operation")
        if len(v) > 50:  # Reasonable batch size limit
            raise ValueError("Maximum 50 items allowed per batch operation")
        return v


class CLIBatchOperationResponse(BaseModel):
    """Response model for batch operations"""
    batch_id: str
    operation_type: str
    total_items: int
    processed_items: int
    successful_items: int
    failed_items: int
    results: List[Dict[str, Any]]
    errors: List[Dict[str, Any]]
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str