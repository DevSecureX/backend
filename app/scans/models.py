from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Float, func, Text, Boolean, Index, ForeignKeyConstraint
from sqlalchemy.dialects.postgresql import UUID
from core.database import Base
import uuid

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repo_full_name = Column(String(255), nullable=False, index=True)
    user_id = Column(Integer, nullable=False)  # Add user_id to create composite FK
    branch = Column(String(255), nullable=False)
    mode = Column(String(50), nullable=False, default="fast")
    scope = Column(String(50), nullable=False, default="code+deps")
    scan_type = Column(String(50), nullable=False, default="manual", index=True)
    niche = Column(String(50), nullable=False)
    
    # Scoring
    total_score = Column(Integer, nullable=False, default=0)
    code_score = Column(Float, nullable=True)
    deps_score = Column(Float, nullable=True)
    secrets_score = Column(Float, nullable=True)
    configs_score = Column(Float, nullable=True)
    
    # Metadata
    commit_sha = Column(String(40), nullable=True)
    pr_number = Column(Integer, nullable=True)
    scan_duration = Column(Integer, nullable=True)
    tools_used = Column(JSON, nullable=True)
    sbom = Column(JSON, nullable=True)  # Added for SBOM storage
    
    # Status
    status = Column(String(20), nullable=False, default="completed", index=True)
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Indexes and Constraints
    __table_args__ = (
        ForeignKeyConstraint(['repo_full_name', 'user_id'], ['repos.full_name', 'repos.user_id']),
        Index('idx_scan_repo_created', 'repo_full_name', 'created_at'),
        Index('idx_scan_status_type', 'status', 'scan_type'),
        Index('idx_scan_pr', 'pr_number'),  # Added for PR scanning
        Index('idx_scan_commit', 'commit_sha'),  # Added for commit tracking
        Index('idx_scan_user_repo', 'user_id', 'repo_full_name')  # Added for composite FK performance
    )

class ScanSummary(Base):
    __tablename__ = "scan_summaries"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Category-wise counts
    category = Column(String(50), nullable=False)
    tool_name = Column(String(50), nullable=False)
    
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    
    total_issues = Column(Integer, nullable=False, default=0)
    sample_issues = Column(JSON, nullable=True)  # Already JSONB via migration
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Index for quick lookups
    __table_args__ = (
        Index('idx_summary_scan_category', 'scan_id', 'category'),
    )

class AIPatternCache(Base):
    __tablename__ = "ai_pattern_cache"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    pattern_hash = Column(String(64), nullable=False, unique=True, index=True)
    rule_id = Column(String(100), nullable=False)
    tool = Column(String(50), nullable=False)
    category = Column(String(50), nullable=False)
    
    # AI Generated Content
    explanation = Column(Text, nullable=False)
    fix_suggestion = Column(Text, nullable=True)
    fixed_code = Column(Text, nullable=True)  # Added for AI-generated fixes
    testing_approach = Column(Text, nullable=True)
    architectural_fix = Column(Text, nullable=True)  # Added for architectural fixes
    owasp_mapping = Column(JSON, nullable=True)
    
    # Metadata
    usage_count = Column(Integer, nullable=False, default=1)
    confidence_score = Column(Float, nullable=True)
    prompt_version = Column(String(10), nullable=False, default="v1.0")
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repo_full_name = Column(String(255), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)  # Added to match prod-release
    scan_type = Column(String(50), nullable=False)
    priority = Column(Integer, nullable=False, default=2)
    
    # Job Data
    job_data = Column(JSON, nullable=False)
    
    # PR specific field to match Scan model
    pr_number = Column(Integer, nullable=True, index=True)
    
    # Link to completed scan
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    
    # Status
    status = Column(String(20), nullable=False, default="queued", index=True)
    assigned_worker = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=3)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Indexes and Constraints
    __table_args__ = (
        ForeignKeyConstraint(['repo_full_name', 'user_id'], ['repos.full_name', 'repos.user_id']),
        Index('idx_job_status_priority', 'status', 'priority'),
        Index('idx_job_repo_created', 'repo_full_name', 'created_at'),
        Index('idx_job_pr', 'pr_number'),  # Added for PR job tracking
        Index('idx_job_user_repo', 'user_id', 'repo_full_name'),  # Added for composite FK performance
        Index('idx_job_status_started', 'status', 'started_at'),  # Added for stuck scan cleanup optimization
    )

class ComplianceMapping(Base):
    __tablename__ = "compliance_mappings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Compliance Frameworks
    owasp_category = Column(String(100), nullable=True)
    cwe_id = Column(String(20), nullable=True)
    nist_id = Column(String(20), nullable=True)  # Added for NIST compliance
    pci_dss_id = Column(String(20), nullable=True)  # Added for PCI DSS
    hipaa_id = Column(String(20), nullable=True)  # Added for HIPAA
    gdpr_article = Column(String(20), nullable=True)  # Added for GDPR
    iso_27001_id = Column(String(20), nullable=True)  # Added for ISO 27001
    
    # Business Context
    business_impact = Column(String(20), nullable=False, default="medium")
    exploitability = Column(String(20), nullable=False, default="medium")
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class IssueFeedback(Base):
    __tablename__ = "issue_feedback"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    issue_hash = Column(String(64), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    is_false_positive = Column(Boolean, nullable=False)
    user_id = Column(String(36), nullable=False, index=True)
    feedback_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_feedback_issue', 'issue_hash'),
        Index('idx_issue_feedback_user', 'user_id'),
    )

class ScanTrends(Base):
    __tablename__ = "scan_trends"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    repo_full_name = Column(String(255), nullable=False)
    period_start = Column(DateTime(timezone=True), nullable=False)
    period_end = Column(DateTime(timezone=True), nullable=False)
    avg_score = Column(Float, nullable=True)
    score_change = Column(Float, nullable=True)
    issues_fixed = Column(Integer, nullable=True)
    issues_introduced = Column(Integer, nullable=True)
    top_issue_types = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_trends_repo_period', 'repo_full_name', 'period_start'),
        Index('unique_trends_repo_period', 'repo_full_name', 'period_start', 'period_end', unique=True),
    )

# CommunityRules and CommunityRuleVotes models have been moved to custom_rules.models

class PRSecurityComment(Base):
    __tablename__ = "pr_security_comments"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    repo_full_name = Column(String(255), nullable=False)
    pr_number = Column(Integer, nullable=False)
    comment_id = Column(String(255), nullable=True)  # GitHub comment ID
    comment_type = Column(String(50), nullable=False)  # 'review', 'comment', 'inline'
    comment_url = Column(String(500), nullable=True)
    posted_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
    
    __table_args__ = (
        Index('idx_pr_comment_scan', 'scan_id'),
        Index('idx_pr_comment_pr', 'repo_full_name', 'pr_number'),
    )

class PRSecurityReview(Base):
    __tablename__ = "pr_security_reviews"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    repo_full_name = Column(String(255), nullable=False)
    pr_number = Column(Integer, nullable=False)
    review_id = Column(String(255), nullable=True)  # GitHub review ID
    review_action = Column(String(50), nullable=False)  # APPROVE, REQUEST_CHANGES, COMMENT
    review_url = Column(String(500), nullable=True)
    
    # Review metadata
    security_score = Column(Integer, nullable=False)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    must_fix_count = Column(Integer, nullable=False, default=0)
    inline_comments_count = Column(Integer, nullable=False, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_pr_review_scan', 'scan_id'),
        Index('idx_pr_review_pr', 'repo_full_name', 'pr_number'),
        Index('idx_pr_review_action', 'review_action'),
    )

class IssueStatusTracking(Base):
    """Track individual security issues across scans to monitor resolution."""
    
    __tablename__ = "issue_status_tracking"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    issue_hash = Column(String(64), nullable=False, unique=True, index=True)  # Unique identifier for the issue
    repo_full_name = Column(String(255), nullable=False, index=True)
    first_detected_scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    last_seen_scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    
    # Issue Status - using string enum for compatibility
    status = Column(String(20), nullable=False, default="open", index=True)  # open, fixed_auto, fixed_manual, fixed_dependency, false_positive
    resolution_method = Column(String(100), nullable=True)  # ai_autofix, manual_fix, dependency_update, etc.
    fixed_in_pr_number = Column(Integer, nullable=True)  # Link to PR where auto-fix was applied
    fixed_at = Column(DateTime(timezone=True), nullable=True)
    fixed_by = Column(String(100), nullable=True)  # Username or 'ai_autofix'
    
    # Issue Details
    issue_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    file_path = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    description = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_issue_repo_status', 'repo_full_name', 'status'),
        Index('idx_issue_type_severity', 'issue_type', 'severity'),
        Index('idx_issue_fixed_at', 'fixed_at'),
        Index('idx_issue_pr', 'fixed_in_pr_number'),
        Index('idx_issue_resolution', 'resolution_method'),
    )

class AutoFixResults(Base):
    """Track AI auto-fix results and link them to issue resolution."""
    
    __tablename__ = "autofix_results"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    issue_hash = Column(String(64), ForeignKey("issue_status_tracking.issue_hash", ondelete="CASCADE"), nullable=False, index=True)
    pr_number = Column(Integer, nullable=False, index=True)
    repo_full_name = Column(String(255), nullable=False, index=True)
    
    # Fix Details
    fix_applied = Column(Boolean, nullable=False, default=False)
    fix_content = Column(Text, nullable=True)  # The actual code fix applied
    ai_confidence_score = Column(Float, nullable=True)
    verification_scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)  # Scan that verified the fix
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_autofix_pr', 'repo_full_name', 'pr_number'),
        Index('idx_autofix_verification', 'verification_scan_id'),
        Index('idx_autofix_applied', 'fix_applied'),
    )

class AIRuleGeneration(Base):
    """Track AI-generated rule suggestions and improvements"""
    __tablename__ = "ai_rule_generation"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    prompt = Column(Text, nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    target_language = Column(String(50), nullable=False)
    target_tool = Column(String(50), nullable=False)
    generated_rule = Column(JSON, nullable=False)  # Generated rule content
    confidence_score = Column(Float, nullable=False)
    is_approved = Column(Boolean, nullable=False, default=False)
    approved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="SET NULL"), nullable=True)
    ai_model = Column(String(50), nullable=False, default="gpt-4")
    generation_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_ai_generation_language', 'target_language'),
        Index('idx_ai_generation_tool', 'target_tool'),
        Index('idx_ai_generation_approved', 'is_approved'),
        Index('idx_ai_generation_confidence', 'confidence_score'),
    )

class RuleVersionHistory(Base):
    """Track version history of rules"""
    __tablename__ = "rule_version_history"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(String(20), nullable=False)
    pattern = Column(Text, nullable=False)  # Pattern at this version
    description = Column(Text, nullable=True)  # Description at this version
    change_summary = Column(Text, nullable=True)  # What changed in this version
    created_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_version_rule', 'rule_id', 'version'),
        Index('idx_version_created', 'created_at'),
    )

class RuleCollections(Base):
    """Rule collections/packages for organizing related rules"""
    __tablename__ = "rule_collections"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    author_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    is_public = Column(Boolean, nullable=False, default=False, index=True)
    category = Column(String(50), nullable=False, default="general", index=True)
    tags = Column(JSON, nullable=True)
    download_count = Column(Integer, nullable=False, default=0)
    star_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_collections_public_popular', 'is_public', 'star_count'),
        Index('idx_collections_category', 'category'),
    )

class RuleCollectionItems(Base):
    """Items (rules) within rule collections"""
    __tablename__ = "rule_collection_items"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    collection_id = Column(String(36), ForeignKey("rule_collections.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    order_index = Column(Integer, nullable=False, default=0)
    added_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_collection_items_unique', 'collection_id', 'rule_id', unique=True),
        Index('idx_collection_items_order', 'collection_id', 'order_index'),
    )

class RuleComments(Base):
    """Comments and discussions on community rules"""
    __tablename__ = "rule_comments"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_comment_id = Column(String(36), ForeignKey("rule_comments.id", ondelete="CASCADE"), nullable=True)  # For replies
    author_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    comment_type = Column(String(20), nullable=False, default="comment")  # comment, suggestion, improvement
    is_resolved = Column(Boolean, nullable=False, default=False)  # For suggestions
    upvotes = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_comments_rule', 'rule_id'),
        Index('idx_comments_parent', 'parent_comment_id'),
        Index('idx_comments_type', 'comment_type'),
    )

class RuleTestResults(Base):
    """Test results for rule validation and effectiveness"""
    __tablename__ = "rule_test_results"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    test_type = Column(String(50), nullable=False)  # sandbox, effectiveness, performance
    test_data = Column(JSON, nullable=False)  # Input test data
    expected_result = Column(JSON, nullable=True)  # Expected outcome
    actual_result = Column(JSON, nullable=True)  # Actual outcome
    success = Column(Boolean, nullable=False)
    execution_time_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    tested_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_test_results_rule', 'rule_id'),
        Index('idx_test_results_type', 'test_type'),
        Index('idx_test_results_success', 'success'),
    )

class RuleUsageAnalytics(Base):
    """Analytics for rule usage and performance"""
    __tablename__ = "rule_usage_analytics"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    usage_date = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    findings_count = Column(Integer, nullable=False, default=0)
    execution_time_ms = Column(Integer, nullable=True)
    false_positives_reported = Column(Integer, nullable=False, default=0)
    true_positives_confirmed = Column(Integer, nullable=False, default=0)
    repository_language = Column(String(50), nullable=True)
    repository_size_kb = Column(Integer, nullable=True)
    
    __table_args__ = (
        Index('idx_analytics_rule_date', 'rule_id', 'usage_date'),
        Index('idx_analytics_user', 'user_id'),
        Index('idx_analytics_scan', 'scan_id'),
    )

class RuleFeedback(Base):
    """User feedback on rule effectiveness"""
    __tablename__ = "rule_feedback"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    feedback_type = Column(String(20), nullable=False)  # false_positive, true_positive, improvement_suggestion
    rating = Column(Integer, nullable=True)  # 1-5 star rating
    comment = Column(Text, nullable=True)
    is_helpful = Column(Boolean, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_feedback_rule', 'rule_id'),
        Index('idx_rule_feedback_user', 'user_id'),
        Index('idx_feedback_type', 'feedback_type'),
        Index('idx_feedback_unique', 'rule_id', 'user_id', 'scan_id', unique=True),
    )