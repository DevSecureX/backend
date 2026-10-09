from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Index
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from core.database import Base

# Hot reload verified for model files ✅

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # NULL for OAuth users
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    mobile_no = Column(String(15), nullable=True)
    is_premium = Column(Boolean, nullable=False, server_default="false")
    premium_expiry = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Password reset fields
    reset_password_token = Column(String(64), nullable=True, index=True)  # Add index for faster lookups
    reset_password_expires = Column(DateTime(timezone=True), nullable=True)
    
    # GitHub integration fields
    github_access_token = Column(Text, nullable=True)  # Encrypted GitHub access token (use Text for larger tokens)
    is_github_connected = Column(Boolean, nullable=False, server_default="false")  # Ensure NOT NULL
    
    # Security fields
    failed_login_attempts = Column(Integer, nullable=False, server_default="0")
    locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Timezone preferences (for cross-device sync)
    timezone = Column(String(50), nullable=True, server_default="'UTC'")
    date_format = Column(String(20), nullable=True, server_default="'MMM dd, yyyy'")
    time_format = Column(String(5), nullable=True, server_default="'12h'")
    show_relative_dates = Column(Boolean, nullable=False, server_default="true")
    show_timezone_abbreviations = Column(Boolean, nullable=False, server_default="false")
    preferences_updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Notification preferences
    email_notifications = Column(Boolean, nullable=False, server_default="true")
    security_alerts = Column(Boolean, nullable=False, server_default="true")
    scan_completion_notifications = Column(Boolean, nullable=False, server_default="true")
    weekly_reports = Column(Boolean, nullable=False, server_default="false")
    marketing_emails = Column(Boolean, nullable=False, server_default="false")
    notification_preferences_updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Soft delete fields (30-day retention policy)
    is_deleted = Column(Boolean, nullable=False, server_default="false", index=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)
    deletion_reason = Column(String(255), nullable=True)  # User requested, admin action, etc.
    
    # Relationships
    feedbacks = relationship("Feedback", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    data_export_requests = relationship("DataExportRequest", back_populates="user", cascade="all, delete-orphan")
    support_queries = relationship("SupportQuery", back_populates="user", cascade="all, delete-orphan")
    
    # AI Assistant relationships - using string-based forward references to avoid circular imports
    chat_sessions = relationship("ChatSession", foreign_keys="ChatSession.user_id", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage", foreign_keys="ChatMessage.user_id", cascade="all, delete-orphan")
    ai_interactions = relationship("AIInteraction", foreign_keys="AIInteraction.user_id", cascade="all, delete-orphan")
    
    # CLI Scan relationships
    cli_scan_results = relationship("CLIScanResult", back_populates="user", cascade="all, delete-orphan")
    cli_activity_logs = relationship("CLIActivityLog", back_populates="user", cascade="all, delete-orphan")
    cli_usage_stats = relationship("CLIUsageStats", back_populates="user", cascade="all, delete-orphan")
    cli_scan_sessions = relationship("CLIScanSession", back_populates="user", cascade="all, delete-orphan")
    
    # Composite indexes for better performance
    __table_args__ = (
        Index('idx_user_email_active', 'email', 'is_premium'),
        Index('idx_user_reset_token', 'reset_password_token', 'reset_password_expires'),
        Index('idx_user_locked', 'locked_until'),
        Index('idx_user_active', 'is_deleted', 'deleted_at'),  # For filtering active/deleted users
        Index('idx_user_cleanup', 'is_deleted', 'deleted_at'),  # For cleanup job performance
    )


class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(36), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Optional: link to user
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)  # For cleanup
    
    # Index for cleanup operations
    __table_args__ = (
        Index('idx_blacklist_expires', 'expires_at'),
    )


class MailList(Base):
    __tablename__ = "mail_list"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, nullable=False, server_default="true")  # Allow unsubscribe
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    unsubscribed_at = Column(DateTime(timezone=True), nullable=True)


class Feedback(Base):
    __tablename__ = "feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    feedback = Column(Text, nullable=False)  # Use Text for potentially long feedback
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_resolved = Column(Boolean, nullable=False, server_default="false")
    priority = Column(String(20), nullable=False, server_default="medium")  # low, medium, high, critical
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship
    user = relationship("User", back_populates="feedbacks")
    
    # Index for admin queries
    __table_args__ = (
        Index('idx_feedback_status', 'is_resolved', 'priority'),
        Index('idx_feedback_user_date', 'user_id', 'created_at'),
    )


class LoginAttempt(Base):
    """Track login attempts for security monitoring"""
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    username_or_email = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 support
    user_agent = Column(String(500), nullable=True)
    success = Column(Boolean, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    __table_args__ = (
        Index('idx_login_attempts_ip_time', 'ip_address', 'created_at'),
        Index('idx_login_attempts_username_time', 'username_or_email', 'created_at'),
    )


class ApiKey(Base):
    """API Keys for Premium users to access DevSecureX API"""
    __tablename__ = "api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)  # User-defined name for the key
    key_hash = Column(String(255), nullable=False, unique=True, index=True)  # SHA256 hash of the key
    key_prefix = Column(String(10), nullable=False)  # First 8 chars for display (dsx_12345...)
    scopes = Column(String(500), nullable=False, server_default="'read'")  # JSON array of scopes
    is_active = Column(Boolean, nullable=False, server_default="true")
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    last_used_ip = Column(String(45), nullable=True)
    usage_count = Column(Integer, nullable=False, server_default="0")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    __table_args__ = (
        Index('idx_api_key_user_active', 'user_id', 'is_active'),
        Index('idx_api_key_last_used', 'last_used_at'),
    )


class DataExportRequest(Base):
    """Data export requests for enterprise compliance"""
    __tablename__ = "data_export_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    export_type = Column(String(50), nullable=False)  # 'full', 'scans_only', 'repos_only', etc.
    status = Column(String(20), nullable=False, server_default="'pending'")  # pending, processing, completed, failed
    file_format = Column(String(10), nullable=False, server_default="'json'")  # json, csv, xml
    include_personal_data = Column(Boolean, nullable=False, server_default="true")
    include_scan_data = Column(Boolean, nullable=False, server_default="true")
    include_repository_data = Column(Boolean, nullable=False, server_default="true")
    
    # Export metadata
    total_records = Column(Integer, nullable=True)
    exported_records = Column(Integer, nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    file_path = Column(String(500), nullable=True)  # Secure file path for download
    download_expires_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    requested_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    processing_started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    downloaded_at = Column(DateTime(timezone=True), nullable=True)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="data_export_requests")
    
    __table_args__ = (
        Index('idx_export_user_status', 'user_id', 'status'),
        Index('idx_export_requested_at', 'requested_at'),
        Index('idx_export_expires_at', 'download_expires_at'),
    )