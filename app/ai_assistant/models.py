from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, JSON, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from typing import TYPE_CHECKING

from core.database import Base

# Import User model only for type hints to avoid circular imports
if TYPE_CHECKING:
    from app.auth.models import User

class ChatSession(Base):
    __tablename__ = "chat_sessions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), nullable=True)  # Auto-generated from first message
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    session_type = Column(String(50), default="general")  # general, issue_analysis, code_review, etc.
    session_meta = Column(JSON, default={})  # Store session context, preferences, etc.
    
    # Relationships
    messages = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")
    user = relationship("User", back_populates="chat_sessions", foreign_keys=[user_id])
    
    # Performance indexes
    __table_args__ = (
        Index('idx_chat_session_user_active', 'user_id', 'is_active'),
        Index('idx_chat_session_created_at', 'created_at'),
        Index('idx_chat_session_type_user', 'session_type', 'user_id'),
        Index('idx_chat_session_updated_at', 'updated_at'),
    )

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("chat_sessions.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)  # user, assistant, system
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    message_type = Column(String(50), default="text")  # text, code, analysis, suggestion
    msg_meta = Column(JSON, default={})  # Store context, tool used, confidence, etc.
    
    # AI-specific fields
    model_used = Column(String(50), nullable=True)  # gpt-4o-mini, etc.
    tokens_used = Column(Integer, nullable=True)
    processing_time = Column(Integer, nullable=True)  # milliseconds
    confidence_score = Column(Integer, nullable=True)  # 0-100
    
    # Context linking
    related_scan_id = Column(String, nullable=True)  # Link to scan if relevant
    related_issue_id = Column(String, nullable=True)  # Link to specific issue
    related_repo = Column(String, nullable=True)  # Repository context
    
    # Relationships
    session = relationship("ChatSession", back_populates="messages")
    user = relationship("User", back_populates="chat_messages", foreign_keys=[user_id])
    
    # Performance indexes
    __table_args__ = (
        Index('idx_chat_message_session_timestamp', 'session_id', 'timestamp'),
        Index('idx_chat_message_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_chat_message_role_type', 'role', 'message_type'),
        Index('idx_chat_message_timestamp', 'timestamp'),
        Index('idx_chat_message_related_scan', 'related_scan_id'),
        Index('idx_chat_message_related_repo', 'related_repo'),
    )

class AIKnowledgeBase(Base):
    __tablename__ = "ai_knowledge_base"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    category = Column(String(100), nullable=False)  # security_rules, best_practices, frameworks, etc.
    subcategory = Column(String(100), nullable=True)  # owasp, nist, language-specific, etc.
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    tags = Column(JSON, default=[])  # Searchable tags
    source = Column(String(200), nullable=True)  # URL or reference
    priority = Column(Integer, default=1)  # For ranking in search results
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    kb_meta = Column(JSON, default={})
    
    # Performance indexes
    __table_args__ = (
        Index('idx_ai_knowledge_category_subcategory', 'category', 'subcategory'),
        Index('idx_ai_knowledge_active_priority', 'is_active', 'priority'),
        Index('idx_ai_knowledge_tags', 'tags', postgresql_using='gin'),  # GIN index for JSON array searching
        Index('idx_ai_knowledge_created_at', 'created_at'),
    )

class AIInteraction(Base):
    __tablename__ = "ai_interactions"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    interaction_type = Column(String(50), nullable=False)  # chat, explain_issue, code_review, etc.
    input_data = Column(JSON, nullable=False)  # Original user input
    ai_response = Column(JSON, nullable=False)  # AI response with metadata
    model_used = Column(String(50), nullable=False)
    tokens_used = Column(Integer, nullable=True)
    processing_time = Column(Integer, nullable=True)
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)
    user_feedback = Column(String(20), nullable=True)  # thumbs_up, thumbs_down, helpful, etc.
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Context
    session_id = Column(String, nullable=True)
    related_scan_id = Column(String, nullable=True)
    related_repo = Column(String, nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="ai_interactions", foreign_keys=[user_id])
    
    # Performance indexes
    __table_args__ = (
        Index('idx_ai_interaction_user_type', 'user_id', 'interaction_type'),
        Index('idx_ai_interaction_created_at', 'created_at'),
        Index('idx_ai_interaction_success_feedback', 'success', 'user_feedback'),
        Index('idx_ai_interaction_session_id', 'session_id'),
        Index('idx_ai_interaction_model_used', 'model_used'),
    )

class AIPromptTemplate(Base):
    __tablename__ = "ai_prompt_templates"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, unique=True)
    category = Column(String(50), nullable=False)  # system, user, security_analysis, etc.
    template = Column(Text, nullable=False)
    variables = Column(JSON, default=[])  # List of template variables
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    version = Column(String(10), default="1.0")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Usage tracking
    usage_count = Column(Integer, default=0)
    last_used = Column(DateTime(timezone=True), nullable=True)
    
    # Performance indexes
    __table_args__ = (
        Index('idx_ai_prompt_template_category_active', 'category', 'is_active'),
        Index('idx_ai_prompt_template_name_version', 'name', 'version'),
        Index('idx_ai_prompt_template_usage_count', 'usage_count'),
        Index('idx_ai_prompt_template_last_used', 'last_used'),
    )

class AIAnalysisCache(Base):
    __tablename__ = "ai_analysis_cache"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    cache_key = Column(String(255), nullable=False, unique=True)  # Hash of input parameters
    analysis_type = Column(String(50), nullable=False)  # issue_explanation, code_review, etc.
    input_hash = Column(String(64), nullable=False)  # SHA256 of input data
    result = Column(JSON, nullable=False)  # Cached AI response
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    accessed_at = Column(DateTime(timezone=True), server_default=func.now())
    access_count = Column(Integer, default=1)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Optional expiration
    
    # Meta
    model_used = Column(String(50), nullable=False)
    tokens_used = Column(Integer, nullable=True)
    quality_score = Column(Integer, nullable=True)  # 0-100 based on user feedback
    
    # Performance indexes
    __table_args__ = (
        Index('idx_ai_analysis_cache_key', 'cache_key'),  # Primary lookup
        Index('idx_ai_analysis_cache_type_hash', 'analysis_type', 'input_hash'),
        Index('idx_ai_analysis_cache_expires_at', 'expires_at'),  # For cleanup
        Index('idx_ai_analysis_cache_accessed_at', 'accessed_at'),  # For LRU cleanup
        Index('idx_ai_analysis_cache_quality_score', 'quality_score'),  # For quality filtering
    )