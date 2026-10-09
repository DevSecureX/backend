from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from core.database import Base
from typing import TYPE_CHECKING

# Import User model only for type hints to avoid circular imports
if TYPE_CHECKING:
    from app.auth.models import User

class SupportQuery(Base):
    __tablename__ = "support_queries"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    subject = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)  # general, technical, billing, feature_request
    priority = Column(String(20), default="medium")  # low, medium, high, urgent
    message = Column(Text, nullable=False)
    status = Column(String(20), default="open")  # open, in_progress, resolved, closed
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships - Fixed using string-based forward references
    user = relationship("User", back_populates="support_queries")
    responses = relationship("SupportResponse", back_populates="query", cascade="all, delete-orphan")
    
    # Performance indexes
    __table_args__ = (
        Index('idx_support_query_user_status', 'user_id', 'status'),
        Index('idx_support_query_category_priority', 'category', 'priority'),
        Index('idx_support_query_created_at', 'created_at'),
        Index('idx_support_query_status_updated', 'status', 'updated_at'),
    )

class SupportResponse(Base):
    __tablename__ = "support_responses"

    id = Column(Integer, primary_key=True, index=True)
    query_id = Column(Integer, ForeignKey("support_queries.id"), nullable=False)
    responder_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Admin/support user
    message = Column(Text, nullable=False)
    is_admin_response = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships - Fixed using string-based forward references
    query = relationship("SupportQuery", back_populates="responses")
    responder = relationship("User", foreign_keys=[responder_id])
    
    # Performance indexes
    __table_args__ = (
        Index('idx_support_response_query_id', 'query_id'),
        Index('idx_support_response_responder', 'responder_id', 'is_admin_response'),
        Index('idx_support_response_created_at', 'created_at'),
    )