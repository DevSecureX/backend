from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Index, UniqueConstraint, Text
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from core.database import Base

class Repo(Base):
    """Repository model for storing connected GitHub repositories."""
    
    __tablename__ = "repos"
    
    # Primary key - using auto-incrementing ID instead of full_name for better performance
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # GitHub repository full name (e.g., 'username/repo')
    full_name = Column(String(255), nullable=False, index=True)
    
    # Foreign key to users table with proper constraint name for easier debugging
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE", name="fk_repo_user"), nullable=False, index=True)
    
    # Repository niche/category
    niche = Column(String(50), nullable=False, index=True)
    
    # JSON settings for repository configuration
    settings = Column(JSON, nullable=False, default=dict)
    
    # GitHub webhook ID (can be null for mock webhooks)
    webhook_id = Column(Integer, nullable=True)
    
    # Repository metadata
    default_branch = Column(String(255), nullable=True, default="main")
    is_private = Column(String(10), nullable=True)  # 'true', 'false', or null if unknown
    language = Column(String(100), nullable=True)  # Primary language of the repository
    description = Column(Text, nullable=True)  # Repository description
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    last_synced = Column(DateTime(timezone=True), nullable=True)  # Last time repo was synced with GitHub
    
    # Status tracking
    status = Column(String(20), nullable=False, default="active")  # active, inactive, error
    sync_error = Column(Text, nullable=True)  # Store last sync error if any
    
    # Constraints
    __table_args__ = (
        # Ensure a user can't connect the same repo twice
        UniqueConstraint('full_name', 'user_id', name='uq_repo_user'),
        
        # Composite indexes for common queries
        Index('idx_user_niche', 'user_id', 'niche'),
        Index('idx_user_status', 'user_id', 'status'),
        Index('idx_full_name_status', 'full_name', 'status'),
        Index('idx_created_at', 'created_at'),
        Index('idx_last_synced', 'last_synced'),
        
        # Partial index for active repositories only (PostgreSQL specific)
        # Index('idx_active_repos', 'user_id', 'full_name', postgresql_where=Column('status') == 'active'),
    )
    
    # Relationship to User model (assuming it exists)
    # user = relationship("User", back_populates="repos")
    
    def __repr__(self) -> str:
        return f"<Repo(id={self.id}, full_name='{self.full_name}', user_id={self.user_id}, niche='{self.niche}')>"
    
    def to_dict(self) -> dict:
        """Convert model to dictionary for API responses."""
        return {
            'id': self.id,
            'full_name': self.full_name,
            'user_id': self.user_id,
            'niche': self.niche,
            'settings': self.settings,
            'webhook_id': self.webhook_id,
            'default_branch': self.default_branch,
            'is_private': self.is_private,
            'language': self.language,
            'description': self.description,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_synced': self.last_synced.isoformat() if self.last_synced else None,
        }
    
    @property
    def owner(self) -> str:
        """Extract owner from full_name."""
        return self.full_name.split('/')[0] if '/' in self.full_name else ''
    
    @property
    def repo_name(self) -> str:
        """Extract repository name from full_name."""
        return self.full_name.split('/')[1] if '/' in self.full_name else self.full_name
    
    @property
    def is_sync_needed(self) -> bool:
        """Check if repository needs to be synced with GitHub."""
        if not self.last_synced:
            return True
        
        from datetime import datetime, timezone, timedelta
        # Consider sync needed if last sync was more than 1 hour ago
        sync_threshold = datetime.now(timezone.utc) - timedelta(hours=1)
        return self.last_synced < sync_threshold
    
    def update_sync_status(self, success: bool = True, error_message: str = None) -> None:
        """Update sync status and timestamp."""
        from datetime import datetime, timezone
        
        self.last_synced = datetime.now(timezone.utc)
        if success:
            self.status = "active"
            self.sync_error = None
        else:
            self.status = "error"
            self.sync_error = error_message