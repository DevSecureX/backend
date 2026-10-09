"""
Custom Rules Database Models

Contains SQLAlchemy models for the custom rules system:
- CommunityRules: Core rule definitions and metadata
- CommunityRuleVotes: Individual user votes on rules
"""

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, JSON, Float, func, Text, Boolean, Index
from core.database import Base
import uuid


class CommunityRules(Base):
    """
    Community rules model for user-created security rules.
    
    Features:
    - User-authored security rules for various tools
    - Community voting and engagement
    - Rule versioning and forking capabilities
    - Advanced metadata for rule management
    - Performance and effectiveness tracking
    """
    __tablename__ = "community_rules"
    
    # Core fields
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_name = Column(String(255), nullable=False, index=True)
    tool = Column(String(50), nullable=False, index=True)
    language = Column(String(50), nullable=True, index=True)
    pattern = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium", index=True)
    author_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    is_public = Column(Boolean, nullable=False, default=False, index=True)
    
    # Voting and engagement
    upvotes = Column(Integer, nullable=False, default=0)
    downvotes = Column(Integer, nullable=False, default=0)
    usage_count = Column(Integer, nullable=False, default=0)
    
    # Verification and quality control
    is_verified = Column(Boolean, nullable=False, default=False)
    verification_notes = Column(Text, nullable=True)
    pattern_hash = Column(String(64), nullable=True, index=True)
    
    # Template system fields
    is_template = Column(Boolean, nullable=False, default=False, index=True)
    template_category = Column(String(50), nullable=True)  # security, crypto, auth, etc.
    complexity = Column(String(20), nullable=False, default="basic")  # basic, intermediate, advanced
    example_usage = Column(Text, nullable=True)  # Detailed usage guide
    pattern_template = Column(Text, nullable=True)  # Template pattern with comments
    template_source = Column(String(20), nullable=False, default="community")  # official, community
    is_curated = Column(Boolean, nullable=False, default=False)  # Quality indicator
    use_case = Column(Text, nullable=True)  # When to use this template
    placeholders = Column(JSON, nullable=True)  # Template placeholders metadata
    
    # Enhanced fields for enterprise features (commented out until needed)
    # version = Column(String(20), nullable=False, default="1.0.0")
    # parent_rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="SET NULL"), nullable=True)  # For rule forking
    # rule_category = Column(String(50), nullable=False, default="security", index=True)  # security, performance, maintainability, etc.
    # complexity_score = Column(Integer, nullable=False, default=0)  # Calculated complexity
    # performance_impact = Column(String(20), nullable=False, default="low")  # low, medium, high
    # false_positive_rate = Column(Float, nullable=True)  # Calculated from feedback
    # effectiveness_score = Column(Float, nullable=True)  # Overall effectiveness
    # test_cases = Column(JSON, nullable=True)  # Test cases for the rule
    # rule_metadata = Column(JSON, nullable=True)  # Additional metadata
    # tags = Column(JSON, nullable=True)  # Searchable tags
    # owasp_categories = Column(JSON, nullable=True)  # OWASP mappings
    # cwe_mappings = Column(JSON, nullable=True)  # CWE mappings
    # compliance_frameworks = Column(JSON, nullable=True)  # SOC2, GDPR, etc.
    # is_deprecated = Column(Boolean, nullable=False, default=False)
    # deprecation_reason = Column(Text, nullable=True)
    # successor_rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="SET NULL"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Database indexes for performance (only for existing columns)
    __table_args__ = (
        Index('idx_rules_tool_lang', 'tool', 'language'),
        Index('idx_rules_public_popular', 'is_public', 'upvotes', postgresql_using='btree'),
        Index('idx_rules_author_public', 'author_id', 'is_public'),
        Index('idx_rules_pattern_hash', 'pattern_hash'),
        Index('idx_rules_verified', 'is_verified', 'is_public'),
        # Performance-critical indexes for custom rules scanning
        Index('idx_rules_author_tool_lang', 'author_id', 'tool', 'language'),  # For user's rules by niche
        Index('idx_rules_ids_lookup', 'id', 'is_public', 'author_id'),  # For selected_custom_rule_ids
        Index('idx_rules_search', 'rule_name', 'severity'),  # For text search
        Index('idx_rules_community_popular', 'is_public', 'upvotes', 'usage_count'),  # For popular community rules
        Index('idx_rules_created_recent', 'created_at', 'is_public'),  # For trending rules
        # Template system indexes
        Index('idx_rules_template', 'is_template', 'template_category', 'complexity'),
        Index('idx_rules_template_source', 'template_source', 'is_curated', 'is_public'),
        Index('idx_rules_template_popular', 'is_template', 'upvotes', 'usage_count'),
        # Indexes for enhanced fields (commented out until needed)
        # Index('idx_rules_category', 'rule_category'),
        # Index('idx_rules_version', 'version'),
        # Index('idx_rules_parent', 'parent_rule_id'),
        # Index('idx_rules_effectiveness', 'effectiveness_score'),
        # Index('idx_rules_complexity', 'complexity_score'),
    )


class CommunityRuleVotes(Base):
    """
    Track individual user votes on community rules.
    
    Prevents duplicate voting and maintains vote integrity.
    Each user can only vote once per rule (up or down).
    """
    __tablename__ = "community_rule_votes"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(36), ForeignKey("community_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    vote_type = Column(String(10), nullable=False)  # 'up' or 'down'
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Indexes and constraints
    __table_args__ = (
        Index('idx_rule_votes_unique', 'rule_id', 'user_id', unique=True),  # One vote per user per rule
        Index('idx_votes_user', 'user_id'),
        Index('idx_votes_rule', 'rule_id'),
    )

# The following models are now defined in scans.models to avoid duplication:
# - RuleComments (rule_comments table)
# - RuleCollections (rule_collections table) 
# - RuleCollectionItems (rule_collection_items table)
# - RuleFeedback (rule_feedback table)
#
# Import them from scans.models when needed