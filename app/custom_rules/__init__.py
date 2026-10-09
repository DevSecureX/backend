"""
Custom Security Rules Module

This module provides a comprehensive custom rules system for DevSecureX,
allowing users to create, manage, and share custom security rules across
multiple security tools like Semgrep, Bandit, ESLint, and others.

Features:
- Rule creation and validation
- Community rule sharing and voting
- Rule templates and recommendations
- Analytics and performance monitoring
- Import/export capabilities
- Version control and governance
"""

__version__ = "1.0.0"
__author__ = "DevSecureX Team"

# Re-export main components for easy imports
from .models import CommunityRules, CommunityRuleVotes
from .routes import rules_router
from .dependencies import get_rules_service, get_rules_config

__all__ = [
    "CommunityRules",
    "CommunityRuleVotes", 
    "rules_router",
    "get_rules_service",
    "get_rules_config"
]