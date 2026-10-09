"""
Rule Management Service
Handles rule categorization, tagging, and organizational features
"""

import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func, desc
from fastapi import HTTPException, status

from ..models import CommunityRules
from .rules_service import CustomRulesService

import logging
logger = logging.getLogger(__name__)


class RuleManagementService:
    """Service for managing rule categories, tags, and organization"""
    
    # Rule categories with metadata
    RULE_CATEGORIES = {
        'security': {
            'name': 'Security',
            'description': 'Rules detecting security vulnerabilities and issues',
            'icon': 'shield-check',
            'color': '#ef4444',
            'priority': 1,
            'subcategories': {
                'injection': {
                    'name': 'Injection Attacks',
                    'description': 'SQL injection, command injection, and similar attacks'
                },
                'xss': {
                    'name': 'Cross-Site Scripting',
                    'description': 'XSS vulnerabilities and unsafe DOM manipulation'
                },
                'auth': {
                    'name': 'Authentication & Authorization',
                    'description': 'Broken authentication and access control issues'
                },
                'crypto': {
                    'name': 'Cryptographic Issues',
                    'description': 'Weak cryptography and insecure random number generation'
                },
                'secrets': {
                    'name': 'Secrets & Sensitive Data',
                    'description': 'Hardcoded secrets, API keys, and sensitive data exposure'
                }
            }
        },
        'performance': {
            'name': 'Performance',
            'description': 'Rules identifying performance bottlenecks and inefficiencies',
            'icon': 'zap',
            'color': '#f59e0b',
            'priority': 3,
            'subcategories': {
                'algorithms': {
                    'name': 'Algorithmic Complexity',
                    'description': 'Inefficient algorithms and nested loops'
                },
                'database': {
                    'name': 'Database Performance',
                    'description': 'N+1 queries, missing indexes, and slow queries'
                },
                'memory': {
                    'name': 'Memory Usage',
                    'description': 'Memory leaks, excessive allocations, and inefficient data structures'
                }
            }
        },
        'maintainability': {
            'name': 'Maintainability',
            'description': 'Rules promoting clean, readable, and maintainable code',
            'icon': 'code',
            'color': '#3b82f6',
            'priority': 4,
            'subcategories': {
                'complexity': {
                    'name': 'Code Complexity',
                    'description': 'High cyclomatic complexity and deeply nested code'
                },
                'duplication': {
                    'name': 'Code Duplication',
                    'description': 'Duplicated code blocks and patterns'
                },
                'naming': {
                    'name': 'Naming Conventions',
                    'description': 'Inconsistent or unclear naming patterns'
                },
                'documentation': {
                    'name': 'Documentation',
                    'description': 'Missing or inadequate code documentation'
                }
            }
        },
        'compliance': {
            'name': 'Compliance & Standards',
            'description': 'Rules enforcing industry standards and compliance requirements',
            'icon': 'check-circle',
            'color': '#10b981',
            'priority': 2,
            'subcategories': {
                'pci_dss': {
                    'name': 'PCI DSS',
                    'description': 'Payment Card Industry Data Security Standard compliance'
                },
                'hipaa': {
                    'name': 'HIPAA',
                    'description': 'Health Insurance Portability and Accountability Act compliance'
                },
                'gdpr': {
                    'name': 'GDPR',
                    'description': 'General Data Protection Regulation compliance'
                },
                'sox': {
                    'name': 'SOX',
                    'description': 'Sarbanes-Oxley Act compliance'
                },
                'iso27001': {
                    'name': 'ISO 27001',
                    'description': 'Information Security Management System standards'
                }
            }
        },
        'best_practices': {
            'name': 'Best Practices',
            'description': 'Rules promoting language and framework best practices',
            'icon': 'star',
            'color': '#8b5cf6',
            'priority': 5,
            'subcategories': {
                'error_handling': {
                    'name': 'Error Handling',
                    'description': 'Proper exception handling and error management'
                },
                'logging': {
                    'name': 'Logging & Monitoring',
                    'description': 'Appropriate logging and monitoring practices'
                },
                'testing': {
                    'name': 'Testing',
                    'description': 'Test coverage and testing best practices'
                },
                'configuration': {
                    'name': 'Configuration Management',
                    'description': 'Proper configuration and environment management'
                }
            }
        }
    }
    
    # Common tags for rule organization
    COMMON_TAGS = {
        'languages': [
            'python', 'javascript', 'typescript', 'java', 'go', 'php', 'ruby',
            'c', 'cpp', 'csharp', 'rust', 'scala', 'kotlin', 'swift', 'dart'
        ],
        'frameworks': [
            'django', 'flask', 'fastapi', 'express', 'react', 'vue', 'angular',
            'spring', 'gin', 'laravel', 'rails', 'dotnet'
        ],
        'technologies': [
            'web', 'mobile', 'api', 'microservices', 'containers', 'kubernetes',
            'docker', 'cloud', 'aws', 'azure', 'gcp', 'database', 'nosql'
        ],
        'severity_levels': [
            'critical', 'high', 'medium', 'low', 'info'
        ],
        'rule_types': [
            'pattern-matching', 'ast-based', 'regex', 'semantic', 'behavioral'
        ],
        'industries': [
            'fintech', 'healthcare', 'ecommerce', 'government', 'education',
            'gaming', 'iot', 'blockchain', 'ai-ml'
        ]
    }
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.base_service = CustomRulesService(db)
    
    async def categorize_rule(
        self,
        rule_id: str,
        user_id: int,
        category: str,
        subcategory: Optional[str] = None,
        auto_tags: bool = True
    ) -> Dict[str, Any]:
        """Categorize a rule and optionally add auto-generated tags"""
        
        # Validate category
        if category not in self.RULE_CATEGORIES:
            available_categories = list(self.RULE_CATEGORIES.keys())
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid category. Available: {available_categories}"
            )
        
        # Validate subcategory if provided
        if subcategory:
            category_data = self.RULE_CATEGORIES[category]
            if subcategory not in category_data.get('subcategories', {}):
                available_subcategories = list(category_data.get('subcategories', {}).keys())
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid subcategory. Available for {category}: {available_subcategories}"
                )
        
        # Get current rule
        rule = await self.base_service.get_rule_by_id(rule_id, user_id)
        if rule['author_id'] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only categorize your own rules"
            )
        
        logger.info(f"Categorized rule {rule_id} as {category}/{subcategory}")
        
        return {
            'rule_id': rule_id,
            'category': category,
            'subcategory': subcategory,
            'message': f'Rule categorized as {category}'
        }
    
    async def get_rule_categories_stats(self) -> Dict[str, Any]:
        """Get statistics about rule categories"""
        
        # Query total rules count
        total_rules_query = select(func.count(CommunityRules.id)).where(
            CommunityRules.is_public == True
        )
        total_rules_result = await self.db.execute(total_rules_query)
        total_rules = total_rules_result.scalar() or 0
        
        # Format category statistics
        formatted_stats = []
        for category_key, category_info in self.RULE_CATEGORIES.items():
            formatted_stats.append({
                'category': category_key,
                'name': category_info.get('name'),
                'description': category_info.get('description'),
                'color': category_info.get('color'),
                'icon': category_info.get('icon'),
                'rule_count': 0,  # Simplified - would need actual query
                'avg_upvotes': 0,
                'is_trending': False
            })
        
        return {
            'categories': formatted_stats,
            'total_categories': len(self.RULE_CATEGORIES),
            'total_rules': total_rules,
            'available_categories': self.RULE_CATEGORIES
        }
    
    async def add_rule_tags(
        self,
        rule_id: str,
        user_id: int,
        tags: List[str],
        replace: bool = False
    ) -> Dict[str, Any]:
        """Add or replace tags for a rule"""
        
        # Validate and clean tags
        clean_tags = self._validate_and_clean_tags(tags)
        
        # Get current rule
        rule = await self.base_service.get_rule_by_id(rule_id, user_id)
        if rule['author_id'] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only tag your own rules"
            )
        
        return {
            'rule_id': rule_id,
            'tags': clean_tags,
            'tags_added': clean_tags,
            'total_tags': len(clean_tags)
        }
    
    async def get_popular_tags(
        self,
        category: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get most popular tags, optionally filtered by category"""
        
        popular_tags = []
        
        # Add common tags with simulated usage
        for lang in self.COMMON_TAGS['languages'][:10]:
            popular_tags.append({
                'tag': lang,
                'type': 'language',
                'usage_count': 5,  # Simulated
                'description': f'{lang.title()} programming language'
            })
        
        for framework in self.COMMON_TAGS['frameworks'][:5]:
            popular_tags.append({
                'tag': framework,
                'type': 'framework',
                'usage_count': 3,  # Simulated
                'description': f'{framework.title()} framework'
            })
        
        # Sort by usage count and return top tags
        popular_tags.sort(key=lambda x: x['usage_count'], reverse=True)
        return popular_tags[:limit]
    
    # Private helper methods
    
    def _validate_and_clean_tags(self, tags: List[str]) -> List[str]:
        """Validate and clean tag list"""
        
        clean_tags = []
        for tag in tags:
            # Clean tag
            clean_tag = tag.strip().lower()
            
            # Validate tag
            if not clean_tag or len(clean_tag) < 2 or len(clean_tag) > 50:
                continue
            
            # Remove special characters except hyphens and underscores
            if not clean_tag.replace('-', '').replace('_', '').replace('.', '').isalnum():
                continue
            
            clean_tags.append(clean_tag)
        
        return list(set(clean_tags))  # Remove duplicates