"""
Output formatting utilities for custom rules.

Provides formatting functions for rule data, analytics, and API responses
to ensure consistent, well-structured output across the custom rules system.
"""

import json
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass


@dataclass
class FormattedRule:
    """Formatted rule data structure"""
    id: str
    rule_name: str
    tool: str
    language: Optional[str]
    pattern: str
    description: Optional[str]
    severity: str
    author_id: int
    is_public: bool
    upvotes: int
    downvotes: int
    usage_count: int
    created_at: str
    updated_at: str
    net_votes: Optional[int] = None
    effectiveness_score: Optional[float] = None


class RuleFormatter:
    """Format rule data for various output formats"""
    
    @classmethod
    def format_rule_for_api(cls, rule_data: Union[Dict, Any]) -> Dict[str, Any]:
        """Format rule data for API responses"""
        if hasattr(rule_data, '__dict__'):
            # SQLAlchemy model or similar
            data = {
                'id': str(rule_data.id),
                'rule_name': rule_data.rule_name,
                'tool': rule_data.tool,
                'language': rule_data.language,
                'pattern': rule_data.pattern,
                'description': rule_data.description,
                'severity': rule_data.severity,
                'author_id': rule_data.author_id,
                'is_public': rule_data.is_public,
                'upvotes': rule_data.upvotes or 0,
                'downvotes': getattr(rule_data, 'downvotes', 0),
                'usage_count': rule_data.usage_count or 0,
                'created_at': cls._format_datetime(rule_data.created_at),
                'updated_at': cls._format_datetime(rule_data.updated_at),
                'net_votes': (rule_data.upvotes or 0) - getattr(rule_data, 'downvotes', 0)
            }
        else:
            # Dictionary
            data = {
                'id': str(rule_data.get('id', '')),
                'rule_name': rule_data.get('rule_name', ''),
                'tool': rule_data.get('tool', ''),
                'language': rule_data.get('language'),
                'pattern': rule_data.get('pattern', ''),
                'description': rule_data.get('description'),
                'severity': rule_data.get('severity', 'medium'),
                'author_id': rule_data.get('author_id', 0),
                'is_public': rule_data.get('is_public', False),
                'upvotes': rule_data.get('upvotes', 0),
                'downvotes': rule_data.get('downvotes', 0),
                'usage_count': rule_data.get('usage_count', 0),
                'created_at': cls._format_datetime(rule_data.get('created_at')),
                'updated_at': cls._format_datetime(rule_data.get('updated_at')),
                'net_votes': rule_data.get('upvotes', 0) - rule_data.get('downvotes', 0)
            }
        
        return data
    
    @classmethod
    def format_rules_list(cls, rules: List[Union[Dict, Any]], total: int = None, 
                         skip: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Format a list of rules for API response"""
        formatted_rules = [cls.format_rule_for_api(rule) for rule in rules]
        
        return {
            'rules': formatted_rules,
            'total': total if total is not None else len(formatted_rules),
            'count': len(formatted_rules),
            'skip': skip,
            'limit': limit,
            'has_more': total and (skip + len(formatted_rules)) < total if total else False
        }
    
    @classmethod
    def format_rule_for_export(cls, rule_data: Union[Dict, Any], 
                              format_type: str = 'json') -> str:
        """Format rule for export in various formats"""
        formatted_rule = cls.format_rule_for_api(rule_data)
        
        if format_type.lower() == 'yaml':
            return yaml.dump(formatted_rule, default_flow_style=False, sort_keys=True)
        elif format_type.lower() == 'json':
            return json.dumps(formatted_rule, indent=2, sort_keys=True)
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
    
    @classmethod
    def format_analytics_data(cls, analytics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format analytics data for dashboard display"""
        return {
            'overview': {
                'total_rules': analytics_data.get('total_rules', 0),
                'active_rules': analytics_data.get('active_rules', 0),
                'community_rules': analytics_data.get('community_rules', 0),
                'trending_tools': analytics_data.get('trending_tools', [])
            },
            'performance': {
                'avg_execution_time': round(analytics_data.get('avg_execution_time', 0.0), 2),
                'success_rate': round(analytics_data.get('success_rate', 0.0), 2),
                'total_tests_run': analytics_data.get('total_tests_run', 0)
            },
            'community': {
                'active_contributors': analytics_data.get('active_contributors', 0),
                'new_rules_this_period': analytics_data.get('new_rules_this_period', 0),
                'top_voted_rules': analytics_data.get('top_voted_rules', [])
            },
            'tool_usage': analytics_data.get('tool_usage', [])
        }
    
    @classmethod
    def _format_datetime(cls, dt: Union[datetime, str, None]) -> str:
        """Format datetime for API output"""
        if dt is None:
            return ""
        if isinstance(dt, str):
            return dt
        if hasattr(dt, 'isoformat'):
            return dt.isoformat()
        return str(dt)


class OutputFormatter:
    """Format various outputs for the rules system"""
    
    @classmethod
    def format_validation_result(cls, validation_result) -> Dict[str, Any]:
        """Format validation results for API response"""
        return {
            'is_valid': validation_result.is_valid,
            'errors': validation_result.errors,
            'warnings': validation_result.warnings,
            'suggestions': validation_result.suggestions,
            'complexity_score': validation_result.complexity_score,
            'performance_impact': validation_result.performance_impact,
            'summary': cls._get_validation_summary(validation_result)
        }
    
    @classmethod
    def format_recommendation(cls, rule_data: Dict[str, Any], 
                            score: float, reason: str) -> Dict[str, Any]:
        """Format rule recommendation for API response"""
        return {
            'rule': RuleFormatter.format_rule_for_api(rule_data),
            'recommendation_score': round(score, 2),
            'reason': reason,
            'similarity_score': round(score * 0.9, 2),
            'effectiveness_match': round(score, 2),
            'language_compatibility': 1.0,  # Can be calculated based on context
            'use_case_relevance': round(score * 0.8, 2),
            'community_endorsement': round((rule_data.get('upvotes', 0) / max(1, rule_data.get('upvotes', 0) + rule_data.get('downvotes', 0))) * score, 2)
        }
    
    @classmethod
    def format_search_results(cls, rules: List[Dict[str, Any]], 
                            query: str, total: int) -> Dict[str, Any]:
        """Format search results with relevance scoring"""
        formatted_results = []
        
        for rule in rules:
            formatted_rule = RuleFormatter.format_rule_for_api(rule)
            # Calculate simple relevance score based on query match
            relevance_score = cls._calculate_relevance(rule, query)
            formatted_rule['relevance_score'] = relevance_score
            formatted_results.append(formatted_rule)
        
        # Sort by relevance
        formatted_results.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        return {
            'results': formatted_results,
            'total': total,
            'query': query,
            'search_time': 0.1,  # Placeholder
            'has_results': len(formatted_results) > 0
        }
    
    @classmethod
    def format_dashboard_metrics(cls, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Format metrics for dashboard display"""
        return {
            'rules': {
                'total': metrics.get('total_rules', 0),
                'active': metrics.get('active_rules', 0),
                'private': metrics.get('private_rules', 0),
                'public': metrics.get('public_rules', 0)
            },
            'engagement': {
                'total_votes': metrics.get('total_votes', 0),
                'avg_rating': round(metrics.get('avg_rating', 0.0), 2),
                'total_usage': metrics.get('total_usage', 0),
                'community_shares': metrics.get('community_shares', 0)
            },
            'performance': {
                'avg_complexity': round(metrics.get('avg_complexity', 0.0), 1),
                'high_impact_rules': metrics.get('high_impact_rules', 0),
                'optimization_opportunities': metrics.get('optimization_opportunities', 0)
            },
            'trends': {
                'growth_rate': f"{metrics.get('growth_rate', 0.0):.1f}%",
                'top_tools': metrics.get('top_tools', []),
                'trending_categories': metrics.get('trending_categories', [])
            }
        }
    
    @classmethod
    def format_error_response(cls, error: str, error_code: str = "VALIDATION_ERROR") -> Dict[str, Any]:
        """Format error response consistently"""
        return {
            'success': False,
            'error': {
                'code': error_code,
                'message': error,
                'timestamp': datetime.utcnow().isoformat()
            }
        }
    
    @classmethod 
    def format_success_response(cls, data: Any, message: str = "Success") -> Dict[str, Any]:
        """Format success response consistently"""
        return {
            'success': True,
            'message': message,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @classmethod
    def _get_validation_summary(cls, validation_result) -> str:
        """Get a human-readable validation summary"""
        if validation_result.is_valid:
            if validation_result.warnings:
                return f"Valid with {len(validation_result.warnings)} warnings"
            return "Valid"
        else:
            return f"Invalid - {len(validation_result.errors)} errors"
    
    @classmethod
    def _calculate_relevance(cls, rule: Dict[str, Any], query: str) -> float:
        """Calculate simple relevance score for search results"""
        if not query:
            return 0.5
        
        query_lower = query.lower()
        score = 0.0
        
        # Check rule name (highest weight)
        if query_lower in rule.get('rule_name', '').lower():
            score += 0.4
        
        # Check description
        if query_lower in (rule.get('description') or '').lower():
            score += 0.3
        
        # Check tool match
        if query_lower == rule.get('tool', '').lower():
            score += 0.2
        
        # Check language match
        if query_lower == (rule.get('language') or '').lower():
            score += 0.1
        
        # Boost for popular rules
        net_votes = rule.get('upvotes', 0) - rule.get('downvotes', 0)
        if net_votes > 0:
            score += min(0.2, net_votes / 50.0)
        
        return min(1.0, score)


def format_rule_pattern_for_tool(pattern: str, tool: str, 
                                language: Optional[str] = None) -> str:
    """Format a rule pattern specifically for a given tool"""
    if tool.lower() == 'semgrep':
        # Ensure proper YAML structure for Semgrep
        if not pattern.strip().startswith('rules:'):
            return f"""rules:
  - id: custom-rule
    message: "Custom security rule"
    languages: [{language or 'python'}]
    severity: ERROR
    pattern: |
{pattern}"""
    elif tool.lower() == 'bandit':
        # Ensure proper format for Bandit
        if not pattern.strip().startswith('{'):
            return json.dumps({
                "rules": {
                    "custom_rule": {
                        "test": "custom_test",
                        "severity": "HIGH"
                    }
                }
            }, indent=2)
    
    return pattern


def truncate_pattern(pattern: str, max_length: int = 500) -> str:
    """Truncate long patterns for display"""
    if len(pattern) <= max_length:
        return pattern
    
    return pattern[:max_length - 3] + "..."


def highlight_pattern_matches(pattern: str, search_term: str) -> str:
    """Add basic highlighting markers for pattern matches (for frontend processing)"""
    if not search_term or search_term not in pattern:
        return pattern
    
    # Add markers that frontend can process for highlighting
    return pattern.replace(search_term, f"[[HIGHLIGHT]]{search_term}[[/HIGHLIGHT]]")