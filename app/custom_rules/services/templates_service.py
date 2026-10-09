"""
Rule Templates Service
Provides comprehensive security rule templates for various tools and frameworks
"""

from typing import Dict, List, Any, Optional
import yaml
import json

import logging
logger = logging.getLogger(__name__)


class RuleTemplatesService:
    """Service providing security rule templates across different tools"""
    
    def __init__(self):
        self.templates = {
            'semgrep': {
                'info': {
                    'name': 'Semgrep',
                    'description': 'Static analysis tool for finding bugs, security issues, and anti-patterns',
                    'supported_languages': ['python', 'javascript', 'typescript', 'java', 'go', 'php', 'ruby', 'c', 'cpp']
                },
                'templates': {
                    'sql-injection': {
                        'name': 'SQL Injection Detection',
                        'description': 'Detects potential SQL injection vulnerabilities',
                        'category': 'security',
                        'severity': 'high',
                        'language': 'python',
                        'pattern': '''rules:
  - id: sql-injection
    patterns:
      - pattern: $FUNC(..., $QUERY, ...)
      - pattern-inside: |
          $QUERY = "..." + $VAR + "..."
          ...
      - metavariable-regex:
          metavariable: $FUNC
          regex: (execute|query|run)
    message: Possible SQL injection
    severity: ERROR
    languages: [python]'''
                    },
                    'hardcoded-secrets': {
                        'name': 'Hardcoded Secrets Detection',
                        'description': 'Finds hardcoded API keys, passwords, and other secrets',
                        'category': 'security',
                        'severity': 'critical',
                        'language': 'python',
                        'pattern': '''rules:
  - id: hardcoded-secrets
    pattern-regex: '(password|secret|key|token)\s*=\s*["\'][a-zA-Z0-9]{10,}["\']'
    message: Hardcoded secret detected
    severity: ERROR
    languages: [python, javascript, typescript]'''
                    }
                }
            },
            'bandit': {
                'info': {
                    'name': 'Bandit',
                    'description': 'Security linter for Python code',
                    'supported_languages': ['python']
                },
                'templates': {
                    'shell-injection': {
                        'name': 'Shell Injection via Subprocess',
                        'description': 'Detects shell injection through subprocess calls',
                        'category': 'security',
                        'severity': 'high',
                        'language': 'python',
                        'pattern': '''# Custom Bandit test for shell injection
import subprocess

def test_shell_injection(context):
    if context.call_function_name in ['subprocess.call', 'subprocess.run', 'os.system']:
        if context.call_function_name_qual in ['subprocess.call', 'subprocess.run']:
            if 'shell=True' in str(context.node):
                return bandit.Issue(
                    severity=bandit.HIGH,
                    confidence=bandit.MEDIUM,
                    text="Possible shell injection via subprocess with shell=True"
                )'''
                    }
                }
            },
            'eslint': {
                'info': {
                    'name': 'ESLint',
                    'description': 'JavaScript and TypeScript linter with security plugins',
                    'supported_languages': ['javascript', 'typescript']
                },
                'templates': {
                    'xss-prevention': {
                        'name': 'XSS Prevention',
                        'description': 'Prevents dangerous DOM manipulation that could lead to XSS',
                        'category': 'security',
                        'severity': 'high',
                        'language': 'javascript',
                        'pattern': '''{
  "rules": {
    "no-dangerous-html": {
      "selector": "CallExpression[callee.property.name='innerHTML']",
      "message": "Avoid using innerHTML with user input - potential XSS vulnerability"
    }
  }
}'''
                    }
                }
            }
        }
    
    async def get_templates_for_tool(
        self, 
        tool: str, 
        category: Optional[str] = None,
        language: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get rule templates for a specific tool"""
        
        if tool not in self.templates:
            return []
        
        tool_templates = self.templates[tool]['templates']
        result = []
        
        for template_id, template_data in tool_templates.items():
            # Filter by category if specified
            if category and template_data.get('category') != category:
                continue
                
            # Filter by language if specified  
            if language and template_data.get('language') != language:
                continue
            
            result.append({
                'id': template_id,
                'tool': tool,
                'name': template_data['name'],
                'description': template_data['description'],
                'category': template_data.get('category', 'general'),
                'severity': template_data.get('severity', 'medium'),
                'language': template_data.get('language', 'any'),
                'pattern': template_data['pattern']
            })
        
        return result
    
    async def get_all_templates(self) -> Dict[str, Any]:
        """Get all available templates organized by tool"""
        
        result = {}
        
        for tool, tool_data in self.templates.items():
            templates = await self.get_templates_for_tool(tool)
            result[tool] = {
                'info': tool_data['info'],
                'templates': templates,
                'template_count': len(templates)
            }
        
        return result
    
    async def get_template_by_id(self, tool: str, template_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific template by tool and ID"""
        
        if tool not in self.templates:
            return None
        
        template_data = self.templates[tool]['templates'].get(template_id)
        if not template_data:
            return None
        
        return {
            'id': template_id,
            'tool': tool,
            'name': template_data['name'],
            'description': template_data['description'],
            'category': template_data.get('category', 'general'),
            'severity': template_data.get('severity', 'medium'),
            'language': template_data.get('language', 'any'),
            'pattern': template_data['pattern']
        }
    
    async def search_templates(
        self, 
        query: str, 
        tool: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Search templates by name or description"""
        
        query_lower = query.lower()
        results = []
        
        # Determine which tools to search
        tools_to_search = [tool] if tool else self.templates.keys()
        
        for search_tool in tools_to_search:
            templates = await self.get_templates_for_tool(search_tool, category=category)
            
            for template in templates:
                # Search in name and description
                if (query_lower in template['name'].lower() or 
                    query_lower in template['description'].lower()):
                    results.append(template)
        
        return results
    
    def get_available_tools(self) -> List[str]:
        """Get list of available tools with templates"""
        return list(self.templates.keys())
    
    def get_tool_info(self, tool: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tool"""
        return self.templates.get(tool, {}).get('info')
    
    def get_tool_categories(self, tool: str) -> List[str]:
        """Get available categories for a tool"""
        if tool not in self.templates:
            return []
        
        categories = set()
        for template_data in self.templates[tool]['templates'].values():
            categories.add(template_data.get('category', 'general'))
        
        return sorted(list(categories))
    
    def get_supported_languages(self, tool: str) -> List[str]:
        """Get supported languages for a tool"""
        if tool not in self.templates:
            return []
        
        return self.templates[tool]['info'].get('supported_languages', [])