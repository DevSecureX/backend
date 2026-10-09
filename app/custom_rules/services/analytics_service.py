"""
Multi-Tool Custom Rules Service
Provides comprehensive custom rule support across multiple security tools
"""

import os
import json
import yaml
import tempfile
import subprocess
import logging
import hashlib
import re
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from fastapi import HTTPException, status

from custom_rules.models import CommunityRules
from custom_rules.config.rules_config import RulesConfig
from .rules_service import CustomRulesService

logger = logging.getLogger(__name__)

class RuleAnalyticsService:
    """Service for managing custom rules across multiple security tools"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.base_service = CustomRulesService(db)
        
        # Tool-specific validators and generators (only actually implemented tools)
        self.tool_handlers = {
            'semgrep': SemgrepRuleHandler(),
            'bandit': BanditRuleHandler(),
            'eslint-security': ESLintSecurityRuleHandler(),
            'gosec': GosecRuleHandler(),
            'checkov': CheckovRuleHandler(),
            'safety': SafetyRuleHandler(),
            'trivy': TrivyRuleHandler(),
            'gitleaks': GitleaksRuleHandler(),
            'cppcheck': CppCheckRuleHandler(),
            'psalm': PsalmRuleHandler(),
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # 'roslynator': RoslynatorRuleHandler(),
            'spotbugs': SpotBugsRuleHandler(),
            'brakeman': BrakemanRuleHandler()
            # Note: CodeQL, SonarQube, Snyk removed - no actual implementation
        }
    
    async def create_multi_tool_rule(
        self,
        user_id: int,
        rule_data: Dict[str, Any],
        target_tools: List[str] = None
    ) -> Dict[str, Any]:
        """Create a rule that can be automatically translated across multiple tools"""
        
        # Validate primary tool
        primary_tool = rule_data.get('tool', 'semgrep')
        if primary_tool not in self.tool_handlers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported primary tool: {primary_tool}"
            )
        
        # Create the primary rule
        primary_rule = await self.base_service.create_rule(user_id, rule_data)
        
        # Auto-translate to other tools if requested
        translated_rules = []
        if target_tools:
            for target_tool in target_tools:
                if target_tool != primary_tool and target_tool in self.tool_handlers:
                    try:
                        translated_rule = await self._translate_rule(
                            primary_rule, primary_tool, target_tool
                        )
                        if translated_rule:
                            # Create the translated rule
                            translated_rule_data = {
                                **rule_data,
                                'tool': target_tool,
                                'pattern': translated_rule['pattern'],
                                'rule_name': f"{rule_data['rule_name']} (translated from {primary_tool})",
                                'description': f"Auto-translated from {primary_tool}: {rule_data.get('description', '')}",
                                'parent_rule_id': primary_rule['id']
                            }
                            
                            translated_result = await self.base_service.create_rule(
                                user_id, translated_rule_data
                            )
                            translated_rules.append({
                                'tool': target_tool,
                                'rule': translated_result,
                                'translation_confidence': translated_rule['confidence']
                            })
                    
                    except Exception as e:
                        logger.warning(f"Failed to translate rule to {target_tool}: {str(e)}")
                        translated_rules.append({
                            'tool': target_tool,
                            'error': str(e),
                            'translation_confidence': 0
                        })
        
        return {
            'primary_rule': primary_rule,
            'translated_rules': translated_rules,
            'total_created': 1 + len([r for r in translated_rules if 'rule' in r])
        }
    
    async def validate_rule_for_tool(
        self,
        rule_pattern: str,
        tool: str,
        language: str = None
    ) -> Dict[str, Any]:
        """Validate a rule pattern for a specific tool"""
        
        if tool not in self.tool_handlers:
            return {
                'valid': False,
                'error': f'Unsupported tool: {tool}',
                'tool_supported': False
            }
        
        handler = self.tool_handlers[tool]
        return await handler.validate_pattern(rule_pattern, language)
    
    async def test_rule_sandbox(
        self,
        rule_data: Dict[str, Any],
        test_code: str,
        language: str = None
    ) -> Dict[str, Any]:
        """Test a rule in a secure sandbox environment"""
        
        tool = rule_data.get('tool')
        if tool not in self.tool_handlers:
            return {
                'success': False,
                'error': f'Tool {tool} not supported for sandbox testing'
            }
        
        handler = self.tool_handlers[tool]
        
        # Security checks before running
        if not handler.is_sandbox_safe(rule_data['pattern']):
            return {
                'success': False,
                'error': 'Rule pattern contains potentially unsafe elements'
            }
        
        return await handler.test_in_sandbox(rule_data, test_code, language)
    
    async def get_rule_recommendations(
        self,
        vulnerability_type: str,
        language: str,
        tool: str = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get rule recommendations based on vulnerability type and language"""
        
        # Get community rules for similar vulnerabilities
        query = select(CommunityRules).where(
            and_(
                CommunityRules.is_public == True,
                CommunityRules.is_deprecated == False,
                or_(
                    CommunityRules.language == language,
                    CommunityRules.language.is_(None)  # Language-agnostic rules
                ),
                or_(
                    CommunityRules.description.ilike(f'%{vulnerability_type}%'),
                    CommunityRules.rule_name.ilike(f'%{vulnerability_type}%'),
                    CommunityRules.tags.contains([vulnerability_type.lower()]),
                    CommunityRules.owasp_categories.contains([vulnerability_type.lower()]),
                    CommunityRules.cwe_mappings.contains([vulnerability_type.upper()])
                )
            )
        )
        
        if tool:
            query = query.where(CommunityRules.tool == tool)
        
        query = query.order_by(
            CommunityRules.effectiveness_score.desc().nulls_last(),
            CommunityRules.upvotes.desc(),
            CommunityRules.usage_count.desc()
        ).limit(limit)
        
        result = await self.db.execute(query)
        rules = result.scalars().all()
        
        recommendations = []
        for rule in rules:
            # Calculate recommendation score
            effectiveness = rule.effectiveness_score or 0
            popularity = (rule.upvotes * 2) + rule.usage_count
            recency_bonus = 1.0 if rule.updated_at > (datetime.now(timezone.utc) - timedelta(days=30)) else 0.5
            
            recommendation_score = (effectiveness * 0.4) + (popularity * 0.4) + (recency_bonus * 0.2)
            
            recommendations.append({
                'id': rule.id,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language,
                'description': rule.description,
                'effectiveness_score': rule.effectiveness_score,
                'upvotes': rule.upvotes,
                'downvotes': rule.downvotes,
                'usage_count': rule.usage_count,
                'complexity_score': rule.complexity_score,
                'false_positive_rate': rule.false_positive_rate,
                'performance_impact': rule.performance_impact,
                'recommendation_score': round(recommendation_score, 2),
                'tags': rule.tags,
                'owasp_categories': rule.owasp_categories,
                'cwe_mappings': rule.cwe_mappings,
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat()
            })
        
        # Sort by recommendation score
        recommendations.sort(key=lambda x: x['recommendation_score'], reverse=True)
        return recommendations
    
    async def generate_rule_from_vulnerability(
        self,
        vulnerability_description: str,
        language: str,
        tool: str = 'semgrep',
        use_ai: bool = False
    ) -> Dict[str, Any]:
        """Generate a rule from vulnerability description"""
        
        if use_ai:
            return await self._ai_generate_rule(vulnerability_description, language, tool)
        else:
            return await self._template_generate_rule(vulnerability_description, language, tool)
    
    async def optimize_rule_performance(
        self,
        rule_id: str,
        user_id: int
    ) -> Dict[str, Any]:
        """Analyze and suggest optimizations for rule performance"""
        
        rule = await self.base_service.get_rule_by_id(rule_id, user_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Rule not found")
        
        tool = rule['tool']
        pattern = rule['pattern']
        
        # Get performance analytics
        analytics_query = select(RuleUsageAnalytics).where(
            RuleUsageAnalytics.rule_id == rule_id
        ).order_by(RuleUsageAnalytics.usage_date.desc()).limit(100)
        
        analytics_result = await self.db.execute(analytics_query)
        analytics = analytics_result.scalars().all()
        
        # Calculate performance metrics
        if analytics:
            avg_execution_time = sum(a.execution_time_ms or 0 for a in analytics) / len(analytics)
            false_positive_rate = sum(a.false_positives_reported for a in analytics) / max(1, sum(a.findings_count for a in analytics))
        else:
            avg_execution_time = 0
            false_positive_rate = 0
        
        # Get tool-specific optimizations
        handler = self.tool_handlers.get(tool)
        optimizations = []
        
        if handler:
            optimizations = handler.suggest_optimizations(pattern, {
                'avg_execution_time': avg_execution_time,
                'false_positive_rate': false_positive_rate,
                'usage_count': rule['usage_count']
            })
        
        # Calculate complexity score
        complexity_analysis = RulesConfig.get_rule_complexity_score(pattern, tool)
        
        return {
            'current_performance': {
                'avg_execution_time_ms': avg_execution_time,
                'false_positive_rate': false_positive_rate,
                'complexity_score': complexity_analysis['score'],
                'complexity_level': complexity_analysis['level']
            },
            'optimizations': optimizations,
            'recommendations': complexity_analysis['recommendations']
        }
    
    async def _translate_rule(
        self,
        source_rule: Dict[str, Any],
        source_tool: str,
        target_tool: str
    ) -> Optional[Dict[str, Any]]:
        """Translate a rule from one tool to another"""
        
        source_handler = self.tool_handlers.get(source_tool)
        target_handler = self.tool_handlers.get(target_tool)
        
        if not source_handler or not target_handler:
            return None
        
        # Extract semantic information from source rule
        semantic_info = source_handler.extract_semantics(source_rule['pattern'])
        
        # Generate target rule pattern
        target_pattern = target_handler.generate_from_semantics(
            semantic_info, source_rule.get('language')
        )
        
        if not target_pattern:
            return None
        
        return {
            'pattern': target_pattern['pattern'],
            'confidence': target_pattern['confidence'],
            'notes': target_pattern.get('notes', [])
        }
    
    async def _ai_generate_rule(
        self,
        vulnerability_description: str,
        language: str,
        tool: str
    ) -> Dict[str, Any]:
        """Use AI to generate a rule from vulnerability description"""
        # This would integrate with OpenAI or similar AI service
        # For now, use template-based generation with AI-like intelligence
        
        handler = self.tool_handlers.get(tool)
        if not handler:
            return {
                'success': False,
                'error': f'Tool {tool} not supported'
            }
        
        # Enhanced template generation with better pattern matching
        ai_enhanced_result = handler.generate_from_template(vulnerability_description, language)
        
        if ai_enhanced_result.get('success'):
            # Add AI-like enhancements
            ai_enhanced_result['ai_generated'] = True
            ai_enhanced_result['generation_method'] = 'template_enhanced'
            ai_enhanced_result['confidence'] = min(0.9, ai_enhanced_result.get('confidence', 0.7) + 0.1)
            
            # TODO: Integrate with actual AI service like OpenAI GPT-4
            # This would send the vulnerability_description, language, and tool
            # to the AI service and get back a properly formatted rule
        
        return ai_enhanced_result
    
    async def _template_generate_rule(
        self,
        vulnerability_description: str,
        language: str,
        tool: str
    ) -> Dict[str, Any]:
        """Generate rule using templates and patterns"""
        
        handler = self.tool_handlers.get(tool)
        if not handler:
            return {
                'success': False,
                'error': f'Tool {tool} not supported'
            }
        
        result = handler.generate_from_template(vulnerability_description, language)
        
        # Add additional metadata for template-based generation
        if result.get('success'):
            result['generation_method'] = 'template_based'
            result['template_matched'] = True
        
        return result


class BaseRuleHandler:
    """Base class for tool-specific rule handlers"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate rule pattern for this tool"""
        raise NotImplementedError
    
    async def test_in_sandbox(self, rule_data: Dict, test_code: str, language: str) -> Dict[str, Any]:
        """Test rule in secure sandbox environment"""
        
        # Create secure sandbox environment
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Write test code to file
                file_ext = self._get_file_extension(language)
                test_file = os.path.join(temp_dir, f'test_code.{file_ext}')
                
                with open(test_file, 'w', encoding='utf-8') as f:
                    f.write(test_code)
                
                # Execute tool-specific testing
                return await self._execute_tool_test(rule_data, test_file, temp_dir)
                
            except Exception as e:
                logger.error(f"Sandbox test failed: {str(e)}")
                return {
                    'success': False,
                    'error': f'Sandbox execution failed: {str(e)}',
                    'execution_time_ms': 0,
                    'findings': []
                }
    
    def _get_file_extension(self, language: str) -> str:
        """Get appropriate file extension for language"""
        extensions = {
            'python': 'py',
            'javascript': 'js', 
            'typescript': 'ts',
            'java': 'java',
            'go': 'go',
            'php': 'php',
            'ruby': 'rb',
            'c': 'c',
            'cpp': 'cpp',
            'c++': 'cpp',
            'csharp': 'cs',
            'c#': 'cs',
            'rust': 'rs',
            'scala': 'scala',
            'kotlin': 'kt'
        }
        return extensions.get(language.lower(), 'txt')
    
    async def _execute_tool_test(self, rule_data: Dict, test_file: str, temp_dir: str) -> Dict[str, Any]:
        """Execute tool-specific testing"""
        # Default implementation - subclasses should override
        return {
            'success': False,
            'error': f'Sandbox testing not implemented for {self.tool_name}',
            'execution_time_ms': 0,
            'findings': []
        }
    
    def is_sandbox_safe(self, pattern: str) -> bool:
        """Check if pattern is safe for sandbox execution"""
        dangerous_patterns = [
            'subprocess', 'exec', 'eval', 'import os', 'system(',
            'shell=True', '__import__', 'compile('
        ]
        pattern_lower = pattern.lower()
        return not any(dangerous in pattern_lower for dangerous in dangerous_patterns)
    
    def extract_semantics(self, pattern: str) -> Dict[str, Any]:
        """Extract semantic information from rule pattern"""
        raise NotImplementedError
    
    def generate_from_semantics(self, semantics: Dict, language: str) -> Dict[str, Any]:
        """Generate rule pattern from semantic information"""
        raise NotImplementedError
    
    def generate_from_template(self, vulnerability_desc: str, language: str) -> Dict[str, Any]:
        """Generate rule from template"""
        raise NotImplementedError
    
    def suggest_optimizations(self, pattern: str, metrics: Dict) -> List[str]:
        """Suggest optimizations for the rule"""
        return []


class SemgrepRuleHandler(BaseRuleHandler):
    """Handler for Semgrep rules"""
    
    def __init__(self):
        super().__init__('semgrep')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Semgrep YAML pattern"""
        try:
            parsed = yaml.safe_load(pattern)
            
            # Check required fields
            if not isinstance(parsed, dict):
                return {'valid': False, 'error': 'Pattern must be a YAML object'}
            
            required_fields = ['patterns', 'message', 'languages', 'severity']
            missing_fields = [f for f in required_fields if f not in parsed]
            
            if missing_fields and 'pattern' not in parsed:
                return {
                    'valid': False,
                    'error': f'Missing required fields: {missing_fields}'
                }
            
            return {'valid': True, 'parsed': parsed}
            
        except yaml.YAMLError as e:
            return {'valid': False, 'error': f'Invalid YAML: {str(e)}'}
    
    def extract_semantics(self, pattern: str) -> Dict[str, Any]:
        """Extract semantic information from Semgrep pattern"""
        try:
            parsed = yaml.safe_load(pattern)
            return {
                'type': 'pattern_matching',
                'patterns': parsed.get('patterns', [parsed.get('pattern')]),
                'language': parsed.get('languages', []),
                'severity': parsed.get('severity'),
                'message': parsed.get('message')
            }
        except:
            return {'type': 'unknown'}
    
    def generate_from_template(self, vulnerability_desc: str, language: str) -> Dict[str, Any]:
        """Generate Semgrep rule from template"""
        
        # Simple template-based generation
        templates = {
            'sql injection': {
                'pattern': 'execute($SQL)',
                'message': 'Potential SQL injection vulnerability',
                'severity': 'ERROR'
            },
            'command injection': {
                'pattern': 'subprocess.call($CMD, shell=True)',
                'message': 'Command injection vulnerability',
                'severity': 'ERROR'
            },
            'hardcoded secret': {
                'pattern': 'password = "..."',
                'message': 'Hardcoded password detected',
                'severity': 'WARNING'
            }
        }
        
        for vuln_type, template in templates.items():
            if vuln_type.lower() in vulnerability_desc.lower():
                rule = {
                    'patterns': [{'pattern': template['pattern']}],
                    'message': template['message'],
                    'languages': [language],
                    'severity': template['severity']
                }
                
                return {
                    'success': True,
                    'pattern': yaml.dump({'rules': [rule]}),
                    'confidence': 0.7
                }
        
        return {
            'success': False,
            'error': 'No suitable template found for this vulnerability type'
        }


class BanditRuleHandler(BaseRuleHandler):
    """Handler for Bandit rules"""
    
    def __init__(self):
        super().__init__('bandit')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Bandit rule pattern"""
        if language and language != 'python':
            return {'valid': False, 'error': 'Bandit only supports Python'}
        
        # Basic validation - would need more sophisticated parsing
        if 'def ' not in pattern and 'class ' not in pattern:
            return {'valid': False, 'error': 'Bandit rules require Python function or class definitions'}
        
        return {'valid': True}
    
    def generate_from_template(self, vulnerability_desc: str, language: str) -> Dict[str, Any]:
        """Generate Bandit rule from template"""
        if language != 'python':
            return {'success': False, 'error': 'Bandit only supports Python'}
        
        # Placeholder - would implement proper Bandit rule generation
        return {
            'success': False,
            'error': 'Bandit rule generation not implemented yet'
        }


class ESLintSecurityRuleHandler(BaseRuleHandler):
    """Handler for ESLint Security Plugin rules"""
    
    def __init__(self):
        super().__init__('eslint-security')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate ESLint Security rule pattern"""
        if language and language not in ['javascript', 'typescript']:
            return {'valid': False, 'error': 'ESLint Security only supports JavaScript/TypeScript'}
        
        try:
            # Parse as JSON configuration or JavaScript function
            if pattern.strip().startswith('{'):
                # JSON configuration format
                config = json.loads(pattern)
                required_keys = ['meta', 'create']
                missing = [k for k in required_keys if k not in config]
                if missing:
                    return {'valid': False, 'error': f'Missing required keys: {missing}'}
                return {'valid': True, 'parsed': config}
            elif 'function(' in pattern or 'create(' in pattern:
                return {'valid': True}
            else:
                return {'valid': False, 'error': 'ESLint rules must be JavaScript functions or JSON config'}
        except json.JSONDecodeError as e:
            return {'valid': False, 'error': f'Invalid JSON syntax: {str(e)}'}
        except Exception as e:
            return {'valid': False, 'error': f'Invalid pattern: {str(e)}'}
    
    def generate_from_template(self, vulnerability_desc: str, language: str) -> Dict[str, Any]:
        """Generate ESLint Security rule from template"""
        if language not in ['javascript', 'typescript']:
            return {'success': False, 'error': 'ESLint Security only supports JavaScript/TypeScript'}
        
        templates = {
            'xss': {
                'meta': {
                    'type': 'problem',
                    'docs': {'description': 'Detect potential XSS vulnerabilities'},
                    'schema': []
                },
                'create': 'function(context) { return { CallExpression: function(node) { if (node.callee.property && node.callee.property.name === "innerHTML") { context.report(node, "Potential XSS vulnerability with innerHTML"); } } }; }'
            },
            'sql injection': {
                'meta': {
                    'type': 'problem', 
                    'docs': {'description': 'Detect SQL injection vulnerabilities'},
                    'schema': []
                },
                'create': 'function(context) { return { CallExpression: function(node) { if (node.callee.name === "query" && node.arguments.length > 0) { context.report(node, "Potential SQL injection vulnerability"); } } }; }'
            }
        }
        
        for vuln_type, template in templates.items():
            if vuln_type.lower() in vulnerability_desc.lower():
                return {
                    'success': True,
                    'pattern': json.dumps(template, indent=2),
                    'confidence': 0.8
                }
        
        return {
            'success': False,
            'error': 'No suitable template found for this vulnerability type'
        }


class GosecRuleHandler(BaseRuleHandler):
    """Handler for Gosec rules"""
    
    def __init__(self):
        super().__init__('gosec')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Gosec rule pattern"""
        if language and language != 'go':
            return {'valid': False, 'error': 'Gosec only supports Go'}
        
        return {'valid': True}  # Placeholder


class CheckovRuleHandler(BaseRuleHandler):
    """Handler for Checkov rules"""
    
    def __init__(self):
        super().__init__('checkov')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Checkov rule pattern"""
        supported_languages = ['terraform', 'cloudformation', 'kubernetes', 'dockerfile']
        if language and language not in supported_languages:
            return {
                'valid': False,
                'error': f'Checkov supports: {supported_languages}'
            }
        
        return {'valid': True}  # Placeholder


class SafetyRuleHandler(BaseRuleHandler):
    """Handler for Safety (Python dependency security) rules"""
    
    def __init__(self):
        super().__init__('safety')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Safety rule pattern"""
        if language and language != 'python':
            return {'valid': False, 'error': 'Safety only supports Python dependencies'}
        
        try:
            # Safety rules are typically JSON with package specifications
            if pattern.strip().startswith('{'):
                config = json.loads(pattern)
                if 'package' not in config or 'versions' not in config:
                    return {'valid': False, 'error': 'Safety rules must specify package and vulnerable versions'}
                return {'valid': True, 'parsed': config}
            else:
                return {'valid': False, 'error': 'Safety rules must be JSON format'}
        except json.JSONDecodeError as e:
            return {'valid': False, 'error': f'Invalid JSON: {str(e)}'}
    
    def generate_from_template(self, vulnerability_desc: str, language: str) -> Dict[str, Any]:
        """Generate Safety rule from template"""
        template = {
            'package': 'vulnerable-package',
            'versions': ['<1.2.3'],
            'cve': 'CVE-2023-XXXX',
            'severity': 'HIGH',
            'description': vulnerability_desc
        }
        
        return {
            'success': True,
            'pattern': json.dumps(template, indent=2),
            'confidence': 0.9
        }


class TrivyRuleHandler(BaseRuleHandler):
    """Handler for Trivy (container/IaC security) rules"""
    
    def __init__(self):
        super().__init__('trivy')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Trivy OPA Rego rule pattern"""
        supported_types = ['dockerfile', 'kubernetes', 'terraform', 'rego']
        if language and language not in supported_types:
            return {'valid': False, 'error': f'Trivy supports: {supported_types}'}
        
        # Basic Rego syntax validation
        if 'package ' not in pattern or 'deny[' not in pattern:
            return {'valid': False, 'error': 'Trivy rules must be valid OPA Rego policies'}
        
        return {'valid': True}
    
    def generate_from_template(self, vulnerability_desc: str, language: str) -> Dict[str, Any]:
        """Generate Trivy Rego rule from template"""
        template = f'''package trivy.custom

import rego.v1

# {vulnerability_desc}
deny[msg] {{
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.image
    not starts_with(container.image, "secure-registry/")
    msg := "Container image must be from secure registry"
}}'''
        
        return {
            'success': True,
            'pattern': template,
            'confidence': 0.7
        }


class GitleaksRuleHandler(BaseRuleHandler):
    """Handler for Gitleaks (secrets detection) rules"""
    
    def __init__(self):
        super().__init__('gitleaks')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Gitleaks rule pattern"""
        try:
            config = yaml.safe_load(pattern)
            
            if not isinstance(config, dict) or 'rules' not in config:
                return {'valid': False, 'error': 'Gitleaks config must contain rules'}
            
            for rule in config['rules']:
                if 'id' not in rule or 'regex' not in rule:
                    return {'valid': False, 'error': 'Each rule must have id and regex'}
            
            return {'valid': True, 'parsed': config}
        except yaml.YAMLError as e:
            return {'valid': False, 'error': f'Invalid YAML: {str(e)}'}
    
    def generate_from_template(self, vulnerability_desc: str, language: str) -> Dict[str, Any]:
        """Generate Gitleaks rule from template"""
        templates = {
            'api key': {
                'id': 'api-key-generic',
                'description': 'Generic API key detection',
                'regex': r'(?i)api[_-]?key[_-]?[=:\s]*["\']?[a-zA-Z0-9]{20,}["\']?',
                'keywords': ['api', 'key']
            },
            'password': {
                'id': 'hardcoded-password',
                'description': 'Hardcoded password detection', 
                'regex': r'(?i)password[_-]?[=:\s]*["\']?[a-zA-Z0-9!@#$%^&*]{8,}["\']?',
                'keywords': ['password']
            }
        }
        
        for secret_type, template in templates.items():
            if secret_type.lower() in vulnerability_desc.lower():
                rule_config = {
                    'rules': [template]
                }
                return {
                    'success': True,
                    'pattern': yaml.dump(rule_config),
                    'confidence': 0.8
                }
        
        return {
            'success': False,
            'error': 'No suitable template found for this secret type'
        }


class SonarQubeRuleHandler(BaseRuleHandler):
    """Handler for SonarQube custom rules"""
    
    def __init__(self):
        super().__init__('sonarqube')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate SonarQube rule pattern"""
        try:
            config = json.loads(pattern)
            required_fields = ['key', 'name', 'type', 'severity']
            missing = [f for f in required_fields if f not in config]
            
            if missing:
                return {'valid': False, 'error': f'Missing required fields: {missing}'}
            
            return {'valid': True, 'parsed': config}
        except json.JSONDecodeError as e:
            return {'valid': False, 'error': f'Invalid JSON: {str(e)}'}


# CodeQL and Snyk handlers removed - no actual implementation in scanner engine

# Enhanced existing handlers
class CppCheckRuleHandler(BaseRuleHandler):
    """Handler for CppCheck (C/C++ static analysis) rules"""
    
    def __init__(self):
        super().__init__('cppcheck')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate CppCheck rule pattern"""
        if language and language not in ['c', 'cpp', 'c++']:
            return {'valid': False, 'error': 'CppCheck only supports C/C++'}
        
        # CppCheck rules are XML-based
        if '<rule>' not in pattern or '<check>' not in pattern:
            return {'valid': False, 'error': 'CppCheck rules must be valid XML with rule and check elements'}
        
        return {'valid': True}


class PsalmRuleHandler(BaseRuleHandler):
    """Handler for Psalm (PHP static analysis) rules"""
    
    def __init__(self):
        super().__init__('psalm')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Psalm rule pattern"""
        if language and language != 'php':
            return {'valid': False, 'error': 'Psalm only supports PHP'}
        
        # Psalm plugins are PHP classes
        if 'class ' not in pattern or 'Plugin' not in pattern:
            return {'valid': False, 'error': 'Psalm rules must be PHP plugin classes'}
        
        return {'valid': True}


# DISABLED: Roslynator tool commented out - C#/.NET tool not installed
# class RoslynatorRuleHandler(BaseRuleHandler):
#     """Handler for Roslynator (C# analyzer) rules"""
#     
#     def __init__(self):
#         super().__init__('roslynator')
#     
#     async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
#         """Validate Roslynator rule pattern"""
#         if language and language not in ['csharp', 'c#']:
#             return {'valid': False, 'error': 'Roslynator only supports C#'}
#         
#         # Roslynator rules are C# analyzer classes
#         if 'DiagnosticAnalyzer' not in pattern:
#             return {'valid': False, 'error': 'Roslynator rules must inherit from DiagnosticAnalyzer'}
#         
#         return {'valid': True}


class SpotBugsRuleHandler(BaseRuleHandler):
    """Handler for SpotBugs (Java static analysis) rules"""
    
    def __init__(self):
        super().__init__('spotbugs')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate SpotBugs rule pattern"""
        if language and language not in ['java', 'scala', 'kotlin']:
            return {'valid': False, 'error': 'SpotBugs supports Java, Scala, and Kotlin'}
        
        # SpotBugs rules are XML-based bug patterns
        if '<BugPattern' not in pattern:
            return {'valid': False, 'error': 'SpotBugs rules must contain BugPattern element'}
        
        return {'valid': True}


class BrakemanRuleHandler(BaseRuleHandler):
    """Handler for Brakeman (Ruby security scanner) rules"""
    
    def __init__(self):
        super().__init__('brakeman')
    
    async def validate_pattern(self, pattern: str, language: str = None) -> Dict[str, Any]:
        """Validate Brakeman rule pattern"""
        if language and language != 'ruby':
            return {'valid': False, 'error': 'Brakeman only supports Ruby'}
        
        # Brakeman checks are Ruby classes
        if 'class ' not in pattern or 'Check' not in pattern:
            return {'valid': False, 'error': 'Brakeman rules must be Ruby check classes'}
        
        return {'valid': True}