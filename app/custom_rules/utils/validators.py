"""
Rule validation utilities for custom security rules.

Provides comprehensive validation for rule patterns, security checks,
and tool-specific validations to ensure rule quality and security.
"""

import re
import yaml
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)


class ValidationResult(BaseModel):
    """Validation result with errors, warnings and suggestions"""
    is_valid: bool
    errors: List[str] = []
    warnings: List[str] = []
    suggestions: List[str] = []
    complexity_score: int = 0
    performance_impact: str = "low"


class RuleValidator:
    """Main rule validator with comprehensive validation logic"""
    
    # Security patterns that should be flagged
    DANGEROUS_PATTERNS = [
        r'eval\s*\(',
        r'exec\s*\(',
        r'__import__\s*\(',
        r'subprocess\.',
        r'os\.system',
        r'shell=True',
        r'pickle\.loads?',
        r'input\s*\(',  # In Python 2 context
    ]
    
    # Common regex patterns that can cause ReDoS
    REDOS_PATTERNS = [
        r'\(\.\*\)\+',
        r'\(\.\*\)\*\+',
        r'\(\.\+\)\+',
        r'\(\.\+\)\*',
        r'\([^)]*\)\+\1',
    ]
    
    @classmethod
    def validate_rule_name(cls, rule_name: str) -> ValidationResult:
        """Validate rule name"""
        result = ValidationResult(is_valid=True)
        
        if not rule_name or not rule_name.strip():
            result.errors.append("Rule name cannot be empty")
            result.is_valid = False
        elif len(rule_name) < 3:
            result.errors.append("Rule name must be at least 3 characters")
            result.is_valid = False
        elif len(rule_name) > 255:
            result.errors.append("Rule name cannot exceed 255 characters")
            result.is_valid = False
        elif not re.match(r'^[a-zA-Z0-9\s\-_\.]+$', rule_name):
            result.errors.append("Rule name contains invalid characters")
            result.is_valid = False
        
        # Warnings for best practices
        if len(rule_name) < 10:
            result.warnings.append("Consider using a more descriptive rule name")
        
        if rule_name.lower() in ['test', 'sample', 'example']:
            result.warnings.append("Generic rule name detected - consider using a specific name")
        
        return result
    
    @classmethod 
    def validate_pattern_security(cls, pattern: str) -> ValidationResult:
        """Check pattern for security vulnerabilities"""
        result = ValidationResult(is_valid=True)
        
        # Check for dangerous patterns
        for dangerous_pattern in cls.DANGEROUS_PATTERNS:
            if re.search(dangerous_pattern, pattern, re.IGNORECASE):
                result.errors.append(f"Potentially dangerous code pattern detected: {dangerous_pattern}")
                result.is_valid = False
        
        # Check for ReDoS vulnerabilities
        for redos_pattern in cls.REDOS_PATTERNS:
            if re.search(redos_pattern, pattern):
                result.warnings.append("Pattern may be vulnerable to ReDoS attacks")
                result.performance_impact = "high"
        
        # Check pattern length
        if len(pattern) > 10000:
            result.errors.append("Pattern is too long (max 10,000 characters)")
            result.is_valid = False
        elif len(pattern) > 5000:
            result.warnings.append("Large pattern may impact performance")
            result.performance_impact = "medium"
        
        return result
    
    @classmethod
    def validate_pattern_complexity(cls, pattern: str) -> ValidationResult:
        """Calculate and validate pattern complexity"""
        result = ValidationResult(is_valid=True)
        
        # Calculate complexity factors
        nesting_depth = pattern.count('{') + pattern.count('[') + pattern.count('(')
        regex_patterns = len(re.findall(r'\$\{[^}]+\}|\*|\+|\?|\|', pattern))
        logical_operators = pattern.count('and') + pattern.count('or') + pattern.count('not')
        wildcards = pattern.count('*') + pattern.count('?')
        
        # Calculate complexity score
        complexity_score = min(100, (
            len(pattern) / 100 +
            nesting_depth * 5 +
            regex_patterns * 3 +
            logical_operators * 2 +
            wildcards * 1
        ))
        
        result.complexity_score = int(complexity_score)
        
        if complexity_score > 80:
            result.performance_impact = "high"
            result.warnings.append("Very high complexity pattern may significantly impact performance")
            result.suggestions.extend([
                "Consider breaking this rule into smaller, simpler rules",
                "Reduce nesting depth where possible",
                "Minimize use of wildcards and complex regex patterns"
            ])
        elif complexity_score > 50:
            result.performance_impact = "medium"
            result.warnings.append("Medium complexity pattern may impact performance")
        
        return result


class PatternValidator:
    """Tool-specific pattern validators"""
    
    @classmethod
    def validate_semgrep_pattern(cls, pattern: str) -> ValidationResult:
        """Validate Semgrep YAML pattern"""
        result = ValidationResult(is_valid=True)
        
        try:
            # Try to parse as YAML
            parsed = yaml.safe_load(pattern)
            
            if not isinstance(parsed, dict):
                result.errors.append("Semgrep pattern must be a valid YAML object")
                result.is_valid = False
                return result
            
            # Check for required fields
            if 'rules' not in parsed:
                result.errors.append("Semgrep pattern must contain 'rules' field")
                result.is_valid = False
            else:
                rules = parsed['rules']
                if not isinstance(rules, list) or not rules:
                    result.errors.append("Semgrep 'rules' must be a non-empty list")
                    result.is_valid = False
                else:
                    # Validate each rule
                    for i, rule in enumerate(rules):
                        if not isinstance(rule, dict):
                            result.errors.append(f"Rule {i+1} must be an object")
                            result.is_valid = False
                            continue
                        
                        # Check required rule fields
                        required_fields = ['id', 'message', 'languages', 'severity']
                        for field in required_fields:
                            if field not in rule:
                                result.errors.append(f"Rule {i+1} missing required field: {field}")
                                result.is_valid = False
                        
                        # Check for pattern fields
                        pattern_fields = ['pattern', 'patterns', 'pattern-either', 'pattern-not']
                        if not any(field in rule for field in pattern_fields):
                            result.errors.append(f"Rule {i+1} must contain at least one pattern field")
                            result.is_valid = False
        
        except yaml.YAMLError as e:
            result.errors.append(f"Invalid YAML syntax: {str(e)}")
            result.is_valid = False
        
        return result
    
    @classmethod
    def validate_bandit_pattern(cls, pattern: str) -> ValidationResult:
        """Validate Bandit pattern (Python plugin format)"""
        result = ValidationResult(is_valid=True)
        
        # For Bandit, patterns are usually Python code or config
        if pattern.strip().startswith('{'):
            # JSON config format
            try:
                config = json.loads(pattern)
                if 'rules' not in config:
                    result.warnings.append("Bandit config should typically contain 'rules' section")
            except json.JSONDecodeError as e:
                result.errors.append(f"Invalid JSON syntax: {str(e)}")
                result.is_valid = False
        else:
            # Python code pattern
            if 'import ast' not in pattern and 'def ' not in pattern:
                result.warnings.append("Bandit patterns typically define functions or import AST")
        
        return result
    
    @classmethod
    def validate_eslint_pattern(cls, pattern: str) -> ValidationResult:
        """Validate ESLint pattern (JavaScript plugin format)"""
        result = ValidationResult(is_valid=True)
        
        try:
            # Try to parse as JSON
            config = json.loads(pattern)
            
            if 'rules' in config:
                # Standard ESLint rules config
                rules = config['rules']
                if not isinstance(rules, dict):
                    result.errors.append("ESLint rules must be an object")
                    result.is_valid = False
            elif 'create' in pattern or 'meta' in pattern:
                # Custom rule definition
                result.suggestions.append("Ensure your custom rule exports a proper ESLint rule object")
            else:
                result.warnings.append("ESLint pattern should contain 'rules' or be a custom rule definition")
        
        except json.JSONDecodeError as e:
            # Could be JavaScript code
            if 'module.exports' not in pattern and 'export' not in pattern:
                result.warnings.append("ESLint patterns should typically export a rule or config")
        
        return result


class SecurityValidator:
    """Advanced security validation for rule patterns"""
    
    @classmethod
    def validate_injection_safety(cls, pattern: str) -> ValidationResult:
        """Check for injection vulnerabilities in patterns"""
        result = ValidationResult(is_valid=True)
        
        # Check for potential code injection
        injection_indicators = [
            r'\$\{.*\}.*eval',
            r'\$\{.*\}.*exec',
            r'`.*\$\{.*\}.*`',
            r'eval\(\$\{.*\}\)',
        ]
        
        for indicator in injection_indicators:
            if re.search(indicator, pattern, re.IGNORECASE):
                result.errors.append("Pattern contains potential code injection vulnerability")
                result.is_valid = False
                break
        
        # Check for path traversal in patterns
        if '../' in pattern or '..\\' in pattern:
            result.warnings.append("Pattern contains path traversal sequences - ensure this is intentional")
        
        return result
    
    @classmethod
    def validate_performance_safety(cls, pattern: str) -> ValidationResult:
        """Check for performance and DoS vulnerabilities"""
        result = ValidationResult(is_valid=True)
        
        # Check for catastrophic backtracking patterns
        backtrack_patterns = [
            r'\([^)]*\*[^)]*\)\+',
            r'\([^)]*\+[^)]*\)\*',
            r'(\.[*+]){2,}',
        ]
        
        for backtrack in backtrack_patterns:
            if re.search(backtrack, pattern):
                result.warnings.append("Pattern may cause catastrophic backtracking")
                result.performance_impact = "high"
                result.suggestions.append("Consider using non-greedy quantifiers or atomic groups")
        
        # Check for excessive resource usage patterns
        if pattern.count('.*') > 5:
            result.warnings.append("Many .* patterns may impact performance")
            result.performance_impact = "medium"
        
        return result


def validate_complete_rule(rule_data: Dict[str, Any]) -> ValidationResult:
    """
    Perform complete validation on a rule including all aspects:
    - Rule structure and naming
    - Pattern security and complexity
    - Tool-specific validation
    """
    overall_result = ValidationResult(is_valid=True)
    
    # Validate rule name
    if 'rule_name' in rule_data:
        name_result = RuleValidator.validate_rule_name(rule_data['rule_name'])
        overall_result.errors.extend(name_result.errors)
        overall_result.warnings.extend(name_result.warnings)
        overall_result.suggestions.extend(name_result.suggestions)
        if not name_result.is_valid:
            overall_result.is_valid = False
    
    # Validate pattern
    if 'pattern' in rule_data:
        pattern = rule_data['pattern']
        
        # Security validation
        security_result = RuleValidator.validate_pattern_security(pattern)
        overall_result.errors.extend(security_result.errors)
        overall_result.warnings.extend(security_result.warnings)
        overall_result.suggestions.extend(security_result.suggestions)
        if not security_result.is_valid:
            overall_result.is_valid = False
        
        # Complexity validation
        complexity_result = RuleValidator.validate_pattern_complexity(pattern)
        overall_result.complexity_score = complexity_result.complexity_score
        overall_result.performance_impact = complexity_result.performance_impact
        overall_result.warnings.extend(complexity_result.warnings)
        overall_result.suggestions.extend(complexity_result.suggestions)
        
        # Advanced security checks
        injection_result = SecurityValidator.validate_injection_safety(pattern)
        perf_result = SecurityValidator.validate_performance_safety(pattern)
        
        overall_result.errors.extend(injection_result.errors)
        overall_result.warnings.extend(injection_result.warnings + perf_result.warnings)
        overall_result.suggestions.extend(injection_result.suggestions + perf_result.suggestions)
        
        if not injection_result.is_valid:
            overall_result.is_valid = False
        
        # Update performance impact to worst case
        if perf_result.performance_impact == "high":
            overall_result.performance_impact = "high"
        elif perf_result.performance_impact == "medium" and overall_result.performance_impact == "low":
            overall_result.performance_impact = "medium"
        
        # Tool-specific validation
        tool = rule_data.get('tool', '').lower()
        if tool == 'semgrep':
            tool_result = PatternValidator.validate_semgrep_pattern(pattern)
        elif tool == 'bandit':
            tool_result = PatternValidator.validate_bandit_pattern(pattern)
        elif tool == 'eslint':
            tool_result = PatternValidator.validate_eslint_pattern(pattern)
        else:
            tool_result = ValidationResult(is_valid=True)
        
        overall_result.errors.extend(tool_result.errors)
        overall_result.warnings.extend(tool_result.warnings)
        overall_result.suggestions.extend(tool_result.suggestions)
        if not tool_result.is_valid:
            overall_result.is_valid = False
    
    return overall_result