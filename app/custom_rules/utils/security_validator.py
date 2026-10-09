"""
Security Validation Utilities for Custom Rules
Comprehensive validation and sanitization for user-generated security rules
"""

import re
import yaml
from typing import Dict, Any, List, Optional
import logging
from pydantic import BaseModel, validator

logger = logging.getLogger(__name__)

class SecurityValidator:
    """
    Comprehensive security validator for custom rules
    Prevents injection attacks and validates rule structure
    """
    
    # Maximum sizes to prevent DoS attacks
    MAX_PATTERN_SIZE = 10000  # 10KB
    MAX_RULE_NAME_LENGTH = 100
    MAX_DESCRIPTION_LENGTH = 500
    MAX_MESSAGE_LENGTH = 200
    MAX_RULES_PER_SCAN = 100
    MAX_COMMUNITY_RULES_PER_SCAN = 50
    
    # Allowed values - Updated to match actual platform capabilities (no CodeQL runner exists)
    ALLOWED_TOOLS = {
        'semgrep', 'bandit', 'eslint-security',           # Core SAST tools
        'gosec', 'checkov', 'cppcheck', 'psalm',          # Language-specific tools 
        # DISABLED: 'roslynator' - C#/.NET tool not installed  
        'spotbugs', 'brakeman',             # More language tools
        'gitleaks', 'safety'                              # Secret detection and dependency scanning
        # Note: CodeQL removed - no actual runner implementation exists
        # Note: Only eslint-security supported, not plain eslint
        # Note: trivy excluded as it doesn't support custom rules (supports_custom: False)
    }
    ALLOWED_NICHES = {'all', 'ai', 'blockchain', 'iot', 'web', 'cloud', 'api'}
    ALLOWED_SEVERITIES = {'ERROR', 'WARNING', 'INFO'}
    ALLOWED_LANGUAGES = {
        'python', 'javascript', 'java', 'go', 'rust', 'typescript',
        'php', 'ruby', 'csharp', 'cpp', 'c', 'swift', 'kotlin',
        'scala', 'generic'
    }
    
    # Security patterns to block (only actual execution, not detection patterns)
    DANGEROUS_PATTERNS = {
        '!!python',  # YAML Python object instantiation
        '__import__(',  # Direct Python imports in execution context
        'eval(',  # Direct eval execution 
        'exec(',  # Direct exec execution
    }
    
    # UUID pattern for ID validation
    UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    
    @classmethod
    def validate_user_id(cls, user_id: int) -> bool:
        """Validate user ID"""
        return isinstance(user_id, int) and user_id > 0
    
    @classmethod
    def validate_tool(cls, tool: str) -> str:
        """Validate and sanitize tool parameter"""
        if not isinstance(tool, str):
            raise ValueError("Tool must be a string")
        
        tool_clean = tool.lower().strip()
        if tool_clean not in cls.ALLOWED_TOOLS:
            raise ValueError(f"Unsupported tool: {tool}. Allowed: {cls.ALLOWED_TOOLS}")
        
        return tool_clean
    
    @classmethod
    def validate_niche(cls, niche: str) -> str:
        """Validate and sanitize niche parameter"""
        if not isinstance(niche, str):
            raise ValueError("Niche must be a string")
        
        niche_clean = niche.lower().strip()
        if niche_clean not in cls.ALLOWED_NICHES:
            raise ValueError(f"Unsupported niche: {niche}. Allowed: {cls.ALLOWED_NICHES}")
        
        return niche_clean
    
    @classmethod
    def validate_rule_ids(cls, rule_ids: Optional[List[str]], max_count: int) -> List[str]:
        """Validate list of rule IDs"""
        if not rule_ids:
            return []
        
        if not isinstance(rule_ids, list):
            raise ValueError("Rule IDs must be a list")
        
        if len(rule_ids) > max_count:
            raise ValueError(f"Too many rules selected (max: {max_count})")
        
        validated_ids = []
        for rule_id in rule_ids:
            if not isinstance(rule_id, str):
                raise ValueError("Rule ID must be a string")
            
            rule_id = rule_id.strip()
            if not cls.UUID_PATTERN.match(rule_id):
                raise ValueError(f"Invalid rule ID format: {rule_id}")
            
            validated_ids.append(rule_id)
        
        return validated_ids
    
    @classmethod
    def validate_rule_pattern(cls, pattern: str) -> Dict[str, Any]:
        """
        Comprehensive validation of rule pattern
        Returns parsed pattern if valid, raises ValueError if invalid
        """
        if not isinstance(pattern, str):
            raise ValueError("Pattern must be a string")
        
        # Size validation
        if len(pattern) > cls.MAX_PATTERN_SIZE:
            raise ValueError(f"Pattern exceeds maximum size ({cls.MAX_PATTERN_SIZE} bytes)")
        
        if len(pattern.strip()) == 0:
            raise ValueError("Pattern cannot be empty")
        
        # Security validation - block dangerous content
        # Only block actual execution patterns, not detection patterns
        cls._validate_pattern_security(pattern)
        
        # YAML parsing validation
        try:
            pattern_data = yaml.safe_load(pattern)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML syntax: {str(e)}")
        
        # Structure validation
        if not isinstance(pattern_data, dict):
            raise ValueError("Pattern must be a valid YAML dictionary")
        
        # Enhanced Semgrep rule validation
        if 'rules' in pattern_data:
            # Full rule format validation
            cls._validate_full_semgrep_rules(pattern_data)
        else:
            # Single pattern format validation
            cls._validate_semgrep_pattern_structure(pattern_data)
        
        return pattern_data
    
    @classmethod
    def _validate_pattern_security(cls, pattern: str):
        """
        Enhanced security validation that understands the context
        Only blocks actual dangerous execution, not legitimate detection patterns
        """
        pattern_lower = pattern.lower()
        
        # Check for actual dangerous YAML constructs
        for dangerous in cls.DANGEROUS_PATTERNS:
            if dangerous in pattern_lower:
                # Additional context checks to avoid false positives
                if dangerous == '!!python' and 'pattern:' in pattern_lower:
                    # This is likely a Semgrep pattern detecting Python issues, not executing
                    continue
                elif dangerous in ['eval(', 'exec(', '__import__('] and ('pattern:' in pattern_lower or 'message:' in pattern_lower):
                    # This is likely a detection rule for these functions, not execution
                    continue
                else:
                    raise ValueError(f"Pattern contains potentially dangerous content: {dangerous}")
        
        # Check for YAML injection attempts
        if '!!python/object/apply:' in pattern_lower:
            raise ValueError("YAML object instantiation not allowed")
        
        # Check for template injection patterns
        template_injection_patterns = ['{{', '${', '<%', '#set(']
        for injection_pattern in template_injection_patterns:
            if injection_pattern in pattern_lower and 'pattern:' not in pattern_lower:
                # Only block if it's not within a legitimate pattern definition
                raise ValueError("Template injection patterns not allowed outside of detection rules")

    @classmethod
    def _validate_full_semgrep_rules(cls, data: Dict[str, Any]):
        """Validate complete Semgrep rule file format"""
        rules = data.get('rules', [])
        if not isinstance(rules, list):
            raise ValueError("'rules' must be an array")
        
        if len(rules) == 0:
            raise ValueError("'rules' array cannot be empty")
        
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"Rule {i} must be an object")
            
            # Check required fields
            required_fields = ['id', 'message']
            for field in required_fields:
                if field not in rule:
                    raise ValueError(f"Rule {i} missing required field '{field}'")
                if not isinstance(rule[field], str) or not rule[field].strip():
                    raise ValueError(f"Rule {i} field '{field}' must be a non-empty string")
            
            # Validate ID format
            rule_id = rule['id'].strip()
            if not re.match(r'^[a-zA-Z0-9._-]+$', rule_id):
                raise ValueError(f"Rule {i} has invalid ID format: {rule_id}")
            
            # Check pattern fields
            cls._validate_semgrep_pattern_structure(rule, f"Rule {i}")
            
            # Validate optional fields
            if 'severity' in rule:
                severity = rule['severity']
                if not isinstance(severity, str) or severity.upper() not in cls.ALLOWED_SEVERITIES:
                    raise ValueError(f"Rule {i} has invalid severity. Must be one of: {', '.join(cls.ALLOWED_SEVERITIES)}")
            
            if 'languages' in rule:
                languages = rule['languages']
                if not isinstance(languages, list):
                    raise ValueError(f"Rule {i} 'languages' must be an array")
                if len(languages) == 0:
                    raise ValueError(f"Rule {i} 'languages' array cannot be empty")
                for lang in languages:
                    if not isinstance(lang, str) or not lang.strip():
                        raise ValueError(f"Rule {i} has invalid language in 'languages' array")
    
    @classmethod
    def _validate_semgrep_pattern_structure(cls, rule_data: Dict[str, Any], context: str = "Pattern"):
        """Validate Semgrep pattern structure"""
        # Check for required pattern fields
        pattern_fields = {'pattern', 'patterns', 'pattern-either', 'pattern-not', 'pattern-regex'}
        has_pattern = any(field in rule_data for field in pattern_fields)
        
        if not has_pattern:
            raise ValueError(f"{context} must contain at least one pattern field: {', '.join(sorted(pattern_fields))}")
        
        # Validate each pattern field if present
        for field in pattern_fields:
            if field not in rule_data:
                continue
                
            value = rule_data[field]
            
            if field == 'patterns':
                # 'patterns' should be a list
                if not isinstance(value, list):
                    raise ValueError(f"{context} '{field}' must be an array")
                if len(value) == 0:
                    raise ValueError(f"{context} '{field}' array cannot be empty")
                # Validate each pattern in the list
                for i, pattern in enumerate(value):
                    if isinstance(pattern, dict):
                        cls._validate_semgrep_pattern_structure(pattern, f"{context} patterns[{i}]")
                    elif not isinstance(pattern, str) or not pattern.strip():
                        raise ValueError(f"{context} patterns[{i}] must be a non-empty string or object")
            
            elif field == 'pattern-either':
                # 'pattern-either' should be a list
                if not isinstance(value, list):
                    raise ValueError(f"{context} '{field}' must be an array")
                if len(value) == 0:
                    raise ValueError(f"{context} '{field}' array cannot be empty")
                # Each item should be a pattern object
                for i, pattern in enumerate(value):
                    if isinstance(pattern, dict):
                        cls._validate_semgrep_pattern_structure(pattern, f"{context} pattern-either[{i}]")
                    elif not isinstance(pattern, str) or not pattern.strip():
                        raise ValueError(f"{context} pattern-either[{i}] must be a non-empty string or object")

            elif field == 'pattern-not':
                # 'pattern-not' can be either a string OR a list (like pattern-either)
                if isinstance(value, list):
                    if len(value) == 0:
                        raise ValueError(f"{context} '{field}' array cannot be empty")
                    # Each item should be a pattern object
                    for i, pattern in enumerate(value):
                        if isinstance(pattern, dict):
                            cls._validate_semgrep_pattern_structure(pattern, f"{context} pattern-not[{i}]")
                        elif not isinstance(pattern, str) or not pattern.strip():
                            raise ValueError(f"{context} pattern-not[{i}] must be a non-empty string or object")
                elif isinstance(value, str):
                    if not value.strip():
                        raise ValueError(f"{context} '{field}' must be a non-empty string")
                else:
                    raise ValueError(f"{context} '{field}' must be a string or array")

            else:
                # 'pattern', 'pattern-regex' should be strings
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"{context} '{field}' must be a non-empty string")
    
    @classmethod
    def validate_complete_rule(cls, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a complete rule object before creation"""
        # Required fields
        required_fields = ['rule_name', 'tool', 'pattern', 'message', 'severity']
        for field in required_fields:
            if field not in rule_data:
                raise ValueError(f"Missing required field: {field}")
        
        validated_rule = {}
        
        # Validate each field
        validated_rule['rule_name'] = cls.sanitize_string(
            rule_data['rule_name'], cls.MAX_RULE_NAME_LENGTH, 'rule_name'
        )
        if not validated_rule['rule_name']:
            raise ValueError("Rule name cannot be empty")
        
        validated_rule['tool'] = cls.validate_tool(rule_data['tool'])
        validated_rule['pattern'] = rule_data['pattern']  # Will be validated by validate_rule_pattern
        
        validated_rule['message'] = cls.sanitize_string(
            rule_data['message'], cls.MAX_MESSAGE_LENGTH, 'message'
        )
        if not validated_rule['message']:
            raise ValueError("Rule message cannot be empty")
        
        validated_rule['severity'] = cls.validate_severity(rule_data['severity'])
        
        # Optional fields
        validated_rule['language'] = cls.validate_language(rule_data.get('language'))
        validated_rule['description'] = cls.sanitize_string(
            rule_data.get('description'), cls.MAX_DESCRIPTION_LENGTH, 'description'
        )
        validated_rule['is_public'] = bool(rule_data.get('is_public', False))
        
        # Validate pattern last (most comprehensive)
        cls.validate_rule_pattern(validated_rule['pattern'])
        
        return validated_rule
    
    @classmethod
    def sanitize_string(cls, value: Optional[str], max_length: int, field_name: str) -> Optional[str]:
        """Sanitize and validate string fields"""
        if value is None:
            return None
        
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string")
        
        # Remove dangerous characters and limit length
        sanitized = value.strip()[:max_length]
        
        # Basic XSS protection
        dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\r\n']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized if sanitized else None
    
    @classmethod
    def validate_severity(cls, severity: str) -> str:
        """Validate severity level"""
        if not isinstance(severity, str):
            raise ValueError("Severity must be a string")
        
        severity_upper = severity.upper().strip()
        if severity_upper not in cls.ALLOWED_SEVERITIES:
            return 'WARNING'  # Default to WARNING for invalid severities
        
        return severity_upper
    
    @classmethod
    def validate_language(cls, language: Optional[str]) -> Optional[str]:
        """Validate programming language"""
        if language is None:
            return None
        
        if not isinstance(language, str):
            raise ValueError("Language must be a string")
        
        language_clean = language.lower().strip()
        if language_clean not in cls.ALLOWED_LANGUAGES:
            return 'generic'  # Default to generic for unknown languages
        
        return language_clean

class RuleCreationRequest(BaseModel):
    """Validated request model for rule creation"""
    
    rule_name: str
    tool: str
    language: Optional[str] = None
    pattern: str
    description: Optional[str] = None
    severity: str = 'WARNING'
    is_public: bool = False
    
    @validator('rule_name')
    def validate_rule_name(cls, v):
        return SecurityValidator.sanitize_string(
            v, SecurityValidator.MAX_RULE_NAME_LENGTH, "rule_name"
        )
    
    @validator('tool')
    def validate_tool(cls, v):
        return SecurityValidator.validate_tool(v)
    
    @validator('language')
    def validate_language(cls, v):
        return SecurityValidator.validate_language(v)
    
    @validator('pattern')
    def validate_pattern(cls, v):
        # This will raise ValueError if invalid
        SecurityValidator.validate_rule_pattern(v)
        return v
    
    @validator('description')
    def validate_description(cls, v):
        return SecurityValidator.sanitize_string(
            v, SecurityValidator.MAX_DESCRIPTION_LENGTH, "description"
        )
    
    @validator('severity')
    def validate_severity(cls, v):
        return SecurityValidator.validate_severity(v)

# Export the validator for use in other modules
__all__ = ['SecurityValidator', 'RuleCreationRequest']