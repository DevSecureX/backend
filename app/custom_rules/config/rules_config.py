"""
Configuration for enhanced security rules
Maps niches to their rule files and provides metadata
"""

from typing import Dict, List, Any

class RulesConfig:
    """Central configuration for all security rules"""
    
    # Tool capabilities for custom rules
    TOOL_CUSTOM_RULE_SUPPORT = {
        'semgrep': {
            'supports_custom': True,
            'rule_format': 'yaml',
            'pattern_types': ['pattern', 'patterns', 'pattern-either', 'pattern-not', 'pattern-inside'],
            'languages': ['python', 'javascript', 'typescript', 'java', 'go', 'php', 'ruby', 'c', 'cpp', 'csharp', 'rust', 'scala', 'kotlin'],
            'severity_levels': ['ERROR', 'WARNING', 'INFO'],
            'max_pattern_length': 10000,
            'validation_required': True,
            'sandbox_supported': True
        },
        'bandit': {
            'supports_custom': True,
            'rule_format': 'python_plugin',
            'pattern_types': ['ast_pattern', 'function_call', 'import_check'],
            'languages': ['python'],
            'severity_levels': ['HIGH', 'MEDIUM', 'LOW'],
            'max_pattern_length': 5000,
            'validation_required': True,
            'sandbox_supported': True
        },
        'eslint-security': {
            'supports_custom': True,
            'rule_format': 'javascript_plugin',
            'pattern_types': ['ast_pattern', 'selector', 'fix'],
            'languages': ['javascript', 'typescript'],
            'severity_levels': ['error', 'warn', 'off'],
            'max_pattern_length': 8000,
            'validation_required': True,
            'sandbox_supported': True
        },
        'gosec': {
            'supports_custom': True,
            'rule_format': 'go_plugin',
            'pattern_types': ['ast_pattern', 'call_check', 'import_check'],
            'languages': ['go'],
            'severity_levels': ['HIGH', 'MEDIUM', 'LOW'],
            'max_pattern_length': 6000,
            'validation_required': True,
            'sandbox_supported': False
        },
        'checkov': {
            'supports_custom': True,
            'rule_format': 'python_check',
            'pattern_types': ['resource_check', 'attribute_check', 'connection_check'],
            'languages': ['terraform', 'cloudformation', 'kubernetes', 'dockerfile', 'arm'],
            'severity_levels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
            'max_pattern_length': 7000,
            'validation_required': True,
            'sandbox_supported': False
        },
        'trivy': {
            'supports_custom': False,
            'rule_format': 'rego',
            'pattern_types': ['policy'],
            'languages': ['rego'],
            'severity_levels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'],
            'max_pattern_length': 5000,
            'validation_required': True,
            'sandbox_supported': False,
            'note': 'Custom policies via OPA Rego - advanced users only'
        },
        'cppcheck': {
            'supports_custom': True,
            'rule_format': 'xml_rule',
            'pattern_types': ['token_pattern', 'function_check'],
            'languages': ['c', 'cpp'],
            'severity_levels': ['error', 'warning', 'style', 'performance', 'portability'],
            'max_pattern_length': 4000,
            'validation_required': True,
            'sandbox_supported': False
        },
        'psalm': {
            'supports_custom': True,
            'rule_format': 'php_plugin',
            'pattern_types': ['ast_pattern', 'method_check', 'property_check'],
            'languages': ['php'],
            'severity_levels': ['error', 'info'],
            'max_pattern_length': 6000,
            'validation_required': True,
            'sandbox_supported': False
        },
        # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
        # 'roslynator': {
        #     'supports_custom': True,
        #     'rule_format': 'csharp_analyzer',
        #     'pattern_types': ['syntax_pattern', 'semantic_pattern'],
        #     'languages': ['csharp'],
        #     'severity_levels': ['Error', 'Warning', 'Info', 'Hidden'],
        #     'max_pattern_length': 8000,
        #     'validation_required': True,
        #     'sandbox_supported': False
        # },
        'spotbugs': {
            'supports_custom': True,
            'rule_format': 'java_plugin',
            'pattern_types': ['bytecode_pattern', 'source_pattern'],
            'languages': ['java', 'scala', 'kotlin'],
            'severity_levels': ['High', 'Medium', 'Low'],
            'max_pattern_length': 7000,
            'validation_required': True,
            'sandbox_supported': False
        },
        'brakeman': {
            'supports_custom': True,
            'rule_format': 'ruby_check',
            'pattern_types': ['call_check', 'file_check', 'render_check'],
            'languages': ['ruby'],
            'severity_levels': ['High', 'Medium', 'Weak'],
            'max_pattern_length': 5000,
            'validation_required': True,
            'sandbox_supported': False
        },
        'gitleaks': {
            'supports_custom': True,
            'rule_format': 'yaml',
            'pattern_types': ['regex', 'entropy', 'keyword'],
            'languages': ['any'],
            'severity_levels': ['critical', 'high', 'medium', 'low'],
            'max_pattern_length': 3000,
            'validation_required': True,
            'sandbox_supported': True,
            'note': 'Secret detection rules with regex patterns'
        },
        'safety': {
            'supports_custom': True,
            'rule_format': 'json',
            'pattern_types': ['vulnerability_database', 'package_check'],
            'languages': ['python'],
            'severity_levels': ['critical', 'high', 'medium', 'low'],
            'max_pattern_length': 2000,
            'validation_required': True,
            'sandbox_supported': True,
            'note': 'Python package vulnerability definitions'
        },
    }
    
    # Rule file mappings by niche
    NICHE_RULES_MAP = {
        'ai': {
            'rule_files': ['ai.yaml', 'ai_enhanced.yaml'],
            'total_rules': 25,
            'description': 'AI/ML security including model poisoning, privacy attacks, and LLM security',
            'tools': ['semgrep', 'bandit', 'safety'],
            'languages': ['python', 'javascript', 'typescript']
        },
        'blockchain': {
            'rule_files': ['blockchain.yaml', 'blockchain_enhanced.yaml'],
            'total_rules': 25,
            'description': 'Smart contract security, DeFi vulnerabilities, and blockchain-specific patterns',
            'tools': ['semgrep', 'checkov'],
            'languages': ['solidity', 'javascript', 'typescript', 'rust']
        },
        'iot': {
            'rule_files': ['iot.yaml', 'iot_enhanced.yaml'],
            'total_rules': 27,
            'description': 'Embedded systems, firmware security, and hardware attack vectors',
            'tools': ['semgrep', 'cppcheck', 'checkov'],
            'languages': ['c', 'cpp', 'rust', 'python']
        },
        'web3': {
            'rule_files': ['web3.yaml'],
            'total_rules': 15,
            'description': 'Web3 frontend security, wallet integration, and dApp vulnerabilities',
            'tools': ['semgrep', 'eslint-security'],
            'languages': ['javascript', 'typescript']
        },
        'cloud': {
            'rule_files': ['cloud_native.yaml'],
            'total_rules': 20,
            'description': 'Kubernetes, Docker, Terraform, and cloud infrastructure security',
            'tools': ['semgrep', 'checkov', 'trivy'],
            'languages': ['yaml', 'hcl', 'dockerfile', 'json']
        },
        'api': {
            'rule_files': ['api_security.yaml'],
            'total_rules': 16,
            'description': 'REST, GraphQL, gRPC API security patterns',
            'tools': ['semgrep', 'bandit'],
            'languages': ['javascript', 'typescript', 'python', 'java', 'go']
        }
    }
    
    # Rule categories for better organization
    RULE_CATEGORIES = {
        'security': {
            'name': 'Security Vulnerabilities',
            'description': 'Rules detecting security vulnerabilities and weaknesses',
            'icon': 'shield',
            'color': 'red'
        },
        'performance': {
            'name': 'Performance Issues',
            'description': 'Rules identifying performance bottlenecks and inefficiencies',
            'icon': 'clock',
            'color': 'orange'
        },
        'maintainability': {
            'name': 'Code Maintainability',
            'description': 'Rules promoting clean, maintainable code practices',
            'icon': 'code',
            'color': 'blue'
        },
        'compliance': {
            'name': 'Compliance & Standards',
            'description': 'Rules enforcing industry standards and compliance requirements',
            'icon': 'check-circle',
            'color': 'green'
        },
        'best_practices': {
            'name': 'Best Practices',
            'description': 'Rules promoting language and framework best practices',
            'icon': 'star',
            'color': 'purple'
        },
        'custom': {
            'name': 'Custom Rules',
            'description': 'User-defined custom security and quality rules',
            'icon': 'settings',
            'color': 'gray'
        }
    }
    
    # Additional rules that can be applied across niches
    CROSS_CUTTING_RULES = {
        'supply_chain': {
            'rule_files': ['supply_chain.yaml'],
            'description': 'Dependency and supply chain security',
            'applies_to': ['ai', 'blockchain', 'web3', 'cloud', 'api'],
            'tools': ['safety', 'trivy', 'semgrep'],
            'custom_rules_supported': True
        },
        'secrets': {
            'rule_files': ['custom_secrets.yaml'],
            'description': 'Secret detection across all code',
            'tools': ['trufflehog', 'gitleaks', 'semgrep'],
            'applies_to': 'all',
            'custom_rules_supported': True
        },
        'privacy': {
            'rule_files': ['privacy.yaml'],
            'description': 'Privacy compliance and data protection rules',
            'tools': ['semgrep', 'bandit'],
            'applies_to': ['ai', 'web3', 'api'],
            'custom_rules_supported': True
        },
        'licensing': {
            'rule_files': ['licensing.yaml'],
            'description': 'Open source license compliance checks',
            'tools': ['semgrep'],
            'applies_to': 'all',
            'custom_rules_supported': True
        }
    }
    
    # Severity weight adjustments by niche
    NICHE_SEVERITY_WEIGHTS = {
        'ai': {
            'model_poisoning': 2.0,      # Double weight for AI model attacks
            'privacy_violation': 1.8,    # Privacy is critical in AI
            'supply_chain': 1.5         # ML libraries often vulnerable
        },
        'blockchain': {
            'reentrancy': 2.5,          # Can drain entire contracts
            'access_control': 2.0,      # Critical for funds
            'integer_overflow': 1.8     # Can corrupt state
        },
        'iot': {
            'buffer_overflow': 2.0,     # Can compromise device
            'firmware': 1.8,            # Hard to patch
            'physical_access': 1.5      # IoT devices often exposed
        },
        'web3': {
            'private_key': 3.0,         # Catastrophic if exposed
            'transaction': 2.0,         # Financial impact
            'frontend': 1.5             # User-facing risks
        },
        'cloud': {
            'public_exposure': 2.5,     # Data breaches
            'privilege_escalation': 2.0, # Container escape
            'secrets': 2.0              # Credential exposure
        },
        'api': {
            'injection': 2.0,           # Can compromise backend
            'authentication': 1.8,      # Access control
            'rate_limiting': 1.5        # DoS potential
        }
    }
    
    @classmethod
    def get_rules_for_niche(cls, niche: str) -> Dict[str, Any]:
        """Get rule configuration for a specific niche"""
        if niche == 'all':
            # Return aggregated configuration for all niches
            all_rule_files = []
            total_rules = 0
            all_tools = set()
            all_languages = set()
            
            for config in cls.NICHE_RULES_MAP.values():
                all_rule_files.extend(config.get('rule_files', []))
                total_rules += config.get('total_rules', 0)
                all_tools.update(config.get('tools', []))
                all_languages.update(config.get('languages', []))
            
            return {
                'rule_files': list(set(all_rule_files)),  # Remove duplicates
                'total_rules': total_rules,
                'description': 'Comprehensive security scanning across ALL domains - AI/ML, blockchain, IoT, Web3, cloud-native, and API security',
                'tools': list(all_tools),
                'languages': list(all_languages)
            }
        
        return cls.NICHE_RULES_MAP.get(niche, {})
    
    @classmethod
    def get_all_rule_files(cls, niche: str, include_cross_cutting: bool = False) -> List[str]:
        """Get all rule files for a niche"""
        rule_files = []
        
        if niche == 'all':
            # For 'all' niche, get rule files from ALL niches
            for niche_name in cls.NICHE_RULES_MAP.keys():
                niche_config = cls.NICHE_RULES_MAP[niche_name]
                rule_files.extend(niche_config.get('rule_files', []))
        else:
            # Add niche-specific rules
            niche_config = cls.get_rules_for_niche(niche)
            if niche_config:
                rule_files.extend(niche_config.get('rule_files', []))
        
        # Add cross-cutting rules if requested
        if include_cross_cutting:
            for cross_rule, config in cls.CROSS_CUTTING_RULES.items():
                applies_to = config.get('applies_to', [])
                if applies_to == 'all' or niche in applies_to or niche == 'all':
                    rule_files.extend(config.get('rule_files', []))
        
        return list(set(rule_files))  # Remove duplicates
    
    @classmethod
    def get_severity_weight(cls, niche: str, issue_type: str) -> float:
        """Get severity weight for a specific issue type in a niche"""
        if niche == 'all':
            # For 'all' niche, check all severity weights and return the highest match
            max_weight = 1.0
            for niche_name, niche_weights in cls.NICHE_SEVERITY_WEIGHTS.items():
                for category, weight in niche_weights.items():
                    if category.lower() in issue_type.lower():
                        max_weight = max(max_weight, weight)
            return max_weight
        
        niche_weights = cls.NICHE_SEVERITY_WEIGHTS.get(niche, {})
        
        # Check if issue type matches any weighted categories
        for category, weight in niche_weights.items():
            if category.lower() in issue_type.lower():
                return weight
        
        return 1.0  # Default weight
    
    @classmethod
    def get_recommended_tools(cls, niche: str) -> List[str]:
        """Get recommended tools for a niche"""
        niche_config = cls.get_rules_for_niche(niche)
        return niche_config.get('tools', ['semgrep'])
    
    @classmethod
    def get_supported_languages(cls, niche: str) -> List[str]:
        """Get supported languages for a niche"""
        niche_config = cls.get_rules_for_niche(niche)
        return niche_config.get('languages', [])
    
    @classmethod
    def get_tools_supporting_custom_rules(cls) -> Dict[str, Dict[str, Any]]:
        """Get all tools that support custom rules"""
        return {tool: config for tool, config in cls.TOOL_CUSTOM_RULE_SUPPORT.items() if config['supports_custom']}
    
    @classmethod
    def get_tool_custom_rule_config(cls, tool: str) -> Dict[str, Any]:
        """Get custom rule configuration for a specific tool"""
        return cls.TOOL_CUSTOM_RULE_SUPPORT.get(tool, {})
    
    @classmethod
    def validate_tool_supports_custom_rules(cls, tool: str) -> bool:
        """Check if a tool supports custom rules"""
        config = cls.TOOL_CUSTOM_RULE_SUPPORT.get(tool, {})
        return config.get('supports_custom', False)
    
    @classmethod
    def get_supported_languages_for_tool(cls, tool: str) -> List[str]:
        """Get supported languages for a specific tool"""
        config = cls.TOOL_CUSTOM_RULE_SUPPORT.get(tool, {})
        return config.get('languages', [])
    
    @classmethod
    def get_pattern_types_for_tool(cls, tool: str) -> List[str]:
        """Get supported pattern types for a specific tool"""
        config = cls.TOOL_CUSTOM_RULE_SUPPORT.get(tool, {})
        return config.get('pattern_types', [])
    
    @classmethod
    def get_severity_levels_for_tool(cls, tool: str) -> List[str]:
        """Get valid severity levels for a specific tool"""
        config = cls.TOOL_CUSTOM_RULE_SUPPORT.get(tool, {})
        return config.get('severity_levels', ['HIGH', 'MEDIUM', 'LOW'])
    
    @classmethod
    def estimate_scan_time(cls, niche: str, file_count: int) -> Dict[str, int]:
        """Estimate scan time based on niche and file count"""
        # Base estimates in seconds per file
        time_per_file = {
            'ai': 0.5,         # Python files scan quickly
            'blockchain': 0.7,  # Solidity analysis takes time
            'iot': 0.8,        # C/C++ analysis is slower
            'web3': 0.4,       # JS/TS files scan fast
            'cloud': 0.3,      # YAML/JSON files are quick
            'api': 0.5,        # Mixed languages
            'all': 1.2         # Comprehensive scanning takes longer
        }
        
        base_time = time_per_file.get(niche, 0.5) * file_count
        
        return {
            'estimated_seconds': int(base_time),
            'estimated_minutes': round(base_time / 60, 1),
            'confidence': 'high' if file_count < 1000 else 'medium'
        }
    
    @classmethod
    def get_rule_complexity_score(cls, pattern: str, tool: str) -> Dict[str, Any]:
        """Calculate complexity score for a rule pattern"""
        complexity_factors = {
            'length': len(pattern),
            'nesting_depth': pattern.count('{') + pattern.count('['),
            'regex_patterns': len(__import__('re').findall(r'\$\{[^}]+\}|\*|\+|\?', pattern)),
            'logical_operators': pattern.count('and') + pattern.count('or') + pattern.count('not'),
            'wildcards': pattern.count('*') + pattern.count('?')
        }
        
        # Calculate base score
        base_score = min(100, (
            complexity_factors['length'] / 100 +
            complexity_factors['nesting_depth'] * 5 +
            complexity_factors['regex_patterns'] * 3 +
            complexity_factors['logical_operators'] * 2 +
            complexity_factors['wildcards'] * 1
        ))
        
        # Adjust for tool-specific factors
        tool_config = cls.get_tool_custom_rule_config(tool)
        max_length = tool_config.get('max_pattern_length', 5000)
        
        if complexity_factors['length'] > max_length * 0.8:
            base_score += 20
        
        complexity_level = 'low'
        if base_score > 70:
            complexity_level = 'high'
        elif base_score > 40:
            complexity_level = 'medium'
        
        return {
            'score': min(100, int(base_score)),
            'level': complexity_level,
            'factors': complexity_factors,
            'performance_impact': 'high' if base_score > 80 else 'medium' if base_score > 50 else 'low',
            'recommendations': cls._get_complexity_recommendations(base_score, complexity_factors)
        }
    
    @classmethod
    def _get_complexity_recommendations(cls, score: float, factors: Dict[str, int]) -> List[str]:
        """Get recommendations to reduce rule complexity"""
        recommendations = []
        
        if factors['length'] > 2000:
            recommendations.append('Consider breaking down the pattern into smaller, more focused rules')
        
        if factors['nesting_depth'] > 5:
            recommendations.append('Reduce nesting depth to improve pattern matching performance')
        
        if factors['regex_patterns'] > 10:
            recommendations.append('Minimize regex patterns to avoid ReDoS vulnerabilities')
        
        if factors['logical_operators'] > 8:
            recommendations.append('Simplify logical conditions or split into multiple rules')
        
        if score > 80:
            recommendations.append('This rule has high complexity and may impact scan performance')
        
        return recommendations