import json
import os
import logging
import yaml
import asyncio
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
from ..utils.code_context_extractor import CodeContextExtractor

logger = logging.getLogger(__name__)

class SemgrepRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("semgrep")
        self.timeout = 900  # 15 minutes for Semgrep - increased for comprehensive analysis
        self.context_extractor = CodeContextExtractor(context_lines=3)
        
    def _validate_rule_file(self, rule_file_path: str) -> bool:
        """Validate a custom rule file to prevent Semgrep crashes"""
        try:
            # Check if file exists and is readable
            if not os.path.exists(rule_file_path):
                logger.warning(f"Rule file does not exist: {rule_file_path}")
                return False
                
            # Check file size (max 10MB)
            file_size = os.path.getsize(rule_file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB
                logger.warning(f"Rule file too large ({file_size} bytes): {rule_file_path}")
                return False
                
            # Read and validate YAML syntax
            with open(rule_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                if not content.strip():
                    logger.warning(f"Rule file is empty: {rule_file_path}")
                    return False
                    
                # Parse YAML to check syntax
                try:
                    yaml_data = yaml.safe_load(content)
                except yaml.YAMLError as e:
                    logger.warning(f"Invalid YAML syntax in rule file {rule_file_path}: {e}")
                    return False
                    
                # Basic structure validation
                if not isinstance(yaml_data, dict):
                    logger.warning(f"Rule file must contain a YAML dictionary: {rule_file_path}")
                    return False
                    
                # Check for rules array
                rules = yaml_data.get('rules', [])
                if not isinstance(rules, list):
                    logger.warning(f"Rule file must contain a 'rules' array: {rule_file_path}")
                    return False
                    
                if len(rules) == 0:
                    logger.warning(f"Rule file contains no rules: {rule_file_path}")
                    return False
                    
                # Validate each rule has required fields
                for i, rule in enumerate(rules):
                    if not isinstance(rule, dict):
                        logger.warning(f"Rule {i} is not a dictionary in {rule_file_path}")
                        return False
                        
                    # Check required fields
                    required_fields = ['id', 'message']
                    for field in required_fields:
                        if field not in rule:
                            logger.warning(f"Rule {i} missing required field '{field}' in {rule_file_path}")
                            return False
                            
                    # Check for pattern or patterns field
                    if 'pattern' not in rule and 'patterns' not in rule and 'pattern-either' not in rule:
                        logger.warning(f"Rule {i} missing pattern field in {rule_file_path}")
                        return False
                        
                    # Validate severity if present
                    if 'severity' in rule:
                        valid_severities = ['ERROR', 'WARNING', 'INFO']
                        if rule['severity'] not in valid_severities:
                            logger.warning(f"Rule {i} has invalid severity '{rule['severity']}' in {rule_file_path}")
                            return False
                            
                    # Validate languages if present
                    if 'languages' in rule:
                        if not isinstance(rule['languages'], list):
                            logger.warning(f"Rule {i} 'languages' must be a list in {rule_file_path}")
                            return False
                            
                logger.info(f"Successfully validated rule file with {len(rules)} rules: {rule_file_path}")
                return True
                
        except Exception as e:
            logger.warning(f"Error validating rule file {rule_file_path}: {e}")
            return False
        
    async def run(self, temp_dir: str, niche: str = None, **kwargs) -> Dict[str, Any]:
        """Semgrep SAST analysis with world-class vulnerability detection accuracy"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        logger.info(f"Running Semgrep with timeout of {self.timeout}s")
        
        # Check if we should scan specific files (for PR scans)
        target_files = kwargs.get('target_files', [])
        
        # Command configuration for security scanning
        cmd = [
            'semgrep',
            '--json',
            '--no-git-ignore',
            '--max-target-bytes', '50000000',  # Increased to 50MB for large files
            '--timeout', '600',  # 10 minutes per file
            '--severity=ERROR',
            '--severity=WARNING', 
            '--severity=INFO',
            '--verbose'  # Enhanced logging for better debugging
        ]
        
        # Collect all config sources for comprehensive vulnerability detection
        config_sources = []
        
        # Always include auto config for default rules FIRST
        config_sources.append('auto')
        
        # If target_files is provided, scan only those files. Otherwise scan entire directory
        if target_files:
            logger.info(f"Semgrep scanning {len(target_files)} target files for PR")
            # Convert relative file paths to absolute paths in temp_dir
            absolute_files = []
            for file_path in target_files:
                abs_path = os.path.join(temp_dir, file_path)
                if os.path.exists(abs_path):
                    absolute_files.append(abs_path)
                else:
                    logger.warning(f"Target file not found: {abs_path}")
            
            if absolute_files:
                cmd.extend(absolute_files)
            else:
                logger.warning("No valid target files found, scanning entire directory")
                cmd.append(temp_dir)
        else:
            cmd.append(temp_dir)
        
        # Add niche-specific rules if available
        if niche:
            # Map niches to their rule files
            niche_rules_map = {
                'ai': ['ai.yaml', 'ai_enhanced.yaml'],
                'blockchain': ['blockchain.yaml', 'blockchain_enhanced.yaml'],
                'iot': ['iot.yaml', 'iot_enhanced.yaml'],
                'web3': ['web3.yaml'],
                'cloud': ['cloud_native.yaml'],
                'api': ['api_security.yaml']
            }
            
            # Handle 'all' niche - load ALL rule files
            if niche == 'all':
                # Get all rule files from all niches
                all_rule_files = []
                for niche_rules in niche_rules_map.values():
                    all_rule_files.extend(niche_rules)
                rule_files = list(set(all_rule_files))  # Remove duplicates
                logger.info(f"Loading ALL security rules for comprehensive scanning: {rule_files}")
            else:
                # Get rule files for specific niche
                rule_files = niche_rules_map.get(niche, [])
                
                # Also check for generic enhanced rules
                if niche in ['ai', 'blockchain', 'iot']:
                    # These niches have enhanced versions
                    pass
                else:
                    # For other niches, check if there's a yaml file
                    default_rule = f"{niche}.yaml"
                    if default_rule not in rule_files:
                        rule_files.append(default_rule)
            
            # Add each rule file that exists to config sources
            rules_added = 0
            for rule_file in rule_files:
                # Use relative path from scans directory
                rule_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules', rule_file)
                if os.path.exists(rule_path):
                    config_sources.append(rule_path)
                    rules_added += 1
                    logger.info(f"Added rule file: {rule_path}")
            
            if rules_added == 0:
                logger.warning(f"No rule files found for niche: {niche}")
            else:
                logger.info(f"Total rules loaded for niche '{niche}': {rules_added} files")
        
        # Also add API security rules for web applications
        if kwargs.get('include_api_rules', False):
            api_rule_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules', 'api_security.yaml')
            if os.path.exists(api_rule_path):
                config_sources.append(api_rule_path)
                logger.info("Added API security rules")
        
        # Add custom rules integration with concurrent validation
        custom_rule_files = kwargs.get('custom_rule_files', [])
        custom_rules_added = 0
        if custom_rule_files:
            # Validate rule files concurrently for better performance
            validated_custom_files = await self._validate_rule_files_concurrent(custom_rule_files)
            custom_rules_added = len(validated_custom_files)
            
            # Only add validated rule files
            config_sources.extend(validated_custom_files)
            
            if custom_rules_added > 0:
                logger.info(f"Enhanced scanning: Default rules (--config auto) + {custom_rules_added} custom rule files (validated concurrently)")
            else:
                logger.warning("No valid custom rule files found, using default rules only")
        
        if not custom_rule_files:
            logger.info("Using default rules only (--config auto)")
        
        # Now add all config sources to the command in the correct order
        for config_source in config_sources:
            cmd.extend(['--config', config_source])
        
        # Log the final configuration for debugging
        total_configs = len(config_sources)
        logger.info(f"Semgrep command configured with {total_configs} config sources: {config_sources}")
        
        if not custom_rule_files:
            logger.info("Using default rules only (--config auto)")
        
        result = await self.execute_command(cmd)
        
        if "error" in result:
            # Check if this was due to custom rules causing exit code 7
            if custom_rule_files and len(config_sources) > 1:  # Has both auto + custom
                logger.warning(f"Semgrep failed with custom rules, attempting fallback to default rules only")
                
                # Retry with default rules only (fallback)
                fallback_cmd = [
                    'semgrep',
                    '--json',
                    '--no-git-ignore',
                    '--max-target-bytes', '1000000',
                    '--config', 'auto'  # Only default rules
                ]
                
                # Add target files/directory
                if target_files:
                    if absolute_files:
                        fallback_cmd.extend(absolute_files)
                    else:
                        fallback_cmd.append(temp_dir)
                else:
                    fallback_cmd.append(temp_dir)
                
                logger.info("Retrying Semgrep with default rules only after custom rules failure")
                fallback_result = await self.execute_command(fallback_cmd)
                
                if "error" not in fallback_result:
                    logger.info("Semgrep fallback to default rules successful")
                    result = fallback_result
                else:
                    logger.error("Semgrep failed even with default rules fallback")
                    return {"issues": [], "error": result["error"], "tool": "semgrep"}
            else:
                return {"issues": [], "error": result["error"], "tool": "semgrep"}
        
        try:
            output = json.loads(result["stdout"])
            issues = []
            
            for finding in output.get("results", []):
                # Extract line information properly
                start_info = finding.get("start", {})
                end_info = finding.get("end", {})
                
                line_start = start_info.get("line")
                line_end = end_info.get("line")
                
                # If line_end is the same as line_start, set it to None for single-line issues
                if line_end == line_start:
                    line_end = None
                    
                file_path = self.clean_file_path(finding.get("path"), temp_dir)
                
                # Extract code context
                code_context = None
                if line_start and file_path:
                    code_context = self.context_extractor.extract_context(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        temp_dir=temp_dir
                    )
                
                # Check if this is from a custom rule
                custom_rule_metadata = {}
                rule_id = finding.get("check_id", "")
                if rule_id.startswith("custom-"):
                    # Extract custom rule metadata from finding
                    extra_metadata = finding.get("extra", {}).get("metadata", {})
                    custom_rule_metadata = {
                        "is_custom_rule": True,
                        "custom_rule_id": extra_metadata.get("rule_id"),
                        "custom_rule_name": extra_metadata.get("rule_name"),
                        "custom_rule_author": extra_metadata.get("author_id"),
                        "custom_rule_source": extra_metadata.get("rule_source", "user_custom"),
                        "custom_rule_votes": extra_metadata.get("net_votes", 0),
                        "custom_rule_verified": extra_metadata.get("is_verified", False)
                    }

                # Get original severity from Semgrep for debugging
                original_severity = finding.get("extra", {}).get("severity", "medium")
                normalized_severity = self.normalize_severity(original_severity)
                
                # Debug logging for severity mapping verification
                if original_severity.lower() in ['error', 'warning']:
                    logger.info(f"Semgrep severity mapping: '{original_severity}' -> '{normalized_severity}' for rule {rule_id}")

                issue = {
                    "tool": "semgrep",
                    "category": "code",
                    "rule_id": rule_id,
                    "message": finding.get("extra", {}).get("message", "Security issue found"),
                    "severity": normalized_severity,
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "confidence": "high",  # Semgrep has high confidence
                    "owasp_category": self._map_to_owasp(rule_id),
                    "cwe_id": self._extract_cwe(finding.get("extra", {})),
                    "code_context": code_context,
                    "custom_rule_metadata": custom_rule_metadata if custom_rule_metadata else None
                }
                issues.append(issue)
            
            # Count custom rule findings
            custom_rule_findings = sum(1 for issue in issues if issue.get("custom_rule_metadata"))
            
            return {
                "issues": issues,
                "tool": "semgrep",
                "duration": result["duration"],
                "rules_run": len(output.get("results", [])),
                "metadata": {
                    "version": output.get("version"),
                    "scan_stats": output.get("paths", {}),
                    "custom_rules_used": len(custom_rule_files) if custom_rule_files else 0,
                    "custom_rule_findings": custom_rule_findings,
                    "builtin_rule_findings": len(issues) - custom_rule_findings,
                    "cli_mode": is_cli_scan,
                    "timeout_used": self.timeout
                }
            }
            
        except json.JSONDecodeError as e:
            return {"issues": [], "error": f"Invalid JSON output: {str(e)}", "tool": "semgrep"}
    
    def _map_to_owasp(self, rule_id: str) -> str:
        """Map Semgrep rule to OWASP Top 10 category"""
        owasp_mappings = {
            "sql": "A03:2021 – Injection",
            "injection": "A03:2021 – Injection", 
            "xss": "A03:2021 – Injection",
            "auth": "A07:2021 – Identification and Authentication Failures",
            "crypto": "A02:2021 – Cryptographic Failures",
            "deserialization": "A08:2021 – Software and Data Integrity Failures",
            "path-traversal": "A01:2021 – Broken Access Control",
            "ssrf": "A10:2021 – Server-Side Request Forgery",
            "xxe": "A05:2021 – Security Misconfiguration",
            "hardcoded": "A07:2021 – Identification and Authentication Failures",
            "insecure": "A04:2021 – Insecure Design"
        }
        
        rule_lower = rule_id.lower()
        for key, category in owasp_mappings.items():
            if key in rule_lower:
                return category
        
        return "A06:2021 – Vulnerable and Outdated Components"
    
    async def _validate_rule_files_concurrent(self, rule_files: List[str]) -> List[str]:
        """Validate multiple rule files concurrently for better performance"""
        
        async def validate_single_file(rule_file: str) -> tuple[str, bool]:
            """Validate a single rule file asynchronously"""
            try:
                # Run validation in thread pool to avoid blocking
                loop = asyncio.get_event_loop()
                is_valid = await loop.run_in_executor(None, self._validate_rule_file_sync, rule_file)
                return rule_file, is_valid
            except Exception as e:
                logger.warning(f"Error validating rule file {rule_file}: {e}")
                return rule_file, False
        
        # Validate all files concurrently
        validation_tasks = [validate_single_file(rule_file) for rule_file in rule_files]
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        # Process results
        validated_files = []
        for result in validation_results:
            if isinstance(result, Exception):
                logger.warning(f"Validation task failed with exception: {result}")
                continue
                
            rule_file, is_valid = result
            if is_valid:
                validated_files.append(rule_file)
                logger.info(f"Added custom rule file: {rule_file}")
            else:
                logger.warning(f"Invalid custom rule file skipped: {rule_file}")
        
        return validated_files
    
    def _validate_rule_file_sync(self, rule_file: str) -> bool:
        """Synchronous rule file validation for use in thread pool"""
        try:
            # Check if file exists and is readable
            if not os.path.exists(rule_file) or not os.access(rule_file, os.R_OK):
                return False
            
            # Check file size (prevent extremely large files)
            if os.path.getsize(rule_file) > 10 * 1024 * 1024:  # 10MB limit
                logger.warning(f"Rule file too large: {rule_file}")
                return False
            
            # Basic YAML validation
            with open(rule_file, 'r') as f:
                try:
                    yaml_content = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    logger.warning(f"Invalid YAML in rule file {rule_file}: {e}")
                    return False
            
            # Check for basic rule structure
            if not isinstance(yaml_content, dict):
                return False
            
            if 'rules' not in yaml_content:
                return False
            
            if not isinstance(yaml_content['rules'], list) or not yaml_content['rules']:
                return False
            
            # Validate each rule has required fields
            for rule in yaml_content['rules']:
                if not isinstance(rule, dict):
                    return False
                if 'id' not in rule or 'message' not in rule:
                    return False
                # Must have at least one pattern
                pattern_keys = ['pattern', 'patterns', 'pattern-either', 'pattern-regex']
                if not any(key in rule for key in pattern_keys):
                    return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Error validating rule file {rule_file}: {e}")
            return False
    
    def _validate_rule_file(self, rule_file: str) -> bool:
        """Legacy synchronous validation method for backward compatibility"""
        return self._validate_rule_file_sync(rule_file)
    
    def _extract_cwe(self, extra: dict) -> str:
        """Extract CWE ID from Semgrep metadata"""
        metadata = extra.get("metadata", {})
        cwe = metadata.get("cwe", [])
        
        if isinstance(cwe, list) and cwe:
            # Handle different CWE formats
            first_cwe = cwe[0]
            if isinstance(first_cwe, str):
                if first_cwe.startswith("CWE-"):
                    return first_cwe
                else:
                    return f"CWE-{first_cwe}"
            elif isinstance(first_cwe, (int, float)):
                return f"CWE-{int(first_cwe)}"
        elif isinstance(cwe, str):
            return cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
        elif isinstance(cwe, (int, float)):
            return f"CWE-{int(cwe)}"
        
        return None