"""
Rule Testing Service
Real rule testing using the existing scanner infrastructure
"""

import os
import yaml
import tempfile
import shutil
import logging
import asyncio
import contextlib
import threading
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from scans.tools.semgrep_runner import SemgrepRunner
from scans.tools.bandit_runner import BanditRunner
from scans.base_runner import BaseToolRunner

logger = logging.getLogger(__name__)

class RuleTestingService:
    """Service for testing custom rules against provided code with atomic operations"""
    
    def __init__(self, db: Optional[AsyncSession] = None):
        self.db = db
        self.tool_runners = {
            'semgrep': SemgrepRunner(),
            'bandit': BanditRunner(),
            # Add more tools as needed
        }
        # Thread lock for ensuring atomic temp directory operations
        self._temp_dir_lock = threading.Lock()
        
    async def test_rule_against_code(
        self,
        rule_pattern: str,
        test_code: str,
        tool: str = 'semgrep',
        language: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Test a custom rule against provided code using real security scanners
        
        Args:
            rule_pattern: The rule pattern in YAML format
            test_code: The code to test against
            tool: Security tool to use (default: semgrep)
            language: Programming language (optional)
            user_id: User ID for context (optional)
            
        Returns:
            Dict containing test results with matches, execution time, etc.
        """
        
        # Validate inputs
        if not rule_pattern or not rule_pattern.strip():
            raise ValueError("Rule pattern is required")
        
        if not test_code or not test_code.strip():
            raise ValueError("Test code is required")
        
        # Validate tool
        if tool not in self.tool_runners:
            raise ValueError(f"Unsupported tool: {tool}. Supported tools: {list(self.tool_runners.keys())}")
        
        # Use atomic context manager for temp directory operations
        @contextlib.asynccontextmanager
        async def atomic_temp_dir():
            """Atomically create and cleanup temp directory to prevent race conditions"""
            temp_dir = None
            with self._temp_dir_lock:  # Ensure atomic creation
                try:
                    # Create temporary directory with unique naming
                    import time
                    timestamp = int(time.time() * 1000000)  # microsecond precision
                    temp_dir = tempfile.mkdtemp(
                        prefix=f'rule_test_{user_id or "anon"}_{timestamp}_'
                    )
                    logger.info(f"Created atomic temp directory: {temp_dir}")
                    yield temp_dir
                finally:
                    # Always cleanup, even on exceptions
                    if temp_dir and os.path.exists(temp_dir):
                        try:
                            shutil.rmtree(temp_dir, ignore_errors=True)
                            logger.info(f"Cleaned up temp directory: {temp_dir}")
                        except Exception as e:
                            logger.warning(f"Failed to cleanup temp directory {temp_dir}: {e}")
        
        try:
            async with atomic_temp_dir() as temp_dir:
                # 1. Create test file with provided code
                test_file_path = await self._create_test_file(test_code, temp_dir, language)
                
                # 2. Create rule file from pattern
                rule_file_path = await self._create_rule_file_from_pattern(
                    rule_pattern, temp_dir, tool, language
                )
                
                # 3. Run the security tool with the custom rule
                runner = self.tool_runners[tool]
                result = await self._run_tool_with_rule(
                    runner, temp_dir, rule_file_path, test_file_path, tool
                )
                
                # 4. Process and return results
                return await self._process_test_results(result, temp_dir, tool)
                
        except Exception as e:
            logger.error(f"Rule testing failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "matches": [],
                "execution_time_ms": 0,
                "errors": [str(e)],
                "warnings": []
            }
    
    async def test_existing_rule(
        self,
        rule_id: str,
        test_code: str,
        user_id: int,
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test an existing custom rule from the database against provided code
        
        Args:
            rule_id: ID of the existing rule to test
            test_code: The code to test against
            user_id: User ID for accessing the rule
            language: Programming language (optional)
            
        Returns:
            Dict containing test results
        """
        
        if not self.db:
            raise ValueError("Database session required for testing existing rules")
        
        # Get the rule from database
        from custom_rules.services.rules_service import CustomRulesService
        rules_service = CustomRulesService(self.db)
        
        try:
            rule = await rules_service.get_rule_by_id(rule_id, user_id)
            if not rule:
                raise ValueError(f"Rule not found or access denied: {rule_id}")
            
            # Test using the stored pattern
            return await self.test_rule_against_code(
                rule_pattern=rule.pattern,
                test_code=test_code,
                tool=rule.tool,
                language=language or rule.language,
                user_id=user_id
            )
            
        except Exception as e:
            logger.error(f"Error testing existing rule {rule_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "matches": [],
                "execution_time_ms": 0,
                "errors": [str(e)],
                "warnings": []
            }
    
    async def _create_test_file(
        self, 
        test_code: str, 
        temp_dir: str, 
        language: Optional[str] = None
    ) -> str:
        """Create a temporary file with the test code using atomic operations"""    
        
        # Determine file extension based on language
        language_extensions = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'go': '.go',
            'c': '.c',
            'cpp': '.cpp',
            'csharp': '.cs',
            'php': '.php',
            'ruby': '.rb',
            'rust': '.rs',
            'scala': '.scala',
            'kotlin': '.kt'
        }
        
        # Default to .py if no language specified or unknown language
        extension = language_extensions.get(language, '.py') if language else '.py'
        
        # Create test file
        test_file_path = os.path.join(temp_dir, f'test_file{extension}')
        
        try:
            # Atomic file creation to prevent race conditions
            with open(test_file_path, 'w', encoding='utf-8') as f:
                f.write(test_code)
                f.flush()  # Ensure data is written
                os.fsync(f.fileno())  # Force write to disk
            
            # Verify file was created successfully
            if not os.path.exists(test_file_path) or os.path.getsize(test_file_path) == 0:
                raise ValueError(f"Test file creation verification failed: {test_file_path}")
            
            logger.info(f"Created test file atomically: {test_file_path}")
            return test_file_path
            
        except Exception as e:
            raise ValueError(f"Failed to create test file atomically: {str(e)}")
    
    async def _create_rule_file_from_pattern(
        self,
        rule_pattern: str,
        temp_dir: str,
        tool: str,
        language: Optional[str] = None
    ) -> str:
        """Create a rule file from the provided pattern using atomic operations"""    
        
        try:
            # Parse the pattern to understand its format
            pattern_data = yaml.safe_load(rule_pattern)
            
            if not isinstance(pattern_data, dict):
                raise ValueError("Rule pattern must be valid YAML")
            
            # Check if this is already a complete rule file
            if 'rules' in pattern_data and isinstance(pattern_data['rules'], list):
                # This is already a complete rule file format
                rule_data = pattern_data
            else:
                # This is a single rule or pattern, wrap it
                if 'id' in pattern_data and 'message' in pattern_data:
                    # This is a single rule
                    rule_data = {'rules': [pattern_data]}
                else:
                    # This is just a pattern, create a complete rule
                    rule_data = {
                        'rules': [{
                            'id': 'custom-test-rule',
                            'message': 'Custom rule test',
                            'severity': 'WARNING',
                            'languages': [language] if language else ['generic'],
                            **pattern_data  # Include the pattern fields
                        }]
                    }
            
            # Validate the rule structure
            self._validate_rule_structure(rule_data)
            
            # Create rule file atomically
            rule_file_path = os.path.join(temp_dir, f'custom_rule_{tool}.yaml')
            
            with open(rule_file_path, 'w', encoding='utf-8') as f:
                yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False)
                f.flush()  # Ensure data is written
                os.fsync(f.fileno())  # Force write to disk
            
            # Verify file was created successfully
            if not os.path.exists(rule_file_path) or os.path.getsize(rule_file_path) == 0:
                raise ValueError(f"Rule file creation verification failed: {rule_file_path}")
            
            # Validate the written YAML can be parsed
            try:
                with open(rule_file_path, 'r', encoding='utf-8') as f:
                    test_load = yaml.safe_load(f)
                    if not isinstance(test_load, dict) or 'rules' not in test_load:
                        raise ValueError("Generated rule file has invalid structure")
            except yaml.YAMLError as e:
                raise ValueError(f"Generated rule file is not valid YAML: {e}")
            
            logger.info(f"Created rule file atomically: {rule_file_path}")
            return rule_file_path
            
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in rule pattern: {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to create rule file: {str(e)}")
    
    def _validate_rule_structure(self, rule_data: dict) -> None:
        """Validate the rule structure for the security tool"""
        
        if 'rules' not in rule_data:
            raise ValueError("Rule data must contain 'rules' array")
        
        rules = rule_data['rules']
        if not isinstance(rules, list) or not rules:
            raise ValueError("Rules must be a non-empty array")
        
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"Rule {i} must be a dictionary")
            
            # Check required fields
            required_fields = ['id', 'message']
            for field in required_fields:
                if field not in rule:
                    raise ValueError(f"Rule {i} missing required field: {field}")
            
            # Check for pattern fields
            pattern_fields = ['pattern', 'patterns', 'pattern-either', 'pattern-regex']
            if not any(field in rule for field in pattern_fields):
                raise ValueError(f"Rule {i} must have at least one pattern field")
    
    async def _run_tool_with_rule(
        self,
        runner: BaseToolRunner,
        temp_dir: str,
        rule_file_path: str,
        test_file_path: str,
        tool: str
    ) -> Dict[str, Any]:
        """Run the security tool with the custom rule"""
        
        try:
            if tool == 'semgrep':
                # For Semgrep, pass the custom rule file
                result = await runner.run(
                    temp_dir,
                    custom_rule_files=[rule_file_path],
                    target_files=[test_file_path]
                )
            elif tool == 'bandit':
                # For Bandit, it uses its own rule format
                result = await runner.run(temp_dir)
            else:
                # For other tools, run normally
                result = await runner.run(temp_dir)
            
            return result
            
        except Exception as e:
            logger.error(f"Tool execution failed: {str(e)}")
            return {
                "tool": tool,
                "error": str(e),
                "issues": [],
                "duration": 0
            }
    
    async def _process_test_results(
        self,
        tool_result: Dict[str, Any],
        temp_dir: str,
        tool: str
    ) -> Dict[str, Any]:
        """Process the tool results into standardized test format"""
        
        try:
            # Check if tool execution had errors
            if "error" in tool_result:
                return {
                    "success": False,
                    "error": tool_result["error"],
                    "matches": [],
                    "execution_time_ms": int(tool_result.get("duration", 0) * 1000),
                    "errors": [tool_result["error"]],
                    "warnings": []
                }
            
            # Extract issues/matches
            issues = tool_result.get("issues", [])
            
            # Convert issues to test format
            matches = []
            for issue in issues:
                match = {
                    "message": issue.get("message", "Security issue detected"),
                    "severity": issue.get("severity", "medium"),
                    "line_start": issue.get("line_start"),
                    "line_end": issue.get("line_end"),
                    "file_path": self._clean_file_path(issue.get("file_path", ""), temp_dir),
                    "rule_id": issue.get("rule_id", "unknown"),
                    "confidence": issue.get("confidence", "medium")
                }
                
                # Add code context if available
                if "code_context" in issue:
                    match["code_context"] = issue["code_context"]
                
                matches.append(match)
            
            # Calculate execution time in milliseconds
            execution_time_ms = int(tool_result.get("duration", 0) * 1000)
            
            return {
                "success": True,
                "matches": matches,
                "execution_time_ms": execution_time_ms,
                "errors": [],
                "warnings": [],
                "tool_metadata": {
                    "tool": tool,
                    "rules_run": tool_result.get("rules_run", 1),
                    "version": tool_result.get("metadata", {}).get("version"),
                    "total_issues": len(matches)
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing test results: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to process results: {str(e)}",
                "matches": [],
                "execution_time_ms": 0,
                "errors": [str(e)],
                "warnings": []
            }
    
    def _clean_file_path(self, file_path: str, temp_dir: str) -> str:
        """Clean file path to show relative path"""
        if temp_dir in file_path:
            return os.path.relpath(file_path, temp_dir)
        return file_path
    
    async def validate_rule_pattern(
        self,
        rule_pattern: str,
        tool: str = 'semgrep',
        language: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate a rule pattern without running it against code
        
        Args:
            rule_pattern: The rule pattern in YAML format
            tool: Security tool to validate for
            language: Programming language context
            
        Returns:
            Dict containing validation results
        """
        
        try:
            # Basic YAML validation
            try:
                pattern_data = yaml.safe_load(rule_pattern)
            except yaml.YAMLError as e:
                return {
                    "is_valid": False,
                    "errors": [f"Invalid YAML syntax: {str(e)}"],
                    "warnings": []
                }
            
            if not isinstance(pattern_data, dict):
                return {
                    "is_valid": False,
                    "errors": ["Rule pattern must be a YAML dictionary"],
                    "warnings": []
                }
            
            errors = []
            warnings = []
            
            # Tool-specific validation
            if tool == 'semgrep':
                errors.extend(self._validate_semgrep_pattern(pattern_data))
            elif tool == 'bandit':
                warnings.append("Bandit rule validation not fully implemented")
            
            # Language consistency check
            if language:
                if 'languages' in pattern_data:
                    specified_languages = pattern_data['languages']
                    if isinstance(specified_languages, list) and language not in specified_languages:
                        warnings.append(f"Specified language '{language}' not in rule languages: {specified_languages}")
            
            return {
                "is_valid": len(errors) == 0,
                "errors": errors,
                "warnings": warnings
            }
            
        except Exception as e:
            return {
                "is_valid": False,
                "errors": [f"Validation failed: {str(e)}"],
                "warnings": []
            }
    
    def _validate_semgrep_pattern(self, pattern_data: dict) -> List[str]:
        """Validate Semgrep-specific pattern structure"""
        
        errors = []
        
        # Check if it's a complete rule file or just a pattern
        if 'rules' in pattern_data:
            rules = pattern_data['rules']
            if not isinstance(rules, list):
                errors.append("'rules' must be an array")
                return errors
            
            for i, rule in enumerate(rules):
                errors.extend(self._validate_single_semgrep_rule(rule, i))
        else:
            # Treat as a single rule
            errors.extend(self._validate_single_semgrep_rule(pattern_data, 0))
        
        return errors
    
    def _validate_single_semgrep_rule(self, rule: dict, index: int) -> List[str]:
        """Validate a single Semgrep rule"""
        
        errors = []
        rule_ref = f"Rule {index}"
        
        if not isinstance(rule, dict):
            errors.append(f"{rule_ref} must be a dictionary")
            return errors
        
        # Required fields for complete rules
        if 'id' in rule or 'message' in rule:
            # This looks like a complete rule, validate accordingly
            required_fields = ['id', 'message']
            for field in required_fields:
                if field not in rule:
                    errors.append(f"{rule_ref} missing required field: {field}")
        
        # Pattern validation
        pattern_fields = ['pattern', 'patterns', 'pattern-either', 'pattern-regex']
        has_pattern = any(field in rule for field in pattern_fields)
        
        if not has_pattern:
            errors.append(f"{rule_ref} must have at least one pattern field: {pattern_fields}")
        
        # Validate pattern content
        for field in pattern_fields:
            if field in rule:
                if field == 'patterns':
                    if not isinstance(rule[field], list):
                        errors.append(f"{rule_ref} '{field}' must be an array")
                    elif not rule[field]:
                        errors.append(f"{rule_ref} '{field}' cannot be empty")
                elif not rule[field] or (isinstance(rule[field], str) and not rule[field].strip()):
                    errors.append(f"{rule_ref} '{field}' cannot be empty")
        
        # Validate severity if present
        if 'severity' in rule:
            valid_severities = ['ERROR', 'WARNING', 'INFO']
            if rule['severity'] not in valid_severities:
                errors.append(f"{rule_ref} invalid severity. Must be one of: {valid_severities}")
        
        # Validate languages if present
        if 'languages' in rule:
            if not isinstance(rule['languages'], list):
                errors.append(f"{rule_ref} 'languages' must be an array")
            elif not rule['languages']:
                errors.append(f"{rule_ref} 'languages' cannot be empty")
        
        return errors