"""
Enhanced Async Semgrep Runner for DevSecureX
Phase 3: High-performance async Semgrep execution with non-blocking I/O
"""

import json
import os
import logging
import yaml
import asyncio
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..async_base_runner import AsyncBaseToolRunner
from core.async_file_io import read_file_async, write_file_async, AsyncFileIOManager
from ..utils.code_context_extractor import CodeContextExtractor

logger = logging.getLogger(__name__)

class AsyncSemgrepRunner(AsyncBaseToolRunner):
    """
    World-class async Semgrep runner with comprehensive vulnerability detection
    
    Features:
    - Non-blocking file I/O operations
    - Concurrent rule processing and validation
    - Memory-efficient large file handling
    - Enhanced error recovery and reporting
    - Intelligent rule optimization
    """
    
    def __init__(self):
        super().__init__("semgrep")
        self.timeout = 900  # 15 minutes for comprehensive analysis
        self.context_extractor = CodeContextExtractor(context_lines=3)
        self.file_manager = AsyncFileIOManager()
        
    async def validate_rule_file_async(self, rule_file_path: str) -> bool:
        """Validate a custom rule file asynchronously to prevent crashes"""
        try:
            # Check if file exists
            if not await self.file_manager.file_exists_async(rule_file_path):
                logger.warning(f"Rule file does not exist: {rule_file_path}")
                return False
            
            # Get file info
            file_info = await self.file_manager.get_file_info_async(rule_file_path)
            if not file_info:
                logger.warning(f"Cannot get file info: {rule_file_path}")
                return False
            
            # Check file size (max 10MB)
            if file_info["size"] > 10 * 1024 * 1024:  # 10MB
                logger.warning(f"Rule file too large ({file_info['size']} bytes): {rule_file_path}")
                return False
            
            # Read file content asynchronously
            content = await read_file_async(rule_file_path)
            if not content.strip():
                logger.warning(f"Rule file is empty: {rule_file_path}")
                return False
            
            # Parse and validate YAML structure
            try:
                yaml_data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                logger.warning(f"Invalid YAML syntax in rule file {rule_file_path}: {e}")
                return False
            
            # Validate rule structure
            return await self._validate_rule_structure_async(yaml_data, rule_file_path)
            
        except Exception as e:
            logger.warning(f"Error validating rule file async {rule_file_path}: {e}")
            return False
    
    async def _validate_rule_structure_async(self, yaml_data: Dict[str, Any], rule_file_path: str) -> bool:
        """Validate rule structure asynchronously"""
        if not isinstance(yaml_data, dict):
            logger.warning(f"Rule file must contain a YAML dictionary: {rule_file_path}")
            return False
        
        # Check for rules array
        rules = yaml_data.get('rules', [])
        if not isinstance(rules, list) or len(rules) == 0:
            logger.warning(f"Rule file must contain a non-empty 'rules' array: {rule_file_path}")
            return False
        
        # Validate each rule concurrently
        validation_tasks = [
            self._validate_single_rule_async(rule, i, rule_file_path)
            for i, rule in enumerate(rules)
        ]
        
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        # Check all validations passed
        all_valid = True
        for result in validation_results:
            if isinstance(result, Exception):
                logger.warning(f"Rule validation exception: {result}")
                all_valid = False
            elif not result:
                all_valid = False
        
        if all_valid:
            logger.info(f"Successfully validated rule file with {len(rules)} rules: {rule_file_path}")
        
        return all_valid
    
    async def _validate_single_rule_async(self, rule: Dict[str, Any], rule_index: int, file_path: str) -> bool:
        """Validate a single rule asynchronously"""
        if not isinstance(rule, dict):
            logger.warning(f"Rule {rule_index} is not a dictionary in {file_path}")
            return False
        
        # Check required fields
        required_fields = ['id', 'message']
        for field in required_fields:
            if field not in rule:
                logger.warning(f"Rule {rule_index} missing required field '{field}' in {file_path}")
                return False
        
        # Check for pattern fields
        pattern_fields = ['pattern', 'patterns', 'pattern-either']
        if not any(field in rule for field in pattern_fields):
            logger.warning(f"Rule {rule_index} missing pattern field in {file_path}")
            return False
        
        # Validate severity if present
        if 'severity' in rule:
            valid_severities = ['ERROR', 'WARNING', 'INFO']
            if rule['severity'] not in valid_severities:
                logger.warning(f"Rule {rule_index} has invalid severity '{rule['severity']}' in {file_path}")
                return False
        
        # Validate languages if present
        if 'languages' in rule and not isinstance(rule['languages'], list):
            logger.warning(f"Rule {rule_index} 'languages' must be a list in {file_path}")
            return False
        
        return True
    
    async def run_async(self, temp_dir: str, niche: str = None, **kwargs) -> Dict[str, Any]:
        """
        Async Semgrep SAST analysis with world-class vulnerability detection
        
        Features:
        - Concurrent file scanning and processing
        - Non-blocking rule loading and validation
        - Memory-efficient result processing
        - Enhanced error handling and recovery
        """
        logger.info(f"Starting async Semgrep analysis in {temp_dir}")
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Prepare command and options concurrently
            command_task = self._prepare_semgrep_command_async(temp_dir, niche, **kwargs)
            file_scan_task = self.scan_files_async(temp_dir, ['*.py', '*.js', '*.jsx', '*.ts', '*.tsx', '*.go', '*.java', '*.php', '*.rb', '*.c', '*.cpp', '*.cs'])
            
            command, target_files = await asyncio.gather(command_task, file_scan_task)
            
            if not target_files:
                logger.warning("No target files found for Semgrep analysis")
                return {
                    "tool": "semgrep",
                    "issues": [],
                    "success": True,
                    "execution_time": asyncio.get_event_loop().time() - start_time
                }
            
            logger.info(f"Async Semgrep will analyze {len(target_files)} files")
            
            # Execute Semgrep asynchronously
            result = await self.execute_tool_command_async(
                command=command,
                working_dir=temp_dir,
                timeout=self.timeout
            )
            
            if not result["success"]:
                logger.error(f"Semgrep execution failed: {result.get('stderr', 'Unknown error')}")
                return {
                    "tool": "semgrep",
                    "issues": [],
                    "error": result.get("stderr", "Semgrep execution failed"),
                    "success": False,
                    "execution_time": result.get("execution_time", 0)
                }
            
            # Process results asynchronously
            issues = await self._process_semgrep_results_async(result["stdout"], temp_dir)
            
            execution_time = asyncio.get_event_loop().time() - start_time
            logger.info(f"Async Semgrep analysis completed: {len(issues)} issues found in {execution_time:.2f}s")
            
            return {
                "tool": "semgrep",
                "issues": issues,
                "success": True,
                "execution_time": execution_time,
                "files_analyzed": len(target_files),
                "stdout": result["stdout"][:1000] if len(result["stdout"]) > 1000 else result["stdout"]  # Truncate for logging
            }
            
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            logger.error(f"Async Semgrep analysis failed: {str(e)}", exc_info=True)
            return {
                "tool": "semgrep",
                "issues": [],
                "error": str(e),
                "success": False,
                "execution_time": execution_time
            }
    
    async def _prepare_semgrep_command_async(self, temp_dir: str, niche: str = None, **kwargs) -> List[str]:
        """Prepare Semgrep command asynchronously with rule optimization"""
        
        # Base command
        command = [
            "semgrep",
            "--config=auto",  # Use Semgrep's curated rulesets
            "--json",
            "--no-git-ignore",
            "--timeout", "900",  # 15 minutes timeout
            "--max-target-bytes", "0",  # Remove file size restrictions for comprehensive scanning
            "--verbose"
        ]
        
        # Add niche-specific rules
        if niche and niche != "all":
            niche_configs = await self._get_niche_configs_async(niche)
            for config in niche_configs:
                command.extend(["--config", config])
        
        # Add custom rules if provided
        custom_rule_files = kwargs.get('custom_rule_files', [])
        if custom_rule_files:
            validated_rules = await self._validate_custom_rules_concurrent(custom_rule_files)
            for rule_file in validated_rules:
                command.extend(["--config", rule_file])
                logger.info(f"Added custom rule file to Semgrep: {rule_file}")
        
        # Add API rules for web applications
        if kwargs.get('include_api_rules', False):
            api_configs = [
                "p/owasp-top-ten",
                "p/security-audit",
                "p/r2c-security-audit"
            ]
            for config in api_configs:
                command.extend(["--config", config])
        
        # Add target directory
        command.append(temp_dir)
        
        return command
    
    async def _get_niche_configs_async(self, niche: str) -> List[str]:
        """Get niche-specific Semgrep configurations asynchronously"""
        niche_mapping = {
            'ai': ["p/python", "p/security-audit", "p/owasp-top-ten"],
            'blockchain': ["p/security-audit", "p/owasp-top-ten", "p/javascript"],
            'iot': ["p/c", "p/security-audit", "p/cwe-top-25"],
            'web3': ["p/javascript", "p/security-audit", "p/owasp-top-ten"],
            'cloud': ["p/security-audit", "p/owasp-top-ten", "p/docker"],
            'api': ["p/owasp-top-ten", "p/security-audit", "p/flask"]
        }
        
        return niche_mapping.get(niche, ["p/security-audit"])
    
    async def _validate_custom_rules_concurrent(self, rule_files: List[str]) -> List[str]:
        """Validate multiple custom rule files concurrently"""
        validation_tasks = [
            self.validate_rule_file_async(rule_file)
            for rule_file in rule_files
        ]
        
        validation_results = await asyncio.gather(*validation_tasks, return_exceptions=True)
        
        validated_files = []
        for rule_file, result in zip(rule_files, validation_results):
            if isinstance(result, Exception):
                logger.warning(f"Rule validation exception for {rule_file}: {result}")
                continue
            if result:
                validated_files.append(rule_file)
            else:
                logger.warning(f"Rule file validation failed: {rule_file}")
        
        logger.info(f"Validated {len(validated_files)}/{len(rule_files)} custom rule files")
        return validated_files
    
    async def _process_semgrep_results_async(self, stdout: str, temp_dir: str) -> List[Dict[str, Any]]:
        """Process Semgrep results asynchronously with concurrent issue processing"""
        if not stdout.strip():
            logger.warning("Semgrep returned no output")
            return []
        
        try:
            # Parse JSON output
            semgrep_data = json.loads(stdout)
            
            if "results" not in semgrep_data:
                logger.warning("No 'results' field in Semgrep output")
                return []
            
            raw_results = semgrep_data["results"]
            if not raw_results:
                logger.info("Semgrep found no security issues")
                return []
            
            logger.info(f"Processing {len(raw_results)} Semgrep findings concurrently")
            
            # Process results concurrently
            process_tasks = [
                self._process_single_semgrep_issue_async(result, temp_dir)
                for result in raw_results
            ]
            
            processed_results = await asyncio.gather(*process_tasks, return_exceptions=True)
            
            # Collect successful results
            issues = []
            for result in processed_results:
                if isinstance(result, Exception):
                    logger.warning(f"Issue processing failed: {result}")
                    continue
                if result:
                    issues.append(result)
            
            logger.info(f"Successfully processed {len(issues)} Semgrep issues")
            return issues
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON output: {e}")
            logger.debug(f"Semgrep output (first 1000 chars): {stdout[:1000]}")
            return []
        except Exception as e:
            logger.error(f"Error processing Semgrep results: {e}")
            return []
    
    async def _process_single_semgrep_issue_async(self, result: Dict[str, Any], temp_dir: str) -> Optional[Dict[str, Any]]:
        """Process a single Semgrep issue asynchronously with context extraction"""
        try:
            # Extract basic issue information
            path = result.get("path", "")
            start_line = result.get("start", {}).get("line", 1)
            end_line = result.get("end", {}).get("line", start_line)
            
            # Convert absolute path to relative
            if path.startswith(temp_dir):
                relative_path = os.path.relpath(path, temp_dir)
            else:
                relative_path = path
            
            # Extract rule information
            check_id = result.get("check_id", "unknown")
            message = result.get("message", "Security issue detected by Semgrep")
            severity = self._map_semgrep_severity(result.get("extra", {}).get("severity", "INFO"))
            
            # Get metadata
            metadata = result.get("extra", {})
            
            # Extract code context asynchronously if file exists
            code_context = None
            if path and await self.file_manager.file_exists_async(path):
                try:
                    # Use async context extraction
                    file_content = await read_file_async(path)
                    lines = file_content.splitlines()
                    
                    # Extract context around the issue
                    context_start = max(0, start_line - 4)  # 3 lines before + current line
                    context_end = min(len(lines), end_line + 3)  # current line + 3 lines after
                    
                    context_lines = []
                    for i in range(context_start, context_end):
                        line_number = i + 1
                        line_content = lines[i] if i < len(lines) else ""
                        marker = ">>>" if context_start < line_number <= end_line else "   "
                        context_lines.append(f"{marker} {line_number:4d}: {line_content}")
                    
                    code_context = "\n".join(context_lines)
                    
                except Exception as e:
                    logger.debug(f"Failed to extract code context for {path}: {e}")
            
            # Map to standardized format
            return {
                "tool": "semgrep",
                "rule_id": check_id,
                "message": message,
                "severity": severity,
                "file_path": relative_path,
                "line_start": start_line,
                "line_end": end_line,
                "category": "code",
                "confidence": self._map_confidence(metadata.get("confidence", "medium")),
                "owasp_category": self._extract_owasp_category(metadata),
                "cwe_id": self._extract_cwe_id(metadata),
                "code_context": code_context,
                "metadata": {
                    "semgrep_rule_id": check_id,
                    "semgrep_metadata": metadata,
                    "fix_suggestions": metadata.get("fix", "")
                }
            }
            
        except Exception as e:
            logger.warning(f"Error processing Semgrep issue: {e}")
            return None
    
    def _map_semgrep_severity(self, severity: str) -> str:
        """Map Semgrep severity to standardized levels"""
        severity_map = {
            "ERROR": "high",
            "WARNING": "medium", 
            "INFO": "low"
        }
        return severity_map.get(severity.upper(), "medium")
    
    def _map_confidence(self, confidence: str) -> str:
        """Map confidence levels"""
        confidence_map = {
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low"
        }
        return confidence_map.get(confidence.upper(), "medium")
    
    def _extract_owasp_category(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Extract OWASP category from metadata"""
        # Look for OWASP references in various fields
        references = metadata.get("references", [])
        for ref in references:
            if isinstance(ref, str) and "owasp" in ref.lower():
                return ref
        
        # Check technology tags for OWASP mappings
        technology = metadata.get("technology", [])
        if isinstance(technology, list):
            for tech in technology:
                if "owasp" in str(tech).lower():
                    return str(tech)
        
        return None
    
    def _extract_cwe_id(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from metadata"""
        # Look for CWE references
        references = metadata.get("references", [])
        for ref in references:
            if isinstance(ref, str) and "cwe-" in ref.lower():
                # Extract CWE number
                import re
                match = re.search(r'cwe-(\d+)', ref.lower())
                if match:
                    return f"CWE-{match.group(1)}"
        
        # Check in other fields
        cwe_id = metadata.get("cwe_id")
        if cwe_id:
            return str(cwe_id)
            
        return None

# Create async instance for import
async_semgrep_runner = AsyncSemgrepRunner()