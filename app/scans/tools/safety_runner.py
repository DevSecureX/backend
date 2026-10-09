import json
import os
import logging
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner

logger = logging.getLogger(__name__)

class SafetyRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("safety")
        self.timeout = 300  # 5 minutes
        
    async def run(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Safety Python dependency scanner with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 90)  # Max 1.5 minutes for CLI
            logger.info(f"Running Safety in CLI mode with {self.timeout}s timeout")
        
        # ENHANCED: Check for multiple Python dependency files with detailed logging
        logger.info("🔍 Safety: Scanning for Python dependency files...")
        requirements_files = []
        dependency_files_to_check = [
            'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt', 
            'requirements-test.txt', 'dev-requirements.txt', 'setup.py', 'pyproject.toml'
        ]
        
        # Check root directory first
        logger.info(f"   Checking root directory: {temp_dir}")
        for dep_file in dependency_files_to_check:
            dep_path = os.path.join(temp_dir, dep_file)
            if os.path.exists(dep_path):
                file_size = os.path.getsize(dep_path)
                requirements_files.append(dep_path)
                logger.info(f"   ✅ Found: {dep_file} ({file_size} bytes)")
            else:
                logger.debug(f"   ❌ Not found: {dep_file}")
        
        # Then check subdirectories
        if not requirements_files:
            logger.info("   No dependency files in root, checking subdirectories...")
            for root, dirs, files in os.walk(temp_dir):
                # Skip hidden and vendor directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['vendor', 'node_modules', 'dist', 'build']]
                
                for dep_file in dependency_files_to_check:
                    if dep_file in files:
                        full_path = os.path.join(root, dep_file)
                        file_size = os.path.getsize(full_path)
                        requirements_files.append(full_path)
                        logger.info(f"   ✅ Found: {os.path.relpath(full_path, temp_dir)} ({file_size} bytes)")
        
        logger.info(f"📊 Safety: Found {len(requirements_files)} dependency files total")
        
        # Use the first requirements.txt found, or any dependency file if no requirements.txt
        requirements_path = None
        for req_file in requirements_files:
            if 'requirements.txt' in os.path.basename(req_file):
                requirements_path = req_file
                logger.info(f"🎯 Using requirements.txt: {os.path.relpath(req_file, temp_dir)}")
                break
        
        if not requirements_path and requirements_files:
            requirements_path = requirements_files[0]  # Use first available dependency file
            logger.info(f"🎯 Using first available dependency file: {os.path.relpath(requirements_path, temp_dir)}")
            
        if not requirements_path:
            return {
                "issues": [],
                "tool": "safety", 
                "duration": 0,
                "metadata": {
                    "message": f"No Python dependency files found (checked: {dependency_files_to_check})",
                    "cli_mode": is_cli_scan
                }
            }
        
        logger.info(f"Safety will scan: {os.path.basename(requirements_path)}")
        
        # IDENTICAL analysis parameters for CLI and main scan
        cmd = [
            'python3', '-m', 'safety', 'check',
            '-r', requirements_path,
            '--json',
            '--full-report'  # CONSISTENT: comprehensive reporting for both CLI and main
        ]
        
        result = await self.execute_command(cmd)
        
        # Handle Safety dependency conflicts (marshmallow post_dump issue) - ENHANCED DETECTION
        safety_failed = False
        if "error" in result:
            error_msg = result["error"].lower()
            if any(keyword in error_msg for keyword in [
                "post_dump", "marshmallow", "attributeerror", "no module named", 
                "importerror", "modulenotfounderror", "dependency", "conflict"
            ]):
                safety_failed = True
                logger.warning(f"Safety failed with dependency issue: {result['error']}")
        
        # Safety returns exit code 64 when vulnerabilities found, but also check for other failures
        if "error" in result and result.get("returncode", 1) not in (0, 64):
            if not safety_failed:
                # Log the error but try trivy fallback anyway
                logger.warning(f"Safety returned unexpected exit code {result.get('returncode')}: {result['error']}")
            safety_failed = True
        
        # If Safety failed or had issues, use trivy fallback immediately
        if safety_failed:
            return await self._fallback_to_trivy(temp_dir, requirements_path)
        
        try:
            output = json.loads(result["stdout"]) if result["stdout"] else {"vulnerabilities": []}
            issues = []
            
            for vuln in output.get("vulnerabilities", []):
                # Get package info
                package_name = vuln.get("package_name", "unknown")
                affected_versions = vuln.get("vulnerable_spec", [])
                installed_version = vuln.get("analyzed_version", "unknown")
                
                for advisory in vuln.get("vulnerabilities", []):
                    issue = {
                        "tool": "safety",
                        "category": "deps",
                        "rule_id": advisory.get("id", f"SAFETY-{package_name}"),
                        "message": f"{package_name} {installed_version}: {advisory.get('title', 'Vulnerability detected')}",
                        "severity": self._map_safety_severity(advisory.get("severity", "unknown")),
                        "file_path": self.clean_file_path(requirements_path, temp_dir),
                        "line_start": self._find_package_line(requirements_path, package_name),
                        "confidence": "very_high",
                        "package_name": package_name,
                        "installed_version": installed_version,
                        "fixed_version": advisory.get("fixed_in", ["No fix available"])[0] if advisory.get("fixed_in") else "No fix available",
                        "cve_id": advisory.get("cve"),
                        "advisory_id": advisory.get("id"),
                        "owasp_category": "A06:2021 – Vulnerable and Outdated Components",
                        "cwe_id": self._extract_cwe_from_advisory(advisory),
                        "metadata": {
                            "description": advisory.get("description"),
                            "references": advisory.get("references", []),
                            "affected_versions": affected_versions
                        }
                    }
                    issues.append(issue)
            
            return {
                "issues": issues,
                "tool": "safety",
                "duration": result["duration"],
                "packages_scanned": len(output.get("scanned_packages", [])),
                "vulnerabilities_found": len(issues)
            }
            
        except json.JSONDecodeError as e:
            return {"issues": [], "error": f"Invalid JSON output: {str(e)}", "tool": "safety"}
    
    def _map_safety_severity(self, severity: str) -> str:
        """Map Safety severity to standard levels"""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "moderate": "medium",
            "low": "low",
            "unknown": "medium"
        }
        return severity_map.get(severity.lower(), "medium")
    
    def _find_package_line(self, requirements_path: str, package_name: str) -> int:
        """Find line number of package in requirements.txt"""
        try:
            with open(requirements_path, 'r') as f:
                for i, line in enumerate(f, 1):
                    if package_name.lower() in line.lower():
                        return i
        except:
            pass
        return 1  # Default to first line if not found
    
    def _extract_cwe_from_advisory(self, advisory: Dict[str, Any]) -> str:
        """Extract CWE from advisory data"""
        # Try to extract from CVE details or description
        cve = advisory.get("cve", "")
        description = advisory.get("description", "").lower()
        
        # Common vulnerability to CWE mappings
        if "injection" in description:
            return "CWE-89" if "sql" in description else "CWE-78"
        elif "cross-site scripting" in description or "xss" in description:
            return "CWE-79"
        elif "buffer overflow" in description:
            return "CWE-119"
        elif "authentication" in description:
            return "CWE-287"
        elif "cryptograph" in description:
            return "CWE-327"
        elif "deserializ" in description:
            return "CWE-502"
        elif "path traversal" in description or "directory traversal" in description:
            return "CWE-22"
        elif "denial of service" in description or "dos" in description:
            return "CWE-400"
        
        # Default to generic vulnerability
        return "CWE-200"
    
    async def _fallback_to_trivy(self, temp_dir: str, requirements_path: str) -> Dict[str, Any]:
        """Enhanced trivy fallback for Python dependency scanning when Safety fails"""
        import logging
        logger = logging.getLogger(__name__)
        
        logger.warning("Safety failed with dependency conflicts. Using enhanced trivy fallback.")
        
        # ENHANCED: Try multiple approaches for better vulnerability detection
        commands_to_try = [
            # First: Direct requirements file scan with pip detector
            [
                'trivy', 'fs',
                '--format', 'json',
                '--scanners', 'vuln',
                '--skip-files', '*.py,*.pyc',  # Only scan dependencies, not code
                '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                '--list-all-pkgs',  # List all packages found
                requirements_path
            ],
            # Second: Try scanning parent directory (in case requirements.txt references relative paths)
            [
                'trivy', 'fs',
                '--format', 'json', 
                '--scanners', 'vuln',
                '--skip-files', '*.py,*.pyc,*.pyo',
                '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                '--list-all-pkgs',
                os.path.dirname(requirements_path) if os.path.dirname(requirements_path) != temp_dir else temp_dir
            ],
            # Third: Full directory scan as last resort
            [
                'trivy', 'fs',
                '--format', 'json',
                '--scanners', 'vuln',
                '--skip-files', '*.py,*.pyc,*.pyo',
                '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
                temp_dir
            ]
        ]
        
        for cmd_idx, cmd in enumerate(commands_to_try):
            try:
                logger.info(f"Trying trivy command {cmd_idx + 1}: {' '.join(cmd)}")
                result = await self.execute_command(cmd)
                
                if "error" not in result or result.get("stdout"):
                    # Process successful result
                    return self._process_trivy_output(result, requirements_path, temp_dir, cmd_idx + 1)
                    
            except Exception as e:
                logger.warning(f"Trivy command {cmd_idx + 1} failed: {str(e)}")
                continue
        
        # If all trivy attempts failed, return error
        return {
            "issues": [],
            "error": "Safety failed and all trivy fallback attempts failed",
            "tool": "safety",
            "metadata": {"fallback_used": "trivy", "reason": "safety_dependency_conflict", "status": "failed"}
        }
    
    def _process_trivy_output(self, result: Dict[str, Any], requirements_path: str, temp_dir: str, attempt_num: int) -> Dict[str, Any]:
        """Process trivy JSON output into safety-compatible format"""
        try:
            import json
            output = json.loads(result["stdout"]) if result["stdout"] else {}
            issues = []
            
            # Parse trivy results - enhanced to catch more vulnerabilities
            results = output.get("Results", [])
            if not results:
                # Try alternative structure
                if "SchemaVersion" in output:
                    results = [output]
            
            for result_item in results:
                # Look for various result types
                result_types = ["pip", "python-pkg", "requirements.txt", "python"]
                vulnerabilities = result_item.get("Vulnerabilities", [])
                
                # If no vulnerabilities found in standard location, try other structures
                if not vulnerabilities:
                    # Check for nested structures
                    for key in ["Results", "Packages", "Dependencies"]:
                        if key in result_item:
                            for sub_item in result_item[key]:
                                vulnerabilities.extend(sub_item.get("Vulnerabilities", []))
                
                for vulnerability in vulnerabilities:
                    # Map trivy severity to standard levels
                    severity = vulnerability.get("Severity", "medium").lower()
                    if severity == "unknown":
                        severity = "medium"
                    elif severity == "negligible":
                        severity = "low"
                    
                    issue = {
                        "tool": "safety",
                        "category": "deps",
                        "rule_id": vulnerability.get("VulnerabilityID", f"TRIVY-{vulnerability.get('PkgName', 'UNKNOWN')}"),
                        "message": f"{vulnerability.get('PkgName', 'unknown')} {vulnerability.get('InstalledVersion', '')}: {vulnerability.get('Title', 'Vulnerability detected')}",
                        "severity": severity,
                        "file_path": self.clean_file_path(requirements_path, temp_dir),
                        "line_start": self._find_package_line(requirements_path, vulnerability.get('PkgName', '')),
                        "confidence": "high",
                        "package_name": vulnerability.get("PkgName"),
                        "installed_version": vulnerability.get("InstalledVersion"),
                        "fixed_version": vulnerability.get("FixedVersion", "No fix available"),
                        "cve_id": vulnerability.get("VulnerabilityID") if vulnerability.get("VulnerabilityID", "").startswith("CVE") else None,
                        "advisory_id": vulnerability.get("VulnerabilityID"),
                        "owasp_category": "A06:2021 – Vulnerable and Outdated Components",
                        "cwe_id": self._extract_cwe_from_trivy_vuln(vulnerability),
                        "metadata": {
                            "description": vulnerability.get("Description"),
                            "references": vulnerability.get("References", []),
                            "fallback_tool": "trivy",
                            "trivy_attempt": attempt_num,
                            "primary_url": vulnerability.get("PrimaryURL"),
                            "data_source": vulnerability.get("DataSource")
                        }
                    }
                    issues.append(issue)
            
            logger.info(f"Trivy fallback (attempt {attempt_num}) found {len(issues)} dependency vulnerabilities")
            
            return {
                "issues": issues,
                "tool": "safety",
                "duration": result["duration"],
                "packages_scanned": len(set(issue["package_name"] for issue in issues if issue.get("package_name"))),
                "vulnerabilities_found": len(issues),
                "metadata": {
                    "fallback_used": "trivy", 
                    "reason": "safety_dependency_conflict",
                    "trivy_attempt": attempt_num,
                    "status": "success"
                }
            }
            
        except json.JSONDecodeError as e:
            return {
                "issues": [],
                "error": f"Trivy fallback JSON parsing failed: {str(e)}",
                "tool": "safety",
                "metadata": {"fallback_used": "trivy", "reason": "json_parse_error"}
            }
    
    def _extract_cwe_from_trivy_vuln(self, vulnerability: Dict[str, Any]) -> str:
        """Extract or map CWE from Trivy vulnerability data"""
        # Check if CWE is directly provided
        cwe_ids = vulnerability.get("CweIDs", [])
        if cwe_ids:
            return cwe_ids[0]
        
        # Try to extract from description or title
        description = (vulnerability.get("Description", "") + " " + vulnerability.get("Title", "")).lower()
        
        # Enhanced CWE mapping based on vulnerability patterns
        cwe_patterns = {
            "injection": "CWE-89",
            "sql injection": "CWE-89", 
            "command injection": "CWE-78",
            "cross-site scripting": "CWE-79",
            "xss": "CWE-79",
            "buffer overflow": "CWE-119",
            "authentication": "CWE-287",
            "authorization": "CWE-285",
            "cryptograph": "CWE-327",
            "weak cryptography": "CWE-327",
            "deserializ": "CWE-502",
            "path traversal": "CWE-22",
            "directory traversal": "CWE-22",
            "denial of service": "CWE-400",
            "dos": "CWE-400",
            "memory": "CWE-119",
            "information disclosure": "CWE-200",
            "sensitive data": "CWE-200",
            "input validation": "CWE-20",
            "race condition": "CWE-362"
        }
        
        for pattern, cwe in cwe_patterns.items():
            if pattern in description:
                return cwe
        
        # Default to generic information disclosure
        return "CWE-200"