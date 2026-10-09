import json
import logging
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner

logger = logging.getLogger(__name__)

class TrivyRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("trivy")
        self.timeout = 600  # 10 minutes for dependency scanning
        
    async def run(self, temp_dir: str, scan_types: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Trivy vulnerability scanning with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 300)  # Max 5 minutes for CLI
            logger.info(f"Running Trivy in CLI mode with {self.timeout}s timeout")
        
        # IDENTICAL analysis parameters: same scan types for CLI and main scan
        if not scan_types:
            scan_types = ['vuln', 'secret', 'misconfig']  # CONSISTENT: same comprehensive scanning for all
        
        all_issues = []
        successful_scans = []
        failed_scans = []
        
        for scan_type in scan_types:
            # IDENTICAL analysis parameters for CLI and main scan
            cmd = [
                'trivy',
                'fs',
                '--format', 'json',
                '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',  # CONSISTENT: same severity levels for all scans
                '--quiet',
                '--no-progress',
                '--scanners', scan_type,
                '--timeout', f'{self.timeout//60}m'  # Use standardized timeout for all scans
            ]
            
            cmd.append(temp_dir)
            
            logger.info(f"Running Trivy {scan_type} scan on {temp_dir}")
            result = await self.execute_command(cmd)
            
            if "error" in result:
                failed_scans.append(scan_type)
                logger.warning(f"Trivy {scan_type} scan failed: {result.get('error')}")
                continue  # Try other scan types even if one fails
            
            successful_scans.append(scan_type)
            
            try:
                stdout = result.get("stdout", "").strip()
                if not stdout:
                    logger.warning(f"Trivy {scan_type} scan produced no output")
                    continue
                
                output = json.loads(stdout)
                
                # Handle different Trivy output formats
                results = output.get("Results", [])
                if not results:
                    logger.info(f"Trivy {scan_type} scan found no results")
                    continue
                
                for target in results:
                    target_path = target.get("Target", "")
                    
                    # Process vulnerabilities
                    vulnerabilities = target.get("Vulnerabilities", [])
                    for vuln in vulnerabilities:
                        issue = {
                            "tool": "trivy",
                            "category": self._get_category(scan_type),
                            "rule_id": vuln.get("VulnerabilityID") or vuln.get("ID", "TRIVY-UNKNOWN"),
                            "message": vuln.get("Title") or vuln.get("Description", "Vulnerability found"),
                            "severity": self.normalize_severity(vuln.get("Severity", "MEDIUM")),
                            "file_path": self.clean_file_path(target_path, temp_dir),
                            "confidence": "high",
                            "package_name": vuln.get("PkgName"),
                            "installed_version": vuln.get("InstalledVersion"),
                            "fixed_version": vuln.get("FixedVersion"),
                            "owasp_category": "A06:2021 – Vulnerable and Outdated Components",
                            "cwe_id": self._extract_cwe_from_references(vuln.get("References", [])),
                            "metadata": {
                                "scan_type": scan_type,
                                "trivy_type": "vulnerability",
                                "cli_mode": is_cli_scan
                            }
                        }
                        all_issues.append(issue)
                    
                    # Process secrets (for secret scanner)
                    secrets = target.get("Secrets", [])
                    for secret in secrets:
                        issue = {
                            "tool": "trivy",
                            "category": "secrets",
                            "rule_id": secret.get("RuleID", "TRIVY-SECRET"),
                            "message": f"Secret detected: {secret.get('Title', 'Potential secret')}",
                            "severity": self.normalize_severity(secret.get("Severity", "HIGH")),
                            "file_path": self.clean_file_path(target_path, temp_dir),
                            "line_start": secret.get("StartLine", 0),
                            "line_end": secret.get("EndLine", 0),
                            "confidence": "medium",
                            "owasp_category": "A07:2021 – Identification and Authentication Failures",
                            "cwe_id": "CWE-798",
                            "metadata": {
                                "scan_type": scan_type,
                                "trivy_type": "secret",
                                "cli_mode": is_cli_scan
                            }
                        }
                        all_issues.append(issue)
                    
                    # Process misconfigurations
                    misconfigs = target.get("Misconfigurations", [])
                    for misconfig in misconfigs:
                        issue = {
                            "tool": "trivy",
                            "category": "configs",
                            "rule_id": misconfig.get("ID", "TRIVY-MISCONFIG"),
                            "message": misconfig.get("Title") or misconfig.get("Description", "Configuration issue"),
                            "severity": self.normalize_severity(misconfig.get("Severity", "MEDIUM")),
                            "file_path": self.clean_file_path(target_path, temp_dir),
                            "line_start": misconfig.get("CauseMetadata", {}).get("StartLine", 0),
                            "line_end": misconfig.get("CauseMetadata", {}).get("EndLine", 0),
                            "confidence": "high",
                            "owasp_category": "A05:2021 – Security Misconfiguration",
                            "cwe_id": misconfig.get("CweID"),
                            "metadata": {
                                "scan_type": scan_type,
                                "trivy_type": "misconfiguration",
                                "cli_mode": is_cli_scan
                            }
                        }
                        all_issues.append(issue)
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy {scan_type} output: {e}")
                failed_scans.append(f"{scan_type}-parse")
                continue
            except Exception as e:
                logger.error(f"Error processing Trivy {scan_type} results: {e}")
                failed_scans.append(f"{scan_type}-process")
                continue
        
        return {
            "issues": all_issues,
            "tool": "trivy",
            "duration": result.get("duration", 0) if 'result' in locals() else 0,
            "scan_types": scan_types,
            "successful_scans": successful_scans,
            "failed_scans": failed_scans,
            "metadata": {
                "cli_mode": is_cli_scan,
                "timeout_used": self.timeout,
                "total_scans": len(scan_types),
                "successful_count": len(successful_scans),
                "failed_count": len(failed_scans)
            }
        }
    
    def _get_category(self, scan_type: str) -> str:
        """Map Trivy scan type to category"""
        category_map = {
            'vuln': 'deps',
            'secret': 'secrets',
            'misconfig': 'configs',
            'license': 'deps'
        }
        return category_map.get(scan_type, 'deps')
    
    def _extract_cwe_from_references(self, references: List[str]) -> str:
        """Extract CWE ID from references"""
        for ref in references:
            if 'cwe.mitre.org' in ref and 'CWE-' in ref:
                # Extract CWE number from URL
                import re
                match = re.search(r'CWE-(\d+)', ref)
                if match:
                    return f"CWE-{match.group(1)}"
        return None