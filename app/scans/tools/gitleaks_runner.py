import json
import os
import logging
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
from ..utils.code_context_extractor import CodeContextExtractor

logger = logging.getLogger(__name__)

class GitLeaksRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("gitleaks")
        self.timeout = 900  # 15 minutes for git history scan
        self.context_extractor = CodeContextExtractor(context_lines=2)  # Less context for secrets
        
    async def run(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Run GitLeaks to detect secrets in files (CLI-compatible) - ENHANCED"""
        
        logger.info(f"GitLeaks runner starting: temp_dir={temp_dir}, kwargs={kwargs}")
        
        # Create a unique report path to avoid conflicts
        import time
        report_path = f'/tmp/gitleaks-report-{int(time.time())}-{os.getpid()}.json'
        
        # Check if it's CLI scan to adjust command
        is_cli_scan = kwargs.get('is_cli_scan', False)
        
        # Enhanced command for better secret detection in CLI mode
        cmd = [
            'gitleaks',
            'detect',
            '--source', temp_dir,
            '--report-format', 'json',
            '--report-path', report_path,
            '--no-banner',
            '--redact',
            '--no-git',  # Scan files directly, not git history
        ]
        
        # Use consistent parameters across CLI and main scan for parity
        # Removed CLI-specific parameter overrides to ensure identical behavior
        
        logger.info(f"CLI scan mode: {is_cli_scan}")
        
        # Log the command for debugging
        logger.info(f"Running GitLeaks with command: {' '.join(cmd)}")
        logger.info(f"Report will be written to: {report_path}")
        
        # Use custom command execution for GitLeaks to handle exit codes properly
        result = await self._execute_gitleaks_command(cmd)
        
        # GitLeaks returns exit code 1 when leaks found, which is expected
        # Exit code 2 is when no .git directory (expected for CLI scans)
        # Be more permissive with exit codes as GitLeaks can be inconsistent
        if "error" in result and result["returncode"] not in [0, 1, 2]:
            logger.warning(f"GitLeaks returned unexpected exit code {result.get('returncode')}: {result['error']}")
            # Continue processing anyway as stdout might still contain findings
        
        issues = []
        
        try:
            # Check if report file exists and has content
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        try:
                            # Handle both single object and array formats
                            if content.startswith('['):
                                output = json.loads(content)
                            else:
                                # Single finding format
                                output = [json.loads(content)]
                        except json.JSONDecodeError:
                            # Handle JSONL format (one JSON object per line)
                            output = []
                            for line in content.split('\n'):
                                if line.strip():
                                    try:
                                        output.append(json.loads(line))
                                    except json.JSONDecodeError:
                                        continue
                    else:
                        output = []
            else:
                logger.warning(f"GitLeaks report file not found: {report_path}")
                output = []
            
            logger.info(f"GitLeaks found {len(output)} potential secrets")
            
            for finding in output:
                # Enhanced file path extraction
                file_path = (
                    finding.get("File") or 
                    finding.get("file") or 
                    finding.get("Path") or
                    ""
                )
                
                if not file_path:
                    logger.warning(f"No file path in GitLeaks finding: {finding}")
                    continue
                
                cleaned_file_path = self.clean_file_path(file_path, temp_dir)
                
                # Enhanced line number extraction
                line_start = (
                    finding.get("StartLine") or 
                    finding.get("Line") or 
                    finding.get("line") or
                    1
                )
                line_end = finding.get("EndLine", line_start)
                
                # Extract code context for the secret
                code_context = None
                if line_start and cleaned_file_path:
                    try:
                        code_context = self.context_extractor.extract_context(
                            file_path=cleaned_file_path,
                            line_start=line_start,
                            line_end=line_end,
                            temp_dir=temp_dir
                        )
                    except Exception as e:
                        logger.debug(f"Failed to extract context for {cleaned_file_path}:{line_start}: {e}")
                
                # Enhanced rule and description extraction
                rule_id = finding.get("RuleID") or finding.get("Rule") or "unknown"
                description = (
                    finding.get("Description") or 
                    finding.get("description") or
                    f"Secret detected by rule {rule_id}"
                )
                
                # Classify secret type from rule ID
                secret_type = self._classify_gitleaks_secret_type(rule_id, finding.get("Secret", ""))
                
                issue = {
                    "tool": "gitleaks",
                    "category": "secrets",
                    "rule_id": f"gitleaks-{rule_id}",
                    "message": f"Secret detected: {description} in {os.path.basename(cleaned_file_path)}",
                    "severity": self._get_gitleaks_severity(rule_id),
                    "file_path": cleaned_file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "confidence": "very_high" if finding.get("Entropy", 0) > 4.5 else "high",
                    "secret_type": secret_type,
                    "commit": finding.get("Commit"),
                    "author": finding.get("Author"),
                    "date": finding.get("Date"),
                    "code_context": code_context,
                    "owasp_category": "A07:2021 – Identification and Authentication Failures",
                    "cwe_id": "CWE-798",
                    "metadata": {
                        "entropy": finding.get("Entropy"),
                        "commit_message": finding.get("Message"),
                        "tags": finding.get("Tags", []),
                        "original_rule_id": rule_id,
                        "fingerprint": finding.get("Fingerprint"),
                        "file_extension": os.path.splitext(cleaned_file_path)[1]
                    }
                }
                
                # Add truncated secret for debugging
                secret = finding.get("Secret", "")
                if secret:
                    if len(secret) > 10:
                        issue["metadata"]["truncated_secret"] = secret[:4] + "..." + secret[-4:]
                    else:
                        issue["metadata"]["truncated_secret"] = "***"
                
                issues.append(issue)
                logger.debug(f"Found secret: {rule_id} in {cleaned_file_path}:{line_start}")
            
            # Clean up report file
            try:
                if os.path.exists(report_path):
                    os.remove(report_path)
            except Exception as e:
                logger.warning(f"Failed to clean up GitLeaks report file {report_path}: {e}")
            
            return {
                "issues": issues,
                "tool": "gitleaks",
                "duration": result["duration"],
                "secrets_found": len(issues),
                "metadata": {
                    "scanned_commits": False,
                    "scan_type": "filesystem",  # Updated for CLI file scanning
                    "cli_mode": is_cli_scan,
                    "report_path": report_path,
                    "secret_types_found": list(set(i.get("secret_type") for i in issues if i.get("secret_type")))
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to parse GitLeaks output: {str(e)}")
            return {"issues": [], "error": f"Failed to parse GitLeaks output: {str(e)}", "tool": "gitleaks"}
    
    def _classify_gitleaks_secret_type(self, rule_id: str, secret: str) -> str:
        """Classify secret type based on GitLeaks rule ID"""
        rule_lower = rule_id.lower()
        
        # Map common GitLeaks rule IDs to secret types
        rule_mapping = {
            "generic-api-key": "API Key",
            "jwt": "JWT Token", 
            "jwt-token": "JWT Token",
            "github": "GitHub Token",
            "github-pat": "GitHub Token",
            "github-oauth": "GitHub Token",
            "aws": "AWS Credentials",
            "aws-access-token": "AWS Credentials",
            "slack": "Slack Token",
            "google": "Google API Key",
            "stripe": "Stripe API Key",
            "paypal": "PayPal Token",
            "twitter": "Twitter API Key",
            "facebook": "Facebook Token",
            "generic-password": "Password",
            "password": "Password",
            "secret": "Generic Secret",
            "private": "Private Key",
            "rsa": "RSA Private Key",
            "ssh": "SSH Private Key",
            "certificate": "Certificate",
            "postgres": "Database Credentials",
            "mysql": "Database Credentials",
            "mongodb": "Database Credentials"
        }
        
        # Check for specific patterns in rule ID
        for pattern, secret_type in rule_mapping.items():
            if pattern in rule_lower:
                return secret_type
        
        # Analyze secret content for additional classification
        if secret:
            if secret.count(".") == 2:  # JWT format
                return "JWT Token"
            elif secret.startswith("sk_") or secret.startswith("pk_"):
                return "Stripe API Key"
            elif secret.startswith("ghp_"):
                return "GitHub Token"
        
        return "Generic Secret"
    
    async def _execute_gitleaks_command(self, cmd: List[str]) -> Dict[str, Any]:
        """Execute GitLeaks command with proper exit code handling"""
        import asyncio
        from datetime import datetime, timezone
        
        start_time = datetime.now(timezone.utc)
        
        try:
            logger.info(f"Running GitLeaks: {' '.join(cmd[:3])}...")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise Exception(f"GitLeaks timed out after {self.timeout} seconds")
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            stdout_str = stdout.decode('utf-8', errors='ignore')
            stderr_str = stderr.decode('utf-8', errors='ignore')
            
            # GitLeaks specific exit code handling
            # 0 = no leaks found, 1 = leaks found, 2 = no .git directory (normal for CLI)
            if process.returncode not in (0, 1, 2):
                logger.error(f"GitLeaks failed (exit {process.returncode}): {stderr_str}")
                return {"error": stderr_str, "duration": duration, "returncode": process.returncode}
            
            if stderr_str:
                logger.warning(f"GitLeaks warnings: {stderr_str}")
            
            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": process.returncode,
                "duration": duration
            }
            
        except Exception as e:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"GitLeaks execution failed: {str(e)}")
            return {"error": str(e), "duration": duration}

    def _get_gitleaks_severity(self, rule_id: str) -> str:
        """Determine severity based on GitLeaks rule ID"""
        rule_lower = rule_id.lower()
        
        # High severity secrets
        high_severity_patterns = [
            "private", "rsa", "ssh", "certificate", "aws", "github-pat",
            "database", "postgres", "mysql", "mongodb","stripe"
        ]
        
        # Critical severity secrets (high-impact secrets that require immediate attention)
        critical_severity_patterns = [
            "jwt", "password", "credentials", "stripe", "api-key", "token", "secret-key",
            "oauth", "bearer", "session", "auth", "access-key", "client-secret", 
            "generic-api-key", "generic-password", "slack", "google", "paypal", "twitter", 
            "facebook", "discord", "telegram", "mongodb", "postgres", "mysql", "redis",
            "api_key", "access_token", "client_id", "private_key", "encryption_key"
        ]
        
        for pattern in critical_severity_patterns:
            if pattern in rule_lower:
                return "critical"
                
        for pattern in high_severity_patterns:
            if pattern in rule_lower:
                return "high"
        
        return "medium"  # Default severity