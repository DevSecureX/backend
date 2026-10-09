import json
import os
import logging
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
from ..utils.code_context_extractor import CodeContextExtractor

logger = logging.getLogger(__name__)

class TruffleHogRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("trufflehog")
        self.timeout = 300  # 5 minutes for secrets
        self.context_extractor = CodeContextExtractor(context_lines=2)  # Fewer lines for secrets
        
    async def run(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """TruffleHog secret detection with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 180)  # Max 3 minutes for CLI
            logger.info(f"Running TruffleHog in CLI mode with {self.timeout}s timeout")
        
        # IDENTICAL analysis parameters for CLI and main scan - CRITICAL FIX: Remove --only-verified for comprehensive detection
        cmd = [
            'trufflehog',
            'filesystem',
            temp_dir,
            '--json',
            '--no-update',  # Don't check for updates during scan
            # REMOVED --only-verified flag to enable detection of all potential secrets (verified and unverified)
        ]
        
        # Log the command for debugging
        logger.info(f"Running TruffleHog with command: {' '.join(cmd)}")
        logger.info(f"CLI scan mode: {is_cli_scan}")
        
        # Use custom execution that handles TruffleHog's exit codes properly
        result = await self._execute_trufflehog_command(cmd)
        
        # TruffleHog returns exit code 183 when secrets found, which is expected
        if "error" in result:
            # Check if we have stdout with potential findings despite error
            if not result.get("stdout") or not result["stdout"].strip():
                logger.warning(f"TruffleHog error with no output: {result['error']}")
                return {"issues": [], "error": result["error"], "tool": "trufflehog"}
        
        issues = []
        
        # Parse line-by-line JSON output - ENHANCED for comprehensive secret detection
        lines_processed = 0
        for line in result["stdout"].strip().split('\n'):
            if not line.strip():
                continue
                
            lines_processed += 1
            try:
                finding = json.loads(line)
                
                # Enhanced extraction to handle various TruffleHog output formats
                source_metadata = finding.get("SourceMetadata", {})
                data = source_metadata.get("Data", {})
                filesystem_data = data.get("Filesystem", {})
                
                # Extract file path with multiple fallback methods
                file_path = (
                    filesystem_data.get("file") or 
                    finding.get("Source") or 
                    finding.get("File") or
                    ""
                )
                
                if not file_path:
                    logger.warning(f"No file path found in TruffleHog finding: {finding}")
                    continue
                
                line_start = (
                    filesystem_data.get("line") or 
                    finding.get("Line") or
                    finding.get("StartLine") or
                    1
                )
                
                cleaned_file_path = self.clean_file_path(file_path, temp_dir)
                
                # Extract code context for secrets (with fewer surrounding lines)
                code_context = None
                if line_start and cleaned_file_path:
                    try:
                        code_context = self.context_extractor.extract_context(
                            file_path=cleaned_file_path,
                            line_start=line_start,
                            line_end=line_start,  # Secrets are typically single-line
                            temp_dir=temp_dir
                        )
                    except Exception as e:
                        logger.debug(f"Failed to extract context for {cleaned_file_path}:{line_start}: {e}")
                
                # Enhanced detector name extraction
                detector_name = (
                    finding.get("DetectorName") or 
                    finding.get("Type") or
                    finding.get("Detector") or
                    "Unknown"
                )
                
                # Enhanced secret type classification
                secret_type = self._classify_secret_type(detector_name, finding.get("Raw", ""))
                
                issue = {
                    "tool": "trufflehog",
                    "category": "secrets", 
                    "rule_id": f"trufflehog-{detector_name.lower().replace(' ', '-')}",
                    "message": f"Secret detected: {detector_name} in {os.path.basename(cleaned_file_path)}",
                    "severity": self._get_secret_severity(secret_type),
                    "file_path": cleaned_file_path,
                    "line_start": line_start,
                    "line_end": line_start,  # Secrets are single-line
                    "confidence": "high" if finding.get("Verified") else "medium",
                    "secret_type": secret_type,
                    "owasp_category": "A07:2021 – Identification and Authentication Failures",
                    "cwe_id": "CWE-798",  # Use of Hard-coded Credentials
                    "code_context": code_context,
                    "metadata": {
                        "detector_name": detector_name,
                        "detector_type": finding.get("DetectorType"),
                        "decoder_name": finding.get("DecoderName"),
                        "verified": finding.get("Verified", False),
                        "entropy": finding.get("Entropy"),
                        "file_extension": os.path.splitext(cleaned_file_path)[1]
                    }
                }
                
                # Add truncated secret info for debugging (be careful in production!)
                raw_secret = finding.get("Raw", "")
                if raw_secret:
                    if len(raw_secret) > 10:
                        issue["metadata"]["truncated_secret"] = raw_secret[:4] + "..." + raw_secret[-4:]
                    else:
                        issue["metadata"]["truncated_secret"] = "***"
                    
                    # Store partial secret for pattern analysis (first/last few chars only)
                    issue["metadata"]["secret_pattern"] = f"{raw_secret[:3]}...{raw_secret[-3:]}" if len(raw_secret) > 6 else "***"
                
                issues.append(issue)
                logger.debug(f"Found secret: {detector_name} in {cleaned_file_path}:{line_start}")
                
            except json.JSONDecodeError as e:
                logger.debug(f"Invalid JSON line {lines_processed}: {line[:100]}...")
                continue  # Skip invalid JSON lines
            except Exception as e:
                logger.warning(f"Error parsing TruffleHog finding line {lines_processed}: {e}")
                continue
        
        logger.info(f"TruffleHog processed {lines_processed} output lines, found {len(issues)} secrets")
        
        return {
            "issues": issues,
            "tool": "trufflehog", 
            "duration": result["duration"],
            "secrets_found": len(issues),
            "metadata": {
                "verified_secrets": len([i for i in issues if i.get("metadata", {}).get("verified")]),
                "scan_type": "filesystem",  # Explicitly filesystem scanning
                "cli_mode": is_cli_scan,
                "timeout_used": self.timeout,
                "lines_processed": lines_processed,
                "secret_types_found": list(set(i.get("secret_type") for i in issues if i.get("secret_type")))
            }
        }
    
    def _classify_secret_type(self, detector_name: str, raw_secret: str) -> str:
        """Classify the type of secret based on detector name and content"""
        detector_lower = detector_name.lower()
        
        # Map detector names to secret types
        secret_type_mapping = {
            "jwt": "JWT Token",
            "api": "API Key", 
            "apikey": "API Key",
            "generic": "Generic Secret",
            "password": "Password",
            "secret": "Generic Secret",
            "token": "Token",
            "key": "Cryptographic Key",
            "private": "Private Key",
            "aws": "AWS Credentials",
            "github": "GitHub Token",
            "slack": "Slack Token",
            "google": "Google API Key",
            "firebase": "Firebase Key",
            "stripe": "Stripe API Key",
            "paypal": "PayPal Token",
            "twitter": "Twitter API Key",
            "facebook": "Facebook Token"
        }
        
        # Check for specific patterns
        for pattern, secret_type in secret_type_mapping.items():
            if pattern in detector_lower:
                return secret_type
        
        # Analyze raw secret content for additional classification
        if raw_secret:
            raw_lower = raw_secret.lower()
            if "jwt" in raw_lower or raw_secret.count(".") == 2:
                return "JWT Token"
            elif len(raw_secret) == 40 and raw_secret.isalnum():
                return "SHA1 Hash/Token"
            elif len(raw_secret) == 32 and raw_secret.isalnum():
                return "MD5 Hash/Token"
            elif "sk_" in raw_secret or "pk_" in raw_secret:
                return "Stripe API Key"
            elif "ghp_" in raw_secret or "github" in raw_lower:
                return "GitHub Token"
        
        return "Generic Secret"
    
    async def _execute_trufflehog_command(self, cmd: List[str]) -> Dict[str, Any]:
        """Execute TruffleHog command with proper exit code handling"""
        import asyncio
        from datetime import datetime, timezone
        
        start_time = datetime.now(timezone.utc)
        
        try:
            logger.info(f"Executing TruffleHog: {' '.join(cmd[:5])}...")
            
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
                raise Exception(f"TruffleHog timed out after {self.timeout} seconds")
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            stdout_str = stdout.decode('utf-8', errors='ignore')
            stderr_str = stderr.decode('utf-8', errors='ignore')
            
            # TruffleHog specific exit codes:
            # 0 = no secrets found
            # 1 = secrets found (common)
            # 183 = secrets found (with --fail flag)
            # Other codes = actual errors
            if process.returncode not in (0, 1, 183):
                logger.error(f"TruffleHog failed (exit {process.returncode}): {stderr_str}")
                return {"error": stderr_str, "duration": duration, "returncode": process.returncode}
            
            if stderr_str and "WARNING" not in stderr_str:
                logger.warning(f"TruffleHog warnings: {stderr_str}")
            
            logger.info(f"TruffleHog completed with exit code {process.returncode}, found output: {len(stdout_str)} chars")
            
            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": process.returncode,
                "duration": duration
            }
            
        except Exception as e:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"TruffleHog execution failed: {str(e)}")
            return {"error": str(e), "duration": duration}
    
    def _get_secret_severity(self, secret_type: str) -> str:
        """Determine severity based on secret type"""
        high_severity_types = {
            "Private Key", "AWS Credentials", "Database Password", 
            "JWT Token", "GitHub Token", "Stripe API Key"
        }
        
        medium_severity_types = {
            "API Key", "Token", "Firebase Key", "PayPal Token"
        }
        
        if secret_type in high_severity_types:
            return "high"
        elif secret_type in medium_severity_types:
            return "medium"
        else:
            return "medium"  # Default to medium for generic secrets