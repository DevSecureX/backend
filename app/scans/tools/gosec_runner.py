import json
import os
import subprocess
import logging
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner

logger = logging.getLogger(__name__)

class GosecRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("gosec")
        self.timeout = 600  # 10 minutes for Go analysis
        
    async def run(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Gosec Go security analysis with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 240)  # Max 4 minutes for CLI
            logger.info(f"Running Gosec in CLI mode with {self.timeout}s timeout")
        
        # ENHANCED: Check if Go files exist with detailed logging
        go_files_found = []
        try:
            logger.info(f"🔍 Scanning for Go files in: {temp_dir}")
            for root, dirs, files in os.walk(temp_dir):
                # Skip vendor and hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['vendor', 'node_modules']]
                
                for file in files:
                    if file.endswith('.go'):
                        full_path = os.path.join(root, file)
                        go_files_found.append(full_path)
                        logger.debug(f"   Found Go file: {os.path.relpath(full_path, temp_dir)}")
                        
            logger.info(f"📁 Go file discovery complete: found {len(go_files_found)} Go files")
            
            # Log first few files for debugging
            if go_files_found:
                for i, go_file in enumerate(go_files_found[:5]):
                    rel_path = os.path.relpath(go_file, temp_dir)
                    file_size = os.path.getsize(go_file) if os.path.exists(go_file) else 0
                    logger.info(f"   Go file {i+1}: {rel_path} ({file_size} bytes)")
                if len(go_files_found) > 5:
                    logger.info(f"   ... and {len(go_files_found) - 5} more Go files")
                    
        except Exception as e:
            logger.error(f"❌ Error scanning for Go files: {e}")
            return {
                "issues": [], 
                "tool": "gosec", 
                "duration": 0,
                "metadata": {"message": f"Error scanning for Go files: {e}"}
            }
        
        if not go_files_found:
            logger.warning(f"❌ No Go files found in {temp_dir}")
            return {
                "issues": [], 
                "tool": "gosec", 
                "duration": 0,
                "metadata": {"message": "No Go files found to scan"}
            }
        
        # Initialize Go module for Gosec to work properly
        await self._initialize_go_module(temp_dir)
        
        # ENHANCED: Check if gosec is available before running
        import shutil
        gosec_path = shutil.which('gosec')
        if not gosec_path:
            logger.error("❌ Gosec not found in PATH")
            
            # Try alternative installation paths
            alternative_paths = [
                '/usr/local/bin/gosec',
                '/usr/bin/gosec',
                os.path.expanduser('~/go/bin/gosec'),
                '/go/bin/gosec'  # Common in Docker
            ]
            
            for alt_path in alternative_paths:
                if os.path.exists(alt_path) and os.access(alt_path, os.X_OK):
                    logger.info(f"✅ Found Gosec at alternative path: {alt_path}")
                    gosec_path = alt_path
                    break
            
            if not gosec_path:
                return {
                    "issues": [], 
                    "tool": "gosec", 
                    "error": "Gosec not installed or not in PATH. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest",
                    "duration": 0,
                    "metadata": {
                        "go_files_found": len(go_files_found),
                        "suggestion": "Install Gosec: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
                    }
                }
        
        logger.info(f"✅ Gosec binary found at: {gosec_path}")
        
        # Get Gosec version for debugging
        try:
            version_result = subprocess.run([gosec_path, '-version'], capture_output=True, text=True, timeout=10)
            if version_result.returncode == 0:
                logger.info(f"Gosec version: {version_result.stdout.strip()}")
            else:
                logger.debug(f"Could not get Gosec version: {version_result.stderr}")
        except Exception as ve:
            logger.debug(f"Version check failed: {ve}")
        
        # ENHANCED analysis parameters for maximum detection accuracy
        cmd = [
            gosec_path,
            '-fmt=json',
            '-quiet',
            '-nosec=false',         # ENHANCED: Don't skip nosec comments for all scans
            '-tests',               # ENHANCED: Include test files for all scans
            '-severity=low',        # ENHANCED: Include all severity levels for comprehensive scanning
            '-confidence=low',      # ENHANCED: Include all confidence levels for comprehensive scanning
            '-enable-audit',        # ENHANCED: Enable audit mode for more thorough analysis
            '-show-ignored',        # ENHANCED: Show ignored issues for debugging
            '-concurrency=8'        # ENHANCED: Use all available CPU cores for faster scanning
        ]
        
        # Scan current directory - more explicit
        cmd.append('./...')  # More explicit Go path pattern
        
        logger.info(f"🔧 Executing Gosec command: {' '.join(cmd)}")
        logger.info(f"🔧 Working directory: {temp_dir}")
        logger.info(f"🔧 Go files count: {len(go_files_found)}")
        
        result = await self.execute_command(cmd, cwd=temp_dir)
        
        logger.info(f"🔧 Gosec execution complete:")
        logger.info(f"   Return code: {result.get('returncode', 'unknown')}")
        logger.info(f"   Duration: {result.get('duration', 0):.2f}s")
        logger.info(f"   Stdout length: {len(result.get('stdout', ''))}")
        logger.info(f"   Stderr length: {len(result.get('stderr', ''))}")
        
        if result.get('stdout'):
            logger.debug(f"Gosec stdout preview: {result['stdout'][:500]}")
        if result.get('stderr'):
            logger.warning(f"Gosec stderr: {result['stderr'][:500]}")
        
        # Handle cases where Gosec fails or returns no JSON - ENHANCED ERROR HANDLING
        if "error" in result:
            error_msg = result.get("error", "").lower()
            stderr_msg = result.get("stderr", "").lower()
            combined_error = f"{error_msg} {stderr_msg}"
            
            # Check if it's a Go module issue (common in CLI scans)
            go_module_errors = [
                "no go files", "no buildable go", "cannot find module", 
                "go.mod file not found", "no required module", "build constraints exclude all go files",
                "no go files to analyze", "directory does not contain a go module"
            ]
            
            if any(phrase in combined_error for phrase in go_module_errors):
                logger.info(f"Gosec: No buildable Go files found (detected {len(go_files_found)} .go files)")
                logger.info(f"This is usually caused by: standalone Go files without proper module structure")
                
                return {
                    "issues": [], 
                    "tool": "gosec", 
                    "duration": result.get("duration", 0),
                    "metadata": {
                        "message": "No buildable Go files found - files may be standalone or missing go.mod", 
                        "go_files_detected": len(go_files_found),
                        "cli_mode": is_cli_scan,
                        "error_category": "go_module_structure",
                        "suggestion": "Ensure Go files are part of a valid Go module with go.mod"
                    }
                }
            
            # Check for Gosec-specific errors
            gosec_specific_errors = [
                "failed to load", "analysis error", "ast parse error", 
                "type checking error", "import error"
            ]
            
            if any(phrase in combined_error for phrase in gosec_specific_errors):
                logger.warning(f"Gosec analysis errors detected: {combined_error[:300]}")
                
                # Still try to parse any partial output
                if go_files_found and result.get("stdout"):
                    logger.info("Attempting to parse partial Gosec results despite errors")
                    # Continue to parsing section
                else:
                    return {
                        "issues": [], 
                        "tool": "gosec", 
                        "duration": result.get("duration", 0),
                        "metadata": {
                            "message": "Gosec analysis failed with parsing errors",
                            "go_files_detected": len(go_files_found),
                            "error_category": "analysis_error",
                            "error_details": combined_error[:500]
                        }
                    }
            
            # For other errors, still try to continue if we found Go files - might be non-fatal
            if go_files_found:
                logger.warning(f"Gosec had errors but {len(go_files_found)} Go files exist, continuing with partial results")
                logger.warning(f"Error details: {combined_error[:300]}")
                # Don't return error immediately, try to parse output anyway
            else:
                return {
                    "issues": [], 
                    "error": result["error"], 
                    "tool": "gosec",
                    "metadata": {
                        "error_category": "general_error",
                        "error_details": combined_error[:500]
                    }
                }
        
        # Handle empty or invalid output
        stdout = result.get("stdout", "").strip()
        if not stdout:
            return {
                "issues": [], 
                "tool": "gosec", 
                "duration": result.get("duration", 0),
                "metadata": {"message": "Gosec produced no output"}
            }
        
        try:
            # Try to parse JSON output
            output = json.loads(stdout)
            
            # Handle different Gosec output formats
            if isinstance(output, dict):
                issues_data = output.get("Issues", [])
            elif isinstance(output, list):
                issues_data = output
            else:
                logger.warning(f"Unexpected Gosec output format: {type(output)}")
                return {
                    "issues": [], 
                    "tool": "gosec", 
                    "duration": result.get("duration", 0),
                    "metadata": {"message": "Unexpected output format from Gosec"}
                }
            
            issues = []
            
            # ENHANCED DEBUG: Log raw issue processing
            logger.info(f"Processing {len(issues_data)} Gosec findings")
            
            for i, issue in enumerate(issues_data):
                if not isinstance(issue, dict):
                    logger.warning(f"Gosec issue {i} is not a dict: {type(issue)}")
                    continue
                
                # Enhanced logging for debugging
                rule_id = issue.get("rule_id") or issue.get("ruleID") or "G999"
                severity = self.normalize_severity(issue.get("severity", "MEDIUM"))
                file_path = self.clean_file_path(issue.get("file"), temp_dir)
                
                logger.info(f"Gosec issue {i+1}: Rule {rule_id}, Severity {severity}, File {file_path}")
                    
                normalized_issue = {
                    "tool": "gosec",
                    "category": "code",
                    "rule_id": rule_id,
                    "message": issue.get("details") or issue.get("what") or "Go security issue detected",
                    "severity": severity,
                    "file_path": file_path,
                    "line_start": int(issue.get("line", 0)),
                    "line_end": int(issue.get("line", 0)),
                    "confidence": self.normalize_severity(issue.get("confidence", "MEDIUM")),
                    "code_snippet": issue.get("code"),
                    "owasp_category": self._map_gosec_to_owasp(rule_id),
                    "cwe_id": issue.get("cwe", {}).get("ID") if issue.get("cwe") else None
                }
                issues.append(normalized_issue)
            
            logger.info(f"Gosec successfully processed {len(issues)} issues")
            
            return {
                "issues": issues,
                "tool": "gosec",
                "duration": result["duration"],
                "files_scanned": len(set(issue.get("file") for issue in issues_data)) if issues_data else 0,
                "metadata": {
                    "cli_mode": is_cli_scan,
                    "timeout_used": self.timeout,
                    "issues_found": len(issues)
                }
            }
            
        except json.JSONDecodeError as e:
            # If JSON parsing fails, try to extract useful info from raw output
            logger.warning(f"Gosec JSON parse error: {e}, raw output length: {len(stdout)}")
            
            # Log first 500 chars for debugging
            logger.debug(f"Gosec raw output preview: {stdout[:500]}")
            
            # Try to find Go files and return a partial result
            go_file_count = 0
            try:
                # os is already imported at the top of the file
                for root, dirs, files in os.walk(temp_dir):
                    go_file_count += len([f for f in files if f.endswith('.go')])
            except Exception as walk_error:
                logger.warning(f"Error counting Go files: {walk_error}")
                pass
            
            if go_file_count > 0:
                return {
                    "issues": [], 
                    "tool": "gosec", 
                    "duration": result.get("duration", 0),
                    "metadata": {
                        "message": f"Found {go_file_count} Go files but Gosec output parsing failed",
                        "parse_error": str(e),
                        "cli_mode": is_cli_scan
                    }
                }
            else:
                return {
                    "issues": [], 
                    "tool": "gosec", 
                    "duration": result.get("duration", 0),
                    "metadata": {"message": "No Go files found to scan"}
                }
    
    def _map_gosec_to_owasp(self, rule_id: str) -> str:
        """Map Gosec rule to OWASP category - ENHANCED with complete rule coverage"""
        owasp_mappings = {
            # Authentication and Credential Issues
            "G101": "A07:2021 – Identification and Authentication Failures",  # Hardcoded credentials
            "G106": "A07:2021 – Identification and Authentication Failures",  # SSH usage audit
            "G407": "A02:2021 – Cryptographic Failures",  # Hardcoded IV/nonce
            
            # Injection Vulnerabilities
            "G102": "A03:2021 – Injection",  # Bind to all interfaces
            "G107": "A03:2021 – Injection",  # URL provided to HTTP request
            "G201": "A03:2021 – Injection",  # SQL string formatting
            "G202": "A03:2021 – Injection",  # SQL string concatenation
            "G203": "A03:2021 – Injection",  # Use of unescaped data in HTML
            "G204": "A03:2021 – Injection",  # Command execution
            "G601": "A03:2021 – Injection",  # Implicit memory aliasing
            
            # Cryptographic Failures
            "G401": "A02:2021 – Cryptographic Failures",  # MD5/SHA1 usage
            "G402": "A02:2021 – Cryptographic Failures",  # TLS InsecureSkipVerify
            "G403": "A02:2021 – Cryptographic Failures",  # RSA key < 2048
            "G404": "A02:2021 – Cryptographic Failures",  # Weak random
            "G405": "A02:2021 – Cryptographic Failures",  # DES/RC4 usage
            "G406": "A02:2021 – Cryptographic Failures",  # MD4/RIPEMD160 usage
            "G501": "A02:2021 – Cryptographic Failures",  # Blacklisted import MD5
            "G502": "A02:2021 – Cryptographic Failures",  # Blacklisted import DES
            "G503": "A02:2021 – Cryptographic Failures",  # Blacklisted import RC4
            "G504": "A02:2021 – Cryptographic Failures",  # Blacklisted import CGI
            "G505": "A02:2021 – Cryptographic Failures",  # Blacklisted import SHA1
            "G506": "A02:2021 – Cryptographic Failures",  # Blacklisted import MD4
            "G507": "A02:2021 – Cryptographic Failures",  # Blacklisted import RIPEMD160
            
            # Access Control Issues
            "G301": "A01:2021 – Broken Access Control",  # Poor file permissions (dir)
            "G302": "A01:2021 – Broken Access Control",  # Poor file permissions (file/chmod)
            "G303": "A01:2021 – Broken Access Control",  # Predictable tempfile creation
            "G304": "A01:2021 – Broken Access Control",  # File path provided as taint
            "G305": "A01:2021 – Broken Access Control",  # File traversal (zip)
            "G306": "A01:2021 – Broken Access Control",  # Poor file permissions (write)
            "G307": "A01:2021 – Broken Access Control",  # Poor file permissions (os.Create)
            
            # Insecure Design
            "G103": "A04:2021 – Insecure Design",  # Unsafe block usage
            "G109": "A04:2021 – Insecure Design",  # Integer conversion overflow
            "G110": "A04:2021 – Insecure Design",  # Decompression bomb (io.Copy)
            "G111": "A04:2021 – Insecure Design",  # HTTP directory exposure
            "G115": "A04:2021 – Insecure Design",  # Type conversion integer overflow
            "G602": "A04:2021 – Insecure Design",  # Slice bounds out of range
            
            # Security Misconfiguration
            "G108": "A05:2021 – Security Misconfiguration",  # Profiling endpoint exposed
            "G112": "A05:2021 – Security Misconfiguration",  # ReadHeaderTimeout not configured
            "G114": "A05:2021 – Security Misconfiguration",  # HTTP serve without timeouts
            
            # Vulnerable Components
            "G104": "A06:2021 – Vulnerable and Outdated Components",  # Errors unhandled
        }
        
        return owasp_mappings.get(rule_id, "A06:2021 – Vulnerable and Outdated Components")
    
    async def _initialize_go_module(self, temp_dir: str):
        """Initialize Go module if needed for Gosec to work properly - ENHANCED for standalone files"""
        try:
            logger.info("🔧 Initializing Go module for Gosec scanning...")
            
            # Check if go.mod already exists
            go_mod_path = os.path.join(temp_dir, 'go.mod')
            if os.path.exists(go_mod_path):
                logger.info("✅ go.mod already exists, verifying content...")
                try:
                    with open(go_mod_path, 'r') as f:
                        content = f.read()
                        logger.info(f"   go.mod content preview: {content[:100]}...")
                except:
                    pass
                return
            
            # Check if we need to create a go.mod
            go_files_found = []
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith('.go'):
                        go_files_found.append(os.path.join(root, file))
            
            if not go_files_found:
                logger.warning("❌ No Go files found during module initialization")
                return
            
            # Create minimal go.mod for standalone Go files
            logger.info(f"🔧 Creating minimal go.mod for {len(go_files_found)} Go files")
            go_mod_content = """module temp-scan

go 1.21
"""
            with open(go_mod_path, 'w') as f:
                f.write(go_mod_content)
            
            logger.info("✅ Created go.mod file")
            
            # Check if 'go' command is available
            import shutil
            if not shutil.which('go'):
                logger.warning("⚠️  Go command not found, skipping go mod tidy")
                return
            
            # Try to run go mod tidy, but don't fail if it doesn't work
            try:
                logger.info("🔧 Running go mod tidy...")
                tidy_result = await self.execute_command(['go', 'mod', 'tidy'], cwd=temp_dir)
                if "error" in tidy_result:
                    logger.warning(f"⚠️  Go mod tidy had issues (non-fatal): {tidy_result['error']}")
                else:
                    logger.info("✅ Go mod tidy completed successfully")
                    
                    # Verify the final go.mod
                    if os.path.exists(go_mod_path):
                        try:
                            with open(go_mod_path, 'r') as f:
                                final_content = f.read()
                                logger.info(f"📄 Final go.mod: {final_content[:200]}")
                        except:
                            pass
                    
            except Exception as tidy_e:
                logger.warning(f"⚠️  Go mod tidy failed (non-fatal): {tidy_e}")
            
        except Exception as e:
            logger.warning(f"❌ Failed to initialize Go module: {e}")
            # Continue without Go module, Gosec can sometimes work without it