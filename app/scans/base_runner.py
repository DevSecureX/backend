import asyncio
import subprocess
import json
import logging
import tempfile
import os
import shutil
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class BaseToolRunner(ABC):
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.timeout = 1200  # 20 minutes default
        self.tool_available = None  # Will be set by _check_tool_availability
        
    @abstractmethod
    async def run(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Run the security tool and return normalized results"""
        pass
    
    def _check_tool_availability(self) -> bool:
        """Check if the tool is available and working"""
        if self.tool_available is not None:
            return self.tool_available
        
        try:
            # Define tool commands for version checking
            version_commands = {
                'semgrep': ['semgrep', '--version'],
                'bandit': ['python3', '-m', 'bandit', '--version'],  # FIXED: Use python3 -m bandit
                'trufflehog': ['trufflehog', '--version'],
                'trivy': ['trivy', '--version'],
                'checkov': ['checkov', '--version'],
                'gitleaks': ['gitleaks', 'version'],
                'safety': ['safety', '--help'],  # FIXED: --version is broken, use --help
                'gosec': ['gosec', '--version'],
                'eslint-security': ['eslint', '--version'],
                'spotbugs': ['spotbugs', '-help'],  # FIXED: SpotBugs doesn't have --version, use -help
                # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
                # 'roslynator': ['roslynator', '--version'],
                'psalm': ['psalm', '--version'],
                'brakeman': ['brakeman', '--version'],
                'cppcheck': ['cppcheck', '--version'],
            }
            
            version_cmd = version_commands.get(self.tool_name)
            if not version_cmd:
                # Default check - just see if tool exists
                tool_cmd = self.tool_name.replace('-', '_').split('_')[0]  # Handle compound names
                self.tool_available = shutil.which(tool_cmd) is not None
                return self.tool_available
            
            # Check if tool exists in PATH - enhanced for Alpine container tools
            primary_tool = version_cmd[0]
            tool_path = shutil.which(primary_tool)
            
            if not tool_path:
                # Try alternative paths for containerized tools (Alpine-specific)
                if primary_tool == 'psalm':
                    alt_paths = [
                        '/opt/tools/.config/composer/vendor/bin/psalm',
                        '/root/.config/composer/vendor/bin/psalm', 
                        '/opt/tools/.composer/vendor/bin/psalm',
                        '/root/.composer/vendor/bin/psalm'
                    ]
                    for alt_path in alt_paths:
                        if os.path.exists(alt_path) and os.access(alt_path, os.X_OK):
                            tool_path = alt_path
                            version_cmd[0] = tool_path  # Update command with full path
                            break
                
                elif primary_tool == 'brakeman':
                    # Brakeman installed via Ruby gems
                    alt_paths = [
                        '/opt/tools/bin/brakeman',
                        '/usr/local/bin/brakeman',
                        '/opt/tools/ruby/gems/3.4.0/bin/brakeman'
                    ]
                    for alt_path in alt_paths:
                        if os.path.exists(alt_path) and os.access(alt_path, os.X_OK):
                            tool_path = alt_path
                            version_cmd[0] = tool_path  # Update command with full path
                            break
                
                elif primary_tool == 'spotbugs':
                    # SpotBugs installed in /opt/spotbugs-4.9.3
                    alt_paths = [
                        '/opt/tools/bin/spotbugs',
                        '/usr/local/bin/spotbugs',
                        '/opt/tools/spotbugs-4.9.3/bin/spotbugs',
                        '/opt/spotbugs-4.9.3/bin/spotbugs'
                    ]
                    for alt_path in alt_paths:
                        if os.path.exists(alt_path) and os.access(alt_path, os.X_OK):
                            tool_path = alt_path
                            version_cmd[0] = tool_path  # Update command with full path
                            break
                
                # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
                # elif primary_tool == 'roslynator':
                #     alt_paths = [
                #         '/opt/tools/.dotnet/tools/roslynator',
                #         '/root/.dotnet/tools/roslynator',
                #         '/opt/tools/bin/roslynator'
                #     ]
                #     for alt_path in alt_paths:
                #         if os.path.exists(alt_path) and os.access(alt_path, os.X_OK):
                #             tool_path = alt_path
                #             version_cmd[0] = tool_path  # Update command with full path
                #             break
                
                if not tool_path:
                    self.tool_available = False
                    return False
            
            # Try to run version command to verify it works
            # Increased timeout to 30s to handle slow tools like Checkov
            result = subprocess.run(
                version_cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False
            )
            
            # Special handling for tools that don't return exit code 0 for help/version
            if primary_tool == 'spotbugs':
                # SpotBugs -help returns non-zero but prints help - consider it available if output exists
                if result.stdout and ('spotbugs' in result.stdout.lower() or 'help' in result.stdout.lower()):
                    self.tool_available = True
                    return True
                elif result.stderr and 'java runtime' in result.stderr.lower():
                    # Java is missing, but SpotBugs binary exists
                    logger.warning(f"SpotBugs found but Java runtime missing: {result.stderr.strip()}")
                    # Still consider it available - the runner will handle Java issues
                    self.tool_available = True
                    return True
            elif primary_tool == 'safety':
                # Safety --help may return non-zero but prints help - consider it available if help output exists
                if result.stdout and ('safety' in result.stdout.lower() or 'usage' in result.stdout.lower() or 'help' in result.stdout.lower()):
                    self.tool_available = True
                    return True
            
            # Consider tool available if command succeeds
            self.tool_available = result.returncode == 0
            return self.tool_available
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            self.tool_available = False
            return False
    
    async def run_with_availability_check(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Wrapper that checks tool availability before running"""
        if not self._check_tool_availability():
            logger.warning(f"🔧 {self.tool_name}: Tool not available - skipping scan")
            return {
                "tool": self.tool_name,
                "issues": [],
                "skipped": True,
                "reason": "tool_not_available",
                "duration": 0,
                "metadata": {
                    "message": f"{self.tool_name} is not installed or not working properly",
                    "suggestion": self._get_installation_suggestion()
                }
            }
        
        # Tool is available, run normally
        return await self.run(temp_dir, **kwargs)
    
    def _get_installation_suggestion(self) -> str:
        """Get installation suggestion for the tool"""
        suggestions = {
            'semgrep': 'Install with: pip install semgrep',
            'bandit': 'Install with: pip install bandit',
            'trufflehog': 'Install from: https://github.com/trufflesecurity/trufflehog/releases',
            'trivy': 'Install from: https://aquasecurity.github.io/trivy/latest/getting-started/installation/',
            'checkov': 'Install with: pip install checkov',
            'gitleaks': 'Install from: https://github.com/gitleaks/gitleaks/releases',
            'safety': 'Install with: pip install safety',
            'gosec': 'Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest',
            'eslint-security': 'Install with: npm install -g eslint eslint-plugin-security',
            'spotbugs': 'Download from: https://spotbugs.github.io/',
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # 'roslynator': 'Install with: dotnet tool install -g Roslynator.DotNet.Cli',
            'psalm': 'Install with: composer global require vimeo/psalm',
            'brakeman': 'Install with: gem install brakeman',
            'cppcheck': 'Install with package manager or from: https://cppcheck.sourceforge.io/',
        }
        return suggestions.get(self.tool_name, f'Please install {self.tool_name} manually')
    
    async def execute_command(self, cmd: List[str], cwd: str = None) -> Dict[str, Any]:
        """Execute command with proper error handling and timeout - ENHANCED DEBUG LOGGING"""
        start_time = datetime.now(timezone.utc)
        
        try:
            # ENHANCED: Log full command and environment for debugging
            logger.info(f"🚀 {self.tool_name.upper()}: Starting execution")
            logger.info(f"   Command: {' '.join(cmd)}")
            logger.info(f"   Working directory: {cwd}")
            logger.info(f"   Timeout: {self.timeout} seconds")
            
            # Check if the primary tool exists
            import shutil
            primary_tool = cmd[0] if cmd else None
            if primary_tool and not shutil.which(primary_tool):
                logger.error(f"❌ {self.tool_name}: Tool '{primary_tool}' not found in PATH")
                # Log current PATH for debugging
                import os
                path_dirs = os.environ.get('PATH', '').split(':')
                logger.debug(f"   Current PATH directories: {path_dirs[:5]}...")  # First 5 for brevity
                return {
                    "error": f"Tool '{primary_tool}' not found in PATH",
                    "duration": 0,
                    "returncode": -1
                }
            
            logger.info(f"✅ {self.tool_name}: Tool '{primary_tool}' found in PATH")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            logger.info(f"⚙️  {self.tool_name}: Process started (PID: {process.pid})")
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.timeout
                )
                logger.info(f"⏱️  {self.tool_name}: Process completed in {(datetime.now(timezone.utc) - start_time).total_seconds():.2f}s")
            except asyncio.TimeoutError:
                logger.error(f"⏰ {self.tool_name}: TIMEOUT after {self.timeout} seconds")
                process.kill()
                await process.wait()
                raise Exception(f"{self.tool_name} timed out after {self.timeout} seconds")
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            stdout_str = stdout.decode('utf-8', errors='ignore')
            stderr_str = stderr.decode('utf-8', errors='ignore')
            
            # ENHANCED: Log execution results
            logger.info(f"📊 {self.tool_name}: Execution summary:")
            logger.info(f"   Exit code: {process.returncode}")
            logger.info(f"   Duration: {duration:.2f}s")
            logger.info(f"   Stdout length: {len(stdout_str)} characters")
            logger.info(f"   Stderr length: {len(stderr_str)} characters")
            
            # Log stdout preview if it exists
            if stdout_str:
                preview = stdout_str[:200].replace('\n', '\\n')
                logger.debug(f"   Stdout preview: {preview}...")
            
            # Enhanced exit code handling - many tools return 1 when they find issues
            if process.returncode not in (0, 1, 2):  # 0=no issues, 1=issues found, 2=additional success code
                logger.error(f"❌ {self.tool_name} failed (exit {process.returncode})")
                if stderr_str:
                    logger.error(f"   Error details: {stderr_str[:500]}")
                return {"error": stderr_str, "duration": duration, "returncode": process.returncode}
            
            if stderr_str:
                # Distinguish between warnings and actual errors
                if process.returncode == 0:
                    logger.warning(f"⚠️  {self.tool_name} warnings: {stderr_str[:300]}")
                else:
                    logger.info(f"ℹ️  {self.tool_name} info/debug: {stderr_str[:300]}")
            
            logger.info(f"✅ {self.tool_name}: Execution completed successfully")
            
            return {
                "stdout": stdout_str,
                "stderr": stderr_str,
                "returncode": process.returncode,
                "duration": duration
            }
            
        except Exception as e:
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            logger.error(f"💥 {self.tool_name}: Execution failed with exception")
            logger.error(f"   Exception: {str(e)}")
            logger.error(f"   Duration before failure: {duration:.2f}s")
            return {"error": str(e), "duration": duration}
    
    def normalize_severity(self, severity: str) -> str:
        """Normalize severity across different tools"""
        severity_map = {
            'error': 'critical',  # ERROR should map to CRITICAL (Semgrep critical issues)
            'warning': 'high',    # WARNING should map to HIGH (was incorrectly mapped to medium)
            'info': 'low',
            'note': 'low',
            'critical': 'critical',
            'high': 'high', 
            'medium': 'medium',
            'low': 'low'
        }
        severity_lower = severity.lower().strip()
        
        # Enhanced logging for debugging severity mapping issues
        mapped_severity = severity_map.get(severity_lower, 'medium')
        if severity_lower != mapped_severity:
            logger.debug(f"Severity mapping: '{severity}' -> '{mapped_severity}'")
        
        return mapped_severity
    
    def clean_file_path(self, file_path: str, temp_dir: str) -> str:
        """Clean file path to show relative path from repo root"""
        if not file_path:
            return file_path
        
        if temp_dir in file_path:
            cleaned_path = file_path.replace(temp_dir, "").lstrip("/")
            return cleaned_path if cleaned_path else file_path
        
        return file_path