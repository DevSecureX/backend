import json
import os
import shutil
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
import logging

logger = logging.getLogger(__name__)

class PsalmRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("psalm")
        self.timeout = 600  # 10 minutes for PHP analysis

    async def run(self, temp_dir: str, file_list: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Psalm PHP security analysis with full CLI-main scan parity and taint analysis"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 180)  # Max 3 minutes for CLI
            logger.info(f"Running Psalm in CLI mode with {self.timeout}s timeout")
        
        # ENHANCED: Check if Psalm is available with detailed logging
        logger.info("🔍 Psalm: Checking tool availability...")
        psalm_path = shutil.which('psalm')
        if not psalm_path:
            # Try alternative composer paths (Alpine uses .config/composer) and PHAR locations
            alt_paths = [
                '/opt/tools/.config/composer/vendor/bin/psalm',  # Alpine in container
                '/root/.config/composer/vendor/bin/psalm',       # Alpine native
                '/opt/tools/.composer/vendor/bin/psalm',         # Legacy in container
                '/root/.composer/vendor/bin/psalm',              # Legacy native
                '/opt/tools/bin/psalm.phar',                     # Downloaded PHAR
                '/opt/tools/bin/psalm'                           # Symlink to PHAR
            ]
            for alt_path in alt_paths:
                if os.path.exists(alt_path):
                    psalm_path = alt_path
                    break
        
        if not psalm_path:
            logger.warning("❌ Psalm not found in PATH or standard composer locations")
            return {
                "issues": [], 
                "tool": "psalm", 
                "duration": 0, 
                "metadata": {"message": "Psalm not installed, skipping PHP security scan"}
            }
        logger.info(f"✅ Psalm tool found at: {psalm_path}")
        
        # ENHANCED: Check for PHP files with detailed logging
        php_files_found = []
        logger.info("🔍 Psalm: Scanning for PHP files...")
        
        if file_list:
            php_files_found = [f for f in file_list if f.endswith('.php')]
            logger.info(f"   File list provided: {len(file_list)} total files")
            logger.info(f"   PHP files in list: {len(php_files_found)}")
            if not php_files_found:
                return {"issues": [], "tool": "psalm", "duration": 0, "metadata": {"message": "No PHP files to scan"}}
        else:
            # Check if directory has PHP files
            logger.info(f"   Scanning directory: {temp_dir}")
            for root, dirs, files in os.walk(temp_dir):
                # Skip vendor and hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['vendor', 'node_modules']]
                
                for file in files:
                    if file.endswith('.php'):
                        full_path = os.path.join(root, file)
                        php_files_found.append(full_path)
                        logger.debug(f"   Found PHP file: {os.path.relpath(full_path, temp_dir)}")
            
            logger.info(f"📊 Psalm: Found {len(php_files_found)} PHP files")
            
            # Log first few files for debugging
            if php_files_found:
                for i, php_file in enumerate(php_files_found[:5]):
                    rel_path = os.path.relpath(php_file, temp_dir)
                    file_size = os.path.getsize(php_file) if os.path.exists(php_file) else 0
                    logger.info(f"   PHP file {i+1}: {rel_path} ({file_size} bytes)")
                if len(php_files_found) > 5:
                    logger.info(f"   ... and {len(php_files_found) - 5} more PHP files")
            
            if not php_files_found:
                logger.warning("❌ No PHP files found in directory")
                return {"issues": [], "tool": "psalm", "duration": 0, "metadata": {"message": "No PHP files found"}}

        # Ensure psalm.xml exists - enhanced config with taint analysis for security focus
        psalm_config_path = os.path.join(temp_dir, 'psalm.xml')
        if not os.path.exists(psalm_config_path):
            psalm_config = """<?xml version="1.0"?>
<psalm
    errorLevel="3"
    resolveFromConfigFile="false"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="https://getpsalm.org/schema/config"
    findUnusedCode="false"
    findUnusedVariablesAndParams="false"
    allowPhpStormGenerics="true"
    usePhpDocMethodsWithoutMagicCall="false"
    disableVarParsing="false"
    requireVendorAutoload="false"
    autoloaderPath=""
    checkForThrowsDocblock="false"
    checkForThrowsInGlobalScope="false"
    ignoreInternalFunctionFalseReturn="true"
    ignoreInternalFunctionNullReturn="true"
    skipChecksOnUnresolvableIncludes="true"
>
    <projectFiles>
        <directory name="." />
    </projectFiles>
    
    <fileExtensions>
        <extension name=".php" />
    </fileExtensions>
    
    <!-- Enhanced taint analysis configuration for security vulnerabilities -->
    <taintAnalysis>
        <ignoreFiles>
            <directory name="vendor"/>
            <directory name="tests"/>
        </ignoreFiles>
    </taintAnalysis>
    
    <issueHandlers>
        <!-- Security-focused taint analysis issues - ALL SET TO ERROR for maximum detection -->
        <TaintedInput errorLevel="error" />
        <TaintedSql errorLevel="error" />
        <TaintedHtml errorLevel="error" />
        <TaintedEval errorLevel="error" />
        <TaintedInclude errorLevel="error" />
        <TaintedCallable errorLevel="error" />
        <TaintedShell errorLevel="error" />
        <TaintedLdap errorLevel="error" />
        <TaintedFile errorLevel="error" />
        <TaintedHeader errorLevel="error" />
        <TaintedSSRF errorLevel="error" />
        <TaintedSystemSecret errorLevel="error" />
        <TaintedUserSecret errorLevel="error" />
        
        <!-- Other security-related issues -->
        <PossiblyNullArgument errorLevel="error" />
        <NullArgument errorLevel="error" />
        <InvalidArgument errorLevel="error" />
        <UnsafeGenericInstantiation errorLevel="error" />
        <ForbiddenCode errorLevel="error" />
        <InvalidScalarArgument errorLevel="error" />
        <InvalidOperand errorLevel="error" />
        
        <!-- Allow basic type issues to be detected -->
        <ArgumentTypeCoercion errorLevel="info" />
        <InvalidStringClass errorLevel="info" />
        
        <!-- Suppress most non-security issues to focus on vulnerabilities -->
        <MissingReturnType errorLevel="suppress" />
        <MissingPropertyType errorLevel="suppress" />
        <MissingParamType errorLevel="suppress" />
        <MixedArgument errorLevel="suppress" />
        <MixedAssignment errorLevel="suppress" />
        <MixedReturnStatement errorLevel="suppress" />
        <UnresolvableInclude errorLevel="suppress" />
        <MissingFile errorLevel="suppress" />
        <UndefinedClass errorLevel="suppress" />
        <UndefinedFunction errorLevel="suppress" />
        <UndefinedMethod errorLevel="suppress" />
        <UndefinedConstant errorLevel="suppress" />
        <UndefinedVariable errorLevel="suppress" />
    </issueHandlers>
</psalm>"""
            with open(psalm_config_path, 'w') as f:
                f.write(psalm_config)

        # Build enhanced command with taint analysis re-enabled (mbstring is now available)
        cmd = [
            'php83', '-d', 'opcache.enable=0',  # Disable problematic opcache extension
            '-d', 'memory_limit=512M',          # Increase memory limit
            psalm_path,
            '--output-format=json',
            '--report-show-info=false',
            '--taint-analysis',                 # RE-ENABLED with mbstring extension available
            '--config=' + psalm_config_path,
            '--show-snippet=false',            # Reduce output noise
            '--no-cache',                      # Disable cache for accurate scanning
            '--memory-limit=512M',             # Increase memory for complex analysis
            temp_dir
        ]
        
        logger.info(f"🔧 Psalm: Enhanced security scanning with taint analysis: {' '.join(cmd[:8])}...")

        # Filter for PHP files if file_list provided
        if file_list:
            php_files = [f for f in file_list if f.endswith('.php')]
            if not php_files:
                return {"issues": [], "tool": "psalm", "duration": 0, "metadata": {"message": "No PHP files to scan"}}

        result = await self.execute_command(cmd, cwd=temp_dir)

        if "error" in result:
            logger.error(f"Psalm execution error: {result['error']}")
            return {"issues": [], "error": result["error"], "tool": "psalm"}

        try:
            # Debug output for troubleshooting
            logger.debug(f"Psalm stdout: {result['stdout'][:500]}..." if result.get('stdout') else "No stdout")
            logger.debug(f"Psalm stderr: {result['stderr'][:500]}..." if result.get('stderr') else "No stderr")
            
            # Handle empty or non-JSON output
            if not result.get("stdout") or result["stdout"].strip() == "":
                logger.warning("Psalm returned empty output - no issues found or analysis failed")
                return {"issues": [], "tool": "psalm", "duration": result["duration"], "metadata": {"message": "No output from Psalm analysis"}}
            
            output = json.loads(result["stdout"]) if result["stdout"] else []
            issues = []
            
            logger.info(f"📊 Psalm: Found {len(output)} potential security issues")

            for issue in output:
                # Handle both old and new Psalm JSON formats
                issue_type = issue.get("type") or issue.get("issue_type", "UnknownIssue")
                file_name = issue.get("file_name") or issue.get("file_path")
                
                issue_data = {
                    "tool": "psalm",
                    "category": "code",
                    "rule_id": issue_type,
                    "message": issue.get("message", "PHP security issue"),
                    "severity": self.normalize_severity(issue.get("severity", "error")),
                    "file_path": self.clean_file_path(file_name, temp_dir),
                    "line_start": issue.get("line_from") or issue.get("line", 0),
                    "line_end": issue.get("line_to") or issue.get("line", 0),
                    "confidence": "high",
                    "owasp_category": self._map_to_owasp(issue_type),
                    "cwe_id": self._map_to_cwe(issue_type)
                }
                issues.append(issue_data)
                logger.info(f"   Security Issue: {issue_type} in {os.path.basename(file_name or 'unknown')} - {issue.get('message', 'No message')[:80]}")

            return {
                "issues": issues,
                "tool": "psalm",
                "duration": result["duration"],
                "files_scanned": len(set(issue.get("file_path") for issue in issues)),
                "metadata": {
                    "taint_analysis_enabled": True,
                    "mbstring_available": True,
                    "security_focused": True
                }
            }

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Psalm output: {e}")
            logger.error(f"Raw output: {result.get('stdout', 'No stdout')[:1000]}")
            logger.error(f"Error output: {result.get('stderr', 'No stderr')[:1000]}")
            return {"issues": [], "error": f"Invalid JSON output: {str(e)}", "tool": "psalm"}

    def _map_to_owasp(self, type_id: str) -> str:
        """Map Psalm issue type to OWASP category"""
        owasp_mappings = {
            "TaintedInput": "A03:2021 – Injection",
            "TaintedSql": "A03:2021 – Injection", 
            "TaintedHtml": "A03:2021 – Injection",
            "TaintedEval": "A03:2021 – Injection",
            "TaintedInclude": "A03:2021 – Injection",
            "TaintedCallable": "A03:2021 – Injection",
            "TaintedShell": "A03:2021 – Injection",
            "TaintedLdap": "A03:2021 – Injection",
            "TaintedFile": "A01:2021 – Broken Access Control",
            "TaintedHeader": "A03:2021 – Injection",
            "TaintedSSRF": "A10:2021 – Server-Side Request Forgery (SSRF)",
            "TaintedSystemSecret": "A02:2021 – Cryptographic Failures",
            "TaintedUserSecret": "A02:2021 – Cryptographic Failures",
            "Security": "A06:2021 – Vulnerable and Outdated Components"
        }
        type_lower = type_id.lower()
        for key, category in owasp_mappings.items():
            if key.lower() in type_lower:
                return category
        return "A06:2021 – Vulnerable and Outdated Components"

    def _map_to_cwe(self, type_id: str) -> str:
        """Map Psalm issue type to CWE"""
        cwe_mappings = {
            "TaintedInput": "CWE-20",  # Improper Input Validation
            "TaintedSql": "CWE-89",   # SQL Injection
            "TaintedHtml": "CWE-79",  # Cross-site Scripting
            "TaintedEval": "CWE-94",  # Code Injection
            "TaintedInclude": "CWE-98", # Remote File Inclusion
            "TaintedCallable": "CWE-94", # Code Injection
            "TaintedShell": "CWE-78", # OS Command Injection
            "TaintedLdap": "CWE-90",  # LDAP Injection
            "TaintedFile": "CWE-22",  # Path Traversal
            "TaintedHeader": "CWE-113", # HTTP Response Splitting
            "TaintedSSRF": "CWE-918", # Server-Side Request Forgery
            "TaintedSystemSecret": "CWE-798", # Hard-coded Credentials
            "TaintedUserSecret": "CWE-200", # Information Exposure
            "Security": "CWE-200" # Generic security issue
        }
        type_lower = type_id.lower()
        for key in cwe_mappings:
            if key.lower() in type_lower:
                return cwe_mappings[key]
        return "CWE-200"