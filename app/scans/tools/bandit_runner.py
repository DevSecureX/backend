import json
import os
import logging
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
from ..utils.code_context_extractor import CodeContextExtractor

logger = logging.getLogger(__name__)

class BanditRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("bandit")
        self.timeout = 600  # 10 minutes for comprehensive analysis
        self.context_extractor = CodeContextExtractor(context_lines=5)  # More context for better analysis
        
    async def run(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Bandit Python security analysis with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 180)  # Max 3 minutes for CLI (increased from 2)
            logger.info(f"Running Bandit in CLI mode with {self.timeout}s timeout")
        else:
            # Full scan mode gets more time for comprehensive analysis
            self.timeout = min(self.timeout, timeout) if timeout else self.timeout
            logger.info(f"Running Bandit in full scan mode with {self.timeout}s timeout")
        
        # Check if we should scan specific files (for PR scans)
        target_files = kwargs.get('target_files', [])
        
        # ENHANCED analysis parameters for maximum detection accuracy
        cmd = [
            'python3', '-m', 'bandit',
            '-f', 'json',
            '--skip', 'B101',  # Skip only assert usage warnings, keep all other checks
            '--severity-level', 'all',  # Include all severity levels  
            '--confidence-level', 'all',  # Include all confidence levels
            '--number', '5',  # Increased context lines for better analysis
            '--ignore-nosec',  # Ignore # nosec comments for comprehensive scanning
            '--verbose'  # Verbose mode for better debugging and coverage analysis
        ]
        
        # Enhanced custom rules integration for maximum detection
        custom_rule_files = kwargs.get('custom_rule_files', [])
        bandit_profile = kwargs.get('bandit_profile', None)
        baseline_file = kwargs.get('baseline_file', None)
        
        # Apply security profile if specified (for focused scanning)
        if bandit_profile:
            cmd.extend(['--profile', bandit_profile])
            logger.info(f"Using Bandit profile: {bandit_profile}")
        
        # Use baseline for progressive improvement tracking
        if baseline_file and os.path.exists(baseline_file):
            cmd.extend(['--baseline', baseline_file])
            logger.info(f"Using Bandit baseline: {baseline_file}")
        
        # Use enhanced security profile by default if no custom config provided
        default_config = os.path.join(os.path.dirname(__file__), 'bandit_security_profile.yaml')
        config_used = False
        
        if custom_rule_files:
            # Bandit can use custom config files for rule customization
            for rule_file in custom_rule_files:
                if rule_file.endswith(('.yaml', '.yml', '.ini')) and 'bandit' in rule_file.lower():
                    if os.path.exists(rule_file):
                        cmd.extend(['--configfile', rule_file])
                        logger.info(f"Added custom Bandit config: {rule_file}")
                        config_used = True
                        break  # Only use first Bandit config file
        
        # Use default enhanced profile if no custom config and file exists
        if not config_used and os.path.exists(default_config):
            cmd.extend(['--configfile', default_config])
            logger.info(f"Using enhanced security profile: {default_config}")
        
        # If target_files is provided, scan only Python files from the list
        if target_files:
            # Filter for Python files only
            python_files = [f for f in target_files if f.endswith('.py')]
            
            if python_files:
                logger.info(f"Bandit scanning {len(python_files)} Python target files for PR")
                # Convert to absolute paths (handle both absolute and relative paths)
                absolute_files = []
                for file_path in python_files:
                    # If path is already absolute, use it as-is
                    if os.path.isabs(file_path):
                        abs_path = file_path
                    else:
                        # If relative, join with temp_dir
                        abs_path = os.path.join(temp_dir, file_path)
                    
                    if os.path.exists(abs_path):
                        absolute_files.append(abs_path)
                        logger.debug(f"Added Python file for Bandit scan: {abs_path}")
                    else:
                        logger.warning(f"Python file not found, skipping: {abs_path}")
                
                logger.info(f"Bandit will scan {len(absolute_files)} existing Python files")
                
                if absolute_files:
                    cmd.extend(absolute_files)
                else:
                    # No Python files found, return empty result
                    return {"issues": [], "tool": "bandit", "skipped": "No Python files in target files"}
            else:
                # No Python files to scan
                return {"issues": [], "tool": "bandit", "skipped": "No Python files in target files"}
        else:
            # Scan entire directory recursively
            cmd.extend(['-r', temp_dir])
        
        result = await self.execute_command(cmd)
        
        if "error" in result:
            return {"issues": [], "error": result["error"], "tool": "bandit"}
        
        try:
            output = json.loads(result["stdout"])
            issues = []
            
            for finding in output.get("results", []):
                line_start = finding.get("line_number")
                file_path = self.clean_file_path(finding.get("filename"), temp_dir)
                
                # Extract enhanced code context with surrounding lines
                code_context = None
                if line_start and file_path:
                    # Enhanced context extraction for better vulnerability analysis
                    line_end = finding.get("line_range", [line_start])[-1] if finding.get("line_range") else line_start
                    code_context = self.context_extractor.extract_context(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        temp_dir=temp_dir
                    )
                
                # Get original severity from Bandit for debugging
                original_severity = finding.get("issue_severity", "medium") 
                normalized_severity = self.normalize_severity(original_severity)
                
                # Debug logging for severity mapping verification
                if original_severity.lower() in ['high', 'medium', 'low']:
                    logger.debug(f"Bandit severity mapping: '{original_severity}' -> '{normalized_severity}' for rule {finding.get('test_id')}")

                # Enhanced issue reporting with additional metadata
                test_id = finding.get("test_id", "")
                issue = {
                    "tool": "bandit",
                    "category": "code",
                    "rule_id": test_id,
                    "test_name": finding.get("test_name", ""),
                    "message": finding.get("issue_text", "Python security issue"),
                    "severity": normalized_severity,
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": finding.get("line_range", [line_start])[-1] if finding.get("line_range") else line_start,
                    "confidence": self.normalize_severity(finding.get("issue_confidence", "medium")),
                    "owasp_category": self._map_bandit_to_owasp(test_id),
                    "cwe_id": self._map_bandit_to_cwe(test_id),
                    "code_context": code_context,
                    "more_info": finding.get("more_info", ""),
                    "cwe_link": finding.get("issue_cwe", {}).get("link", ""),
                    "col_offset": finding.get("col_offset", 0),
                    "end_col_offset": finding.get("end_col_offset", 0)
                }
                issues.append(issue)
            
            return {
                "issues": issues,
                "tool": "bandit",
                "duration": result["duration"],
                "files_scanned": len(output.get("results", [])),
                "metadata": {
                    **output.get("metrics", {}),
                    "cli_mode": is_cli_scan,
                    "timeout_used": self.timeout
                }
            }
            
        except json.JSONDecodeError as e:
            return {"issues": [], "error": f"Invalid JSON output: {str(e)}", "tool": "bandit"}
    
    def _map_bandit_to_owasp(self, test_id: str) -> str:
        """Map Bandit test ID to OWASP category - ENHANCED with comprehensive mappings"""
        owasp_mappings = {
            # Code Execution and Injection Vulnerabilities
            "B102": "A03:2021 – Injection",  # exec_used
            "B103": "A05:2021 – Security Misconfiguration",  # set_bad_file_permissions
            "B104": "A05:2021 – Security Misconfiguration",  # hardcoded_bind_all_interfaces
            "B105": "A07:2021 – Identification and Authentication Failures",  # hardcoded_password_string
            "B106": "A07:2021 – Identification and Authentication Failures",  # hardcoded_password_funcarg
            "B107": "A07:2021 – Identification and Authentication Failures",  # hardcoded_password_default
            "B108": "A05:2021 – Security Misconfiguration",  # hardcoded_tmp_directory
            "B110": "A09:2021 – Security Logging and Monitoring Failures",  # try_except_pass
            "B112": "A09:2021 – Security Logging and Monitoring Failures",  # try_except_continue
            "B113": "A05:2021 – Security Misconfiguration",  # request_without_timeout
            
            # Flask and Web Framework Issues
            "B201": "A05:2021 – Security Misconfiguration",  # flask_debug_true
            "B202": "A01:2021 – Broken Access Control",  # tarfile_unsafe_members
            
            # Serialization and Cryptographic Issues
            "B301": "A08:2021 – Software and Data Integrity Failures",  # pickle
            "B302": "A08:2021 – Software and Data Integrity Failures",  # marshal
            "B303": "A02:2021 – Cryptographic Failures",  # md5
            "B304": "A02:2021 – Cryptographic Failures",  # ciphers
            "B305": "A02:2021 – Cryptographic Failures",  # cipher_modes
            "B306": "A05:2021 – Security Misconfiguration",  # mktemp_q
            "B307": "A03:2021 – Injection",  # eval
            "B308": "A03:2021 – Injection",  # mark_safe
            "B310": "A03:2021 – Injection",  # urllib_urlopen
            "B311": "A02:2021 – Cryptographic Failures",  # random
            "B312": "A07:2021 – Identification and Authentication Failures",  # telnetlib
            
            # XML Processing Vulnerabilities
            "B313": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_cElementTree
            "B314": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_ElementTree
            "B315": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_expatreader
            "B316": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_expatbuilder
            "B317": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_sax
            "B318": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_minidom
            "B319": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_pulldom
            "B320": "A06:2021 – Vulnerable and Outdated Components",  # xml_bad_etree
            
            # Network Security Issues
            "B321": "A07:2021 – Identification and Authentication Failures",  # ftplib
            "B322": "A03:2021 – Injection",  # input
            "B323": "A02:2021 – Cryptographic Failures",  # unverified_context
            "B324": "A02:2021 – Cryptographic Failures",  # hashlib_insecure_functions
            "B325": "A05:2021 – Security Misconfiguration",  # tempfile
            
            # Import-based Security Issues
            "B401": "A06:2021 – Vulnerable and Outdated Components",  # import_telnetlib
            "B402": "A06:2021 – Vulnerable and Outdated Components",  # import_ftplib
            "B403": "A06:2021 – Vulnerable and Outdated Components",  # import_pickle
            "B404": "A06:2021 – Vulnerable and Outdated Components",  # import_subprocess
            "B405": "A06:2021 – Vulnerable and Outdated Components",  # import_xml_etree
            "B406": "A06:2021 – Vulnerable and Outdated Components",  # import_xml_sax
            "B407": "A06:2021 – Vulnerable and Outdated Components",  # import_xml_expat
            "B408": "A06:2021 – Vulnerable and Outdated Components",  # import_xml_minidom
            "B409": "A06:2021 – Vulnerable and Outdated Components",  # import_xml_pulldom
            "B410": "A06:2021 – Vulnerable and Outdated Components",  # import_lxml
            "B411": "A06:2021 – Vulnerable and Outdated Components",  # import_xmlrpclib
            "B412": "A05:2021 – Security Misconfiguration",  # import_httpoxy
            "B413": "A02:2021 – Cryptographic Failures",  # import_pycrypto
            "B415": "A06:2021 – Vulnerable and Outdated Components",  # import_pyghmi
            
            # SSL/TLS and Network Security
            "B501": "A02:2021 – Cryptographic Failures",  # request_with_no_cert_validation
            "B502": "A02:2021 – Cryptographic Failures",  # ssl_with_bad_version
            "B503": "A02:2021 – Cryptographic Failures",  # ssl_with_bad_defaults
            "B504": "A02:2021 – Cryptographic Failures",  # ssl_with_no_version
            "B505": "A02:2021 – Cryptographic Failures",  # weak_cryptographic_key
            "B506": "A08:2021 – Software and Data Integrity Failures",  # yaml_load
            "B507": "A07:2021 – Identification and Authentication Failures",  # ssh_no_host_key_verification
            "B508": "A02:2021 – Cryptographic Failures",  # snmp_insecure_version
            "B509": "A02:2021 – Cryptographic Failures",  # snmp_weak_cryptography
            
            # Command Injection and Process Execution
            "B601": "A03:2021 – Injection",  # paramiko_calls
            "B602": "A03:2021 – Injection",  # subprocess_popen_with_shell_equals_true
            "B603": "A03:2021 – Injection",  # subprocess_without_shell_equals_true
            "B604": "A03:2021 – Injection",  # any_other_function_with_shell_equals_true
            "B605": "A03:2021 – Injection",  # start_process_with_a_shell
            "B606": "A03:2021 – Injection",  # start_process_with_no_shell
            "B607": "A03:2021 – Injection",  # start_process_with_partial_path
            "B608": "A03:2021 – Injection",  # hardcoded_sql_expressions
            "B609": "A03:2021 – Injection",  # linux_commands_wildcard_injection
            "B610": "A03:2021 – Injection",  # django_extra_used
            "B611": "A03:2021 – Injection",  # django_rawsql_used
            "B612": "A05:2021 – Security Misconfiguration",  # logging_config_insecure_listen
            
            # Template and Output Encoding Issues
            "B701": "A03:2021 – Injection",  # jinja2_autoescape_false
            "B702": "A03:2021 – Injection",  # use_of_mako_templates
            "B703": "A03:2021 – Injection"   # django_mark_safe
        }
        
        return owasp_mappings.get(test_id, "A10:2021 – Server-Side Request Forgery (SSRF)")  # More appropriate default
    
    def _map_bandit_to_cwe(self, test_id: str) -> str:
        """Map Bandit test ID to CWE - ENHANCED with comprehensive and accurate mappings"""
        cwe_mappings = {
            # Code Execution and Injection
            "B102": "CWE-94",   # exec_used - Code Injection
            "B103": "CWE-732",  # set_bad_file_permissions - Incorrect Permission Assignment
            "B104": "CWE-605",  # hardcoded_bind_all_interfaces - Multiple Binds Same Port
            "B105": "CWE-798",  # hardcoded_password_string - Use of Hard-coded Credentials
            "B106": "CWE-798",  # hardcoded_password_funcarg - Use of Hard-coded Credentials
            "B107": "CWE-798",  # hardcoded_password_default - Use of Hard-coded Credentials
            "B108": "CWE-377",  # hardcoded_tmp_directory - Insecure Temporary File
            "B110": "CWE-754",  # try_except_pass - Improper Check for Exceptional Conditions
            "B112": "CWE-754",  # try_except_continue - Improper Check for Exceptional Conditions
            "B113": "CWE-400",  # request_without_timeout - Uncontrolled Resource Consumption
            
            # Web Application Issues
            "B201": "CWE-489",  # flask_debug_true - Debug Mode
            "B202": "CWE-22",   # tarfile_unsafe_members - Path Traversal
            
            # Serialization and Data Processing
            "B301": "CWE-502",  # pickle - Deserialization of Untrusted Data
            "B302": "CWE-502",  # marshal - Deserialization of Untrusted Data
            "B303": "CWE-327",  # md5 - Use of a Broken or Risky Cryptographic Algorithm
            "B304": "CWE-327",  # ciphers - Use of a Broken or Risky Cryptographic Algorithm
            "B305": "CWE-327",  # cipher_modes - Use of a Broken or Risky Cryptographic Algorithm
            "B306": "CWE-377",  # mktemp_q - Insecure Temporary File
            "B307": "CWE-95",   # eval - Improper Neutralization of Directives
            "B308": "CWE-79",   # mark_safe - Cross-site Scripting
            "B310": "CWE-22",   # urllib_urlopen - Path Traversal
            "B311": "CWE-330",  # random - Use of Insufficiently Random Values
            "B312": "CWE-319",  # telnetlib - Cleartext Transmission
            
            # XML Processing Vulnerabilities (XXE)
            "B313": "CWE-611",  # xml_bad_cElementTree - XML External Entity Reference
            "B314": "CWE-611",  # xml_bad_ElementTree - XML External Entity Reference
            "B315": "CWE-611",  # xml_bad_expatreader - XML External Entity Reference
            "B316": "CWE-611",  # xml_bad_expatbuilder - XML External Entity Reference
            "B317": "CWE-611",  # xml_bad_sax - XML External Entity Reference
            "B318": "CWE-611",  # xml_bad_minidom - XML External Entity Reference
            "B319": "CWE-611",  # xml_bad_pulldom - XML External Entity Reference
            "B320": "CWE-611",  # xml_bad_etree - XML External Entity Reference
            
            # Network and Protocol Security
            "B321": "CWE-319",  # ftplib - Cleartext Transmission
            "B322": "CWE-20",   # input - Improper Input Validation
            "B323": "CWE-295",  # unverified_context - Certificate Validation
            "B324": "CWE-327",  # hashlib_insecure_functions - Broken Cryptographic Algorithm
            "B325": "CWE-377",  # tempfile - Insecure Temporary File
            
            # Import-based Issues
            "B401": "CWE-319",  # import_telnetlib - Cleartext Transmission
            "B402": "CWE-319",  # import_ftplib - Cleartext Transmission
            "B403": "CWE-502",  # import_pickle - Deserialization Risk
            "B404": "CWE-78",   # import_subprocess - OS Command Injection Risk
            "B405": "CWE-611",  # import_xml_etree - XXE Risk
            "B406": "CWE-611",  # import_xml_sax - XXE Risk
            "B407": "CWE-611",  # import_xml_expat - XXE Risk
            "B408": "CWE-611",  # import_xml_minidom - XXE Risk
            "B409": "CWE-611",  # import_xml_pulldom - XXE Risk
            "B410": "CWE-611",  # import_lxml - XXE Risk
            "B411": "CWE-611",  # import_xmlrpclib - XXE/RPC Risk
            "B412": "CWE-20",   # import_httpoxy - HTTP Request Smuggling
            "B413": "CWE-327",  # import_pycrypto - Weak Cryptography
            "B415": "CWE-319",  # import_pyghmi - Cleartext IPMI
            
            # SSL/TLS and Cryptographic Issues
            "B501": "CWE-295",  # request_with_no_cert_validation - Certificate Validation
            "B502": "CWE-326",  # ssl_with_bad_version - Inadequate Encryption Strength
            "B503": "CWE-326",  # ssl_with_bad_defaults - Inadequate Encryption Strength
            "B504": "CWE-326",  # ssl_with_no_version - Inadequate Encryption Strength
            "B505": "CWE-326",  # weak_cryptographic_key - Inadequate Encryption Strength
            "B506": "CWE-502",  # yaml_load - Deserialization of Untrusted Data
            "B507": "CWE-322",  # ssh_no_host_key_verification - Key Exchange without Entity Authentication
            "B508": "CWE-326",  # snmp_insecure_version - Inadequate Encryption
            "B509": "CWE-326",  # snmp_weak_cryptography - Inadequate Encryption
            
            # Command and Process Injection
            "B601": "CWE-78",   # paramiko_calls - OS Command Injection
            "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true - OS Command Injection
            "B603": "CWE-78",   # subprocess_without_shell_equals_true - OS Command Injection
            "B604": "CWE-78",   # any_other_function_with_shell_equals_true - OS Command Injection
            "B605": "CWE-78",   # start_process_with_a_shell - OS Command Injection
            "B606": "CWE-78",   # start_process_with_no_shell - OS Command Injection
            "B607": "CWE-78",   # start_process_with_partial_path - OS Command Injection
            "B608": "CWE-89",   # hardcoded_sql_expressions - SQL Injection
            "B609": "CWE-78",   # linux_commands_wildcard_injection - OS Command Injection
            "B610": "CWE-89",   # django_extra_used - SQL Injection
            "B611": "CWE-89",   # django_rawsql_used - SQL Injection
            "B612": "CWE-200",  # logging_config_insecure_listen - Information Exposure
            
            # Template and Output Issues
            "B701": "CWE-79",   # jinja2_autoescape_false - Cross-site Scripting
            "B702": "CWE-79",   # use_of_mako_templates - Cross-site Scripting
            "B703": "CWE-79"    # django_mark_safe - Cross-site Scripting
        }
        
        return cwe_mappings.get(test_id, "CWE-693")  # Default to Protection Mechanism Failure