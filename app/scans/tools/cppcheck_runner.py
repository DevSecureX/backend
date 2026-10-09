import json
import os
import tempfile
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
import logging

logger = logging.getLogger(__name__)

class CppcheckRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("cppcheck")
        self.timeout = 600  # 10 minutes for C/C++ analysis
        self._setup_enhanced_config()

    async def run(self, temp_dir: str, file_list: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Cppcheck C/C++ security analysis with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 180)  # Max 3 minutes for CLI
            logger.info(f"Running Cppcheck in CLI mode with {self.timeout}s timeout")
        # ENHANCED SECURITY-FOCUSED CPPCHECK CONFIGURATION
        report_file = f"/tmp/cppcheck-security-report-{os.getpid()}.xml"
        
        cmd = [
            'cppcheck',
            # Enable comprehensive security checks
            '--enable=all',              # Enable ALL available checks for maximum coverage
            
            # Enhanced security-specific checks
            '--check-level=exhaustive',  # Most thorough analysis
            '--max-ctu-depth=10',        # Cross-translation unit analysis depth
            
            # XML output configuration
            '--xml',
            '--xml-version=2',
            f'--output-file={report_file}',
            
            # Security-focused suppressions (minimal to maximize detection)
            '--suppress=missingIncludeSystem',  # Only suppress include system errors
            
            # Include inconclusive results for maximum coverage
            '--inconclusive',
            
            # Platform and standard configurations for better analysis
            '--std=c11',                 # Modern C standard
            '--std=c++17',               # Modern C++ standard  
            '--platform=native',         # Use native platform settings
            
            # Enhanced analysis options
            '--force',                   # Check all files even with missing includes
            '--verbose',                 # Detailed output for better parsing
            
            # Directory to scan
            temp_dir
        ]
        
        self.current_report_file = report_file

        # Filter for C/C++ files if file_list provided
        if file_list:
            cpp_files = [f for f in file_list if f.endswith(('.c', '.cpp', '.h', '.hpp'))]
            if not cpp_files:
                return {"issues": [], "tool": "cppcheck", "duration": 0, "metadata": {"message": "No C/C++ files to scan"}}

        result = await self.execute_command(cmd, cwd=temp_dir)

        if "error" in result:
            return {"issues": [], "error": result["error"], "tool": "cppcheck"}

        try:
            if not os.path.exists(self.current_report_file):
                logger.warning(f"Cppcheck report file not found: {self.current_report_file}")
                return {"issues": [], "tool": "cppcheck", "duration": result["duration"], "error": "No report generated"}
            
            with open(self.current_report_file, 'r', encoding='utf-8') as f:
                output = f.read()

            import xml.etree.ElementTree as ET
            root = ET.fromstring(output)
            issues = []

            for error in root.findall('.//error'):
                error_id = error.get('id', '')
                error_msg = error.get('msg', 'C/C++ security issue')
                error_severity = error.get('severity', 'warning')
                error_cwe = error.get('cwe', '')
                verbose_msg = error.get('verbose', error_msg)
                inconclusive = error.get('inconclusive', 'false') == 'true'
                
                # Extract location information - handle multiple locations
                locations = error.findall('location')
                if not locations:
                    # Fallback for errors without location
                    locations = [error]  # Use error element itself
                
                for location in locations:
                    file_path = location.get('file', '')
                    line_num = int(location.get('line', 0))
                    column_num = int(location.get('column', 0))
                    location_info = location.get('info', '')
                    
                    # Enhanced confidence calculation
                    confidence = self._calculate_confidence(error_id, error_severity, inconclusive, error_cwe)
                    
                    # Enhanced message with context
                    enhanced_message = self._enhance_message(error_msg, verbose_msg, location_info, error_id)
                    
                    issue = {
                        "tool": "cppcheck",
                        "category": "security",  # More specific category
                        "rule_id": error_id,
                        "message": enhanced_message,
                        "severity": self._map_cppcheck_severity(error_severity),
                        "file_path": self.clean_file_path(file_path, temp_dir),
                        "line_start": line_num,
                        "line_end": line_num,
                        "column_start": column_num,
                        "confidence": confidence,
                        "owasp_category": self._map_to_owasp(error_id),
                        "cwe_id": self._map_to_cwe(error_id),
                        "inconclusive": inconclusive,
                        "verbose_message": verbose_msg,
                        "raw_severity": error_severity,
                        "context": location_info
                    }
                    
                    # Only add if it's a valid issue with file path
                    if file_path and self._is_security_relevant(error_id):
                        issues.append(issue)

            # Clean up report file
            if os.path.exists(self.current_report_file):
                os.remove(self.current_report_file)

            # Enhanced metadata
            metadata = {
                "total_issues": len(issues),
                "security_issues": len([i for i in issues if self._is_high_security_impact(i["rule_id"])]),
                "high_confidence_issues": len([i for i in issues if i["confidence"] == "high"]),
                "files_scanned": len(set(issue.get("file_path") for issue in issues if issue.get("file_path"))),
                "cwe_categories": list(set(issue.get("cwe_id") for issue in issues if issue.get("cwe_id") != "CWE-200")),
                "tool_version": "2.18.0+",
                "analysis_depth": "exhaustive"
            }
            
            return {
                "issues": issues,
                "tool": "cppcheck",
                "duration": result["duration"],
                "files_scanned": metadata["files_scanned"],
                "metadata": metadata
            }

        except Exception as e:
            logger.error(f"Failed to parse Cppcheck output: {e}")
            return {"issues": [], "error": f"Failed to parse output: {str(e)}", "tool": "cppcheck"}

    def _setup_enhanced_config(self):
        """Setup enhanced configuration for security-focused analysis"""
        self.current_report_file = None
        
        # Security-critical error IDs that should always be high priority
        self.critical_security_ids = {
            'bufferAccessOutOfBounds', 'arrayIndexOutOfBounds', 'bufferOverflow',
            'memoryLeak', 'deallocuse', 'doubleFree', 'useAfterFree',
            'nullPointer', 'nullPointerRedundantCheck', 'nullPointerDefaultArg',
            'uninitvar', 'uninitdata', 'uninitstring',
            'integerOverflow', 'signConversion', 'truncLongCastAssignment',
            'getsCalled', 'sprintfOverlappingData', 'wrongPrintfScanfArgNum',
            'invalidPrintfArgType_s', 'invalidPrintfArgType_n',
            'resourceLeak', 'memleak', 'memleakOnRealloc',
            'danglingTemporaryLifetime', 'returnDanglingLifetime'
        }

    def _map_cppcheck_severity(self, severity: str) -> str:
        """Enhanced severity mapping with security context"""
        severity_map = {
            'error': 'high',
            'warning': 'medium', 
            'style': 'low',
            'performance': 'medium',
            'portability': 'medium',
            'information': 'low'
        }
        return severity_map.get(severity.lower(), 'medium')
    
    def _calculate_confidence(self, error_id: str, severity: str, inconclusive: bool, cwe: str) -> str:
        """Calculate confidence level based on multiple factors"""
        # High confidence for critical security issues
        if error_id in self.critical_security_ids:
            return 'high' if not inconclusive else 'medium'
        
        # High confidence for errors with CWE mappings
        if cwe and cwe != '':
            return 'high' if severity == 'error' else 'medium'
        
        # Medium confidence for warnings
        if severity == 'warning':
            return 'medium' if not inconclusive else 'low'
        
        # High confidence for errors
        if severity == 'error':
            return 'high'
        
        return 'low'
    
    def _enhance_message(self, msg: str, verbose_msg: str, location_info: str, error_id: str) -> str:
        """Enhance error message with additional context"""
        base_message = verbose_msg if verbose_msg and len(verbose_msg) > len(msg) else msg
        
        # Add security context for critical issues
        if error_id in self.critical_security_ids:
            security_context = self._get_security_context(error_id)
            if security_context:
                base_message += f" [{security_context}]"
        
        # Add location context if available
        if location_info and location_info not in base_message:
            base_message += f" Context: {location_info}"
        
        return base_message
    
    def _get_security_context(self, error_id: str) -> str:
        """Get security context for error ID"""
        security_contexts = {
            'bufferAccessOutOfBounds': 'Potential buffer overflow attack vector',
            'arrayIndexOutOfBounds': 'Array bounds violation - potential memory corruption',
            'memoryLeak': 'Resource exhaustion vulnerability',
            'deallocuse': 'Use-after-free - critical security vulnerability',
            'doubleFree': 'Double-free - heap corruption vulnerability',
            'nullPointer': 'Null pointer dereference - denial of service risk',
            'uninitvar': 'Uninitialized variable - unpredictable behavior',
            'integerOverflow': 'Integer overflow - potential security bypass',
            'getsCalled': 'Dangerous function - buffer overflow risk'
        }
        return security_contexts.get(error_id, '')
    
    def _is_security_relevant(self, error_id: str) -> bool:
        """Determine if error ID is security-relevant"""
        # Security-relevant patterns
        security_patterns = [
            'buffer', 'overflow', 'bounds', 'memory', 'leak', 'free', 'null',
            'uninit', 'integer', 'gets', 'printf', 'scanf', 'resource',
            'dangling', 'lifetime', 'cast', 'sign', 'trunc'
        ]
        
        error_lower = error_id.lower()
        return any(pattern in error_lower for pattern in security_patterns) or error_id in self.critical_security_ids
    
    def _is_high_security_impact(self, error_id: str) -> bool:
        """Determine if error has high security impact"""
        return error_id in self.critical_security_ids

    def _map_to_owasp(self, error_id: str) -> str:
        """Comprehensive mapping of Cppcheck errors to OWASP Top 10 categories"""
        
        # Direct mappings for exact matches
        direct_mappings = {
            # Buffer/Memory vulnerabilities -> A03: Injection
            'bufferAccessOutOfBounds': 'A03:2021 – Injection',
            'arrayIndexOutOfBounds': 'A03:2021 – Injection', 
            'bufferOverflow': 'A03:2021 – Injection',
            'bufferOverflowUnicode': 'A03:2021 – Injection',
            
            # Authentication/Access Control
            'nullPointer': 'A01:2021 – Broken Access Control',
            'nullPointerDefaultArg': 'A01:2021 – Broken Access Control',
            'nullPointerRedundantCheck': 'A01:2021 – Broken Access Control',
            
            # Cryptographic failures
            'weakRandom': 'A02:2021 – Cryptographic Failures',
            'randomGeneratorSeeded': 'A02:2021 – Cryptographic Failures',
            
            # Memory management -> Insecure Design
            'memoryLeak': 'A04:2021 – Insecure Design',
            'memleak': 'A04:2021 – Insecure Design',
            'memleakOnRealloc': 'A04:2021 – Insecure Design',
            'deallocuse': 'A04:2021 – Insecure Design',
            'useAfterFree': 'A04:2021 – Insecure Design',
            'doubleFree': 'A04:2021 – Insecure Design',
            'resourceLeak': 'A04:2021 – Insecure Design',
            
            # Security misconfiguration
            'uninitvar': 'A05:2021 – Security Misconfiguration',
            'uninitdata': 'A05:2021 – Security Misconfiguration',
            'uninitstring': 'A05:2021 – Security Misconfiguration',
            'unreadVariable': 'A05:2021 – Security Misconfiguration',
            
            # Vulnerable components
            'getsCalled': 'A06:2021 – Vulnerable and Outdated Components',
            'unsafeFunctionUsage': 'A06:2021 – Vulnerable and Outdated Components',
            
            # Identification and authentication failures
            'hardcodedPassword': 'A07:2021 – Identification and Authentication Failures',
            'hardcodedCredentials': 'A07:2021 – Identification and Authentication Failures',
            
            # Data integrity failures
            'integerOverflow': 'A08:2021 – Software and Data Integrity Failures',
            'signConversion': 'A08:2021 – Software and Data Integrity Failures',
            'truncLongCastAssignment': 'A08:2021 – Software and Data Integrity Failures',
            'integerOverflowCond': 'A08:2021 – Software and Data Integrity Failures',
            
            # Logging and monitoring failures  
            'unusedFunction': 'A09:2021 – Security Logging and Monitoring Failures',
            'constParameter': 'A09:2021 – Security Logging and Monitoring Failures',
            
            # SSRF (Server Side Request Forgery)
            'fileOpenedTwice': 'A10:2021 – Server-Side Request Forgery (SSRF)',
            'IOWithoutPosCheck': 'A10:2021 – Server-Side Request Forgery (SSRF)'
        }
        
        # Check for direct match first
        if error_id in direct_mappings:
            return direct_mappings[error_id]
        
        # Pattern-based mappings for partial matches
        error_lower = error_id.lower()
        
        # Injection patterns
        if any(pattern in error_lower for pattern in ['buffer', 'bounds', 'overflow', 'format', 'printf', 'scanf']):
            return 'A03:2021 – Injection'
        
        # Access control patterns
        if any(pattern in error_lower for pattern in ['null', 'pointer', 'access']):
            return 'A01:2021 – Broken Access Control'
        
        # Cryptographic patterns
        if any(pattern in error_lower for pattern in ['crypto', 'random', 'hash', 'encrypt']):
            return 'A02:2021 – Cryptographic Failures'
        
        # Memory/Design patterns
        if any(pattern in error_lower for pattern in ['memory', 'leak', 'free', 'malloc', 'alloc']):
            return 'A04:2021 – Insecure Design'
        
        # Configuration patterns
        if any(pattern in error_lower for pattern in ['uninit', 'config', 'setup', 'init']):
            return 'A05:2021 – Security Misconfiguration'
        
        # Vulnerable function patterns
        if any(pattern in error_lower for pattern in ['gets', 'strcpy', 'strcat', 'sprintf', 'dangerous']):
            return 'A06:2021 – Vulnerable and Outdated Components'
        
        # Integer/data integrity patterns
        if any(pattern in error_lower for pattern in ['integer', 'overflow', 'underflow', 'cast', 'conversion']):
            return 'A08:2021 – Software and Data Integrity Failures'
        
        # Default fallback
        return 'A04:2021 – Insecure Design'

    def _map_to_cwe(self, error_id: str) -> str:
        """Comprehensive mapping of Cppcheck errors to CWE (Common Weakness Enumeration)"""
        
        # Direct CWE mappings for specific error IDs
        direct_mappings = {
            # Buffer and bounds errors
            'bufferAccessOutOfBounds': 'CWE-125',  # Out-of-bounds Read
            'arrayIndexOutOfBounds': 'CWE-787',    # Out-of-bounds Write
            'bufferOverflow': 'CWE-120',           # Buffer Copy without Checking Size
            'bufferOverflowUnicode': 'CWE-120',    # Buffer Copy without Checking Size
            'possibleBufferOverflow': 'CWE-120',   # Buffer Copy without Checking Size
            
            # Memory management errors
            'memoryLeak': 'CWE-401',               # Missing Release of Memory
            'memleak': 'CWE-401',                  # Missing Release of Memory  
            'memleakOnRealloc': 'CWE-401',         # Missing Release of Memory
            'deallocuse': 'CWE-416',               # Use After Free
            'useAfterFree': 'CWE-416',             # Use After Free
            'doubleFree': 'CWE-415',               # Double Free
            'mismatchAllocDealloc': 'CWE-762',     # Mismatched Memory Management
            'resourceLeak': 'CWE-404',             # Improper Resource Shutdown
            
            # Null pointer errors
            'nullPointer': 'CWE-476',              # NULL Pointer Dereference
            'nullPointerDefaultArg': 'CWE-476',    # NULL Pointer Dereference
            'nullPointerRedundantCheck': 'CWE-476', # NULL Pointer Dereference
            'nullPointerArithmetic': 'CWE-476',    # NULL Pointer Dereference
            
            # Initialization errors
            'uninitvar': 'CWE-457',                # Use of Uninitialized Variable
            'uninitdata': 'CWE-457',               # Use of Uninitialized Variable
            'uninitstring': 'CWE-457',             # Use of Uninitialized Variable
            'uninitStructMember': 'CWE-457',       # Use of Uninitialized Variable
            
            # Integer errors
            'integerOverflow': 'CWE-190',          # Integer Overflow
            'integerOverflowCond': 'CWE-190',      # Integer Overflow
            'signConversion': 'CWE-195',           # Signed to Unsigned Conversion
            'truncLongCastAssignment': 'CWE-197',  # Numeric Truncation Error
            'integerDivisionByZero': 'CWE-369',    # Divide By Zero
            
            # Dangerous function usage
            'getsCalled': 'CWE-242',               # Use of Inherently Dangerous Function
            'unsafeFunctionUsage': 'CWE-676',      # Use of Potentially Dangerous Function
            'sprintfOverlappingData': 'CWE-628',   # Function Call with Overlapping Memory
            
            # Format string errors
            'wrongPrintfScanfArgNum': 'CWE-685',   # Function Call With Incorrect Number of Arguments
            'invalidPrintfArgType_s': 'CWE-686',   # Function Call With Incorrect Argument Type
            'invalidPrintfArgType_n': 'CWE-686',   # Function Call With Incorrect Argument Type
            'invalidScanfArgType_s': 'CWE-686',    # Function Call With Incorrect Argument Type
            
            # Input validation
            'negativeIndex': 'CWE-129',            # Improper Validation of Array Index
            'arrayIndexThenCheck': 'CWE-129',      # Improper Validation of Array Index
            'checkCastIntToCharAndBack': 'CWE-197', # Numeric Truncation Error
            
            # Race conditions and concurrency
            'raceAfterCheck': 'CWE-367',           # Time-of-check Time-of-use Race
            'staticStringCompare': 'CWE-597',      # Use of Wrong Operator in String Comparison
            
            # Information exposure
            'leakReturnValNotUsed': 'CWE-252',     # Unchecked Return Value
            'resourceUseAfterFree': 'CWE-416',     # Use After Free
            'danglingTemporaryLifetime': 'CWE-416', # Use After Free
            'returnDanglingLifetime': 'CWE-416',   # Use After Free
            
            # Cryptographic issues
            'weakRandom': 'CWE-338',               # Use of Cryptographically Weak PRNG
            'randomGeneratorSeeded': 'CWE-335',    # Incorrect Usage of Seeds in PRNG
            'hardcodedPassword': 'CWE-798',        # Use of Hard-coded Credentials
            'hardcodedCredentials': 'CWE-798',     # Use of Hard-coded Credentials
            
            # File and I/O operations
            'fileOpenedTwice': 'CWE-675',          # Multiple Operations on Resource
            'IOWithoutPosCheck': 'CWE-252',        # Unchecked Return Value
            'seekOnAppendedFile': 'CWE-628',       # Function Call with Overlapping Memory
            
            # Type and casting issues
            'cstyleCast': 'CWE-704',               # Incorrect Type Conversion
            'invalidPointerCast': 'CWE-704',       # Incorrect Type Conversion
            'unusedAllocatedMemory': 'CWE-561',    # Dead Code
            'unreadVariable': 'CWE-563',           # Assignment to Variable without Use
            
            # Logic errors
            'duplicateCondition': 'CWE-561',       # Dead Code
            'duplicateExpressionTernary': 'CWE-561', # Dead Code
            'identicalConditionAfterEarlyExit': 'CWE-561', # Dead Code
            'unreachableCode': 'CWE-561',          # Dead Code
            
            # Function and parameter issues
            'unusedFunction': 'CWE-561',           # Dead Code
            'constParameter': 'CWE-398',           # Indicator of Poor Code Quality
            'constParameterPointer': 'CWE-398',    # Indicator of Poor Code Quality
            'constVariable': 'CWE-398',            # Indicator of Poor Code Quality
        }
        
        # Check for direct match first
        if error_id in direct_mappings:
            return direct_mappings[error_id]
        
        # Pattern-based CWE mapping for partial matches
        error_lower = error_id.lower()
        
        # Buffer/bounds patterns
        if any(pattern in error_lower for pattern in ['buffer', 'bounds', 'overflow']):
            if 'read' in error_lower or 'access' in error_lower:
                return 'CWE-125'  # Out-of-bounds Read
            return 'CWE-787'  # Out-of-bounds Write
        
        # Memory patterns
        if 'leak' in error_lower:
            return 'CWE-401'  # Missing Release of Memory
        if 'free' in error_lower and 'use' in error_lower:
            return 'CWE-416'  # Use After Free
        if 'double' in error_lower and 'free' in error_lower:
            return 'CWE-415'  # Double Free
        
        # Null patterns
        if 'null' in error_lower and 'pointer' in error_lower:
            return 'CWE-476'  # NULL Pointer Dereference
        
        # Initialization patterns
        if 'uninit' in error_lower:
            return 'CWE-457'  # Use of Uninitialized Variable
        
        # Integer patterns
        if 'overflow' in error_lower and 'integer' in error_lower:
            return 'CWE-190'  # Integer Overflow
        if 'underflow' in error_lower:
            return 'CWE-191'  # Integer Underflow
        
        # Format string patterns
        if any(pattern in error_lower for pattern in ['printf', 'scanf', 'format']):
            return 'CWE-134'  # Use of Externally-Controlled Format String
        
        # Input validation patterns
        if 'index' in error_lower and ('negative' in error_lower or 'bounds' in error_lower):
            return 'CWE-129'  # Improper Validation of Array Index
        
        # Race condition patterns
        if 'race' in error_lower or 'toctou' in error_lower:
            return 'CWE-367'  # Time-of-check Time-of-use Race Condition
        
        # Cryptographic patterns
        if any(pattern in error_lower for pattern in ['random', 'crypto', 'weak']):
            return 'CWE-338'  # Use of Cryptographically Weak PRNG
        
        # Resource management patterns
        if 'resource' in error_lower:
            return 'CWE-404'  # Improper Resource Shutdown
        
        # Default fallback for unmapped errors
        return 'CWE-703'  # Improper Check or Handling of Exceptional Conditions