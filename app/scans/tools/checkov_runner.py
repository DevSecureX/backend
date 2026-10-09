import json
import os
import shutil
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
from ..utils.code_context_extractor import CodeContextExtractor
import logging

logger = logging.getLogger(__name__)

class CheckovRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("checkov")
        self.timeout = 300  # 5 minutes for IaC
        self.context_extractor = CodeContextExtractor(context_lines=3)
        
    async def run(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Checkov Infrastructure as Code scanning with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 120)  # Max 2 minutes for CLI
            logger.info(f"Running Checkov in CLI mode with {self.timeout}s timeout")
        
        # Check if Checkov is available
        checkov_cmd = self._find_checkov_command()
        if not checkov_cmd:
            return {
                "issues": [], 
                "tool": "checkov", 
                "duration": 0, 
                "metadata": {"message": "Checkov not installed, skipping Infrastructure as Code scan"}
            }
        
        # First check if there are IaC files to scan
        iac_files = self._find_iac_files(temp_dir)
        if not iac_files:
            logger.warning(f"No Infrastructure as Code files found in {temp_dir}")
            # List some files that were checked for debugging
            try:
                all_files = []
                for root, dirs, files in os.walk(temp_dir):
                    all_files.extend([os.path.join(root, f) for f in files[:10]])  # First 10 per directory
                logger.debug(f"Sample files found in temp_dir: {[os.path.basename(f) for f in all_files[:20]]}")
            except Exception as e:
                logger.debug(f"Could not list files for debugging: {e}")
            
            return {
                "issues": [], 
                "tool": "checkov", 
                "duration": 0, 
                "metadata": {"message": "No Infrastructure as Code files found to scan"}
            }
        
        logger.info(f"Found {len(iac_files)} IaC files to scan: {[os.path.basename(f) for f in iac_files[:10]]}")
        logger.debug(f"IaC file types detected: {set(os.path.splitext(f)[1].lower() for f in iac_files)}")
        
        # ENHANCED analysis parameters for comprehensive IaC scanning - CRITICAL FIX: More aggressive detection
        # CRITICAL BUG FIX: Checkov 2.3.228 has issues with multiple frameworks and --check all
        # Use individual framework scans for reliable results
        frameworks_to_scan = ['dockerfile', 'terraform', 'kubernetes', 'cloudformation', 'arm', 'bicep', 'helm', 'kustomize', 'ansible', 'secrets', 'github_configuration']
        
        # We'll run Checkov multiple times (once per framework) and aggregate results
        # This is more reliable than trying to use multiple --framework arguments
        framework_results = []
        total_issues = []
        total_duration = 0
        
        for framework in frameworks_to_scan:
            framework_args = [
                '-d', temp_dir,
                '--output', 'json',
                '--skip-download',
                '--framework', framework
            ]
            
            framework_cmd = checkov_cmd + framework_args
            logger.info(f"Executing Checkov {framework} scan: {' '.join(framework_cmd)}")
            
            result = await self.execute_command(framework_cmd)
            
            if "error" in result:
                logger.warning(f"Checkov {framework} scan failed: {result['error']}")
                continue
                
            stdout_content = result.get("stdout", "")
            if not stdout_content.strip():
                logger.debug(f"Checkov {framework} returned empty output")
                continue
                
            try:
                framework_output = json.loads(stdout_content)
                framework_issues = self._parse_checkov_output(framework_output, temp_dir, framework)
                total_issues.extend(framework_issues)
                total_duration += result.get("duration", 0)
                framework_results.append({
                    'framework': framework,
                    'issues_count': len(framework_issues),
                    'duration': result.get("duration", 0)
                })
                logger.info(f"✅ Checkov {framework}: Found {len(framework_issues)} issues in {result.get('duration', 0):.2f}s")
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Checkov {framework} JSON: {e}")
                continue
        
        logger.info(f"Checkov comprehensive scan completed:")
        logger.info(f"  - Frameworks scanned: {len(framework_results)}")
        logger.info(f"  - Total issues found: {len(total_issues)}")
        logger.info(f"  - Total duration: {total_duration:.2f}s")
        
        return {
            "issues": total_issues,
            "tool": "checkov",
            "duration": total_duration,
            "files_scanned": len(set(issue["file_path"] for issue in total_issues if issue.get("file_path"))),
            "iac_files_detected": len(iac_files),
            "frameworks_scanned": [f['framework'] for f in framework_results],
            "framework_results": framework_results,
            "metadata": {
                "cli_mode": is_cli_scan,
                "timeout_used": self.timeout,
                "iac_files_found": [os.path.basename(f) for f in iac_files[:10]]
            }
        }
    
    def _parse_checkov_output(self, output: dict, temp_dir: str, framework: str) -> list:
        """Parse Checkov JSON output and extract failed checks as issues"""
        issues = []
        
        # Handle the new Checkov 2.3.228 JSON structure
        results_section = output.get("results", {})
        failed_checks = results_section.get("failed_checks", [])
        
        for check_result in failed_checks:
            file_path_raw = check_result.get("file_path", "")
            # Remove leading slash to get relative path  
            if file_path_raw.startswith("/"):
                file_path_raw = file_path_raw[1:]
            file_path = self.clean_file_path(file_path_raw, temp_dir)
            
            line_range = check_result.get("file_line_range", [])
            line_start = line_range[0] if line_range else None
            line_end = line_range[1] if len(line_range) > 1 else line_start
            
            # Extract code context for infrastructure issues
            code_context = None
            if line_start and file_path:
                try:
                    code_context = self.context_extractor.extract_context(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_end,
                        temp_dir=temp_dir
                    )
                except Exception:
                    # Skip context extraction if file not found
                    pass
            
            issue = {
                "tool": "checkov",
                "category": "configs",
                "rule_id": check_result.get("check_id"),
                "message": check_result.get("check_name", "Infrastructure misconfiguration"),
                "severity": self._map_checkov_severity(check_result.get("severity")),
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "confidence": "high",
                "resource": check_result.get("resource"),
                "guideline": check_result.get("guideline"),
                "owasp_category": "A05:2021 – Security Misconfiguration",
                "cwe_id": self._map_checkov_to_cwe(check_result.get("check_id")),
                "code_context": code_context,
                "framework": framework
            }
            issues.append(issue)
        
        return issues
    
    def _map_checkov_severity(self, severity: str) -> str:
        """Map Checkov severity to standard levels"""
        if not severity:
            return "medium"
        
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high", 
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "low"
        }
        
        return severity_map.get(severity.upper(), "medium")
    
    def _map_checkov_to_cwe(self, check_id: str) -> str:
        """Map Checkov check ID to CWE"""
        if not check_id:
            return None
            
        # Common infrastructure misconfigurations
        cwe_mappings = {
            # Docker checks
            "CKV_DOCKER_1": "CWE-250",  # Execution with Unnecessary Privileges
            "CKV_DOCKER_3": "CWE-250",  # USER instruction
            "CKV_DOCKER_4": "CWE-93",   # CRLF Injection (COPY instead of ADD)
            "CKV_DOCKER_5": "CWE-693",  # Protection Mechanism Failure (health check)
            
            # Kubernetes checks
            "CKV_K8S_1": "CWE-250",     # Do not admit containers wishing to share host process ID namespace
            "CKV_K8S_2": "CWE-250",     # Do not admit privileged containers
            "CKV_K8S_3": "CWE-250",     # Do not admit containers wishing to share host IPC namespace
            "CKV_K8S_4": "CWE-250",     # Do not admit containers wishing to share host network namespace
            "CKV_K8S_8": "CWE-326",     # Liveness probe should be configured
            "CKV_K8S_9": "CWE-326",     # Readiness probe should be configured
            "CKV_K8S_11": "CWE-770",    # CPU limits should be set
            "CKV_K8S_12": "CWE-770",    # Memory requests should be set
            "CKV_K8S_13": "CWE-770",    # Memory limits should be set
            "CKV_K8S_14": "CWE-770",    # CPU requests should be set
            
            # AWS checks
            "CKV_AWS_1": "CWE-326",     # S3 Bucket Public access
            "CKV_AWS_2": "CWE-326",     # ALB protocol is HTTPS
            "CKV_AWS_3": "CWE-326",     # EBS encryption
            "CKV_AWS_7": "CWE-326",     # KMS rotation
            "CKV_AWS_8": "CWE-326",     # RDS encryption
            "CKV_AWS_16": "CWE-326",    # RDS is encrypted
            "CKV_AWS_17": "CWE-326",    # RDS is publicly accessible
            "CKV_AWS_18": "CWE-326",    # S3 Buckets encrypted
            "CKV_AWS_19": "CWE-326",    # S3 Buckets encrypted with KMS
            "CKV_AWS_20": "CWE-326",    # S3 Bucket public access
            "CKV_AWS_21": "CWE-326",    # S3 Bucket public access
            "CKV_AWS_23": "CWE-326",    # RDS is encrypted
            
            # General patterns
            "encryption": "CWE-311",    # Missing Encryption of Sensitive Data
            "logging": "CWE-778",       # Insufficient Logging
            "monitoring": "CWE-778",    # Insufficient Logging
            "public": "CWE-668",        # Exposure of Resource to Wrong Sphere
            "password": "CWE-521",      # Weak Password Requirements
            "secret": "CWE-798"         # Use of Hard-coded Credentials
        }
        
        # Check exact match first
        if check_id in cwe_mappings:
            return cwe_mappings[check_id]
        
        # Check patterns in check_id
        check_lower = check_id.lower()
        for pattern, cwe in cwe_mappings.items():
            if pattern in check_lower:
                return cwe
        
        # Default for security misconfigurations
        return "CWE-16"  # Configuration
    
    def _find_checkov_command(self) -> list:
        """Find available Checkov command - FIXED for Checkov 2.3.228+"""
        
        # 1. Check global installation
        if shutil.which('checkov'):
            return ['checkov']
        
        # 2. Check common Python installation paths
        common_paths = [
            '/usr/local/bin/checkov',
            '/opt/homebrew/bin/checkov',
            '/Library/Frameworks/Python.framework/Versions/3.12/bin/checkov',
            '/Library/Frameworks/Python.framework/Versions/3.11/bin/checkov',
            '/Library/Frameworks/Python.framework/Versions/3.10/bin/checkov',
            '/usr/bin/checkov'
        ]
        
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return [path]
        
        # 3. Try pip user installation
        user_path = os.path.expanduser('~/.local/bin/checkov')
        if shutil.which(user_path):
            return [user_path]
        
        # 4. CRITICAL FIX: Try programmatic execution for newer Checkov versions  
        # This is the most reliable method for Checkov 2.3.228+
        try:
            import checkov.main
            # Test that we can create a Checkov instance
            checkov.main.Checkov()
            # Use Python to execute Checkov programmatically with a wrapper script
            python_cmd = 'python3' if shutil.which('python3') else 'python'
            if shutil.which(python_cmd):
                # Create a more reliable command structure that handles arguments properly
                wrapper_script = '''
import sys
import os
from checkov.main import Checkov

# Override sys.argv with the passed arguments
sys.argv = sys.argv[1:]  # Remove the script name, keep the arguments
checkov_instance = Checkov()
exit_code = checkov_instance.run()
sys.exit(exit_code or 0)
'''
                return [python_cmd, '-c', wrapper_script.strip()]
        except ImportError:
            logger.debug("Checkov Python module not available")
        
        # 5. Fallback: Try with python -m (less reliable for 2.3.228+)
        if shutil.which('python3'):
            return ['python3', '-m', 'checkov']
        if shutil.which('python'):
            return ['python', '-m', 'checkov']
        
        # 6. No Checkov available
        return None
    
    def _find_iac_files(self, temp_dir: str) -> list:
        """Find Infrastructure as Code files in the directory - ENHANCED for comprehensive detection"""
        iac_extensions = {
            # Terraform
            '.tf', '.terraform', '.tfvars', '.tfvar',
            # Kubernetes & Docker
            '.yaml', '.yml', 'dockerfile',
            # CloudFormation & AWS
            '.json', '.template',
            # Azure
            '.bicep', '.arm',
            # Ansible
            '.ansible', '.playbook',
            # Helm charts
            '.tpl', '.gotmpl'
        }
        
        iac_filenames = {
            # Docker
            'dockerfile', 'dockerfile.prod', 'dockerfile.dev', 'dockerfile.test',
            'docker-compose.yml', 'docker-compose.yaml', 'docker-compose.prod.yml',
            'docker-compose.dev.yml', 'docker-compose.test.yml',
            # CloudFormation
            'cloudformation.json', 'cloudformation.yaml', 'cloudformation.yml',
            'template.json', 'template.yaml', 'template.yml',
            # Kubernetes
            'kubernetes.yaml', 'kubernetes.yml', 'k8s.yaml', 'k8s.yml',
            'deployment.yaml', 'deployment.yml', 'service.yaml', 'service.yml',
            'configmap.yaml', 'configmap.yml', 'secret.yaml', 'secret.yml',
            'ingress.yaml', 'ingress.yml', 'namespace.yaml', 'namespace.yml',
            # Terraform
            'main.tf', 'variables.tf', 'outputs.tf', 'terraform.tfvars',
            # Ansible
            'playbook.yml', 'playbook.yaml', 'site.yml', 'site.yaml',
            # Helm
            'values.yaml', 'values.yml', 'chart.yaml', 'chart.yml'
        }
        
        iac_files = []
        
        try:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    file_lower = file.lower()
                    file_path = os.path.join(root, file)
                    
                    # Check by extension
                    _, ext = os.path.splitext(file_lower)
                    if ext in iac_extensions:
                        iac_files.append(file_path)
                        continue
                    
                    # Check by filename
                    if file_lower in iac_filenames:
                        iac_files.append(file_path)
                        continue
                    
                    # Check if it's a Dockerfile variant
                    if 'dockerfile' in file_lower:
                        iac_files.append(file_path)
                        continue
                    
                    # ENHANCED: Content-based detection for files without clear extensions
                    if ext in ['.txt', '.config', '.cfg', '.conf', ''] and os.path.getsize(file_path) < 1024 * 1024:  # Max 1MB files
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read(1024).lower()  # Read first 1KB
                                
                                # Check for Infrastructure as Code patterns
                                iac_patterns = [
                                    'apiversion:', 'kind:', 'metadata:',  # Kubernetes
                                    'resource "', 'provider "', 'variable "',  # Terraform
                                    'from ', 'run ', 'copy ', 'add ',  # Dockerfile
                                    'version:', 'services:', 'volumes:',  # Docker Compose
                                    'resources:', 'parameters:', 'awstemplateformatversion',  # CloudFormation
                                    'subscription_id', 'resource_group_name',  # Azure
                                    'hosts:', 'tasks:', 'vars:'  # Ansible
                                ]
                                
                                if any(pattern in content for pattern in iac_patterns):
                                    logger.debug(f"Content-based IaC detection: {file_path}")
                                    iac_files.append(file_path)
                                    
                        except Exception:
                            continue  # Skip files that can't be read
        
        except Exception as e:
            logger.warning(f"Error scanning for IaC files: {e}")
        
        logger.debug(f"Found {len(iac_files)} Infrastructure as Code files")
        return iac_files