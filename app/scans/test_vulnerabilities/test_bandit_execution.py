#!/usr/bin/env python3
"""
Bandit Tool Execution Test and Debugger
Tests Bandit runner execution through scanner engine and directly
"""

import asyncio
import logging
import os
import sys
import tempfile
import shutil
import json
from pathlib import Path

# Add app root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from app.scans.tools.bandit_runner import BanditRunner
from app.scans.scanner_engine import ScannerEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BanditTester:
    """Test Bandit tool execution and debug issues"""
    
    def __init__(self):
        self.bandit_runner = BanditRunner()
        self.scanner_engine = ScannerEngine()
        self.test_dir = None
    
    async def run_comprehensive_test(self):
        """Run comprehensive Bandit testing"""
        logger.info("🔍 Starting Comprehensive Bandit Testing")
        
        results = {
            'availability_test': None,
            'direct_execution': None,
            'scanner_engine_integration': None,
            'vulnerability_detection': None
        }
        
        try:
            # Setup test environment
            await self.setup_test_environment()
            
            # Test 1: Tool availability
            results['availability_test'] = await self.test_tool_availability()
            
            # Test 2: Direct execution
            results['direct_execution'] = await self.test_direct_execution()
            
            # Test 3: Scanner engine integration
            results['scanner_engine_integration'] = await self.test_scanner_engine_integration()
            
            # Test 4: Vulnerability detection capabilities
            results['vulnerability_detection'] = await self.test_vulnerability_detection()
            
            # Print comprehensive report
            self.print_test_report(results)
            
        except Exception as e:
            logger.error(f"❌ Test failed: {str(e)}", exc_info=True)
            results['error'] = str(e)
        finally:
            await self.cleanup()
        
        return results
    
    async def setup_test_environment(self):
        """Setup test environment with vulnerable Python code"""
        self.test_dir = tempfile.mkdtemp(prefix="bandit_test_")
        logger.info(f"Test directory: {self.test_dir}")
        
        # Create vulnerable Python file
        vulnerable_code = '''
#!/usr/bin/env python3
"""
Intentionally vulnerable Python code for Bandit testing
Contains multiple security issues that Bandit should detect
"""

import pickle
import subprocess
import hashlib
import random
import os
import yaml
from flask import Flask

app = Flask(__name__)

# B105: hardcoded_password_string - HIGH severity
PASSWORD = "admin123"
SECRET_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://user:password123@localhost/db"

# B108: hardcoded_bind_all_interfaces - MEDIUM severity  
def start_server():
    host = "0.0.0.0"  # Binding to all interfaces
    return host

# B102: exec_used - HIGH severity
def execute_user_code(user_input):
    exec(user_input)  # Direct code execution

# B301: pickle usage - HIGH severity
def load_user_data(data):
    return pickle.loads(data)  # Unsafe deserialization

# B602: subprocess_popen_with_shell_equals_true - HIGH severity
def run_system_command(command):
    subprocess.Popen(command, shell=True)  # Shell injection

# B608: possible_sql_injection - MEDIUM severity
def get_user_by_name(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query

# B303: md5_insecure_hash - MEDIUM severity
def hash_user_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# B311: random_module_for_security - LOW severity
def generate_session_token():
    return str(random.randint(100000, 999999))

# B107: hardcoded_password_default - MEDIUM severity
def connect_to_database(password="defaultpassword"):
    return f"Connected with {password}"

# B506: yaml_load_unsafe - HIGH severity
def parse_config_file(config_data):
    return yaml.load(config_data)

# B324: hashlib_new_insecure_functions - MEDIUM severity
def create_weak_hash(data):
    return hashlib.new('md5', data.encode()).hexdigest()

# B110: try_except_pass - LOW severity
def risky_database_operation():
    try:
        # Simulate database operation
        result = 1 / 0
    except:
        pass  # Silent failure - bad practice

# B609: linux_commands_wildcard_injection - HIGH severity
def backup_user_files(directory):
    cmd = f"tar -czf backup.tar.gz {directory}/*"
    os.system(cmd)

# Flask-specific issues
# B201: flask_debug_true - HIGH severity
app.debug = True  # Debug mode in production

@app.route('/execute')
def execute_command():
    # B602: Command injection via subprocess
    user_cmd = request.args.get('cmd', '')
    subprocess.call(user_cmd, shell=True)
    return "Command executed"

# B506: Unsafe YAML loading in route
@app.route('/config')
def load_config():
    config_data = request.get_data()
    config = yaml.load(config_data)  # Unsafe YAML loading
    return str(config)

if __name__ == "__main__":
    # Multiple security issues in main
    print("Starting vulnerable application...")
    
    # Use hardcoded credentials
    db_connection = connect_to_database(PASSWORD)
    
    # Generate weak token
    token = generate_session_token()
    
    # Create weak hash
    user_hash = hash_user_password("user123")
    
    print(f"DB: {db_connection}, Token: {token}, Hash: {user_hash}")
    
    # Start server on all interfaces
    host = start_server()
    app.run(host=host, debug=True)  # Another debug=True issue
'''
        
        # Write vulnerable code to test file
        test_file = os.path.join(self.test_dir, 'vulnerable_app.py')
        with open(test_file, 'w') as f:
            f.write(vulnerable_code)
        
        # Create additional test files
        additional_files = {
            'config.py': '''
# Configuration with secrets
SECRET_KEY = "super-secret-key-123"
DATABASE_PASSWORD = "admin123"
API_TOKEN = "token-abc-123-def"
''',
            'utils.py': '''
import pickle
import subprocess

def serialize_object(obj):
    return pickle.dumps(obj)  # B301
    
def execute_shell(cmd):
    return subprocess.call(cmd, shell=True)  # B602
''',
            'requirements.txt': '''
flask==0.12.4
django==1.11.0
pyyaml==3.13
requests==2.18.0
'''
        }
        
        for filename, content in additional_files.items():
            with open(os.path.join(self.test_dir, filename), 'w') as f:
                f.write(content)
        
        logger.info(f"✅ Created test files in {self.test_dir}")
    
    async def test_tool_availability(self):
        """Test if Bandit tool is available"""
        logger.info("🔧 Testing Bandit availability...")
        
        try:
            available = self.bandit_runner._check_tool_availability()
            
            result = {
                'available': available,
                'suggestion': self.bandit_runner._get_installation_suggestion() if not available else None
            }
            
            status = "✅" if available else "❌"
            logger.info(f"{status} Bandit availability: {available}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Availability test failed: {str(e)}")
            return {'available': False, 'error': str(e)}
    
    async def test_direct_execution(self):
        """Test direct Bandit runner execution"""
        logger.info("🚀 Testing direct Bandit execution...")
        
        try:
            # Run Bandit on test directory
            result = await self.bandit_runner.run(self.test_dir)
            
            issues = result.get('issues', [])
            has_error = 'error' in result
            
            analysis = {
                'success': not has_error,
                'issues_found': len(issues),
                'error': result.get('error'),
                'duration': result.get('duration', 0),
                'metadata': result.get('metadata', {}),
                'issue_breakdown': self.analyze_issues(issues)
            }
            
            status = "✅" if not has_error else "❌"
            logger.info(f"{status} Direct execution: {len(issues)} issues found")
            
            if has_error:
                logger.error(f"   Error: {result.get('error')}")
            else:
                # Log issue breakdown
                for severity, count in analysis['issue_breakdown'].items():
                    if count > 0:
                        logger.info(f"   {severity}: {count} issues")
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Direct execution failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def test_scanner_engine_integration(self):
        """Test Bandit through scanner engine"""
        logger.info("🔧 Testing Scanner Engine integration...")
        
        try:
            # Create file list for CLI-style scan
            file_list = []
            for root, dirs, files in os.walk(self.test_dir):
                for file in files:
                    if file.endswith('.py'):
                        file_list.append(os.path.join(root, file))
            
            logger.info(f"Testing with {len(file_list)} Python files")
            
            # Run comprehensive scan through scanner engine
            scan_result = await self.scanner_engine.run_comprehensive_scan(
                repo_full_name="test/bandit-integration",
                branch="main",
                scope="full",
                mode="comprehensive",
                niche="general",
                gh_token="dummy_token",
                scan_type="cli",
                file_list=file_list
            )
            
            success = scan_result.get('success', False)
            total_issues = len(scan_result.get('issues', []))
            tools_used = scan_result.get('metadata', {}).get('tools_used', [])
            
            # Filter for Bandit issues specifically
            bandit_issues = [
                issue for issue in scan_result.get('issues', [])
                if issue.get('tool') == 'bandit'
            ]
            
            analysis = {
                'success': success,
                'total_issues': total_issues,
                'bandit_issues': len(bandit_issues),
                'tools_used': tools_used,
                'bandit_in_tools': 'bandit' in tools_used,
                'error': scan_result.get('error'),
                'metadata': scan_result.get('metadata', {}),
                'bandit_issue_breakdown': self.analyze_issues(bandit_issues)
            }
            
            status = "✅" if success and len(bandit_issues) > 0 else "⚠️ "
            logger.info(f"{status} Scanner engine: {len(bandit_issues)} Bandit issues (of {total_issues} total)")
            
            if 'bandit' not in tools_used:
                logger.warning("   ⚠️  Bandit was not included in selected tools!")
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Scanner engine test failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    async def test_vulnerability_detection(self):
        """Test specific vulnerability detection capabilities"""
        logger.info("🔍 Testing vulnerability detection capabilities...")
        
        try:
            # Run Bandit and analyze specific vulnerability types
            result = await self.bandit_runner.run(self.test_dir)
            issues = result.get('issues', [])
            
            # Expected vulnerabilities and their Bandit test IDs
            expected_vulnerabilities = {
                'hardcoded_password': ['B105', 'B106', 'B107'],
                'command_injection': ['B602', 'B609'],
                'code_injection': ['B102'],
                'insecure_deserialization': ['B301'],
                'weak_cryptography': ['B303', 'B324'],
                'sql_injection': ['B608'],
                'yaml_unsafe_load': ['B506'],
                'random_for_security': ['B311'],
                'try_except_pass': ['B110']
            }
            
            detected_vulnerabilities = {}
            for vuln_type, test_ids in expected_vulnerabilities.items():
                detected = [
                    issue for issue in issues
                    if issue.get('rule_id') in test_ids
                ]
                detected_vulnerabilities[vuln_type] = {
                    'count': len(detected),
                    'test_ids_found': list(set(issue.get('rule_id') for issue in detected)),
                    'expected_test_ids': test_ids,
                    'coverage': len(set(issue.get('rule_id') for issue in detected)) / len(test_ids) * 100
                }
            
            # Overall detection statistics
            total_expected = sum(len(test_ids) for test_ids in expected_vulnerabilities.values())
            total_detected = len(set(issue.get('rule_id') for issue in issues))
            
            analysis = {
                'total_issues': len(issues),
                'unique_rule_ids': len(set(issue.get('rule_id') for issue in issues)),
                'expected_vulnerability_types': len(expected_vulnerabilities),
                'detected_vulnerabilities': detected_vulnerabilities,
                'detection_coverage': (total_detected / total_expected) * 100 if total_expected > 0 else 0,
                'severity_breakdown': self.analyze_issues(issues)
            }
            
            logger.info(f"✅ Vulnerability detection: {len(issues)} total issues")
            logger.info(f"   Detection coverage: {analysis['detection_coverage']:.1f}%")
            
            # Log detection results for each vulnerability type
            for vuln_type, data in detected_vulnerabilities.items():
                if data['count'] > 0:
                    logger.info(f"   ✅ {vuln_type}: {data['count']} issues ({data['coverage']:.0f}% coverage)")
                else:
                    logger.warning(f"   ❌ {vuln_type}: No issues detected")
            
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Vulnerability detection test failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def analyze_issues(self, issues):
        """Analyze issues by severity and other metrics"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for issue in issues:
            severity = issue.get('severity', 'medium').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return severity_counts
    
    def print_test_report(self, results):
        """Print comprehensive test report"""
        print("\n" + "="*80)
        print("BANDIT TOOL EXECUTION TEST REPORT")
        print("="*80)
        
        # Availability Test
        availability = results.get('availability_test', {})
        status = "✅ AVAILABLE" if availability.get('available') else "❌ NOT AVAILABLE"
        print(f"Tool Availability: {status}")
        if not availability.get('available') and availability.get('suggestion'):
            print(f"Installation: {availability['suggestion']}")
        
        print()
        
        # Direct Execution Test
        direct = results.get('direct_execution', {})
        if direct:
            status = "✅ SUCCESS" if direct.get('success') else "❌ FAILED"
            print(f"Direct Execution: {status}")
            print(f"  Issues Found: {direct.get('issues_found', 0)}")
            print(f"  Duration: {direct.get('duration', 0):.2f}s")
            
            breakdown = direct.get('issue_breakdown', {})
            for severity, count in breakdown.items():
                if count > 0:
                    print(f"  {severity.title()}: {count}")
            
            if direct.get('error'):
                print(f"  Error: {direct['error']}")
        
        print()
        
        # Scanner Engine Integration
        scanner = results.get('scanner_engine_integration', {})
        if scanner:
            status = "✅ SUCCESS" if scanner.get('success') else "❌ FAILED"
            print(f"Scanner Engine Integration: {status}")
            print(f"  Total Issues: {scanner.get('total_issues', 0)}")
            print(f"  Bandit Issues: {scanner.get('bandit_issues', 0)}")
            print(f"  Bandit in Tools: {scanner.get('bandit_in_tools', False)}")
            
            if scanner.get('error'):
                print(f"  Error: {scanner['error']}")
        
        print()
        
        # Vulnerability Detection
        detection = results.get('vulnerability_detection', {})
        if detection:
            print("Vulnerability Detection Analysis:")
            print(f"  Total Issues: {detection.get('total_issues', 0)}")
            print(f"  Detection Coverage: {detection.get('detection_coverage', 0):.1f}%")
            
            detected_vulns = detection.get('detected_vulnerabilities', {})
            for vuln_type, data in detected_vulns.items():
                status = "✅" if data['count'] > 0 else "❌"
                print(f"  {status} {vuln_type}: {data['count']} issues ({data['coverage']:.0f}% coverage)")
        
        print("\n" + "="*80)
    
    async def cleanup(self):
        """Clean up test environment"""
        if self.test_dir and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
            logger.info("🧹 Cleaned up test environment")

async def main():
    """Main entry point"""
    tester = BanditTester()
    
    try:
        results = await tester.run_comprehensive_test()
        
        # Save results to JSON file
        output_file = "bandit_test_results.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\nDetailed results saved to: {output_file}")
        
        # Return appropriate exit code
        availability = results.get('availability_test', {})
        direct = results.get('direct_execution', {})
        
        if not availability.get('available'):
            return 2  # Tool not available
        elif not direct.get('success'):
            return 1  # Execution failed
        else:
            return 0  # Success
            
    except Exception as e:
        logger.error(f"Main execution failed: {str(e)}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(asyncio.run(main()))