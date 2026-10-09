#!/usr/bin/env python3
"""
Security Tools Debug and Validation Script
Comprehensive debugging toolkit for DevSecureX security tools
"""

import asyncio
import logging
import os
import sys
import subprocess
import shutil
import json
import time
import tempfile
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# Add app root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from app.scans.scanner_engine import ScannerEngine
from app.scans.base_runner import BaseToolRunner

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityToolsDebugger:
    """Comprehensive debugging system for security tools"""
    
    def __init__(self):
        self.scanner_engine = ScannerEngine()
        self.debug_results = {}
        
        # Tool command mappings for direct testing
        self.tool_commands = {
            'bandit': ['bandit', '--version'],
            'semgrep': ['semgrep', '--version'],
            'gitleaks': ['gitleaks', 'version'],
            'gosec': ['gosec', '--version'],
            'eslint-security': ['eslint', '--version'],
            'trivy': ['trivy', '--version'],
            'checkov': ['checkov', '--version'],
            'safety': ['safety', '--version'],
            'trufflehog': ['trufflehog', '--version'],
            'spotbugs': ['spotbugs', '-version'],
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # 'roslynator': ['roslynator', '--version'],
            'psalm': ['psalm', '--version'],
            'brakeman': ['brakeman', '--version'],
            'cppcheck': ['cppcheck', '--version']
        }
    
    async def run_comprehensive_debug(self) -> Dict[str, Any]:
        """Run comprehensive debugging of all security tools"""
        logger.info("🔍 Starting Comprehensive Security Tools Debugging")
        
        start_time = time.time()
        self.debug_results = {
            'timestamp': datetime.now().isoformat(),
            'environment_check': {},
            'tool_availability': {},
            'command_line_tests': {},
            'scanner_engine_debug': {},
            'tool_runner_tests': {},
            'common_issues': {},
            'recommendations': []
        }
        
        try:
            # Step 1: Environment checks
            await self.check_environment()
            
            # Step 2: Tool availability checks
            await self.check_tool_availability_detailed()
            
            # Step 3: Command line tests
            await self.test_tools_command_line()
            
            # Step 4: Scanner engine debugging
            await self.debug_scanner_engine()
            
            # Step 5: Tool runner tests
            await self.test_tool_runners()
            
            # Step 6: Identify common issues
            await self.identify_common_issues()
            
            # Step 7: Generate recommendations
            self.generate_debug_recommendations()
            
            duration = time.time() - start_time
            self.debug_results['duration'] = duration
            
            logger.info(f"✅ Debug analysis completed in {duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"❌ Debug analysis failed: {str(e)}", exc_info=True)
            self.debug_results['error'] = str(e)
        
        return self.debug_results
    
    async def check_environment(self):
        """Check system environment for security tool requirements"""
        logger.info("🔧 Checking system environment")
        
        env_info = {
            'python_version': sys.version,
            'platform': sys.platform,
            'path_directories': os.environ.get('PATH', '').split(':'),
            'current_directory': os.getcwd(),
            'temp_directory': tempfile.gettempdir()
        }
        
        # Check for common tool installation locations
        common_locations = [
            '/usr/bin', '/usr/local/bin', '/opt/bin',
            os.path.expanduser('~/.local/bin'),
            os.path.expanduser('~/.cargo/bin'),
            os.path.expanduser('~/.go/bin'),
            '/opt/tools/bin'  # Docker container location
        ]
        
        existing_locations = []
        for location in common_locations:
            if os.path.exists(location):
                existing_locations.append({
                    'path': location,
                    'files': len(os.listdir(location)) if os.path.isdir(location) else 0
                })
        
        env_info['tool_directories'] = existing_locations
        
        # Check for package managers
        package_managers = ['pip', 'npm', 'go', 'cargo', 'gem', 'composer']
        available_managers = {}
        
        for pm in package_managers:
            available_managers[pm] = shutil.which(pm) is not None
        
        env_info['package_managers'] = available_managers
        
        self.debug_results['environment_check'] = env_info
        logger.info(f"✅ Environment check: {len(existing_locations)} tool directories found")
    
    async def check_tool_availability_detailed(self):
        """Detailed tool availability checking with diagnostics"""
        logger.info("🔧 Performing detailed tool availability checks")
        
        for tool_name, version_cmd in self.tool_commands.items():
            tool_info = {
                'command': version_cmd,
                'executable_path': None,
                'version_check': {},
                'availability': False,
                'issues': []
            }
            
            try:
                # Check if executable exists in PATH
                executable_path = shutil.which(version_cmd[0])
                tool_info['executable_path'] = executable_path
                
                if not executable_path:
                    tool_info['issues'].append(f"Executable '{version_cmd[0]}' not found in PATH")
                    tool_info['availability'] = False
                else:
                    # Try version check
                    try:
                        result = subprocess.run(
                            version_cmd,
                            capture_output=True,
                            text=True,
                            timeout=10,
                            check=False
                        )
                        
                        tool_info['version_check'] = {
                            'returncode': result.returncode,
                            'stdout': result.stdout[:500],  # First 500 chars
                            'stderr': result.stderr[:500],  # First 500 chars
                            'success': result.returncode == 0
                        }
                        
                        tool_info['availability'] = result.returncode == 0
                        
                        if result.returncode != 0:
                            tool_info['issues'].append(f"Version check failed with exit code {result.returncode}")
                        
                    except subprocess.TimeoutExpired:
                        tool_info['issues'].append("Version check timed out")
                        tool_info['availability'] = False
                    except Exception as e:
                        tool_info['issues'].append(f"Version check error: {str(e)}")
                        tool_info['availability'] = False
                
            except Exception as e:
                tool_info['issues'].append(f"General error: {str(e)}")
                tool_info['availability'] = False
            
            self.debug_results['tool_availability'][tool_name] = tool_info
            
            status = "✅" if tool_info['availability'] else "❌"
            logger.info(f"{status} {tool_name}: {'Available' if tool_info['availability'] else 'Issues found'}")
            
            if tool_info['issues']:
                for issue in tool_info['issues']:
                    logger.debug(f"   Issue: {issue}")
    
    async def test_tools_command_line(self):
        """Test tools directly via command line"""
        logger.info("🚀 Testing tools via command line")
        
        # Create minimal test files
        test_dir = tempfile.mkdtemp(prefix="cli_test_")
        
        try:
            # Create minimal vulnerable files
            test_files = {
                'test.py': 'password = "admin123"\nimport os\nos.system("ls")',
                'test.js': 'const secret = "api-key-123";\neval(userInput);',
                'test.go': 'package main\nconst password = "admin123"\nfunc main() {}',
                '.env': 'SECRET_KEY=sk-test-12345\nAPI_TOKEN=token-abc-123'
            }
            
            for filename, content in test_files.items():
                with open(os.path.join(test_dir, filename), 'w') as f:
                    f.write(content)
            
            # Test specific tools with minimal configurations
            test_configs = {
                'bandit': {
                    'command': ['bandit', '-f', 'json', '-r', test_dir],
                    'expected_issues': True,
                    'timeout': 30
                },
                'semgrep': {
                    'command': ['semgrep', '--config=auto', '--json', test_dir],
                    'expected_issues': True,
                    'timeout': 60
                },
                'gitleaks': {
                    'command': ['gitleaks', 'detect', '--source', test_dir, '--report-format', 'json', '--no-git'],
                    'expected_issues': True,
                    'timeout': 30
                },
                'gosec': {
                    'command': ['gosec', '-fmt=json', '-stdout', os.path.join(test_dir, 'test.go')],
                    'expected_issues': True,
                    'timeout': 30
                }
            }
            
            for tool_name, config in test_configs.items():
                if not self.debug_results['tool_availability'][tool_name]['availability']:
                    logger.info(f"⚠️  Skipping {tool_name} - not available")
                    continue
                
                logger.info(f"Testing {tool_name} command line execution...")
                
                test_result = {
                    'command': config['command'],
                    'execution_success': False,
                    'issues_found': False,
                    'output_length': 0,
                    'error_details': None
                }
                
                try:
                    result = subprocess.run(
                        config['command'],
                        capture_output=True,
                        text=True,
                        timeout=config['timeout'],
                        check=False,
                        cwd=test_dir if tool_name == 'gosec' else None
                    )
                    
                    test_result['returncode'] = result.returncode
                    test_result['stdout_length'] = len(result.stdout)
                    test_result['stderr_length'] = len(result.stderr)
                    
                    # Most security tools return 0 when no issues, 1+ when issues found
                    test_result['execution_success'] = result.returncode in [0, 1, 2]
                    test_result['issues_found'] = result.returncode > 0 and result.stdout
                    
                    if result.stdout:
                        # Try to parse JSON output if possible
                        try:
                            if tool_name in ['bandit', 'semgrep', 'gitleaks']:
                                json_data = json.loads(result.stdout)
                                if tool_name == 'bandit':
                                    test_result['parsed_issues'] = len(json_data.get('results', []))
                                elif tool_name == 'semgrep':
                                    test_result['parsed_issues'] = len(json_data.get('results', []))
                                elif tool_name == 'gitleaks':
                                    test_result['parsed_issues'] = len(json_data) if isinstance(json_data, list) else 0
                        except json.JSONDecodeError:
                            test_result['json_parse_error'] = True
                    
                    if result.stderr:
                        test_result['stderr_preview'] = result.stderr[:200]
                    
                except subprocess.TimeoutExpired:
                    test_result['error_details'] = f"Command timed out after {config['timeout']} seconds"
                except Exception as e:
                    test_result['error_details'] = str(e)
                
                self.debug_results['command_line_tests'][tool_name] = test_result
                
                status = "✅" if test_result['execution_success'] else "❌"
                issues_info = f", {test_result.get('parsed_issues', 0)} issues" if test_result.get('parsed_issues') else ""
                logger.info(f"{status} {tool_name} CLI: Success={test_result['execution_success']}{issues_info}")
        
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)
    
    async def debug_scanner_engine(self):
        """Debug scanner engine tool selection and execution"""
        logger.info("🔧 Debugging scanner engine")
        
        debug_info = {
            'tool_detection': {},
            'tool_selection': {},
            'execution_flow': {}
        }
        
        try:
            # Test tool detection
            if hasattr(self.scanner_engine, '_detect_available_tools'):
                available_tools = self.scanner_engine._detect_available_tools()
                debug_info['tool_detection'] = {
                    'available_tools': available_tools,
                    'available_count': sum(1 for available in available_tools.values() if available),
                    'total_tools': len(available_tools)
                }
            
            # Test language detection
            test_dir = tempfile.mkdtemp(prefix="scanner_debug_")
            try:
                # Create test files
                test_files = {
                    'app.py': 'print("Hello Python")',
                    'script.js': 'console.log("Hello JavaScript");',
                    'main.go': 'package main\nfunc main() {}',
                    'Dockerfile': 'FROM ubuntu:20.04\nRUN apt-get update'
                }
                
                for filename, content in test_files.items():
                    with open(os.path.join(test_dir, filename), 'w') as f:
                        f.write(content)
                
                # Test language detection
                if hasattr(self.scanner_engine, '_detect_languages_from_files'):
                    file_list = [os.path.join(test_dir, f) for f in test_files.keys()]
                    languages = self.scanner_engine._detect_languages_from_files(file_list)
                    debug_info['language_detection'] = {
                        'detected_languages': languages,
                        'language_count': len(languages)
                    }
                
                # Test tool selection
                if hasattr(self.scanner_engine, '_select_tools_intelligently'):
                    selected_tools = self.scanner_engine._select_tools_intelligently(
                        scope='full',
                        mode='comprehensive',
                        niche='general',
                        languages=languages if 'languages' in locals() else {'Python': 1000},
                        file_list=file_list
                    )
                    debug_info['tool_selection'] = {
                        'selected_tools': list(selected_tools),
                        'selected_count': len(selected_tools),
                        'tool_breakdown': self.analyze_tool_selection(selected_tools)
                    }
            
            finally:
                shutil.rmtree(test_dir, ignore_errors=True)
        
        except Exception as e:
            debug_info['error'] = str(e)
            logger.error(f"Scanner engine debug failed: {str(e)}")
        
        self.debug_results['scanner_engine_debug'] = debug_info
    
    async def test_tool_runners(self):
        """Test individual tool runners"""
        logger.info("🔧 Testing individual tool runners")
        
        # Import available tool runners
        tool_runners = {}
        
        try:
            from app.scans.tools.bandit_runner import BanditRunner
            tool_runners['bandit'] = BanditRunner()
        except ImportError:
            pass
        
        try:
            from app.scans.tools.semgrep_runner import SemgrepRunner
            tool_runners['semgrep'] = SemgrepRunner()
        except ImportError:
            pass
        
        try:
            from app.scans.tools.gitleaks_runner import GitLeaksRunner
            tool_runners['gitleaks'] = GitLeaksRunner()
        except ImportError:
            pass
        
        try:
            from app.scans.tools.gosec_runner import GosecRunner
            tool_runners['gosec'] = GosecRunner()
        except ImportError:
            pass
        
        for tool_name, runner in tool_runners.items():
            logger.info(f"Testing {tool_name} runner...")
            
            runner_test = {
                'availability_check': None,
                'instantiation_success': True,
                'method_tests': {}
            }
            
            try:
                # Test availability check
                if hasattr(runner, '_check_tool_availability'):
                    availability = runner._check_tool_availability()
                    runner_test['availability_check'] = availability
                
                # Test method existence
                required_methods = ['run', '_check_tool_availability']
                for method_name in required_methods:
                    runner_test['method_tests'][method_name] = hasattr(runner, method_name)
                
                # Test timeout setting
                if hasattr(runner, 'timeout'):
                    runner_test['timeout_configured'] = runner.timeout
                
                # Test tool name
                if hasattr(runner, 'tool_name'):
                    runner_test['tool_name'] = runner.tool_name
            
            except Exception as e:
                runner_test['instantiation_success'] = False
                runner_test['error'] = str(e)
            
            self.debug_results['tool_runner_tests'][tool_name] = runner_test
    
    def analyze_tool_selection(self, selected_tools: set) -> Dict[str, Any]:
        """Analyze tool selection patterns"""
        categories = {
            'secret_detection': ['gitleaks', 'trufflehog', 'semgrep'],
            'code_analysis': ['bandit', 'semgrep', 'gosec', 'eslint-security'],
            'dependency_analysis': ['safety', 'trivy'],
            'infrastructure': ['checkov', 'trivy'],
            # DISABLED: Removed 'roslynator' from language_specific tools - C#/.NET tool not installed
            'language_specific': ['bandit', 'gosec', 'eslint-security', 'spotbugs', 'psalm', 'brakeman', 'cppcheck']
        }
        
        analysis = {}
        for category, tools in categories.items():
            selected_in_category = [tool for tool in tools if tool in selected_tools]
            analysis[category] = {
                'selected': selected_in_category,
                'count': len(selected_in_category),
                'percentage': len(selected_in_category) / len(tools) * 100
            }
        
        return analysis
    
    async def identify_common_issues(self):
        """Identify common issues across tools"""
        logger.info("🔍 Identifying common issues")
        
        common_issues = {
            'missing_tools': [],
            'permission_issues': [],
            'configuration_issues': [],
            'version_incompatibilities': [],
            'path_issues': []
        }
        
        # Analyze tool availability results
        for tool_name, info in self.debug_results['tool_availability'].items():
            if not info['availability']:
                if not info['executable_path']:
                    common_issues['missing_tools'].append(tool_name)
                elif 'permission' in str(info.get('issues', [])).lower():
                    common_issues['permission_issues'].append(tool_name)
                elif info.get('version_check', {}).get('returncode') != 0:
                    common_issues['version_incompatibilities'].append(tool_name)
        
        # Analyze command line test results
        for tool_name, test_info in self.debug_results['command_line_tests'].items():
            if not test_info.get('execution_success'):
                if 'not found' in str(test_info.get('error_details', '')):
                    if tool_name not in common_issues['missing_tools']:
                        common_issues['missing_tools'].append(tool_name)
                elif 'permission' in str(test_info.get('error_details', '')).lower():
                    common_issues['permission_issues'].append(tool_name)
        
        self.debug_results['common_issues'] = common_issues
        
        # Log issues found
        for issue_type, tools in common_issues.items():
            if tools:
                logger.warning(f"⚠️  {issue_type}: {', '.join(tools)}")
    
    def generate_debug_recommendations(self):
        """Generate debugging recommendations"""
        recommendations = []
        
        # Tool installation recommendations
        missing_tools = self.debug_results['common_issues']['missing_tools']
        if missing_tools:
            recommendations.append({
                'category': 'Installation',
                'priority': 'High',
                'issue': f'Missing tools: {", ".join(missing_tools)}',
                'solution': 'Install missing security tools using package managers or Docker'
            })
        
        # Permission issues
        permission_issues = self.debug_results['common_issues']['permission_issues']
        if permission_issues:
            recommendations.append({
                'category': 'Permissions',
                'priority': 'Medium',
                'issue': f'Permission issues: {", ".join(permission_issues)}',
                'solution': 'Check file permissions and user access rights'
            })
        
        # Configuration issues
        config_issues = self.debug_results['common_issues']['configuration_issues']
        if config_issues:
            recommendations.append({
                'category': 'Configuration',
                'priority': 'Medium',
                'issue': f'Configuration issues: {", ".join(config_issues)}',
                'solution': 'Review tool configurations and environment settings'
            })
        
        # Scanner engine recommendations
        scanner_debug = self.debug_results.get('scanner_engine_debug', {})
        if 'error' in scanner_debug:
            recommendations.append({
                'category': 'Scanner Engine',
                'priority': 'High',
                'issue': 'Scanner engine has errors',
                'solution': 'Debug scanner engine initialization and tool integration'
            })
        
        # Tool selection recommendations
        tool_selection = scanner_debug.get('tool_selection', {})
        if tool_selection and tool_selection.get('selected_count', 0) < 5:
            recommendations.append({
                'category': 'Tool Selection',
                'priority': 'Medium',
                'issue': 'Low number of tools selected',
                'solution': 'Review tool selection logic and language detection'
            })
        
        self.debug_results['recommendations'] = recommendations
        logger.info(f"📋 Generated {len(recommendations)} debugging recommendations")
    
    def save_debug_results(self, output_file: str):
        """Save debug results to file"""
        with open(output_file, 'w') as f:
            json.dump(self.debug_results, f, indent=2, default=str)
        logger.info(f"💾 Debug results saved to {output_file}")
    
    def print_debug_summary(self):
        """Print comprehensive debug summary"""
        print("\n" + "="*80)
        print("SECURITY TOOLS DEBUG SUMMARY")
        print("="*80)
        
        # Environment summary
        env = self.debug_results.get('environment_check', {})
        print(f"Environment: {env.get('platform', 'unknown')}")
        print(f"Python: {env.get('python_version', 'unknown')[:20]}...")
        print(f"Tool directories: {len(env.get('tool_directories', []))}")
        
        # Tool availability summary
        availability = self.debug_results.get('tool_availability', {})
        available_count = sum(1 for tool in availability.values() if tool.get('availability'))
        total_count = len(availability)
        print(f"Tools available: {available_count}/{total_count} ({available_count/total_count*100:.1f}%)")
        
        # Command line test summary
        cli_tests = self.debug_results.get('command_line_tests', {})
        successful_cli = sum(1 for test in cli_tests.values() if test.get('execution_success'))
        print(f"CLI tests successful: {successful_cli}/{len(cli_tests)} ({successful_cli/len(cli_tests)*100:.1f}%)" if cli_tests else "CLI tests: No tests run")
        
        # Common issues
        common_issues = self.debug_results.get('common_issues', {})
        total_issues = sum(len(issues) for issues in common_issues.values())
        print(f"Common issues identified: {total_issues}")
        
        # Recommendations
        recommendations = self.debug_results.get('recommendations', [])
        high_priority = len([r for r in recommendations if r.get('priority') == 'High'])
        print(f"Recommendations: {len(recommendations)} total, {high_priority} high priority")
        
        print(f"Debug duration: {self.debug_results.get('duration', 0):.2f} seconds")
        print("="*80)

async def main():
    """Main entry point for debugging script"""
    debugger = SecurityToolsDebugger()
    
    try:
        results = await debugger.run_comprehensive_debug()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"security_tools_debug_{timestamp}.json"
        debugger.save_debug_results(output_file)
        
        # Print summary
        debugger.print_debug_summary()
        
        # Print detailed recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            print("\nDETAILED RECOMMENDATIONS:")
            print("-" * 50)
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. [{rec['priority']}] {rec['category']}")
                print(f"   Issue: {rec['issue']}")
                print(f"   Solution: {rec['solution']}\n")
        
        print(f"Detailed debug results saved to: {output_file}")
        
        # Return appropriate exit code
        missing_tools = results.get('common_issues', {}).get('missing_tools', [])
        if missing_tools:
            return 2  # Critical tools missing
        elif recommendations:
            return 1  # Issues found
        else:
            return 0  # All good
            
    except Exception as e:
        logger.error(f"Main execution failed: {str(e)}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(asyncio.run(main()))