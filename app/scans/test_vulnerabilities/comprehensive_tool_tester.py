#!/usr/bin/env python3
"""
Comprehensive Security Tools Tester for DevSecureX
Tests all 7 priority security tools against vulnerable code samples to validate detection capabilities.

Priority Tools for Testing:
1. Bandit - Python security scanner
2. ESLint Security - JavaScript/TypeScript security  
3. Gosec - Go security scanner
4. SpotBugs - Java security scanner
5. Cppcheck - C++ security scanner
6. Brakeman - Ruby security scanner
7. Psalm - PHP security scanner
"""

import asyncio
import json
import logging
import os
import sys
import tempfile
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the parent directories to Python path to import scanner modules
current_dir = Path(__file__).parent
scanner_dir = current_dir.parent
app_dir = scanner_dir.parent
sys.path.insert(0, str(app_dir))
sys.path.insert(0, str(scanner_dir))

# Import our tool runners directly
from scans.tools.bandit_runner import BanditRunner
from scans.tools.eslint_security_runner import ESLintSecurityRunner
from scans.tools.gosec_runner import GosecRunner
from scans.tools.spotbugs_runner import SpotBugsRunner
from scans.tools.cppcheck_runner import CppcheckRunner
from scans.tools.brakeman_runner import BrakemanRunner
from scans.tools.psalm_runner import PsalmRunner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(current_dir / 'tool_testing_results.log')
    ]
)
logger = logging.getLogger(__name__)

class ComprehensiveToolTester:
    """Comprehensive tester for all 7 priority security tools"""
    
    def __init__(self):
        self.test_dir = current_dir
        self.results = {}
        
        # Tool configurations with their test files
        self.tool_configs = {
            'bandit': {
                'runner': BanditRunner(),
                'test_files': ['vulnerable_code.py'],
                'language': 'Python',
                'expected_min_issues': 15,  # Expect at least 15 issues from vulnerable_code.py
                'critical_rules': ['B105', 'B102', 'B301', 'B602', 'B608']
            },
            'eslint-security': {
                'runner': ESLintSecurityRunner(), 
                'test_files': ['vulnerable_javascript.js'],
                'language': 'JavaScript',
                'expected_min_issues': 8,  # Expect at least 8 security issues
                'critical_rules': ['security/detect-eval-with-expression', 'security/detect-child-process']
            },
            'gosec': {
                'runner': GosecRunner(),
                'test_files': ['vulnerable_go.go'],
                'language': 'Go',
                'expected_min_issues': 10,  # Expect at least 10 Go security issues
                'critical_rules': ['G101', 'G201', 'G204', 'G401']
            },
            'spotbugs': {
                'runner': SpotBugsRunner(),
                'test_files': ['VulnerableJava.java'],
                'language': 'Java',
                'expected_min_issues': 5,  # SpotBugs might find fewer issues due to compilation requirements
                'critical_rules': ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL']
            },
            'cppcheck': {
                'runner': CppcheckRunner(),
                'test_files': ['vulnerable_cpp.cpp'],
                'language': 'C++',
                'expected_min_issues': 12,  # Expect buffer overflows, memory leaks, etc.
                'critical_rules': ['bufferAccessOutOfBounds', 'memleakOnRealloc', 'nullPointer']
            },
            'brakeman': {
                'runner': BrakemanRunner(),
                'test_files': ['vulnerable_ruby.rb'],
                'language': 'Ruby',
                'expected_min_issues': 8,  # Expect SQL injection, XSS, command injection
                'critical_rules': ['SQL Injection', 'Command Injection', 'Cross-Site Scripting']
            },
            'psalm': {
                'runner': PsalmRunner(),
                'test_files': ['vulnerable_php.php'],
                'language': 'PHP',
                'expected_min_issues': 3,  # Psalm focuses more on type safety, may find fewer security issues
                'critical_rules': ['TaintedInput', 'TaintedSql', 'TaintedShell']
            }
        }
    
    async def run_comprehensive_tests(self) -> Dict[str, Any]:
        """Run comprehensive tests on all 7 priority security tools"""
        
        logger.info("🚀 Starting Comprehensive Security Tools Testing")
        logger.info("=" * 80)
        
        start_time = time.time()
        test_results = {
            'test_metadata': {
                'start_time': datetime.now().isoformat(),
                'test_directory': str(self.test_dir),
                'tools_tested': list(self.tool_configs.keys()),
                'total_tools': len(self.tool_configs)
            },
            'individual_results': {},
            'summary': {}
        }
        
        # Test each tool individually
        for tool_name, config in self.tool_configs.items():
            logger.info(f"\n📋 Testing {tool_name.upper()} - {config['language']} Security Scanner")
            logger.info("-" * 60)
            
            try:
                tool_result = await self._test_individual_tool(tool_name, config)
                test_results['individual_results'][tool_name] = tool_result
                
                # Log summary for this tool
                if tool_result.get('success'):
                    issues_found = len(tool_result.get('issues', []))
                    expected_min = config.get('expected_min_issues', 0)
                    status = "✅ PASSED" if issues_found >= expected_min else "⚠️  PARTIAL"
                    
                    logger.info(f"{status} - {tool_name}: Found {issues_found} issues (expected: {expected_min}+)")
                else:
                    logger.error(f"❌ FAILED - {tool_name}: {tool_result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                logger.error(f"❌ EXCEPTION - {tool_name}: {str(e)}")
                test_results['individual_results'][tool_name] = {
                    'success': False,
                    'error': f"Test exception: {str(e)}",
                    'issues': [],
                    'duration': 0
                }
        
        # Generate comprehensive summary
        test_results['summary'] = self._generate_test_summary(test_results['individual_results'])
        test_results['test_metadata']['duration'] = time.time() - start_time
        test_results['test_metadata']['end_time'] = datetime.now().isoformat()
        
        # Save results to file
        await self._save_test_results(test_results)
        
        # Print final summary
        self._print_final_summary(test_results)
        
        return test_results
    
    async def _test_individual_tool(self, tool_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test an individual security tool against its vulnerable code samples"""
        
        start_time = time.time()
        
        # Create temporary directory for testing
        with tempfile.TemporaryDirectory(prefix=f"devsecurex_{tool_name}_test_") as temp_dir:
            try:
                # Copy test files to temp directory
                test_files = []
                for test_file in config['test_files']:
                    source_path = self.test_dir / test_file
                    if source_path.exists():
                        dest_path = Path(temp_dir) / test_file
                        shutil.copy2(source_path, dest_path)
                        test_files.append(str(dest_path))
                        logger.info(f"   📁 Copied test file: {test_file}")
                    else:
                        logger.warning(f"   ⚠️  Test file not found: {test_file}")
                
                if not test_files:
                    return {
                        'success': False,
                        'error': f"No test files found for {tool_name}",
                        'issues': [],
                        'duration': 0
                    }
                
                # Special setup for specific tools
                await self._setup_tool_environment(tool_name, temp_dir)
                
                # Run the tool
                logger.info(f"   🔧 Running {tool_name} against {len(test_files)} test files...")
                
                tool_runner = config['runner']
                result = await tool_runner.run(temp_dir, timeout_per_tool=300)  # 5 minute timeout
                
                duration = time.time() - start_time
                
                # Validate results
                validation = self._validate_tool_results(tool_name, result, config)
                
                return {
                    'success': True,
                    'tool': tool_name,
                    'language': config['language'],
                    'test_files': config['test_files'],
                    'issues': result.get('issues', []),
                    'issues_count': len(result.get('issues', [])),
                    'duration': duration,
                    'raw_result': result,
                    'validation': validation,
                    'metadata': {
                        'temp_dir': temp_dir,
                        'expected_min_issues': config.get('expected_min_issues', 0),
                        'critical_rules': config.get('critical_rules', [])
                    }
                }
                
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"   ❌ Error testing {tool_name}: {str(e)}")
                
                return {
                    'success': False,
                    'tool': tool_name,
                    'error': str(e),
                    'issues': [],
                    'duration': duration
                }
    
    async def _setup_tool_environment(self, tool_name: str, temp_dir: str):
        """Setup special environment requirements for specific tools"""
        
        if tool_name == 'gosec':
            # Create go.mod for Go files
            go_mod_content = """module temp-security-test

go 1.21

require (
    github.com/lib/pq v1.10.9
)
"""
            with open(os.path.join(temp_dir, 'go.mod'), 'w') as f:
                f.write(go_mod_content)
            
            logger.info(f"   🔧 Created go.mod for Gosec testing")
            
        elif tool_name == 'brakeman':
            # Create basic Rails-like structure for Brakeman
            app_dir = os.path.join(temp_dir, 'app')
            controllers_dir = os.path.join(app_dir, 'controllers')
            models_dir = os.path.join(app_dir, 'models')
            
            os.makedirs(controllers_dir, exist_ok=True)
            os.makedirs(models_dir, exist_ok=True)
            
            # Move Ruby file to controllers directory
            ruby_file = os.path.join(temp_dir, 'vulnerable_ruby.rb')
            if os.path.exists(ruby_file):
                controller_file = os.path.join(controllers_dir, 'vulnerable_controller.rb')
                shutil.move(ruby_file, controller_file)
            
            # Create Gemfile for Brakeman
            gemfile_content = """source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'sqlite3'
"""
            with open(os.path.join(temp_dir, 'Gemfile'), 'w') as f:
                f.write(gemfile_content)
            
            logger.info(f"   🔧 Created Rails structure for Brakeman testing")
            
        elif tool_name == 'psalm':
            # Create psalm.xml configuration
            psalm_config = """<?xml version="1.0"?>
<psalm
    errorLevel="1"
    resolveFromConfigFile="true"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="https://getpsalm.org/schema/config"
>
    <projectFiles>
        <directory name="." />
    </projectFiles>
    
    <plugins>
        <pluginClass class="Psalm\\PhpUnitPlugin\\Plugin"/>
    </plugins>
</psalm>
"""
            with open(os.path.join(temp_dir, 'psalm.xml'), 'w') as f:
                f.write(psalm_config)
                
            logger.info(f"   🔧 Created psalm.xml for Psalm testing")
    
    def _validate_tool_results(self, tool_name: str, result: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that the tool found the expected types of vulnerabilities"""
        
        issues = result.get('issues', [])
        expected_min = config.get('expected_min_issues', 0)
        critical_rules = config.get('critical_rules', [])
        
        validation = {
            'meets_minimum_threshold': len(issues) >= expected_min,
            'found_critical_rules': [],
            'missing_critical_rules': [],
            'unique_rule_types': set(),
            'severity_distribution': {}
        }
        
        # Analyze found issues
        for issue in issues:
            rule_id = issue.get('rule_id', 'unknown')
            severity = issue.get('severity', 'unknown')
            
            validation['unique_rule_types'].add(rule_id)
            validation['severity_distribution'][severity] = validation['severity_distribution'].get(severity, 0) + 1
            
            # Check if this is a critical rule we expected to find
            if any(critical_rule in rule_id or rule_id in critical_rule for critical_rule in critical_rules):
                if rule_id not in validation['found_critical_rules']:
                    validation['found_critical_rules'].append(rule_id)
        
        # Determine missing critical rules
        validation['missing_critical_rules'] = [
            rule for rule in critical_rules 
            if not any(rule in found_rule or found_rule in rule for found_rule in validation['found_critical_rules'])
        ]
        
        validation['unique_rule_types'] = list(validation['unique_rule_types'])
        
        return validation
    
    def _generate_test_summary(self, individual_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive test summary"""
        
        total_tools = len(individual_results)
        successful_tools = sum(1 for result in individual_results.values() if result.get('success', False))
        total_issues_found = sum(len(result.get('issues', [])) for result in individual_results.values())
        
        # Calculate tool performance metrics
        tool_performance = {}
        for tool_name, result in individual_results.items():
            if result.get('success'):
                issues_count = len(result.get('issues', []))
                expected_min = result.get('metadata', {}).get('expected_min_issues', 0)
                validation = result.get('validation', {})
                
                performance_score = 0
                if issues_count >= expected_min:
                    performance_score += 40  # Meets minimum threshold
                
                if validation.get('found_critical_rules'):
                    performance_score += 30  # Found critical rules
                
                if validation.get('severity_distribution', {}).get('critical', 0) > 0:
                    performance_score += 20  # Found critical severity issues
                
                if validation.get('severity_distribution', {}).get('high', 0) > 0:
                    performance_score += 10  # Found high severity issues
                
                tool_performance[tool_name] = {
                    'score': min(performance_score, 100),
                    'issues_found': issues_count,
                    'expected_minimum': expected_min,
                    'critical_rules_found': len(validation.get('found_critical_rules', [])),
                    'duration': result.get('duration', 0)
                }
            else:
                tool_performance[tool_name] = {
                    'score': 0,
                    'issues_found': 0,
                    'error': result.get('error', 'Unknown error')
                }
        
        return {
            'total_tools_tested': total_tools,
            'successful_tools': successful_tools,
            'failed_tools': total_tools - successful_tools,
            'success_rate': (successful_tools / total_tools * 100) if total_tools > 0 else 0,
            'total_issues_found': total_issues_found,
            'average_issues_per_tool': total_issues_found / successful_tools if successful_tools > 0 else 0,
            'tool_performance': tool_performance,
            'overall_status': 'PASSED' if successful_tools == total_tools else 'PARTIAL' if successful_tools > 0 else 'FAILED'
        }
    
    async def _save_test_results(self, test_results: Dict[str, Any]):
        """Save comprehensive test results to JSON file"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = self.test_dir / f"comprehensive_tool_test_results_{timestamp}.json"
        
        try:
            with open(results_file, 'w') as f:
                json.dump(test_results, f, indent=2, default=str)
            
            logger.info(f"💾 Test results saved to: {results_file}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save test results: {str(e)}")
    
    def _print_final_summary(self, test_results: Dict[str, Any]):
        """Print comprehensive final summary of all tests"""
        
        summary = test_results['summary']
        
        logger.info("\n" + "=" * 80)
        logger.info("🏆 COMPREHENSIVE SECURITY TOOLS TEST SUMMARY")
        logger.info("=" * 80)
        
        logger.info(f"📊 Overall Status: {summary['overall_status']}")
        logger.info(f"🔧 Tools Tested: {summary['total_tools_tested']}")
        logger.info(f"✅ Successful: {summary['successful_tools']}")
        logger.info(f"❌ Failed: {summary['failed_tools']}")
        logger.info(f"📈 Success Rate: {summary['success_rate']:.1f}%")
        logger.info(f"🐛 Total Issues Found: {summary['total_issues_found']}")
        logger.info(f"📈 Average Issues/Tool: {summary['average_issues_per_tool']:.1f}")
        
        logger.info("\n📋 INDIVIDUAL TOOL PERFORMANCE:")
        logger.info("-" * 60)
        
        for tool_name, performance in summary['tool_performance'].items():
            if 'error' in performance:
                logger.info(f"❌ {tool_name}: FAILED - {performance['error']}")
            else:
                score = performance['score']
                issues = performance['issues_found']
                expected = performance['expected_minimum']
                duration = performance.get('duration', 0)
                
                status_emoji = "🟢" if score >= 80 else "🟡" if score >= 50 else "🔴"
                logger.info(f"{status_emoji} {tool_name}: Score {score}/100, Found {issues} issues (expected {expected}+), {duration:.1f}s")
        
        # Print critical findings
        logger.info("\n🚨 CRITICAL SECURITY FINDINGS SUMMARY:")
        logger.info("-" * 60)
        
        for tool_name, result in test_results['individual_results'].items():
            if result.get('success') and result.get('validation'):
                validation = result['validation']
                critical_rules = validation.get('found_critical_rules', [])
                
                if critical_rules:
                    logger.info(f"🔍 {tool_name}: Found critical rules: {', '.join(critical_rules[:5])}")
                else:
                    logger.info(f"⚠️  {tool_name}: No critical rules detected")
        
        logger.info("\n" + "=" * 80)
        logger.info("✨ COMPREHENSIVE TESTING COMPLETED")
        logger.info("=" * 80)

async def main():
    """Main function to run comprehensive security tools testing"""
    
    try:
        tester = ComprehensiveToolTester()
        results = await tester.run_comprehensive_tests()
        
        # Return success/failure based on results
        summary = results.get('summary', {})
        success_rate = summary.get('success_rate', 0)
        
        if success_rate >= 85:
            logger.info("🎉 COMPREHENSIVE TESTING: EXCELLENT RESULTS")
            return 0
        elif success_rate >= 60:
            logger.info("⚠️  COMPREHENSIVE TESTING: GOOD RESULTS WITH SOME ISSUES")
            return 1
        else:
            logger.error("❌ COMPREHENSIVE TESTING: SIGNIFICANT ISSUES DETECTED")
            return 2
            
    except KeyboardInterrupt:
        logger.info("⚠️  Testing interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"❌ CRITICAL ERROR during comprehensive testing: {str(e)}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)