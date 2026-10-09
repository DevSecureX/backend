#!/usr/bin/env python3
"""
Security Tools Comprehensive Audit Runner
Orchestrates all security tool testing and validation
"""

import asyncio
import logging
import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add app root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityAuditRunner:
    """Comprehensive security audit runner"""
    
    def __init__(self):
        self.audit_results = {}
    
    async def run_full_audit(self):
        """Run complete security audit with all tools"""
        logger.info("🚀 Starting Complete Security Tools Audit")
        
        start_time = datetime.now()
        audit_summary = {
            'start_time': start_time.isoformat(),
            'tests_run': [],
            'results': {},
            'summary': {}
        }
        
        try:
            # Test 1: Debug tool execution
            logger.info("🔧 Running tool execution debug...")
            from debug_tool_execution import SecurityToolsDebugger
            debugger = SecurityToolsDebugger()
            debug_results = await debugger.run_comprehensive_debug()
            audit_summary['results']['debug_analysis'] = debug_results
            audit_summary['tests_run'].append('debug_analysis')
            
            # Test 2: Comprehensive tools audit
            logger.info("🔍 Running comprehensive tools audit...")
            from security_tools_auditor import SecurityToolsAuditor
            auditor = SecurityToolsAuditor()
            audit_results = await auditor.run_comprehensive_audit()
            audit_summary['results']['tools_audit'] = audit_results
            audit_summary['tests_run'].append('tools_audit')
            
            # Test 3: Bandit specific testing
            logger.info("🐍 Running Bandit-specific tests...")
            from test_bandit_execution import BanditTester
            bandit_tester = BanditTester()
            bandit_results = await bandit_tester.run_comprehensive_test()
            audit_summary['results']['bandit_test'] = bandit_results
            audit_summary['tests_run'].append('bandit_test')
            
            # Generate comprehensive summary
            audit_summary['summary'] = self.generate_comprehensive_summary(audit_summary['results'])
            
        except Exception as e:
            logger.error(f"❌ Audit failed: {str(e)}", exc_info=True)
            audit_summary['error'] = str(e)
        
        end_time = datetime.now()
        audit_summary['end_time'] = end_time.isoformat()
        audit_summary['duration'] = (end_time - start_time).total_seconds()
        
        return audit_summary
    
    def generate_comprehensive_summary(self, results):
        """Generate comprehensive summary from all test results"""
        summary = {
            'overall_health': 'unknown',
            'tool_availability': {},
            'vulnerability_detection': {},
            'critical_issues': [],
            'recommendations': [],
            'performance_metrics': {}
        }
        
        # Analyze debug results
        debug_results = results.get('debug_analysis', {})
        if debug_results:
            tool_availability = debug_results.get('tool_availability', {})
            available_count = sum(1 for tool in tool_availability.values() if tool.get('availability'))
            total_count = len(tool_availability)
            
            summary['tool_availability'] = {
                'available': available_count,
                'total': total_count,
                'percentage': (available_count / total_count * 100) if total_count > 0 else 0
            }
            
            # Critical issues from debug
            common_issues = debug_results.get('common_issues', {})
            missing_tools = common_issues.get('missing_tools', [])
            if missing_tools:
                summary['critical_issues'].append(f"Missing tools: {', '.join(missing_tools)}")
        
        # Analyze audit results  
        audit_results = results.get('tools_audit', {})
        if audit_results:
            vuln_detection = audit_results.get('vulnerability_detection', {})
            successful_detections = sum(
                1 for tool in vuln_detection.values()
                if tool.get('success') and tool.get('issues_found', 0) > 0
            )
            
            total_issues = sum(
                tool.get('issues_found', 0)
                for tool in vuln_detection.values()
            )
            
            summary['vulnerability_detection'] = {
                'successful_tools': successful_detections,
                'total_issues_found': total_issues,
                'scanner_engine_issues': audit_results.get('scanner_engine_test', {}).get('total_issues', 0)
            }
        
        # Analyze Bandit specific results
        bandit_results = results.get('bandit_test', {})
        if bandit_results:
            availability = bandit_results.get('availability_test', {})
            direct_exec = bandit_results.get('direct_execution', {})
            scanner_integration = bandit_results.get('scanner_engine_integration', {})
            
            if not availability.get('available'):
                summary['critical_issues'].append("Bandit tool not available")
            elif not direct_exec.get('success'):
                summary['critical_issues'].append("Bandit direct execution failed")
            elif not scanner_integration.get('success'):
                summary['critical_issues'].append("Bandit scanner engine integration failed")
        
        # Determine overall health
        if summary['critical_issues']:
            summary['overall_health'] = 'critical'
        elif summary['tool_availability'].get('percentage', 0) < 70:
            summary['overall_health'] = 'poor'
        elif summary['vulnerability_detection'].get('successful_tools', 0) < 3:
            summary['overall_health'] = 'fair'
        else:
            summary['overall_health'] = 'good'
        
        # Generate recommendations
        summary['recommendations'] = self.generate_recommendations(summary, results)
        
        return summary
    
    def generate_recommendations(self, summary, results):
        """Generate actionable recommendations"""
        recommendations = []
        
        # Tool availability recommendations
        availability_pct = summary.get('tool_availability', {}).get('percentage', 0)
        if availability_pct < 50:
            recommendations.append({
                'priority': 'Critical',
                'category': 'Installation',
                'action': 'Install missing security tools',
                'details': 'Less than 50% of security tools are available'
            })
        elif availability_pct < 80:
            recommendations.append({
                'priority': 'High',
                'category': 'Installation', 
                'action': 'Complete security tool installation',
                'details': f'Only {availability_pct:.1f}% of tools available'
            })
        
        # Vulnerability detection recommendations
        successful_tools = summary.get('vulnerability_detection', {}).get('successful_tools', 0)
        if successful_tools < 3:
            recommendations.append({
                'priority': 'High',
                'category': 'Detection',
                'action': 'Fix vulnerability detection issues',
                'details': f'Only {successful_tools} tools successfully detecting vulnerabilities'
            })
        
        # Critical issues recommendations
        for issue in summary.get('critical_issues', []):
            recommendations.append({
                'priority': 'Critical',
                'category': 'Core Functionality',
                'action': 'Fix critical issue',
                'details': issue
            })
        
        # Performance recommendations
        debug_results = results.get('debug_analysis', {})
        if debug_results and debug_results.get('duration', 0) > 60:
            recommendations.append({
                'priority': 'Medium',
                'category': 'Performance',
                'action': 'Optimize tool execution time',
                'details': f'Debug analysis took {debug_results.get("duration", 0):.1f} seconds'
            })
        
        return recommendations
    
    def save_audit_results(self, results, filename):
        """Save audit results to file"""
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"💾 Audit results saved to {filename}")
    
    def print_comprehensive_report(self, results):
        """Print comprehensive audit report"""
        summary = results.get('summary', {})
        
        print("\n" + "="*100)
        print("DEVSECUREX SECURITY TOOLS COMPREHENSIVE AUDIT REPORT")
        print("="*100)
        
        # Executive Summary
        health = summary.get('overall_health', 'unknown').upper()
        health_color = {
            'GOOD': '🟢',
            'FAIR': '🟡', 
            'POOR': '🟠',
            'CRITICAL': '🔴',
            'UNKNOWN': '⚪'
        }
        
        print(f"Overall System Health: {health_color.get(health, '⚪')} {health}")
        print(f"Audit Duration: {results.get('duration', 0):.1f} seconds")
        print(f"Tests Run: {len(results.get('tests_run', []))}")
        print()
        
        # Tool Availability
        availability = summary.get('tool_availability', {})
        print("TOOL AVAILABILITY:")
        print(f"  Available: {availability.get('available', 0)}/{availability.get('total', 0)} ({availability.get('percentage', 0):.1f}%)")
        
        # Vulnerability Detection
        detection = summary.get('vulnerability_detection', {})
        print("\nVULNERABILITY DETECTION:")
        print(f"  Successful Tools: {detection.get('successful_tools', 0)}")
        print(f"  Total Issues Found (Individual): {detection.get('total_issues_found', 0)}")
        print(f"  Scanner Engine Issues: {detection.get('scanner_engine_issues', 0)}")
        
        # Critical Issues
        critical_issues = summary.get('critical_issues', [])
        if critical_issues:
            print("\nCRITICAL ISSUES:")
            for i, issue in enumerate(critical_issues, 1):
                print(f"  {i}. {issue}")
        
        # Recommendations
        recommendations = summary.get('recommendations', [])
        if recommendations:
            print("\nRECOMMENDATIONS:")
            for i, rec in enumerate(recommendations, 1):
                priority_icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(rec['priority'], '⚪')
                print(f"  {i}. {priority_icon} [{rec['priority']}] {rec['category']}: {rec['action']}")
                print(f"     {rec['details']}")
        
        # Detailed Test Results Summary
        print("\nDETAILED TEST RESULTS:")
        test_results = results.get('results', {})
        
        for test_name, test_data in test_results.items():
            print(f"\n  {test_name.upper().replace('_', ' ')}:")
            
            if test_name == 'debug_analysis':
                env_check = test_data.get('environment_check', {})
                print(f"    Environment: {env_check.get('platform', 'unknown')}")
                print(f"    Tool Directories: {len(env_check.get('tool_directories', []))}")
                
                cli_tests = test_data.get('command_line_tests', {})
                successful_cli = sum(1 for test in cli_tests.values() if test.get('execution_success'))
                print(f"    CLI Tests: {successful_cli}/{len(cli_tests)} successful")
                
            elif test_name == 'tools_audit':
                print(f"    Success: {test_data.get('success', False)}")
                print(f"    Total Issues: {len(test_data.get('issues', []))}")
                print(f"    Tools Used: {len(test_data.get('metadata', {}).get('tools_used', []))}")
                
            elif test_name == 'bandit_test':
                availability = test_data.get('availability_test', {})
                direct = test_data.get('direct_execution', {})
                print(f"    Available: {availability.get('available', False)}")
                print(f"    Direct Execution: {direct.get('success', False) if direct else 'Not tested'}")
                print(f"    Issues Found: {direct.get('issues_found', 0) if direct else 0}")
        
        print("\n" + "="*100)

async def main():
    """Main entry point"""
    runner = SecurityAuditRunner()
    
    try:
        # Run comprehensive audit
        results = await runner.run_full_audit()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"comprehensive_security_audit_{timestamp}.json"
        runner.save_audit_results(results, output_file)
        
        # Print comprehensive report
        runner.print_comprehensive_report(results)
        
        print(f"\nComplete audit results saved to: {output_file}")
        
        # Return appropriate exit code
        health = results.get('summary', {}).get('overall_health', 'unknown')
        if health == 'critical':
            return 2
        elif health in ['poor', 'fair']:
            return 1
        else:
            return 0
            
    except Exception as e:
        logger.error(f"Main execution failed: {str(e)}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(asyncio.run(main()))