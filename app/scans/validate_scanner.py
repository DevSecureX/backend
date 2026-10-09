#!/usr/bin/env python3
"""
Validation script to ensure scanner detection capabilities match scan-v2/v3 benchmarks
"""

import os
import sys
import logging
import asyncio
from typing import Dict, List, Any

# Add app directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scans.scanner_engine import ScannerEngine
from scans.tools.semgrep_runner import SemgrepRunner
from scans.tools.bandit_runner import BanditRunner
from scans.tools.trivy_runner import TrivyRunner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

class ScannerValidator:
    """Validate scanner functionality against benchmarks"""
    
    def __init__(self):
        self.scanner = ScannerEngine()
        self.validation_results = {
            'passed': [],
            'failed': [],
            'warnings': []
        }
    
    async def validate_niche_rule_detection(self):
        """Validate that niche-specific rules are properly detected"""
        logger.info("="*60)
        logger.info("Validating Niche-Specific Rule Detection")
        logger.info("="*60)
        
        # Create test files with known vulnerabilities
        test_cases = [
            {
                'niche': 'ai',
                'file': 'test_ai_vuln.py',
                'content': '''
import torch
import numpy as np

# Should be detected by ai.yaml rules
model = torch.load('model.pth')  # Unsafe model loading
data = np.load('data.npy', allow_pickle=True)  # Pickle vulnerability

class MyDataset:
    def __getitem__(self, idx):
        # Should trigger dataset RNG issue
        np.random.seed(42)
        return self.data[idx]
                ''',
                'expected_issues': ['torch.load', 'allow_pickle', 'numpy.random']
            },
            {
                'niche': 'blockchain',
                'file': 'test_blockchain.sol',
                'content': '''
pragma solidity ^0.8.0;

contract Vulnerable {
    // Should be detected by blockchain.yaml rules
    function borrowFresh() external {
        // Potential reentrancy
        (bool success,) = msg.sender.call{value: amount}("");
        totalBorrows = totalBorrows + borrowAmount;
    }
    
    function _transfer(address to, uint256 amount) public {
        // Exposed internal function
        balances[to] += amount;
    }
}
                ''',
                'expected_issues': ['reentrancy', '_transfer']
            },
            {
                'niche': 'iot',
                'file': 'test_iot_vuln.c',
                'content': '''
#include <string.h>
#include <stdio.h>

void vulnerable_function(char* input) {
    char buffer[100];
    // Should be detected by iot.yaml rules
    strcpy(buffer, input);  // Buffer overflow
    gets(buffer);  // Dangerous function
    
    char* password = "hardcoded123";  // Hardcoded credential
}
                ''',
                'expected_issues': ['strcpy', 'gets', 'hardcoded']
            }
        ]
        
        # Create temporary test directory
        test_dir = '/tmp/scanner_validation'
        os.makedirs(test_dir, exist_ok=True)
        
        for test_case in test_cases:
            logger.info(f"\nTesting {test_case['niche']} detection...")
            
            # Write test file
            file_path = os.path.join(test_dir, test_case['file'])
            with open(file_path, 'w') as f:
                f.write(test_case['content'])
            
            # Run Semgrep with niche rules
            semgrep = SemgrepRunner()
            result = await semgrep.run(test_dir, niche=test_case['niche'])
            
            # Check for expected issues
            issues_found = result.get('issues', [])
            logger.info(f"Found {len(issues_found)} issues")
            
            for expected in test_case['expected_issues']:
                found = any(expected.lower() in str(issue).lower() for issue in issues_found)
                if found:
                    logger.info(f"✅ Detected expected issue: {expected}")
                    self.validation_results['passed'].append(f"{test_case['niche']}: {expected}")
                else:
                    logger.error(f"❌ Failed to detect: {expected}")
                    self.validation_results['failed'].append(f"{test_case['niche']}: {expected}")
            
            # Cleanup
            os.remove(file_path)
        
        # Cleanup directory
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
    
    async def validate_tool_configurations(self):
        """Validate tool configurations match benchmarks"""
        logger.info("\n" + "="*60)
        logger.info("Validating Tool Configurations")
        logger.info("="*60)
        
        # Test Bandit configuration
        logger.info("\nTesting Bandit configuration...")
        test_code = '''
import os

# Low confidence issue - should be detected with -l flag
password = input("Enter password")  # B105 - low confidence

# Assert usage - should NOT be detected (B101 skipped)
assert user.is_authenticated

# Shell usage - should be detected (B601 NOT skipped in develop)
os.system("ls -la")
        '''
        
        test_dir = '/tmp/bandit_test'
        os.makedirs(test_dir, exist_ok=True)
        
        with open(os.path.join(test_dir, 'test.py'), 'w') as f:
            f.write(test_code)
        
        bandit = BanditRunner()
        result = await bandit.run(test_dir)
        issues = result.get('issues', [])
        
        # Check configurations
        b105_found = any('B105' in issue.get('rule_id', '') for issue in issues)
        b101_found = any('B101' in issue.get('rule_id', '') for issue in issues)
        b601_found = any('B601' in issue.get('rule_id', '') or 'os.system' in issue.get('message', '') for issue in issues)
        
        if b105_found:
            logger.info("✅ Low confidence issues detected (correct -l flag)")
            self.validation_results['passed'].append("Bandit: low confidence detection")
        else:
            logger.error("❌ Low confidence issues not detected")
            self.validation_results['failed'].append("Bandit: low confidence detection")
        
        if not b101_found:
            logger.info("✅ Assert warnings correctly skipped")
            self.validation_results['passed'].append("Bandit: B101 skip")
        else:
            logger.error("❌ Assert warnings not skipped")
            self.validation_results['failed'].append("Bandit: B101 skip")
        
        if b601_found:
            logger.info("✅ Shell usage detected (B601 not skipped)")
            self.validation_results['passed'].append("Bandit: shell detection")
        else:
            logger.warning("⚠️ Shell usage not detected - check if intentional")
            self.validation_results['warnings'].append("Bandit: shell detection")
        
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)
    
    async def validate_language_thresholds(self):
        """Validate language detection thresholds"""
        logger.info("\n" + "="*60)
        logger.info("Validating Language Detection Thresholds")
        logger.info("="*60)
        
        # Test with different language percentages
        test_cases = [
            {
                'languages': {'Python': 4, 'JavaScript': 96},
                'expected_no_python_tools': True,  # Below 5% threshold
                'description': '4% Python (below threshold)'
            },
            {
                'languages': {'Python': 6, 'JavaScript': 94},
                'expected_no_python_tools': False,  # Above 5% threshold
                'description': '6% Python (above threshold)'
            },
            {
                'languages': {'Java': 9, 'Python': 91},
                'expected_no_java_tools': True,  # Below 10% threshold for Java
                'description': '9% Java (below threshold)'
            }
        ]
        
        for test_case in test_cases:
            logger.info(f"\nTesting: {test_case['description']}")
            
            selected_tools = self.scanner._select_tools_intelligently(
                scope='code-only',
                mode='fast',
                niche='general',
                languages=test_case['languages']
            )
            
            logger.info(f"Selected tools: {selected_tools}")
            
            # Check Python tools
            if 'expected_no_python_tools' in test_case:
                python_tools_selected = any(tool in selected_tools for tool in ['bandit', 'safety'])
                if test_case['expected_no_python_tools'] and not python_tools_selected:
                    logger.info("✅ Python tools correctly not selected")
                    self.validation_results['passed'].append(f"Threshold: {test_case['description']}")
                elif not test_case['expected_no_python_tools'] and python_tools_selected:
                    logger.info("✅ Python tools correctly selected")
                    self.validation_results['passed'].append(f"Threshold: {test_case['description']}")
                else:
                    logger.error("❌ Incorrect tool selection based on threshold")
                    self.validation_results['failed'].append(f"Threshold: {test_case['description']}")
    
    async def validate_performance_optimizations(self):
        """Validate performance optimizations"""
        logger.info("\n" + "="*60)
        logger.info("Validating Performance Optimizations")
        logger.info("="*60)
        
        # Check concurrency settings
        optimal_concurrency = self.scanner.max_concurrent_tools
        logger.info(f"Optimal concurrency set to: {optimal_concurrency}")
        
        if 2 <= optimal_concurrency <= 8:
            logger.info("✅ Concurrency within reasonable bounds")
            self.validation_results['passed'].append("Performance: concurrency limits")
        else:
            logger.error("❌ Concurrency outside reasonable bounds")
            self.validation_results['failed'].append("Performance: concurrency limits")
        
        # Check timeout settings
        if self.scanner.tool_timeout == 600:  # 10 minutes
            logger.info("✅ Tool timeout correctly set to 10 minutes")
            self.validation_results['passed'].append("Performance: tool timeout")
        else:
            logger.warning(f"⚠️ Tool timeout is {self.scanner.tool_timeout}s (expected 600s)")
            self.validation_results['warnings'].append("Performance: tool timeout")
    
    def generate_report(self):
        """Generate validation report"""
        logger.info("\n" + "="*60)
        logger.info("Validation Report")
        logger.info("="*60)
        
        total_tests = len(self.validation_results['passed']) + len(self.validation_results['failed']) + len(self.validation_results['warnings'])
        
        logger.info(f"\nTotal Tests: {total_tests}")
        logger.info(f"Passed: {len(self.validation_results['passed'])}")
        logger.info(f"Failed: {len(self.validation_results['failed'])}")
        logger.info(f"Warnings: {len(self.validation_results['warnings'])}")
        
        if self.validation_results['failed']:
            logger.error("\nFailed Tests:")
            for failure in self.validation_results['failed']:
                logger.error(f"  - {failure}")
        
        if self.validation_results['warnings']:
            logger.warning("\nWarnings:")
            for warning in self.validation_results['warnings']:
                logger.warning(f"  - {warning}")
        
        success_rate = (len(self.validation_results['passed']) / total_tests * 100) if total_tests > 0 else 0
        logger.info(f"\nSuccess Rate: {success_rate:.1f}%")
        
        if success_rate >= 90:
            logger.info("\n✅ Scanner validation PASSED - detection quality restored!")
        elif success_rate >= 75:
            logger.warning("\n⚠️ Scanner validation PARTIAL - some issues remain")
        else:
            logger.error("\n❌ Scanner validation FAILED - significant issues detected")
        
        return success_rate >= 90

async def main():
    validator = ScannerValidator()
    
    # Run all validations
    await validator.validate_niche_rule_detection()
    await validator.validate_tool_configurations()
    await validator.validate_language_thresholds()
    await validator.validate_performance_optimizations()
    
    # Generate report
    success = validator.generate_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    asyncio.run(main())