#!/usr/bin/env python3
"""
Validate all security rules for syntax and effectiveness
"""

import os
import sys
import yaml
import logging
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RuleValidator:
    def __init__(self, rules_dir: str = "/app/rules"):
        self.rules_dir = rules_dir
        self.validation_results = {
            'valid': [],
            'invalid': [],
            'warnings': []
        }
    
    def validate_all_rules(self) -> bool:
        """Validate all rule files in the rules directory"""
        logger.info(f"Validating rules in {self.rules_dir}")
        
        rule_files = [f for f in os.listdir(self.rules_dir) if f.endswith('.yaml')]
        
        for rule_file in rule_files:
            file_path = os.path.join(self.rules_dir, rule_file)
            self.validate_rule_file(file_path)
        
        # Summary
        logger.info("\n" + "="*60)
        logger.info("Validation Summary")
        logger.info("="*60)
        logger.info(f"Total files checked: {len(rule_files)}")
        logger.info(f"Valid files: {len(self.validation_results['valid'])}")
        logger.info(f"Invalid files: {len(self.validation_results['invalid'])}")
        logger.info(f"Warnings: {len(self.validation_results['warnings'])}")
        
        if self.validation_results['invalid']:
            logger.error("\nInvalid files:")
            for invalid in self.validation_results['invalid']:
                logger.error(f"  - {invalid}")
        
        if self.validation_results['warnings']:
            logger.warning("\nWarnings:")
            for warning in self.validation_results['warnings']:
                logger.warning(f"  - {warning}")
        
        return len(self.validation_results['invalid']) == 0
    
    def validate_rule_file(self, file_path: str) -> bool:
        """Validate a single rule file"""
        logger.info(f"\nValidating {os.path.basename(file_path)}...")
        
        try:
            with open(file_path, 'r') as f:
                content = yaml.safe_load(f)
            
            if not isinstance(content, dict) or 'rules' not in content:
                self.validation_results['invalid'].append(
                    f"{file_path}: Missing 'rules' key"
                )
                return False
            
            rules = content.get('rules', [])
            if not isinstance(rules, list):
                self.validation_results['invalid'].append(
                    f"{file_path}: 'rules' must be a list"
                )
                return False
            
            # Validate each rule
            for idx, rule in enumerate(rules):
                if not self.validate_single_rule(rule, file_path, idx):
                    return False
            
            logger.info(f"✅ {os.path.basename(file_path)}: Valid ({len(rules)} rules)")
            self.validation_results['valid'].append(file_path)
            return True
            
        except yaml.YAMLError as e:
            self.validation_results['invalid'].append(
                f"{file_path}: YAML parsing error - {e}"
            )
            return False
        except Exception as e:
            self.validation_results['invalid'].append(
                f"{file_path}: Unexpected error - {e}"
            )
            return False
    
    def validate_single_rule(self, rule: Dict[str, Any], file_path: str, idx: int) -> bool:
        """Validate a single rule structure"""
        required_fields = ['id', 'languages', 'severity', 'message']
        
        # Check required fields
        for field in required_fields:
            if field not in rule:
                self.validation_results['invalid'].append(
                    f"{file_path} rule {idx}: Missing required field '{field}'"
                )
                return False
        
        # Validate pattern exists
        pattern_fields = ['pattern', 'patterns', 'pattern-either', 'pattern-regex']
        if not any(field in rule for field in pattern_fields):
            self.validation_results['invalid'].append(
                f"{file_path} rule {rule['id']}: Missing pattern definition"
            )
            return False
        
        # Validate severity
        valid_severities = ['ERROR', 'WARNING', 'INFO', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        if rule['severity'] not in valid_severities:
            self.validation_results['warnings'].append(
                f"{file_path} rule {rule['id']}: Unknown severity '{rule['severity']}'"
            )
        
        # Validate languages
        if not isinstance(rule['languages'], list):
            self.validation_results['invalid'].append(
                f"{file_path} rule {rule['id']}: 'languages' must be a list"
            )
            return False
        
        # Check for fix suggestion
        if 'fix' not in rule:
            self.validation_results['warnings'].append(
                f"{file_path} rule {rule['id']}: No 'fix' suggestion provided"
            )
        
        return True

def main():
    # Get rules directory from command line or use default
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "/app/rules"
    
    # If running locally, use relative path
    if not os.path.exists(rules_dir):
        rules_dir = os.path.join(os.path.dirname(__file__))
    
    validator = RuleValidator(rules_dir)
    success = validator.validate_all_rules()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()