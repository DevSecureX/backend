#!/usr/bin/env python3
"""
Security Tools Auditor for DevSecureX Platform
Comprehensive testing framework to validate all security tools
"""

import asyncio
import logging
import os
import tempfile
import shutil
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

# Add app root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from app.scans.scanner_engine import ScannerEngine
from app.scans.tools.bandit_runner import BanditRunner
from app.scans.tools.semgrep_runner import SemgrepRunner
from app.scans.tools.gitleaks_runner import GitLeaksRunner
from app.scans.tools.gosec_runner import GosecRunner
from app.scans.tools.eslint_security_runner import ESLintSecurityRunner
from app.scans.tools.trivy_runner import TrivyRunner
from app.scans.tools.checkov_runner import CheckovRunner
from app.scans.tools.safety_runner import SafetyRunner

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityToolsAuditor:
    """Comprehensive security tools audit system"""
    
    def __init__(self):
        self.scanner_engine = ScannerEngine()
        self.test_dir = None
        self.results = {}
        
        # Tool runners for direct testing
        self.tools = {
            'bandit': BanditRunner(),
            'semgrep': SemgrepRunner(),
            'gitleaks': GitLeaksRunner(),
            'gosec': GosecRunner(),
            'eslint-security': ESLintSecurityRunner(),
            'trivy': TrivyRunner(),
            'checkov': CheckovRunner(),
            'safety': SafetyRunner()
        }
    
    async def run_comprehensive_audit(self) -> Dict[str, Any]:
        """Run comprehensive audit of all security tools"""
        logger.info("🔍 Starting Comprehensive Security Tools Audit")
        
        start_time = time.time()
        self.results = {
            'start_time': datetime.now().isoformat(),
            'tool_availability': {},
            'vulnerability_detection': {},
            'scanner_engine_test': {},
            'individual_tool_tests': {},
            'summary': {}
        }
        
        try:
            # Step 1: Setup test environment
            await self.setup_test_environment()
            
            # Step 2: Check tool availability
            await self.check_tool_availability()
            
            # Step 3: Test vulnerability detection capabilities
            await self.test_vulnerability_detection()
            
            # Step 4: Test scanner engine integration
            await self.test_scanner_engine_integration()
            
            # Step 5: Test individual tools directly
            await self.test_individual_tools()
            
            # Step 6: Generate summary
            self.generate_summary()
            
            duration = time.time() - start_time
            self.results['duration'] = duration
            self.results['end_time'] = datetime.now().isoformat()
            
            logger.info(f"✅ Audit completed in {duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"❌ Audit failed: {str(e)}", exc_info=True)
            self.results['error'] = str(e)
        finally:
            await self.cleanup_test_environment()
        
        return self.results
    
    async def setup_test_environment(self):
        """Setup test environment with vulnerable files"""
        logger.info("🔧 Setting up test environment")
        
        self.test_dir = tempfile.mkdtemp(prefix="security_audit_")
        logger.info(f"Test directory: {self.test_dir}")
        
        # Create vulnerable files for each tool
        await self.create_vulnerable_files()
        
        self.results['test_directory'] = self.test_dir
        logger.info("✅ Test environment setup complete")
    
    async def create_vulnerable_files(self):
        """Create vulnerable test files for all security tools"""
        
        # Python vulnerable file for Bandit
        python_content = '''
import pickle
import subprocess
import hashlib

# Hardcoded credentials
PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def execute_command(cmd):
    # Command injection
    subprocess.call(cmd, shell=True)

def deserialize_data(data):
    # Insecure deserialization
    return pickle.loads(data)

def hash_password(password):
    # Weak cryptography
    return hashlib.md5(password.encode()).hexdigest()

def sql_query(user_input):
    # SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query
'''
        
        # JavaScript vulnerable file for ESLint Security
        js_content = '''
const crypto = require('crypto');
const exec = require('child_process').exec;

// Hardcoded secrets
const API_SECRET = "sk-abc123def456";
const PASSWORD = "admin123";

function executeCommand(userInput) {
    // Command injection
    exec(userInput, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

function unsafeEval(userCode) {
    // Code injection
    eval(userCode);
}

function weakCrypto(data) {
    // Weak cryptography
    return crypto.createHash('md5').update(data).digest('hex');
}

function sqlQuery(userId) {
    // SQL injection (template)
    return `SELECT * FROM users WHERE id = ${userId}`;
}

module.exports = { executeCommand, unsafeEval, weakCrypto };
'''
        
        # Go vulnerable file for Gosec
        go_content = '''
package main

import (
    "crypto/md5"
    "fmt"
    "os/exec"
    "database/sql"
)

// Hardcoded credentials
const APIKey = "sk-1234567890abcdef"
const Password = "admin123"

func executeCommand(input string) error {
    // Command injection
    cmd := exec.Command("sh", "-c", input)
    return cmd.Run()
}

func weakHash(data []byte) string {
    // Weak cryptography
    h := md5.New()
    h.Write(data)
    return fmt.Sprintf("%x", h.Sum(nil))
}

func sqlQuery(db *sql.DB, userInput string) {
    // SQL injection
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", userInput)
    db.Query(query)
}

func main() {
    fmt.Println("Vulnerable Go code for testing")
}
'''
        
        # Requirements.txt for Safety
        requirements_content = '''
# Vulnerable dependencies for testing
django==2.0.1
flask==0.12.4
requests==2.8.1
pyyaml==3.12
jinja2==2.8.1
'''
        
        # Dockerfile for Trivy
        dockerfile_content = '''
FROM ubuntu:16.04

# Install vulnerable packages
RUN apt-get update && apt-get install -y \\
    openssl=1.0.2g-1ubuntu4.1 \\
    curl=7.47.0-1ubuntu2.1 \\
    wget=1.17.1-1ubuntu1.1

# Add user with weak permissions
RUN useradd -m -s /bin/bash testuser
USER testuser

WORKDIR /app
COPY . .

# Expose all ports (security issue)
EXPOSE 0-65535

CMD ["python", "app.py"]
'''
        
        # Terraform file for Checkov
        terraform_content = '''
# Vulnerable Terraform configuration
resource "aws_s3_bucket" "example" {
  bucket = "my-vulnerable-bucket"
  
  # Public read access - security risk
  acl = "public-read"
  
  versioning {
    enabled = false
  }
  
  # No encryption
  server_side_encryption_configuration {}
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  # Security group allows all traffic
  vpc_security_group_ids = [aws_security_group.allow_all.id]
  
  # No key pair specified
  associate_public_ip_address = true
}

resource "aws_security_group" "allow_all" {
  name_prefix = "allow_all"
  
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        
        # .env file with secrets for Gitleaks
        env_content = '''
# Environment variables with secrets
DATABASE_URL=postgres://admin:password123@localhost:5432/mydb
API_SECRET_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwxyz1234567890ABCDEF
STRIPE_SECRET_KEY=sk_test_1234567890abcdefghijklmnopqrstuvwx
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz12
JWT_SECRET=my-super-secret-jwt-key-123456789
'''
        
        # Create all test files
        test_files = {
            'vulnerable.py': python_content,
            'vulnerable.js': js_content,
            'vulnerable.go': go_content,
            'requirements.txt': requirements_content,
            'Dockerfile': dockerfile_content,
            'main.tf': terraform_content,
            '.env': env_content,
            'package.json': '{"name": "test", "version": "1.0.0", "dependencies": {"lodash": "4.0.0"}}',
            'config.yaml': 'password: admin123\napi_key: sk-test-12345',
        }
        
        for filename, content in test_files.items():
            file_path = os.path.join(self.test_dir, filename)
            with open(file_path, 'w') as f:
                f.write(content)
            logger.debug(f"Created test file: {filename}")
        
        logger.info(f"✅ Created {len(test_files)} vulnerable test files")
    
    async def check_tool_availability(self):
        """Check availability of all security tools"""
        logger.info("🔧 Checking tool availability")
        
        for tool_name, tool_runner in self.tools.items():
            try:
                available = tool_runner._check_tool_availability()
                self.results['tool_availability'][tool_name] = {
                    'available': available,
                    'installation_suggestion': tool_runner._get_installation_suggestion() if not available else None
                }
                
                status = "✅" if available else "❌"
                logger.info(f"{status} {tool_name}: {'Available' if available else 'Not available'}")
                
            except Exception as e:
                self.results['tool_availability'][tool_name] = {
                    'available': False,
                    'error': str(e)
                }
                logger.error(f"❌ {tool_name}: Error checking availability - {str(e)}")
    
    async def test_vulnerability_detection(self):
        """Test vulnerability detection capabilities of each tool"""
        logger.info("🔍 Testing vulnerability detection")
        
        for tool_name, tool_runner in self.tools.items():
            if not self.results['tool_availability'][tool_name]['available']:
                logger.warning(f"⚠️  Skipping {tool_name} - not available")
                continue
            
            try:
                logger.info(f"Testing {tool_name}...")
                start_time = time.time()
                
                result = await tool_runner.run(self.test_dir)
                
                duration = time.time() - start_time
                issues_found = len(result.get('issues', []))
                
                self.results['vulnerability_detection'][tool_name] = {
                    'success': True,
                    'issues_found': issues_found,
                    'duration': duration,
                    'has_error': 'error' in result,
                    'error_message': result.get('error'),
                    'metadata': result.get('metadata', {})
                }
                
                status = "✅" if issues_found > 0 else "⚠️ "
                logger.info(f"{status} {tool_name}: Found {issues_found} issues in {duration:.2f}s")
                
                if 'error' in result:
                    logger.warning(f"   ⚠️  {tool_name} had errors: {result['error']}")
                
            except Exception as e:
                self.results['vulnerability_detection'][tool_name] = {
                    'success': False,
                    'error': str(e)
                }
                logger.error(f"❌ {tool_name}: Test failed - {str(e)}")
    
    async def test_scanner_engine_integration(self):
        """Test scanner engine integration"""
        logger.info("🔧 Testing Scanner Engine integration")
        
        try:
            # Create file list for CLI-style scanning
            file_list = []
            for filename in os.listdir(self.test_dir):
                file_list.append(os.path.join(self.test_dir, filename))
            
            logger.info(f"Testing scanner engine with {len(file_list)} files")
            
            # Test comprehensive scan
            result = await self.scanner_engine.run_comprehensive_scan(
                repo_full_name="test/security-audit",
                branch="main",
                scope="full",
                mode="comprehensive",
                niche="general",
                gh_token="dummy_token",
                scan_type="cli",
                file_list=file_list
            )
            
            self.results['scanner_engine_test'] = {
                'success': result.get('success', False),
                'total_issues': len(result.get('issues', [])),
                'tools_used': result.get('metadata', {}).get('tools_used', []),
                'scan_duration': result.get('metadata', {}).get('scan_duration', 0),
                'languages_detected': result.get('metadata', {}).get('languages_detected', []),
                'error': result.get('error')
            }
            
            total_issues = len(result.get('issues', []))
            tools_used = len(result.get('metadata', {}).get('tools_used', []))
            
            logger.info(f"✅ Scanner Engine: {total_issues} issues found using {tools_used} tools")
            
        except Exception as e:
            self.results['scanner_engine_test'] = {
                'success': False,
                'error': str(e)
            }
            logger.error(f"❌ Scanner Engine test failed: {str(e)}")
    
    async def test_individual_tools(self):
        """Test individual tools with specific parameters"""
        logger.info("🔧 Testing individual tools with specific parameters")
        
        # Test Bandit with Python file only
        if self.results['tool_availability']['bandit']['available']:
            try:
                python_file = os.path.join(self.test_dir, 'vulnerable.py')
                result = await self.tools['bandit'].run(
                    self.test_dir, 
                    target_files=[python_file]
                )
                
                self.results['individual_tool_tests']['bandit'] = {
                    'python_specific_test': {
                        'issues_found': len(result.get('issues', [])),
                        'success': 'error' not in result,
                        'error': result.get('error')
                    }
                }
                
                logger.info(f"✅ Bandit Python-specific: {len(result.get('issues', []))} issues")
                
            except Exception as e:
                logger.error(f"❌ Bandit individual test failed: {str(e)}")
        
        # Test Gosec with Go file only
        if self.results['tool_availability']['gosec']['available']:
            try:
                # Create a temporary Go module
                go_mod_content = "module test\n\ngo 1.19\n"
                with open(os.path.join(self.test_dir, 'go.mod'), 'w') as f:
                    f.write(go_mod_content)
                
                result = await self.tools['gosec'].run(self.test_dir)
                
                self.results['individual_tool_tests']['gosec'] = {
                    'go_specific_test': {
                        'issues_found': len(result.get('issues', [])),
                        'success': 'error' not in result,
                        'error': result.get('error')
                    }
                }
                
                logger.info(f"✅ Gosec Go-specific: {len(result.get('issues', []))} issues")
                
            except Exception as e:
                logger.error(f"❌ Gosec individual test failed: {str(e)}")
    
    def generate_summary(self):
        """Generate comprehensive audit summary"""
        logger.info("📊 Generating audit summary")
        
        available_tools = sum(1 for tool in self.results['tool_availability'].values() if tool['available'])
        total_tools = len(self.results['tool_availability'])
        
        successful_detections = sum(
            1 for tool in self.results['vulnerability_detection'].values() 
            if tool.get('success') and tool.get('issues_found', 0) > 0
        )
        
        total_issues_found = sum(
            tool.get('issues_found', 0) 
            for tool in self.results['vulnerability_detection'].values()
        )
        
        scanner_engine_success = self.results['scanner_engine_test'].get('success', False)
        scanner_engine_issues = self.results['scanner_engine_test'].get('total_issues', 0)
        
        self.results['summary'] = {
            'tool_availability_percentage': (available_tools / total_tools) * 100,
            'available_tools': available_tools,
            'total_tools': total_tools,
            'successful_vulnerability_detections': successful_detections,
            'total_issues_found_individual': total_issues_found,
            'scanner_engine_success': scanner_engine_success,
            'scanner_engine_issues_found': scanner_engine_issues,
            'recommendations': self.generate_recommendations()
        }
        
        logger.info(f"📊 Summary: {available_tools}/{total_tools} tools available")
        logger.info(f"📊 Individual tests found {total_issues_found} total issues")
        logger.info(f"📊 Scanner engine found {scanner_engine_issues} issues")
    
    def generate_recommendations(self) -> List[str]:
        """Generate recommendations based on audit results"""
        recommendations = []
        
        # Check for missing tools
        missing_tools = [
            tool for tool, info in self.results['tool_availability'].items()
            if not info['available']
        ]
        
        if missing_tools:
            recommendations.append(
                f"Install missing security tools: {', '.join(missing_tools)}"
            )
        
        # Check for tools that didn't find vulnerabilities
        ineffective_tools = [
            tool for tool, info in self.results['vulnerability_detection'].items()
            if info.get('success') and info.get('issues_found', 0) == 0
        ]
        
        if ineffective_tools:
            recommendations.append(
                f"Investigate why these tools found no issues: {', '.join(ineffective_tools)}"
            )
        
        # Check for tools with errors
        error_tools = [
            tool for tool, info in self.results['vulnerability_detection'].items()
            if info.get('has_error')
        ]
        
        if error_tools:
            recommendations.append(
                f"Fix errors in these tools: {', '.join(error_tools)}"
            )
        
        # Scanner engine recommendations
        if not self.results['scanner_engine_test'].get('success'):
            recommendations.append("Fix scanner engine integration issues")
        
        return recommendations
    
    async def cleanup_test_environment(self):
        """Clean up test environment"""
        if self.test_dir and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)
            logger.info("🧹 Cleaned up test environment")
    
    def save_results(self, output_file: str):
        """Save audit results to file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        logger.info(f"💾 Results saved to {output_file}")

async def main():
    """Main entry point"""
    auditor = SecurityToolsAuditor()
    
    try:
        results = await auditor.run_comprehensive_audit()
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"security_tools_audit_{timestamp}.json"
        auditor.save_results(output_file)
        
        # Print summary
        summary = results.get('summary', {})
        print("\n" + "="*60)
        print("SECURITY TOOLS AUDIT SUMMARY")
        print("="*60)
        print(f"Tool Availability: {summary.get('available_tools', 0)}/{summary.get('total_tools', 0)} ({summary.get('tool_availability_percentage', 0):.1f}%)")
        print(f"Successful Detections: {summary.get('successful_vulnerability_detections', 0)}")
        print(f"Total Issues (Individual): {summary.get('total_issues_found_individual', 0)}")
        print(f"Scanner Engine Success: {summary.get('scanner_engine_success', False)}")
        print(f"Scanner Engine Issues: {summary.get('scanner_engine_issues_found', 0)}")
        print(f"Duration: {results.get('duration', 0):.2f} seconds")
        
        recommendations = summary.get('recommendations', [])
        if recommendations:
            print("\nRECOMMENDATIONS:")
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. {rec}")
        
        print(f"\nDetailed results saved to: {output_file}")
        
    except Exception as e:
        logger.error(f"Main execution failed: {str(e)}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    exit(asyncio.run(main()))