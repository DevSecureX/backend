#!/usr/bin/env python3
"""
Continuous CLI-Main Scan Parity Monitoring System

This script continuously monitors and validates parity between CLI and main scans
to ensure 100% consistency is maintained over time.

Features:
- Daily automated parity validation
- Real-time parity degradation alerts  
- Historical parity trend analysis
- Performance regression detection
- Automated issue reporting and escalation

Usage:
    python scripts/parity_monitor.py --mode daily
    python scripts/parity_monitor.py --mode continuous --interval 3600
    python scripts/parity_monitor.py --mode test-run
"""

import asyncio
import argparse
import json
import logging
import os
import sys
import time
import tempfile
import shutil
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import statistics
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

# Add the parent directory to sys.path to import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app.cli_scan.routes import scan_code, CLIScanRequest
    from app.scans.scanner_engine import ScannerEngine
    from app.auth.models import User
    from app.core.database import get_db
    from sqlalchemy.ext.asyncio import AsyncSession
except ImportError as e:
    print(f"Failed to import application modules: {e}")
    print("Make sure you're running this script from the correct directory and dependencies are installed")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('parity_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ParityResult:
    """Container for parity test results"""
    repository_name: str
    cli_issues_count: int
    main_issues_count: int
    cli_critical_count: int
    main_critical_count: int
    cli_total_score: float
    main_total_score: float
    cli_scan_duration: float
    main_scan_duration: float
    parity_score: float
    timestamp: str
    tools_cli: List[str]
    tools_main: List[str]
    success: bool
    error_message: Optional[str] = None

@dataclass
class ParityReport:
    """Container for daily parity monitoring report"""
    date: str
    repositories_tested: int
    overall_parity_score: float
    parity_results: List[ParityResult]
    performance_metrics: Dict[str, float]
    alerts_triggered: List[str]
    recommendations: List[str]
    trend_analysis: Dict[str, Any]

class ParityMonitor:
    """Main parity monitoring system"""
    
    def __init__(self):
        self.test_repositories = self._get_test_repositories()
        self.parity_threshold = 0.95  # 95% parity minimum
        self.performance_threshold = 1.5  # CLI should be within 150% of main scan time
        self.alert_recipients = self._get_alert_recipients()
        self.storage_path = "parity_monitoring_data"
        self._ensure_storage_directory()
    
    def _get_test_repositories(self) -> Dict[str, Dict[str, str]]:
        """Get test repositories for parity validation"""
        return {
            "vulnerable-node-app": {
                "app.js": '''
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');

const app = express();

// Hardcoded secrets
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'admin123';
const JWT_SECRET = 'super-secret-jwt-key';

app.use(express.json());

// XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    res.send(`<h1>Results: ${query}</h1>`);
});

// Command injection
app.post('/execute', (req, res) => {
    const cmd = req.body.command;
    exec(cmd, (error, stdout) => {
        res.json({ output: stdout });
    });
});

// Path traversal
app.get('/file/:name', (req, res) => {
    const filename = req.params.name;
    fs.readFile(`./uploads/${filename}`, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

app.listen(3000);
''',
                "package.json": '''
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.16.0",
    "lodash": "4.17.20",
    "moment": "2.24.0",
    "axios": "0.18.0",
    "serialize-javascript": "2.1.0"
  }
}
'''
            },
            
            "vulnerable-flask-app": {
                "app.py": '''
import os
import sqlite3
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Hardcoded secrets
app.secret_key = "hardcoded-flask-secret"
DATABASE_PASSWORD = "admin123"
API_TOKEN = "bearer-token-1234567890"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = sqlite3.connect('app.db')
    result = conn.execute(query).fetchone()
    return str(result)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # XSS vulnerability
    return f"<h1>Search: {query}</h1>"

@app.route('/execute')
def execute():
    cmd = request.args.get('cmd')
    # Command injection
    result = os.system(cmd)
    return f"Result: {result}"

@app.route('/hash')
def hash_data():
    data = request.args.get('data', '')
    # Weak crypto
    return hashlib.md5(data.encode()).hexdigest()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
''',
                "requirements.txt": '''
Flask==1.0.0
requests==2.18.0
Pillow==5.4.0
PyYAML==3.12
urllib3==1.24.0
Jinja2==2.10.0
SQLAlchemy==1.2.0
paramiko==2.4.0
'''
            },
            
            "vulnerable-defi-contract": {
                "vulnerable_defi.sol": '''
pragma solidity ^0.8.0;

contract VulnerableDefi {
    mapping(address => uint256) public balances;
    address public owner;
    
    // Hardcoded private key - critical vulnerability
    string private constant PRIVATE_KEY = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    constructor() {
        owner = msg.sender;
    }
    
    // Reentrancy vulnerability
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;  // State change after external call
    }
    
    // Integer overflow vulnerability (pre-0.8.0 style)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Access control vulnerability
    function emergencyWithdraw() public {
        // Missing onlyOwner modifier
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // Timestamp dependence
    function timeBasedReward() public view returns (bool) {
        return block.timestamp % 2 == 0;
    }
    
    // Unchecked external call
    function callExternalContract(address target, bytes memory data) public {
        target.call(data);  // No return value check
    }
}
''',
                "package.json": '''
{
  "name": "vulnerable-defi",
  "version": "1.0.0",
  "dependencies": {
    "@openzeppelin/contracts": "4.1.0",
    "web3": "1.3.0",
    "truffle": "5.1.0"
  }
}
'''
            },
            
            "vulnerable-terraform": {
                "main.tf": '''
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"  # Hardcoded credentials
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-west-2"
}

resource "aws_s3_bucket" "data" {
  bucket = "company-sensitive-data"
  acl    = "public-read"  # Public bucket
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow all traffic
  }
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SSH from anywhere
  }
}

resource "aws_db_instance" "main" {
  publicly_accessible = true      # Public database
  storage_encrypted   = false     # No encryption
  password           = "admin123" # Hardcoded password
  backup_retention_period = 0    # No backups
  skip_final_snapshot = true
}
''',
                "variables.tf": '''
variable "database_password" {
  description = "Database password"
  type        = string
  default     = "hardcoded_password_123"  # Hardcoded default
}

variable "api_key" {
  description = "API key for external service"  
  type        = string
  default     = "sk-1234567890abcdef"  # Hardcoded secret
}
'''
            }
        }
    
    def _get_alert_recipients(self) -> List[str]:
        """Get email addresses for parity alerts"""
        # In production, these would come from environment variables or config
        return [
            "security-team@devsecurex.com",
            "engineering-lead@devsecurex.com",
            "devops@devsecurex.com"
        ]
    
    def _ensure_storage_directory(self):
        """Ensure parity data storage directory exists"""
        os.makedirs(self.storage_path, exist_ok=True)
    
    async def daily_parity_check(self) -> ParityReport:
        """Run daily comprehensive parity validation"""
        logger.info("Starting daily parity validation check")
        
        start_time = time.time()
        parity_results = []
        alerts_triggered = []
        
        # Test each repository
        for repo_name, repo_files in self.test_repositories.items():
            logger.info(f"Testing parity for repository: {repo_name}")
            
            try:
                result = await self._test_repository_parity(repo_name, repo_files)
                parity_results.append(result)
                
                # Check for alerts
                if result.parity_score < self.parity_threshold:
                    alert_msg = (
                        f"PARITY ALERT: {repo_name} parity degraded to {result.parity_score:.3f} "
                        f"(threshold: {self.parity_threshold:.3f})"
                    )
                    alerts_triggered.append(alert_msg)
                    logger.warning(alert_msg)
                
                if result.cli_scan_duration > result.main_scan_duration * self.performance_threshold:
                    alert_msg = (
                        f"PERFORMANCE ALERT: {repo_name} CLI scan {result.cli_scan_duration:.1f}s "
                        f"vs main scan {result.main_scan_duration:.1f}s "
                        f"(ratio: {result.cli_scan_duration / result.main_scan_duration:.1f}x)"
                    )
                    alerts_triggered.append(alert_msg)
                    logger.warning(alert_msg)
                    
            except Exception as e:
                logger.error(f"Failed to test repository {repo_name}: {e}")
                parity_results.append(ParityResult(
                    repository_name=repo_name,
                    cli_issues_count=0,
                    main_issues_count=0,
                    cli_critical_count=0,
                    main_critical_count=0,
                    cli_total_score=0,
                    main_total_score=0,
                    cli_scan_duration=0,
                    main_scan_duration=0,
                    parity_score=0,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    tools_cli=[],
                    tools_main=[],
                    success=False,
                    error_message=str(e)
                ))
        
        # Calculate overall metrics
        successful_results = [r for r in parity_results if r.success]
        overall_parity = statistics.mean([r.parity_score for r in successful_results]) if successful_results else 0.0
        
        performance_metrics = self._calculate_performance_metrics(successful_results)
        recommendations = self._generate_recommendations(parity_results, alerts_triggered)
        trend_analysis = await self._analyze_trends()
        
        # Create report
        report = ParityReport(
            date=datetime.now(timezone.utc).date().isoformat(),
            repositories_tested=len(self.test_repositories),
            overall_parity_score=overall_parity,
            parity_results=parity_results,
            performance_metrics=performance_metrics,
            alerts_triggered=alerts_triggered,
            recommendations=recommendations,
            trend_analysis=trend_analysis
        )
        
        # Store report
        await self._store_parity_report(report)
        
        # Send alerts if needed
        if alerts_triggered:
            await self._send_parity_alerts(report)
        
        total_duration = time.time() - start_time
        logger.info(f"Daily parity check completed in {total_duration:.1f}s")
        logger.info(f"Overall parity score: {overall_parity:.3f}")
        logger.info(f"Alerts triggered: {len(alerts_triggered)}")
        
        return report
    
    async def _test_repository_parity(self, repo_name: str, repo_files: Dict[str, str]) -> ParityResult:
        """Test parity for a specific repository"""
        
        # Create mock user for testing
        mock_user = type('User', (), {
            'id': 999,
            'username': 'parity_monitor',
            'email': 'monitor@devsecurex.com',
            'is_premium': True,
            'is_active': True
        })()
        
        mock_db = type('AsyncSession', (), {})()
        
        try:
            # Run CLI scan
            cli_start = time.time()
            cli_request = CLIScanRequest(
                code_files=repo_files,
                scan_mode="comprehensive",
                scan_scope="full",
                include_custom_rules=True,
                niche="all"
            )
            
            # Mock the dependencies for CLI scan
            from unittest.mock import patch, AsyncMock
            
            with patch('app.cli_scan.routes.get_current_user_from_api_key', return_value=mock_user):
                with patch('app.cli_scan.routes.get_db', return_value=AsyncMock()):
                    cli_result = await scan_code(cli_request, mock_user, AsyncMock())
            
            cli_duration = time.time() - cli_start
            
            # Run main scan (simulated)
            main_start = time.time()
            main_result = await self._simulate_main_scan(repo_name, repo_files)
            main_duration = time.time() - main_start
            
            # Calculate parity score
            parity_score = self._calculate_parity_score(cli_result, main_result)
            
            return ParityResult(
                repository_name=repo_name,
                cli_issues_count=len(cli_result.issues),
                main_issues_count=len(main_result.get('issues', [])),
                cli_critical_count=len([i for i in cli_result.issues if i.get('severity') == 'critical']),
                main_critical_count=len([i for i in main_result.get('issues', []) if i.get('severity') == 'critical']),
                cli_total_score=cli_result.total_score,
                main_total_score=main_result.get('total_score', 0),
                cli_scan_duration=cli_duration,
                main_scan_duration=main_duration,
                parity_score=parity_score,
                timestamp=datetime.now(timezone.utc).isoformat(),
                tools_cli=cli_result.statistics.get('tools_executed', []),
                tools_main=main_result.get('tools_used', []),
                success=True
            )
            
        except Exception as e:
            logger.error(f"Error testing {repo_name}: {e}")
            raise
    
    async def _simulate_main_scan(self, repo_name: str, repo_files: Dict[str, str]) -> Dict[str, Any]:
        """
        Simulate main scan results
        In production, this would call actual main scan functionality
        """
        # Simulate processing time
        await asyncio.sleep(1.0)
        
        # Analyze files for realistic simulation
        issues = []
        
        for file_path, content in repo_files.items():
            # Simulate various vulnerability detections based on content
            if 'hardcoded' in content.lower() or 'secret' in content.lower():
                if any(pattern in content for pattern in ['AKIA', 'sk-', 'password', 'secret_key']):
                    issues.append({
                        'tool': 'gitleaks',
                        'severity': 'critical',
                        'title': 'Hardcoded secret detected',
                        'file_path': file_path,
                        'rule_id': 'hardcoded-secret'
                    })
            
            if 'exec(' in content or 'os.system' in content or 'eval(' in content:
                issues.append({
                    'tool': 'bandit',
                    'severity': 'high', 
                    'title': 'Code injection vulnerability',
                    'file_path': file_path,
                    'rule_id': 'B102'
                })
            
            if 'SELECT * FROM' in content and ("'" + content) or ('f"' in content):
                issues.append({
                    'tool': 'semgrep',
                    'severity': 'critical',
                    'title': 'SQL injection vulnerability',
                    'file_path': file_path,
                    'rule_id': 'sql-injection'
                })
            
            if 'md5(' in content or 'hashlib.md5' in content:
                issues.append({
                    'tool': 'bandit',
                    'severity': 'medium',
                    'title': 'Use of insecure hash function',
                    'file_path': file_path,
                    'rule_id': 'B303'
                })
            
            # Infrastructure-specific issues
            if file_path.endswith('.tf'):
                if 'publicly_accessible = true' in content:
                    issues.append({
                        'tool': 'checkov',
                        'severity': 'high',
                        'title': 'Resource is publicly accessible',
                        'file_path': file_path,
                        'rule_id': 'CKV_AWS_17'
                    })
                
                if 'storage_encrypted = false' in content:
                    issues.append({
                        'tool': 'checkov', 
                        'severity': 'medium',
                        'title': 'Storage is not encrypted',
                        'file_path': file_path,
                        'rule_id': 'CKV_AWS_16'
                    })
            
            # Dependency vulnerabilities
            if file_path in ['package.json', 'requirements.txt']:
                issues.extend([
                    {
                        'tool': 'trivy',
                        'severity': 'high',
                        'title': 'Known vulnerability in dependency',
                        'file_path': file_path,
                        'rule_id': 'CVE-2020-8203'
                    }
                ])
        
        # Calculate simulated score
        issue_count = len(issues)
        critical_count = len([i for i in issues if i.get('severity') == 'critical'])
        high_count = len([i for i in issues if i.get('severity') == 'high'])
        
        # Simple scoring algorithm for simulation
        base_score = 100
        score_deduction = (critical_count * 20) + (high_count * 10) + ((issue_count - critical_count - high_count) * 3)
        total_score = max(0, base_score - score_deduction)
        
        return {
            'total_score': total_score,
            'scores': {
                'code_score': max(0, 100 - (critical_count * 15 + high_count * 8)),
                'deps_score': max(0, 100 - len([i for i in issues if 'package.json' in i.get('file_path', '')])),
                'secrets_score': max(0, 100 - len([i for i in issues if i.get('tool') == 'gitleaks']) * 25),
                'configs_score': max(0, 100 - len([i for i in issues if '.tf' in i.get('file_path', '')]) * 10)
            },
            'issues': issues,
            'tools_used': ['semgrep', 'bandit', 'gitleaks', 'trufflehog', 'checkov', 'trivy'],
            'metadata': {
                'scan_duration': 1.2,
                'files_scanned': len(repo_files)
            }
        }
    
    def _calculate_parity_score(self, cli_result, main_result) -> float:
        """Calculate parity score between CLI and main scan results"""
        
        cli_issues = len(cli_result.issues)
        main_issues = len(main_result.get('issues', []))
        
        cli_score = cli_result.total_score
        main_score = main_result.get('total_score', 0)
        
        # Issue count parity (weight: 0.4)
        if main_issues > 0:
            issue_parity = 1.0 - min(abs(cli_issues - main_issues) / main_issues, 1.0)
        else:
            issue_parity = 1.0 if cli_issues == 0 else 0.0
        
        # Score parity (weight: 0.3)
        if main_score > 0:
            score_parity = 1.0 - min(abs(cli_score - main_score) / main_score, 1.0)
        else:
            score_parity = 1.0 if cli_score == 0 else 0.0
        
        # Critical issue parity (weight: 0.3)
        cli_critical = len([i for i in cli_result.issues if i.get('severity') == 'critical'])
        main_critical = len([i for i in main_result.get('issues', []) if i.get('severity') == 'critical'])
        
        if main_critical > 0:
            critical_parity = 1.0 - min(abs(cli_critical - main_critical) / main_critical, 1.0)
        else:
            critical_parity = 1.0 if cli_critical == 0 else 0.0
        
        # Weighted average
        overall_parity = (issue_parity * 0.4) + (score_parity * 0.3) + (critical_parity * 0.3)
        
        return overall_parity
    
    def _calculate_performance_metrics(self, results: List[ParityResult]) -> Dict[str, float]:
        """Calculate performance metrics from results"""
        if not results:
            return {}
        
        cli_durations = [r.cli_scan_duration for r in results]
        main_durations = [r.main_scan_duration for r in results]
        performance_ratios = [r.cli_scan_duration / r.main_scan_duration 
                             for r in results if r.main_scan_duration > 0]
        
        return {
            'avg_cli_duration': statistics.mean(cli_durations),
            'avg_main_duration': statistics.mean(main_durations),
            'avg_performance_ratio': statistics.mean(performance_ratios) if performance_ratios else 0,
            'max_performance_ratio': max(performance_ratios) if performance_ratios else 0,
            'cli_duration_std': statistics.stdev(cli_durations) if len(cli_durations) > 1 else 0
        }
    
    def _generate_recommendations(self, results: List[ParityResult], alerts: List[str]) -> List[str]:
        """Generate recommendations based on parity results"""
        recommendations = []
        
        successful_results = [r for r in results if r.success]
        
        if not successful_results:
            recommendations.append("🚨 CRITICAL: All parity tests failed - investigate immediately")
            return recommendations
        
        avg_parity = statistics.mean([r.parity_score for r in successful_results])
        
        if avg_parity < 0.90:
            recommendations.append("🚨 URGENT: Overall parity below 90% - immediate investigation required")
        elif avg_parity < 0.95:
            recommendations.append("⚠️  WARNING: Parity below target threshold - schedule investigation")
        
        # Performance recommendations
        slow_scans = [r for r in successful_results 
                     if r.cli_scan_duration > r.main_scan_duration * self.performance_threshold]
        
        if slow_scans:
            recommendations.append(
                f"⚡ PERFORMANCE: {len(slow_scans)} repositories have slow CLI performance - optimize"
            )
        
        # Tool coverage recommendations
        for result in successful_results:
            if len(result.tools_cli) < 5:
                recommendations.append(
                    f"🛠️  TOOLS: {result.repository_name} using only {len(result.tools_cli)} tools - check coverage"
                )
        
        # Issue detection recommendations
        low_detection = [r for r in successful_results 
                        if r.cli_issues_count < r.main_issues_count * 0.8]
        
        if low_detection:
            recommendations.append(
                f"🔍 DETECTION: {len(low_detection)} repositories have low CLI issue detection - investigate rules"
            )
        
        if not alerts:
            recommendations.append("✅ All parity metrics within acceptable ranges")
        
        return recommendations[:8]  # Limit to top 8 recommendations
    
    async def _analyze_trends(self) -> Dict[str, Any]:
        """Analyze historical parity trends"""
        try:
            # Load historical data from the last 30 days
            historical_data = []
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
            
            for filename in os.listdir(self.storage_path):
                if filename.startswith('parity_report_') and filename.endswith('.json'):
                    filepath = os.path.join(self.storage_path, filename)
                    try:
                        with open(filepath, 'r') as f:
                            report_data = json.load(f)
                            report_date = datetime.fromisoformat(report_data.get('date', ''))
                            if report_date >= cutoff_date:
                                historical_data.append(report_data)
                    except (json.JSONDecodeError, ValueError, KeyError):
                        continue
            
            if not historical_data:
                return {"status": "insufficient_data", "message": "Need at least 7 days of data for trend analysis"}
            
            # Sort by date
            historical_data.sort(key=lambda x: x.get('date', ''))
            
            # Calculate trends
            parity_scores = [report.get('overall_parity_score', 0) for report in historical_data]
            
            if len(parity_scores) >= 2:
                recent_avg = statistics.mean(parity_scores[-7:]) if len(parity_scores) >= 7 else statistics.mean(parity_scores)
                older_avg = statistics.mean(parity_scores[:-7]) if len(parity_scores) >= 14 else statistics.mean(parity_scores[:-3]) if len(parity_scores) >= 6 else recent_avg
                
                trend_direction = "improving" if recent_avg > older_avg else "declining" if recent_avg < older_avg else "stable"
                trend_magnitude = abs(recent_avg - older_avg)
                
                return {
                    "status": "success",
                    "trend_direction": trend_direction,
                    "trend_magnitude": trend_magnitude,
                    "recent_avg_parity": recent_avg,
                    "historical_avg_parity": older_avg,
                    "data_points": len(historical_data),
                    "analysis_period_days": 30
                }
            else:
                return {"status": "insufficient_data", "message": "Need at least 2 data points for trend analysis"}
                
        except Exception as e:
            logger.error(f"Failed to analyze trends: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _store_parity_report(self, report: ParityReport):
        """Store parity report to persistent storage"""
        filename = f"parity_report_{report.date}.json"
        filepath = os.path.join(self.storage_path, filename)
        
        try:
            # Convert dataclasses to dict for JSON serialization
            report_dict = asdict(report)
            
            with open(filepath, 'w') as f:
                json.dump(report_dict, f, indent=2, default=str)
            
            logger.info(f"Parity report stored: {filepath}")
            
            # Also store summary metrics for quick access
            summary_filepath = os.path.join(self.storage_path, "latest_summary.json")
            summary = {
                "last_updated": report.date,
                "overall_parity_score": report.overall_parity_score,
                "repositories_tested": report.repositories_tested,
                "alerts_count": len(report.alerts_triggered),
                "success_rate": len([r for r in report.parity_results if r.success]) / len(report.parity_results) if report.parity_results else 0
            }
            
            with open(summary_filepath, 'w') as f:
                json.dump(summary, f, indent=2)
            
        except Exception as e:
            logger.error(f"Failed to store parity report: {e}")
    
    async def _send_parity_alerts(self, report: ParityReport):
        """Send parity alerts to configured recipients"""
        if not self.alert_recipients:
            logger.warning("No alert recipients configured")
            return
        
        try:
            subject = f"DevSecureX CLI Parity Alert - {report.date}"
            
            # Create email content
            body = self._create_alert_email_body(report)
            
            # In a production environment, you would configure actual SMTP settings
            # For now, we'll log the alert that would be sent
            
            logger.info("=== PARITY ALERT EMAIL ===")
            logger.info(f"Subject: {subject}")
            logger.info(f"Recipients: {', '.join(self.alert_recipients)}")
            logger.info("Body:")
            logger.info(body)
            logger.info("=== END ALERT EMAIL ===")
            
            # If you have SMTP configured, uncomment and configure this:
            # await self._send_smtp_email(subject, body, self.alert_recipients)
            
        except Exception as e:
            logger.error(f"Failed to send parity alerts: {e}")
    
    def _create_alert_email_body(self, report: ParityReport) -> str:
        """Create alert email body"""
        body = f"""
DevSecureX CLI-Main Scan Parity Alert Report
===========================================

Date: {report.date}
Overall Parity Score: {report.overall_parity_score:.3f}
Repositories Tested: {report.repositories_tested}

ALERTS TRIGGERED ({len(report.alerts_triggered)}):
"""
        
        for alert in report.alerts_triggered:
            body += f"- {alert}\n"
        
        body += f"""

PERFORMANCE METRICS:
- Average CLI Duration: {report.performance_metrics.get('avg_cli_duration', 0):.2f}s
- Average Main Duration: {report.performance_metrics.get('avg_main_duration', 0):.2f}s  
- Average Performance Ratio: {report.performance_metrics.get('avg_performance_ratio', 0):.2f}x

RECOMMENDATIONS:
"""
        
        for recommendation in report.recommendations:
            body += f"- {recommendation}\n"
        
        body += f"""

DETAILED RESULTS:
"""
        
        for result in report.parity_results:
            if not result.success or result.parity_score < 0.95:
                body += f"""
Repository: {result.repository_name}
- Parity Score: {result.parity_score:.3f}
- CLI Issues: {result.cli_issues_count} | Main Issues: {result.main_issues_count}
- CLI Score: {result.cli_total_score:.1f} | Main Score: {result.main_total_score:.1f}
- Performance Ratio: {result.cli_scan_duration / result.main_scan_duration:.2f}x
"""
        
        body += f"""

TREND ANALYSIS:
{json.dumps(report.trend_analysis, indent=2)}

This is an automated alert from the DevSecureX CLI Parity Monitoring System.
Please investigate any issues and ensure CLI-Main scan parity is maintained.
"""
        
        return body
    
    async def continuous_monitoring(self, interval_seconds: int = 3600):
        """Run continuous parity monitoring"""
        logger.info(f"Starting continuous parity monitoring (interval: {interval_seconds}s)")
        
        while True:
            try:
                report = await self.daily_parity_check()
                
                if report.overall_parity_score < self.parity_threshold:
                    logger.warning(f"Continuous monitoring detected parity degradation: {report.overall_parity_score:.3f}")
                
                logger.info(f"Continuous check completed. Next check in {interval_seconds}s")
                await asyncio.sleep(interval_seconds)
                
            except KeyboardInterrupt:
                logger.info("Continuous monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def test_run(self):
        """Run a single test for validation"""
        logger.info("Running parity monitor test")
        
        try:
            report = await self.daily_parity_check()
            
            print("\n=== PARITY MONITOR TEST RESULTS ===")
            print(f"Overall Parity Score: {report.overall_parity_score:.3f}")
            print(f"Repositories Tested: {report.repositories_tested}")
            print(f"Alerts Triggered: {len(report.alerts_triggered)}")
            
            if report.alerts_triggered:
                print("\nALERTS:")
                for alert in report.alerts_triggered:
                    print(f"  - {alert}")
            
            print("\nRECOMMENDATIONS:")
            for rec in report.recommendations:
                print(f"  - {rec}")
            
            print("\nDETAILED RESULTS:")
            for result in report.parity_results:
                print(f"  {result.repository_name}: {result.parity_score:.3f} parity")
            
            print("=== END TEST RESULTS ===\n")
            
            return report
            
        except Exception as e:
            logger.error(f"Test run failed: {e}")
            raise

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="CLI-Main Scan Parity Monitor")
    parser.add_argument('--mode', choices=['daily', 'continuous', 'test-run'], 
                       default='test-run', help='Monitoring mode')
    parser.add_argument('--interval', type=int, default=3600, 
                       help='Interval in seconds for continuous mode')
    
    args = parser.parse_args()
    
    monitor = ParityMonitor()
    
    if args.mode == 'daily':
        await monitor.daily_parity_check()
    elif args.mode == 'continuous':
        await monitor.continuous_monitoring(args.interval)
    elif args.mode == 'test-run':
        await monitor.test_run()

if __name__ == "__main__":
    asyncio.run(main())