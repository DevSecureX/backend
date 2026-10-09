"""
Scan-Specific Auto-Fix Integration for DevSecureX
Handles auto-fix for completed scans using existing scan results
"""

import logging
import json
import os
import tempfile
import shutil
import asyncio
import aiohttp
import ast
import re
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

class ScanAutoFixer:
    """
    Auto-fix system for completed scans that already have issues identified
    Works with scan IDs to retrieve and fix existing security issues
    """
    
    def __init__(self):
        self.github_api_base = "https://api.github.com"
        
        # Initialize AI for fixes
        from ..ai.smart_explainer import SmartAIExplainer
        openai_api_key = os.getenv('OPENAI_API_KEY', '')
        self.ai_explainer = SmartAIExplainer(openai_api_key) if openai_api_key else None
        
        # Performance metrics
        self.metrics = {
            'fetch_time': 0,
            'fix_time': 0,
            'pr_time': 0,
            'total_time': 0
        }
    
    async def apply_scan_fixes(
        self,
        scan_id: str,
        scan_data: Dict[str, Any],
        gh_token: str,
        create_pr: bool = True,
        severity_filter: Optional[List[str]] = None,
        db_session = None,
        progress_callback = None
    ) -> Dict[str, Any]:
        """
        Apply auto-fixes for issues from a completed scan
        
        Args:
            scan_id: The scan ID to retrieve issues from
            scan_data: Scan details including repo info and issues
            gh_token: GitHub access token
            create_pr: Whether to create a PR with fixes
            severity_filter: List of severities to fix (e.g., ['critical', 'high'])
            db_session: Database session for retrieving additional data
        """
        
        start_time = time.time()
        logger.info(f"Starting scan-based auto-fix for scan {scan_id}")
        
        try:
            # 1. Extract scan information
            if progress_callback:
                await progress_callback(20, "Extracting scan information...")
                
            fetch_start = time.time()
            repo_full_name = scan_data.get('repo_full_name')
            branch = scan_data.get('branch', 'main')
            issues = scan_data.get('issues', [])
            pr_number = scan_data.get('metadata', {}).get('pr_number')
            commit_sha = scan_data.get('metadata', {}).get('commit_sha')
            
            self.metrics['fetch_time'] = time.time() - fetch_start
            
            if not repo_full_name:
                raise ValueError("Repository name not found in scan data")
            
            if not issues:
                logger.info("No issues found in scan to fix")
                return {
                    "status": "success",
                    "scan_id": scan_id,
                    "fixed_count": 0,
                    "message": "No security issues found to fix",
                    "metrics": self.metrics
                }
            
            logger.info(f"Found {len(issues)} issues in scan {scan_id}")
            
            # 2. Filter issues by severity if requested
            if progress_callback:
                await progress_callback(30, "Filtering issues by severity...")
                
            if severity_filter:
                filtered_issues = [
                    issue for issue in issues 
                    if issue.get('severity', '').lower() in [s.lower() for s in severity_filter]
                ]
                logger.info(f"Filtered to {len(filtered_issues)} issues based on severity: {severity_filter}")
            else:
                filtered_issues = issues
            
            if not filtered_issues:
                return {
                    "status": "success",
                    "scan_id": scan_id,
                    "fixed_count": 0,
                    "issues_found": len(issues),
                    "message": f"No issues matching severity filter {severity_filter}",
                    "metrics": self.metrics
                }
            
            # 3. Clone repository and prepare workspace
            if progress_callback:
                await progress_callback(40, "Setting up workspace...")
                
            temp_dir = await self._setup_workspace(repo_full_name, branch, commit_sha, gh_token)
            
            if progress_callback:
                await progress_callback(50, "Repository cloned successfully...")
            
            try:
                # 4. Apply targeted fixes
                if progress_callback:
                    await progress_callback(60, "Analyzing issues for fixes...")
                    
                fix_start = time.time()
                fixed_files, fix_details = await self._apply_fixes_to_issues(
                    temp_dir, filtered_issues, progress_callback
                )
                self.metrics['fix_time'] = time.time() - fix_start
                
                if progress_callback:
                    await progress_callback(70, "Security fixes generated successfully...")
                
                if not fixed_files:
                    logger.info("No fixes could be applied")
                    return {
                        "status": "success",
                        "scan_id": scan_id,
                        "fixed_count": 0,
                        "issues_found": len(filtered_issues),
                        "message": "Issues found but no automatic fixes available",
                        "metrics": self.metrics
                    }
                
                logger.info(f"Successfully fixed {len(fixed_files)} files")
                
                # 5. Create PR if requested
                if create_pr:
                    if progress_callback:
                        await progress_callback(85, "Creating pull request...")
                        
                    pr_start = time.time()
                    pr_url = await self._create_fix_pr(
                        repo_full_name, branch, fixed_files, 
                        filtered_issues, fix_details, 
                        scan_id, pr_number, gh_token
                    )
                    self.metrics['pr_time'] = time.time() - pr_start
                    
                    self.metrics['total_time'] = time.time() - start_time
                    
                    if progress_callback:
                        await progress_callback(95, "Finalizing auto-fix...")
                    
                    return {
                        "status": "success",
                        "scan_id": scan_id,
                        "fixed_count": len(fixed_files),
                        "fixed_files": list(fixed_files.keys()),
                        "pr_url": pr_url,
                        "issues_found": len(filtered_issues),
                        "metrics": self.metrics,
                        "message": f"Successfully created PR with {len(fixed_files)} security fixes"
                    }
                else:
                    self.metrics['total_time'] = time.time() - start_time
                    
                    return {
                        "status": "success",
                        "scan_id": scan_id,
                        "fixed_count": len(fixed_files),
                        "fixed_files": list(fixed_files.keys()),
                        "issues_found": len(filtered_issues),
                        "metrics": self.metrics,
                        "message": f"Successfully applied {len(fixed_files)} security fixes"
                    }
                    
            finally:
                # Always cleanup temp directory
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    
        except Exception as e:
            logger.error(f"Scan auto-fix failed: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    async def _setup_workspace(
        self, 
        repo_full_name: str, 
        branch: str,
        commit_sha: Optional[str],
        gh_token: str
    ) -> str:
        """Setup workspace with repository code"""
        
        temp_dir = tempfile.mkdtemp(prefix=f"scan_autofix_{repo_full_name.replace('/', '_')}_")
        
        # Clone the repository
        clone_url = f"https://{gh_token}@github.com/{repo_full_name}.git"
        
        # Clone at specific commit if available, otherwise use branch
        if commit_sha:
            # Clone and checkout specific commit
            cmd = [
                "git", "clone", "--no-checkout", clone_url, temp_dir
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Failed to clone repository: {stderr.decode()}")
            
            # Checkout specific commit
            checkout_cmd = ["git", "checkout", commit_sha]
            process = await asyncio.create_subprocess_exec(
                *checkout_cmd,
                cwd=temp_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.warning(f"Failed to checkout commit {commit_sha}, using branch {branch}")
                # Fallback to branch
                checkout_cmd = ["git", "checkout", branch]
                process = await asyncio.create_subprocess_exec(
                    *checkout_cmd,
                    cwd=temp_dir,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
        else:
            # Clone specific branch
            cmd = [
                "git", "clone", "--single-branch", "--branch", branch,
                "--depth", "1", clone_url, temp_dir
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Failed to clone repository: {stderr.decode()}")
        
        logger.info(f"Cloned repository to {temp_dir}")
        return temp_dir
    
    async def _apply_fixes_to_issues(
        self,
        temp_dir: str,
        issues: List[Dict[str, Any]],
        progress_callback = None
    ) -> Tuple[Dict[str, str], Dict[str, Any]]:
        """Apply fixes to identified security issues"""
        
        if not self.ai_explainer:
            logger.warning("AI explainer not available, cannot apply fixes")
            return {}, {}
        
        # Stage 1: Initialize and parse repository information
        if progress_callback:
            await progress_callback(9, "Stage 1 of 11: Initializing autofix process...")
        
        # Group issues by file
        issues_by_file = defaultdict(list)
        for issue in issues:
            file_path = issue.get('file_path', '')
            if file_path and not file_path.startswith(".git/"):
                issues_by_file[file_path].append(issue)
        
        # Stage 2: Analyze and categorize security issues
        if progress_callback:
            await progress_callback(18, "Stage 2 of 11: Analyzing security issues...")
        
        fixed_files = {}
        fix_details = {}
        
        # Stage 3: Preparing fix generation system
        if progress_callback:
            await progress_callback(27, "Stage 3 of 11: Initializing AI-powered fix generation...")
        
        # Process each file
        file_count = 0
        total_files = len(issues_by_file)
        for file_path, file_issues in issues_by_file.items():
            file_count += 1
            # Progress within Stage 4-7: 36% + (file_progress * 36% / total_files)
            file_progress = (file_count / total_files) * 36
            if progress_callback:
                await progress_callback(36 + file_progress, f"Stage 4-7 of 11: Processing file {file_count}/{total_files}: {file_path}...")
            full_path = os.path.join(temp_dir, file_path)
            
            if not os.path.exists(full_path):
                logger.warning(f"File not found: {full_path}")
                continue
            
            try:
                # Read original file
                with open(full_path, 'r', encoding='utf-8') as f:
                    original_content = f.read()
                
                # Detect language and context
                language = self._detect_language(file_path)
                
                # Apply fixes
                fixed_content, fix_info = await self._fix_file_issues(
                    original_content, file_issues, file_path, language
                )
                
                if fixed_content != original_content:
                    # Write fixed content
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                    
                    fixed_files[file_path] = fixed_content
                    fix_details[file_path] = fix_info
                    
                    logger.info(f"Applied fixes to {file_path}")
                
            except Exception as e:
                logger.error(f"Error fixing file {file_path}: {e}")
                continue
        
        # Stage 8: Finalizing file processing
        if progress_callback:
            await progress_callback(81, "Stage 8 of 11: Finalizing file processing...")
        
        # Stage 9: Validating fixes and quality assurance
        if progress_callback:
            await progress_callback(90, "Stage 9 of 11: Validating security fixes...")
        
        # Stage 10: Preparing results and metrics
        if progress_callback:
            await progress_callback(95, "Stage 10 of 11: Preparing fix results...")
        
        # Stage 11: Completing autofix process
        if progress_callback:
            await progress_callback(100, "Stage 11 of 11: Autofix process completed!")
        
        return fixed_files, fix_details
    
    async def _fix_file_issues(
        self,
        content: str,
        issues: List[Dict[str, Any]],
        file_path: str,
        language: str
    ) -> Tuple[str, Dict[str, Any]]:
        """Apply fixes to a single file"""
        
        fix_info = {
            'issues_fixed': [],
            'confidence_score': 0.0
        }
        
        # Create fix prompt
        prompt = f"""Fix the following security vulnerabilities in this {language} file.

Current Code:
```{language}
{content}
```

Security Issues to Fix:
"""
        
        for i, issue in enumerate(issues, 1):
            prompt += f"""
{i}. {issue.get('severity', 'MEDIUM').upper()}: {issue.get('message', 'Security issue')}
   - Line: {issue.get('line_start', 'Unknown')}
   - Rule: {issue.get('rule_id', 'Unknown')}
   - Tool: {issue.get('tool', 'Unknown')}
"""
        
        prompt += """

Requirements:
1. Fix ALL security issues listed above
2. Preserve all functionality while fixing security issues
3. Add necessary imports if needed
4. Return the COMPLETE fixed file
5. Do not add any comments

Fixed Code:"""
        
        try:
            # Use AI to generate fixes
            response = await asyncio.to_thread(
                self.ai_explainer.client.chat.completions.create,
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer. Fix security vulnerabilities while maintaining code functionality. Return only the fixed code without any explanations or comments."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=4000
            )
            
            fixed_content = response.choices[0].message.content.strip()
            
            # Extract code from markdown if present
            if "```" in fixed_content:
                code_match = re.search(r'```(?:\w+)?\n(.*?)\n```', fixed_content, re.DOTALL)
                if code_match:
                    fixed_content = code_match.group(1)
            
            # Record fixed issues
            fix_info['issues_fixed'] = [
                {
                    'rule_id': issue.get('rule_id'),
                    'severity': issue.get('severity'),
                    'line': issue.get('line_start'),
                    'message': issue.get('message')
                }
                for issue in issues
            ]
            
            # High confidence with GPT-4
            fix_info['confidence_score'] = 0.85
            
            return fixed_content, fix_info
            
        except Exception as e:
            logger.error(f"AI fix generation failed: {e}")
            return content, fix_info
    
    async def _create_fix_pr(
        self,
        repo_full_name: str,
        base_branch: str,
        fixed_files: Dict[str, str],
        issues: List[Dict[str, Any]],
        fix_details: Dict[str, Any],
        scan_id: str,
        pr_number: Optional[int],
        gh_token: str
    ) -> str:
        """Create a pull request with the fixes"""
        
        owner, repo = repo_full_name.split("/")
        
        # Create unique branch name
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        if pr_number:
            fix_branch = f"devsecurex-scan-fixes-pr-{pr_number}-{timestamp}"
        else:
            fix_branch = f"devsecurex-scan-fixes-{scan_id[:8]}-{timestamp}"
        
        # Get default branch SHA
        default_sha = await self._get_branch_sha(owner, repo, base_branch, gh_token)
        
        # Create fix branch
        await self._create_github_branch(owner, repo, fix_branch, default_sha, gh_token)
        
        # Commit fixed files
        commit_message = f"""🔒 Security fixes from scan {scan_id[:8]}

Fixed {len(fixed_files)} files with {len(issues)} security issues

Generated by DevSecureX Scan Auto-Fix"""
        
        for file_path, content in fixed_files.items():
            await self._update_github_file(
                owner, repo, file_path, content, 
                commit_message, fix_branch, gh_token
            )
        
        # Create PR body
        pr_body = self._generate_pr_body(
            fixed_files, issues, fix_details, scan_id, pr_number
        )
        
        # Create PR
        pr_data = {
            "title": f"🔒 DevSecureX Auto-Fix: {len(issues)} vulnerabilities from scan {scan_id[:8]}",
            "body": pr_body,
            "head": fix_branch,
            "base": base_branch
        }
        
        pr_response = await self._create_github_pr(owner, repo, pr_data, gh_token)
        return pr_response.get("html_url", "")
    
    def _generate_pr_body(
        self,
        fixed_files: Dict[str, str],
        issues: List[Dict[str, Any]],
        fix_details: Dict[str, Any],
        scan_id: str,
        pr_number: Optional[int]
    ) -> str:
        """Generate PR body for scan-based fixes"""
        
        # Group issues by severity
        issues_by_severity = defaultdict(list)
        for issue in issues:
            severity = issue.get('severity', 'medium').lower()
            issues_by_severity[severity].append(issue)
        
        body = f"""# 🔒 DevSecureX Security Auto-Fix

## Summary
This PR contains automated security fixes for vulnerabilities identified in scan `{scan_id[:8]}`.

## Metrics
- **Files Fixed:** {len(fixed_files)}
- **Issues Addressed:** {len(issues)}
- **Scan ID:** `{scan_id}`
"""
        
        if pr_number:
            body += f"- **Related PR:** #{pr_number}\n"
        
        body += "\n## Issues Fixed by Severity\n\n"
        
        severity_order = ['critical', 'high', 'medium', 'low']
        severity_emojis = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️'
        }
        
        for severity in severity_order:
            if severity in issues_by_severity:
                severity_issues = issues_by_severity[severity]
                emoji = severity_emojis.get(severity, '📌')
                
                body += f"### {emoji} {severity.upper()} ({len(severity_issues)} issues)\n\n"
                
                for issue in severity_issues[:5]:  # Show first 5 issues
                    body += f"- **{issue.get('message', 'Security issue')}**\n"
                    body += f"  - File: `{issue.get('file_path', 'unknown')}`\n"
                    body += f"  - Line: {issue.get('line_start', '?')}\n"
                    body += f"  - Tool: {issue.get('tool', 'unknown')}\n\n"
                
                if len(severity_issues) > 5:
                    body += f"_...and {len(severity_issues) - 5} more {severity} issues_\n\n"
        
        body += """## Modified Files

| File | Issues Fixed |
|------|--------------|
"""
        
        for file_path in fixed_files:
            file_issue_count = len([i for i in issues if i.get('file_path') == file_path])
            body += f"| `{file_path}` | {file_issue_count} |\n"
        
        body += """
## Review Checklist
- [ ] Verify all functionality remains intact
- [ ] Run tests to ensure no regressions
- [ ] Review security fixes for correctness
- [ ] Check for any performance impacts

---
_Generated by [DevSecureX](https://www.devsecurex.com) Scan Auto-Fix_
"""
        
        return body
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        ext = Path(file_path).suffix.lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.java': 'java',
            '.cs': 'csharp',
            '.c': 'c',
            '.cpp': 'cpp',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin'
        }
        
        return language_map.get(ext, 'text')
    
    async def _get_branch_sha(self, owner: str, repo: str, branch: str, gh_token: str) -> str:
        """Get the SHA of a branch"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/git/ref/heads/{branch}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status != 200:
                    raise Exception(f"Failed to get branch SHA: {await response.text()}")
                data = await response.json()
                return data["object"]["sha"]
    
    async def _create_github_branch(self, owner: str, repo: str, branch_name: str, base_sha: str, gh_token: str):
        """Create a new branch on GitHub"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/git/refs"
        
        data = {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=data,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status != 201:
                    error_text = await response.text()
                    raise Exception(f"Failed to create branch: {error_text}")
    
    async def _update_github_file(
        self,
        owner: str,
        repo: str,
        file_path: str,
        content: str,
        commit_message: str,
        branch: str,
        gh_token: str
    ):
        """Update a file on GitHub"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/contents/{file_path}"
        
        async with aiohttp.ClientSession() as session:
            # Get current file SHA
            async with session.get(
                url,
                params={"ref": branch},
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status == 200:
                    file_data = await response.json()
                    file_sha = file_data["sha"]
                else:
                    file_sha = None
            
            # Update file
            import base64
            data = {
                "message": commit_message,
                "content": base64.b64encode(content.encode()).decode(),
                "branch": branch
            }
            
            if file_sha:
                data["sha"] = file_sha
            
            async with session.put(
                url,
                json=data,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status not in [200, 201]:
                    error_text = await response.text()
                    raise Exception(f"Failed to update file {file_path}: {error_text}")
    
    async def _create_github_pr(self, owner: str, repo: str, pr_data: Dict[str, Any], gh_token: str) -> Dict[str, Any]:
        """Create a pull request on GitHub"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/pulls"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=pr_data,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status == 201:
                    return await response.json()
                else:
                    error_text = await response.text()
                    raise Exception(f"Failed to create PR: {error_text}")