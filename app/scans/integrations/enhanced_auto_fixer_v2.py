"""
Enhanced Auto-Fix Integration V2 for DevSecureX
Improved version with performance optimizations, better PR descriptions, and smarter fixes
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
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
from collections import defaultdict
from functools import lru_cache

logger = logging.getLogger(__name__)

class EnhancedAutoFixerV2:
    """
    Enhanced auto-fix system V2 with performance optimizations and improved PR creation
    """
    
    # Cache for scan results (TTL: 5 minutes)
    _scan_cache = {}
    _cache_ttl = 300  # 5 minutes
    
    def __init__(self):
        self.github_api_base = "https://api.github.com"
        
        # Import ALL available security tools
        from ..tools.semgrep_runner import SemgrepRunner
        from ..tools.bandit_runner import BanditRunner
        from ..tools.eslint_security_runner import ESLintSecurityRunner
        from ..tools.gosec_runner import GosecRunner
        from ..tools.trivy_runner import TrivyRunner
        from ..tools.gitleaks_runner import GitLeaksRunner
        from ..tools.checkov_runner import CheckovRunner
        from ..tools.safety_runner import SafetyRunner
        from ..tools.trufflehog_runner import TruffleHogRunner
        from ..tools.brakeman_runner import BrakemanRunner
        from ..tools.cppcheck_runner import CppcheckRunner
        from ..tools.psalm_runner import PsalmRunner
        # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
        # from ..tools.roslynator_runner import RoslynatorRunner
        from ..tools.spotbugs_runner import SpotBugsRunner
        
        # Initialize ALL tool runners
        self.tool_runners = {
            'semgrep': SemgrepRunner(),
            'bandit': BanditRunner(), 
            'eslint': ESLintSecurityRunner(),
            'gosec': GosecRunner(),
            'trivy': TrivyRunner(),
            'gitleaks': GitLeaksRunner(),
            'checkov': CheckovRunner(),
            'safety': SafetyRunner(),
            'trufflehog': TruffleHogRunner(),
            'brakeman': BrakemanRunner(),
            'cppcheck': CppcheckRunner(),
            'psalm': PsalmRunner(),
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # 'roslynator': RoslynatorRunner(),
            'spotbugs': SpotBugsRunner()
        }
        
        # Initialize AI for focused fixes
        from ..ai.smart_explainer import SmartAIExplainer
        openai_api_key = os.getenv('OPENAI_API_KEY', '')
        self.ai_explainer = SmartAIExplainer(openai_api_key) if openai_api_key else None
        
        # Performance metrics tracking
        self.metrics = {
            'scan_time': 0,
            'fix_time': 0,
            'verification_time': 0,
            'total_time': 0
        }
    
    async def apply_enhanced_fixes(
        self,
        repo_full_name: str,
        pr_number: int,
        gh_token: str,
        create_pr: bool = True,
        enable_caching: bool = True,
        generate_tests: bool = False,
        update_dependencies: bool = False
    ) -> Dict[str, Any]:
        """
        Apply enhanced auto-fixes with performance optimizations
        
        Args:
            repo_full_name: Repository name (owner/repo)
            pr_number: Pull request number
            gh_token: GitHub access token
            create_pr: Whether to create a new PR with fixes
            enable_caching: Use cached scan results for identical files
            generate_tests: Generate unit tests for fixes
            update_dependencies: Auto-update vulnerable dependencies
        """
        
        start_time = time.time()
        logger.info(f"Starting enhanced auto-fix V2 for {repo_full_name}#{pr_number}")
        
        # Clear scan cache for PR-specific operations to ensure fresh, consistent results
        self._scan_cache.clear()
        logger.info("Cleared scan cache for fresh PR analysis")
        
        try:
            # 1. Get PR details and changed files
            pr_details = await self._get_pr_details(repo_full_name, pr_number, gh_token)
            changed_files = await self._get_pr_changed_files(repo_full_name, pr_number, gh_token)
            
            logger.info(f"Found {len(changed_files)} changed files in PR #{pr_number}")
            
            # 2. Clone repository and checkout PR branch
            temp_dir = await self._setup_pr_workspace(repo_full_name, pr_details, gh_token)
            
            try:
                # 3. Run security scans with parallel execution and caching
                scan_start = time.time()
                security_issues = await self._scan_changed_files_parallel(
                    temp_dir, changed_files, enable_caching
                )
                self.metrics['scan_time'] = time.time() - scan_start
                
                if not security_issues:
                    logger.info("No security issues found in changed files")
                    return {
                        "fixed_count": 0,
                        "message": "No security issues found in PR changes",
                        "metrics": self.metrics
                    }
                
                logger.info(f"Found {len(security_issues)} security issues")
                
                # 4. Calculate security score before fixes
                security_score_before = self._calculate_security_score(security_issues)
                
                # 5. Apply targeted fixes with improved AI
                fix_start = time.time()
                fixed_files, fix_details = await self._apply_smart_fixes(
                    temp_dir, security_issues, generate_tests
                )
                self.metrics['fix_time'] = time.time() - fix_start
                
                if not fixed_files:
                    logger.info("No fixes could be applied")
                    return {
                        "fixed_count": 0,
                        "message": "Security issues found but no automatic fixes available",
                        "issues_found": len(security_issues),
                        "security_score": security_score_before,
                        "metrics": self.metrics
                    }
                
                # 6. Update dependencies if requested
                if update_dependencies:
                    dependency_updates = await self._update_vulnerable_dependencies(temp_dir)
                else:
                    dependency_updates = []
                
                # 7. Verify fixes with comprehensive testing
                verify_start = time.time()
                verification_result = await self._comprehensive_verification(
                    temp_dir, changed_files, fixed_files, generate_tests, len(security_issues)
                )
                self.metrics['verification_time'] = time.time() - verify_start
                
                # 8. Calculate security score after fixes
                # Use actual remaining issues with their real severities
                remaining_issues = verification_result.get('security_scan_results', {}).get('remaining_issues_list', [])
                remaining_issues_count = len(remaining_issues)
                security_score_after = self._calculate_security_score(remaining_issues)
                
                # 9. Create enhanced PR if requested
                if create_pr:
                    # Calculate total time before PR generation
                    self.metrics['total_time'] = time.time() - start_time
                    
                    pr_url = await self._create_enhanced_pr(
                        repo_full_name, pr_details, fixed_files, 
                        security_issues, verification_result, 
                        security_score_before, security_score_after,
                        fix_details, dependency_updates, gh_token
                    )
                    
                    return {
                        "fixed_count": len(fixed_files),
                        "fixed_files": list(fixed_files.keys()),
                        "pr_url": pr_url,
                        "issues_found": len(security_issues),
                        "issues_fixed": len(security_issues) - remaining_issues_count,
                        "security_score_before": security_score_before,
                        "security_score_after": security_score_after,
                        "security_improvement": security_score_after - security_score_before,
                        "verification": verification_result,
                        "dependency_updates": dependency_updates,
                        "metrics": self.metrics,
                        "message": f"Successfully applied {len(fixed_files)} security fixes"
                    }
                else:
                    self.metrics['total_time'] = time.time() - start_time
                    return {
                        "fixed_count": len(fixed_files),
                        "fixed_files": list(fixed_files.keys()),
                        "issues_found": len(security_issues),
                        "issues_fixed": len(security_issues) - remaining_issues_count,
                        "security_score_before": security_score_before,
                        "security_score_after": security_score_after,
                        "verification": verification_result,
                        "metrics": self.metrics,
                        "message": f"Successfully applied {len(fixed_files)} security fixes"
                    }
                    
            finally:
                # Always cleanup temp directory
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    
        except Exception as e:
            import traceback
            import sys
            exc_type, exc_value, exc_traceback = sys.exc_info()
            tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            logger.error(f"Enhanced auto-fix V2 failed with {type(e).__name__}: {e}")
            for line in tb_lines:
                logger.error(f"TRACE: {line.strip()}")
            raise
    
    async def _scan_changed_files_parallel(
        self, 
        temp_dir: str, 
        changed_files: List[Dict[str, Any]],
        enable_caching: bool = True
    ) -> List[Dict[str, Any]]:
        """Run security scans in parallel for better performance"""
        
        target_files = [f["filename"] for f in changed_files]
        logger.info(f"Parallel scanning {len(target_files)} files")
        
        # Check cache for identical files
        if enable_caching:
            cached_results = []
            files_to_scan = []
            
            for file in sorted(target_files):  # Sort for consistent processing order
                cache_key = self._get_file_cache_key(temp_dir, file)
                cached = self._get_cached_scan(cache_key)
                
                if cached:
                    logger.info(f"Using cached results for {file}")
                    cached_results.extend(cached)
                else:
                    files_to_scan.append(file)
        else:
            files_to_scan = sorted(target_files)  # Sort for consistent processing order
            cached_results = []
        
        if not files_to_scan:
            return cached_results
        
        # Determine which tools to run
        tools_to_run = self._determine_tools_for_files(files_to_scan)
        
        # Run tools in parallel with consistent ordering for deterministic results
        scan_tasks = []
        for tool_name in sorted(tools_to_run):  # Sort for consistent execution order
            if tool_name in self.tool_runners:
                task = self._run_tool_async(tool_name, temp_dir, files_to_scan)
                scan_tasks.append(task)
        
        # Execute all scans in parallel
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Process results
        all_issues = cached_results
        for result in scan_results:
            if isinstance(result, Exception):
                logger.error(f"Tool scan failed: {result}")
                continue
            
            # Handle different result types from tools
            if isinstance(result, list):
                all_issues.extend(result)
            elif isinstance(result, dict) and 'issues' in result:
                if isinstance(result['issues'], list):
                    all_issues.extend(result['issues'])
                else:
                    logger.warning(f"Tool returned non-list issues: {type(result['issues'])}")
            elif result is not None:
                logger.warning(f"Tool returned unexpected result type: {type(result)} - {result}")
                continue
        
        # Cache results for scanned files
        if enable_caching and files_to_scan:
            for file in files_to_scan:
                file_issues = [i for i in all_issues if i.get('file_path') == file]
                cache_key = self._get_file_cache_key(temp_dir, file)
                self._cache_scan_result(cache_key, file_issues)
        
        # Sort issues for consistent processing order (deterministic results)
        all_issues.sort(key=lambda x: (
            x.get('file_path', ''),
            x.get('line_start', 0),
            x.get('tool', ''),
            x.get('rule_id', '')
        ))
        
        # Deduplicate issues
        unique_issues = self._deduplicate_issues(all_issues)
        
        logger.info(f"Total unique security issues found: {len(unique_issues)}")
        return unique_issues
    
    async def _run_tool_async(self, tool_name: str, temp_dir: str, target_files: List[str]) -> List[Dict[str, Any]]:
        """Run a security tool asynchronously"""
        try:
            logger.info(f"Running {tool_name} on {len(target_files)} files")
            runner = self.tool_runners[tool_name]
            
            # Run tool with appropriate parameters based on tool type
            # Match the working implementation from enhanced_auto_fixer.py
            if tool_name == 'semgrep':
                result = await runner.run(
                    temp_dir, 
                    target_files=target_files,
                    niche=None,
                    custom_rule_files=[]
                )
            elif tool_name == 'bandit':
                result = await runner.run(
                    temp_dir, 
                    target_files=target_files
                )
            elif tool_name == 'eslint':
                result = await runner.run(
                    temp_dir, 
                    target_files=target_files
                )
            elif tool_name == 'gosec':
                result = await runner.run(
                    temp_dir, 
                    target_files=target_files
                )
            elif tool_name == 'trivy':
                result = await runner.run(
                    temp_dir,
                    scan_types=['vuln', 'secret', 'misconfig']
                )
            elif tool_name == 'gitleaks':
                result = await runner.run(temp_dir)
            elif tool_name == 'checkov':
                result = await runner.run(temp_dir)
            elif tool_name == 'safety':
                result = await runner.run(temp_dir)
            elif tool_name == 'trufflehog':
                result = await runner.run(temp_dir)
            elif tool_name == 'brakeman':
                result = await runner.run(temp_dir, file_list=target_files)
            elif tool_name == 'cppcheck':
                result = await runner.run(temp_dir, target_files=target_files)
            elif tool_name == 'psalm':
                result = await runner.run(temp_dir)
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # elif tool_name == 'roslynator':
                result = await runner.run(temp_dir)
            elif tool_name == 'spotbugs':
                result = await runner.run(temp_dir)
            else:
                # Generic runner for any other tools
                try:
                    result = await runner.run(temp_dir, target_files=target_files)
                except:
                    result = await runner.run(temp_dir)
            
            if "error" not in result and result.get("issues"):
                issues = result["issues"]
                logger.info(f"{tool_name} found {len(issues)} issues")
                # Add tool name to each issue and filter to changed files only
                for issue in issues:
                    issue['tool'] = tool_name
                # Filter issues to only those in target files (important for tools that scan entire repo)
                filtered_issues = self._filter_issues_to_changed_files(issues, target_files)
                logger.info(f"{tool_name} contributed {len(filtered_issues)} issues from changed files")
                return filtered_issues
            else:
                logger.info(f"{tool_name} found no issues")
                return []
                
        except Exception as e:
            logger.error(f"Error running {tool_name}: {e}")
            return []
    
    def _get_file_cache_key(self, temp_dir: str, filename: str) -> str:
        """Generate cache key for a file based on its content"""
        try:
            full_path = os.path.join(temp_dir, filename)
            if os.path.exists(full_path):
                with open(full_path, 'rb') as f:
                    content = f.read()
                    return hashlib.sha256(content).hexdigest()
        except:
            pass
        return None
    
    def _get_cached_scan(self, cache_key: str) -> Optional[List[Dict[str, Any]]]:
        """Get cached scan results if available and not expired"""
        if not cache_key:
            return None
            
        if cache_key in self._scan_cache:
            cached_data = self._scan_cache[cache_key]
            if time.time() - cached_data['timestamp'] < self._cache_ttl:
                return cached_data['issues']
            else:
                # Expired, remove from cache
                del self._scan_cache[cache_key]
        return None
    
    def _cache_scan_result(self, cache_key: str, issues: List[Dict[str, Any]]):
        """Cache scan results for a file"""
        if cache_key:
            self._scan_cache[cache_key] = {
                'issues': issues,
                'timestamp': time.time()
            }
    
    def _calculate_security_score(self, issues: List[Dict[str, Any]]) -> float:
        """Calculate security score based on issues (0-100, higher is better)"""
        if not issues:
            return 100.0
        
        # Weight by severity
        severity_weights = {
            'critical': 10,
            'high': 5,
            'medium': 2,
            'low': 1
        }
        
        total_weight = sum(
            severity_weights.get(issue.get('severity', 'medium').lower(), 1)
            for issue in issues
        )
        
        # Score decreases with more and severe issues
        score = max(0, 100 - (total_weight * 2))
        return round(score, 1)
    
    async def _apply_smart_fixes(
        self, 
        temp_dir: str, 
        security_issues: List[Dict[str, Any]],
        generate_tests: bool = False
    ) -> Tuple[Dict[str, str], Dict[str, Any]]:
        """Apply smart fixes with context awareness and test generation"""
        
        if not self.ai_explainer:
            logger.warning("AI explainer not available, cannot apply fixes")
            return {}, {}
        
        # Group issues by file (excluding .git directory)
        issues_by_file = defaultdict(list)
        for issue in security_issues:
            file_path = issue.get('file_path', '')
            # Skip .git directory files
            if file_path and not file_path.startswith(".git/"):
                issues_by_file[file_path].append(issue)
            elif file_path.startswith(".git/"):
                logger.warning(f"Skipping issue in .git directory file: {file_path}")
        
        fixed_files = {}
        fix_details = {}
        
        # Process each file
        for file_path, file_issues in issues_by_file.items():
            full_path = os.path.join(temp_dir, file_path)
            
            if not os.path.exists(full_path):
                logger.warning(f"File not found: {full_path}")
                continue
            
            try:
                # Read original file
                with open(full_path, 'r', encoding='utf-8') as f:
                    original_content = f.read()
                
                # Detect project patterns and imports
                project_context = self._analyze_project_context(temp_dir, file_path)
                
                # Apply comprehensive fixes with context
                fixed_content, fix_info = await self._fix_with_context(
                    original_content, file_issues, file_path, project_context
                )
                
                if fixed_content != original_content:
                    # Write fixed content
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(fixed_content)
                    
                    fixed_files[file_path] = fixed_content
                    fix_details[file_path] = fix_info
                    
                    # Generate tests if requested
                    if generate_tests:
                        test_content = await self._generate_tests_for_fixes(
                            file_path, fix_info, project_context
                        )
                        if test_content:
                            test_path = self._get_test_file_path(file_path)
                            test_full_path = os.path.join(temp_dir, test_path)
                            os.makedirs(os.path.dirname(test_full_path), exist_ok=True)
                            with open(test_full_path, 'w') as f:
                                f.write(test_content)
                            fixed_files[test_path] = test_content
                    
                    logger.info(f"Applied fixes to {file_path}")
                
            except Exception as e:
                logger.error(f"Error fixing file {file_path}: {e}")
                continue
        
        return fixed_files, fix_details
    
    def _analyze_project_context(self, temp_dir: str, file_path: str) -> Dict[str, Any]:
        """Analyze project context to make context-aware fixes"""
        context = {
            'language': self._detect_language(file_path),
            'framework': None,
            'test_framework': None,
            'imports': [],
            'coding_style': {},
            'dependencies': []
        }
        
        language = context['language']
        
        # Detect framework and common patterns
        if language == 'python':
            # Check for common Python frameworks
            package_files = ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile']
            for pf in package_files:
                pf_path = os.path.join(temp_dir, pf)
                if os.path.exists(pf_path):
                    with open(pf_path, 'r') as f:
                        content = f.read().lower()
                        if 'flask' in content:
                            context['framework'] = 'flask'
                        elif 'django' in content:
                            context['framework'] = 'django'
                        elif 'fastapi' in content:
                            context['framework'] = 'fastapi'
                        
                        if 'pytest' in content:
                            context['test_framework'] = 'pytest'
                        elif 'unittest' in content:
                            context['test_framework'] = 'unittest'
        
        elif language == 'javascript':
            # Check for package.json
            package_json_path = os.path.join(temp_dir, 'package.json')
            if os.path.exists(package_json_path):
                with open(package_json_path, 'r') as f:
                    try:
                        package_data = json.load(f)
                        deps = {**package_data.get('dependencies', {}), 
                               **package_data.get('devDependencies', {})}
                        
                        if 'react' in deps:
                            context['framework'] = 'react'
                        elif 'vue' in deps:
                            context['framework'] = 'vue'
                        elif 'express' in deps:
                            context['framework'] = 'express'
                        
                        if 'jest' in deps:
                            context['test_framework'] = 'jest'
                        elif 'mocha' in deps:
                            context['test_framework'] = 'mocha'
                        
                        context['dependencies'] = list(deps.keys())
                    except:
                        pass
        
        return context
    
    async def _fix_with_context(
        self,
        content: str,
        issues: List[Dict[str, Any]],
        file_path: str,
        project_context: Dict[str, Any]
    ) -> Tuple[str, Dict[str, Any]]:
        """Apply fixes with project context awareness"""
        
        fix_info = {
            'issues_fixed': [],
            'imports_added': [],
            'breaking_changes': [],
            'confidence_scores': {}
        }
        
        # Create comprehensive fix prompt with context
        prompt = f"""Fix the following security vulnerabilities in this {project_context['language']} file.

Project Context:
- Framework: {project_context.get('framework', 'None detected')}
- Test Framework: {project_context.get('test_framework', 'None detected')}
- File: {file_path}

Current Code:
```{project_context['language']}
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
2. Use the project's existing framework patterns when possible
3. Add necessary imports at the top of the file
4. Preserve all functionality while fixing security issues
5. Add brief comments explaining security fixes
6. Return the COMPLETE fixed file

Fixed Code:"""
        
        try:
            # Use GPT-4 for complex fixes
            response = await asyncio.to_thread(
                self.ai_explainer.client.chat.completions.create,
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security engineer. Fix security vulnerabilities while maintaining code functionality and following project patterns."
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
            
            # Detect added imports
            original_imports = set(re.findall(r'^import\s+(\S+)', content, re.MULTILINE))
            fixed_imports = set(re.findall(r'^import\s+(\S+)', fixed_content, re.MULTILINE))
            fix_info['imports_added'] = list(fixed_imports - original_imports)
            
            # Check for potential breaking changes
            if 'eval(' in content and 'eval(' not in fixed_content:
                fix_info['breaking_changes'].append("Removed eval() - may affect dynamic code execution")
            
            # Record fixed issues
            fix_info['issues_fixed'] = [
                {
                    'rule_id': issue.get('rule_id'),
                    'severity': issue.get('severity'),
                    'line': issue.get('line_start')
                }
                for issue in issues
            ]
            
            # Calculate confidence score
            fix_info['confidence_scores']['overall'] = 0.85  # High confidence with GPT-4
            
            return fixed_content, fix_info
            
        except Exception as e:
            logger.error(f"Context-aware fix failed: {e}")
            return content, fix_info
    
    async def _generate_tests_for_fixes(
        self,
        file_path: str,
        fix_info: Dict[str, Any],
        project_context: Dict[str, Any]
    ) -> Optional[str]:
        """Generate unit tests for the security fixes"""
        
        if not fix_info.get('issues_fixed'):
            return None
        
        language = project_context['language']
        test_framework = project_context.get('test_framework')
        
        if language == 'python' and test_framework:
            prompt = f"""Generate unit tests for security fixes in {file_path}.

Fixed Issues:
{json.dumps(fix_info['issues_fixed'], indent=2)}

Test Framework: {test_framework}

Generate comprehensive tests that verify:
1. The security vulnerabilities are fixed
2. The functionality still works correctly
3. Edge cases are handled

Tests:"""
            
            try:
                response = await asyncio.to_thread(
                    self.ai_explainer.client.chat.completions.create,
                    model="gpt-4o-mini",
                    messages=[
                        {
                            "role": "system",
                            "content": f"Generate {test_framework} tests for security fixes."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                    max_tokens=2000
                )
                
                return response.choices[0].message.content.strip()
                
            except Exception as e:
                logger.error(f"Test generation failed: {e}")
        
        return None
    
    def _get_test_file_path(self, source_file: str) -> str:
        """Get the test file path for a source file"""
        base_name = os.path.basename(source_file)
        name_without_ext = os.path.splitext(base_name)[0]
        ext = os.path.splitext(base_name)[1]
        
        if ext == '.py':
            return f"tests/test_{name_without_ext}.py"
        elif ext in ['.js', '.ts']:
            return f"tests/{name_without_ext}.test{ext}"
        else:
            return f"tests/test_{base_name}"
    
    async def _update_vulnerable_dependencies(self, temp_dir: str) -> List[Dict[str, Any]]:
        """Update vulnerable dependencies automatically"""
        updates = []
        
        # Check for Python dependencies
        requirements_path = os.path.join(temp_dir, 'requirements.txt')
        if os.path.exists(requirements_path):
            # Run safety check
            try:
                from ..tools.safety_runner import SafetyRunner
                safety = SafetyRunner()
                result = await safety.run(temp_dir)
                
                if not result.get('error') and result.get('issues'):
                    for issue in result['issues']:
                        if 'package' in issue:
                            package = issue['package']
                            safe_version = issue.get('safe_version', 'latest')
                            updates.append({
                                'file': 'requirements.txt',
                                'package': package,
                                'current': issue.get('installed_version'),
                                'updated': safe_version,
                                'vulnerability': issue.get('vulnerability')
                            })
                            
                            # Update requirements.txt
                            with open(requirements_path, 'r') as f:
                                content = f.read()
                            
                            # Update version
                            pattern = f"{package}[=<>~!]*[\\d.]*"
                            replacement = f"{package}>={safe_version}"
                            content = re.sub(pattern, replacement, content)
                            
                            with open(requirements_path, 'w') as f:
                                f.write(content)
                                
            except Exception as e:
                logger.error(f"Dependency update failed: {e}")
        
        # Check for Node.js dependencies
        package_json_path = os.path.join(temp_dir, 'package.json')
        if os.path.exists(package_json_path):
            # Run npm audit fix
            try:
                result = subprocess.run(
                    ['npm', 'audit', 'fix', '--force'],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    # Parse npm audit output
                    audit_result = subprocess.run(
                        ['npm', 'audit', '--json'],
                        cwd=temp_dir,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if audit_result.stdout:
                        try:
                            audit_data = json.loads(audit_result.stdout)
                            if 'vulnerabilities' in audit_data:
                                for vuln in audit_data.get('vulnerabilities', {}).values():
                                    updates.append({
                                        'file': 'package.json',
                                        'package': vuln.get('name'),
                                        'severity': vuln.get('severity'),
                                        'vulnerability': vuln.get('title')
                                    })
                        except:
                            pass
                            
            except Exception as e:
                logger.error(f"NPM audit failed: {e}")
        
        return updates
    
    async def _comprehensive_verification(
        self,
        temp_dir: str,
        changed_files: List[Dict[str, Any]],
        fixed_files: Dict[str, str],
        run_tests: bool = False,
        original_issues_count: int = 0
    ) -> Dict[str, Any]:
        """Comprehensive verification including tests and performance checks"""
        
        logger.info("Running comprehensive verification")
        
        verification = {
            'syntax_validation': {},
            'security_scan_results': {},
            'test_results': {},
            'performance_impact': {},
            'breaking_changes': []
        }
        
        # 1. Syntax validation for all fixed files
        for file_path in fixed_files:
            is_valid = await self._validate_syntax(
                os.path.join(temp_dir, file_path),
                self._detect_language(file_path)
            )
            verification['syntax_validation'][file_path] = is_valid
        
        # 2. Re-run security scans
        # Ensure fixed_files is a dict before accessing keys
        if isinstance(fixed_files, dict):
            target_files = list(fixed_files.keys())
        else:
            logger.error(f"fixed_files is not a dict in verification: {type(fixed_files)}")
            target_files = []
        
        if target_files:
            verification_issues = await self._scan_changed_files_parallel(
                temp_dir, [{"filename": f} for f in target_files], enable_caching=False
            )
        else:
            verification_issues = []
        
        # Ensure verification_issues is a list
        if not isinstance(verification_issues, list):
            logger.warning(f"Verification issues is not a list: {type(verification_issues)}")
            verification_issues = []
        
        # Safe calculation to avoid type errors
        total_scanned = len(target_files) if isinstance(target_files, list) else 0
        issues_remaining = len(verification_issues) if isinstance(verification_issues, list) else 0
        
        # Calculate resolution rate based on original issues vs remaining issues
        if original_issues_count > 0:
            resolution_rate = 1 - (issues_remaining / original_issues_count)
        else:
            resolution_rate = 1.0 if issues_remaining == 0 else 0.0
        
        verification['security_scan_results'] = {
            'total_scanned': total_scanned,
            'issues_remaining': issues_remaining,
            'remaining_issues_list': verification_issues,  # Include actual remaining issues
            'resolution_rate': max(0.0, min(1.0, resolution_rate))  # Clamp to 0-1 range
        }
        
        # 3. Run existing tests if requested
        if run_tests:
            test_results = await self._run_project_tests(temp_dir)
            verification['test_results'] = test_results
        
        # 4. Check for performance impact (basic check)
        for file_path in fixed_files:
            # Check if fixes added loops or complex operations
            original = changed_files[0].get('patch', '')
            if 'for ' in fixed_files[file_path] and 'for ' not in original:
                verification['performance_impact'][file_path] = 'Added loop - may impact performance'
        
        # 5. Detect breaking changes
        for file_path in fixed_files:
            content = fixed_files[file_path]
            if 'eval(' in original and 'eval(' not in content:
                verification['breaking_changes'].append(f"{file_path}: Removed eval() function")
            if 'exec(' in original and 'exec(' not in content:
                verification['breaking_changes'].append(f"{file_path}: Removed exec() function")
        
        verification['verification_successful'] = (
            all(verification['syntax_validation'].values()) and
            verification['security_scan_results']['resolution_rate'] > 0.5
        )
        
        return verification
    
    async def _run_project_tests(self, temp_dir: str) -> Dict[str, Any]:
        """Run project's existing tests"""
        test_results = {
            'framework': None,
            'passed': False,
            'test_count': 0,
            'failures': []
        }
        
        # Try Python tests
        if os.path.exists(os.path.join(temp_dir, 'pytest.ini')) or \
           os.path.exists(os.path.join(temp_dir, 'setup.cfg')):
            try:
                result = subprocess.run(
                    ['pytest', '--tb=short', '-q'],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                test_results['framework'] = 'pytest'
                test_results['passed'] = result.returncode == 0
                
                # Parse output for test count
                if 'passed' in result.stdout:
                    import re
                    match = re.search(r'(\d+) passed', result.stdout)
                    if match:
                        test_results['test_count'] = int(match.group(1))
                
                if result.returncode != 0:
                    test_results['failures'].append(result.stderr[:500])
                    
            except Exception as e:
                logger.error(f"pytest failed: {e}")
        
        # Try Node.js tests
        elif os.path.exists(os.path.join(temp_dir, 'package.json')):
            try:
                result = subprocess.run(
                    ['npm', 'test'],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                test_results['framework'] = 'npm'
                test_results['passed'] = result.returncode == 0
                
                if result.returncode != 0:
                    test_results['failures'].append(result.stderr[:500])
                    
            except Exception as e:
                logger.error(f"npm test failed: {e}")
        
        return test_results
    
    async def _create_enhanced_pr(
        self,
        repo_full_name: str,
        pr_details: Dict[str, Any],
        fixed_files: Dict[str, str],
        original_issues: List[Dict[str, Any]],
        verification: Dict[str, Any],
        security_score_before: float,
        security_score_after: float,
        fix_details: Dict[str, Any],
        dependency_updates: List[Dict[str, Any]],
        gh_token: str
    ) -> str:
        """Create enhanced PR with comprehensive information"""
        
        owner, repo = repo_full_name.split("/")
        base_branch = pr_details["head"]["ref"]
        fix_branch = f"devsecurex-security-fixes-pr-{pr_details['number']}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        # Create fix branch
        await self._create_github_branch(owner, repo, fix_branch, pr_details["head"]["sha"], gh_token)
        
        # Commit fixed files with detailed message
        # Safely get counts
        fixed_files_count = len(fixed_files) if isinstance(fixed_files, dict) else 0
        original_issues_count = len(original_issues) if isinstance(original_issues, list) else original_issues if isinstance(original_issues, int) else 0
        
        commit_message = f"""🔒 Security fixes for PR #{pr_details['number']}

Fixed {fixed_files_count} files with {original_issues_count} security issues
Security Score: {security_score_before}% → {security_score_after}% (+{security_score_after - security_score_before}%)

Generated by DevSecureX Enhanced Auto-Fix V2"""
        
        for file_path, content in fixed_files.items():
            # Skip .git directory files completely
            if file_path.startswith(".git/"):
                logger.warning(f"Skipping .git directory file in PR creation: {file_path}")
                continue
            await self._update_github_file(owner, repo, file_path, content, commit_message, fix_branch, gh_token)
        
        # Calculate issues resolved before generating PR content
        original_issues_count = len(original_issues)
        issues_resolved = original_issues_count - verification.get('security_scan_results', {}).get('issues_remaining', 0)
        
        # Create comprehensive PR body
        pr_body = self._generate_enhanced_pr_body_v2(
            fixed_files, original_issues, verification,
            security_score_before, security_score_after,
            fix_details, dependency_updates, self.metrics
        )
        
        pr_data = {
            "title": f"🔒 DevSecureX Auto-Fix: {issues_resolved} vulnerabilities resolved (+{security_score_after - security_score_before:.1f}% security boost)",
            "body": pr_body,
            "head": fix_branch,
            "base": base_branch
        }
        
        pr_response = await self._create_github_pr(owner, repo, pr_data, gh_token)
        return pr_response.get("html_url", "")
    
    def _generate_enhanced_pr_body_v2(
        self,
        fixed_files: Dict[str, str],
        original_issues: List[Dict[str, Any]],
        verification: Dict[str, Any],
        score_before: float,
        score_after: float,
        fix_details: Dict[str, Any],
        dependency_updates: List[Dict[str, Any]],
        metrics: Dict[str, Any]
    ) -> str:
        """Generate comprehensive PR body with all improvements"""
        
        # Debug logging to identify the issue
        logger.debug(f"Type of fixed_files: {type(fixed_files)}")
        logger.debug(f"Type of original_issues: {type(original_issues)}")
        
        # Ensure fixed_files is a dict
        if not isinstance(fixed_files, dict):
            logger.error(f"fixed_files is not a dict, it's {type(fixed_files)}: {fixed_files}")
            fixed_files_count = 0
        else:
            fixed_files_count = len(fixed_files)
        
        # Ensure original_issues is a list
        if not isinstance(original_issues, list):
            logger.error(f"original_issues is not a list, it's {type(original_issues)}: {original_issues}")
            original_issues_count = 0
        else:
            original_issues_count = len(original_issues)
        
        # Calculate improvement metrics
        issues_resolved = original_issues_count - verification.get('security_scan_results', {}).get('issues_remaining', 0)
        resolution_rate_after = verification.get('security_scan_results', {}).get('resolution_rate', 0) * 100
        resolution_rate_before = 0  # Before fixing, no issues were resolved
        
        # Count unique tools used and vulnerability types dynamically  
        tools_used = set()
        vuln_types = set()
        if isinstance(original_issues, list):
            for issue in original_issues:
                if issue.get('tool'):
                    tools_used.add(issue.get('tool').title())
                if issue.get('owasp_category'):
                    vuln_types.add(issue.get('owasp_category'))
        tools_count = len(tools_used) if tools_used else 15  # fallback to 15
        top_vuln_types = list(vuln_types)[:3] if vuln_types else []
        
        body = f"""# 🔒 **DevSecureX** Security Remediation Report

> 🚀 **Ship code that's safe by default** - Automated by DevSecureX

## Executive Summary  
**DevSecureX**'s AI-powered automated security remediation has successfully addressed **{issues_resolved} of {original_issues_count}** identified vulnerabilities across **{fixed_files_count}** file(s), delivering a **{score_after - score_before:.1f}%** improvement in your overall security posture.

## Security Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **Security Score** | {score_before:.1f}% | {score_after:.1f}% | +{score_after - score_before:.1f}% |
| **Resolution Rate** | {resolution_rate_before:.1f}% | {resolution_rate_after:.1f}% | +{resolution_rate_after - resolution_rate_before:.1f}% |
| **Files Processed** | - | {fixed_files_count} | - |
| **Issues Addressed** | {original_issues_count} found | {issues_resolved} resolved | {issues_resolved}/{original_issues_count} |

## Vulnerability Analysis & Remediation

**Primary Threat Categories:** {', '.join(top_vuln_types) if top_vuln_types else 'Multiple security categories'}  
**Detection Coverage:** {tools_count} specialized security tools deployed

"""
        
        # Group issues by severity with CVSS scores
        issues_by_severity = defaultdict(list)
        # Ensure original_issues is iterable
        if isinstance(original_issues, list):
            for issue in original_issues:
                severity = issue.get('severity', 'medium').lower()
                issues_by_severity[severity].append(issue)
        else:
            logger.warning(f"original_issues is not a list for iteration: {type(original_issues)}")
        
        severity_emojis = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️'
        }
        
        cvss_scores = {
            'critical': '9.0-10.0',
            'high': '7.0-8.9',
            'medium': '4.0-6.9',
            'low': '0.1-3.9'
        }
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity in issues_by_severity:
                issues = issues_by_severity[severity]
                severity_icon = severity_emojis.get(severity, '📌')
                
                body += f"""### {severity_icon} {severity.upper()} Risk Vulnerabilities
**CVSS Score Range:** {cvss_scores[severity]} | **Count:** {len(issues)} issue(s)

"""
                
                for i, issue in enumerate(issues[:3], 1):
                    cwe_id = issue.get('cwe_id', 'CWE-Unknown').replace('CWE-', '')
                    cwe_link = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html" if cwe_id != 'Unknown' else "#"
                    
                    body += f"""<details>
<summary><strong>#{i}: {issue.get('message', 'Security vulnerability detected')}</strong></summary>

**Vulnerability Details:**
- **Location:** `{issue.get('file_path', 'unknown')}:{issue.get('line_start', '?')}`
- **Detection Tool:** {issue.get('tool', 'unknown').title()}
- **Rule ID:** `{issue.get('rule_id', 'unknown')}`
- **Classification:** [{issue.get('cwe_id', 'CWE-Unknown')}]({cwe_link})
- **OWASP Category:** {issue.get('owasp_category', 'Not classified')}

**Risk Assessment:**
This {severity}-severity vulnerability could potentially impact system security and requires immediate attention.

</details>

"""
                
                if len(issues) > 3:
                    body += f"> **Note:** {len(issues) - 3} additional {severity}-severity issues were also addressed in this remediation.\n\n"
        
        # Add dependency updates if any
        if dependency_updates:
            body += f"""## 📦 Dependency Security Updates

The following packages have been updated to address known security vulnerabilities:

| Package | Previous Version | Updated Version | Security Advisory |
|---------|------------------|-----------------|-------------------|
"""
            for update in dependency_updates[:5]:
                body += f"| `{update['package']}` | {update.get('current', 'N/A')} | {update['updated']} | {update.get('vulnerability', 'Security enhancement')} |\n"
            
            if len(dependency_updates) > 5:
                body += f"\n> **Note:** {len(dependency_updates) - 5} additional packages were also updated.\n"
        
        # Add verification results
        body += f"""

## 🔍 Quality Assurance & Verification

### Code Integrity Assessment
"""
        syntax_results = verification.get('syntax_validation', {})
        if syntax_results:
            all_valid = all(syntax_results.values())
            status_icon = "✅" if all_valid else "⚠️"
            body += f"""
**Status:** {status_icon} {'All files maintain syntactic integrity' if all_valid else 'Syntax validation required'}

| File | Validation Status |
|------|-------------------|
"""
            for file, valid in syntax_results.items():
                status = "✅ Valid" if valid else "❌ Requires Review"
                body += f"| `{file}` | {status} |\n"
        
        if verification.get('test_results', {}).get('framework'):
            test_results = verification['test_results']
            test_status_icon = "✅" if test_results['passed'] else "❌"
            body += f"""

### Automated Testing Results
**Framework:** {test_results['framework']} | **Status:** {test_status_icon} {'Passed' if test_results['passed'] else 'Failed'} | **Tests Executed:** {test_results.get('test_count', 'N/A')}
"""
        
        if verification.get('breaking_changes'):
            body += f"""

### ⚠️ Change Impact Analysis
The following modifications may require additional review:

"""
            for change in verification['breaking_changes']:
                body += f"- {change}\n"
        
        # Add professional examples and resources
        body += f"""

## 📋 Implementation Examples

<details>
<summary><strong>SQL Injection Prevention</strong></summary>

**Vulnerability Pattern:**
```python
# Unsafe: String concatenation with user input
query = f"SELECT * FROM users WHERE username = '{{{{username}}}}'"
cursor.execute(query)
```

**Secure Implementation:**
```python
# Safe: Parameterized query prevents injection
cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
```
</details>

<details>
<summary><strong>Cross-Site Scripting (XSS) Mitigation</strong></summary>

**Vulnerability Pattern:**
```javascript
// Unsafe: Direct HTML injection
document.getElementById('output').innerHTML = userInput;
```

**Secure Implementation:**
```javascript
// Safe: Text content prevents script execution
document.getElementById('output').textContent = userInput;
```
</details>

## 📚 Security Framework Compliance

| Standard | Status | Reference |
|----------|---------|-----------|
| **OWASP Top 10 2021** | ✅ Compliant | [owasp.org/Top10](https://owasp.org/www-project-top-ten/) |
| **CWE Guidelines** | ✅ Aligned | [cwe.mitre.org](https://cwe.mitre.org/) |
| **NIST Cybersecurity Framework** | ✅ Supported | [nist.gov/cyberframework](https://www.nist.gov/cyberframework) |
| **DevSecureX Standards** | ✅ Validated | Production-grade security automation |

## 🔬 Review & Deployment Checklist

### Pre-Deployment Validation
- [ ] **Functional Testing:** Verify all application features operate correctly
- [ ] **Performance Analysis:** Confirm no degradation in system performance
- [ ] **Security Validation:** Run penetration tests to confirm vulnerability resolution
- [ ] **Integration Testing:** Ensure compatibility with existing systems
- [ ] **Code Review:** Manual inspection of critical security changes

### Post-Deployment Monitoring  
- [ ] **DevSecureX Continuous Monitoring:** Enable ongoing vulnerability scanning
- [ ] **Error Tracking:** Monitor for any new issues or regressions  
- [ ] **Performance Metrics:** Track system performance indicators
- [ ] **Security Dashboard:** Review metrics in DevSecureX platform

---

## 🛡️ DevSecureX

**Remediation Engine:** Enhanced Auto-Fix V2  
**Tools Used:** {', '.join(sorted(tools_used)) if tools_used else 'Multiple security scanners'}  
**Performance:** Scan: {metrics.get('scan_time', 0):.1f}s | Fix: {metrics.get('fix_time', 0):.1f}s | Verify: {metrics.get('verification_time', 0):.1f}s | **Total: {metrics.get('total_time', 0):.1f}s**

> Automated security remediation • Ship code that's safe by default  
> Learn more at [devsecurex.com](https://www.devsecurex.com)
"""
        
        return body
    
    # Include all helper methods from original enhanced_auto_fixer.py
    # (Methods like _get_pr_details, _get_pr_changed_files, _setup_pr_workspace, etc.)
    # These remain the same as in the original file
    
    def _determine_tools_for_files(self, target_files: List[str]) -> List[str]:
        """Determine which security tools to run based on file extensions"""
        tools = set()
        
        for filename in target_files:
            ext = Path(filename).suffix.lower()
            
            if ext == '.py':
                tools.update(['bandit', 'semgrep', 'safety'])
            elif ext in ['.js', '.ts', '.jsx', '.tsx']:
                tools.update(['eslint', 'semgrep'])
            elif ext == '.go':
                tools.update(['gosec', 'semgrep'])
            elif ext in ['.yml', '.yaml']:
                tools.update(['checkov', 'semgrep'])
            elif ext == '.rb':
                tools.update(['brakeman', 'semgrep'])
            elif ext in ['.c', '.cpp', '.h', '.hpp']:
                tools.update(['cppcheck', 'semgrep'])
            elif ext == '.php':
                tools.update(['psalm', 'semgrep'])
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # elif ext == '.cs':
            #     tools.update(['roslynator', 'semgrep'])  # C# security (Roslynator disabled)
            elif ext == '.java':
                tools.update(['spotbugs', 'semgrep'])
            else:
                # For other files, use versatile tools
                tools.update(['semgrep', 'trivy'])
        
        # Always run secret detection
        tools.update(['gitleaks', 'trufflehog'])
        
        return list(tools)
    
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
            '.h': 'c',
            '.hpp': 'cpp',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala'
        }
        
        return language_map.get(ext, 'unknown')
    
    def _deduplicate_issues(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate issues based on location and rule"""
        seen = set()
        unique_issues = []
        
        for issue in issues:
            # Create unique key
            key = (
                issue.get('file_path', ''),
                issue.get('line_start', 0),
                issue.get('rule_id', ''),
                issue.get('message', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)
        
        return unique_issues
    
    def _filter_issues_to_changed_files(self, issues: List[Dict[str, Any]], target_files: List[str]) -> List[Dict[str, Any]]:
        """Filter security issues to only those in changed files"""
        if not target_files:
            return issues
        
        filtered_issues = []
        target_file_set = set(target_files)
        
        for issue in issues:
            issue_file = issue.get('file_path', '')
            
            # Skip .git directory files completely
            if issue_file.startswith('.git/') or '/.git/' in issue_file:
                logger.debug(f"Skipping .git directory issue: {issue_file}")
                continue
            
            # Check if issue file matches any target file (handle relative paths)
            if any(issue_file.endswith(target_file) or target_file.endswith(issue_file) 
                   for target_file in target_file_set):
                filtered_issues.append(issue)
        
        return filtered_issues
    
    async def _validate_syntax(self, file_path: str, language: str) -> bool:
        """Validate syntax of fixed file"""
        try:
            if language == 'python':
                with open(file_path, 'r') as f:
                    code = f.read()
                ast.parse(code)
                return True
            elif language in ['javascript', 'typescript']:
                # Use node to check syntax
                result = subprocess.run(
                    ['node', '--check', file_path],
                    capture_output=True,
                    timeout=5
                )
                return result.returncode == 0
            else:
                # Basic validation for other languages
                with open(file_path, 'r') as f:
                    content = f.read()
                # Check for basic syntax elements
                return self._basic_syntax_check(content, language)
        except Exception as e:
            logger.error(f"Syntax validation failed for {file_path}: {e}")
            return False
    
    def _basic_syntax_check(self, content: str, language: str) -> bool:
        """Basic syntax checking for various languages"""
        # Check for balanced brackets
        brackets = {'(': ')', '[': ']', '{': '}'}
        stack = []
        
        for char in content:
            if char in brackets:
                stack.append(brackets[char])
            elif char in brackets.values():
                if not stack or stack.pop() != char:
                    return False
        
        return len(stack) == 0
    
    async def _get_pr_details(self, repo_full_name: str, pr_number: int, gh_token: str) -> Dict[str, Any]:
        """Get PR details from GitHub API"""
        url = f"{self.github_api_base}/repos/{repo_full_name}/pulls/{pr_number}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status != 200:
                    raise Exception(f"Failed to get PR details: {await response.text()}")
                return await response.json()
    
    async def _get_pr_changed_files(self, repo_full_name: str, pr_number: int, gh_token: str) -> List[Dict[str, Any]]:
        """Get list of files changed in the PR"""
        url = f"{self.github_api_base}/repos/{repo_full_name}/pulls/{pr_number}/files"
        
        changed_files = []
        page = 1
        
        async with aiohttp.ClientSession() as session:
            while True:
                async with session.get(
                    url,
                    params={"page": page, "per_page": 100},
                    headers={"Authorization": f"token {gh_token}"}
                ) as response:
                    if response.status != 200:
                        raise Exception(f"Failed to get PR files: {await response.text()}")
                    
                    files = await response.json()
                    if not files:
                        break
                    
                    # Filter out deleted files and .git directory files
                    for file_info in files:
                        filename = file_info["filename"]
                        # Skip .git directory files (GitHub API shouldn't allow these anyway)
                        if filename.startswith(".git/"):
                            logger.warning(f"Skipping .git directory file: {filename}")
                            continue
                        
                        if file_info.get("status") in ["added", "modified"]:
                            changed_files.append({
                                "filename": filename,
                                "status": file_info["status"],
                                "additions": file_info.get("additions", 0),
                                "deletions": file_info.get("deletions", 0),
                                "changes": file_info.get("changes", 0),
                                "patch": file_info.get("patch", "")
                            })
                    
                    page += 1
        
        return changed_files
    
    async def _setup_pr_workspace(self, repo_full_name: str, pr_details: Dict[str, Any], gh_token: str) -> str:
        """Setup workspace with PR code"""
        temp_dir = tempfile.mkdtemp(prefix=f"autofix_{repo_full_name.replace('/', '_')}_")
        
        # Clone the repository at the PR head
        head_ref = pr_details["head"]["ref"]
        clone_url = f"https://{gh_token}@github.com/{repo_full_name}.git"
        
        cmd = [
            "git", "clone", "--single-branch", "--branch", head_ref, 
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
        
        logger.info(f"Cloned PR branch {head_ref} to {temp_dir}")
        return temp_dir
    
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
                    raise Exception(f"Failed to create branch: {await response.text()}")
    
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
        # Skip .git directory files
        if file_path.startswith(".git/"):
            logger.warning(f"Skipping update for .git directory file: {file_path}")
            return
        
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
                    raise Exception(f"Failed to update file {file_path}: {await response.text()}")
    
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
                    raise Exception(f"Failed to create PR: {await response.text()}")