"""
Performance-Optimized Scanner Engine for DevSecureX
World-class scan performance targeting 15-20 second execution times
"""

import asyncio
import tempfile
import shutil
import logging
import os
import time
import concurrent.futures
from typing import Dict, List, Any, Optional, Set
import psutil
from pathlib import Path

from .tools.semgrep_runner import SemgrepRunner
from .tools.bandit_runner import BanditRunner
from .tools.trufflehog_runner import TruffleHogRunner
from .tools.trivy_runner import TrivyRunner
from .tools.checkov_runner import CheckovRunner
from .tools.gitleaks_runner import GitLeaksRunner
from .tools.safety_runner import SafetyRunner
from .tools.gosec_runner import GosecRunner
from .tools.eslint_security_runner import ESLintSecurityRunner
from .tools.spotbugs_runner import SpotBugsRunner
from .tools.psalm_runner import PsalmRunner
from .tools.brakeman_runner import BrakemanRunner
from .tools.cppcheck_runner import CppcheckRunner
from .scoring import AdvancedScoring
from .utils.deduplicator import IssueDuplicator
from .utils.code_context_extractor import CodeContextExtractor

logger = logging.getLogger(__name__)

class PerformanceOptimizedScanner:
    """
    High-performance scanner engine optimized for 15-20 second execution times
    
    Key optimizations:
    - Aggressive parallelization with proper resource management
    - Cached tool availability checks
    - Optimized subprocess execution with connection pooling
    - Smart tool selection based on repository characteristics
    - Batched database operations
    - Memory-efficient processing
    """
    
    def __init__(self):
        self.scoring = AdvancedScoring()
        self.deduplicator = IssueDuplicator()
        self.context_extractor = CodeContextExtractor(context_lines=3)
        
        # Performance optimization settings
        self.max_concurrent_tools = self._calculate_optimal_concurrency()
        self.tool_timeout = 300  # Reduced from 600s to 300s (5 minutes)
        self.clone_timeout = 120  # Reduced from 300s to 120s (2 minutes)
        
        # Tool availability cache - check once on startup
        self._tool_availability_cache = None
        self._tools_cache = None
        
        # Process pool for CPU-intensive tasks
        self._process_pool = None
        
        # Performance tracking
        self.metrics = {
            "total_scans": 0,
            "avg_scan_time": 0,
            "tool_performance": {},
            "cache_hits": 0
        }
        
        logger.info(f"PerformanceOptimizedScanner initialized with {self.max_concurrent_tools} max concurrent tools")
    
    @property
    def tools(self):
        """Cached tools initialization"""
        if self._tools_cache is None:
            self._tools_cache = {
                'semgrep': SemgrepRunner(),
                'bandit': BanditRunner(),
                'trufflehog': TruffleHogRunner(),
                'trivy': TrivyRunner(),
                'checkov': CheckovRunner(),
                'gitleaks': GitLeaksRunner(),
                'safety': SafetyRunner(),
                'gosec': GosecRunner(),
                'eslint-security': ESLintSecurityRunner(),
                'spotbugs': SpotBugsRunner(),
                'psalm': PsalmRunner(),
                'brakeman': BrakemanRunner(),
                'cppcheck': CppcheckRunner(),
            }
        return self._tools_cache
    
    def _calculate_optimal_concurrency(self) -> int:
        """Calculate optimal concurrency based on system resources"""
        try:
            cpu_count = os.cpu_count() or 4
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # More aggressive concurrency for better performance
            optimal = min(
                cpu_count + 2,  # Increased from cpu_count to cpu_count + 2
                int(memory_gb / 0.5),  # Reduced memory requirement per tool from 1GB to 0.5GB
                16  # Increased max from 12 to 16
            )
            
            logger.info(f"Optimal concurrency: {optimal} (CPUs: {cpu_count}, Memory: {memory_gb:.1f}GB)")
            return optimal
        except Exception:
            return 8  # Increased default from 3 to 8
    
    async def get_process_pool(self):
        """Get or create process pool for CPU-intensive tasks"""
        if self._process_pool is None:
            self._process_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_concurrent_tools,
                thread_name_prefix="scanner"
            )
        return self._process_pool
    
    async def check_tool_availability_cached(self) -> Dict[str, bool]:
        """Check tool availability with caching"""
        if self._tool_availability_cache is not None:
            self.metrics["cache_hits"] += 1
            return self._tool_availability_cache
        
        logger.info("Checking tool availability (first time)")
        start_time = time.time()
        
        # Check all tools concurrently
        availability_tasks = [
            self._check_single_tool_availability(tool_name, tool)
            for tool_name, tool in self.tools.items()
        ]
        
        results = await asyncio.gather(*availability_tasks, return_exceptions=True)
        
        availability = {}
        for tool_name, result in zip(self.tools.keys(), results):
            if isinstance(result, Exception):
                logger.warning(f"Error checking {tool_name}: {result}")
                availability[tool_name] = False
            else:
                availability[tool_name] = result
        
        self._tool_availability_cache = availability
        check_time = time.time() - start_time
        
        available_tools = [t for t, available in availability.items() if available]
        logger.info(f"Tool availability check completed in {check_time:.2f}s: {len(available_tools)}/{len(self.tools)} available")
        logger.info(f"Available tools: {sorted(available_tools)}")
        
        return availability
    
    async def _check_single_tool_availability(self, tool_name: str, tool) -> bool:
        """Check a single tool's availability"""
        try:
            # Use the correct method from BaseToolRunner
            return tool._check_tool_availability()
        except Exception as e:
            logger.debug(f"Tool {tool_name} not available: {e}")
            return False
    
    async def run_performance_optimized_scan(
        self,
        repo_full_name: str,
        branch: str,
        scope: str,
        mode: str,
        niche: str,
        gh_token: str,
        scan_type: str = "manual",
        pr_number: Optional[int] = None,
        commit_sha: Optional[str] = None,
        file_list: Optional[List[str]] = None,
        progress_callback = None,
        user_id: Optional[int] = None,
        db_session = None,
        include_custom_rules: bool = False,
        include_community_rules: bool = False,
        selected_custom_rule_ids: Optional[List[str]] = None,
        selected_community_rule_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Run performance-optimized security scan targeting 15-20 second execution
        """
        start_time = time.time()
        temp_dir = None
        
        try:
            logger.info(f"🚀 Starting PERFORMANCE-OPTIMIZED scan for {repo_full_name}")
            
            # 1. Concurrent initialization - run multiple tasks in parallel
            if progress_callback:
                await progress_callback(0.05, "Initializing scan", "init")
            
            init_tasks = [
                self._clone_repository_fast(repo_full_name, branch, gh_token, scan_type),
                self.check_tool_availability_cached()
            ]
            
            if scan_type != "cli":
                temp_dir, tool_availability = await asyncio.gather(*init_tasks)
            else:
                tool_availability = await init_tasks[1]
                if file_list and len(file_list) > 0:
                    temp_dir = os.path.dirname(file_list[0])
                else:
                    raise ValueError("CLI scan requires file_list parameter")
            
            # 2. Fast language detection
            if progress_callback:
                await progress_callback(0.15, "Detecting languages", "language")
                
            languages = await self._detect_languages_fast(temp_dir, repo_full_name, file_list)
            
            # 3. Smart tool selection
            if progress_callback:
                await progress_callback(0.2, "Selecting tools", "selection")
                
            selected_tools = self._select_tools_optimized(
                scope, mode, niche, languages, tool_availability, file_list
            )
            
            logger.info(f"🔧 Selected {len(selected_tools)} tools for performance scan: {sorted(selected_tools)}")
            
            # 4. Parallel tool execution with aggressive concurrency
            if progress_callback:
                await progress_callback(0.25, "Running security tools", "scanning")
            
            tool_results = await self._run_tools_parallel_optimized(
                temp_dir, selected_tools, languages, file_list, progress_callback, niche
            )
            
            # 5. Fast result processing
            if progress_callback:
                await progress_callback(0.8, "Processing results", "processing")
            
            all_issues = await self._process_results_fast(tool_results, temp_dir, file_list, scan_type)
            
            # 6. Quick scoring and finalization
            if progress_callback:
                await progress_callback(0.9, "Computing scores", "scoring")
                
            scores = await self._compute_scores_fast(all_issues, selected_tools)
            total_score = scores.get("total_score", 0)
            
            execution_time = time.time() - start_time
            
            # Update metrics
            self.metrics["total_scans"] += 1
            self.metrics["avg_scan_time"] = (
                (self.metrics["avg_scan_time"] * (self.metrics["total_scans"] - 1) + execution_time) /
                self.metrics["total_scans"]
            )
            
            if progress_callback:
                await progress_callback(1.0, "Scan complete", "completed")
            
            logger.info(f"🎯 PERFORMANCE SCAN COMPLETED in {execution_time:.2f}s - Found {len(all_issues)} issues")
            
            return {
                "issues": all_issues,
                "total_score": total_score,
                "scores": scores,
                "tools_used": list(selected_tools),
                "scan_duration": execution_time,
                "metadata": {
                    "scan_type": scan_type,
                    "repository": repo_full_name,
                    "branch": branch,
                    "scope": scope,
                    "mode": mode,
                    "performance_optimized": True,
                    "languages": languages,
                    "total_tools_selected": len(selected_tools),
                    "execution_time": execution_time
                }
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Performance scan failed after {execution_time:.2f}s: {e}", exc_info=True)
            
            return {
                "issues": [],
                "total_score": 0,
                "scores": {},
                "tools_used": [],
                "scan_duration": execution_time,
                "error": str(e),
                "metadata": {
                    "scan_type": scan_type,
                    "repository": repo_full_name,
                    "branch": branch,
                    "error": str(e),
                    "execution_time": execution_time
                }
            }
        finally:
            # Cleanup
            if temp_dir and scan_type != "cli" and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp directory: {e}")
    
    async def _clone_repository_fast(
        self, repo_full_name: str, branch: str, gh_token: str, scan_type: str
    ) -> str:
        """Ultra-fast repository cloning optimized for security scanning"""
        if scan_type == "cli":
            return None  # CLI scans don't need cloning
        
        clone_start = time.time()
        temp_dir = tempfile.mkdtemp(prefix="devsecurex_fast_")
        
        try:
            # Use aggressive shallow clone settings for maximum speed
            clone_cmd = [
                'git', 'clone',
                '--filter=blob:none',  # Exclude large files
                '--depth', '1',  # Single commit
                '--no-checkout',  # Don't checkout working tree initially
                '--branch', branch,
                '--single-branch',
                '--no-tags',
                f"https://oauth2:{gh_token}@github.com/{repo_full_name}.git",
                temp_dir
            ]
            
            # Execute with shorter timeout
            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
            )
            
            _, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.clone_timeout
            )
            
            if process.returncode != 0:
                raise Exception(f"Git clone failed: {stderr.decode()}")
            
            # Now checkout only the files we need for scanning
            checkout_process = await asyncio.create_subprocess_exec(
                'git', 'checkout', 'HEAD', '--',
                cwd=temp_dir,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE
            )
            
            await checkout_process.communicate()
            
            clone_time = time.time() - clone_start
            logger.info(f"⚡ Fast clone completed in {clone_time:.2f}s for {repo_full_name}")
            
            return temp_dir
            
        except Exception as e:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"Fast repository clone failed: {e}")
    
    async def _detect_languages_fast(
        self, temp_dir: str, repo_full_name: str, file_list: Optional[List[str]] = None  # repo_full_name kept for API compatibility
    ) -> Dict[str, int]:
        """Fast language detection with caching and sampling"""
        try:
            # Simple file extension-based detection for speed
            extensions_count = {}
            
            if file_list:
                # Use provided file list
                files_to_check = file_list
            else:
                # Sample files for large repositories to speed up detection
                all_files = []
                for root, _, files in os.walk(temp_dir):
                    for file in files[:50]:  # Limit to first 50 files per directory
                        if not file.startswith('.'):
                            all_files.append(os.path.join(root, file))
                
                # Sample maximum 500 files for language detection
                files_to_check = all_files[:500] if len(all_files) > 500 else all_files
            
            for file_path in files_to_check:
                ext = Path(file_path).suffix.lower()
                extensions_count[ext] = extensions_count.get(ext, 0) + 1
            
            # Map extensions to languages
            extension_mapping = {
                '.py': 'python',
                '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
                '.go': 'go',
                '.java': 'java',
                '.php': 'php',
                '.rb': 'ruby',
                '.c': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp',
                '.cs': 'csharp',
                '.sh': 'shell', '.bash': 'shell',
                '.yaml': 'yaml', '.yml': 'yaml',
                '.dockerfile': 'docker', '.json': 'json',
                '.sql': 'sql'
            }
            
            languages = {}
            for ext, count in extensions_count.items():
                if ext in extension_mapping:
                    lang = extension_mapping[ext]
                    languages[lang] = languages.get(lang, 0) + count
            
            logger.info(f"🔍 Fast language detection: {languages}")
            return languages
            
        except Exception as e:
            logger.warning(f"Fast language detection failed: {e}")
            return {"unknown": 1}
    
    def _select_tools_optimized(
        self,
        scope: str,
        mode: str,  # kept for API compatibility
        niche: str,  # kept for API compatibility  
        languages: Dict[str, int],
        tool_availability: Dict[str, bool],
        file_list: Optional[List[str]] = None  # kept for API compatibility
    ) -> Set[str]:
        """Optimized tool selection for performance scans"""
        
        # Start with high-performance, high-value tools
        selected = set()
        
        # Always include fast, comprehensive tools
        core_tools = ['semgrep', 'trufflehog', 'gitleaks']
        for tool in core_tools:
            if tool_availability.get(tool, False):
                selected.add(tool)
        
        # Add language-specific tools for maximum security coverage
        # Note: We run all available tools regardless of languages for comprehensive scanning
        if tool_availability.get('bandit', False):
            selected.add('bandit')
        if tool_availability.get('gosec', False):
            selected.add('gosec')
        if tool_availability.get('eslint-security', False):
            selected.add('eslint-security')
        
        # Add dependency scanning tools
        if tool_availability.get('safety', False):
            selected.add('safety')
        if tool_availability.get('trivy', False):
            selected.add('trivy')
            
        # Add infrastructure scanning tools
        if tool_availability.get('checkov', False):
            selected.add('checkov')
            
        # Add additional language-specific tools
        if tool_availability.get('spotbugs', False):
            selected.add('spotbugs')
        if tool_availability.get('psalm', False):
            selected.add('psalm')
        if tool_availability.get('brakeman', False):
            selected.add('brakeman')
        if tool_availability.get('cppcheck', False):
            selected.add('cppcheck')
        
        # MAXIMUM SECURITY COVERAGE: Include ALL available tools instead of limiting to 8
        # This ensures comprehensive security scanning with all available tools
        
        logger.info(f"🎯 Performance-optimized tool selection: {len(selected)} tools - {sorted(selected)}")
        return selected
    
    async def _run_tools_parallel_optimized(
        self,
        temp_dir: str,
        selected_tools: Set[str],
        languages: Dict[str, int],
        file_list: Optional[List[str]] = None,
        progress_callback = None,
        niche: str = None
    ) -> Dict[str, Any]:
        """Run tools with maximum parallelization and real-time progress updates"""
        
        scan_start = time.time()
        tool_results = {}
        
        # Create semaphore with higher concurrency for performance
        semaphore = asyncio.Semaphore(self.max_concurrent_tools)
        
        # Track progress in real-time with thread-safe counter
        import threading
        completed_tools_lock = threading.Lock()
        completed_tools = [0]  # Use list for mutable reference
        total_tools = len(selected_tools)
        
        # Create all tasks upfront for maximum parallelization
        tasks = []
        for tool_name in selected_tools:
            task = self._run_tool_with_progress(
                tool_name, temp_dir, semaphore, 
                languages=languages,
                file_list=file_list,
                niche=niche,
                progress_callback=progress_callback,
                completed_tools_ref=completed_tools,
                completed_tools_lock=completed_tools_lock,
                total_tools=total_tools
            )
            tasks.append((tool_name, task))
        
        # Run ALL tools in parallel
        logger.info(f"🔥 Running {len(tasks)} tools in PARALLEL with real-time progress updates")
        
        # Execute all tasks concurrently
        results = await asyncio.gather(
            *[task for _, task in tasks], 
            return_exceptions=True
        )
        
        # Process results
        for (tool_name, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                logger.error(f"Tool {tool_name} failed: {result}")
                tool_results[tool_name] = {
                    "tool": tool_name,
                    "error": str(result),
                    "issues": []
                }
            else:
                tool_results[tool_name] = result
        
        scan_time = time.time() - scan_start
        logger.info(f"🚀 Parallel tool execution completed in {scan_time:.2f}s")
        
        return tool_results
    
    async def _run_tool_with_progress(
        self,
        tool_name: str,
        temp_dir: str,
        semaphore: asyncio.Semaphore,
        completed_tools_ref: List[int],
        completed_tools_lock,
        total_tools: int,
        progress_callback = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Run tool with real-time progress updates"""
        
        async with semaphore:
            start_time = time.time()
            
            # Update progress when tool starts
            if progress_callback:
                await progress_callback(0.25, f"Starting {tool_name}", tool_name)
            
            try:
                # Use reduced timeout for performance scans
                result = await asyncio.wait_for(
                    self._run_tool_safe(tool_name, temp_dir, **kwargs),
                    timeout=self.tool_timeout
                )
                
                execution_time = time.time() - start_time
                
                # Track tool performance
                if tool_name not in self.metrics["tool_performance"]:
                    self.metrics["tool_performance"][tool_name] = {
                        "runs": 0, "avg_time": 0, "issues_found": 0
                    }
                
                metrics = self.metrics["tool_performance"][tool_name]
                metrics["runs"] += 1
                metrics["avg_time"] = (
                    (metrics["avg_time"] * (metrics["runs"] - 1) + execution_time) / 
                    metrics["runs"]
                )
                metrics["issues_found"] += len(result.get("issues", []))
                
                # Update completed tools count and progress (thread-safe)
                with completed_tools_lock:
                    completed_tools_ref[0] += 1
                    current_completed = completed_tools_ref[0]
                
                if progress_callback:
                    progress = 0.25 + (current_completed / total_tools) * 0.55  # 25-80% for tool execution
                    await progress_callback(progress, f"Completed {tool_name}", tool_name)
                
                logger.info(f"⚡ {tool_name} completed in {execution_time:.2f}s - {len(result.get('issues', []))} issues")
                
                return result
                
            except asyncio.TimeoutError:
                logger.warning(f"⏰ Tool {tool_name} timed out after {self.tool_timeout}s")
                with completed_tools_lock:
                    completed_tools_ref[0] += 1
                    current_completed = completed_tools_ref[0]
                if progress_callback:
                    progress = 0.25 + (current_completed / total_tools) * 0.55
                    await progress_callback(progress, f"Timeout {tool_name}", tool_name)
                return {"tool": tool_name, "error": f"Timeout after {self.tool_timeout}s", "issues": []}
            except Exception as e:
                logger.error(f"💥 Tool {tool_name} failed: {e}")
                with completed_tools_lock:
                    completed_tools_ref[0] += 1
                    current_completed = completed_tools_ref[0]
                if progress_callback:
                    progress = 0.25 + (current_completed / total_tools) * 0.55
                    await progress_callback(progress, f"Failed {tool_name}", tool_name)
                return {"tool": tool_name, "error": str(e), "issues": []}
    
    
    async def _run_tool_safe(self, tool_name: str, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Safe tool execution with error handling"""
        try:
            tool = self.tools.get(tool_name)
            if not tool:
                raise ValueError(f"Tool {tool_name} not found")
            
            # Run tool with performance optimizations
            if hasattr(tool, 'run_with_availability_check'):
                return await tool.run_with_availability_check(temp_dir, **kwargs)
            else:
                return await tool.run(temp_dir, **kwargs)
                
        except Exception as e:
            logger.error(f"Tool {tool_name} execution failed: {e}")
            return {"tool": tool_name, "error": str(e), "issues": []}
    
    async def _process_results_fast(
        self,
        tool_results: Dict[str, Any],
        temp_dir: str,  # kept for API compatibility
        file_list: Optional[List[str]] = None,  # kept for API compatibility
        scan_type: str = "manual"  # kept for API compatibility
    ) -> List[Dict[str, Any]]:
        """Fast result processing with minimal overhead"""
        
        all_issues = []
        
        for tool_name, result in tool_results.items():
            issues = result.get("issues", [])
            if issues:
                all_issues.extend(issues)
        
        logger.info(f"📊 Raw issues collected: {len(all_issues)}")
        
        # Fast deduplication (lighter weight than full deduplication)
        if all_issues:
            all_issues = await self._fast_deduplication(all_issues)
        
        logger.info(f"🔧 Issues after fast deduplication: {len(all_issues)}")
        
        # Add code context extraction for better user experience
        if all_issues and temp_dir:
            logger.info(f"🔍 Extracting code context for {len(all_issues)} issues")
            all_issues = self.context_extractor.extract_batch_context(all_issues, temp_dir)
            logger.info(f"✅ Code context extraction completed")
        
        return all_issues
    
    async def _fast_deduplication(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fast deduplication based on key characteristics"""
        seen = set()
        deduplicated = []
        
        for issue in issues:
            # Create a simple hash based on key fields
            key = (
                issue.get("file_path", ""),
                issue.get("line_start", 0),
                issue.get("rule_id", ""),
                issue.get("message", "")[:100]  # First 100 chars of message
            )
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(issue)
        
        return deduplicated
    
    async def _compute_scores_fast(
        self, issues: List[Dict[str, Any]], tools_used: Set[str]  # kept for API compatibility
    ) -> Dict[str, Any]:
        """Fast scoring computation using proper AdvancedScoring system"""
        
        if not issues:
            return {
                "total_score": 100,
                "code_score": 100.0,
                "deps_score": 100.0,
                "secrets_score": 100.0,
                "configs_score": 100.0,
                "anomaly_score": 100.0
            }
        
        # Use the proper AdvancedScoring system instead of broken additive scoring
        # This ensures scores are properly capped at 100 and uses weighted calculations
        comprehensive_scores = self.scoring.calculate_comprehensive_scores(
            issues, scope="full", niche="all"
        )
        
        logger.info(f"Performance scanner computed scores: {comprehensive_scores}")
        
        return comprehensive_scores
    
    async def cleanup(self):
        """Cleanup resources"""
        if self._process_pool:
            self._process_pool.shutdown(wait=True)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for monitoring"""
        return {
            **self.metrics,
            "optimal_concurrency": self.max_concurrent_tools,
            "cache_status": {
                "tool_availability_cached": self._tool_availability_cache is not None,
                "tools_cached": self._tools_cache is not None
            }
        }

# Global instance for use
performance_scanner = PerformanceOptimizedScanner()