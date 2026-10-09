"""
Optimized Scanner Engine with improved performance, error handling, and monitoring
World-class security scanning engine competing with Snyk, CodeRabbit, and SonarQube
"""

import asyncio
import tempfile
import shutil
import subprocess
import logging
import os
import time
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone
import psutil
from github import Github, GithubException

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
# DISABLED: Roslynator tool commented out - C#/.NET tool not installed
# from .tools.roslynator_runner import RoslynatorRunner
from .tools.psalm_runner import PsalmRunner
from .tools.brakeman_runner import BrakemanRunner
from .tools.cppcheck_runner import CppcheckRunner
from .scoring import AdvancedScoring
from .utils.deduplicator import IssueDuplicator
from .utils.code_context_extractor import CodeContextExtractor
logger = logging.getLogger(__name__)

# Import custom rules config conditionally
try:
    from custom_rules.config.rules_config import RulesConfig
    from .services.custom_rules_integration import enhance_scanner_with_custom_rules
    CUSTOM_RULES_AVAILABLE = True
except ImportError:
    logger.warning("Custom rules module not available - continuing with standard tools")
    CUSTOM_RULES_AVAILABLE = False
# Import redis_client only when needed to avoid production connections

class ScannerEngine:
    """High-performance security scanner engine with enterprise-grade features"""
    
    async def _get_safe_redis_client(self):
        """Get Redis client safely"""
        try:
            from core.redis import get_redis_client
            return await get_redis_client()
        except Exception as e:
            logger.warning(f"Failed to get Redis client: {e}")
            return None
    
    def __init__(self):
        # Initialize tools with lazy loading
        self._tools = None
        self.available_tools = None  # Will be populated during tool detection
        self.scoring = AdvancedScoring()
        self.deduplicator = IssueDuplicator()
        self.context_extractor = CodeContextExtractor(context_lines=3)
        
        # PERFORMANCE OPTIMIZATION SETTINGS - Aggressive tuning for speed
        self.max_concurrent_tools = self._calculate_optimal_concurrency()
        self.tool_timeout = 300  # Reduced from 600s to 300s (5 minutes per tool)
        self.clone_timeout = 120  # Reduced from 300s to 120s (2 minutes for cloning)
        
        # Cache for language detection
        self._language_cache = {}
        
        # Metrics tracking
        self.metrics = {
            "scans_completed": 0,
            "total_issues_found": 0,
            "average_scan_time": 0,
            "tool_performance": {}
        }
        
    @property
    def tools(self):
        """Lazy load tools to improve startup time"""
        if self._tools is None:
            self._tools = {
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
                # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
                # 'roslynator': RoslynatorRunner(),
                'psalm': PsalmRunner(),
                'brakeman': BrakemanRunner(),
                'cppcheck': CppcheckRunner(),
            }
            
            # ENHANCED: Verify tool availability on first access
            self.available_tools = self._detect_available_tools()
            self._verify_tool_availability()
        return self._tools
    
    def _detect_available_tools(self):
        """Detect which security tools are actually installed and working"""
        import shutil
        import subprocess
        
        tools = {}
        tool_commands = {
            'semgrep': ['semgrep', '--version'],
            'bandit': ['bandit', '--version'],
            'trufflehog': ['trufflehog', '--version'],
            'trivy': ['trivy', '--version'],
            'checkov': ['checkov', '--version'],
            'gitleaks': ['gitleaks', 'version'],
            'safety': ['safety', '--version'],
            'gosec': ['gosec', '--version'],
            'eslint-security': ['eslint', '--version'],  # ESLint with security plugin
            'spotbugs': ['spotbugs', '-version'],
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # 'roslynator': ['roslynator', '--version'],
            'psalm': ['psalm', '--version'],
            'brakeman': ['brakeman', '--version'],
            'cppcheck': ['cppcheck', '--version'],
        }
        
        logger.info("🔧 DETECTING AVAILABLE SECURITY TOOLS:")
        
        for tool, cmd in tool_commands.items():
            try:
                # Check if command exists in PATH
                if shutil.which(cmd[0]):
                    # Try to run version command to verify it works
                    result = subprocess.run(
                        cmd, 
                        capture_output=True, 
                        text=True, 
                        timeout=10,
                        check=False
                    )
                    if result.returncode == 0:
                        tools[tool] = True
                        logger.info(f"   ✅ {tool}: Available and working")
                    else:
                        tools[tool] = False
                        logger.warning(f"   ⚠️  {tool}: Found but not working properly")
                else:
                    tools[tool] = False
                    logger.warning(f"   ❌ {tool}: Not found in PATH")
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
                tools[tool] = False
                logger.warning(f"   ❌ {tool}: Error testing availability - {str(e)}")
        
        available_count = sum(1 for available in tools.values() if available)
        logger.info(f"📊 TOOL AVAILABILITY SUMMARY: {available_count}/{len(tools)} tools available")
        
        return tools
    
    def _verify_tool_availability(self):
        """Legacy method for backward compatibility - now uses _detect_available_tools"""
        if not hasattr(self, 'available_tools') or self.available_tools is None:
            self.available_tools = self._detect_available_tools()
        
        available_tools = [tool for tool, available in self.available_tools.items() if available]
        missing_tools = [tool for tool, available in self.available_tools.items() if not available]
        
        logger.info(f"📊 LEGACY TOOL AVAILABILITY VERIFICATION:")
        logger.info(f"   Available tools: {len(available_tools)}/15")
        logger.info(f"   Missing tools: {len(missing_tools)}/15")
        logger.info(f"   Available: {sorted(available_tools)}")
        if missing_tools:
            logger.warning(f"   Missing: {sorted(missing_tools)}")
        
        # Store availability for later reference
        self._tool_availability = {
            'available': available_tools,
            'missing': missing_tools,
            'total': len(self.available_tools),
            'availability_percentage': (len(available_tools) / len(self.available_tools)) * 100
        }
    
    def _calculate_optimal_concurrency(self) -> int:
        """Calculate optimal concurrency based on system resources - PERFORMANCE OPTIMIZED"""
        try:
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024 ** 3)
            
            # AGGRESSIVE CONCURRENCY for maximum performance
            # Use 100% of CPUs + buffer for I/O bound security tools  
            optimal = max(6, min(16, cpu_count + 4))  # Increased from 50% to 100% + buffer
            
            # More lenient memory requirements for performance
            if memory_gb / optimal < 0.4:  # Reduced from 2GB to 0.4GB per task
                optimal = max(6, int(memory_gb / 0.4))
            
            logger.info(f"🚀 PERFORMANCE OPTIMIZED concurrency: {optimal} (CPUs: {cpu_count}, Memory: {memory_gb:.1f}GB)")
            return optimal
            
        except Exception:
            return 8  # Increased performance default from 3 to 8
    
    async def run_comprehensive_scan(
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
        cli_original_filenames: Optional[List[str]] = None,  # NEW: For CLI scan tool selection
        performance_mode: bool = True  # Enable performance optimizations by default
    ) -> Dict[str, Any]:
        """Run comprehensive security scan with PERFORMANCE OPTIMIZATIONS"""
        
        start_time = time.time()
        scan_id = f"{repo_full_name}:{branch}:{start_time}"
        temp_dir = None
        
        logger.info(f"🚀 Starting {'PERFORMANCE-OPTIMIZED' if performance_mode else 'STANDARD'} scan for {repo_full_name}")
        
        # Use performance-optimized scanner if enabled
        if performance_mode:
            try:
                from .performance_optimized_scanner import performance_scanner
                return await performance_scanner.run_performance_optimized_scan(
                    repo_full_name=repo_full_name,
                    branch=branch,
                    scope=scope,
                    mode=mode,
                    niche=niche,
                    gh_token=gh_token,
                    scan_type=scan_type,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    file_list=file_list,
                    progress_callback=progress_callback,
                    user_id=user_id,
                    db_session=db_session,
                    include_custom_rules=include_custom_rules,
                    include_community_rules=include_community_rules,
                    selected_custom_rule_ids=selected_custom_rule_ids,
                    selected_community_rule_ids=selected_community_rule_ids
                )
            except ImportError:
                logger.warning("Performance scanner not available, falling back to standard scan")
                performance_mode = False
        
        try:
            # Cache check removed - all scans are now comprehensive for maximum security coverage
            
            # 1. Clone repository with optimizations (skip for CLI scans)
            logger.info(f"Starting optimized scan for {repo_full_name}, scope: {scope}, mode: {mode}")
            if scan_type == "cli":
                # For CLI scans, temp_dir should already exist with files
                logger.info("CLI scan detected - skipping repository clone")
                # CRITICAL FIX: For CLI scans, temp_dir is passed via file_list directory
                if file_list and len(file_list) > 0:
                    # Get temp_dir from the first file's directory
                    temp_dir = os.path.dirname(file_list[0])
                    logger.info(f"CLI scan using temp_dir from file list: {temp_dir}")
                else:
                    logger.error("CLI scan: No file_list provided")
                    raise ValueError("CLI scan requires file_list parameter")
            else:
                if progress_callback:
                    await progress_callback(0.1, "Cloning repository", "clone")
                    
                temp_dir = await self._clone_repository_optimized(
                    repo_full_name, branch, gh_token, 
                    shallow=(scan_type == "pr")  # Only PR scans use shallow clone
                )
            
            # 2. Fast language detection with caching
            if progress_callback:
                await progress_callback(0.2, "Detecting languages", "language_detection")
            
            if scan_type == "cli" and file_list:
                # For CLI scans, use original filenames for language detection if provided
                if cli_original_filenames:
                    languages = self._detect_languages_from_files(cli_original_filenames)
                    logger.info(f"CLI scan using original filenames for language detection: {cli_original_filenames}")
                else:
                    languages = self._detect_languages_from_files(file_list)
                logger.info(f"CLI scan languages detected: {languages}")
                logger.info(f"CLI scan using temp_dir: {temp_dir}")
            else:
                languages = await self._detect_languages_cached(temp_dir, repo_full_name, gh_token)
                logger.info(f"Languages detected: {languages}")
            
            # 3. Smart tool selection based on context
            if progress_callback:
                await progress_callback(0.25, "Selecting security tools", "tool_selection")
                
            selected_tools = self._select_tools_intelligently(
                scope, mode, niche, languages, file_list, cli_original_filenames
            )
            logger.info(f"Selected tools: {list(selected_tools)}")
            
            # ENHANCED: Comprehensive tool verification logging
            logger.info(f"🔧 TOOL SELECTION VERIFICATION:")
            logger.info(f"   📊 Languages detected: {list(languages.keys())}")
            logger.info(f"   🎯 Total tools selected: {len(selected_tools)}")
            logger.info(f"   🔧 Selected tools: {sorted(selected_tools)}")
            
            # Log critical information about secret detection tools
            secret_tools = {'gitleaks', 'trufflehog', 'semgrep'} & selected_tools
            logger.info(f"🔐 Secret detection tools selected: {list(secret_tools)}")
            if not secret_tools:
                logger.error("❌ NO SECRET DETECTION TOOLS SELECTED - This will result in 0 critical issues!")
            
            # Log language-specific tool verification
            logger.info(f"🔍 LANGUAGE-SPECIFIC TOOL VERIFICATION:")
            for lang, count in languages.items():
                percentage = self._get_language_percentage(languages, lang)
                logger.info(f"   📝 {lang}: {count} bytes ({percentage:.1f}%)")
                
                # Check which tools should be activated for this language
                expected_tools = []
                if lang == 'Python': expected_tools = ['bandit', 'safety']
                elif lang == 'Go': expected_tools = ['gosec']
                elif lang in ['JavaScript', 'TypeScript']: expected_tools = ['eslint-security']  
                elif lang == 'Java': expected_tools = ['spotbugs']
                # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
                # elif lang == 'C#': expected_tools = ['roslynator']
                elif lang == 'PHP': expected_tools = ['psalm']
                elif lang == 'Ruby': expected_tools = ['brakeman']
                elif lang in ['C', 'C++']: expected_tools = ['cppcheck']
                
                if expected_tools:
                    activated = [tool for tool in expected_tools if tool in selected_tools]
                    missing = [tool for tool in expected_tools if tool not in selected_tools]
                    
                    if activated:
                        logger.info(f"     ✅ Activated for {lang}: {activated}")
                    if missing:
                        logger.warning(f"     ❌ Missing for {lang}: {missing}")
            
            # Log scope information
            logger.info(f"🎯 SCAN CONFIGURATION:")
            logger.info(f"   Scope: {scope}, Mode: {mode}, Niche: {niche}")
            logger.info(f"   CLI scan: {scan_type == 'cli'}")
            logger.info(f"   File count: {len(file_list) if file_list else 'Unknown'}")
            
            if scope != 'full':
                logger.info(f"   Non-full scope '{scope}' - ensuring critical secret detection is still enabled")
            
            # Log rule configuration for transparency
            if CUSTOM_RULES_AVAILABLE:
                rule_config = RulesConfig.get_rules_for_niche(niche)
                if rule_config:
                    logger.info(f"Niche '{niche}' will load {rule_config.get('total_rules', 0)} security rules")
                    logger.info(f"Rule files: {rule_config.get('rule_files', [])}")
            else:
                logger.info(f"Using standard rules for niche '{niche}' (custom rules not available)")
            
            # 3.5. Prepare custom rules if enabled
            custom_rules_info = None
            if include_custom_rules and user_id and db_session and CUSTOM_RULES_AVAILABLE:
                if progress_callback:
                    await progress_callback(0.28, "Preparing custom rules", "custom_rules")
                
                try:
                    custom_rules_info = await enhance_scanner_with_custom_rules(
                        scanner_engine=self,
                        user_id=user_id,
                        db=db_session,
                        niche=niche,
                        temp_dir=temp_dir,
                        include_community=include_community_rules,
                        selected_custom_rule_ids=selected_custom_rule_ids,
                        selected_community_rule_ids=selected_community_rule_ids
                    )
                    
                    if custom_rules_info and custom_rules_info['total_rules'] > 0:
                        logger.info(
                            f"Custom rules prepared: {custom_rules_info['user_rules_count']} user rules, "
                            f"{custom_rules_info['community_rules_count']} community rules"
                        )
                    else:
                        logger.info("No custom rules available for this scan")
                        
                except Exception as e:
                    logger.warning(f"Failed to prepare custom rules: {str(e)}")
                    custom_rules_info = None
            
            # 4. Run tools with advanced parallelization
            if progress_callback:
                await progress_callback(0.3, "Running security tools", "tool_execution")
                
            # Check if we should include API rules for web applications
            include_api_rules = self._should_include_api_rules(languages, file_list)
            
            # CRITICAL: Enhanced logging for debugging missing issues
            logger.info(f"🔧 EXECUTING TOOLS: {list(selected_tools)}")
            logger.info(f"🔧 LANGUAGES DETECTED: {list(languages.keys())}")
            logger.info(f"🔧 API RULES ENABLED: {include_api_rules}")
            logger.info(f"🔧 CUSTOM RULES INFO: {bool(custom_rules_info)}")
            
            tool_results = await self._run_tools_optimized(
                temp_dir, selected_tools, languages, file_list, progress_callback, niche,
                include_api_rules=include_api_rules,
                custom_rules_info=custom_rules_info
            )
            
            # 5. Process results with batched operations
            all_issues = await self._process_results_batch(
                tool_results, temp_dir, file_list, scan_type
            )
            
            # COMPREHENSIVE DEBUG: Log RAW tool results BEFORE any processing
            logger.info("🔍 RAW TOOL RESULTS BEFORE DEDUPLICATION:")
            raw_tool_counts = {}
            for tool_name, tool_result in tool_results.items():
                raw_issues = tool_result.get('issues', [])
                raw_tool_counts[tool_name] = len(raw_issues)
                
                if raw_issues:
                    logger.info(f"   🔧 {tool_name}: {len(raw_issues)} RAW issues")
                    # Log first few issues for debugging
                    for i, issue in enumerate(raw_issues[:3]):
                        logger.info(f"      Issue {i+1}: {issue.get('rule_id', 'unknown')} [{issue.get('severity', 'unknown')}] in {issue.get('file_path', 'unknown')}:{issue.get('line_start', 0)}")
                    if len(raw_issues) > 3:
                        logger.info(f"      ... and {len(raw_issues) - 3} more issues")
                else:
                    logger.warning(f"   ❌ {tool_name}: 0 RAW issues")
                    
                # Log any errors from tools
                if tool_result.get('error'):
                    logger.error(f"      🚨 {tool_name} ERROR: {tool_result['error']}")
                    
            logger.info(f"📊 TOTAL RAW ISSUES FROM ALL TOOLS: {sum(raw_tool_counts.values())}")
            
            # DEBUG: Log what each tool found - ENHANCED FOR ALL TOOLS DEBUGGING
            tool_issue_counts = {}
            tool_summary = {}
            gosec_issues = []
            eslint_issues = []
            
            for issue in all_issues:
                tool = issue.get('tool', 'unknown')
                severity = issue.get('severity', 'unknown')
                category = issue.get('category', 'unknown')
                
                # CRITICAL DEBUG: Track specific tools that are reportedly not working
                if tool == 'gosec':
                    gosec_issues.append({
                        'rule_id': issue.get('rule_id'),
                        'severity': severity,
                        'file_path': issue.get('file_path'),
                        'line': issue.get('line_start'),
                        'message': issue.get('message', '')[:100]  # First 100 chars
                    })
                elif tool == 'eslint-security':
                    eslint_issues.append({
                        'rule_id': issue.get('rule_id'),
                        'severity': severity,
                        'file_path': issue.get('file_path'),
                        'line': issue.get('line_start'),
                        'message': issue.get('message', '')[:100]
                    })
                
                # Count by tool and severity
                key = f"{tool}_{severity}"
                tool_issue_counts[key] = tool_issue_counts.get(key, 0) + 1
                
                # Track tool summaries
                if tool not in tool_summary:
                    tool_summary[tool] = {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'categories': set()}
                tool_summary[tool]['total'] += 1
                tool_summary[tool][severity] += 1
                tool_summary[tool]['categories'].add(category)
            
            # ENHANCED TOOL DEBUG: Log all problematic tool issues found before deduplication
            if gosec_issues:
                logger.info(f"🔍 GOSEC DETAILED FINDINGS (BEFORE DEDUPLICATION): {len(gosec_issues)} issues")
                for i, gosec_issue in enumerate(gosec_issues[:10]):  # Log first 10 for debugging
                    logger.info(f"  Gosec #{i+1}: {gosec_issue['rule_id']} [{gosec_issue['severity']}] in {gosec_issue['file_path']}:{gosec_issue['line']}")
                if len(gosec_issues) > 10:
                    logger.info(f"  ... and {len(gosec_issues) - 10} more Gosec issues")
            else:
                logger.warning(f"🚨 GOSEC FOUND NO ISSUES - This may indicate a problem!")
            
            # ENHANCED ESLint DEBUG: Log all ESLint issues found before deduplication
            if eslint_issues:
                logger.info(f"🔍 ESLINT-SECURITY DETAILED FINDINGS (BEFORE DEDUPLICATION): {len(eslint_issues)} issues")
                for i, eslint_issue in enumerate(eslint_issues[:10]):  # Log first 10 for debugging
                    logger.info(f"  ESLint #{i+1}: {eslint_issue['rule_id']} [{eslint_issue['severity']}] in {eslint_issue['file_path']}:{eslint_issue['line']}")
                if len(eslint_issues) > 10:
                    logger.info(f"  ... and {len(eslint_issues) - 10} more ESLint issues")
            else:
                logger.warning(f"🚨 ESLINT-SECURITY FOUND NO ISSUES - This may indicate a problem!")
            
            logger.info("🔍 COMPREHENSIVE TOOL ANALYSIS:")
            for tool, summary in tool_summary.items():
                categories_str = ', '.join(summary['categories'])
                logger.info(f"  🔧 {tool}: {summary['total']} total (C:{summary['critical']}, H:{summary['high']}, M:{summary['medium']}, L:{summary['low']}) - Categories: {categories_str}")
            
            logger.info("🔍 TOOL RESULTS BY SEVERITY:")
            for tool_sev, count in sorted(tool_issue_counts.items()):
                tool, severity = tool_sev.split('_', 1)
                if severity == 'critical':
                    logger.info(f"  🚨 {tool}: {count} CRITICAL issues")
                elif severity == 'high':
                    logger.info(f"  ⚠️  {tool}: {count} HIGH issues")
                else:
                    logger.info(f"  ℹ️  {tool}: {count} {severity.upper()} issues")
            
            # 6. Deduplicate with standard algorithm (preserve critical issues)
            # DEBUG: Log issues before deduplication
            critical_before = len([i for i in all_issues if i.get('severity') == 'critical'])
            gosec_before = len([i for i in all_issues if i.get('tool') == 'gosec'])
            logger.info(f"🔍 BEFORE DEDUPLICATION: {len(all_issues)} total issues, {critical_before} critical, {gosec_before} Gosec")
            
            deduplicated_issues = self.deduplicator.deduplicate(all_issues)
            
            # DEBUG: Log issues after deduplication
            critical_after = len([i for i in deduplicated_issues if i.get('severity') == 'critical'])
            gosec_after = len([i for i in deduplicated_issues if i.get('tool') == 'gosec'])
            logger.info(f"🔍 AFTER DEDUPLICATION: {len(deduplicated_issues)} total issues, {critical_after} critical, {gosec_after} Gosec")
            
            # Generate multi-tool detection statistics
            multi_tool_stats = self.deduplicator.get_multi_tool_detection_stats(deduplicated_issues)
            logger.info(f"🤝 MULTI-TOOL DETECTION STATS: {multi_tool_stats['multi_tool_detections']} issues found by multiple tools ({multi_tool_stats['multi_tool_percentage']}%), {multi_tool_stats['highly_confident_detections']} highly confident detections")
            
            # CRITICAL DEBUG: If Gosec issues were lost, log warning
            if gosec_before > 0 and gosec_after == 0:
                logger.error(f"🚨 ALL GOSEC ISSUES LOST DURING DEDUPLICATION! {gosec_before} -> {gosec_after}")
            elif gosec_before > gosec_after:
                logger.warning(f"⚠️ Some Gosec issues lost during deduplication: {gosec_before} -> {gosec_after}")
            
            # 7. Calculate scores with caching
            scores = await self._calculate_scores_cached(
                deduplicated_issues, scope, niche
            )
            
            # 8. Generate SBOM only for full scope
            sbom = None
            if scope == "full":
                sbom = await self._generate_sbom_async(temp_dir)
            
            # 9. Generate compliance mappings
            compliance_data = self._generate_compliance_mappings_optimized(
                deduplicated_issues
            )
            
            # Calculate metrics
            scan_duration = time.time() - start_time
            self._update_metrics(scan_duration, len(deduplicated_issues))
            
            # CRITICAL FIX: Return ONLY the real deduplicated issues, not anomaly issues
            # Anomaly issues are from historical data and should not be mixed with current scan
            result = {
                "success": True,
                "issues": deduplicated_issues,  # FIXED: Only real issues from current scan
                "scores": scores,
                "compliance": compliance_data,
                "metadata": {
                    "scan_duration": scan_duration,
                    "tools_used": list(tool_results.keys()),
                    "languages_detected": list(languages.keys()),
                    "total_issues": len(deduplicated_issues),  # FIXED: Count only real issues
                    "deduplicated_count": len(all_issues) - len(deduplicated_issues),
                    "scan_type": scan_type,
                    "repository": repo_full_name,
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "pr_number": pr_number,
                    "sbom": sbom,
                    "scope": scope,
                    "mode": mode,
                    "file_list": file_list,
                    "performance_metrics": {
                        "clone_time": getattr(self, '_clone_time', 0),
                        "scan_time": getattr(self, '_scan_time', 0),
                        "processing_time": scan_duration - getattr(self, '_scan_time', 0)
                    },
                    "custom_rules": {
                        "enabled": include_custom_rules,
                        "user_rules_count": custom_rules_info['user_rules_count'] if custom_rules_info else 0,
                        "community_rules_count": custom_rules_info['community_rules_count'] if custom_rules_info else 0,
                        "total_custom_rules": custom_rules_info['total_rules'] if custom_rules_info else 0
                    },
                    "multi_tool_detection": multi_tool_stats
                }
            }
            
            # Caching removed - all scans are comprehensive and should not be cached
            
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"Scan timeout for {repo_full_name}")
            return self._create_error_response(
                "Scan timeout exceeded", scan_type, repo_full_name, branch,
                time.time() - start_time
            )
        except Exception as e:
            logger.error(f"Scan failed for {repo_full_name}: {str(e)}", exc_info=True)
            return self._create_error_response(
                str(e), scan_type, repo_full_name, branch,
                time.time() - start_time
            )
        finally:
            # Cleanup with error handling
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp directory: {e}")
    
    async def _clone_repository_optimized(
        self, repo_full_name: str, branch: str, gh_token: str, shallow: bool = True
    ) -> str:
        """Optimized repository cloning with sparse checkout for large repos"""
        
        clone_start = time.time()
        temp_dir = tempfile.mkdtemp(prefix="devsecurex_scan_")
        
        try:
            # Use sparse checkout for very large repositories
            clone_cmd = [
                'git', 'clone',
                '--filter=blob:none',  # Exclude large blobs
                '--sparse',
                '--depth', '1' if shallow else '10',
                '--branch', branch,
                '--single-branch',
                '--no-tags',
                f"https://oauth2:{gh_token}@github.com/{repo_full_name}.git",
                temp_dir
            ]
            
            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'}
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=self.clone_timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                raise Exception(f"Repository clone timeout after {self.clone_timeout}s")
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                if "Repository not found" in error_msg:
                    raise Exception("Repository not found or access denied")
                raise Exception(f"Git clone failed: {error_msg}")
            
            self._clone_time = time.time() - clone_start
            logger.info(f"Repository cloned in {self._clone_time:.2f}s")
            return temp_dir
            
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise e
    
    async def _detect_languages_cached(
        self, temp_dir: str, repo_full_name: str, gh_token: str
    ) -> Dict[str, int]:
        """Detect languages with caching"""
        
        # Check cache first
        cache_key = f"languages:{repo_full_name}"
        if cache_key in self._language_cache:
            return self._language_cache[cache_key]
        
        # Try Redis cache
        try:
            redis_client = await self._get_safe_redis_client()
            if redis_client:
                cached = await redis_client.get(cache_key)
                if cached:
                    import json
                    languages = json.loads(cached)
                    self._language_cache[cache_key] = languages
                    return languages
        except Exception:
            pass
        
        # Detect languages
        languages = await self._detect_languages_extended(temp_dir, repo_full_name, gh_token)
        
        # Cache result
        self._language_cache[cache_key] = languages
        try:
            redis_client = await self._get_safe_redis_client()
            if redis_client:
                import json
                await redis_client.setex(
                    cache_key, 
                    3600,  # 1 hour TTL
                    json.dumps(languages)
                )
        except Exception:
            pass
        
        return languages
    
    def _select_tools_intelligently(
        self,
        scope: str,
        mode: str,  # Used in comments for context
        niche: str,
        languages: Dict[str, int],
        file_list: Optional[List[str]] = None,
        cli_original_filenames: Optional[List[str]] = None
    ) -> Set[str]:
        """MAXIMUM SECURITY COVERAGE: Select ALL available security tools regardless of mode/scope"""
        
        logger.debug(f"_select_tools_intelligently called with cli_original_filenames={cli_original_filenames}")
        
        selected = set()
        
        # MAXIMUM COVERAGE: ALWAYS include ALL core security tools for EVERY scan
        # This eliminates any "fast vs comprehensive" or scope limitations
        selected.update([
            'semgrep',        # Multi-language static analysis
            'trufflehog',     # Secret detection
            'gitleaks',       # Git secret scanning
            'trivy',          # Container & dependency vulnerabilities
            'checkov',        # Infrastructure as Code security
        ])
        
        logger.info("🚀 MAXIMUM SECURITY COVERAGE: ALL core tools selected regardless of scope/mode")
        logger.info(f"   Core tools: semgrep, trufflehog, gitleaks, trivy, checkov")
        
        # MAXIMUM COVERAGE: Language-specific tools - ALWAYS add if language detected
        is_cli_scan = file_list is not None and len(file_list) < 20  # CLI scans typically have few files
        
        # Enhanced CLI scan detection
        if cli_original_filenames:
            is_cli_scan = True
            logger.info(f"🔧 CLI scan confirmed via cli_original_filenames parameter: {cli_original_filenames}")
            logger.debug(f"CLI scan detected with original files: {cli_original_filenames}")
        
        # MAXIMUM COVERAGE: ALL language-specific tools enabled for detected languages (NO THRESHOLDS)
        lang_tools = {
            'Python': ['bandit', 'safety'],      # Python security analysis + dependency check
            'Go': ['gosec'],                     # Go security analysis
            'JavaScript': ['eslint-security'],   # JavaScript/Node.js security
            'TypeScript': ['eslint-security'],   # TypeScript security
            'Java': ['spotbugs'],                # Java security analysis
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # 'C#': ['roslynator'],                # C# security analysis
            'PHP': ['psalm'],                    # PHP security analysis
            'Ruby': ['brakeman'],                # Ruby on Rails security
            'C': ['cppcheck'],                   # C/C++ security analysis
            'C++': ['cppcheck']                  # C++ security analysis
        }
        
        # CRITICAL DEBUG: Log all detected languages and tool matching process
        logger.info(f"🔍 LANGUAGE-SPECIFIC TOOL SELECTION:")
        logger.info(f"   CLI scan detected: {is_cli_scan}")
        logger.info(f"   Detected languages: {list(languages.keys())}")
        logger.info(f"   Language counts: {languages}")
        logger.info(f"   File list length: {len(file_list) if file_list else 0}")
        
        # MAXIMUM COVERAGE: Add ALL tools for detected languages (NO THRESHOLD CHECKS)
        for lang, tools in lang_tools.items():
            if lang in languages:
                percentage = self._get_language_percentage(languages, lang)
                logger.info(f"✅ Language {lang}: {percentage:.1f}% - ADDING ALL TOOLS")
                selected.update(tools)
                logger.info(f"   ➕ Added tools for {lang}: {tools}")
            else:
                logger.info(f"❌ Language {lang} not detected in: {list(languages.keys())}")
        
        # CRITICAL FIX: For CLI scans, force include language-specific tools if we have any files of that type
        if is_cli_scan and file_list:
            logger.info(f"🔧 CLI SCAN ENHANCEMENT: Checking file extensions directly")
            
            # For CLI scans, use original filenames if provided, otherwise use file_list
            files_to_check = cli_original_filenames or file_list
            logger.info(f"🔧 CLI: Checking extensions in files: {files_to_check}")
            
            # Check file extensions directly for CLI scans to ensure tools aren't missed
            has_python = any(f.endswith(('.py',)) for f in files_to_check)
            has_javascript = any(f.endswith(('.js', '.jsx', '.ts', '.tsx')) for f in files_to_check)  
            has_java = any(f.endswith(('.java',)) for f in files_to_check)
            has_go = any(f.endswith(('.go',)) for f in files_to_check)
            has_ruby = any(f.endswith(('.rb',)) for f in files_to_check)
            has_php = any(f.endswith(('.php',)) for f in files_to_check)
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # has_csharp = any(f.endswith(('.cs',)) for f in files_to_check)
            has_cpp = any(f.endswith(('.cpp', '.cc', '.cxx', '.c')) for f in files_to_check)
            
            # Force add tools for detected languages in CLI scans
            logger.info(f"🔧 CLI: File detection results - Python:{has_python}, JS:{has_javascript}, Java:{has_java}, Go:{has_go}")
            logger.debug(f"CLI force-add logic - Python:{has_python}, JS:{has_javascript}, Java:{has_java}")
            
            if has_python:
                selected.update(['bandit', 'safety'])
                logger.info(f"   🔧 CLI: Force-added Python tools (bandit, safety)")
                logger.debug(f"Added Python tools - bandit, safety")
            if has_javascript:
                selected.add('eslint-security')
                logger.info(f"   🔧 CLI: Force-added JavaScript tool (eslint-security)")
            if has_java:  # All scans are comprehensive, so include SpotBugs for Java
                selected.add('spotbugs')
                logger.info(f"   🔧 CLI: Force-added Java tool (spotbugs)")
            if has_go:
                selected.add('gosec') 
                logger.info(f"   🔧 CLI: Force-added Go tool (gosec)")
                logger.debug(f"Force-added Gosec tool for Go files")
            if has_ruby:
                selected.add('brakeman')
                logger.info(f"   🔧 CLI: Force-added Ruby tool (brakeman)")
            if has_php:
                selected.add('psalm')
                logger.info(f"   🔧 CLI: Force-added PHP tool (psalm)")
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # if has_csharp:
            #     selected.add('roslynator')
            #     logger.info(f"   🔧 CLI: Force-added C# tool (roslynator)")
            if has_cpp:
                selected.add('cppcheck')
                logger.info(f"   🔧 CLI: Force-added C/C++ tool (cppcheck)")
                
            # DISABLED: Removed has_csharp since Roslynator tool is disabled
            if not any([has_python, has_javascript, has_java, has_go, has_ruby, has_php, has_cpp]):
                logger.warning(f"🔧 CLI: No language-specific files detected - this may be a bug!")
                logger.warning(f"🔧 CLI: Files being checked: {files_to_check}")
        
        # Special case: Python dependencies
        if 'Python' in languages and 'safety' not in selected:
            if file_list:
                if any('requirements.txt' in f for f in file_list):
                    selected.add('safety')
            else:
                selected.add('safety')
        
        # MAXIMUM COVERAGE: Niche-specific tool enhancements (additive only, never restrictive)
        # All niche adjustments ADD tools, never remove or limit existing selection
        if niche == 'ai':
            # AI/ML security: Python analysis + API security + container scanning
            selected.update(['bandit', 'safety', 'trivy'])
            logger.info("🤖 AI niche: Enhanced Python, dependency, and container security")
        elif niche == 'blockchain':
            # Blockchain: Smart contracts + infrastructure + web3 frontend
            selected.update(['eslint-security', 'checkov', 'trivy'])
            logger.info("⛓️ Blockchain niche: Enhanced smart contract and infrastructure security")
        elif niche == 'iot':
            # IoT: Embedded systems + network + infrastructure
            selected.update(['cppcheck', 'checkov', 'trivy'])
            logger.info("📱 IoT niche: Enhanced embedded systems and infrastructure security")
        elif niche == 'web3':
            # Web3: Frontend + smart contracts + API security
            selected.update(['eslint-security', 'bandit', 'trivy'])
            logger.info("🌐 Web3 niche: Enhanced frontend and API security")
        elif niche == 'cloud' or niche == 'cloud-native':
            # Cloud: Infrastructure + containers + APIs
            selected.update(['checkov', 'trivy', 'bandit'])
            logger.info("☁️ Cloud niche: Enhanced infrastructure and container security")
        elif niche == 'api':
            # API security: Multiple language support + infrastructure
            selected.update(['bandit', 'eslint-security', 'gosec', 'checkov'])
            logger.info("🔌 API niche: Enhanced multi-language API security")
        
        # REMOVED MODE RESTRICTIONS - Let all tools run regardless of mode for maximum coverage
        # Mode adjustments removed to prevent missing vulnerabilities
        # Previous logic was too restrictive and prevented tools from finding issues
        logger.info(f"🔧 MODE RESTRICTIONS REMOVED: All selected tools will run regardless of mode for maximum security coverage")
        
        # CRITICAL DEBUG: Final tool selection summary
        logger.info(f"🔧 FINAL TOOL SELECTION:")
        logger.info(f"   Core tools (always included): ['semgrep', 'trufflehog', 'gitleaks']")
        logger.info(f"   Scope-based tools: {sorted([t for t in selected if t not in ['semgrep', 'trufflehog', 'gitleaks']])}")
        logger.info(f"   Total tools selected: {len(selected)}")
        logger.info(f"   Final selected tools: {sorted(selected)}")
        
        # MODIFIED: More graceful handling of unavailable tools - warn but don't remove completely
        if hasattr(self, '_tool_availability'):
            available_tools = set(self._tool_availability['available'])
            unavailable_selected = selected - available_tools
            if unavailable_selected:
                # Only remove tools that are completely missing, not just having issues
                logger.warning(f"⚠️  Some selected tools may not be fully available: {sorted(unavailable_selected)}")
                logger.warning(f"⚠️  These tools will still be attempted - some may work despite availability check")
                # Don't automatically remove tools - let them try to run and fail gracefully
                logger.info(f"🔧 FINAL SELECTED TOOLS (including potentially unavailable): {sorted(selected)} ({len(selected)} tools)")
        
        # Validate we have enough tools for comprehensive scans (all scans are comprehensive now)
        expected_min_tools = 8  # Always expect comprehensive tool set
        if len(selected) < expected_min_tools:
            logger.warning(f"⚠️  Only {len(selected)} tools selected - expecting {expected_min_tools}+ for comprehensive scan")
            logger.warning(f"⚠️  This may be due to missing tool installations")
            
        return selected
    
    async def _run_tools_optimized(
        self,
        temp_dir: str,
        selected_tools: Set[str],
        languages: Dict[str, int],
        file_list: Optional[List[str]] = None,
        progress_callback = None,
        niche: str = None,
        include_api_rules: bool = False,
        custom_rules_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Run tools with optimized parallelization"""
        
        scan_start = time.time()
        tool_results = {}
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent_tools)
        
        # Group tools by priority
        priority_groups = self._group_tools_by_priority(selected_tools, languages)
        
        # Calculate progress tracking
        total_tools = len(selected_tools)
        completed_tools = 0
        
        # Run tools in priority groups
        for priority, tools in sorted(priority_groups.items()):
            if not tools:
                continue
                
            tasks = []
            for tool_name in tools:
                task = self._run_tool_with_monitoring(
                    tool_name, temp_dir, semaphore, 
                    file_list=file_list, languages=languages,
                    focus_on_changed_files=file_list is not None,
                    niche=niche,
                    include_api_rules=include_api_rules,
                    custom_rules_info=custom_rules_info
                )
                tasks.append(task)
            
            # Run group in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results and update progress
            for tool_name, result in zip(tools, results):
                completed_tools += 1
                
                if progress_callback:
                    progress = 0.3 + (completed_tools / total_tools) * 0.4  # 30-70% for tool execution
                    await progress_callback(
                        progress, 
                        f"Running {tool_name}", 
                        tool_name,
                        completed_tools,
                        total_tools
                    )
                
                if isinstance(result, Exception):
                    logger.error(f"Tool {tool_name} failed: {result}")
                    tool_results[tool_name] = {
                        "tool": tool_name,
                        "error": str(result),
                        "issues": []
                    }
                else:
                    tool_results[tool_name] = result
        
        self._scan_time = time.time() - scan_start
        logger.info(f"All tools completed in {self._scan_time:.2f}s")
        
        return tool_results
    
    def _group_tools_by_priority(
        self, selected_tools: Set[str], languages: Dict[str, int]  # languages used for future priority optimization
    ) -> Dict[int, List[str]]:
        """Group tools by execution priority"""
        
        # Priority 1: Fast, high-value tools
        priority_1 = ['semgrep', 'trufflehog']
        
        # Priority 2: Medium-speed tools
        priority_2 = ['bandit', 'gosec', 'eslint-security', 'checkov', 'gitleaks']
        
        # Priority 3: Slower tools
        # DISABLED: Roslynator tool commented out - C#/.NET tool not installed  
        priority_3 = ['trivy', 'spotbugs', 'psalm', 'brakeman', 'cppcheck', 'safety']
        logger.debug(f"Priority 3 tools available: {len(priority_3)}")
        
        groups = {1: [], 2: [], 3: []}
        
        for tool in selected_tools:
            if tool in priority_1:
                groups[1].append(tool)
            elif tool in priority_2:
                groups[2].append(tool)
            else:
                groups[3].append(tool)
        
        return groups
    
    async def _run_tool_with_monitoring(
        self,
        tool_name: str,
        temp_dir: str,
        semaphore: asyncio.Semaphore,
        **kwargs
    ) -> Dict[str, Any]:
        """Run tool with monitoring and timeout - ENHANCED with comprehensive logging"""
        
        async with semaphore:
            start_time = time.time()
            
            # ENHANCED: Pre-execution logging
            logger.info(f"🚀 STARTING {tool_name.upper()}: {kwargs.get('languages', {})} detected, timeout={self.tool_timeout}s")
            
            try:
                # Run tool with timeout
                result = await asyncio.wait_for(
                    self._run_tool_safe(tool_name, temp_dir, **kwargs),
                    timeout=self.tool_timeout
                )
                
                # Track performance
                duration = time.time() - start_time
                if tool_name not in self.metrics["tool_performance"]:
                    self.metrics["tool_performance"][tool_name] = {
                        "runs": 0,
                        "total_time": 0,
                        "avg_time": 0,
                        "failures": 0
                    }
                
                self.metrics["tool_performance"][tool_name]["runs"] += 1
                self.metrics["tool_performance"][tool_name]["total_time"] += duration
                self.metrics["tool_performance"][tool_name]["avg_time"] = (
                    self.metrics["tool_performance"][tool_name]["total_time"] /
                    self.metrics["tool_performance"][tool_name]["runs"]
                )
                
                # ENHANCED: Post-execution logging
                issues_count = len(result.get("issues", []))
                if issues_count > 0:
                    logger.info(f"✅ {tool_name.upper()} COMPLETED: Found {issues_count} issues in {duration:.2f}s")
                else:
                    logger.info(f"✅ {tool_name.upper()} COMPLETED: No issues found in {duration:.2f}s")
                    
                # Log any errors or warnings
                if "error" in result:
                    logger.warning(f"⚠️  {tool_name.upper()} HAD ERRORS: {result['error']}")
                
                return result
                
            except asyncio.TimeoutError:
                duration = time.time() - start_time
                logger.error(f"❌ {tool_name.upper()} TIMEOUT: Exceeded {self.tool_timeout}s limit (ran {duration:.2f}s)")
                if tool_name in self.metrics["tool_performance"]:
                    self.metrics["tool_performance"][tool_name]["failures"] += 1
                return {
                    "tool": tool_name,
                    "error": f"Timeout after {self.tool_timeout}s",
                    "issues": []
                }
            except Exception as e:
                duration = time.time() - start_time
                logger.error(f"❌ {tool_name.upper()} FAILED: {str(e)} (ran {duration:.2f}s)")
                if tool_name in self.metrics["tool_performance"]:
                    self.metrics["tool_performance"][tool_name]["failures"] += 1
                return {
                    "tool": tool_name,
                    "error": str(e),
                    "issues": []
                }
    
    async def _process_results_batch(
        self,
        tool_results: Dict[str, Any],
        temp_dir: str,
        file_list: Optional[List[str]],
        scan_type: str
    ) -> List[Dict[str, Any]]:
        """Process results in batches for better performance"""
        
        all_issues = []
        
        # Collect all issues first
        raw_issues = []
        for tool_name, result in tool_results.items():
            if "error" not in result:
                tool_issues = result.get("issues", [])
                raw_issues.extend(tool_issues)
                logger.info(f"🔍 _process_results_batch: {tool_name} contributed {len(tool_issues)} issues")
                
                # Debug: Log first few issues from each tool
                if tool_issues and tool_name == 'bandit':
                    logger.info(f"   First Bandit issue sample: {tool_issues[0] if tool_issues else 'None'}")
            else:
                logger.warning(f"🔍 _process_results_batch: {tool_name} had errors: {result.get('error')}")
        
        # Batch process code context extraction
        if raw_issues:
            # Group by file for efficient processing
            issues_by_file = {}
            for issue in raw_issues:
                file_path = issue.get("file_path")
                if file_path:
                    if file_path not in issues_by_file:
                        issues_by_file[file_path] = []
                    issues_by_file[file_path].append(issue)
            
            # Process each file's issues
            for file_path, file_issues in issues_by_file.items():
                # FIXED: Improved file filtering logic for CLI scans
                should_skip_file = False
                
                if file_list and scan_type == "pr":
                    # For PR scans, only process files in the PR diff
                    should_skip_file = file_path not in file_list
                elif file_list and scan_type == "cli":
                    # For CLI scans, check both absolute and relative paths
                    relative_path = os.path.relpath(file_path, temp_dir) if file_path.startswith(temp_dir) else file_path
                    absolute_path = os.path.join(temp_dir, file_path) if not os.path.isabs(file_path) else file_path
                    
                    # Check if file is in the CLI file list (support both relative and absolute paths)
                    path_in_list = (
                        file_path in file_list or 
                        relative_path in file_list or 
                        absolute_path in file_list or
                        any(f.endswith(relative_path) for f in file_list) or
                        any(relative_path.endswith(os.path.basename(f)) for f in file_list)
                    )
                    should_skip_file = not path_in_list
                
                if should_skip_file:
                    logger.debug(f"Skipping file {file_path} - not in target file list for {scan_type} scan")
                    continue
                
                # Extract context for all issues in this file at once
                updated_issues = self.context_extractor.extract_batch_context(
                    file_issues, temp_dir
                )
                
                # Normalize and add to results
                for issue in updated_issues:
                    normalized = self._normalize_issue(issue, temp_dir)
                    if normalized:
                        all_issues.append(normalized)
                        logger.debug(f"Added normalized issue from {normalized.get('tool')} for {normalized.get('file_path')}")
        
        return all_issues
    
    async def _calculate_scores_cached(
        self,
        issues: List[Dict[str, Any]],
        scope: str,
        niche: str
    ) -> Dict[str, float]:
        """Calculate scores with caching for common patterns"""
        
        # Create a cache key based on issue patterns
        issue_summary = f"{len(issues)}:{scope}:{niche}"
        severity_counts = {}
        for issue in issues[:100]:  # Sample first 100 for cache key
            sev = issue.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        cache_key = f"scores:{issue_summary}:{hash(str(severity_counts))}"
        
        # Try cache
        try:
            redis_client = await self._get_safe_redis_client()
            if redis_client:
                cached = await redis_client.get(cache_key)
                if cached:
                    import json
                    return json.loads(cached)
        except Exception:
            pass
        
        # Calculate scores
        scores = self.scoring.calculate_comprehensive_scores(issues, scope, niche)
        
        # Cache result
        try:
            redis_client = await self._get_safe_redis_client()
            if redis_client:
                import json
                await redis_client.setex(cache_key, 300, json.dumps(scores))  # 5 min TTL
        except Exception:
            pass
        
        return scores
    
    async def _generate_sbom_async(self, temp_dir: str) -> Optional[Dict[str, Any]]:
        """Generate SBOM asynchronously with better error handling"""
        
        try:
            # Run trivy in SBOM mode
            cmd = [
                'trivy', 'fs',
                '--format', 'cyclonedx',
                '--scanners', 'vuln',
                '--timeout', '5m',
                temp_dir
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 minutes
            )
            
            if process.returncode == 0 and stdout:
                # Parse SBOM
                return self._parse_sbom(stdout.decode())
            else:
                logger.warning(f"SBOM generation failed: {stderr.decode()}")
                return None
                
        except Exception as e:
            logger.error(f"SBOM generation error: {e}")
            return None
    
    def _parse_sbom(self, sbom_xml: str) -> Dict[str, Any]:
        """Parse SBOM with error handling"""
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(sbom_xml)
            
            # Extract components
            components = []
            ns = {'cdx': 'http://cyclonedx.org/schema/bom/1.4'}
            
            for comp in root.findall('.//cdx:component', ns):
                comp_data = {
                    "type": comp.get("type"),
                    "name": self._safe_find_text(comp, 'cdx:name', ns),
                    "version": self._safe_find_text(comp, 'cdx:version', ns),
                    "purl": self._safe_find_text(comp, 'cdx:purl', ns)
                }
                if comp_data["name"]:  # Only add if we have a name
                    components.append(comp_data)
            
            return {
                "format": "CycloneDX",
                "version": "1.4",
                "components": components,
                "component_count": len(components),
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"SBOM parsing error: {e}")
            return {
                "format": "CycloneDX",
                "version": "1.4",
                "components": [],
                "component_count": 0,
                "error": str(e)
            }
    
    def _safe_find_text(self, element, path: str, namespaces: dict) -> Optional[str]:
        """Safely find text in XML element"""
        
        try:
            elem = element.find(path, namespaces)
            return elem.text if elem is not None else None
        except Exception:
            return None
    
    def _generate_compliance_mappings_optimized(
        self, issues: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate compliance mappings with optimizations"""
        
        # Use counters for efficiency
        from collections import Counter
        
        owasp_counter = Counter()
        cwe_counter = Counter()
        severity_counter = Counter()
        
        for issue in issues:
            if owasp := issue.get("owasp_category"):
                owasp_counter[owasp] += 1
            if cwe := issue.get("cwe_id"):
                # Handle both string and list CWE IDs
                if isinstance(cwe, list):
                    for cwe_item in cwe:
                        if cwe_item:  # Skip empty values
                            cwe_counter[str(cwe_item)] += 1
                else:
                    cwe_counter[str(cwe)] += 1
            severity_counter[issue.get("severity", "medium")] += 1
        
        # Calculate compliance score
        compliance_score = self._calculate_compliance_score_optimized(
            dict(owasp_counter), dict(severity_counter)
        )
        
        return {
            "owasp_top10_coverage": dict(owasp_counter),
            "cwe_distribution": dict(cwe_counter),
            "severity_distribution": dict(severity_counter),
            "compliance_score": compliance_score,
            "framework_mappings": {
                "OWASP": len(owasp_counter),
                "CWE": len(cwe_counter),
                "Critical Issues": severity_counter.get("critical", 0),
                "High Issues": severity_counter.get("high", 0)
            },
            "risk_score": self._calculate_risk_score(dict(severity_counter))
        }
    
    def _calculate_compliance_score_optimized(
        self, owasp_counts: Dict[str, int], severity_counts: Dict[str, int]
    ) -> int:
        """Calculate compliance score with logarithmic scaling"""
        
        if not owasp_counts and not severity_counts:
            return 100
        
        # Import math for logarithmic calculations
        import math
        
        # Weight by severity for impact calculation
        severity_weights = {
            "critical": 10,
            "high": 5,
            "medium": 2,
            "low": 1
        }
        
        # Calculate total weighted impact
        total_impact = sum(
            severity_weights.get(sev, 1) * count
            for sev, count in severity_counts.items()
        )
        
        # Add OWASP category impact
        owasp_impact = len(owasp_counts) * 3  # Reduced from 5
        total_impact += owasp_impact
        
        if total_impact <= 0:
            return 100
        
        # Use logarithmic scaling for proper score calculation
        # This ensures meaningful scores even with high issue counts
        
        # Calculate total issues for adaptive scaling
        total_issues = sum(severity_counts.values()) if severity_counts else 1
        
        # Adaptive scaling based on issue count to ensure meaningful scores
        if total_issues > 200:
            scaling_factor = 15  # Very gentle scaling for massive issue counts
        elif total_issues > 100:
            scaling_factor = 18  # Moderate scaling for high counts
        else:
            scaling_factor = 22  # Standard scaling
        
        log_score = 100 - (math.log10(total_impact + 1) * scaling_factor)
        
        # Ensure minimum meaningful score for high issue counts
        if total_issues > 50:
            min_score = 5 + min(15, math.log10(total_issues) * 3)
            log_score = max(log_score, min_score)
        
        # Ensure score is within bounds [0, 100]
        final_score = max(0, min(100, int(round(log_score))))
        
        return final_score
    
    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate risk score based on issue severity using proper logarithmic scaling"""
        
        weights = {
            "critical": 10.0,
            "high": 5.0,
            "medium": 2.0,
            "low": 0.5
        }
        
        total_impact = sum(
            weights.get(sev, 1.0) * count
            for sev, count in severity_counts.items()
        )
        
        if total_impact == 0:
            return 0.0
        
        # Use logarithmic scale for proper risk distribution
        # Risk score represents the severity of security risk (0-100)
        import math
        
        # Logarithmic scaling: higher impact = higher risk score
        # Formula: log10(impact + 1) * scaling_factor
        risk_score = min(100.0, math.log10(total_impact + 1) * 25)
        
        return round(risk_score, 2)
    
    def _update_metrics(self, scan_duration: float, issues_found: int):
        """Update performance metrics"""
        
        self.metrics["scans_completed"] += 1
        self.metrics["total_issues_found"] += issues_found
        
        # Update average scan time
        total_time = (
            self.metrics["average_scan_time"] * (self.metrics["scans_completed"] - 1) +
            scan_duration
        )
        self.metrics["average_scan_time"] = total_time / self.metrics["scans_completed"]
    
    def _create_error_response(
        self,
        error: str,
        scan_type: str,
        repository: str,
        branch: str,
        duration: float
    ) -> Dict[str, Any]:
        """Create standardized error response"""
        
        return {
            "success": False,
            "error": error,
            "issues": [],
            "scores": {
                "total_score": 0,
                "code_score": 0,
                "deps_score": 0,
                "secrets_score": 0,
                "configs_score": 0,
                "anomaly_score": 0
            },
            "metadata": {
                "scan_duration": duration,
                "scan_type": scan_type,
                "repository": repository,
                "branch": branch,
                "error_details": error
            }
        }
    
    async def _check_scan_cache(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Check for cached scan results"""
        
        try:
            redis_client = await self._get_safe_redis_client()
            if redis_client:
                cache_key = f"scan_result:{scan_id}"
                cached = await redis_client.get(cache_key)
                if cached:
                    import json
                    return json.loads(cached)
        except Exception as e:
            logger.debug(f"Cache check failed: {e}")
        
        return None
    
    async def _cache_scan_result(self, scan_id: str, result: Dict[str, Any]):
        """Cache scan results for fast mode"""
        
        try:
            redis_client = await self._get_safe_redis_client()
            if redis_client:
                import json
                cache_key = f"scan_result:{scan_id}"
                # Cache for 30 minutes
                await redis_client.setex(
                    cache_key,
                    1800,
                    json.dumps(result, default=str)
                )
        except Exception as e:
            logger.debug(f"Cache write failed: {e}")
    
    def _get_language_percentage(self, languages: Dict[str, int], language: str) -> float:
        """Calculate percentage of a language in the repository"""
        
        total = sum(languages.values())
        if total == 0:
            return 0
        return (languages.get(language, 0) / total) * 100
    
    def _detect_languages_from_files(self, file_list: List[str]) -> Dict[str, int]:
        """Detect languages from file list for CLI scans - FIXED: Use same capitalization as main scan"""
        
        languages = {}
        
        # CRITICAL FIX: Language mapping with CAPITALIZED keys to match main scan and tool selection logic
        extension_map = {
            '.py': 'Python',         # CAPITALIZED to match tool selection
            '.js': 'JavaScript',     # CAPITALIZED to match tool selection  
            '.jsx': 'JavaScript',
            '.ts': 'TypeScript',     # CAPITALIZED to match tool selection
            '.tsx': 'TypeScript',
            '.java': 'Java',         # CAPITALIZED to match tool selection
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.go': 'Go',             # CAPITALIZED to match tool selection
            '.rb': 'Ruby',           # CAPITALIZED to match tool selection
            '.php': 'PHP',           # CAPITALIZED to match tool selection
            '.c': 'C',               # CAPITALIZED to match tool selection
            '.cpp': 'C++',           # CAPITALIZED to match tool selection
            '.cc': 'C++',
            '.cxx': 'C++',
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # '.cs': 'C#',             # CAPITALIZED to match tool selection
            '.rs': 'Rust',
            '.swift': 'Swift',
            '.m': 'Objective-C',
            '.mm': 'Objective-C++',
            '.sh': 'Shell',
            '.bash': 'Shell',
            '.dockerfile': 'Dockerfile',
            '.tf': 'HCL',            # Terraform uses HCL
            '.yaml': 'YAML',
            '.yml': 'YAML',
            '.json': 'JSON',
            '.xml': 'XML',
            '.html': 'HTML',
            '.css': 'CSS',
            '.scss': 'SCSS',
            '.less': 'Less'
        }
        
        for file_path in file_list:
            # Get file extension
            _, ext = os.path.splitext(file_path.lower())
            
            # Special case for Dockerfile
            filename = os.path.basename(file_path.lower())
            if filename == 'dockerfile' or filename.startswith('dockerfile.'):
                language = 'dockerfile'
            else:
                language = extension_map.get(ext)
            
            if language:
                languages[language] = languages.get(language, 0) + 1
        
        logger.info(f"CLI language detection: {languages}")
        return languages
    
    def _should_include_api_rules(self, languages: Dict[str, int], file_list: Optional[List[str]] = None) -> bool:
        """Determine if API security rules should be included"""
        
        # Check for web languages
        web_languages = ['JavaScript', 'TypeScript', 'Python', 'Java', 'Ruby', 'PHP', 'Go']
        has_web_language = any(lang in languages for lang in web_languages)
        
        if not has_web_language:
            return False
        
        # Check for API-related files
        api_indicators = [
            'routes', 'controllers', 'api', 'endpoints', 'graphql', 
            'rest', 'swagger', 'openapi', 'handler', 'service'
        ]
        
        if file_list:
            for file in file_list:
                file_lower = file.lower()
                if any(indicator in file_lower for indicator in api_indicators):
                    logger.info("API rules enabled: API-related files detected")
                    return True
        
        # Check for framework indicators in languages
        if 'Python' in languages and self._get_language_percentage(languages, 'Python') > 10:
            logger.info("API rules enabled: Significant Python presence")
            return True
        
        if ('JavaScript' in languages or 'TypeScript' in languages) and \
           (self._get_language_percentage(languages, 'JavaScript') + 
            self._get_language_percentage(languages, 'TypeScript')) > 15:
            logger.info("API rules enabled: Significant JS/TS presence")
            return True
        
        return False
    
    def _normalize_issue(self, issue: Dict[str, Any], temp_dir: str) -> Optional[Dict[str, Any]]:
        """Normalize issue format with validation"""
        
        try:
            # Ensure required fields
            if not issue.get("tool") or not issue.get("file_path"):
                return None
            
            # Clean file path
            file_path = issue["file_path"]
            if file_path.startswith(temp_dir):
                file_path = os.path.relpath(file_path, temp_dir)
            
            return {
                "tool": issue.get("tool"),
                "category": issue.get("category", "code"),
                "rule_id": issue.get("rule_id", "unknown"),
                "message": issue.get("message", "Security issue detected"),
                "severity": issue.get("severity", "medium").lower(),
                "file_path": file_path,
                "line_start": issue.get("line_start") or issue.get("line"),
                "line_end": issue.get("line_end"),
                "confidence": issue.get("confidence", "medium"),
                "owasp_category": issue.get("owasp_category"),
                "cwe_id": issue.get("cwe_id"),
                "code_context": issue.get("code_context"),
                "metadata": {
                    k: v for k, v in issue.items()
                    if k not in [
                        "tool", "category", "rule_id", "message", "severity",
                        "file_path", "line_start", "line_end", "confidence",
                        "owasp_category", "cwe_id", "code_context"
                    ]
                }
            }
        except Exception as e:
            logger.warning(f"Could not normalize issue: {e}")
            return None
    
    async def _detect_languages_extended(
        self, temp_dir: str, repo_full_name: str, gh_token: str
    ) -> Dict[str, int]:
        """Enhanced language detection using both GitHub API and file extensions"""
        
        languages = {}
        
        # Try GitHub API first for accuracy
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            languages = repo.get_languages()
        except GithubException as e:
            logger.warning(f"Could not detect languages via API: {e}")
        
        # Supplement with file extension scanning
        extension_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.mjs': 'JavaScript',
            '.ts': 'TypeScript',
            '.jsx': 'JavaScript',
            '.tsx': 'TypeScript',
            '.go': 'Go',
            '.java': 'Java',
            # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
            # '.cs': 'C#',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.cxx': 'C++',
            '.h': 'C',
            '.hpp': 'C++',
            '.rs': 'Rust',
            '.kt': 'Kotlin',
            '.swift': 'Swift',
            '.scala': 'Scala',
            '.r': 'R',
            '.m': 'Objective-C',
            '.mm': 'Objective-C++',
            '.dart': 'Dart',
            '.lua': 'Lua',
            '.pl': 'Perl',
            '.sh': 'Shell',
            '.bash': 'Shell',
            '.ps1': 'PowerShell',
            '.psm1': 'PowerShell',
            '.yml': 'YAML',
            '.yaml': 'YAML'
        }
        
        # Count files efficiently
        file_counts = {}
        for root, dirs, files in os.walk(temp_dir):
            # Skip hidden and vendor directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['vendor', 'node_modules', 'dist', 'build']]
            
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in extension_map:
                    lang = extension_map[ext]
                    file_counts[lang] = file_counts.get(lang, 0) + 1
        
        # Merge with API results
        for lang, count in file_counts.items():
            if lang not in languages:
                # Estimate bytes based on file count
                languages[lang] = count * 1000
        
        return languages
    
    async def _run_tool_safe(self, tool_name: str, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Safely run a tool with comprehensive error handling"""
        
        try:
            if tool_name not in self.tools:
                return {"tool": tool_name, "error": "Tool not available", "issues": []}
            
            # REMOVED SEMGREP FILE SIZE RESTRICTION - Allow analysis of large files
            # Previous 1MB limit was preventing analysis of large files that may contain vulnerabilities
            if tool_name == 'semgrep':
                # Removed max_target_bytes restriction to allow scanning of all files
                logger.info(f"🔧 SEMGREP: File size restrictions removed for comprehensive scanning")
            
            # Focus on changed files for PR scans
            if kwargs.get('focus_on_changed_files') and kwargs.get('file_list'):
                kwargs['target_files'] = kwargs['file_list']
                logger.info(f"Tool {tool_name} focusing on {len(kwargs['file_list'])} changed files")
            
            # Add custom rules for supported tools
            custom_rules_info = kwargs.get('custom_rules_info')
            if custom_rules_info and custom_rules_info.get('rule_files'):
                if tool_name in ['semgrep', 'bandit']:  # Tools that support custom rules
                    kwargs['custom_rule_files'] = custom_rules_info['rule_files']
                    logger.info(f"Tool {tool_name} using {len(custom_rules_info['rule_files'])} custom rule files")
                
            return await self.tools[tool_name].run_with_availability_check(temp_dir, **kwargs)
            
        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {str(e)}", exc_info=True)
            return {"tool": tool_name, "error": str(e), "issues": []}