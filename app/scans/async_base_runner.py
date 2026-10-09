"""
Enhanced Async Base Runner for DevSecureX Security Tools
Phase 3: High-performance async security tool execution with non-blocking I/O
"""

import asyncio
import json
import logging
import tempfile
import os
import shutil
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from core.async_file_io import AsyncFileIOManager, read_file_async, write_file_async, read_json_async
from core.async_subprocess import AsyncSubprocessManager, execute_security_tool_async

logger = logging.getLogger(__name__)

class AsyncBaseToolRunner(ABC):
    """
    Enhanced async base class for security tool runners with world-class performance optimizations
    
    Features:
    - Non-blocking file I/O with aiofiles
    - Async subprocess execution with intelligent concurrency
    - Memory-efficient file processing
    - Comprehensive error handling and recovery
    - Performance monitoring and metrics
    - Concurrent tool execution capabilities
    """
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.timeout = 1200  # 20 minutes default
        self.tool_available = None
        self.file_manager = AsyncFileIOManager()
        self.subprocess_manager = AsyncSubprocessManager()
        
        # Performance metrics
        self.execution_metrics = {
            "runs": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "total_execution_time": 0.0,
            "avg_execution_time": 0.0,
            "total_files_processed": 0,
            "issues_found": 0
        }
    
    @abstractmethod
    async def run_async(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Run the security tool asynchronously and return normalized results"""
        pass
    
    async def check_tool_availability_async(self) -> bool:
        """Check if the tool is available and working asynchronously"""
        if self.tool_available is not None:
            return self.tool_available
        
        try:
            # Define tool commands for version checking
            version_commands = {
                'semgrep': ['semgrep', '--version'],
                'bandit': ['python3', '-m', 'bandit', '--version'],
                'trufflehog': ['trufflehog', '--version'],
                'trivy': ['trivy', '--version'],
                'checkov': ['checkov', '--version'],
                'gitleaks': ['gitleaks', 'version'],
                'safety': ['safety', '--version'],
                'gosec': ['gosec', '--version'],
                'eslint-security': ['eslint', '--version'],
                'spotbugs': ['spotbugs', '-help'],
                'psalm': ['psalm', '--version'],
                'brakeman': ['brakeman', '--version'],
                'cppcheck': ['cppcheck', '--version'],
            }
            
            version_cmd = version_commands.get(self.tool_name)
            if not version_cmd:
                self.tool_available = False
                return False
            
            # Use async subprocess execution
            result = await self.subprocess_manager.execute_process(
                command=version_cmd,
                timeout=10,
                capture_output=True
            )
            
            # Special handling for SpotBugs
            if self.tool_name == 'spotbugs':
                if result.stdout and ('spotbugs' in result.stdout.lower() or 'help' in result.stdout.lower()):
                    self.tool_available = True
                    return True
                elif result.stderr and 'java runtime' in result.stderr.lower():
                    self.tool_available = True  # Binary exists, runtime issue is handled separately
                    return True
            
            self.tool_available = result.success or result.returncode == 0
            
            if self.tool_available:
                logger.info(f"Tool {self.tool_name} is available and working")
            else:
                logger.warning(f"Tool {self.tool_name} availability check failed: {result.stderr[:200]}")
            
            return self.tool_available
            
        except Exception as e:
            logger.error(f"Error checking tool availability for {self.tool_name}: {e}")
            self.tool_available = False
            return False
    
    async def run_with_availability_check_async(self, temp_dir: str, **kwargs) -> Dict[str, Any]:
        """Run tool with async availability check and comprehensive error handling"""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Update metrics
            self.execution_metrics["runs"] += 1
            
            # Check availability asynchronously
            if not await self.check_tool_availability_async():
                return {
                    "tool": self.tool_name,
                    "error": f"Tool {self.tool_name} is not available or not working",
                    "issues": [],
                    "success": False,
                    "execution_time": 0.0
                }
            
            # Run the tool asynchronously
            result = await self.run_async(temp_dir, **kwargs)
            
            # Update success metrics
            execution_time = asyncio.get_event_loop().time() - start_time
            self.execution_metrics["total_execution_time"] += execution_time
            self.execution_metrics["avg_execution_time"] = (
                self.execution_metrics["total_execution_time"] / self.execution_metrics["runs"]
            )
            
            if result.get("success", True):
                self.execution_metrics["successful_runs"] += 1
            else:
                self.execution_metrics["failed_runs"] += 1
            
            # Update issues found
            issues = result.get("issues", [])
            self.execution_metrics["issues_found"] += len(issues)
            
            # Add execution metadata
            result.update({
                "execution_time": execution_time,
                "tool_metrics": self.get_execution_metrics()
            })
            
            return result
            
        except Exception as e:
            execution_time = asyncio.get_event_loop().time() - start_time
            self.execution_metrics["failed_runs"] += 1
            self.execution_metrics["total_execution_time"] += execution_time
            
            logger.error(f"Async tool execution failed for {self.tool_name}: {str(e)}", exc_info=True)
            return {
                "tool": self.tool_name,
                "error": str(e),
                "issues": [],
                "success": False,
                "execution_time": execution_time
            }
    
    async def scan_files_async(self, temp_dir: str, file_patterns: List[str] = None) -> List[str]:
        """
        Scan directory for files asynchronously with pattern matching
        
        Args:
            temp_dir: Directory to scan
            file_patterns: List of file patterns to match (default: language-specific)
            
        Returns:
            List of matching file paths
        """
        if not file_patterns:
            file_patterns = self._get_default_file_patterns()
        
        all_files = []
        
        # Scan for each pattern concurrently
        scan_tasks = [
            self.file_manager.scan_directory_async(temp_dir, pattern, recursive=True)
            for pattern in file_patterns
        ]
        
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Collect results
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"File scan pattern failed: {result}")
                continue
            all_files.extend(result)
        
        # Remove duplicates and return
        unique_files = list(set(all_files))
        self.execution_metrics["total_files_processed"] += len(unique_files)
        
        logger.debug(f"Async file scan found {len(unique_files)} files in {temp_dir}")
        return unique_files
    
    def _get_default_file_patterns(self) -> List[str]:
        """Get default file patterns for the tool"""
        # Tool-specific file patterns
        tool_patterns = {
            'semgrep': ['*.py', '*.js', '*.jsx', '*.ts', '*.tsx', '*.go', '*.java', '*.php', '*.rb', '*.c', '*.cpp', '*.cs'],
            'bandit': ['*.py'],
            'gosec': ['*.go'],
            'eslint-security': ['*.js', '*.jsx', '*.ts', '*.tsx'],
            'spotbugs': ['*.java', '*.class', '*.jar'],
            'psalm': ['*.php'],
            'brakeman': ['*.rb'],
            'cppcheck': ['*.c', '*.cpp', '*.cc', '*.cxx', '*.h', '*.hpp'],
            'trivy': ['*'],  # Container and dependency scanning
            'checkov': ['*.tf', '*.json', '*.yaml', '*.yml', 'Dockerfile*'],
            'trufflehog': ['*'],  # Secret scanning - all files
            'gitleaks': ['*'],   # Git secret scanning - all files
            'safety': ['requirements*.txt', 'Pipfile*', 'pyproject.toml', 'setup.py']
        }
        
        return tool_patterns.get(self.tool_name, ['*'])
    
    async def write_config_file_async(self, config_path: str, config_data: Dict[str, Any]) -> None:
        """Write tool configuration file asynchronously"""
        try:
            await write_file_async(config_path, json.dumps(config_data, indent=2))
            logger.debug(f"Config file written asynchronously: {config_path}")
        except Exception as e:
            logger.error(f"Failed to write config file async {config_path}: {e}")
            raise
    
    async def read_results_file_async(self, results_path: str) -> Dict[str, Any]:
        """Read tool results file asynchronously"""
        try:
            if not await self.file_manager.file_exists_async(results_path):
                logger.warning(f"Results file does not exist: {results_path}")
                return {}
            
            content = await read_file_async(results_path)
            
            if not content.strip():
                logger.warning(f"Results file is empty: {results_path}")
                return {}
            
            # Try to parse as JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                logger.warning(f"Results file is not valid JSON: {results_path}")
                return {"raw_content": content}
                
        except Exception as e:
            logger.error(f"Failed to read results file async {results_path}: {e}")
            return {}
    
    async def execute_tool_command_async(
        self, 
        command: List[str], 
        working_dir: str,
        timeout: Optional[int] = None,
        env_vars: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Execute tool command asynchronously with enhanced monitoring"""
        
        tool_timeout = timeout or self.timeout
        
        # Execute using the async subprocess manager
        result = await execute_security_tool_async(
            tool_name=self.tool_name,
            command=command,
            working_dir=working_dir,
            timeout=tool_timeout,
            env_vars=env_vars
        )
        
        return result
    
    async def process_results_concurrent(self, results_data: Dict[str, Any], temp_dir: str) -> List[Dict[str, Any]]:
        """Process tool results with concurrent file operations for enhanced performance"""
        issues = []
        
        try:
            # Extract issues from results (tool-specific implementation in subclasses)
            raw_issues = self._extract_issues_from_results(results_data)
            
            if not raw_issues:
                return []
            
            # Process issues concurrently
            process_tasks = [
                self._process_single_issue_async(issue, temp_dir)
                for issue in raw_issues
            ]
            
            processed_results = await asyncio.gather(*process_tasks, return_exceptions=True)
            
            # Collect successful results
            for result in processed_results:
                if isinstance(result, Exception):
                    logger.warning(f"Issue processing failed: {result}")
                    continue
                if result:
                    issues.append(result)
            
            logger.info(f"Processed {len(issues)} issues concurrently for {self.tool_name}")
            return issues
            
        except Exception as e:
            logger.error(f"Error processing results concurrently: {e}")
            return []
    
    def _extract_issues_from_results(self, results_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract issues from tool results - to be implemented by subclasses"""
        # Default implementation - subclasses should override
        return results_data.get("issues", [])
    
    async def _process_single_issue_async(self, issue: Dict[str, Any], temp_dir: str) -> Optional[Dict[str, Any]]:
        """Process a single issue asynchronously - to be implemented by subclasses"""
        # Default implementation - subclasses should override for enhanced processing
        return issue
    
    def get_execution_metrics(self) -> Dict[str, Any]:
        """Get execution metrics for this tool"""
        return self.execution_metrics.copy()
    
    def reset_metrics(self):
        """Reset execution metrics"""
        self.execution_metrics = {
            "runs": 0,
            "successful_runs": 0,
            "failed_runs": 0,
            "total_execution_time": 0.0,
            "avg_execution_time": 0.0,
            "total_files_processed": 0,
            "issues_found": 0
        }
    
    async def cleanup_async(self):
        """Async cleanup resources"""
        try:
            if hasattr(self.file_manager, 'close'):
                await self.file_manager.close()
        except Exception as e:
            logger.debug(f"Error during async cleanup for {self.tool_name}: {e}")

class AsyncConcurrentToolRunner:
    """
    Manages concurrent execution of multiple async security tools
    """
    
    def __init__(self, tools: List[AsyncBaseToolRunner], max_concurrent: int = 6):
        self.tools = {tool.tool_name: tool for tool in tools}
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        logger.info(f"AsyncConcurrentToolRunner initialized with {len(tools)} tools, max concurrent: {max_concurrent}")
    
    async def run_tools_concurrent(
        self, 
        temp_dir: str, 
        selected_tools: List[str],
        **kwargs
    ) -> Dict[str, Dict[str, Any]]:
        """
        Run selected tools concurrently with intelligent load balancing
        
        Args:
            temp_dir: Working directory for tools
            selected_tools: List of tool names to run
            **kwargs: Additional arguments passed to tools
            
        Returns:
            Dictionary mapping tool names to their results
        """
        # Filter available tools
        available_tools = [name for name in selected_tools if name in self.tools]
        
        if not available_tools:
            logger.warning("No available tools found for concurrent execution")
            return {}
        
        logger.info(f"Running {len(available_tools)} tools concurrently: {available_tools}")
        
        async def run_single_tool(tool_name: str) -> tuple[str, Dict[str, Any]]:
            async with self.semaphore:
                tool = self.tools[tool_name]
                logger.info(f"Starting async execution of {tool_name}")
                result = await tool.run_with_availability_check_async(temp_dir, **kwargs)
                logger.info(f"Completed async execution of {tool_name}")
                return tool_name, result
        
        # Execute all tools concurrently
        start_time = asyncio.get_event_loop().time()
        tasks = [run_single_tool(tool_name) for tool_name in available_tools]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        execution_time = asyncio.get_event_loop().time() - start_time
        logger.info(f"Concurrent tool execution completed in {execution_time:.2f}s")
        
        # Process results
        tool_results = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Tool execution failed with exception: {result}")
                continue
            
            tool_name, tool_result = result
            tool_results[tool_name] = tool_result
        
        return tool_results
    
    async def health_check_all_tools(self) -> Dict[str, bool]:
        """Check availability of all tools concurrently"""
        async def check_tool(tool_name: str, tool: AsyncBaseToolRunner) -> tuple[str, bool]:
            available = await tool.check_tool_availability_async()
            return tool_name, available
        
        tasks = [check_tool(name, tool) for name, tool in self.tools.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        availability = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Tool health check failed: {result}")
                continue
            tool_name, available = result
            availability[tool_name] = available
        
        return availability
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get execution metrics for all tools"""
        return {name: tool.get_execution_metrics() for name, tool in self.tools.items()}
    
    async def cleanup_all(self):
        """Cleanup all tools"""
        cleanup_tasks = [tool.cleanup_async() for tool in self.tools.values()]
        await asyncio.gather(*cleanup_tasks, return_exceptions=True)