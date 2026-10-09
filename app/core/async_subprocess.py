"""
Async Subprocess Management for DevSecureX Security Scanning
Phase 3: Non-blocking process execution with intelligent concurrency control
"""

import asyncio
import logging
import os
import time
import psutil
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import signal
import sys

logger = logging.getLogger(__name__)

@dataclass
class ProcessResult:
    """Result of an async process execution"""
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    success: bool
    pid: Optional[int] = None
    memory_usage: Optional[float] = None
    
class AsyncSubprocessManager:
    """
    World-class async subprocess manager for DevSecureX security tool execution
    
    Features:
    - Non-blocking process execution with asyncio
    - Intelligent concurrency control and resource management
    - Memory and timeout monitoring
    - Process pool management for optimal performance
    - Comprehensive error handling and recovery
    - Performance metrics and monitoring
    """
    
    def __init__(self, max_concurrent_processes: int = None, default_timeout: int = 300):
        """
        Initialize the async subprocess manager
        
        Args:
            max_concurrent_processes: Maximum concurrent processes (auto-detected if None)
            default_timeout: Default timeout for processes in seconds
        """
        self.max_concurrent_processes = max_concurrent_processes or self._calculate_optimal_concurrency()
        self.default_timeout = default_timeout
        self.active_processes: Dict[int, asyncio.subprocess.Process] = {}
        self.semaphore = asyncio.Semaphore(self.max_concurrent_processes)
        
        # Performance metrics
        self.metrics = {
            "processes_executed": 0,
            "successful_processes": 0,
            "failed_processes": 0,
            "timeout_processes": 0,
            "total_execution_time": 0.0,
            "avg_execution_time": 0.0,
            "peak_memory_usage": 0.0,
            "concurrent_processes_peak": 0
        }
        
        logger.info(f"AsyncSubprocessManager initialized with {self.max_concurrent_processes} max concurrent processes")
    
    def _calculate_optimal_concurrency(self) -> int:
        """Calculate optimal concurrency based on system resources - PERFORMANCE OPTIMIZED"""
        try:
            cpu_count = psutil.cpu_count(logical=True)
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # AGGRESSIVE CONCURRENCY for maximum performance
            # Use 100% of CPUs + buffer for I/O bound tasks
            optimal = max(4, min(cpu_count + 4, int(memory_gb / 0.3)))
            
            # Increased cap for high-performance scanning
            optimal = min(optimal, 20)
            
            logger.info(f"🚀 PERFORMANCE OPTIMIZED concurrency: {optimal} (CPUs: {cpu_count}, Memory: {memory_gb:.1f}GB)")
            return optimal
            
        except Exception as e:
            logger.warning(f"Failed to calculate optimal concurrency: {e}, using performance default: 8")
            return 8
    
    async def execute_process(
        self, 
        command: List[str], 
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        input_data: Optional[str] = None,
        capture_output: bool = True
    ) -> ProcessResult:
        """
        Execute a single process asynchronously with comprehensive monitoring
        
        Args:
            command: Command to execute as list
            cwd: Working directory
            env: Environment variables
            timeout: Timeout in seconds (uses default if None)
            input_data: Data to send to stdin
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            ProcessResult with execution details
        """
        timeout = timeout or self.default_timeout
        start_time = time.time()
        process = None
        
        async with self.semaphore:
            try:
                # Update peak concurrent processes metric
                current_active = len(self.active_processes)
                self.metrics["concurrent_processes_peak"] = max(
                    self.metrics["concurrent_processes_peak"], 
                    current_active + 1
                )
                
                # Prepare environment
                process_env = os.environ.copy()
                if env:
                    process_env.update(env)
                
                # Create subprocess
                stdout = asyncio.subprocess.PIPE if capture_output else None
                stderr = asyncio.subprocess.PIPE if capture_output else None
                stdin = asyncio.subprocess.PIPE if input_data else None
                
                process = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=cwd,
                    env=process_env,
                    stdout=stdout,
                    stderr=stderr,
                    stdin=stdin
                )
                
                # Track active process
                if process.pid:
                    self.active_processes[process.pid] = process
                
                # Monitor memory usage
                memory_usage = 0.0
                try:
                    if process.pid:
                        psutil_process = psutil.Process(process.pid)
                        memory_info = psutil_process.memory_info()
                        memory_usage = memory_info.rss / (1024**2)  # MB
                        self.metrics["peak_memory_usage"] = max(self.metrics["peak_memory_usage"], memory_usage)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                
                # Execute with timeout
                try:
                    if input_data:
                        stdout_data, stderr_data = await asyncio.wait_for(
                            process.communicate(input=input_data.encode()),
                            timeout=timeout
                        )
                    else:
                        stdout_data, stderr_data = await asyncio.wait_for(
                            process.communicate(),
                            timeout=timeout
                        )
                    
                    execution_time = time.time() - start_time
                    
                    # Update metrics
                    self.metrics["processes_executed"] += 1
                    self.metrics["total_execution_time"] += execution_time
                    self.metrics["avg_execution_time"] = (
                        self.metrics["total_execution_time"] / self.metrics["processes_executed"]
                    )
                    
                    if process.returncode == 0:
                        self.metrics["successful_processes"] += 1
                    else:
                        self.metrics["failed_processes"] += 1
                    
                    return ProcessResult(
                        command=command,
                        returncode=process.returncode,
                        stdout=stdout_data.decode() if stdout_data else "",
                        stderr=stderr_data.decode() if stderr_data else "",
                        execution_time=execution_time,
                        success=process.returncode == 0,
                        pid=process.pid,
                        memory_usage=memory_usage
                    )
                    
                except asyncio.TimeoutError:
                    # Handle timeout
                    execution_time = time.time() - start_time
                    self.metrics["processes_executed"] += 1
                    self.metrics["timeout_processes"] += 1
                    self.metrics["total_execution_time"] += execution_time
                    
                    # Terminate process
                    if process:
                        await self._terminate_process_gracefully(process)
                    
                    logger.warning(f"Process timed out after {timeout}s: {' '.join(command)}")
                    
                    return ProcessResult(
                        command=command,
                        returncode=-1,
                        stdout="",
                        stderr=f"Process timed out after {timeout} seconds",
                        execution_time=execution_time,
                        success=False,
                        pid=process.pid if process else None,
                        memory_usage=memory_usage
                    )
                    
            except Exception as e:
                execution_time = time.time() - start_time
                self.metrics["processes_executed"] += 1
                self.metrics["failed_processes"] += 1
                self.metrics["total_execution_time"] += execution_time
                
                logger.error(f"Process execution failed: {' '.join(command)}: {e}")
                
                return ProcessResult(
                    command=command,
                    returncode=-1,
                    stdout="",
                    stderr=f"Process execution failed: {str(e)}",
                    execution_time=execution_time,
                    success=False,
                    pid=process.pid if process and process.pid else None
                )
                
            finally:
                # Cleanup
                if process and process.pid and process.pid in self.active_processes:
                    del self.active_processes[process.pid]
    
    async def execute_processes_concurrent(
        self, 
        commands: List[List[str]], 
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        max_concurrent: Optional[int] = None
    ) -> List[ProcessResult]:
        """
        Execute multiple processes concurrently with intelligent batching
        
        Args:
            commands: List of commands to execute
            cwd: Working directory for all processes
            env: Environment variables
            timeout: Timeout per process
            max_concurrent: Override max concurrent processes
            
        Returns:
            List of ProcessResult objects
        """
        if max_concurrent:
            # Create temporary semaphore for this batch
            original_semaphore = self.semaphore
            self.semaphore = asyncio.Semaphore(min(max_concurrent, self.max_concurrent_processes))
        
        try:
            # Create tasks for all processes
            tasks = [
                self.execute_process(command, cwd=cwd, env=env, timeout=timeout)
                for command in commands
            ]
            
            # Execute all processes concurrently
            logger.info(f"Executing {len(commands)} processes concurrently (max: {self.semaphore._value})")
            start_time = time.time()
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            execution_time = time.time() - start_time
            logger.info(f"Concurrent execution completed in {execution_time:.2f}s")
            
            # Process results
            process_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Process {i} failed with exception: {result}")
                    process_results.append(ProcessResult(
                        command=commands[i],
                        returncode=-1,
                        stdout="",
                        stderr=f"Exception: {str(result)}",
                        execution_time=0.0,
                        success=False
                    ))
                else:
                    process_results.append(result)
            
            return process_results
            
        finally:
            if max_concurrent:
                # Restore original semaphore
                self.semaphore = original_semaphore
    
    async def _terminate_process_gracefully(self, process: asyncio.subprocess.Process):
        """Terminate a process gracefully with escalating signals"""
        if not process or not process.pid:
            return
        
        try:
            # Try SIGTERM first
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
                return
            except asyncio.TimeoutError:
                pass
            
            # Escalate to SIGKILL if still running
            if sys.platform != "win32":  # SIGKILL not available on Windows
                process.kill()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    logger.error(f"Failed to kill process {process.pid}")
            
        except Exception as e:
            logger.error(f"Error terminating process {process.pid}: {e}")
    
    async def execute_security_tool(
        self, 
        tool_name: str, 
        tool_command: List[str],
        working_dir: str,
        timeout: Optional[int] = None,
        env_vars: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Execute a security tool with specialized handling and monitoring
        
        Args:
            tool_name: Name of the security tool
            tool_command: Command to execute
            working_dir: Working directory
            timeout: Tool-specific timeout
            env_vars: Tool-specific environment variables
            
        Returns:
            Dictionary with tool execution results
        """
        logger.info(f"Executing security tool: {tool_name}")
        
        # Tool-specific environment setup
        tool_env = {
            'PYTHONPATH': os.environ.get('PYTHONPATH', ''),
            'PATH': os.environ.get('PATH', ''),
            'HOME': os.environ.get('HOME', ''),
            'TMPDIR': os.environ.get('TMPDIR', '/tmp'),
            'TERM': 'xterm-256color',  # Better terminal support
        }
        
        if env_vars:
            tool_env.update(env_vars)
        
        # Tool-specific timeout handling
        tool_timeout = timeout or self._get_tool_timeout(tool_name)
        
        start_time = time.time()
        result = await self.execute_process(
            command=tool_command,
            cwd=working_dir,
            env=tool_env,
            timeout=tool_timeout
        )
        
        # Log execution details
        if result.success:
            logger.info(f"Security tool {tool_name} completed successfully in {result.execution_time:.2f}s")
        else:
            logger.warning(f"Security tool {tool_name} failed (exit code: {result.returncode}) in {result.execution_time:.2f}s")
            if result.stderr:
                logger.debug(f"Tool stderr: {result.stderr[:500]}")
        
        return {
            'tool': tool_name,
            'success': result.success,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'execution_time': result.execution_time,
            'command': tool_command,
            'memory_usage': result.memory_usage
        }
    
    def _get_tool_timeout(self, tool_name: str) -> int:
        """Get tool-specific timeout values"""
        tool_timeouts = {
            'semgrep': 900,      # 15 minutes - comprehensive analysis
            'bandit': 300,       # 5 minutes - Python focused
            'gosec': 300,        # 5 minutes - Go focused
            'eslint-security': 600,  # 10 minutes - JavaScript/TypeScript
            'trivy': 900,        # 15 minutes - Container/dependency scanning
            'checkov': 600,      # 10 minutes - Infrastructure as Code
            'spotbugs': 1200,    # 20 minutes - Java bytecode analysis
            'trufflehog': 900,   # 15 minutes - Secret scanning
            'gitleaks': 600,     # 10 minutes - Git secret scanning
            'safety': 300,       # 5 minutes - Python dependency check
            'psalm': 600,        # 10 minutes - PHP analysis
            'brakeman': 600,     # 10 minutes - Ruby on Rails
            'cppcheck': 900,     # 15 minutes - C/C++ analysis
        }
        
        return tool_timeouts.get(tool_name, self.default_timeout)
    
    async def kill_all_processes(self):
        """Emergency kill all active processes"""
        if not self.active_processes:
            return
        
        logger.warning(f"Killing {len(self.active_processes)} active processes")
        
        # Create tasks to terminate all processes
        tasks = []
        for process in self.active_processes.values():
            tasks.append(self._terminate_process_gracefully(process))
        
        # Wait for all terminations with timeout
        try:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=10.0)
        except asyncio.TimeoutError:
            logger.error("Some processes could not be terminated within timeout")
        
        self.active_processes.clear()
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""
        metrics = self.metrics.copy()
        
        # Add current system metrics
        try:
            system_info = {
                "active_processes": len(self.active_processes),
                "max_concurrent_processes": self.max_concurrent_processes,
                "system_cpu_percent": psutil.cpu_percent(),
                "system_memory_percent": psutil.virtual_memory().percent,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            metrics.update(system_info)
        except Exception as e:
            logger.debug(f"Failed to get system metrics: {e}")
        
        return metrics
    
    def reset_metrics(self):
        """Reset performance metrics"""
        self.metrics = {
            "processes_executed": 0,
            "successful_processes": 0,
            "failed_processes": 0,
            "timeout_processes": 0,
            "total_execution_time": 0.0,
            "avg_execution_time": 0.0,
            "peak_memory_usage": 0.0,
            "concurrent_processes_peak": 0
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the subprocess manager"""
        return {
            "status": "healthy" if len(self.active_processes) < self.max_concurrent_processes else "busy",
            "active_processes": len(self.active_processes),
            "max_concurrent": self.max_concurrent_processes,
            "metrics": self.get_performance_metrics()
        }

# Global instance for use across the application
async_subprocess_manager = AsyncSubprocessManager()

# Convenience functions
async def execute_async(command: List[str], **kwargs) -> ProcessResult:
    """Convenience function for async process execution"""
    return await async_subprocess_manager.execute_process(command, **kwargs)

async def execute_concurrent(commands: List[List[str]], **kwargs) -> List[ProcessResult]:
    """Convenience function for concurrent process execution"""
    return await async_subprocess_manager.execute_processes_concurrent(commands, **kwargs)

async def execute_security_tool_async(tool_name: str, command: List[str], working_dir: str, **kwargs) -> Dict[str, Any]:
    """Convenience function for security tool execution"""
    return await async_subprocess_manager.execute_security_tool(tool_name, command, working_dir, **kwargs)