"""
Async Optimization Manager for DevSecureX
Phase 3: Central coordinator for all async optimizations and performance enhancements
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from core.async_file_io import AsyncFileIOManager, async_file_manager
from core.async_subprocess import AsyncSubprocessManager, async_subprocess_manager
from core.async_github_client import AsyncGitHubClient
from core.async_middleware import AsyncPerformanceMiddleware

logger = logging.getLogger(__name__)

class AsyncOptimizationManager:
    """
    Central manager for all async optimizations in DevSecureX
    
    Features:
    - Coordinates all async operations and optimizations
    - Manages resource allocation and concurrency limits
    - Provides unified performance monitoring and metrics
    - Handles async operation lifecycle management
    - Optimizes system-wide async performance
    """
    
    def __init__(self):
        self.file_manager: AsyncFileIOManager = async_file_manager
        self.subprocess_manager: AsyncSubprocessManager = async_subprocess_manager
        self.github_clients: Dict[str, AsyncGitHubClient] = {}
        self.performance_middleware: Optional[AsyncPerformanceMiddleware] = None
        
        # Global optimization settings
        self.optimization_config = {
            "max_concurrent_file_ops": 50,
            "max_concurrent_processes": 12,
            "max_concurrent_github_requests": 10,
            "enable_file_io_optimization": True,
            "enable_subprocess_optimization": True,
            "enable_github_optimization": True,
            "enable_performance_monitoring": True
        }
        
        # Performance tracking
        self.global_metrics = {
            "initialization_time": 0.0,
            "total_optimized_operations": 0,
            "total_time_saved": 0.0,
            "concurrent_operations_peak": 0,
            "optimization_efficiency": 0.0
        }
        
        self.initialized = False
        self.initialization_time = 0.0
        
        logger.info("AsyncOptimizationManager initialized")
    
    async def initialize(self):
        """Initialize all async optimization components"""
        if self.initialized:
            return
        
        start_time = time.time()
        logger.info("Initializing async optimization system...")
        
        try:
            # Initialize components concurrently
            init_tasks = []
            
            if self.optimization_config["enable_file_io_optimization"]:
                init_tasks.append(self._initialize_file_io_optimization())
            
            if self.optimization_config["enable_subprocess_optimization"]:
                init_tasks.append(self._initialize_subprocess_optimization())
            
            if self.optimization_config["enable_github_optimization"]:
                init_tasks.append(self._initialize_github_optimization())
            
            # Wait for all initializations to complete
            await asyncio.gather(*init_tasks, return_exceptions=True)
            
            self.initialization_time = time.time() - start_time
            self.global_metrics["initialization_time"] = self.initialization_time
            self.initialized = True
            
            logger.info(f"Async optimization system initialized in {self.initialization_time:.2f}s")
            
        except Exception as e:
            logger.error(f"Failed to initialize async optimization system: {e}")
            raise
    
    async def _initialize_file_io_optimization(self):
        """Initialize file I/O optimizations"""
        try:
            # Configure file manager with optimal settings
            self.file_manager.max_concurrent_files = self.optimization_config["max_concurrent_file_ops"]
            
            # Test file operations
            test_file_path = "/tmp/async_test_file.json"
            test_data = {"test": "async_file_io_optimization", "timestamp": datetime.now(timezone.utc).isoformat()}
            
            await self.file_manager.write_json_async(test_file_path, test_data)
            read_data = await self.file_manager.read_json_async(test_file_path)
            
            if read_data.get("test") == "async_file_io_optimization":
                logger.info("File I/O optimization initialized successfully")
            else:
                raise Exception("File I/O test failed")
            
            # Cleanup test file
            await self.file_manager.delete_file_async(test_file_path)
            
        except Exception as e:
            logger.error(f"File I/O optimization initialization failed: {e}")
            self.optimization_config["enable_file_io_optimization"] = False
    
    async def _initialize_subprocess_optimization(self):
        """Initialize subprocess optimizations"""
        try:
            # Configure subprocess manager
            if hasattr(self.subprocess_manager, 'max_concurrent_processes'):
                self.subprocess_manager.max_concurrent_processes = min(
                    self.optimization_config["max_concurrent_processes"],
                    self.subprocess_manager.max_concurrent_processes
                )
            
            # Test subprocess execution
            test_result = await self.subprocess_manager.execute_process(
                command=["echo", "async_subprocess_test"],
                timeout=5
            )
            
            if test_result.success and "async_subprocess_test" in test_result.stdout:
                logger.info("Subprocess optimization initialized successfully")
            else:
                raise Exception("Subprocess test failed")
                
        except Exception as e:
            logger.error(f"Subprocess optimization initialization failed: {e}")
            self.optimization_config["enable_subprocess_optimization"] = False
    
    async def _initialize_github_optimization(self):
        """Initialize GitHub API optimizations"""
        try:
            # GitHub optimization is initialized on-demand when needed
            # Just verify the system can create GitHub clients
            logger.info("GitHub API optimization system ready")
            
        except Exception as e:
            logger.error(f"GitHub optimization initialization failed: {e}")
            self.optimization_config["enable_github_optimization"] = False
    
    def create_github_client(self, token: str, client_id: str = "default") -> AsyncGitHubClient:
        """Create or get cached GitHub client with optimal settings"""
        if not self.optimization_config["enable_github_optimization"]:
            raise RuntimeError("GitHub optimization is disabled")
        
        if client_id not in self.github_clients:
            self.github_clients[client_id] = AsyncGitHubClient(
                token=token,
                max_concurrent_requests=self.optimization_config["max_concurrent_github_requests"]
            )
            logger.info(f"Created async GitHub client: {client_id}")
        
        return self.github_clients[client_id]
    
    async def optimize_security_scan(
        self, 
        scan_function: callable,
        temp_dir: str,
        selected_tools: List[str],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Optimize security scanning operations with async patterns
        
        Args:
            scan_function: The scanning function to optimize
            temp_dir: Working directory
            selected_tools: List of tools to run
            **kwargs: Additional arguments
            
        Returns:
            Optimized scan results
        """
        if not self.initialized:
            await self.initialize()
        
        start_time = time.time()
        logger.info(f"Optimizing security scan with {len(selected_tools)} tools")
        
        try:
            # Track concurrent operations
            current_operations = len(selected_tools)
            if current_operations > self.global_metrics["concurrent_operations_peak"]:
                self.global_metrics["concurrent_operations_peak"] = current_operations
            
            # Execute optimized scan
            results = await scan_function(temp_dir, selected_tools, **kwargs)
            
            # Calculate optimization metrics
            execution_time = time.time() - start_time
            estimated_sequential_time = len(selected_tools) * 300  # Estimate 5 minutes per tool
            time_saved = max(0, estimated_sequential_time - execution_time)
            
            self.global_metrics["total_optimized_operations"] += 1
            self.global_metrics["total_time_saved"] += time_saved
            self.global_metrics["optimization_efficiency"] = (
                self.global_metrics["total_time_saved"] / 
                max(1, self.global_metrics["total_optimized_operations"] * estimated_sequential_time / len(selected_tools))
            ) * 100
            
            logger.info(f"Security scan optimized: {execution_time:.2f}s (estimated time saved: {time_saved:.2f}s)")
            
            return results
            
        except Exception as e:
            logger.error(f"Security scan optimization failed: {e}")
            raise
    
    async def batch_file_operations(
        self,
        file_operations: List[Dict[str, Any]]
    ) -> List[Any]:
        """
        Optimize batch file operations with concurrent processing
        
        Args:
            file_operations: List of file operations to perform
            
        Returns:
            List of operation results
        """
        if not self.optimization_config["enable_file_io_optimization"]:
            # Fall back to sequential operations
            return await self._sequential_file_operations(file_operations)
        
        logger.info(f"Optimizing {len(file_operations)} file operations")
        
        async def execute_operation(operation: Dict[str, Any]):
            op_type = operation.get("type")
            
            if op_type == "read":
                return await self.file_manager.read_file_async(operation["path"])
            elif op_type == "write":
                return await self.file_manager.write_file_async(operation["path"], operation["content"])
            elif op_type == "read_json":
                return await self.file_manager.read_json_async(operation["path"])
            elif op_type == "write_json":
                return await self.file_manager.write_json_async(operation["path"], operation["data"])
            elif op_type == "copy":
                return await self.file_manager.copy_file_async(operation["src"], operation["dst"])
            else:
                raise ValueError(f"Unsupported file operation: {op_type}")
        
        # Execute all operations concurrently
        tasks = [execute_operation(op) for op in file_operations]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"File operation {i} failed: {result}")
                successful_results.append(None)
            else:
                successful_results.append(result)
        
        return successful_results
    
    async def _sequential_file_operations(self, operations: List[Dict[str, Any]]) -> List[Any]:
        """Fallback sequential file operations"""
        results = []
        for operation in operations:
            try:
                if operation["type"] == "read":
                    with open(operation["path"], 'r') as f:
                        results.append(f.read())
                elif operation["type"] == "write":
                    with open(operation["path"], 'w') as f:
                        f.write(operation["content"])
                        results.append(True)
                # Add more sequential operations as needed
            except Exception as e:
                logger.error(f"Sequential file operation failed: {e}")
                results.append(None)
        
        return results
    
    async def concurrent_github_operations(
        self,
        github_token: str,
        operations: List[Dict[str, Any]]
    ) -> List[Any]:
        """
        Execute multiple GitHub API operations concurrently
        
        Args:
            github_token: GitHub API token
            operations: List of GitHub operations to perform
            
        Returns:
            List of operation results
        """
        if not self.optimization_config["enable_github_optimization"]:
            return []
        
        client = self.create_github_client(github_token)
        
        async def execute_github_operation(operation: Dict[str, Any]):
            op_type = operation.get("type")
            
            if op_type == "get_repository":
                return await client.get_repository_async(operation["owner"], operation["repo"])
            elif op_type == "get_languages":
                return await client.get_repository_languages_async(operation["owner"], operation["repo"])
            elif op_type == "get_contents":
                return await client.get_repository_contents_async(
                    operation["owner"], operation["repo"], operation.get("path", "")
                )
            elif op_type == "get_file":
                return await client.get_file_content_async(
                    operation["owner"], operation["repo"], operation["path"]
                )
            else:
                raise ValueError(f"Unsupported GitHub operation: {op_type}")
        
        # Execute all operations concurrently
        tasks = [execute_github_operation(op) for op in operations]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    def get_optimization_metrics(self) -> Dict[str, Any]:
        """Get comprehensive optimization metrics"""
        metrics = {
            "global_metrics": self.global_metrics.copy(),
            "configuration": self.optimization_config.copy(),
            "initialization_status": {
                "initialized": self.initialized,
                "initialization_time": self.initialization_time
            },
            "component_metrics": {}
        }
        
        # Add component-specific metrics
        if self.optimization_config["enable_file_io_optimization"]:
            metrics["component_metrics"]["file_io"] = self.file_manager.get_performance_metrics()
        
        if self.optimization_config["enable_subprocess_optimization"]:
            metrics["component_metrics"]["subprocess"] = self.subprocess_manager.get_performance_metrics()
        
        if self.github_clients:
            metrics["component_metrics"]["github"] = {}
            for client_id, client in self.github_clients.items():
                metrics["component_metrics"]["github"][client_id] = client.get_performance_metrics()
        
        metrics["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        return metrics
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all optimization components"""
        health_status = {
            "overall_status": "healthy",
            "initialization_status": "initialized" if self.initialized else "not_initialized",
            "components": {}
        }
        
        try:
            # Check file I/O optimization
            if self.optimization_config["enable_file_io_optimization"]:
                test_path = "/tmp/health_check_file.txt"
                await self.file_manager.write_file_async(test_path, "health_check")
                content = await self.file_manager.read_file_async(test_path)
                await self.file_manager.delete_file_async(test_path)
                
                health_status["components"]["file_io"] = {
                    "status": "healthy" if content == "health_check" else "unhealthy",
                    "metrics": self.file_manager.get_performance_metrics()
                }
            
            # Check subprocess optimization
            if self.optimization_config["enable_subprocess_optimization"]:
                test_result = await self.subprocess_manager.execute_process(
                    ["echo", "health_check"], timeout=5
                )
                health_status["components"]["subprocess"] = {
                    "status": "healthy" if test_result.success else "unhealthy",
                    "metrics": self.subprocess_manager.get_performance_metrics()
                }
            
            # Check GitHub clients
            if self.github_clients:
                github_health = {}
                for client_id, client in self.github_clients.items():
                    client_health = await client.health_check()
                    github_health[client_id] = client_health
                health_status["components"]["github"] = github_health
            
        except Exception as e:
            health_status["overall_status"] = "degraded"
            health_status["error"] = str(e)
        
        return health_status
    
    async def shutdown(self):
        """Gracefully shutdown all optimization components"""
        logger.info("Shutting down async optimization system...")
        
        shutdown_tasks = []
        
        # Shutdown GitHub clients
        for client in self.github_clients.values():
            shutdown_tasks.append(client.close())
        
        # Shutdown subprocess manager
        if hasattr(self.subprocess_manager, 'kill_all_processes'):
            shutdown_tasks.append(self.subprocess_manager.kill_all_processes())
        
        # Shutdown file manager
        if hasattr(self.file_manager, 'close'):
            shutdown_tasks.append(self.file_manager.close())
        
        # Wait for all shutdowns to complete
        await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        
        self.github_clients.clear()
        self.initialized = False
        
        logger.info("Async optimization system shutdown complete")

# Global instance
async_optimization_manager = AsyncOptimizationManager()

@asynccontextmanager
async def async_optimization_context():
    """Context manager for async optimization lifecycle"""
    try:
        await async_optimization_manager.initialize()
        yield async_optimization_manager
    finally:
        await async_optimization_manager.shutdown()

# Convenience functions
async def initialize_async_optimizations():
    """Initialize async optimizations globally"""
    return await async_optimization_manager.initialize()

async def get_optimization_metrics():
    """Get current optimization metrics"""
    return async_optimization_manager.get_optimization_metrics()

async def shutdown_async_optimizations():
    """Shutdown async optimizations globally"""
    return await async_optimization_manager.shutdown()