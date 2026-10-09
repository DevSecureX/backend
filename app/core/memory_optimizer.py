"""
Memory optimization utilities for DevSecureX
Helps manage memory usage on resource-constrained environments like Render starter plans
"""
import os
import gc
import psutil
import logging
from typing import Optional, Dict, Any
from functools import wraps
import asyncio

logger = logging.getLogger(__name__)

class MemoryOptimizer:
    """Memory optimization utilities"""
    
    def __init__(self):
        self.memory_optimized = os.getenv("MEMORY_OPTIMIZED", "false").lower() == "true"
        self.process = psutil.Process()
        logger.info(f"Memory optimizer initialized (optimized: {self.memory_optimized})")
    
    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage stats"""
        try:
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            return {
                "rss_mb": memory_info.rss / 1024 / 1024,  # Resident memory in MB
                "vms_mb": memory_info.vms / 1024 / 1024,  # Virtual memory in MB
                "percent": memory_percent,
                "available_mb": psutil.virtual_memory().available / 1024 / 1024
            }
        except Exception as e:
            logger.warning(f"Failed to get memory usage: {e}")
            return {"error": str(e)}
    
    def check_memory_threshold(self, threshold_percent: float = 80.0) -> bool:
        """Check if memory usage is above threshold"""
        try:
            usage = self.get_memory_usage()
            if "percent" in usage:
                return usage["percent"] > threshold_percent
            return False
        except Exception:
            return False
    
    def force_garbage_collection(self):
        """Force garbage collection to free memory"""
        try:
            collected = gc.collect()
            logger.debug(f"Garbage collection freed {collected} objects")
            return collected
        except Exception as e:
            logger.warning(f"Garbage collection failed: {e}")
            return 0
    
    def is_memory_optimized(self) -> bool:
        """Check if running in memory-optimized mode"""
        return self.memory_optimized
    
    def get_recommended_workers(self) -> int:
        """Get recommended number of workers based on available memory"""
        try:
            if self.memory_optimized:
                return 0  # No background workers in memory-optimized mode
            
            usage = self.get_memory_usage()
            available_mb = usage.get("available_mb", 0)
            
            if available_mb > 1000:  # > 1GB available
                return 2
            elif available_mb > 500:  # > 500MB available
                return 1
            else:
                return 0  # Not enough memory for workers
                
        except Exception:
            return 0 if self.memory_optimized else 1

# Global memory optimizer instance
memory_optimizer = MemoryOptimizer()

def memory_efficient(threshold_percent: float = 80.0):
    """Decorator to make functions memory-efficient"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                # Check memory before execution
                if memory_optimizer.check_memory_threshold(threshold_percent):
                    logger.warning("High memory usage detected, forcing garbage collection")
                    memory_optimizer.force_garbage_collection()
                
                # Execute function
                result = await func(*args, **kwargs)
                
                # Clean up after execution if in memory-optimized mode
                if memory_optimizer.is_memory_optimized():
                    memory_optimizer.force_garbage_collection()
                
                return result
                
            except Exception as e:
                logger.error(f"Memory-efficient execution failed: {e}")
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                # Check memory before execution
                if memory_optimizer.check_memory_threshold(threshold_percent):
                    logger.warning("High memory usage detected, forcing garbage collection")
                    memory_optimizer.force_garbage_collection()
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Clean up after execution if in memory-optimized mode
                if memory_optimizer.is_memory_optimized():
                    memory_optimizer.force_garbage_collection()
                
                return result
                
            except Exception as e:
                logger.error(f"Memory-efficient execution failed: {e}")
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator

def log_memory_usage(operation: str):
    """Log current memory usage for an operation"""
    try:
        usage = memory_optimizer.get_memory_usage()
        logger.info(f"Memory usage for {operation}: "
                   f"{usage.get('rss_mb', 0):.1f}MB RSS, "
                   f"{usage.get('percent', 0):.1f}% of system")
    except Exception as e:
        logger.warning(f"Failed to log memory usage for {operation}: {e}")

async def memory_health_check() -> Dict[str, Any]:
    """Get memory health status"""
    try:
        usage = memory_optimizer.get_memory_usage()
        is_optimized = memory_optimizer.is_memory_optimized()
        recommended_workers = memory_optimizer.get_recommended_workers()
        
        status = "healthy" if usage.get("percent", 100) < 80 else "warning"
        if usage.get("percent", 100) > 90:
            status = "critical"
        
        return {
            "status": status,
            "memory_usage": usage,
            "memory_optimized": is_optimized,
            "recommended_workers": recommended_workers,
            "gc_enabled": gc.isenabled(),
            "thresholds": {
                "warning": 80,
                "critical": 90
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

# Memory monitoring middleware
class MemoryMonitoringMiddleware:
    """Middleware to monitor memory usage per request"""
    
    def __init__(self, app):
        self.app = app
        self.request_count = 0
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            self.request_count += 1
            
            # Log memory usage every 100 requests
            if self.request_count % 100 == 0:
                log_memory_usage(f"request #{self.request_count}")
                
                # Force GC if memory usage is high
                if memory_optimizer.check_memory_threshold(85.0):
                    logger.warning("High memory usage detected, forcing garbage collection")
                    memory_optimizer.force_garbage_collection()
        
        await self.app(scope, receive, send)

# CRITICAL FIX: Worker restart logic for memory/job limits
def should_restart_worker(worker_id: str, jobs_processed: int = 0, uptime_seconds: float = 0, 
                         memory_mb: float = 0) -> bool:
    """
    CRITICAL FIX: Determine if worker should restart based on limits
    Prevents memory accumulation and job overload from killing workers
    """
    # Job limit: 50 jobs per worker
    if jobs_processed >= 50:
        logger.info(f"Worker {worker_id} reached job limit ({jobs_processed} >= 50)")
        return True
    
    # Time limit: 5 minutes (300 seconds)  
    if uptime_seconds >= 300:
        logger.info(f"Worker {worker_id} reached time limit ({uptime_seconds} >= 300s)")
        return True
    
    # Memory limit: 80% of threshold
    memory_threshold = float(os.getenv("MEMORY_THRESHOLD_MB", "1024"))
    if memory_mb > memory_threshold * 0.8:
        logger.info(f"Worker {worker_id} reached memory limit ({memory_mb}MB >= {memory_threshold * 0.8}MB)")
        return True
    
    return False

async def cleanup_memory():
    """
    CRITICAL FIX: Aggressive memory cleanup
    Forces garbage collection and clears caches
    """
    try:
        # Force garbage collection
        collected = memory_optimizer.force_garbage_collection()
        
        # Clear any global caches if available
        try:
            # Clear asyncio debug traces
            import asyncio
            if hasattr(asyncio, '_current_task'):
                asyncio._current_task.clear()
        except Exception:
            pass
        
        logger.info(f"Memory cleanup completed: {collected} objects collected")
        return collected
        
    except Exception as e:
        logger.warning(f"Memory cleanup failed: {e}")
        return 0

def get_memory_stats() -> Dict[str, Any]:
    """
    CRITICAL FIX: Get comprehensive memory statistics
    Used by worker health monitoring
    """
    stats = memory_optimizer.get_memory_usage()
    
    # Add garbage collection stats
    try:
        import gc
        stats.update({
            "gc_counts": gc.get_count(),
            "gc_thresholds": gc.get_threshold(),
            "gc_stats": gc.get_stats()
        })
    except Exception:
        pass
    
    return stats