"""
Memory Management and Resource Cleanup for Production Workers
CRITICAL FIX: Prevents memory leaks and ensures workers run indefinitely
"""

import gc
import logging
import asyncio
import psutil
import os
import time
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class MemoryStats:
    """Memory usage statistics"""
    rss_mb: float  # Resident Set Size
    vms_mb: float  # Virtual Memory Size
    percent: float  # Memory percentage
    available_mb: float  # Available system memory
    swap_mb: float  # Swap usage
    gc_collections: Dict[int, int]  # Garbage collection stats


class MemoryManager:
    """
    CRITICAL FIX: Production-grade memory management for worker processes
    Prevents memory leaks and ensures workers can run indefinitely
    """
    
    def __init__(self, process_name: str = "unknown"):
        self.process_name = process_name
        self.process = psutil.Process(os.getpid())
        
        # Memory thresholds (configurable via environment)
        self.warning_threshold_mb = float(os.getenv("MEMORY_WARNING_THRESHOLD_MB", "1024"))  # 1GB
        self.critical_threshold_mb = float(os.getenv("MEMORY_CRITICAL_THRESHOLD_MB", "2048"))  # 2GB
        self.cleanup_threshold_mb = float(os.getenv("MEMORY_CLEANUP_THRESHOLD_MB", "1536"))  # 1.5GB
        
        # Cleanup intervals
        self.gc_interval = float(os.getenv("GC_INTERVAL_SECONDS", "300"))  # 5 minutes
        self.memory_check_interval = float(os.getenv("MEMORY_CHECK_INTERVAL", "60"))  # 1 minute
        self.deep_cleanup_interval = float(os.getenv("DEEP_CLEANUP_INTERVAL", "1800"))  # 30 minutes
        
        # State tracking
        self.last_gc_time = time.time()
        self.last_memory_check = time.time()
        self.last_deep_cleanup = time.time()
        self.cleanup_callbacks: List[Callable] = []
        self.memory_history: List[MemoryStats] = []
        self.max_history_size = 100
        
        # Control flags
        self.monitoring_active = False
        self.monitoring_task: Optional[asyncio.Task] = None
        
        logger.info(f"Memory manager initialized for {process_name} "
                   f"(warning: {self.warning_threshold_mb}MB, "
                   f"critical: {self.critical_threshold_mb}MB)")
    
    def add_cleanup_callback(self, callback: Callable):
        """Add a cleanup callback to be called during memory cleanup"""
        self.cleanup_callbacks.append(callback)
        logger.debug(f"Added cleanup callback for {self.process_name}")
    
    async def start_monitoring(self):
        """Start memory monitoring"""
        if self.monitoring_active:
            logger.warning(f"Memory monitoring already active for {self.process_name}")
            return
        
        self.monitoring_active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info(f"Started memory monitoring for {self.process_name}")
    
    async def stop_monitoring(self):
        """Stop memory monitoring"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info(f"Stopped memory monitoring for {self.process_name}")
    
    async def _monitoring_loop(self):
        """Main memory monitoring loop"""
        while self.monitoring_active:
            try:
                current_time = time.time()
                
                # Regular memory check
                if current_time - self.last_memory_check >= self.memory_check_interval:
                    await self._check_memory()
                    self.last_memory_check = current_time
                
                # Periodic garbage collection
                if current_time - self.last_gc_time >= self.gc_interval:
                    await self._periodic_gc()
                    self.last_gc_time = current_time
                
                # Deep cleanup
                if current_time - self.last_deep_cleanup >= self.deep_cleanup_interval:
                    await self._deep_cleanup()
                    self.last_deep_cleanup = current_time
                
                # Sleep before next check
                await asyncio.sleep(min(self.memory_check_interval, 30))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in memory monitoring loop for {self.process_name}: {e}")
                await asyncio.sleep(60)  # Back off on error
    
    async def _check_memory(self):
        """Check current memory usage and take action if needed"""
        try:
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            
            # Get system memory info
            system_memory = psutil.virtual_memory()
            swap_info = psutil.swap_memory()
            
            # Get garbage collection stats
            gc_stats = {i: gc.get_count()[i] for i in range(3)}
            
            current_stats = MemoryStats(
                rss_mb=memory_info.rss / 1024 / 1024,
                vms_mb=memory_info.vms / 1024 / 1024,
                percent=memory_percent,
                available_mb=system_memory.available / 1024 / 1024,
                swap_mb=swap_info.used / 1024 / 1024,
                gc_collections=gc_stats
            )
            
            # Store in history
            self.memory_history.append(current_stats)
            if len(self.memory_history) > self.max_history_size:
                self.memory_history.pop(0)
            
            # Check thresholds and take action
            if current_stats.rss_mb >= self.critical_threshold_mb:
                logger.error(f"CRITICAL: Memory usage {current_stats.rss_mb:.1f}MB exceeds critical threshold "
                           f"{self.critical_threshold_mb}MB for {self.process_name}")
                await self._emergency_cleanup()
                
            elif current_stats.rss_mb >= self.cleanup_threshold_mb:
                logger.warning(f"High memory usage {current_stats.rss_mb:.1f}MB for {self.process_name}, "
                             f"triggering cleanup")
                await self._memory_cleanup()
                
            elif current_stats.rss_mb >= self.warning_threshold_mb:
                logger.warning(f"Memory usage {current_stats.rss_mb:.1f}MB approaching threshold "
                             f"for {self.process_name}")
            
            # Log stats periodically
            if len(self.memory_history) % 10 == 0:
                logger.info(f"Memory stats for {self.process_name}: "
                          f"RSS={current_stats.rss_mb:.1f}MB, "
                          f"VMS={current_stats.vms_mb:.1f}MB, "
                          f"Percent={current_stats.percent:.1f}%, "
                          f"Available={current_stats.available_mb:.1f}MB")
                
        except Exception as e:
            logger.error(f"Error checking memory for {self.process_name}: {e}")
    
    async def _periodic_gc(self):
        """Perform periodic garbage collection"""
        try:
            # Get pre-GC stats
            pre_stats = {i: gc.get_count()[i] for i in range(3)}
            pre_memory = self.process.memory_info().rss / 1024 / 1024
            
            # Force garbage collection
            collected = []
            for generation in range(3):
                collected.append(gc.collect(generation))
            
            # Get post-GC stats
            post_memory = self.process.memory_info().rss / 1024 / 1024
            memory_freed = pre_memory - post_memory
            
            logger.debug(f"Garbage collection for {self.process_name}: "
                        f"freed {memory_freed:.1f}MB, "
                        f"collected {collected}")
            
            # Log significant memory reductions
            if memory_freed > 50:  # More than 50MB freed
                logger.info(f"Significant memory freed by GC for {self.process_name}: {memory_freed:.1f}MB")
                
        except Exception as e:
            logger.error(f"Error during garbage collection for {self.process_name}: {e}")
    
    async def _memory_cleanup(self):
        """Perform memory cleanup using registered callbacks"""
        try:
            logger.info(f"Starting memory cleanup for {self.process_name}")
            
            # Run cleanup callbacks
            for callback in self.cleanup_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback()
                    else:
                        # Run sync callbacks in thread pool
                        await asyncio.get_event_loop().run_in_executor(None, callback)
                except Exception as e:
                    logger.error(f"Error in cleanup callback for {self.process_name}: {e}")
            
            # Force garbage collection
            await self._periodic_gc()
            
            logger.info(f"Memory cleanup completed for {self.process_name}")
            
        except Exception as e:
            logger.error(f"Error during memory cleanup for {self.process_name}: {e}")
    
    async def _deep_cleanup(self):
        """Perform deep cleanup including cache clearing and connection cleanup"""
        try:
            logger.info(f"Starting deep cleanup for {self.process_name}")
            
            # Run regular cleanup first
            await self._memory_cleanup()
            
            # Clear various caches that might be holding memory
            try:
                # Clear SQLAlchemy session registry if available
                from sqlalchemy.orm import sessionmaker
                sessionmaker.registry.clear()
            except ImportError:
                pass
            except Exception as e:
                logger.debug(f"SQLAlchemy cleanup failed: {e}")
            
            try:
                # Clear Redis connection pools if available
                from core.redis import close_redis_client
                await close_redis_client()
            except Exception as e:
                logger.debug(f"Redis cleanup failed: {e}")
            
            # Force multiple generations of garbage collection
            for _ in range(3):
                for generation in range(3):
                    gc.collect(generation)
                await asyncio.sleep(0.1)
            
            logger.info(f"Deep cleanup completed for {self.process_name}")
            
        except Exception as e:
            logger.error(f"Error during deep cleanup for {self.process_name}: {e}")
    
    async def _emergency_cleanup(self):
        """Emergency cleanup when memory usage is critical"""
        try:
            logger.error(f"EMERGENCY: Starting emergency cleanup for {self.process_name}")
            
            # Run deep cleanup immediately
            await self._deep_cleanup()
            
            # Additional emergency measures
            try:
                # Clear import caches
                import sys
                if hasattr(sys, '_clear_type_cache'):
                    sys._clear_type_cache()
            except Exception as e:
                logger.debug(f"Import cache cleanup failed: {e}")
            
            # Multiple aggressive GC cycles
            for _ in range(5):
                for generation in range(3):
                    gc.collect(generation)
                await asyncio.sleep(0.1)
            
            # Check if emergency cleanup helped
            post_memory = self.process.memory_info().rss / 1024 / 1024
            if post_memory >= self.critical_threshold_mb:
                logger.error(f"EMERGENCY: Memory usage still critical after cleanup: {post_memory:.1f}MB")
                # Could trigger worker restart here if needed
            else:
                logger.info(f"Emergency cleanup successful, memory reduced to {post_memory:.1f}MB")
            
        except Exception as e:
            logger.error(f"Error during emergency cleanup for {self.process_name}: {e}")
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get current memory statistics"""
        try:
            memory_info = self.process.memory_info()
            memory_percent = self.process.memory_percent()
            system_memory = psutil.virtual_memory()
            gc_stats = {i: gc.get_count()[i] for i in range(3)}
            
            return {
                "process_name": self.process_name,
                "rss_mb": memory_info.rss / 1024 / 1024,
                "vms_mb": memory_info.vms / 1024 / 1024,
                "percent": memory_percent,
                "system_available_mb": system_memory.available / 1024 / 1024,
                "system_percent": system_memory.percent,
                "gc_collections": gc_stats,
                "thresholds": {
                    "warning_mb": self.warning_threshold_mb,
                    "cleanup_mb": self.cleanup_threshold_mb,
                    "critical_mb": self.critical_threshold_mb
                },
                "monitoring_active": self.monitoring_active,
                "history_size": len(self.memory_history)
            }
        except Exception as e:
            logger.error(f"Error getting memory stats for {self.process_name}: {e}")
            return {"error": str(e)}
    
    def get_memory_trend(self) -> Dict[str, Any]:
        """Get memory usage trend analysis"""
        if len(self.memory_history) < 2:
            return {"status": "insufficient_data"}
        
        try:
            recent_stats = self.memory_history[-10:]  # Last 10 measurements
            
            # Calculate trend
            memory_values = [stat.rss_mb for stat in recent_stats]
            if len(memory_values) >= 2:
                trend = memory_values[-1] - memory_values[0]
                avg_memory = sum(memory_values) / len(memory_values)
                max_memory = max(memory_values)
                min_memory = min(memory_values)
                
                return {
                    "trend_mb": trend,
                    "average_mb": avg_memory,
                    "max_mb": max_memory,
                    "min_mb": min_memory,
                    "measurements": len(memory_values),
                    "trend_direction": "increasing" if trend > 10 else "decreasing" if trend < -10 else "stable"
                }
            else:
                return {"status": "insufficient_data"}
                
        except Exception as e:
            logger.error(f"Error calculating memory trend: {e}")
            return {"error": str(e)}


# Global memory managers for different worker types
_memory_managers: Dict[str, MemoryManager] = {}


def get_memory_manager(process_name: str) -> MemoryManager:
    """Get or create a memory manager for a specific process"""
    if process_name not in _memory_managers:
        _memory_managers[process_name] = MemoryManager(process_name)
    return _memory_managers[process_name]


async def start_memory_monitoring(process_name: str):
    """Start memory monitoring for a process"""
    manager = get_memory_manager(process_name)
    await manager.start_monitoring()


async def stop_memory_monitoring(process_name: str):
    """Stop memory monitoring for a process"""
    if process_name in _memory_managers:
        await _memory_managers[process_name].stop_monitoring()


def cleanup_all_memory_managers():
    """Clean up all memory managers"""
    for manager in _memory_managers.values():
        if manager.monitoring_active:
            # Can't await in sync function, so just log
            logger.warning(f"Memory manager for {manager.process_name} still active during cleanup")
    _memory_managers.clear()


# Decorators for automatic memory management
def memory_managed(process_name: str):
    """Decorator to add automatic memory management to a function"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            manager = get_memory_manager(process_name)
            await manager.start_monitoring()
            try:
                return await func(*args, **kwargs)
            finally:
                await manager.stop_monitoring()
        return wrapper
    return decorator


# Utility functions
async def force_cleanup(process_name: str = "current"):
    """Force memory cleanup for a specific process"""
    if process_name == "current":
        process_name = f"pid_{os.getpid()}"
    
    manager = get_memory_manager(process_name)
    await manager._memory_cleanup()


async def emergency_cleanup(process_name: str = "current"):
    """Force emergency memory cleanup"""
    if process_name == "current":
        process_name = f"pid_{os.getpid()}"
    
    manager = get_memory_manager(process_name)
    await manager._emergency_cleanup()


def get_system_memory_info() -> Dict[str, Any]:
    """Get system-wide memory information"""
    try:
        virtual_memory = psutil.virtual_memory()
        swap_memory = psutil.swap_memory()
        
        return {
            "virtual": {
                "total_gb": virtual_memory.total / 1024 / 1024 / 1024,
                "available_gb": virtual_memory.available / 1024 / 1024 / 1024,
                "percent": virtual_memory.percent,
                "used_gb": virtual_memory.used / 1024 / 1024 / 1024
            },
            "swap": {
                "total_gb": swap_memory.total / 1024 / 1024 / 1024,
                "used_gb": swap_memory.used / 1024 / 1024 / 1024,
                "percent": swap_memory.percent
            }
        }
    except Exception as e:
        logger.error(f"Error getting system memory info: {e}")
        return {"error": str(e)}