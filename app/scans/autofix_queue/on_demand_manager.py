#!/usr/bin/env python3
"""
On-Demand Autofix Worker Manager

This module provides on-demand initialization and management of autofix workers
to improve resource efficiency and prevent startup loops.

Key Features:
- On-demand worker startup when autofix functionality is requested
- Automatic worker shutdown after idle timeout to save resources
- Support for both enterprise and legacy worker systems
- Thread-safe operation with async locks
- Comprehensive status and health monitoring
- Timeout protection for startup operations
"""

import asyncio
import logging
import os
import time
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
from core.utils import utc_now, utc_now_iso

logger = logging.getLogger(__name__)


class OnDemandAutofixManager:
    """
    Manager for on-demand autofix worker lifecycle
    
    This class handles the lifecycle of autofix workers, starting them on-demand
    when autofix functionality is requested and automatically stopping them
    after an idle timeout period.
    """
    
    def __init__(self):
        # Configuration from environment variables
        self.enabled = os.getenv("ENABLE_AUTOFIX_WORKERS", "true").lower() == "true"
        self.use_enterprise_workers = os.getenv("USE_ENTERPRISE_WORKERS", "true").lower() == "true"
        self.idle_timeout = int(os.getenv("AUTOFIX_WORKER_IDLE_TIMEOUT", "1800"))  # 30 minutes default
        self.startup_timeout = int(os.getenv("AUTOFIX_WORKER_STARTUP_TIMEOUT", "60"))  # 60 seconds default
        
        # State tracking
        self.workers_active = False
        self.workers_starting = False
        self.last_activity = None
        self.startup_error = None
        
        # Async locks for thread safety
        self._startup_lock = asyncio.Lock()
        self._shutdown_lock = asyncio.Lock()
        
        # Worker system references
        self._worker_manager = None
        self._enterprise_manager = None
        
        logger.info(f"OnDemandAutofixManager initialized - enabled: {self.enabled}, "
                   f"enterprise: {self.use_enterprise_workers}, idle_timeout: {self.idle_timeout}s")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the autofix worker system
        
        Returns:
            Dict containing status information
        """
        if not self.enabled:
            return {
                "status": "disabled",
                "enabled": False,
                "message": "Autofix workers are disabled via configuration"
            }
        
        if self.workers_starting:
            return {
                "status": "starting",
                "enabled": True,
                "workers_active": False,
                "message": "Autofix workers are starting up"
            }
        
        if self.workers_active:
            idle_time = (utc_now() - self.last_activity).total_seconds() if self.last_activity else 0
            return {
                "status": "active",
                "enabled": True,
                "workers_active": True,
                "idle_time_seconds": idle_time,
                "message": f"Autofix workers are active (idle: {int(idle_time)}s)"
            }
        
        if self.startup_error:
            return {
                "status": "error",
                "enabled": True,
                "workers_active": False,
                "error": self.startup_error,
                "message": f"Autofix workers failed to start: {self.startup_error}"
            }
        
        return {
            "status": "on_demand_ready",
            "enabled": True,
            "workers_active": False,
            "message": "Autofix workers are ready to start on-demand"
        }
    
    async def get_health(self) -> Dict[str, Any]:
        """
        Get comprehensive health status of autofix workers
        
        Returns:
            Dict containing health information
        """
        base_health = {
            "timestamp": utc_now_iso(),
            "enabled": self.enabled,
            "workers_active": self.workers_active,
            "use_enterprise_workers": self.use_enterprise_workers
        }
        
        if not self.enabled:
            return {
                **base_health,
                "status": "disabled",
                "message": "Autofix workers disabled via configuration"
            }
        
        if not self.workers_active:
            return {
                **base_health,
                "status": "idle" if not self.startup_error else "error",
                "message": "Autofix workers not active" if not self.startup_error else f"Startup error: {self.startup_error}",
                "error": self.startup_error
            }
        
        try:
            # Get health from active worker system
            if self.use_enterprise_workers and self._enterprise_manager:
                worker_health = await self._enterprise_manager.get_health_status()
                return {
                    **base_health,
                    "status": "active",
                    "worker_type": "enterprise",
                    "worker_health": worker_health
                }
            elif self._worker_manager:
                worker_health = await self._worker_manager.get_health_status()
                return {
                    **base_health,
                    "status": "active",
                    "worker_type": "legacy",
                    "worker_health": worker_health
                }
            else:
                return {
                    **base_health,
                    "status": "error",
                    "message": "No worker manager available despite active status"
                }
                
        except Exception as e:
            logger.error(f"Error getting worker health: {e}")
            return {
                **base_health,
                "status": "error",
                "message": f"Health check failed: {str(e)}"
            }
    
    async def ensure_workers_available(self, context: str = "general") -> bool:
        """
        Ensure autofix workers are available, starting them if necessary
        
        Args:
            context: Context string for logging purposes
            
        Returns:
            bool: True if workers are available, False otherwise
        """
        if not self.enabled:
            logger.info(f"Autofix workers disabled for context: {context}")
            return False
        
        # If workers are already active, just update activity and return
        if self.workers_active:
            self.last_activity = utc_now()
            logger.debug(f"Autofix workers already active for context: {context}")
            return True
        
        # If workers are starting, wait a bit for them to become available
        if self.workers_starting:
            logger.info(f"Autofix workers are starting, waiting for availability (context: {context})")
            # Wait up to 5 seconds for workers to start
            for _ in range(10):
                await asyncio.sleep(0.5)
                if self.workers_active:
                    self.last_activity = utc_now()
                    return True
            # If still starting after 5 seconds, consider it available anyway
            # Workers will activate in background
            logger.info(f"Workers still starting, proceeding anyway for context: {context}")
            return True
        
        # Start workers if not active
        async with self._startup_lock:
            # Double-check after acquiring lock
            if self.workers_active:
                self.last_activity = utc_now()
                return True
            
            if self.workers_starting:
                # Another task is starting workers
                return True
            
            logger.info(f"Starting autofix workers on-demand for context: {context}")
            
            # CRITICAL FIX: Actually wait for workers to start for critical contexts
            # For autofix job processing, we need workers to be ready immediately
            if (context in ["autofix_job", "api_request", "job_processing", "manual_start"] or 
                context.startswith("autofix_job_")):
                logger.info(f"Critical context detected ({context}), waiting for workers to start...")
                self.workers_starting = True
                success = await self._start_workers()
                return success
            else:
                # For non-critical contexts, start in background
                self.workers_starting = True
                asyncio.create_task(self._start_workers_background(context))
                return True
    
    async def _start_workers_background(self, context: str):
        """
        Start workers in background without blocking the API response
        
        Args:
            context: Context string for logging purposes
        """
        try:
            logger.info(f"Starting autofix workers in background for context: {context}")
            await self._start_workers()
            logger.info(f"Background worker initialization completed for context: {context}")
        except Exception as e:
            logger.error(f"Background worker initialization failed for context: {context}, error: {e}")
    
    async def _start_workers(self) -> bool:
        """
        Internal method to start autofix workers
        
        Returns:
            bool: True if workers started successfully, False otherwise
        """
        self.workers_starting = True
        self.startup_error = None
        
        try:
            # Create timeout for startup operation
            startup_task = asyncio.create_task(self._do_start_workers())
            
            try:
                success = await asyncio.wait_for(startup_task, timeout=self.startup_timeout)
                
                if success:
                    self.workers_active = True
                    self.last_activity = utc_now()
                    logger.info("Autofix workers started successfully")
                    
                    # Start idle monitoring
                    asyncio.create_task(self._monitor_idle_timeout())
                    return True
                else:
                    self.startup_error = "Worker startup failed"
                    logger.error("Autofix workers failed to start")
                    return False
                    
            except asyncio.TimeoutError:
                self.startup_error = f"Worker startup timed out after {self.startup_timeout}s"
                logger.error(self.startup_error)
                startup_task.cancel()
                return False
                
        except Exception as e:
            self.startup_error = f"Worker startup error: {str(e)}"
            logger.error(f"Error starting autofix workers: {e}", exc_info=True)
            return False
        finally:
            self.workers_starting = False
    
    async def _do_start_workers(self) -> bool:
        """
        Perform the actual worker startup
        
        Returns:
            bool: True if workers started successfully, False otherwise
        """
        try:
            if self.use_enterprise_workers:
                # Use enterprise autofix worker manager
                try:
                    from scans.autofix_queue.enterprise_autofix_worker_manager import get_enterprise_autofix_worker_manager
                    
                    logger.info("Starting enterprise autofix workers...")
                    self._enterprise_manager = await get_enterprise_autofix_worker_manager()
                    
                    # Manager created successfully, workers will be available shortly
                    logger.info(f"Enterprise autofix manager initialized successfully")
                    return True
                    
                except ImportError as e:
                    logger.error(f"Enterprise autofix system not available: {e}")
                    return False
            else:
                # Use legacy autofix worker manager
                try:
                    from scans.autofix_queue.worker_manager import get_worker_manager
                    
                    logger.info("Starting legacy autofix workers...")
                    self._worker_manager = get_worker_manager()
                    await self._worker_manager.start_workers()
                    
                    # CRITICAL FIX: Wait for workers to become active with retry logic
                    max_wait_time = 30  # 30 seconds for legacy workers (faster startup)
                    check_interval = 0.5  # Check every 500ms
                    waited_time = 0
                    
                    while waited_time < max_wait_time:
                        status = self._worker_manager.get_worker_status()
                        if status.get('manager_running') and len(status.get('workers', {})) > 0:
                            active_workers = len(status.get('workers', {}))
                            logger.info(f"Legacy autofix workers started successfully: {active_workers} workers (waited {waited_time:.1f}s)")
                            return True
                        
                        await asyncio.sleep(check_interval)
                        waited_time += check_interval
                    
                    # Final check with detailed logging
                    status = self._worker_manager.get_worker_status()
                    logger.error(f"Legacy autofix workers failed to start: manager_running={status.get('manager_running')}, workers={len(status.get('workers', {}))}")
                    return False
                    
                except ImportError as e:
                    logger.error(f"Legacy autofix system not available: {e}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error in worker startup: {e}", exc_info=True)
            return False
    
    async def stop_workers_if_idle(self, context: str = "manual") -> bool:
        """
        Stop autofix workers if they are idle
        
        Args:
            context: Context string for logging purposes
            
        Returns:
            bool: True if workers were stopped, False otherwise
        """
        if not self.workers_active:
            logger.debug(f"Autofix workers not active, nothing to stop for context: {context}")
            return False
        
        async with self._shutdown_lock:
            # Double-check after acquiring lock
            if not self.workers_active:
                return False
            
            logger.info(f"Stopping autofix workers for context: {context}")
            return await self._stop_workers()
    
    async def _stop_workers(self) -> bool:
        """
        Internal method to stop autofix workers
        
        Returns:
            bool: True if workers stopped successfully, False otherwise
        """
        try:
            if self._enterprise_manager:
                # Stop enterprise workers
                try:
                    from scans.autofix_queue.enterprise_autofix_worker_manager import shutdown_enterprise_autofix_worker_manager
                    await shutdown_enterprise_autofix_worker_manager()
                    logger.info("Enterprise autofix workers stopped")
                except Exception as e:
                    logger.error(f"Error stopping enterprise autofix workers: {e}")
                    return False
                finally:
                    self._enterprise_manager = None
            
            if self._worker_manager:
                # Stop legacy workers
                try:
                    await self._worker_manager.stop_workers()
                    logger.info("Legacy autofix workers stopped")
                except Exception as e:
                    logger.error(f"Error stopping legacy autofix workers: {e}")
                    return False
                finally:
                    self._worker_manager = None
            
            self.workers_active = False
            self.last_activity = None
            return True
            
        except Exception as e:
            logger.error(f"Error stopping autofix workers: {e}", exc_info=True)
            return False
    
    async def _monitor_idle_timeout(self):
        """
        Monitor worker idle timeout and stop workers if idle too long
        """
        try:
            while self.workers_active:
                await asyncio.sleep(60)  # Check every minute
                
                if not self.workers_active:
                    break
                
                if self.last_activity:
                    idle_time = (utc_now() - self.last_activity).total_seconds()
                    
                    if idle_time >= self.idle_timeout:
                        logger.info(f"Autofix workers idle for {int(idle_time)}s, stopping due to timeout ({self.idle_timeout}s)")
                        await self.stop_workers_if_idle("idle_timeout")
                        break
                        
        except Exception as e:
            logger.error(f"Error in idle timeout monitoring: {e}")


# Global manager instance
_on_demand_manager: Optional[OnDemandAutofixManager] = None


def get_on_demand_autofix_manager() -> OnDemandAutofixManager:
    """
    Get the global on-demand autofix manager instance
    
    Returns:
        OnDemandAutofixManager: The global instance
    """
    global _on_demand_manager
    if _on_demand_manager is None:
        _on_demand_manager = OnDemandAutofixManager()
    return _on_demand_manager


# Convenience functions for API endpoints
def get_autofix_workers_status() -> Dict[str, Any]:
    """
    Get current status of autofix workers
    
    Returns:
        Dict containing status information
    """
    manager = get_on_demand_autofix_manager()
    return manager.get_status()


async def get_autofix_workers_health() -> Dict[str, Any]:
    """
    Get comprehensive health status of autofix workers
    
    Returns:
        Dict containing health information
    """
    manager = get_on_demand_autofix_manager()
    return await manager.get_health()


async def ensure_autofix_workers_available(context: str = "api_request") -> bool:
    """
    Ensure autofix workers are available, starting them if necessary
    
    Args:
        context: Context string for logging purposes
        
    Returns:
        bool: True if workers are available, False otherwise
    """
    manager = get_on_demand_autofix_manager()
    return await manager.ensure_workers_available(context)


async def stop_autofix_workers_if_idle(context: str = "manual") -> bool:
    """
    Stop autofix workers if they are idle
    
    Args:
        context: Context string for logging purposes
        
    Returns:
        bool: True if workers were stopped, False otherwise
    """
    manager = get_on_demand_autofix_manager()
    return await manager.stop_workers_if_idle(context)


async def restart_autofix_workers(context: str = "manual") -> bool:
    """
    Restart autofix workers
    
    Args:
        context: Context string for logging purposes
        
    Returns:
        bool: True if workers were restarted successfully, False otherwise
    """
    manager = get_on_demand_autofix_manager()
    
    # Stop current workers
    await manager.stop_workers_if_idle(f"restart_{context}")
    
    # Wait a moment for cleanup
    await asyncio.sleep(1)
    
    # Start new workers
    return await manager.ensure_workers_available(f"restart_{context}")