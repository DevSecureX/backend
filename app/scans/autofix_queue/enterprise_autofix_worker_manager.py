"""
Enterprise Autofix Worker Management System
Auto-scaling workers that consume from the enterprise autofix queue with load balancing and health monitoring.
Applies the same enterprise patterns as the main scanning system to autofix processing.
"""

import asyncio
import logging
import os
import time
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import psutil
from dataclasses import dataclass

from .enterprise_autofix_queue import get_enterprise_autofix_queue_manager, QueuedAutofix, AutofixStatus
from .autofix_worker import AutofixWorker

logger = logging.getLogger(__name__)


@dataclass
class AutofixWorkerStats:
    """Autofix worker performance statistics"""
    worker_id: str
    started_at: datetime
    autofixes_processed: int = 0
    autofixes_failed: int = 0
    average_processing_time: float = 0.0
    current_autofix: Optional[str] = None
    last_activity: Optional[datetime] = None
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    status: str = "idle"  # idle, busy, error, shutdown


class EnterpriseAutofixWorker:
    """Individual worker that processes autofixes from the enterprise queue"""
    
    def __init__(self, worker_id: str, max_concurrent_autofixes: int = 2):
        self.worker_id = worker_id
        self.max_concurrent_autofixes = max_concurrent_autofixes
        
        # Use existing autofix worker logic but wrap it with enterprise features
        self.base_worker = AutofixWorker(worker_id)
        
        # Worker state
        self.active_autofixes: Dict[str, QueuedAutofix] = {}
        self.is_running = False
        self.shutdown_requested = False
        self.active = False  # CRITICAL FIX: Add missing active property for compatibility
        
        # Statistics
        self.stats = AutofixWorkerStats(
            worker_id=worker_id,
            started_at=datetime.now(timezone.utc)
        )
        
        # PHASE 2 OPTIMIZATION: Extended health check interval for Redis cost reduction
        self.last_health_check = time.time()
        raw_health_interval = int(os.getenv("AUTOFIX_WORKER_HEALTH_INTERVAL", "300"))
        self.health_check_interval = max(300, raw_health_interval)  # 5 minutes minimum (was 1 minute)
        
        if raw_health_interval < 300:
            logger.warning(f"Autofix worker health interval increased from {raw_health_interval}s to {self.health_check_interval}s for Redis cost optimization")
        
        logger.info(f"Enterprise Autofix Worker {worker_id} initialized")
    
    async def start(self):
        """Start the autofix worker"""
        self.is_running = True
        self.stats.status = "idle"
        
        logger.info(f"Enterprise Autofix Worker {self.worker_id} starting...")
        
        # Start worker loops in background but don't wait for them
        tasks = [
            asyncio.create_task(self._autofix_processing_loop()),
            asyncio.create_task(self._health_monitoring_loop())
        ]
        
        # CRITICAL FIX: Ensure tasks actually start before marking active
        # Wait a moment for tasks to begin their execution
        await asyncio.sleep(0.1)  # Allow tasks to initialize
        
        # Verify tasks are actually running
        running_tasks = [task for task in tasks if not task.done()]
        if len(running_tasks) != len(tasks):
            failed_tasks = [task for task in tasks if task.done()]
            logger.error(f"Enterprise Autofix Worker {self.worker_id} - {len(failed_tasks)} tasks failed to start")
            for task in failed_tasks:
                if task.exception():
                    logger.error(f"Task failed with exception: {task.exception()}")
            self.active = False
            raise RuntimeError(f"Worker {self.worker_id} failed to start all tasks")
        
        self.active = True  # Mark worker as active when tasks are actually running
        
        logger.info(f"Enterprise Autofix Worker {self.worker_id} started successfully with {len(running_tasks)} active tasks")
        
        # Store tasks for cleanup later but don't await them here
        self._running_tasks = tasks
        
        # Return immediately to allow the manager to detect the worker as active
        # The tasks will run in the background
        return
        
    async def _wait_for_completion(self):
        """Wait for worker tasks to complete (called during shutdown)"""
        if hasattr(self, '_running_tasks'):
            try:
                await asyncio.gather(*self._running_tasks, return_exceptions=True)
            except Exception as e:
                logger.error(f"Enterprise Autofix Worker {self.worker_id} task error: {e}")
    
    async def shutdown(self):
        """Gracefully shutdown the autofix worker"""
        logger.info(f"Shutting down Enterprise Autofix Worker {self.worker_id}")
        
        self.shutdown_requested = True
        self.active = False  # CRITICAL FIX: Mark worker as inactive when shutting down
        self.stats.status = "shutdown"
        
        # Cancel running tasks if they exist
        if hasattr(self, '_running_tasks'):
            for task in self._running_tasks:
                if not task.done():
                    task.cancel()
        
        # Wait for active autofixes to complete (with longer timeout than scans)
        if self.active_autofixes:
            logger.info(f"Autofix Worker {self.worker_id}: Waiting for {len(self.active_autofixes)} active autofixes to complete...")
            
            timeout = 600  # 10 minutes (longer than scans)
            start_time = time.time()
            
            while self.active_autofixes and (time.time() - start_time) < timeout:
                await asyncio.sleep(10)
            
            # Force complete remaining autofixes
            for autofix_id in list(self.active_autofixes.keys()):
                logger.warning(f"Force completing autofix {autofix_id} due to worker shutdown")
                queue_manager = await get_enterprise_autofix_queue_manager()
                await queue_manager.complete_autofix(
                    autofix_id, 
                    success=False, 
                    error="Autofix worker shutdown during processing"
                )
        
        self.is_running = False
        logger.info(f"Enterprise Autofix Worker {self.worker_id} shut down")
    
    async def _autofix_processing_loop(self):
        """Main loop for processing autofixes from the queue"""
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        while self.is_running and not self.shutdown_requested:
            try:
                # Check if worker can handle more autofixes
                if len(self.active_autofixes) >= self.max_concurrent_autofixes:
                    await asyncio.sleep(15)  # Longer wait than scans
                    continue
                
                # Get next autofix from queue
                autofix = await queue_manager.get_next_autofix(self.worker_id)
                
                if autofix:
                    logger.info(f"Autofix Worker {self.worker_id} received autofix: {autofix.autofix_id}")
                    
                    # Process autofix in background
                    task = asyncio.create_task(self._process_autofix(autofix))
                    self.active_autofixes[autofix.autofix_id] = autofix
                    self.stats.current_autofix = autofix.autofix_id
                    self.stats.status = "busy"
                    
                    # Don't await here to allow parallel processing
                else:
                    # No autofixes available, wait before checking again
                    self.stats.status = "idle"
                    self.stats.current_autofix = None
                    
                    # CRITICAL FIX: Use fast polling for autofix job processing
                    # Autofix jobs need to be processed quickly, so use short intervals
                    raw_poll_interval = float(os.getenv("AUTOFIX_WORKER_POLL_INTERVAL", "5"))
                    min_poll_interval = 2  # Minimum 2 seconds for responsive autofix job processing  
                    max_poll_interval = 30  # Maximum 30 seconds to prevent delays
                    safe_poll_interval = max(min_poll_interval, min(raw_poll_interval, max_poll_interval))
                    
                    if raw_poll_interval > max_poll_interval:
                        logger.warning(f"AUTOFIX WORKER: Poll interval clamped from {raw_poll_interval}s to {safe_poll_interval}s for responsive job processing")
                    
                    logger.debug(f"Autofix worker {self.worker_id} polling queue every {safe_poll_interval}s")
                    await asyncio.sleep(safe_poll_interval)  # Use responsive polling interval
                
            except Exception as e:
                logger.error(f"Error in autofix worker {self.worker_id} processing loop: {e}")
                await asyncio.sleep(60)  # Back off on errors
    
    async def _process_autofix(self, autofix: QueuedAutofix):
        """Process a single autofix"""
        start_time = time.time()
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        try:
            logger.info(f"Autofix Worker {self.worker_id} starting autofix: {autofix.autofix_id}")
            
            # Convert enterprise autofix to format expected by base worker
            job_data = {
                "id": autofix.autofix_id,
                "scan_id": autofix.scan_id,
                "user_id": autofix.user_id,
                "repo_full_name": autofix.repo_full_name,
                "autofix_data": autofix.autofix_config,
                "status": autofix.status.value
            }
            
            # Use the existing autofix worker to process the job
            await self.base_worker._process_autofix_job(job_data)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Update statistics
            self.stats.autofixes_processed += 1
            self._update_average_processing_time(processing_time)
            
            # Complete autofix in queue
            await queue_manager.complete_autofix(
                autofix.autofix_id,
                success=True,
                result={"processing_time": processing_time, "worker_id": self.worker_id}
            )
            
            logger.info(
                f"Autofix Worker {self.worker_id} completed autofix {autofix.autofix_id} "
                f"in {processing_time:.2f}s: success"
            )
            
        except Exception as e:
            logger.error(f"Autofix Worker {self.worker_id} failed to process autofix {autofix.autofix_id}: {e}")
            
            # Update failure statistics
            self.stats.autofixes_failed += 1
            processing_time = time.time() - start_time
            
            # Complete autofix with error
            await queue_manager.complete_autofix(
                autofix.autofix_id,
                success=False,
                error=str(e)
            )
        
        finally:
            # Clean up
            if autofix.autofix_id in self.active_autofixes:
                del self.active_autofixes[autofix.autofix_id]
            
            # Update worker status
            if not self.active_autofixes:
                self.stats.status = "idle"
                self.stats.current_autofix = None
            
            self.stats.last_activity = datetime.now(timezone.utc)
    
    async def _health_monitoring_loop(self):
        """Monitor autofix worker health and update statistics"""
        while self.is_running and not self.shutdown_requested:
            try:
                # Update CPU and memory usage
                process = psutil.Process()
                self.stats.cpu_usage = process.cpu_percent()
                self.stats.memory_usage = process.memory_info().rss / (1024 * 1024)  # MB
                
                self.last_health_check = time.time()
                
                await asyncio.sleep(self.health_check_interval)
                
            except Exception as e:
                logger.error(f"Error in autofix worker {self.worker_id} health monitoring: {e}")
                await asyncio.sleep(60)
    
    def _update_average_processing_time(self, new_time: float):
        """Update average processing time using exponential smoothing"""
        if self.stats.average_processing_time == 0:
            self.stats.average_processing_time = new_time
        else:
            alpha = 0.1  # Smoothing factor
            self.stats.average_processing_time = (
                alpha * new_time + (1 - alpha) * self.stats.average_processing_time
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get autofix worker statistics"""
        return {
            "worker_id": self.worker_id,
            "status": self.stats.status,
            "uptime_seconds": (datetime.now(timezone.utc) - self.stats.started_at).total_seconds(),
            "autofixes_processed": self.stats.autofixes_processed,
            "autofixes_failed": self.stats.autofixes_failed,
            "success_rate": (
                self.stats.autofixes_processed / max(1, self.stats.autofixes_processed + self.stats.autofixes_failed)
            ) * 100,
            "active_autofixes": len(self.active_autofixes),
            "current_autofix": self.stats.current_autofix,
            "average_processing_time": self.stats.average_processing_time,
            "cpu_usage_percent": self.stats.cpu_usage,
            "memory_usage_mb": self.stats.memory_usage,
            "last_activity": self.stats.last_activity.isoformat() if self.stats.last_activity else None
        }


class EnterpriseAutofixWorkerManager:
    """Manages multiple autofix workers with auto-scaling capabilities"""
    
    def __init__(self):
        self.workers: Dict[str, EnterpriseAutofixWorker] = {}
        self.worker_tasks: Dict[str, asyncio.Task] = {}
        
        # PHASE 2 OPTIMIZATION: Extended intervals for Redis cost reduction
        self.min_workers = int(os.getenv("MIN_AUTOFIX_WORKERS", "1"))
        self.max_workers = int(os.getenv("MAX_AUTOFIX_WORKERS", "5"))
        self.target_cpu_usage = 75.0  # More conservative than scans
        raw_scaling_interval = int(os.getenv("AUTOFIX_SCALING_CHECK_INTERVAL", "300"))
        self.scaling_check_interval = max(300, raw_scaling_interval)  # 5 minutes minimum (was 3 minutes)
        
        if raw_scaling_interval < 300:
            logger.warning(f"Autofix scaling interval increased from {raw_scaling_interval}s to {self.scaling_check_interval}s for Redis cost optimization")
        
        # Auto-scaling state
        self.last_scaling_decision = time.time()
        self.scaling_cooldown = 600  # 10 minutes (longer than scans)
        
        self.is_running = False
        self.scaling_task: Optional[asyncio.Task] = None
        
        logger.info(f"Enterprise Autofix Worker Manager initialized: {self.min_workers}-{self.max_workers} workers")
    
    async def start(self):
        """Start the autofix worker manager"""
        self.is_running = True
        
        # Start initial workers with explicit wait
        logger.info(f"Starting {self.min_workers} initial autofix workers...")
        await self._scale_workers(self.min_workers)
        
        # CRITICAL FIX: Verify workers actually started before continuing
        logger.warning(f"MANAGER START: About to call get_worker_count(), total workers: {len(self.workers)}")
        active_count = self.get_worker_count()
        logger.warning(f"MANAGER START: get_worker_count() returned {active_count}, min_workers: {self.min_workers}")
        
        if active_count < self.min_workers:
            logger.warning(f"MANAGER START: Only {active_count}/{self.min_workers} autofix workers became active")
        else:
            logger.info(f"Successfully started {active_count} autofix workers")
        
        # Start auto-scaling monitoring
        self.scaling_task = asyncio.create_task(self._auto_scaling_loop())
        
        logger.info("Enterprise Autofix Worker Manager started")
    
    async def stop(self):
        """Stop all autofix workers gracefully"""
        logger.info("Stopping Enterprise Autofix Worker Manager...")
        
        self.is_running = False
        
        # Cancel auto-scaling
        if self.scaling_task:
            self.scaling_task.cancel()
        
        # Stop all workers
        stop_tasks = []
        for worker in self.workers.values():
            stop_tasks.append(asyncio.create_task(worker.shutdown()))
        
        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)
        
        # Cancel worker tasks
        for task in self.worker_tasks.values():
            task.cancel()
        
        self.workers.clear()
        self.worker_tasks.clear()
        
        logger.info("Enterprise Autofix Worker Manager stopped")
    
    async def _scale_workers(self, target_count: int):
        """Scale autofix workers to target count"""
        current_count = len(self.workers)
        
        if target_count == current_count:
            return
        
        if target_count > current_count:
            # Scale up
            for i in range(target_count - current_count):
                await self._add_worker()
        else:
            # Scale down
            workers_to_remove = list(self.workers.keys())[target_count:]
            for worker_id in workers_to_remove:
                await self._remove_worker(worker_id)
        
        logger.info(f"Scaled autofix workers from {current_count} to {len(self.workers)}")
    
    async def _add_worker(self) -> str:
        """Add a new autofix worker"""
        worker_id = f"autofix-worker-{uuid.uuid4().hex[:8]}"
        
        # Create worker
        worker = EnterpriseAutofixWorker(worker_id)
        self.workers[worker_id] = worker
        
        # Start worker (now returns immediately after setting active=True)
        await worker.start()
        
        # Create a task to handle worker lifecycle management
        # This task will handle the worker tasks and cleanup
        task = asyncio.create_task(self._manage_worker_lifecycle(worker))
        self.worker_tasks[worker_id] = task
        
        # CRITICAL FIX: Worker should now be active immediately
        if worker.active:
            logger.info(f"Added autofix worker: {worker_id} (active immediately)")
        else:
            logger.error(f"Autofix worker {worker_id} failed to become active")
            # Clean up failed worker
            await self._remove_worker(worker_id)
            raise RuntimeError(f"Worker {worker_id} failed to activate")
        
        return worker_id
    
    async def _manage_worker_lifecycle(self, worker: 'EnterpriseAutofixWorker'):
        """Manage the lifecycle of a worker's background tasks"""
        try:
            # Wait for the worker's background tasks to complete
            if hasattr(worker, '_running_tasks'):
                await asyncio.gather(*worker._running_tasks, return_exceptions=True)
        except asyncio.CancelledError:
            logger.info(f"Worker {worker.worker_id} lifecycle task cancelled")
        except Exception as e:
            logger.error(f"Worker {worker.worker_id} lifecycle error: {e}")
        finally:
            # Ensure worker is properly shut down
            if worker.active:
                await worker.shutdown()
    
    async def _remove_worker(self, worker_id: str):
        """Remove an autofix worker gracefully"""
        if worker_id not in self.workers:
            return
        
        worker = self.workers[worker_id]
        task = self.worker_tasks.get(worker_id)
        
        # Shutdown worker
        await worker.shutdown()
        
        # Cancel task
        if task:
            task.cancel()
            del self.worker_tasks[worker_id]
        
        del self.workers[worker_id]
        
        logger.info(f"Removed autofix worker: {worker_id}")
    
    async def _auto_scaling_loop(self):
        """Auto-scaling based on autofix queue size and system resources"""
        while self.is_running:
            try:
                await asyncio.sleep(self.scaling_check_interval)
                
                # Check if we're in cooldown period
                if time.time() - self.last_scaling_decision < self.scaling_cooldown:
                    continue
                
                # Get current metrics
                queue_manager = await get_enterprise_autofix_queue_manager()
                stats = await queue_manager.get_queue_statistics()
                system_health = stats["system_health"]
                
                # Calculate scaling decision
                new_worker_count = await self._calculate_optimal_worker_count(stats, system_health)
                
                if new_worker_count != len(self.workers):
                    logger.info(
                        f"Autofix Auto-scaling: {len(self.workers)} -> {new_worker_count} workers "
                        f"(Queue: {stats['total_queued']}, CPU: {system_health['cpu']['current']:.1f}%)"
                    )
                    
                    await self._scale_workers(new_worker_count)
                    self.last_scaling_decision = time.time()
                
            except Exception as e:
                logger.error(f"Error in autofix auto-scaling loop: {e}")
                await asyncio.sleep(180)
    
    async def _calculate_optimal_worker_count(
        self, 
        queue_stats: Dict[str, Any], 
        system_health: Dict[str, Any]
    ) -> int:
        """Calculate optimal number of autofix workers based on current conditions"""
        
        current_workers = len(self.workers)
        total_queued = queue_stats["total_queued"]
        active_autofixes = queue_stats["active_autofixes"]
        
        # Resource-based scaling (more conservative than scans)
        cpu_usage = system_health.get("cpu", {}).get("current", 0)
        memory_healthy = system_health.get("memory", {}).get("healthy", True)
        
        # Scale up conditions (more conservative)
        if total_queued > current_workers * 3:  # More than 3 autofixes per worker queued
            if cpu_usage < self.target_cpu_usage and memory_healthy:
                return min(self.max_workers, current_workers + 1)
        
        # Scale down conditions
        elif total_queued == 0 and active_autofixes < current_workers * 0.3:
            if current_workers > self.min_workers:
                return max(self.min_workers, current_workers - 1)
        
        # High CPU usage - scale down more aggressively
        elif cpu_usage > 80:  # Lower threshold than scans
            return max(self.min_workers, current_workers - 1)
        
        return current_workers
    
    def get_worker_count(self) -> int:
        """
        CRITICAL FIX: Get the current count of active workers
        This method is required by the on-demand manager for worker availability checking
        """
        active_workers = [worker for worker in self.workers.values() if worker.active]
        total_workers = len(self.workers.values())
        
        # CRITICAL DEBUG: Log detailed worker status every time this is called
        worker_details = []
        for worker_id, worker in self.workers.items():
            worker_details.append(f"{worker_id}(active={worker.active},running={worker.is_running})")
        
        logger.warning(f"get_worker_count() called: {len(active_workers)}/{total_workers} active - Details: {', '.join(worker_details)}")
        
        return len(active_workers)
    
    def get_worker_statistics(self) -> Dict[str, Any]:
        """Get statistics for all autofix workers"""
        worker_stats = []
        
        for worker in self.workers.values():
            worker_stats.append(worker.get_stats())
        
        # Calculate aggregate statistics
        total_processed = sum(stats["autofixes_processed"] for stats in worker_stats)
        total_failed = sum(stats["autofixes_failed"] for stats in worker_stats)
        total_active = sum(stats["active_autofixes"] for stats in worker_stats)
        
        return {
            "total_workers": len(self.workers),
            "worker_details": worker_stats,
            "aggregate_stats": {
                "total_autofixes_processed": total_processed,
                "total_autofixes_failed": total_failed,
                "total_active_autofixes": total_active,
                "overall_success_rate": (
                    total_processed / max(1, total_processed + total_failed)
                ) * 100 if (total_processed + total_failed) > 0 else 100,
                "average_processing_time": (
                    sum(stats["average_processing_time"] for stats in worker_stats) / len(worker_stats)
                ) if worker_stats else 0
            },
            "scaling_info": {
                "min_workers": self.min_workers,
                "max_workers": self.max_workers,
                "last_scaling_decision": self.last_scaling_decision,
                "scaling_cooldown_remaining": max(0, self.scaling_cooldown - (time.time() - self.last_scaling_decision))
            }
        }
    
    # COMPATIBILITY METHODS FOR ROUTES.PY
    # These methods provide compatibility with the basic autofix worker manager interface
    
    def get_worker_status(self) -> Dict[str, Any]:
        """
        Compatibility method for routes.py - get worker status
        """
        try:
            # CRITICAL FIX: Add manager_running flag for compatibility
            return {
                "manager_running": self.is_running and len(self.workers) > 0,
                "num_workers": len(self.workers),
                "active_workers": sum(1 for worker in self.workers.values() if worker.active),
                "total_processed": sum(worker.stats.autofixes_processed for worker in self.workers.values()),
                "total_failed": sum(worker.stats.autofixes_failed for worker in self.workers.values()),
                "average_processing_time": sum(worker.stats.average_processing_time for worker in self.workers.values()) / len(self.workers) if self.workers else 0.0,
                "workers": {
                    worker_id: {
                        "id": worker_id,
                        "active": worker.active,
                        "processed": worker.stats.autofixes_processed,
                        "failed": worker.stats.autofixes_failed,
                        "avg_time": worker.stats.average_processing_time,
                        "started_at": worker.stats.started_at.isoformat()
                    }
                    for worker_id, worker in self.workers.items()
                }
            }
        except Exception as e:
            logger.error(f"Error getting worker status: {e}")
            return {
                "manager_running": False,
                "num_workers": 0,
                "active_workers": 0,
                "total_processed": 0,
                "total_failed": 0,
                "average_processing_time": 0.0,
                "workers": {}
            }
    
    async def get_health_status(self) -> Dict[str, Any]:
        """
        Compatibility method for routes.py - get health status
        """
        try:
            # Get system health
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Calculate worker health
            healthy_workers = sum(1 for worker in self.workers.values() if worker.active)
            total_workers = len(self.workers)
            
            return {
                "system": {
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "disk_percent": disk.percent,
                    "healthy": cpu_percent < 80 and memory.percent < 80 and disk.percent < 90
                },
                "workers": {
                    "total": total_workers,
                    "healthy": healthy_workers,
                    "health_ratio": healthy_workers / total_workers if total_workers > 0 else 1.0,
                    "healthy": healthy_workers == total_workers and total_workers > 0
                },
                "overall_healthy": (
                    cpu_percent < 80 and 
                    memory.percent < 80 and 
                    healthy_workers == total_workers and 
                    total_workers > 0
                )
            }
        except Exception as e:
            logger.error(f"Error getting health status: {e}")
            return {
                "system": {"healthy": False, "error": str(e)},
                "workers": {"healthy": False, "error": str(e)},
                "overall_healthy": False
            }
    
    async def restart_workers(self):
        """
        Compatibility method for routes.py - restart workers
        """
        logger.info("Restarting all autofix workers")
        
        # Stop all workers
        await self.stop()
        
        # Wait a moment
        await asyncio.sleep(2)
        
        # Start workers again
        await self.start()
        
        logger.info(f"Successfully restarted {len(self.workers)} autofix workers")
    
    async def scale_workers(self, worker_count: int):
        """
        Compatibility method for routes.py - scale workers to specific count
        """
        logger.info(f"Scaling autofix workers to {worker_count}")
        
        # Use the internal scaling method
        await self._scale_workers(worker_count)
        
        logger.info(f"Successfully scaled to {len(self.workers)} autofix workers")


# Global instance
_enterprise_autofix_worker_manager: Optional[EnterpriseAutofixWorkerManager] = None


async def get_enterprise_autofix_worker_manager() -> EnterpriseAutofixWorkerManager:
    """Get or create the global enterprise autofix worker manager"""
    global _enterprise_autofix_worker_manager
    
    logger.debug("get_enterprise_autofix_worker_manager() called")
    
    if _enterprise_autofix_worker_manager is None:
        logger.debug("Creating new enterprise autofix worker manager")
        _enterprise_autofix_worker_manager = EnterpriseAutofixWorkerManager()
        logger.debug("About to call _enterprise_autofix_worker_manager.start()")
        await _enterprise_autofix_worker_manager.start()
        logger.debug("_enterprise_autofix_worker_manager.start() completed")
    else:
        logger.debug("Reusing existing enterprise autofix worker manager")
    
    # Check worker count before returning
    worker_count = _enterprise_autofix_worker_manager.get_worker_count()
    logger.debug(f"Returning manager with {worker_count} active workers")
    
    return _enterprise_autofix_worker_manager


async def shutdown_enterprise_autofix_worker_manager():
    """Shutdown the global enterprise autofix worker manager"""
    global _enterprise_autofix_worker_manager
    
    if _enterprise_autofix_worker_manager:
        await _enterprise_autofix_worker_manager.stop()
        _enterprise_autofix_worker_manager = None