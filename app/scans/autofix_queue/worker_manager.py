import asyncio
import logging
import os
import time
from typing import Dict, List, Optional
from datetime import datetime

from core.utils import utc_now, utc_now_iso
from core.circuit_breaker import get_circuit_breaker, CircuitBreakerConfig, CircuitBreakerOpenError
from .autofix_worker import AutofixWorker

logger = logging.getLogger(__name__)

class AutofixWorkerManager:
    """Manager for auto-fix workers"""
    
    def __init__(self, num_workers: int = None):
        # Default to 2 workers in production, 1 in development
        if num_workers is None:
            self.num_workers = int(os.getenv("AUTOFIX_WORKERS", "2" if os.getenv("APP_ENV") == "production" else "1"))
        else:
            self.num_workers = num_workers
            
        self.workers: Dict[str, AutofixWorker] = {}
        self.worker_tasks: Dict[str, asyncio.Task] = {}
        self.running = False
        self._start_time = None
        
        logger.info(f"AutofixWorkerManager initialized with {self.num_workers} workers")
    
    async def start_workers(self):
        """Start all auto-fix workers"""
        
        if self.running:
            logger.warning("Workers already running")
            return
        
        self.running = True
        self._start_time = utc_now()
        
        logger.info(f"Starting {self.num_workers} auto-fix workers")
        
        for i in range(self.num_workers):
            worker_id = f"autofix-worker-{i+1}"
            worker = AutofixWorker(worker_id)
            
            # Start worker task
            task = asyncio.create_task(worker.start())
            
            self.workers[worker_id] = worker
            self.worker_tasks[worker_id] = task
            
            logger.info(f"Started auto-fix worker: {worker_id}")
        
        # Monitor workers
        asyncio.create_task(self._monitor_workers())
        
        logger.info("All auto-fix workers started successfully")
    
    async def stop_workers(self):
        """Stop all auto-fix workers gracefully"""
        
        if not self.running:
            return
        
        logger.info("Stopping auto-fix workers...")
        self.running = False
        
        # Stop all workers
        stop_tasks = []
        for worker_id, worker in self.workers.items():
            logger.info(f"Stopping worker: {worker_id}")
            stop_tasks.append(worker.stop())
        
        # Wait for all workers to stop
        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)
        
        # Cancel any remaining tasks
        for worker_id, task in self.worker_tasks.items():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                logger.info(f"Cancelled worker task: {worker_id}")
        
        self.workers.clear()
        self.worker_tasks.clear()
        
        logger.info("All auto-fix workers stopped")
    
    async def restart_workers(self):
        """Restart all workers"""
        logger.info("Restarting auto-fix workers...")
        await self.stop_workers()
        await asyncio.sleep(2)  # Give time for cleanup
        await self.start_workers()
    
    async def _monitor_workers(self):
        """Monitor worker health and restart if needed with circuit breaker protection"""
        
        # Create circuit breaker for monitoring operations
        circuit_breaker = get_circuit_breaker(
            "autofix_worker_monitoring",
            config=CircuitBreakerConfig(
                failure_threshold=5,
                success_threshold=3,
                timeout=60.0,
                max_timeout=300.0
            )
        )
        
        consecutive_failures = 0
        max_consecutive_failures = 10
        max_runtime = 24 * 60 * 60  # 24 hours max runtime
        start_time = time.time()
        
        try:
            while self.running:
                try:
                    # Check runtime limit
                    if time.time() - start_time > max_runtime:
                        logger.warning("AutofixWorkerManager monitoring reached max runtime, stopping")
                        break
                    
                    async with circuit_breaker:
                        # Check worker health every 30 seconds
                        await asyncio.sleep(30)
                        
                        if not self.running:
                            break
                        
                        # Check for failed workers
                        failed_workers = []
                        for worker_id, task in self.worker_tasks.items():
                            if task.done():
                                exception = task.exception()
                                if exception:
                                    logger.error(f"Worker {worker_id} failed: {exception}")
                                    failed_workers.append(worker_id)
                                else:
                                    logger.warning(f"Worker {worker_id} completed unexpectedly")
                                    failed_workers.append(worker_id)
                        
                        # Restart failed workers
                        for worker_id in failed_workers:
                            await self._restart_worker(worker_id)
                            
                        consecutive_failures = 0  # Reset on success
                
                except asyncio.CancelledError:
                    logger.info("Worker monitoring cancelled")
                    break
                    
                except CircuitBreakerOpenError as e:
                    logger.warning(f"Monitoring circuit breaker open: {e}")
                    consecutive_failures += 1
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error("Max consecutive monitoring failures reached, stopping")
                        break
                    
                    # Wait when circuit is open
                    await asyncio.sleep(60)
                    
                except Exception as e:
                    logger.error(f"Error in worker monitoring: {e}")
                    consecutive_failures += 1
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error("Max consecutive monitoring failures reached, stopping")
                        break
                        
                    # Exponential backoff on failures
                    backoff_delay = min(30 * (2 ** min(consecutive_failures - 1, 4)), 300)
                    await asyncio.sleep(backoff_delay)
                    
        except Exception as e:
            logger.error(f"Fatal error in worker monitoring: {e}", exc_info=True)
        finally:
            logger.info("Worker monitoring stopped")
    
    async def _restart_worker(self, worker_id: str):
        """Restart a specific worker"""
        
        logger.info(f"Restarting failed worker: {worker_id}")
        
        try:
            # Stop the old worker
            old_worker = self.workers.get(worker_id)
            if old_worker:
                await old_worker.stop()
            
            old_task = self.worker_tasks.get(worker_id)
            if old_task and not old_task.done():
                old_task.cancel()
                try:
                    await old_task
                except asyncio.CancelledError:
                    pass
            
            # Start new worker
            new_worker = AutofixWorker(worker_id)
            new_task = asyncio.create_task(new_worker.start())
            
            self.workers[worker_id] = new_worker
            self.worker_tasks[worker_id] = new_task
            
            logger.info(f"Successfully restarted worker: {worker_id}")
            
        except Exception as e:
            logger.error(f"Failed to restart worker {worker_id}: {e}")
    
    def get_worker_status(self) -> Dict[str, any]:
        """Get status of all workers"""
        
        worker_statuses = {}
        
        for worker_id, worker in self.workers.items():
            task = self.worker_tasks.get(worker_id)
            
            status = {
                "worker_id": worker_id,
                "running": worker.running,
                "task_done": task.done() if task else True,
                "task_exception": str(task.exception()) if task and task.done() and task.exception() else None,
                "stats": worker.get_worker_stats()
            }
            
            worker_statuses[worker_id] = status
        
        return {
            "manager_running": self.running,
            "num_workers": self.num_workers,
            "workers": worker_statuses,
            "uptime_seconds": (utc_now() - self._start_time).total_seconds() if self._start_time else 0
        }
    
    async def get_health_status(self) -> Dict[str, any]:
        """Get comprehensive health status"""
        
        try:
            from .manager import AutofixQueueManager
            queue_manager = AutofixQueueManager()
            queue_stats = await queue_manager.get_queue_stats()
        except Exception as e:
            queue_stats = {"error": str(e)}
        
        worker_health = []
        healthy_workers = 0
        
        for worker_id, worker in self.workers.items():
            try:
                health = await worker.health_check()
                worker_health.append(health)
                if health.get("status") == "healthy":
                    healthy_workers += 1
            except Exception as e:
                worker_health.append({
                    "worker_id": worker_id,
                    "status": "error",
                    "error": str(e)
                })
        
        overall_health = "healthy" if healthy_workers == len(self.workers) and self.running else "degraded"
        if healthy_workers == 0:
            overall_health = "unhealthy"
        
        return {
            "overall_status": overall_health,
            "manager_running": self.running,
            "healthy_workers": healthy_workers,
            "total_workers": len(self.workers),
            "worker_health": worker_health,
            "queue_stats": queue_stats,
            "timestamp": utc_now_iso()
        }
    
    async def scale_workers(self, new_count: int):
        """Scale the number of workers"""
        
        if new_count < 1:
            raise ValueError("Worker count must be at least 1")
        
        if new_count > 10:  # Safety limit
            raise ValueError("Worker count cannot exceed 10")
        
        current_count = len(self.workers)
        
        if new_count == current_count:
            logger.info(f"Worker count already at {new_count}")
            return
        
        if new_count > current_count:
            # Scale up
            logger.info(f"Scaling up from {current_count} to {new_count} workers")
            
            for i in range(current_count, new_count):
                worker_id = f"autofix-worker-{i+1}"
                worker = AutofixWorker(worker_id)
                task = asyncio.create_task(worker.start())
                
                self.workers[worker_id] = worker
                self.worker_tasks[worker_id] = task
                
                logger.info(f"Added worker: {worker_id}")
        
        else:
            # Scale down
            logger.info(f"Scaling down from {current_count} to {new_count} workers")
            
            # Stop excess workers
            workers_to_stop = list(self.workers.keys())[new_count:]
            
            for worker_id in workers_to_stop:
                worker = self.workers[worker_id]
                task = self.worker_tasks[worker_id]
                
                await worker.stop()
                
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                
                del self.workers[worker_id]
                del self.worker_tasks[worker_id]
                
                logger.info(f"Removed worker: {worker_id}")
        
        self.num_workers = new_count
        logger.info(f"Successfully scaled to {new_count} workers")

# Global worker manager instance
_worker_manager: Optional[AutofixWorkerManager] = None

def get_worker_manager() -> AutofixWorkerManager:
    """Get the global worker manager instance"""
    global _worker_manager
    if _worker_manager is None:
        _worker_manager = AutofixWorkerManager()
    return _worker_manager

async def start_autofix_workers():
    """Start the auto-fix workers"""
    manager = get_worker_manager()
    await manager.start_workers()

async def stop_autofix_workers():
    """Stop the auto-fix workers"""
    manager = get_worker_manager()
    await manager.stop_workers()