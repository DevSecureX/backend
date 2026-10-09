import asyncio
import logging
import os
import time
from typing import Dict, List
from contextlib import asynccontextmanager

from .scan_worker import ScanWorker

logger = logging.getLogger(__name__)

class WorkerManager:
    def __init__(self, num_workers: int = None, openai_api_key: str = None):
        # Check if workers are enabled
        self.enable_workers = os.getenv("ENABLE_BACKGROUND_WORKERS", "false").lower() == "true"
        
        if self.enable_workers:
            self.num_workers = num_workers or int(os.getenv("SCAN_WORKERS", "2"))
            logger.info(f"WorkerManager initialized with {self.num_workers} workers (ENABLE_BACKGROUND_WORKERS=true)")
        else:
            self.num_workers = 0
            logger.info("WorkerManager initialized with 0 workers (ENABLE_BACKGROUND_WORKERS=false)")
        
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.workers: Dict[str, ScanWorker] = {}
        self.worker_tasks: Dict[str, asyncio.Task] = {}
        self.running = False
        self.health_monitor_task = None
        self.health_check_interval = 60  # Check worker health every 60 seconds
        
    async def start(self):
        """Start all workers based on ENABLE_BACKGROUND_WORKERS setting"""
        if not self.enable_workers:
            logger.info("Worker startup skipped (ENABLE_BACKGROUND_WORKERS=false)")
            return
        
        if self.running:
            logger.warning("Worker manager already running")
            return
        
        if self.num_workers == 0:
            logger.info("No workers configured to start")
            return
        
        self.running = True
        logger.info(f"Starting {self.num_workers} scan workers")
        
        # CRITICAL FIX: Create and start workers with proper state validation
        for i in range(self.num_workers):
            worker_id = f"worker-{i+1}"
            worker = ScanWorker(worker_id, self.openai_api_key)
            self.workers[worker_id] = worker
            
            # Start worker in background task with proper error handling
            task = asyncio.create_task(self._start_worker_with_validation(worker, worker_id))
            self.worker_tasks[worker_id] = task
            
            logger.info(f"Initiating startup for worker {worker_id}")
        
        # CRITICAL FIX: Wait for all workers to reach active state
        await self._wait_for_workers_ready()
    
    async def _start_worker_with_validation(self, worker: ScanWorker, worker_id: str):
        """CRITICAL FIX: Start worker with proper validation and error handling"""
        try:
            await worker.start()
        except Exception as e:
            logger.error(f"Worker {worker_id} failed to start: {e}")
            # Mark worker as failed
            try:
                await worker.stop()
            except:
                pass
            raise
    
    async def _wait_for_workers_ready(self):
        """CRITICAL FIX: Wait for all workers to reach active state before continuing"""
        max_wait_time = 60.0  # 60 seconds max wait
        check_interval = 1.0
        start_time = asyncio.get_event_loop().time()
        
        while True:
            current_time = asyncio.get_event_loop().time()
            if current_time - start_time > max_wait_time:
                logger.error(f"Timeout waiting for workers to become active after {max_wait_time}s")
                break
            
            # Check worker states
            active_workers = 0
            failed_workers = 0
            
            for worker_id, worker in self.workers.items():
                try:
                    state = await worker.get_worker_state()
                    if state == "active":
                        active_workers += 1
                    elif state in ["failed", "stopped"]:
                        failed_workers += 1
                        logger.error(f"Worker {worker_id} is in failed state: {state}")
                except Exception as e:
                    logger.error(f"Failed to get state for worker {worker_id}: {e}")
                    failed_workers += 1
            
            # Check if all workers are ready
            if active_workers == len(self.workers):
                logger.info(f"✅ All {active_workers} workers are now ACTIVE and ready to process jobs")
                break
            elif failed_workers > 0:
                logger.warning(f"⚠️  {failed_workers} workers failed to start, {active_workers} active, continuing...")
                break
            
            # Wait before next check
            await asyncio.sleep(check_interval)
        
        logger.info(f"Worker manager startup complete: {active_workers} active, {failed_workers} failed")
        
        # Start health monitoring
        self.health_monitor_task = asyncio.create_task(self._health_monitor_loop())
        logger.info("Started worker health monitoring")
    
    async def stop(self):
        """Stop all workers gracefully with enhanced Redis connection cleanup"""
        if not self.running:
            return
        
        logger.info("🛑 Stopping worker manager and cleaning up Redis connections...")
        self.running = False
        
        # Stop health monitor
        if self.health_monitor_task and not self.health_monitor_task.done():
            self.health_monitor_task.cancel()
            try:
                await self.health_monitor_task
            except asyncio.CancelledError:
                pass
            logger.info("✅ Health monitor stopped")
        
        # CRITICAL FIX: Stop all workers with timeout for graceful shutdown
        stop_tasks = []
        for worker_id, worker in self.workers.items():
            logger.info(f"Stopping worker {worker_id}")
            stop_tasks.append(worker.stop())
        
        # Wait for all workers to stop with timeout
        if stop_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*stop_tasks, return_exceptions=True),
                    timeout=30.0  # 30 second timeout for graceful worker shutdown
                )
                logger.info("✅ All workers stopped gracefully")
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for workers to stop gracefully, forcing shutdown")
        
        # Cancel worker tasks with timeout
        cancel_tasks = []
        for worker_id, task in self.worker_tasks.items():
            if not task.done():
                task.cancel()
                cancel_tasks.append(task)
        
        if cancel_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*cancel_tasks, return_exceptions=True),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                logger.warning("Timeout cancelling worker tasks")
        
        # CRITICAL FIX: Clean up all worker Redis connections via worker manager
        try:
            from core.redis_pool_manager import get_worker_redis_manager
            worker_manager = await get_worker_redis_manager()
            await worker_manager.close_all()
            logger.info("✅ All worker Redis connections cleaned up successfully")
        except ImportError:
            logger.debug("Worker Redis manager not available for cleanup")
        except Exception as cleanup_error:
            logger.warning(f"Worker Redis cleanup failed: {cleanup_error}")
        
        # Clear worker references
        self.workers.clear()
        self.worker_tasks.clear()
        
        logger.info("✅ Worker manager stopped and all resources cleaned up")
    
    async def get_worker_status(self) -> Dict[str, str]:
        """CRITICAL FIX: Get detailed status of all workers including internal state"""
        status = {}
        
        for worker_id, task in self.worker_tasks.items():
            try:
                # Get worker internal state if available
                worker = self.workers.get(worker_id)
                if worker:
                    try:
                        worker_state = await worker.get_worker_state()
                        status[worker_id] = f"task_running, worker_state: {worker_state}"
                    except Exception as e:
                        status[worker_id] = f"task_running, state_error: {str(e)}"
                else:
                    status[worker_id] = "worker_missing"
                
                # Also check task state
                if task.done():
                    if task.exception():
                        status[worker_id] += f", task_failed: {task.exception()}"
                    else:
                        status[worker_id] += ", task_completed"
                elif task.cancelled():
                    status[worker_id] += ", task_cancelled"
                    
            except Exception as e:
                status[worker_id] = f"status_check_failed: {e}"
        
        return status
    
    async def restart_worker(self, worker_id: str):
        """Restart a specific worker"""
        if worker_id not in self.workers:
            raise ValueError(f"Worker {worker_id} not found")
        
        logger.info(f"Restarting worker {worker_id}")
        
        # Stop the worker
        old_worker = self.workers[worker_id]
        await old_worker.stop()
        
        # Cancel old task
        old_task = self.worker_tasks[worker_id]
        if not old_task.done():
            old_task.cancel()
            try:
                await old_task
            except asyncio.CancelledError:
                pass
        
        # Create new worker
        new_worker = ScanWorker(worker_id, self.openai_api_key)
        self.workers[worker_id] = new_worker
        
        # Start new worker
        new_task = asyncio.create_task(new_worker.start())
        self.worker_tasks[worker_id] = new_task
        
        logger.info(f"Restarted worker {worker_id}")
    
    async def _health_monitor_loop(self):
        """Monitor worker health and clean up dead workers from Redis"""
        try:
            from core.redis_pool_manager import get_worker_redis_manager
            
            while self.running:
                try:
                    await self._cleanup_dead_workers()
                    await asyncio.sleep(self.health_check_interval)
                except Exception as e:
                    logger.error(f"Health monitor error: {e}")
                    await asyncio.sleep(self.health_check_interval)
                    
        except asyncio.CancelledError:
            logger.info("Health monitor cancelled")
        except Exception as e:
            logger.error(f"Health monitor crashed: {e}")
    
    async def _cleanup_dead_workers(self):
        """Remove dead workers from Redis that haven't sent heartbeat in 10+ minutes"""
        try:
            from core.redis_pool_manager import get_worker_redis_manager
            worker_manager = await get_worker_redis_manager()
            redis_client = await worker_manager.get_shared_client()
            
            if not redis_client:
                logger.error("Failed to get Redis client for dead worker cleanup")
                return
            
            # Get all heartbeats from Redis
            heartbeats = await redis_client.hgetall("devsecurex_tasks:workers:heartbeats")
            if not heartbeats:
                logger.debug("No worker heartbeats found in Redis")
                return
                
            current_time = time.time()
            dead_worker_threshold = 10 * 60  # 10 minutes
            
            dead_workers = []
            
            for worker_id, heartbeat_str in heartbeats.items():
                try:
                    from datetime import datetime
                    # Parse ISO format timestamp
                    heartbeat_time = datetime.fromisoformat(heartbeat_str.replace('Z', '+00:00'))
                    heartbeat_timestamp = heartbeat_time.timestamp()
                    
                    # Check if worker is dead (no heartbeat for 10+ minutes)
                    time_since_heartbeat = current_time - heartbeat_timestamp
                    if time_since_heartbeat > dead_worker_threshold:
                        dead_workers.append(worker_id)
                        logger.warning(f"Found dead worker {worker_id} (last heartbeat: {time_since_heartbeat:.0f}s ago)")
                        
                except (ValueError, TypeError) as e:
                    logger.error(f"Error parsing heartbeat timestamp for {worker_id}: {e}")
                    dead_workers.append(worker_id)  # Remove corrupted entries too
            
            # Remove dead workers from heartbeats
            if dead_workers:
                await redis_client.hdel("devsecurex_tasks:workers:heartbeats", *dead_workers)
                logger.info(f"✅ Cleaned up {len(dead_workers)} dead workers from heartbeats: {dead_workers}")
                
                # Also update metrics
                try:
                    await redis_client.hincrby("devsecurex_tasks:workers:metrics", "workers_removed", len(dead_workers))
                except Exception as e:
                    logger.warning(f"Failed to update worker removal metrics: {e}")
                
        except Exception as e:
            logger.error(f"Failed to cleanup dead workers: {e}")
    
    @asynccontextmanager
    async def managed_workers(self):
        """Context manager for worker lifecycle"""
        await self.start()
        try:
            yield self
        finally:
            await self.stop()

# Global worker manager instance
worker_manager = None

async def start_background_workers():
    """Start background workers for scan processing based on ENABLE_BACKGROUND_WORKERS"""
    enable_workers = os.getenv("ENABLE_BACKGROUND_WORKERS", "false").lower() == "true"
    
    if not enable_workers:
        app_env = os.getenv("APP_ENV", "development").lower()
        logger.info(f"Background worker startup skipped - ENABLE_BACKGROUND_WORKERS=false (APP_ENV: {app_env})")
        return
    
    global worker_manager
    
    if worker_manager is None:
        worker_manager = WorkerManager()
        await worker_manager.start()
        logger.info("Background scan workers started")

async def stop_background_workers():
    """Stop background workers"""
    global worker_manager
    
    if worker_manager:
        await worker_manager.stop()
        worker_manager = None
        logger.info("Background scan workers stopped")

async def get_worker_stats():
    """Get worker statistics"""
    global worker_manager
    
    if worker_manager:
        return await worker_manager.get_worker_status()
    return {}