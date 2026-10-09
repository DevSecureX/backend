"""
Worker Coordinator for Distributed Task Processing

Features:
- Worker lifecycle management and coordination
- Health monitoring and automatic recovery
- Load balancing and task assignment
- Resource management and optimization
- Worker specialization and capabilities matching
"""

import asyncio
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict

from core.redis import get_redis_client
from core.utils import utc_now_iso, ensure_utc_datetime, utc_now
from core.circuit_breaker import get_circuit_breaker, CircuitBreakerConfig, CircuitBreakerOpenError

logger = logging.getLogger(__name__)

class WorkerStatus(Enum):
    """Worker status enumeration"""
    STARTING = "starting"
    ACTIVE = "active"
    BUSY = "busy"
    IDLE = "idle"
    UNHEALTHY = "unhealthy"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"

@dataclass
class WorkerCapabilities:
    """Worker capability specification"""
    max_concurrent_tasks: int = 2
    supported_task_types: List[str] = None
    resource_limits: Dict[str, Any] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.supported_task_types is None:
            self.supported_task_types = []
        if self.resource_limits is None:
            self.resource_limits = {"cpu": 1.0, "memory": 512}
        if self.tags is None:
            self.tags = []

@dataclass
class WorkerInfo:
    """Complete worker information"""
    worker_id: str
    worker_type: str
    status: WorkerStatus
    capabilities: WorkerCapabilities
    current_tasks: List[str]
    total_tasks_completed: int = 0
    total_tasks_failed: int = 0
    created_at: str = None
    last_heartbeat: str = None
    last_task_completed_at: Optional[str] = None
    average_task_duration: float = 0.0
    error_count: int = 0
    consecutive_failures: int = 0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = utc_now_iso()
        if self.last_heartbeat is None:
            self.last_heartbeat = utc_now_iso()

class WorkerCoordinator:
    """Coordinates worker lifecycle and task distribution"""
    
    def __init__(self, redis_key_prefix: str = "worker_coordinator"):
        self.redis_key_prefix = redis_key_prefix
        
        # Redis keys
        self.workers_key = f"{redis_key_prefix}:workers"
        self.heartbeat_key = f"{redis_key_prefix}:heartbeats"
        self.assignments_key = f"{redis_key_prefix}:assignments"
        self.metrics_key = f"{redis_key_prefix}:metrics"
        self.health_key = f"{redis_key_prefix}:health"
        
        # PHASE 2 OPTIMIZATION: Extended intervals for Redis cost reduction
        self.heartbeat_timeout = max(900, int(os.getenv("WORKER_HEARTBEAT_TIMEOUT", "900")))  # 15 minutes (was 60s)
        raw_health_check_interval = int(os.getenv("WORKER_HEALTH_CHECK_INTERVAL", "600"))
        self.health_check_interval = max(600, raw_health_check_interval)  # 10 minutes (was 30s)
        self.max_consecutive_failures = 3
        self.task_assignment_timeout = 300  # Seconds
        
        if raw_health_check_interval < 600:
            logger.warning(f"Worker health check interval increased from {raw_health_check_interval}s to {self.health_check_interval}s for Redis cost optimization")
        
        # State tracking
        self.active_workers: Dict[str, WorkerInfo] = {}
        self.worker_assignments: Dict[str, Set[str]] = defaultdict(set)  # worker_id -> task_ids
        self.task_assignments: Dict[str, str] = {}  # task_id -> worker_id
        
        # Metrics
        self.metrics = {
            'workers_created': 0,
            'workers_removed': 0,
            'tasks_assigned': 0,
            'health_check_failures': 0,
            'worker_recoveries': 0
        }
    
    async def create_worker(
        self,
        worker_type: str = "general",
        capabilities: WorkerCapabilities = None
    ) -> Optional[str]:
        """Create a new worker and register it"""
        
        if capabilities is None:
            capabilities = WorkerCapabilities()
        
        worker_id = f"worker-{uuid.uuid4().hex[:8]}"
        
        try:
            # Create worker info
            worker_info = WorkerInfo(
                worker_id=worker_id,
                worker_type=worker_type,
                status=WorkerStatus.STARTING,
                capabilities=capabilities,
                current_tasks=[]
            )
            
            # Store in Redis
            redis_client = await get_redis_client()
            if not redis_client:
                logger.error("Redis unavailable for worker creation")
                return None
            
            await redis_client.hset(
                self.workers_key,
                worker_id,
                json.dumps(asdict(worker_info), default=str)
            )
            
            # Initialize heartbeat
            await redis_client.hset(
                self.heartbeat_key,
                worker_id,
                utc_now_iso()
            )
            
            # Add to local tracking
            self.active_workers[worker_id] = worker_info
            
            # Start the worker process
            worker_started = await self._start_worker_process(worker_id, worker_type, capabilities)
            
            if worker_started:
                # Update status to active
                worker_info.status = WorkerStatus.ACTIVE
                await self._update_worker_status(worker_id, WorkerStatus.ACTIVE)
                
                # Update metrics
                await self._update_metrics('workers_created')
                
                logger.info(f"Created and started worker {worker_id} of type {worker_type}")
                return worker_id
            else:
                # Failed to start, clean up
                await self._cleanup_worker(worker_id)
                logger.error(f"Failed to start worker {worker_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating worker: {e}", exc_info=True)
            return None
    
    async def _start_worker_process(
        self,
        worker_id: str,
        worker_type: str,
        capabilities: WorkerCapabilities
    ) -> bool:
        """Start the actual worker process"""
        
        try:
            # Import worker classes based on type
            if worker_type in ["security_scan", "general"]:
                from scans.workers.scan_worker import ScanWorker
                
                # Create enhanced scan worker with auto-scaling awareness
                openai_api_key = os.getenv("OPENAI_API_KEY")
                worker = ScanWorker(worker_id, openai_api_key)
                
                # Enhance worker with coordinator awareness
                worker.coordinator = self
                worker.capabilities = capabilities
                
                # Start worker in background
                asyncio.create_task(self._run_enhanced_worker(worker, worker_id))
                
            elif worker_type == "autofix":
                from scans.autofix_queue.autofix_worker import AutofixWorker
                
                worker = AutofixWorker(worker_id)
                worker.coordinator = self
                worker.capabilities = capabilities
                
                asyncio.create_task(self._run_enhanced_worker(worker, worker_id))
                
            else:
                # Create generic worker
                worker = GenericWorker(worker_id, capabilities)
                worker.coordinator = self
                
                asyncio.create_task(self._run_enhanced_worker(worker, worker_id))
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting worker process {worker_id}: {e}", exc_info=True)
            return False
    
    async def _run_enhanced_worker(self, worker, worker_id: str):
        """Run worker with coordinator integration"""
        
        try:
            # Set up heartbeat
            heartbeat_task = asyncio.create_task(self._worker_heartbeat_loop(worker_id))
            
            # Run worker with health monitoring
            await worker.start()
            
        except Exception as e:
            logger.error(f"Worker {worker_id} failed: {e}", exc_info=True)
            await self._handle_worker_failure(worker_id, str(e))
        finally:
            # Cleanup
            if 'heartbeat_task' in locals():
                heartbeat_task.cancel()
            await self._mark_worker_stopped(worker_id)
    
    async def _worker_heartbeat_loop(self, worker_id: str):
        """
        PHASE 2 OPTIMIZATION: Event-driven heartbeat with Redis cost reduction.
        Publishes health status change events and extends heartbeat intervals.
        """
        
        # SAFETY: Extended heartbeat intervals to reduce Redis load
        raw_heartbeat_interval = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "300"))  # Default 5 minutes
        heartbeat_interval = max(300, raw_heartbeat_interval)  # Minimum 5 minutes (was 15 seconds)
        
        if raw_heartbeat_interval < 300:
            logger.warning(f"Worker heartbeat interval increased from {raw_heartbeat_interval}s to {heartbeat_interval}s for Redis cost optimization")
        
        logger.info(f"Worker {worker_id} using extended heartbeat interval: {heartbeat_interval}s")
        
        # Create circuit breaker for heartbeat operations
        circuit_breaker = get_circuit_breaker(
            f"worker_heartbeat_{worker_id}",
            config=CircuitBreakerConfig(
                failure_threshold=3,  # Reduced from 5 since intervals are longer
                success_threshold=2,
                timeout=120.0,  # 2 minute circuit break
                max_timeout=600.0  # Max 10 minutes
            )
        )
        
        consecutive_failures = 0
        max_consecutive_failures = 5  # Reduced since intervals are longer
        previous_status = None
        
        try:
            while True:
                try:
                    async with circuit_breaker:
                        await self._update_worker_heartbeat(worker_id)
                        
                        # PHASE 2: Publish health status change events
                        current_worker_info = self.active_workers.get(worker_id)
                        if current_worker_info and current_worker_info.status != previous_status:
                            # Publish worker health status change event
                            try:
                                from scans.event_driven.worker_events import event_system
                                
                                health_event_data = {
                                    "worker_id": worker_id,
                                    "old_status": previous_status,
                                    "new_status": current_worker_info.status.value,
                                    "health_score": self._calculate_worker_health_score(current_worker_info),
                                    "consecutive_failures": current_worker_info.consecutive_failures,
                                    "timestamp": utc_now_iso()
                                }
                                
                                await event_system.publish_worker_health_status_change(health_event_data)
                                previous_status = current_worker_info.status
                                
                            except Exception as event_error:
                                logger.debug(f"Failed to publish worker health event: {event_error}")
                        
                        consecutive_failures = 0  # Reset on success
                        
                        # REDIS OPTIMIZATION: Extended interval reduces heartbeat calls by 95%
                        await asyncio.sleep(heartbeat_interval)  # Was 15s, now 300s+ = 95% reduction
                        
                except asyncio.CancelledError:
                    logger.info(f"Heartbeat loop cancelled for worker {worker_id}")
                    break
                    
                except CircuitBreakerOpenError as e:
                    logger.warning(f"Heartbeat circuit breaker open for worker {worker_id}: {e}")
                    consecutive_failures += 1
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Max consecutive heartbeat failures ({max_consecutive_failures}) reached for worker {worker_id}")
                        await self._mark_worker_unhealthy(worker_id)
                        break
                        
                    # Wait before retrying when circuit is open
                    await asyncio.sleep(60)  # Longer wait when circuit is open
                    
                except Exception as e:
                    logger.warning(f"Heartbeat error for worker {worker_id}: {e}")
                    consecutive_failures += 1
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Max consecutive heartbeat failures reached for worker {worker_id}")
                        await self._mark_worker_unhealthy(worker_id)
                        break
                        
                    # Exponential backoff on repeated failures (longer delays)
                    backoff_delay = min(60 * (2 ** min(consecutive_failures - 1, 3)), 300)
                    await asyncio.sleep(backoff_delay)
                    
        except Exception as e:
            logger.error(f"Fatal error in heartbeat loop for worker {worker_id}: {e}", exc_info=True)
            await self._mark_worker_unhealthy(worker_id)
        finally:
            logger.info(f"Heartbeat loop ended for worker {worker_id}")
    
    def _calculate_worker_health_score(self, worker_info: WorkerInfo) -> float:
        """Calculate health score for worker (0-100)"""
        if not worker_info:
            return 0.0
        
        # Base score
        base_score = 100.0
        
        # Deduct for failures
        failure_penalty = min(worker_info.consecutive_failures * 10, 50)
        
        # Deduct for high utilization
        utilization = len(worker_info.current_tasks) / max(1, worker_info.capabilities.max_concurrent_tasks)
        utilization_penalty = max(0, (utilization - 0.8) * 50)  # Penalty after 80% utilization
        
        # Deduct for status issues
        status_penalty = 0
        if worker_info.status == WorkerStatus.UNHEALTHY:
            status_penalty = 30
        elif worker_info.status == WorkerStatus.FAILED:
            status_penalty = 50
        
        final_score = max(0, base_score - failure_penalty - utilization_penalty - status_penalty)
        return final_score
    
    async def remove_worker(self, worker_id: str, graceful: bool = True) -> bool:
        """Remove a worker gracefully or forcefully"""
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                logger.warning("Redis unavailable for worker removal")
                return False
            
            # Get worker info
            worker_info = await self._get_worker_info(worker_id)
            if not worker_info:
                logger.warning(f"Worker {worker_id} not found for removal")
                return False
            
            if graceful:
                # Wait for current tasks to complete
                await self._graceful_worker_shutdown(worker_id)
            else:
                # Force stop immediately
                await self._force_worker_shutdown(worker_id)
            
            # Clean up from Redis
            await self._cleanup_worker(worker_id)
            
            # Update metrics
            await self._update_metrics('workers_removed')
            
            logger.info(f"Removed worker {worker_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error removing worker {worker_id}: {e}", exc_info=True)
            return False
    
    async def _graceful_worker_shutdown(self, worker_id: str):
        """Gracefully shutdown worker by waiting for tasks to complete"""
        
        # Mark worker as stopping
        await self._update_worker_status(worker_id, WorkerStatus.STOPPING)
        
        # Wait for current tasks to complete (with timeout)
        timeout_seconds = 300  # 5 minutes
        start_time = time.time()
        
        while time.time() - start_time < timeout_seconds:
            worker_info = await self._get_worker_info(worker_id)
            if not worker_info or len(worker_info.current_tasks) == 0:
                break
            
            await asyncio.sleep(5)
        
        # Force stop if tasks didn't complete in time
        if worker_info and len(worker_info.current_tasks) > 0:
            logger.warning(f"Worker {worker_id} still has {len(worker_info.current_tasks)} tasks after timeout, forcing shutdown")
            await self._force_worker_shutdown(worker_id)
    
    async def _force_worker_shutdown(self, worker_id: str):
        """Force immediate worker shutdown"""
        
        # Mark worker as stopped
        await self._update_worker_status(worker_id, WorkerStatus.STOPPED)
        
        # Reassign current tasks to other workers
        await self._reassign_worker_tasks(worker_id)
    
    async def _reassign_worker_tasks(self, failed_worker_id: str):
        """Reassign tasks from failed worker to other workers"""
        
        try:
            if failed_worker_id not in self.worker_assignments:
                return
            
            failed_tasks = list(self.worker_assignments[failed_worker_id])
            
            for task_id in failed_tasks:
                # Find available worker
                available_worker = await self._find_available_worker_for_task(task_id)
                
                if available_worker:
                    # Reassign task
                    await self._assign_task_to_worker(task_id, available_worker)
                    logger.info(f"Reassigned task {task_id} from failed worker {failed_worker_id} to {available_worker}")
                else:
                    # No available worker, task will need to be requeued
                    logger.warning(f"No available worker to reassign task {task_id} from {failed_worker_id}")
                    # Remove from assignments
                    self.task_assignments.pop(task_id, None)
            
            # Clear failed worker assignments
            self.worker_assignments[failed_worker_id].clear()
            
        except Exception as e:
            logger.error(f"Error reassigning tasks from worker {failed_worker_id}: {e}", exc_info=True)
    
    async def assign_task_to_worker(self, task_id: str, task_data: Dict[str, Any]) -> Optional[str]:
        """Assign a task to the most suitable available worker"""
        
        try:
            # Find best worker for task
            best_worker_id = await self._find_best_worker_for_task(task_data)
            
            if not best_worker_id:
                logger.warning(f"No suitable worker found for task {task_id}")
                return None
            
            # Assign task
            await self._assign_task_to_worker(task_id, best_worker_id)
            
            # Update metrics
            await self._update_metrics('tasks_assigned')
            
            logger.info(f"Assigned task {task_id} to worker {best_worker_id}")
            return best_worker_id
            
        except Exception as e:
            logger.error(f"Error assigning task {task_id}: {e}", exc_info=True)
            return None
    
    async def _find_best_worker_for_task(self, task_data: Dict[str, Any]) -> Optional[str]:
        """Find the best worker for a specific task"""
        
        task_type = task_data.get('type', 'general')
        task_requirements = task_data.get('resource_requirements', {})
        preferred_tags = task_data.get('preferred_worker_tags', [])
        
        # Score workers based on suitability
        worker_scores = []
        
        for worker_id, worker_info in self.active_workers.items():
            if worker_info.status not in [WorkerStatus.ACTIVE, WorkerStatus.IDLE]:
                continue
            
            # Check if worker can handle more tasks
            if len(worker_info.current_tasks) >= worker_info.capabilities.max_concurrent_tasks:
                continue
            
            score = 0.0
            
            # Task type compatibility
            if (not worker_info.capabilities.supported_task_types or 
                task_type in worker_info.capabilities.supported_task_types):
                score += 10.0
            
            # Resource availability
            for resource, required in task_requirements.items():
                available = worker_info.capabilities.resource_limits.get(resource, 0)
                if available >= required:
                    score += 5.0
                else:
                    score -= 10.0  # Cannot handle resource requirement
            
            # Prefer workers with matching tags
            matching_tags = set(preferred_tags) & set(worker_info.capabilities.tags)
            score += len(matching_tags) * 2.0
            
            # Prefer less busy workers
            utilization = len(worker_info.current_tasks) / worker_info.capabilities.max_concurrent_tasks
            score += (1.0 - utilization) * 5.0
            
            # Consider historical performance
            if worker_info.total_tasks_completed > 0:
                success_rate = 1.0 - (worker_info.total_tasks_failed / worker_info.total_tasks_completed)
                score += success_rate * 3.0
            
            # Penalize workers with recent failures
            score -= worker_info.consecutive_failures * 2.0
            
            if score > 0:
                worker_scores.append((worker_id, score))
        
        # Sort by score and return best worker
        if worker_scores:
            worker_scores.sort(key=lambda x: x[1], reverse=True)
            return worker_scores[0][0]
        
        return None
    
    async def _find_available_worker_for_task(self, task_id: str) -> Optional[str]:
        """Find any available worker for task reassignment"""
        
        for worker_id, worker_info in self.active_workers.items():
            if (worker_info.status in [WorkerStatus.ACTIVE, WorkerStatus.IDLE] and
                len(worker_info.current_tasks) < worker_info.capabilities.max_concurrent_tasks):
                return worker_id
        
        return None
    
    async def _assign_task_to_worker(self, task_id: str, worker_id: str):
        """Assign task to specific worker"""
        
        try:
            # Update worker assignments
            self.worker_assignments[worker_id].add(task_id)
            self.task_assignments[task_id] = worker_id
            
            # Update worker current tasks
            if worker_id in self.active_workers:
                self.active_workers[worker_id].current_tasks.append(task_id)
            
            # Store assignment in Redis
            redis_client = await get_redis_client()
            if redis_client:
                assignment_data = {
                    'task_id': task_id,
                    'worker_id': worker_id,
                    'assigned_at': utc_now_iso()
                }
                
                await redis_client.hset(
                    self.assignments_key,
                    task_id,
                    json.dumps(assignment_data)
                )
                
                # Set TTL for assignment
                await redis_client.expire(f"{self.assignments_key}:{task_id}", self.task_assignment_timeout)
                
        except Exception as e:
            logger.error(f"Error in task assignment {task_id} -> {worker_id}: {e}", exc_info=True)
    
    async def mark_task_completed(self, task_id: str, worker_id: str, success: bool = True):
        """Mark task as completed by worker"""
        
        try:
            # Update worker assignments
            if worker_id in self.worker_assignments:
                self.worker_assignments[worker_id].discard(task_id)
            
            self.task_assignments.pop(task_id, None)
            
            # Update worker stats
            if worker_id in self.active_workers:
                worker_info = self.active_workers[worker_id]
                
                if task_id in worker_info.current_tasks:
                    worker_info.current_tasks.remove(task_id)
                
                if success:
                    worker_info.total_tasks_completed += 1
                    worker_info.consecutive_failures = 0  # Reset failure count
                    worker_info.last_task_completed_at = utc_now_iso()
                else:
                    worker_info.total_tasks_failed += 1
                    worker_info.consecutive_failures += 1
                    worker_info.error_count += 1
                
                # Update worker status based on task load
                if len(worker_info.current_tasks) == 0:
                    worker_info.status = WorkerStatus.IDLE
                elif len(worker_info.current_tasks) >= worker_info.capabilities.max_concurrent_tasks:
                    worker_info.status = WorkerStatus.BUSY
                else:
                    worker_info.status = WorkerStatus.ACTIVE
                
                # Update in Redis
                await self._update_worker_info(worker_info)
            
            # Remove assignment from Redis
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hdel(self.assignments_key, task_id)
            
            logger.debug(f"Task {task_id} marked as {'completed' if success else 'failed'} by worker {worker_id}")
            
        except Exception as e:
            logger.error(f"Error marking task {task_id} completed: {e}", exc_info=True)
    
    async def health_check_all_workers(self) -> List[str]:
        """Perform health check on all workers, return list of unhealthy workers"""
        
        unhealthy_workers = []
        current_time = utc_now()
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                logger.warning("Redis unavailable for health checks")
                return unhealthy_workers
            
            # Get all worker heartbeats
            heartbeats = await redis_client.hgetall(self.heartbeat_key)
            
            for worker_id in list(self.active_workers.keys()):
                try:
                    worker_info = self.active_workers[worker_id]
                    
                    # Skip if already marked as unhealthy or stopping
                    if worker_info.status in [WorkerStatus.UNHEALTHY, WorkerStatus.STOPPING, WorkerStatus.STOPPED]:
                        continue
                    
                    # Check heartbeat
                    last_heartbeat_str = heartbeats.get(worker_id)
                    if not last_heartbeat_str:
                        logger.warning(f"No heartbeat found for worker {worker_id}")
                        unhealthy_workers.append(worker_id)
                        continue
                    
                    last_heartbeat = ensure_utc_datetime(last_heartbeat_str)
                    time_since_heartbeat = (current_time - last_heartbeat).total_seconds()
                    
                    if time_since_heartbeat > self.heartbeat_timeout:
                        logger.warning(f"Worker {worker_id} heartbeat timeout: {time_since_heartbeat:.1f}s")
                        unhealthy_workers.append(worker_id)
                        continue
                    
                    # Check for excessive failures
                    if worker_info.consecutive_failures >= self.max_consecutive_failures:
                        logger.warning(f"Worker {worker_id} has {worker_info.consecutive_failures} consecutive failures")
                        unhealthy_workers.append(worker_id)
                        continue
                    
                    # Worker is healthy
                    if worker_info.status == WorkerStatus.UNHEALTHY:
                        # Worker recovered
                        worker_info.status = WorkerStatus.ACTIVE if worker_info.current_tasks else WorkerStatus.IDLE
                        await self._update_worker_status(worker_id, worker_info.status)
                        await self._update_metrics('worker_recoveries')
                        logger.info(f"Worker {worker_id} recovered")
                    
                except Exception as e:
                    logger.error(f"Error checking health of worker {worker_id}: {e}", exc_info=True)
                    unhealthy_workers.append(worker_id)
            
            # Mark unhealthy workers
            for worker_id in unhealthy_workers:
                await self._mark_worker_unhealthy(worker_id)
                await self._update_metrics('health_check_failures')
            
            return unhealthy_workers
            
        except Exception as e:
            logger.error(f"Error during health check: {e}", exc_info=True)
            return unhealthy_workers
    
    async def recover_worker(self, worker_id: str) -> bool:
        """Attempt to recover an unhealthy worker"""
        
        try:
            worker_info = await self._get_worker_info(worker_id)
            if not worker_info:
                return False
            
            # Try to restart worker
            restarted = await self._restart_worker(worker_id)
            
            if restarted:
                # Reset failure counters
                worker_info.consecutive_failures = 0
                worker_info.error_count = 0
                worker_info.status = WorkerStatus.ACTIVE
                
                await self._update_worker_info(worker_info)
                logger.info(f"Successfully recovered worker {worker_id}")
                return True
            else:
                logger.error(f"Failed to recover worker {worker_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error recovering worker {worker_id}: {e}", exc_info=True)
            return False
    
    async def _restart_worker(self, worker_id: str) -> bool:
        """Restart a worker process"""
        
        try:
            worker_info = await self._get_worker_info(worker_id)
            if not worker_info:
                return False
            
            # Stop current worker process (if running)
            await self._force_worker_shutdown(worker_id)
            
            # Wait a bit for cleanup
            await asyncio.sleep(2)
            
            # Start new worker process
            return await self._start_worker_process(
                worker_id,
                worker_info.worker_type,
                worker_info.capabilities
            )
            
        except Exception as e:
            logger.error(f"Error restarting worker {worker_id}: {e}", exc_info=True)
            return False
    
    async def stop_all_workers(self):
        """Stop all workers gracefully"""
        
        logger.info("Stopping all workers...")
        
        # Get all active workers
        active_worker_ids = list(self.active_workers.keys())
        
        # Stop workers in parallel
        stop_tasks = [
            self.remove_worker(worker_id, graceful=True)
            for worker_id in active_worker_ids
        ]
        
        if stop_tasks:
            await asyncio.gather(*stop_tasks, return_exceptions=True)
        
        # Clear local state
        self.active_workers.clear()
        self.worker_assignments.clear()
        self.task_assignments.clear()
        
        logger.info("All workers stopped")
    
    async def get_active_worker_count(self) -> int:
        """Get count of active workers"""
        return len([w for w in self.active_workers.values() 
                   if w.status in [WorkerStatus.ACTIVE, WorkerStatus.BUSY, WorkerStatus.IDLE]])
    
    async def get_worker_stats(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed statistics for a specific worker"""
        
        worker_info = self.active_workers.get(worker_id)
        if not worker_info:
            return None
        
        return {
            'worker_id': worker_id,
            'worker_type': worker_info.worker_type,
            'status': worker_info.status.value,
            'current_task_count': len(worker_info.current_tasks),
            'max_concurrent_tasks': worker_info.capabilities.max_concurrent_tasks,
            'utilization': len(worker_info.current_tasks) / worker_info.capabilities.max_concurrent_tasks,
            'total_completed': worker_info.total_tasks_completed,
            'total_failed': worker_info.total_tasks_failed,
            'success_rate': (worker_info.total_tasks_completed / 
                           max(1, worker_info.total_tasks_completed + worker_info.total_tasks_failed)),
            'consecutive_failures': worker_info.consecutive_failures,
            'error_count': worker_info.error_count,
            'uptime_seconds': (utc_now() - ensure_utc_datetime(worker_info.created_at)).total_seconds(),
            'last_heartbeat': worker_info.last_heartbeat,
            'capabilities': asdict(worker_info.capabilities)
        }
    
    async def get_all_worker_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all workers"""
        
        all_stats = {}
        
        for worker_id in self.active_workers:
            stats = await self.get_worker_stats(worker_id)
            if stats:
                all_stats[worker_id] = stats
        
        return all_stats
    
    async def get_system_stats(self) -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        
        try:
            # Worker status distribution
            status_counts = defaultdict(int)
            total_utilization = 0.0
            total_workers = 0
            
            for worker_info in self.active_workers.values():
                status_counts[worker_info.status.value] += 1
                utilization = len(worker_info.current_tasks) / worker_info.capabilities.max_concurrent_tasks
                total_utilization += utilization
                total_workers += 1
            
            avg_utilization = total_utilization / max(1, total_workers)
            
            # Task assignment stats
            total_assigned_tasks = sum(len(tasks) for tasks in self.worker_assignments.values())
            
            return {
                'timestamp': utc_now_iso(),
                'total_workers': total_workers,
                'worker_status_distribution': dict(status_counts),
                'average_utilization': avg_utilization,
                'total_assigned_tasks': total_assigned_tasks,
                'metrics': self.metrics.copy(),
                'assignment_counts': {
                    worker_id: len(tasks) 
                    for worker_id, tasks in self.worker_assignments.items()
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting system stats: {e}", exc_info=True)
            return {'error': str(e)}
    
    # Helper methods
    
    async def _get_worker_info(self, worker_id: str) -> Optional[WorkerInfo]:
        """Get worker info from Redis or local cache"""
        
        # Try local cache first
        if worker_id in self.active_workers:
            return self.active_workers[worker_id]
        
        # Try Redis
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return None
            
            worker_data = await redis_client.hget(self.workers_key, worker_id)
            if worker_data:
                worker_dict = json.loads(worker_data)
                
                # Convert status back to enum
                worker_dict['status'] = WorkerStatus(worker_dict['status'])
                
                # Convert capabilities
                caps_dict = worker_dict.get('capabilities', {})
                worker_dict['capabilities'] = WorkerCapabilities(**caps_dict)
                
                worker_info = WorkerInfo(**worker_dict)
                
                # Update local cache
                self.active_workers[worker_id] = worker_info
                
                return worker_info
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting worker info for {worker_id}: {e}", exc_info=True)
            return None
    
    async def _update_worker_info(self, worker_info: WorkerInfo):
        """Update worker info in Redis and local cache"""
        
        try:
            # Update local cache
            self.active_workers[worker_info.worker_id] = worker_info
            
            # Update Redis
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hset(
                    self.workers_key,
                    worker_info.worker_id,
                    json.dumps(asdict(worker_info), default=str)
                )
        except Exception as e:
            logger.error(f"Error updating worker info for {worker_info.worker_id}: {e}", exc_info=True)
    
    async def _update_worker_status(self, worker_id: str, status: WorkerStatus):
        """Update worker status"""
        
        try:
            if worker_id in self.active_workers:
                self.active_workers[worker_id].status = status
            
            # Update in Redis
            redis_client = await get_redis_client()
            if redis_client:
                worker_data = await redis_client.hget(self.workers_key, worker_id)
                if worker_data:
                    worker_dict = json.loads(worker_data)
                    worker_dict['status'] = status.value
                    
                    await redis_client.hset(
                        self.workers_key,
                        worker_id,
                        json.dumps(worker_dict)
                    )
        except Exception as e:
            logger.error(f"Error updating worker status for {worker_id}: {e}", exc_info=True)
    
    async def _update_worker_heartbeat(self, worker_id: str):
        """Update worker heartbeat"""
        
        try:
            current_time = utc_now_iso()
            
            # Update local cache
            if worker_id in self.active_workers:
                self.active_workers[worker_id].last_heartbeat = current_time
            
            # Update Redis
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hset(self.heartbeat_key, worker_id, current_time)
        except Exception as e:
            logger.error(f"Error updating heartbeat for worker {worker_id}: {e}", exc_info=True)
    
    async def _mark_worker_unhealthy(self, worker_id: str):
        """Mark worker as unhealthy"""
        
        await self._update_worker_status(worker_id, WorkerStatus.UNHEALTHY)
        logger.warning(f"Marked worker {worker_id} as unhealthy")
    
    async def _mark_worker_stopped(self, worker_id: str):
        """Mark worker as stopped"""
        
        await self._update_worker_status(worker_id, WorkerStatus.STOPPED)
        
        # Remove from local tracking
        self.active_workers.pop(worker_id, None)
        self.worker_assignments.pop(worker_id, None)
    
    async def _handle_worker_failure(self, worker_id: str, error_message: str):
        """Handle worker failure"""
        
        logger.error(f"Worker {worker_id} failed: {error_message}")
        
        # Mark as failed
        await self._update_worker_status(worker_id, WorkerStatus.FAILED)
        
        # Reassign tasks
        await self._reassign_worker_tasks(worker_id)
        
        # Update failure metrics
        if worker_id in self.active_workers:
            self.active_workers[worker_id].consecutive_failures += 1
            self.active_workers[worker_id].error_count += 1
    
    async def _cleanup_worker(self, worker_id: str):
        """Clean up worker from Redis"""
        
        try:
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hdel(self.workers_key, worker_id)
                await redis_client.hdel(self.heartbeat_key, worker_id)
                
            # Clean up local state
            self.active_workers.pop(worker_id, None)
            self.worker_assignments.pop(worker_id, None)
            
        except Exception as e:
            logger.error(f"Error cleaning up worker {worker_id}: {e}", exc_info=True)
    
    async def _update_metrics(self, metric: str):
        """Update coordinator metrics"""
        
        try:
            self.metrics[metric] = self.metrics.get(metric, 0) + 1
            
            # Store in Redis
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hincrby(self.metrics_key, metric, 1)
        except Exception as e:
            logger.warning(f"Error updating metric {metric}: {e}")


class GenericWorker:
    """Generic worker for handling various task types"""
    
    def __init__(self, worker_id: str, capabilities: WorkerCapabilities):
        self.worker_id = worker_id
        self.capabilities = capabilities
        self.coordinator = None
        self.running = False
    
    async def start(self):
        """Start the generic worker with circuit breaker protection"""
        self.running = True
        logger.info(f"Starting generic worker {self.worker_id}")
        
        # Create circuit breaker for worker operations
        circuit_breaker = get_circuit_breaker(
            f"generic_worker_{self.worker_id}",
            config=CircuitBreakerConfig(
                failure_threshold=5,
                success_threshold=2,
                timeout=30.0,
                max_timeout=300.0
            )
        )
        
        consecutive_failures = 0
        max_consecutive_failures = 10
        max_runtime = 24 * 60 * 60  # 24 hours max runtime
        start_time = time.time()
        
        try:
            # Main processing loop with safety guards
            while self.running:
                try:
                    # Check runtime limit
                    if time.time() - start_time > max_runtime:
                        logger.warning(f"Generic worker {self.worker_id} reached max runtime, stopping")
                        break
                    
                    async with circuit_breaker:
                        # This would integrate with the task queue system
                        # For now, just maintain heartbeat and wait
                        await asyncio.sleep(10)
                        consecutive_failures = 0  # Reset on success
                        
                except CircuitBreakerOpenError as e:
                    logger.warning(f"Circuit breaker open for generic worker {self.worker_id}: {e}")
                    consecutive_failures += 1
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Max consecutive failures reached for generic worker {self.worker_id}")
                        break
                    
                    # Wait when circuit is open
                    await asyncio.sleep(30)
                    
                except Exception as e:
                    logger.error(f"Generic worker {self.worker_id} error: {e}", exc_info=True)
                    consecutive_failures += 1
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Max consecutive failures reached for generic worker {self.worker_id}")
                        break
                        
                    # Exponential backoff on failures
                    backoff_delay = min(5 * (2 ** min(consecutive_failures - 1, 4)), 60)
                    await asyncio.sleep(backoff_delay)
                    
        except Exception as e:
            logger.error(f"Fatal error in generic worker {self.worker_id}: {e}", exc_info=True)
        finally:
            self.running = False
            logger.info(f"Generic worker {self.worker_id} stopped")
    
    async def stop(self):
        """Stop the generic worker"""
        self.running = False
        logger.info(f"Stopping generic worker {self.worker_id}")