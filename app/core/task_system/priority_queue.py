"""
Advanced Priority-Based Task Queuing System with Intelligent Load Distribution

Features:
- Multi-level priority queuing (5 levels: CRITICAL, HIGH, NORMAL, LOW, BACKGROUND)
- Intelligent task routing based on priority and load
- Queue overflow protection and throttling
- Dynamic priority adjustment based on system load
- Real-time queue monitoring and metrics
- Fair scheduling to prevent starvation
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum, IntEnum
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

from core.redis import get_redis_client
from core.utils import utc_now, utc_now_iso

logger = logging.getLogger(__name__)

class TaskPriority(IntEnum):
    """Task priority levels - lower numbers = higher priority"""
    CRITICAL = 0    # System critical tasks (security alerts, failures)
    HIGH = 1        # User-initiated high-priority tasks (PR scans, manual scans)
    NORMAL = 2      # Standard tasks (scheduled scans, reports)
    LOW = 3         # Background tasks (cleanup, maintenance)
    BACKGROUND = 4  # Lowest priority (analytics, archival)

class TaskType(Enum):
    """Task types for specialized processing"""
    SECURITY_SCAN = "security_scan"
    AUTOFIX = "autofix"
    REPORT_GENERATION = "report_generation"
    REPOSITORY_ANALYSIS = "repository_analysis"
    NOTIFICATION = "notification"
    CLEANUP = "cleanup"
    ANALYTICS = "analytics"
    WEBHOOK = "webhook"
    CUSTOM = "custom"

class TaskState(Enum):
    """Task lifecycle states"""
    QUEUED = "queued"
    ASSIGNED = "assigned"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"

@dataclass
class Task:
    """Enhanced task representation"""
    id: str
    type: TaskType
    priority: TaskPriority
    payload: Dict[str, Any]
    
    # Metadata
    created_at: str
    expires_at: Optional[str] = None
    max_retries: int = 3
    retry_count: int = 0
    timeout_seconds: int = 3600
    
    # Routing and coordination
    preferred_worker_tags: List[str] = None
    resource_requirements: Dict[str, Any] = None
    dependencies: List[str] = None
    
    # Progress tracking
    progress: float = 0.0
    current_stage: str = "initialized"
    estimated_duration_seconds: Optional[int] = None
    
    # Error handling
    last_error: Optional[str] = None
    error_count: int = 0
    
    # Worker assignment
    assigned_worker_id: Optional[str] = None
    started_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self):
        if self.preferred_worker_tags is None:
            self.preferred_worker_tags = []
        if self.resource_requirements is None:
            self.resource_requirements = {}
        if self.dependencies is None:
            self.dependencies = []

class PriorityTaskQueue:
    """Advanced priority-based task queue with intelligent load management"""
    
    def __init__(self, redis_key_prefix: str = "task_queue"):
        self.redis_key_prefix = redis_key_prefix
        self.queue_keys = {
            priority: f"{redis_key_prefix}:{priority.name.lower()}"
            for priority in TaskPriority
        }
        
        # Queue management keys
        self.processing_key = f"{redis_key_prefix}:processing"
        self.completed_key = f"{redis_key_prefix}:completed"
        self.failed_key = f"{redis_key_prefix}:failed"
        self.metrics_key = f"{redis_key_prefix}:metrics"
        self.deadletter_key = f"{redis_key_prefix}:deadletter"
        
        # Fair scheduling state
        self.last_priority_served = defaultdict(float)
        self.priority_weights = {
            TaskPriority.CRITICAL: 10.0,
            TaskPriority.HIGH: 5.0,
            TaskPriority.NORMAL: 2.0,
            TaskPriority.LOW: 1.0,
            TaskPriority.BACKGROUND: 0.5
        }
        
        # Queue limits and throttling
        self.max_queue_sizes = {
            TaskPriority.CRITICAL: 100,
            TaskPriority.HIGH: 500,
            TaskPriority.NORMAL: 1000,
            TaskPriority.LOW: 2000,
            TaskPriority.BACKGROUND: 5000
        }
        
        # Metrics tracking
        self.metrics = {
            'tasks_enqueued': 0,
            'tasks_dequeued': 0,
            'tasks_completed': 0,
            'tasks_failed': 0,
            'queue_overflows': 0,
            'average_wait_time': 0.0
        }
    
    async def enqueue_task(
        self,
        task_type: TaskType,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        expires_in_seconds: Optional[int] = None,
        max_retries: int = 3,
        timeout_seconds: int = 3600,
        preferred_worker_tags: List[str] = None,
        resource_requirements: Dict[str, Any] = None,
        dependencies: List[str] = None,
        estimated_duration_seconds: Optional[int] = None
    ) -> str:
        """Enqueue a task with advanced routing and scheduling options"""
        
        task_id = str(uuid.uuid4())
        now = utc_now_iso()
        
        # Calculate expiration
        expires_at = None
        if expires_in_seconds:
            expire_time = datetime.utcnow() + timedelta(seconds=expires_in_seconds)
            expires_at = expire_time.isoformat()
        
        # Create task
        task = Task(
            id=task_id,
            type=task_type,
            priority=priority,
            payload=payload,
            created_at=now,
            expires_at=expires_at,
            max_retries=max_retries,
            timeout_seconds=timeout_seconds,
            preferred_worker_tags=preferred_worker_tags or [],
            resource_requirements=resource_requirements or {},
            dependencies=dependencies or [],
            estimated_duration_seconds=estimated_duration_seconds
        )
        
        redis_client = await get_redis_client()
        if not redis_client:
            logger.error("Redis client not available for task enqueuing")
            raise RuntimeError("Task queue unavailable - Redis not accessible")
        
        try:
            # Check queue capacity
            await self._check_queue_capacity(priority, redis_client)
            
            # Check dependencies are satisfied
            if task.dependencies:
                await self._validate_dependencies(task.dependencies, redis_client)
            
            # Store task data
            task_json = json.dumps(asdict(task))
            
            # Add to priority queue with score based on priority and creation time
            # Lower score = higher priority for processing
            score = priority.value * 1000000 + time.time()
            
            await redis_client.zadd(
                self.queue_keys[priority],
                {task_json: score}
            )
            
            # Update metrics
            await self._update_metrics('tasks_enqueued', redis_client)
            
            logger.info(f"Enqueued task {task_id} with priority {priority.name} and type {task_type.value}")
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to enqueue task: {e}", exc_info=True)
            raise
    
    async def dequeue_task(
        self,
        worker_id: str,
        worker_tags: List[str] = None,
        worker_capabilities: Dict[str, Any] = None
    ) -> Optional[Task]:
        """Dequeue highest priority task using fair scheduling"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for task dequeuing")
            return None
        
        try:
            # Get task using fair scheduling algorithm
            task = await self._fair_dequeue(worker_id, worker_tags or [], worker_capabilities or {}, redis_client)
            
            if task:
                # Move to processing state
                await self._mark_task_processing(task, worker_id, redis_client)
                await self._update_metrics('tasks_dequeued', redis_client)
                
                logger.info(f"Dequeued task {task.id} of type {task.type.value} for worker {worker_id}")
            
            return task
            
        except Exception as e:
            logger.error(f"Failed to dequeue task for worker {worker_id}: {e}", exc_info=True)
            return None
    
    async def _fair_dequeue(
        self,
        worker_id: str,
        worker_tags: List[str],
        worker_capabilities: Dict[str, Any],
        redis_client
    ) -> Optional[Task]:
        """Fair scheduling algorithm to prevent priority starvation"""
        
        current_time = time.time()
        best_task = None
        best_score = float('-inf')
        best_priority = None
        best_task_json = None
        
        # Check each priority queue
        for priority in TaskPriority:
            queue_key = self.queue_keys[priority]
            
            # Get tasks from this priority queue (oldest first)
            tasks = await redis_client.zrange(queue_key, 0, 9, withscores=True)  # Check top 10
            
            if not tasks:
                continue
            
            for task_json, score in tasks:
                try:
                    task_data = json.loads(task_json)
                    task = Task(**task_data)
                    
                    # Skip expired tasks
                    if task.expires_at and datetime.fromisoformat(task.expires_at) < datetime.utcnow():
                        await self._move_to_expired(task, redis_client)
                        continue
                    
                    # Check worker compatibility
                    if not self._is_worker_compatible(task, worker_tags, worker_capabilities):
                        continue
                    
                    # Check dependencies
                    if task.dependencies and not await self._are_dependencies_satisfied(task.dependencies, redis_client):
                        continue
                    
                    # Calculate scheduling score (fair scheduling)
                    scheduling_score = self._calculate_scheduling_score(task, priority, current_time)
                    
                    if scheduling_score > best_score:
                        best_score = scheduling_score
                        best_task = task
                        best_priority = priority
                        best_task_json = task_json
                        
                except Exception as e:
                    logger.warning(f"Error processing task in queue: {e}")
                    continue
        
        # Remove selected task from queue
        if best_task and best_priority:
            await redis_client.zrem(self.queue_keys[best_priority], best_task_json)
            self.last_priority_served[best_priority] = current_time
            
        return best_task
    
    def _calculate_scheduling_score(self, task: Task, priority: TaskPriority, current_time: float) -> float:
        """Calculate task scheduling score for fair scheduling"""
        
        # Base priority weight
        priority_score = self.priority_weights[priority]
        
        # Age factor - older tasks get higher score
        age_seconds = current_time - datetime.fromisoformat(task.created_at).timestamp()
        age_factor = min(age_seconds / 3600, 10.0)  # Max 10x boost for age
        
        # Starvation prevention - boost if this priority hasn't been served recently
        last_served = self.last_priority_served.get(priority, 0)
        starvation_factor = min((current_time - last_served) / 1800, 5.0)  # Max 5x boost for starvation
        
        # Retry penalty - lower score for tasks that have failed before
        retry_penalty = 0.9 ** task.retry_count if task.retry_count > 0 else 1.0
        
        return priority_score * (1 + age_factor + starvation_factor) * retry_penalty
    
    def _is_worker_compatible(
        self,
        task: Task,
        worker_tags: List[str],
        worker_capabilities: Dict[str, Any]
    ) -> bool:
        """Check if worker is compatible with task requirements"""
        
        # Check preferred worker tags
        if task.preferred_worker_tags:
            if not any(tag in worker_tags for tag in task.preferred_worker_tags):
                return False
        
        # Check resource requirements
        if task.resource_requirements:
            for resource, required_amount in task.resource_requirements.items():
                available_amount = worker_capabilities.get(resource, 0)
                if available_amount < required_amount:
                    return False
        
        return True
    
    async def _check_queue_capacity(self, priority: TaskPriority, redis_client):
        """Check if queue has capacity and implement overflow protection"""
        
        queue_key = self.queue_keys[priority]
        current_size = await redis_client.zcard(queue_key)
        max_size = self.max_queue_sizes[priority]
        
        if current_size >= max_size:
            await self._update_metrics('queue_overflows', redis_client)
            
            if priority in [TaskPriority.CRITICAL, TaskPriority.HIGH]:
                # For critical/high priority, remove oldest low priority tasks
                await self._make_room_for_priority_task(priority, redis_client)
            else:
                raise RuntimeError(f"Queue capacity exceeded for priority {priority.name}")
    
    async def _make_room_for_priority_task(self, priority: TaskPriority, redis_client):
        """Make room for high priority tasks by removing low priority ones"""
        
        # Remove oldest background tasks first, then low priority
        for low_priority in [TaskPriority.BACKGROUND, TaskPriority.LOW]:
            low_queue = self.queue_keys[low_priority]
            
            # Move oldest tasks to deadletter queue instead of losing them
            oldest_tasks = await redis_client.zrange(low_queue, 0, 9)  # Get 10 oldest
            
            for task_json in oldest_tasks:
                await redis_client.lpush(self.deadletter_key, task_json)
                await redis_client.zrem(low_queue, task_json)
                
                if await redis_client.zcard(self.queue_keys[priority]) < self.max_queue_sizes[priority]:
                    return  # Enough room made
    
    async def _validate_dependencies(self, dependencies: List[str], redis_client):
        """Validate that task dependencies exist"""
        # For now, just log - in production you'd check if dependency tasks exist
        if dependencies:
            logger.debug(f"Task has dependencies: {dependencies}")
    
    async def _are_dependencies_satisfied(self, dependencies: List[str], redis_client) -> bool:
        """Check if all task dependencies are completed"""
        
        if not dependencies:
            return True
        
        # Check if all dependency tasks are in completed state
        for dep_id in dependencies:
            completed_tasks = await redis_client.hget(self.completed_key, dep_id)
            if not completed_tasks:
                return False
        
        return True
    
    async def _mark_task_processing(self, task: Task, worker_id: str, redis_client):
        """Mark task as processing"""
        
        task.assigned_worker_id = worker_id
        task.started_at = utc_now_iso()
        task.updated_at = utc_now_iso()
        
        # Store in processing hash with TTL
        await redis_client.hset(
            self.processing_key,
            task.id,
            json.dumps(asdict(task))
        )
        
        # Set TTL for timeout handling
        await redis_client.expire(f"{self.processing_key}:{task.id}", task.timeout_seconds)
    
    async def _move_to_expired(self, task: Task, redis_client):
        """Move expired task to deadletter queue"""
        
        expired_task = asdict(task)
        expired_task['expired_at'] = utc_now_iso()
        
        await redis_client.lpush(self.deadletter_key, json.dumps(expired_task))
        logger.warning(f"Task {task.id} expired and moved to deadletter queue")
    
    async def mark_task_completed(
        self,
        task_id: str,
        result: Dict[str, Any] = None,
        final_progress: float = 100.0
    ) -> bool:
        """Mark task as completed"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for task completion")
            return False
        
        try:
            # Get task from processing
            task_data = await redis_client.hget(self.processing_key, task_id)
            if not task_data:
                logger.warning(f"Task {task_id} not found in processing queue")
                return False
            
            task_dict = json.loads(task_data)
            task_dict['progress'] = final_progress
            task_dict['current_stage'] = 'completed'
            task_dict['completed_at'] = utc_now_iso()
            task_dict['updated_at'] = utc_now_iso()
            
            if result:
                task_dict['result'] = result
            
            # Move to completed
            await redis_client.hset(self.completed_key, task_id, json.dumps(task_dict))
            await redis_client.hdel(self.processing_key, task_id)
            
            # Update metrics
            await self._update_metrics('tasks_completed', redis_client)
            
            # Calculate and update wait time metric
            if 'created_at' in task_dict and 'started_at' in task_dict:
                created_time = datetime.fromisoformat(task_dict['created_at'])
                started_time = datetime.fromisoformat(task_dict['started_at'])
                wait_time = (started_time - created_time).total_seconds()
                await self._update_average_wait_time(wait_time, redis_client)
            
            logger.info(f"Task {task_id} marked as completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to mark task {task_id} as completed: {e}", exc_info=True)
            return False
    
    async def mark_task_failed(
        self,
        task_id: str,
        error_message: str,
        retry: bool = True
    ) -> bool:
        """Mark task as failed with retry logic"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for task failure marking")
            return False
        
        try:
            # Get task from processing
            task_data = await redis_client.hget(self.processing_key, task_id)
            if not task_data:
                logger.warning(f"Task {task_id} not found in processing queue")
                return False
            
            task_dict = json.loads(task_data)
            task_dict['last_error'] = error_message
            task_dict['error_count'] += 1
            task_dict['retry_count'] += 1
            task_dict['updated_at'] = utc_now_iso()
            
            # Remove from processing
            await redis_client.hdel(self.processing_key, task_id)
            
            # Check if should retry
            if retry and task_dict['retry_count'] <= task_dict['max_retries']:
                # Re-queue with lower priority and exponential backoff delay
                original_priority = TaskPriority(task_dict['priority'])
                retry_priority = min(TaskPriority.LOW, TaskPriority(original_priority.value + 1))
                
                # Add exponential backoff delay
                delay_seconds = min(300, 5 * (2 ** task_dict['retry_count']))  # Max 5 minutes
                retry_time = time.time() + delay_seconds
                
                await redis_client.zadd(
                    self.queue_keys[retry_priority],
                    {json.dumps(task_dict): retry_time}
                )
                
                logger.info(f"Task {task_id} failed, scheduled for retry {task_dict['retry_count']} in {delay_seconds} seconds")
            else:
                # Move to failed permanently
                task_dict['failed_at'] = utc_now_iso()
                task_dict['final_error'] = error_message
                
                await redis_client.hset(self.failed_key, task_id, json.dumps(task_dict))
                await self._update_metrics('tasks_failed', redis_client)
                
                logger.error(f"Task {task_id} failed permanently: {error_message}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to mark task {task_id} as failed: {e}", exc_info=True)
            return False
    
    async def update_task_progress(
        self,
        task_id: str,
        progress: float,
        current_stage: str = None
    ) -> bool:
        """Update task progress"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return False
        
        try:
            task_data = await redis_client.hget(self.processing_key, task_id)
            if not task_data:
                return False
            
            task_dict = json.loads(task_data)
            task_dict['progress'] = max(0, min(100, progress))
            task_dict['updated_at'] = utc_now_iso()
            
            if current_stage:
                task_dict['current_stage'] = current_stage
            
            await redis_client.hset(self.processing_key, task_id, json.dumps(task_dict))
            return True
            
        except Exception as e:
            logger.error(f"Failed to update progress for task {task_id}: {e}", exc_info=True)
            return False
    
    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get current task status"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return None
        
        try:
            # Check processing
            task_data = await redis_client.hget(self.processing_key, task_id)
            if task_data:
                task_dict = json.loads(task_data)
                task_dict['state'] = TaskState.PROCESSING.value
                return task_dict
            
            # Check completed
            task_data = await redis_client.hget(self.completed_key, task_id)
            if task_data:
                task_dict = json.loads(task_data)
                task_dict['state'] = TaskState.COMPLETED.value
                return task_dict
            
            # Check failed
            task_data = await redis_client.hget(self.failed_key, task_id)
            if task_data:
                task_dict = json.loads(task_data)
                task_dict['state'] = TaskState.FAILED.value
                return task_dict
            
            # Check queued (search all priority queues)
            for priority in TaskPriority:
                tasks = await redis_client.zrange(self.queue_keys[priority], 0, -1, withscores=True)
                for task_json, score in tasks:
                    task_dict = json.loads(task_json)
                    if task_dict['id'] == task_id:
                        task_dict['state'] = TaskState.QUEUED.value
                        task_dict['queue_position'] = await self._get_queue_position(task_id, priority, redis_client)
                        return task_dict
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get status for task {task_id}: {e}", exc_info=True)
            return None
    
    async def _get_queue_position(self, task_id: str, priority: TaskPriority, redis_client) -> int:
        """Get task position in priority queue"""
        
        try:
            tasks = await redis_client.zrange(self.queue_keys[priority], 0, -1)
            for i, task_json in enumerate(tasks):
                task_dict = json.loads(task_json)
                if task_dict['id'] == task_id:
                    return i + 1
            return 0
        except:
            return 0
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return {'error': 'Redis unavailable'}
        
        try:
            stats = {}
            
            # Queue sizes by priority
            queue_sizes = {}
            total_queued = 0
            for priority in TaskPriority:
                size = await redis_client.zcard(self.queue_keys[priority])
                queue_sizes[priority.name.lower()] = size
                total_queued += size
            
            stats['queue_sizes'] = queue_sizes
            stats['total_queued'] = total_queued
            
            # Processing, completed, failed counts
            stats['processing'] = await redis_client.hlen(self.processing_key)
            stats['completed'] = await redis_client.hlen(self.completed_key)
            stats['failed'] = await redis_client.hlen(self.failed_key)
            stats['deadletter'] = await redis_client.llen(self.deadletter_key)
            
            # Metrics
            metrics_data = await redis_client.hgetall(self.metrics_key)
            stats['metrics'] = {k: float(v) if v else 0 for k, v in metrics_data.items()}
            
            # Calculate throughput (tasks per minute)
            if stats['metrics'].get('tasks_completed', 0) > 0:
                # This is a simplified calculation - in production you'd track time windows
                stats['throughput_per_minute'] = stats['metrics']['tasks_completed'] / max(1, time.time() / 60)
            else:
                stats['throughput_per_minute'] = 0
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}", exc_info=True)
            return {'error': str(e)}
    
    async def cleanup_expired_tasks(self) -> int:
        """Clean up expired and stale tasks"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return 0
        
        cleanup_count = 0
        current_time = datetime.utcnow()
        
        try:
            # Clean expired tasks from all queues
            for priority in TaskPriority:
                queue_key = self.queue_keys[priority]
                tasks = await redis_client.zrange(queue_key, 0, -1, withscores=True)
                
                for task_json, score in tasks:
                    try:
                        task_dict = json.loads(task_json)
                        
                        # Check expiration
                        if task_dict.get('expires_at'):
                            expires_at = datetime.fromisoformat(task_dict['expires_at'])
                            if current_time > expires_at:
                                # Move to deadletter
                                task_dict['expired_at'] = utc_now_iso()
                                await redis_client.lpush(self.deadletter_key, json.dumps(task_dict))
                                await redis_client.zrem(queue_key, task_json)
                                cleanup_count += 1
                                
                    except Exception as e:
                        logger.warning(f"Error processing task during cleanup: {e}")
            
            # Clean stale processing tasks (timeout exceeded)
            processing_tasks = await redis_client.hgetall(self.processing_key)
            for task_id, task_data in processing_tasks.items():
                try:
                    task_dict = json.loads(task_data)
                    started_at = datetime.fromisoformat(task_dict['started_at'])
                    timeout = timedelta(seconds=task_dict.get('timeout_seconds', 3600))
                    
                    if current_time - started_at > timeout:
                        # Move to failed
                        task_dict['failed_at'] = utc_now_iso()
                        task_dict['final_error'] = 'Task timeout exceeded'
                        
                        await redis_client.hset(self.failed_key, task_id, json.dumps(task_dict))
                        await redis_client.hdel(self.processing_key, task_id)
                        cleanup_count += 1
                        
                except Exception as e:
                    logger.warning(f"Error cleaning stale task {task_id}: {e}")
            
            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} expired/stale tasks")
            
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Error during task cleanup: {e}", exc_info=True)
            return 0
    
    async def _update_metrics(self, metric: str, redis_client):
        """Update queue metrics"""
        try:
            await redis_client.hincrby(self.metrics_key, metric, 1)
        except Exception as e:
            logger.warning(f"Failed to update metric {metric}: {e}")
    
    async def _update_average_wait_time(self, wait_time: float, redis_client):
        """Update average wait time metric using exponential moving average"""
        try:
            current_avg = float(await redis_client.hget(self.metrics_key, 'average_wait_time') or 0)
            # Exponential moving average with alpha=0.1
            new_avg = current_avg * 0.9 + wait_time * 0.1
            await redis_client.hset(self.metrics_key, 'average_wait_time', str(new_avg))
        except Exception as e:
            logger.warning(f"Failed to update average wait time: {e}")