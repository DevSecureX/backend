"""
Enterprise Task Queue Manager
Unifies all enterprise queue management patterns for the core task system.
Provides a central hub for all background task processing with enterprise-grade reliability.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import psutil

logger = logging.getLogger(__name__)


class TaskType(Enum):
    """Task type enumeration"""
    SCAN = "scan"
    AUTOFIX = "autofix"
    WEBHOOK = "webhook"
    ANALYTICS = "analytics"
    MAINTENANCE = "maintenance"
    NOTIFICATION = "notification"
    INTEGRATION = "integration"


class TaskPriority(Enum):
    """Unified task priority levels"""
    CRITICAL = 0     # System critical tasks
    HIGH = 1         # User-triggered tasks
    NORMAL = 2       # Standard operations
    LOW = 3          # Background tasks
    MAINTENANCE = 4  # System maintenance


class TaskStatus(Enum):
    """Enhanced task status tracking"""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RETRY = "retry"


@dataclass
class UnifiedTask:
    """Unified task structure for all task types"""
    task_id: str
    task_type: TaskType
    priority: TaskPriority
    payload: Dict[str, Any]
    
    # Queue management
    queue_position: int = 0
    estimated_wait_time: int = 0
    estimated_completion_time: Optional[datetime] = None
    
    # Status tracking
    status: TaskStatus = TaskStatus.QUEUED
    worker_id: Optional[str] = None
    started_at: Optional[datetime] = None
    queued_at: datetime = None
    completed_at: Optional[datetime] = None
    
    # Enterprise features
    user_id: Optional[int] = None
    user_tier: str = "free"
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 3600  # 1 hour default
    
    # Routing information
    target_queue: Optional[str] = None  # Which specialized queue to use
    callback_url: Optional[str] = None
    
    # Performance tracking
    processing_time: float = 0.0
    queue_time: float = 0.0
    
    def __post_init__(self):
        if self.queued_at is None:
            self.queued_at = datetime.now(timezone.utc)
        
        # Auto-assign target queue based on task type
        if self.target_queue is None:
            self.target_queue = f"{self.task_type.value}_queue"


class UnifiedResourceMonitor:
    """Unified resource monitoring for all task types"""
    
    def __init__(self):
        self.max_concurrent_tasks = {
            TaskType.SCAN: 50,
            TaskType.AUTOFIX: 25,
            TaskType.WEBHOOK: 100,
            TaskType.ANALYTICS: 20,
            TaskType.MAINTENANCE: 10,
            TaskType.NOTIFICATION: 50,
            TaskType.INTEGRATION: 30
        }
        
        self.history_size = 120  # 2 hours of data points
        self.resource_history = []
        
    async def get_system_health(self) -> Dict[str, Any]:
        """Get comprehensive system health for all task types"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            # Update history
            self.resource_history.append({
                "timestamp": time.time(),
                "cpu": cpu_percent,
                "memory": memory.percent,
                "disk": disk.percent,
                "network_sent": network.bytes_sent,
                "network_recv": network.bytes_recv
            })
            
            # Keep only recent history
            if len(self.resource_history) > self.history_size:
                self.resource_history.pop(0)
            
            # Calculate trends
            cpu_trend = self._calculate_resource_trend("cpu")
            memory_trend = self._calculate_resource_trend("memory")
            
            # System health assessment
            health_score = self._calculate_health_score(cpu_percent, memory.percent, disk.percent)
            
            return {
                "cpu": {
                    "current": cpu_percent,
                    "average": sum(r["cpu"] for r in self.resource_history) / len(self.resource_history),
                    "trend": cpu_trend,
                    "healthy": cpu_percent < 85
                },
                "memory": {
                    "current": memory.percent,
                    "available_gb": memory.available / (1024**3),
                    "trend": memory_trend,
                    "healthy": memory.percent < 85
                },
                "disk": {
                    "used_percent": disk.percent,
                    "free_gb": disk.free / (1024**3),
                    "healthy": disk.percent < 90
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "healthy": True  # Network is typically always healthy
                },
                "overall": {
                    "health_score": health_score,
                    "healthy": health_score > 70,
                    "status": self._get_health_status(health_score)
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get system health: {e}")
            return {
                "cpu": {"healthy": False, "error": str(e)},
                "memory": {"healthy": False, "error": str(e)},
                "disk": {"healthy": False, "error": str(e)},
                "overall": {"healthy": False, "health_score": 0},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def _calculate_resource_trend(self, resource: str) -> str:
        """Calculate trend for a specific resource"""
        if len(self.resource_history) < 10:
            return "stable"
        
        recent = [r[resource] for r in self.resource_history[-10:]]
        older = [r[resource] for r in self.resource_history[-20:-10]] if len(self.resource_history) >= 20 else recent
        
        recent_avg = sum(recent) / len(recent)
        older_avg = sum(older) / len(older)
        
        if recent_avg > older_avg * 1.1:
            return "increasing"
        elif recent_avg < older_avg * 0.9:
            return "decreasing"
        else:
            return "stable"
    
    def _calculate_health_score(self, cpu: float, memory: float, disk: float) -> float:
        """Calculate overall system health score (0-100)"""
        cpu_score = max(0, 100 - cpu)
        memory_score = max(0, 100 - memory)
        disk_score = max(0, 100 - disk)
        
        # Weighted average (CPU and memory are more important)
        health_score = (cpu_score * 0.4 + memory_score * 0.4 + disk_score * 0.2)
        return min(100, max(0, health_score))
    
    def _get_health_status(self, health_score: float) -> str:
        """Get health status based on score"""
        if health_score >= 80:
            return "excellent"
        elif health_score >= 60:
            return "good"
        elif health_score >= 40:
            return "fair"
        elif health_score >= 20:
            return "poor"
        else:
            return "critical"
    
    def get_optimal_concurrency(self, task_type: TaskType, current_tasks: int) -> int:
        """Get optimal concurrency for a specific task type"""
        try:
            base_limit = self.max_concurrent_tasks.get(task_type, 20)
            
            # Adjust based on system health
            if self.resource_history:
                latest = self.resource_history[-1]
                cpu_factor = max(0.2, (100 - latest["cpu"]) / 100)
                memory_factor = max(0.2, (100 - latest["memory"]) / 100)
                
                adjusted_limit = int(base_limit * cpu_factor * memory_factor)
                return max(2, min(base_limit * 2, adjusted_limit))
            
            return base_limit
            
        except Exception as e:
            logger.error(f"Failed to calculate optimal concurrency: {e}")
            return 10


class UnifiedCircuitBreaker:
    """Unified circuit breaker for all task types"""
    
    def __init__(self):
        self.task_breakers = {
            task_type: {
                "state": "CLOSED",
                "failure_count": 0,
                "failure_threshold": self._get_failure_threshold(task_type),
                "timeout": self._get_timeout(task_type),
                "last_failure_time": 0
            }
            for task_type in TaskType
        }
    
    def _get_failure_threshold(self, task_type: TaskType) -> int:
        """Get failure threshold for task type"""
        thresholds = {
            TaskType.SCAN: 5,
            TaskType.AUTOFIX: 3,
            TaskType.WEBHOOK: 10,
            TaskType.ANALYTICS: 5,
            TaskType.MAINTENANCE: 2,
            TaskType.NOTIFICATION: 8,
            TaskType.INTEGRATION: 5
        }
        return thresholds.get(task_type, 5)
    
    def _get_timeout(self, task_type: TaskType) -> int:
        """Get timeout for task type"""
        timeouts = {
            TaskType.SCAN: 300,      # 5 minutes
            TaskType.AUTOFIX: 600,   # 10 minutes
            TaskType.WEBHOOK: 120,   # 2 minutes
            TaskType.ANALYTICS: 300, # 5 minutes
            TaskType.MAINTENANCE: 60, # 1 minute
            TaskType.NOTIFICATION: 60, # 1 minute
            TaskType.INTEGRATION: 180  # 3 minutes
        }
        return timeouts.get(task_type, 300)
    
    def can_execute(self, task_type: TaskType) -> bool:
        """Check if tasks of this type can execute"""
        breaker = self.task_breakers[task_type]
        
        if breaker["state"] == "CLOSED":
            return True
        elif breaker["state"] == "OPEN":
            if time.time() - breaker["last_failure_time"] > breaker["timeout"]:
                breaker["state"] = "HALF_OPEN"
                return True
            return False
        else:  # HALF_OPEN
            return True
    
    def record_success(self, task_type: TaskType):
        """Record successful task execution"""
        breaker = self.task_breakers[task_type]
        
        if breaker["state"] == "HALF_OPEN":
            breaker["state"] = "CLOSED"
        
        breaker["failure_count"] = max(0, breaker["failure_count"] - 1)
    
    def record_failure(self, task_type: TaskType):
        """Record failed task execution"""
        breaker = self.task_breakers[task_type]
        
        breaker["failure_count"] += 1
        breaker["last_failure_time"] = time.time()
        
        if breaker["failure_count"] >= breaker["failure_threshold"]:
            breaker["state"] = "OPEN"
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status for all task types"""
        return {
            task_type.value: {
                "state": breaker["state"],
                "failure_count": breaker["failure_count"],
                "failure_threshold": breaker["failure_threshold"],
                "timeout": breaker["timeout"]
            }
            for task_type, breaker in self.task_breakers.items()
        }


class EnterpriseTaskQueueManager:
    """Unified enterprise task queue manager for all task types"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        
        # Unified queue system
        self.task_queues = {
            task_type: {
                priority: asyncio.Queue()
                for priority in TaskPriority
            }
            for task_type in TaskType
        }
        
        # Active tasks tracking
        self.active_tasks: Dict[str, UnifiedTask] = {}
        self.worker_assignments: Dict[str, str] = {}
        
        # Enterprise components
        self.resource_monitor = UnifiedResourceMonitor()
        self.circuit_breaker = UnifiedCircuitBreaker()
        
        # Configuration
        self.max_queue_size = 5000  # Total across all task types
        self.max_user_queue_size = 100  # Per user across all task types
        self.cleanup_interval = 300
        self.metrics_interval = 60
        
        # Metrics
        self.metrics = {
            "total_queued": 0,
            "total_processed": 0,
            "total_failed": 0,
            "task_type_distribution": {t.value: 0 for t in TaskType},
            "priority_distribution": {p.value: 0 for p in TaskPriority},
            "user_task_counts": {},
            "average_processing_times": {t.value: 0.0 for t in TaskType},
            "peak_queue_size": 0
        }
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.metrics_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("Enterprise Unified Task Queue Manager initialized")
    
    async def start(self):
        """Start the unified task queue manager"""
        self._running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.metrics_task = asyncio.create_task(self._metrics_loop())
        logger.info("Enterprise Unified Task Queue Manager started")
    
    async def stop(self):
        """Stop the unified task queue manager"""
        self._running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if self.metrics_task:
            self.metrics_task.cancel()
        
        if self.active_tasks:
            logger.info(f"Waiting for {len(self.active_tasks)} active tasks to complete...")
            await asyncio.sleep(30)
        
        logger.info("Enterprise Unified Task Queue Manager stopped")
    
    async def enqueue_task(
        self,
        task_type: TaskType,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        user_id: Optional[int] = None,
        user_tier: str = "free",
        timeout: int = 3600,
        max_retries: int = 3,
        callback_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Enqueue a task for processing"""
        
        # Check circuit breaker
        if not self.circuit_breaker.can_execute(task_type):
            breaker_status = self.circuit_breaker.task_breakers[task_type]
            return {
                "success": False,
                "error": f"{task_type.value} system temporarily unavailable",
                "retry_after": breaker_status["timeout"],
                "circuit_breaker_state": breaker_status["state"]
            }
        
        try:
            task_id = str(uuid.uuid4())
            
            # Check system capacity
            system_health = await self.resource_monitor.get_system_health()
            if not self._can_accept_request(system_health, task_type, user_tier):
                return {
                    "success": False,
                    "error": f"{task_type.value} system at capacity",
                    "system_health": system_health,
                    "estimated_retry_time": 600
                }
            
            # Check per-user limits
            if user_id:
                user_task_count = self.metrics["user_task_counts"].get(user_id, 0)
                max_user_tasks = self._get_user_task_limit(user_tier)
                
                if user_task_count >= max_user_tasks:
                    return {
                        "success": False,
                        "error": f"User task limit reached ({max_user_tasks})",
                        "user_tier": user_tier,
                        "current_task_count": user_task_count
                    }
            
            # Create unified task
            task = UnifiedTask(
                task_id=task_id,
                task_type=task_type,
                priority=priority,
                payload=payload,
                user_id=user_id,
                user_tier=user_tier,
                timeout=timeout,
                max_retries=max_retries,
                callback_url=callback_url
            )
            
            # Calculate queue metrics
            queue_info = await self._calculate_queue_metrics(task_type, priority, user_tier)
            task.queue_position = queue_info["position"]
            task.estimated_wait_time = queue_info["wait_time"]
            task.estimated_completion_time = queue_info["completion_time"]
            
            # Add to appropriate queue
            await self.task_queues[task_type][priority].put(task)
            
            # Update metrics
            self.metrics["total_queued"] += 1
            self.metrics["task_type_distribution"][task_type.value] += 1
            self.metrics["priority_distribution"][priority.value] += 1
            
            if user_id:
                self.metrics["user_task_counts"][user_id] = user_task_count + 1
            
            # Update peak queue size
            total_queued = self._get_total_queued_count()
            self.metrics["peak_queue_size"] = max(self.metrics["peak_queue_size"], total_queued)
            
            # Store in Redis
            await self._persist_task_to_redis(task)
            
            self.circuit_breaker.record_success(task_type)
            
            logger.info(f"Task queued: {task_id} ({task_type.value}) priority: {priority.name}")
            
            return {
                "success": True,
                "task_id": task_id,
                "task_type": task_type.value,
                "status": "queued",
                "queue_position": task.queue_position,
                "estimated_wait_time": task.estimated_wait_time,
                "estimated_completion_time": task.estimated_completion_time.isoformat() if task.estimated_completion_time else None,
                "priority": priority.name,
                "target_queue": task.target_queue
            }
            
        except Exception as e:
            logger.error(f"Failed to enqueue task: {e}")
            self.circuit_breaker.record_failure(task_type)
            return {
                "success": False,
                "error": str(e),
                "task_id": None
            }
    
    async def get_next_task(self, worker_id: str, supported_task_types: List[TaskType] = None) -> Optional[UnifiedTask]:
        """Get next task for processing (supports task type filtering)"""
        
        if supported_task_types is None:
            supported_task_types = list(TaskType)
        
        # Check worker load
        current_load = len([t for t in self.active_tasks.values() if t.worker_id == worker_id])
        if current_load >= 5:  # Max tasks per worker
            return None
        
        # Try each supported task type and priority
        for task_type in supported_task_types:
            for priority in TaskPriority:
                queue = self.task_queues[task_type][priority]
                
                try:
                    task = queue.get_nowait()
                    
                    # Update task status
                    task.status = TaskStatus.PROCESSING
                    task.worker_id = worker_id
                    task.started_at = datetime.now(timezone.utc)
                    
                    # Calculate queue time
                    if task.queued_at:
                        task.queue_time = (task.started_at - task.queued_at).total_seconds()
                    
                    # Track active task
                    self.active_tasks[task.task_id] = task
                    self.worker_assignments[worker_id] = task.task_id
                    
                    # Update user task count
                    if task.user_id and task.user_id in self.metrics["user_task_counts"]:
                        self.metrics["user_task_counts"][task.user_id] -= 1
                    
                    logger.info(f"Assigned task {task.task_id} ({task.task_type.value}) to worker {worker_id}")
                    return task
                    
                except asyncio.QueueEmpty:
                    continue
        
        return None
    
    async def complete_task(
        self,
        task_id: str,
        success: bool = True,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        should_retry: bool = False
    ):
        """Mark task as completed or schedule retry"""
        
        if task_id not in self.active_tasks:
            logger.warning(f"Attempted to complete unknown task: {task_id}")
            return
        
        task = self.active_tasks[task_id]
        
        # Check if should retry
        if not success and should_retry and task.retry_count < task.max_retries:
            task.retry_count += 1
            task.status = TaskStatus.RETRY
            
            # Re-queue with delay
            asyncio.create_task(self._schedule_retry(task))
            
            logger.info(f"Task {task_id} scheduled for retry {task.retry_count}/{task.max_retries}")
            return
        
        # Complete task
        task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        task.completed_at = datetime.now(timezone.utc)
        
        if task.started_at:
            task.processing_time = (task.completed_at - task.started_at).total_seconds()
            self._update_average_processing_time(task.task_type, task.processing_time)
        
        # Update metrics
        if success:
            self.metrics["total_processed"] += 1
            self.circuit_breaker.record_success(task.task_type)
        else:
            self.metrics["total_failed"] += 1
            self.circuit_breaker.record_failure(task.task_type)
        
        # Clean up
        del self.active_tasks[task_id]
        if task.worker_id and task.worker_id in self.worker_assignments:
            del self.worker_assignments[task.worker_id]
        
        # Store completion in Redis
        await self._update_task_in_redis(task_id, {
            "status": task.status.value,
            "completed_at": task.completed_at.isoformat(),
            "success": success,
            "result": result,
            "error": error,
            "processing_time": task.processing_time
        })
        
        # Send callback if configured
        if task.callback_url and success:
            asyncio.create_task(self._send_completion_callback(task, result))
        
        logger.info(f"Task {task_id} ({task.task_type.value}) completed: {'success' if success else 'failed'}")
    
    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status"""
        
        # Check active tasks
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            return {
                "task_id": task_id,
                "task_type": task.task_type.value,
                "status": task.status.value,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "worker_id": task.worker_id,
                "processing_time": (datetime.now(timezone.utc) - task.started_at).total_seconds() if task.started_at else 0,
                "retry_count": task.retry_count,
                "queue_time": task.queue_time
            }
        
        # Check Redis
        return await self._get_task_from_redis(task_id)
    
    async def get_queue_statistics(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        
        system_health = await self.resource_monitor.get_system_health()
        
        # Queue sizes by task type and priority
        queue_sizes = {}
        for task_type in TaskType:
            queue_sizes[task_type.value] = {}
            for priority in TaskPriority:
                queue_sizes[task_type.value][priority.value] = self.task_queues[task_type][priority].qsize()
        
        # Active tasks by type
        active_tasks_by_type = {}
        for task_type in TaskType:
            active_tasks_by_type[task_type.value] = len([
                t for t in self.active_tasks.values() if t.task_type == task_type
            ])
        
        return {
            "queue_sizes": queue_sizes,
            "total_queued": self._get_total_queued_count(),
            "active_tasks": len(self.active_tasks),
            "active_tasks_by_type": active_tasks_by_type,
            "system_health": system_health,
            "circuit_breaker": self.circuit_breaker.get_status(),
            "metrics": self.metrics,
            "capacity": {
                task_type.value: self.resource_monitor.get_optimal_concurrency(
                    task_type, active_tasks_by_type.get(task_type.value, 0)
                )
                for task_type in TaskType
            }
        }
    
    def _get_total_queued_count(self) -> int:
        """Get total number of queued tasks across all types and priorities"""
        total = 0
        for task_type in TaskType:
            for priority in TaskPriority:
                total += self.task_queues[task_type][priority].qsize()
        return total
    
    def _can_accept_request(self, system_health: Dict[str, Any], task_type: TaskType, user_tier: str) -> bool:
        """Check if system can accept new requests"""
        
        # Check system health
        if not system_health.get("overall", {}).get("healthy", False):
            return False
        
        # Check total queue size
        total_queued = self._get_total_queued_count()
        if total_queued >= self.max_queue_size:
            return False
        
        # Premium users get priority during high load
        if user_tier in ["pro", "enterprise"]:
            return total_queued < self.max_queue_size * 0.9
        
        return True
    
    def _get_user_task_limit(self, user_tier: str) -> int:
        """Get task limit based on user tier"""
        limits = {
            "free": 20,
            "pro": 100,
            "enterprise": 500
        }
        return limits.get(user_tier, 20)
    
    async def _calculate_queue_metrics(self, task_type: TaskType, priority: TaskPriority, user_tier: str) -> Dict[str, Any]:
        """Calculate queue position and wait time"""
        
        # Count tasks with higher or equal priority
        position = 0
        for p in TaskPriority:
            if p.value <= priority.value:
                position += self.task_queues[task_type][p].qsize()
        
        # Estimate wait time
        avg_processing_time = self.metrics["average_processing_times"].get(task_type.value, 300)
        concurrent_capacity = self.resource_monitor.get_optimal_concurrency(task_type, 0)
        
        estimated_wait = (position / max(1, concurrent_capacity)) * avg_processing_time
        
        # Premium users get priority
        if user_tier in ["pro", "enterprise"]:
            estimated_wait *= 0.7
        
        completion_time = datetime.now(timezone.utc) + timedelta(seconds=estimated_wait)
        
        return {
            "position": position,
            "wait_time": int(estimated_wait),
            "completion_time": completion_time,
            "concurrent_capacity": concurrent_capacity
        }
    
    def _update_average_processing_time(self, task_type: TaskType, processing_time: float):
        """Update average processing time for task type"""
        alpha = 0.1
        current_avg = self.metrics["average_processing_times"][task_type.value]
        if current_avg == 0:
            self.metrics["average_processing_times"][task_type.value] = processing_time
        else:
            self.metrics["average_processing_times"][task_type.value] = (
                alpha * processing_time + (1 - alpha) * current_avg
            )
    
    async def _schedule_retry(self, task: UnifiedTask):
        """Schedule task for retry"""
        try:
            retry_delay = 60 * task.retry_count  # Exponential backoff
            await asyncio.sleep(retry_delay)
            
            # Reset status and re-queue
            task.status = TaskStatus.QUEUED
            task.worker_id = None
            task.started_at = None
            task.queued_at = datetime.now(timezone.utc)
            
            await self.task_queues[task.task_type][task.priority].put(task)
            
            logger.info(f"Task {task.task_id} re-queued for retry")
            
        except Exception as e:
            logger.error(f"Failed to schedule task retry: {e}")
    
    async def _send_completion_callback(self, task: UnifiedTask, result: Dict[str, Any]):
        """Send completion callback"""
        try:
            import aiohttp
            
            payload = {
                "task_id": task.task_id,
                "task_type": task.task_type.value,
                "status": "completed",
                "result": result,
                "processing_time": task.processing_time,
                "queue_time": task.queue_time,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    task.callback_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        logger.info(f"Callback sent for task {task.task_id}")
                    else:
                        logger.warning(f"Callback failed for task {task.task_id}: HTTP {response.status}")
        
        except Exception as e:
            logger.error(f"Failed to send completion callback for task {task.task_id}: {e}")
    
    async def _persist_task_to_redis(self, task: UnifiedTask):
        """Persist task to Redis"""
        if not self.redis:
            return
        
        try:
            task_data = asdict(task)
            for key, value in task_data.items():
                if isinstance(value, datetime):
                    task_data[key] = value.isoformat()
                elif isinstance(value, (TaskType, TaskPriority, TaskStatus)):
                    task_data[key] = value.value
            
            await self.redis.setex(
                f"task:{task.task_id}",
                7200,  # 2 hours
                json.dumps(task_data, default=str)
            )
        except Exception as e:
            logger.warning(f"Failed to persist task to Redis: {e}")
    
    async def _update_task_in_redis(self, task_id: str, updates: Dict[str, Any]):
        """Update task in Redis"""
        if not self.redis:
            return
        
        try:
            key = f"task:{task_id}"
            existing_data = await self.redis.get(key)
            
            if existing_data:
                task_data = json.loads(existing_data)
                task_data.update(updates)
                await self.redis.setex(key, 7200, json.dumps(task_data, default=str))
        except Exception as e:
            logger.warning(f"Failed to update task in Redis: {e}")
    
    async def _get_task_from_redis(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task from Redis"""
        if not self.redis:
            return None
        
        try:
            key = f"task:{task_id}"
            data = await self.redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.warning(f"Failed to get task from Redis: {e}")
            return None
    
    async def _cleanup_loop(self):
        """Cleanup expired tasks"""
        while self._running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Clean up expired tasks
                expired_tasks = []
                for task_id, task in self.active_tasks.items():
                    if task.started_at and (current_time - task.started_at).total_seconds() > task.timeout:
                        expired_tasks.append(task_id)
                
                for task_id in expired_tasks:
                    logger.warning(f"Cleaning up expired task: {task_id}")
                    await self.complete_task(task_id, success=False, error="Task timeout")
                
                await asyncio.sleep(self.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in task cleanup loop: {e}")
                await asyncio.sleep(60)
    
    async def _metrics_loop(self):
        """Update task metrics"""
        while self._running:
            try:
                system_health = await self.resource_monitor.get_system_health()
                queue_stats = await self.get_queue_statistics()
                
                logger.info(
                    f"Task Queue Stats - Total Queued: {queue_stats['total_queued']}, "
                    f"Active: {queue_stats['active_tasks']}, "
                    f"Health: {system_health['overall']['status']}"
                )
                
                await asyncio.sleep(self.metrics_interval)
                
            except Exception as e:
                logger.error(f"Error in task metrics loop: {e}")
                await asyncio.sleep(60)


# Global instance
_enterprise_task_queue_manager: Optional[EnterpriseTaskQueueManager] = None


async def get_enterprise_task_queue_manager() -> EnterpriseTaskQueueManager:
    """Get or create the global task queue manager"""
    global _enterprise_task_queue_manager
    
    if _enterprise_task_queue_manager is None:
        try:
            from core.redis import get_redis_client
            redis_client = await get_redis_client()
        except Exception as e:
            logger.warning(f"Failed to get Redis client for tasks: {e}")
            redis_client = None
        
        _enterprise_task_queue_manager = EnterpriseTaskQueueManager(redis_client)
        await _enterprise_task_queue_manager.start()
    
    return _enterprise_task_queue_manager


async def shutdown_enterprise_task_queue_manager():
    """Shutdown the global task queue manager"""
    global _enterprise_task_queue_manager
    
    if _enterprise_task_queue_manager:
        await _enterprise_task_queue_manager.stop()
        _enterprise_task_queue_manager = None