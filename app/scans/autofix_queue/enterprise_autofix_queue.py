"""
Enterprise-Grade Autofix Queue Manager
Applies the same enterprise optimizations as the main scanning system to autofix processing.
Handles concurrent autofix requests with graceful degradation, user notifications, and resource management.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import psutil
import hashlib
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class AutofixPriority(Enum):
    """Autofix priority levels for enterprise queue management"""
    CRITICAL = 0     # Security incidents, urgent fixes
    HIGH = 1         # User-initiated auto-fixes
    NORMAL = 2       # Scheduled auto-fixes
    LOW = 3          # Background maintenance fixes


class AutofixStatus(Enum):
    """Enhanced autofix status tracking"""
    QUEUED = "queued"
    WAITING = "waiting"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class QueuedAutofix:
    """Enhanced autofix request with enterprise features"""
    autofix_id: str
    scan_id: str
    user_id: int
    repo_full_name: str
    priority: AutofixPriority
    autofix_config: Dict[str, Any]
    
    # Queue management
    queue_position: int = 0
    estimated_wait_time: int = 0  # seconds
    estimated_completion_time: Optional[datetime] = None
    
    # Status tracking
    status: AutofixStatus = AutofixStatus.QUEUED
    worker_id: Optional[str] = None
    started_at: Optional[datetime] = None
    queued_at: datetime = None
    
    # Enterprise features
    client_ip: Optional[str] = None
    user_tier: str = "free"  # free, pro, enterprise
    retry_count: int = 0
    max_retries: int = 3
    
    # Performance tracking
    queue_metrics: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.queued_at is None:
            self.queued_at = datetime.now(timezone.utc)
        if self.queue_metrics is None:
            self.queue_metrics = {}


class AutofixResourceMonitor:
    """Real-time resource monitoring for intelligent autofix queue management"""
    
    def __init__(self):
        self.cpu_threshold = 85.0  # CPU usage threshold
        self.memory_threshold = 85.0  # Memory usage threshold
        self.max_concurrent_autofixes = 25  # Dynamic limit (lower than scans)
        self.history_size = 60  # Keep 60 data points
        
        # Resource history for trend analysis
        self.cpu_history = []
        self.memory_history = []
        self.autofix_duration_history = []
        self.last_update = time.time()
        
    async def get_system_health(self) -> Dict[str, Any]:
        """Get comprehensive system health metrics"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Update history
            self.cpu_history.append(cpu_percent)
            self.memory_history.append(memory.percent)
            
            # Keep only recent history
            if len(self.cpu_history) > self.history_size:
                self.cpu_history.pop(0)
                self.memory_history.pop(0)
            
            # Calculate trends
            cpu_trend = self._calculate_trend(self.cpu_history)
            memory_trend = self._calculate_trend(self.memory_history)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Network stats
            network = psutil.net_io_counters()
            
            return {
                "cpu": {
                    "current": cpu_percent,
                    "average": sum(self.cpu_history) / len(self.cpu_history) if self.cpu_history else 0,
                    "trend": cpu_trend,
                    "healthy": cpu_percent < self.cpu_threshold
                },
                "memory": {
                    "current": memory.percent,
                    "available_gb": memory.available / (1024**3),
                    "trend": memory_trend,
                    "healthy": memory.percent < self.memory_threshold
                },
                "disk": {
                    "used_percent": disk.percent,
                    "free_gb": disk.free / (1024**3),
                    "healthy": disk.percent < 90
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get system health for autofix: {e}")
            return {
                "cpu": {"healthy": False, "error": str(e)},
                "memory": {"healthy": False, "error": str(e)},
                "disk": {"healthy": False, "error": str(e)},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction from recent values"""
        if len(values) < 3:
            return "stable"
        
        recent = values[-3:]
        if recent[-1] > recent[0] * 1.1:
            return "increasing"
        elif recent[-1] < recent[0] * 0.9:
            return "decreasing" 
        else:
            return "stable"
    
    def calculate_optimal_concurrency(self, current_autofixes: int) -> int:
        """Calculate optimal concurrent autofix limit based on system resources"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Base limit on CPU cores (lower than scans since autofixes are more intensive)
            cpu_cores = psutil.cpu_count()
            base_limit = max(4, cpu_cores)  # Lower base than scanning
            
            # Adjust for current resource usage
            cpu_factor = max(0.3, (100 - cpu_percent) / 100)
            memory_factor = max(0.3, (100 - memory.percent) / 100)
            
            # Calculate adjusted limit
            adjusted_limit = int(base_limit * cpu_factor * memory_factor)
            
            # Apply boundaries
            min_limit = 2  # Always allow at least 2 autofixes
            max_limit = 50  # Cap at 50 for safety
            
            optimal = max(min_limit, min(max_limit, adjusted_limit))
            
            logger.info(
                f"Autofix resource-based concurrency calculation: "
                f"CPU: {cpu_percent}%, Memory: {memory.percent}%, "
                f"Cores: {cpu_cores}, Optimal: {optimal}"
            )
            
            return optimal
            
        except Exception as e:
            logger.error(f"Failed to calculate optimal autofix concurrency: {e}")
            return 5  # Conservative fallback


class AutofixCircuitBreaker:
    """Circuit breaker for protecting against autofix system overload"""
    
    def __init__(self, failure_threshold: int = 3, timeout: int = 120):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        
    def can_execute(self) -> bool:
        """Check if autofix operations can proceed"""
        if self.state == "CLOSED":
            return True
        elif self.state == "OPEN":
            if time.time() - self.last_failure_time > self.timeout:
                self.state = "HALF_OPEN"
                return True
            return False
        else:  # HALF_OPEN
            return True
    
    def record_success(self):
        """Record successful autofix operation"""
        if self.state == "HALF_OPEN":
            self.state = "CLOSED"
        self.failure_count = 0
    
    def record_failure(self):
        """Record failed autofix operation"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status"""
        return {
            "state": self.state,
            "failure_count": self.failure_count,
            "failure_threshold": self.failure_threshold,
            "last_failure_time": self.last_failure_time,
            "timeout": self.timeout
        }


class EnterpriseAutofixQueueManager:
    """Enterprise-grade queue manager for concurrent autofix processing at scale"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        
        # DEBUG: Log Redis initialization status
        if self.redis:
            logger.info("✅ Enterprise Autofix Queue Manager initialized WITH Redis client")
        else:
            logger.warning("⚠️ Enterprise Autofix Queue Manager initialized WITHOUT Redis client - persistence disabled")
        
        # Queue management
        self.queues = {
            AutofixPriority.CRITICAL: asyncio.Queue(),
            AutofixPriority.HIGH: asyncio.Queue(),
            AutofixPriority.NORMAL: asyncio.Queue(),
            AutofixPriority.LOW: asyncio.Queue()
        }
        
        # Active autofixes tracking
        self.active_autofixes: Dict[str, QueuedAutofix] = {}
        self.worker_assignments: Dict[str, str] = {}  # worker_id -> autofix_id
        
        # Enterprise components
        self.resource_monitor = AutofixResourceMonitor()
        self.circuit_breaker = AutofixCircuitBreaker()
        
        # Configuration
        self.max_queue_size = 500  # Total queue size limit (lower than scans)
        self.max_user_queue_size = 5  # Per-user queue limit (lower than scans)
        self.cleanup_interval = 300  # 5 minutes
        self.metrics_interval = 60  # 1 minute
        
        # Metrics
        self.metrics = {
            "total_queued": 0,
            "total_processed": 0,
            "total_failed": 0,
            "average_queue_time": 0.0,
            "average_processing_time": 0.0,
            "peak_queue_size": 0,
            "user_queue_counts": {},
            "priority_distribution": {p.name: 0 for p in AutofixPriority}
        }
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.metrics_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("Enterprise Autofix Queue Manager initialized")
    
    async def start(self):
        """Start the autofix queue manager and background tasks"""
        self._running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.metrics_task = asyncio.create_task(self._metrics_loop())
        logger.info("Enterprise Autofix Queue Manager started")
    
    async def stop(self):
        """Stop the autofix queue manager gracefully"""
        self._running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if self.metrics_task:
            self.metrics_task.cancel()
        
        # Wait for active autofixes to complete (with timeout)
        if self.active_autofixes:
            logger.info(f"Waiting for {len(self.active_autofixes)} active autofixes to complete...")
            await asyncio.sleep(10)  # Give autofixes more time than scans
        
        logger.info("Enterprise Autofix Queue Manager stopped")
    
    async def enqueue_autofix(
        self,
        scan_id: str,
        user_id: int,
        repo_full_name: str,
        autofix_config: Dict[str, Any],
        priority: AutofixPriority = AutofixPriority.HIGH,
        client_ip: Optional[str] = None,
        user_tier: str = "free"
    ) -> Dict[str, Any]:
        """Enqueue an autofix with enterprise-grade queue management"""
        
        # Check circuit breaker
        if not self.circuit_breaker.can_execute():
            return {
                "success": False,
                "error": "Autofix system temporarily unavailable due to overload",
                "retry_after": 120,
                "circuit_breaker_state": self.circuit_breaker.state
            }
        
        try:
            # Generate unique autofix ID
            autofix_id = str(uuid.uuid4())
            
            # Check system capacity
            system_health = await self.resource_monitor.get_system_health()
            if not self._can_accept_request(system_health, user_tier):
                return {
                    "success": False,
                    "error": "Autofix system at capacity. Please try again later.",
                    "system_health": system_health,
                    "estimated_retry_time": 600  # 10 minutes
                }
            
            # Check per-user limits
            user_queue_count = self.metrics["user_queue_counts"].get(user_id, 0)
            max_user_autofixes = self._get_user_autofix_limit(user_tier)
            
            if user_queue_count >= max_user_autofixes:
                return {
                    "success": False,
                    "error": f"User autofix queue limit reached ({max_user_autofixes} autofixes)",
                    "user_tier": user_tier,
                    "current_queue_count": user_queue_count
                }
            
            # Create queued autofix
            queued_autofix = QueuedAutofix(
                autofix_id=autofix_id,
                scan_id=scan_id,
                user_id=user_id,
                repo_full_name=repo_full_name,
                priority=priority,
                autofix_config=autofix_config,
                client_ip=client_ip,
                user_tier=user_tier
            )
            
            # Calculate queue position and wait time
            queue_info = await self._calculate_queue_metrics(priority, user_tier)
            queued_autofix.queue_position = queue_info["position"]
            queued_autofix.estimated_wait_time = queue_info["wait_time"]
            queued_autofix.estimated_completion_time = queue_info["completion_time"]
            
            # Add to appropriate priority queue
            await self.queues[priority].put(queued_autofix)
            
            # Update metrics
            self.metrics["total_queued"] += 1
            self.metrics["priority_distribution"][priority.name] += 1
            self.metrics["user_queue_counts"][user_id] = user_queue_count + 1
            
            # Update peak queue size
            total_queued = sum(q.qsize() for q in self.queues.values())
            self.metrics["peak_queue_size"] = max(self.metrics["peak_queue_size"], total_queued)
            
            # Store in Redis for persistence
            await self._persist_autofix_to_redis(queued_autofix)
            
            self.circuit_breaker.record_success()
            
            logger.info(
                f"Autofix queued successfully: {autofix_id} for scan {scan_id}, "
                f"priority: {priority.name}, position: {queued_autofix.queue_position}"
            )
            
            return {
                "success": True,
                "autofix_id": autofix_id,
                "status": "queued",
                "queue_position": queued_autofix.queue_position,
                "estimated_wait_time": queued_autofix.estimated_wait_time,
                "estimated_completion_time": queued_autofix.estimated_completion_time.isoformat() if queued_autofix.estimated_completion_time else None,
                "priority": priority.name,
                "message": "Autofix queued successfully. You will be notified when processing begins.",
                "queue_info": queue_info
            }
            
        except Exception as e:
            logger.error(f"Failed to enqueue autofix: {e}")
            self.circuit_breaker.record_failure()
            return {
                "success": False,
                "error": f"Failed to queue autofix: {str(e)}",
                "autofix_id": None
            }
    
    async def get_next_autofix(self, worker_id: str) -> Optional[QueuedAutofix]:
        """Get the next autofix for processing (priority-based)"""
        
        # Check if worker can handle more autofixes
        current_load = len([a for a in self.active_autofixes.values() if a.worker_id == worker_id])
        if current_load >= 2:  # Max 2 autofixes per worker (more intensive)
            return None
        
        # Try each priority queue in order
        for priority in AutofixPriority:
            queue = self.queues[priority]
            
            try:
                # Non-blocking get
                autofix = queue.get_nowait()
                
                # Update autofix status
                autofix.status = AutofixStatus.PROCESSING
                autofix.worker_id = worker_id
                autofix.started_at = datetime.now(timezone.utc)
                
                # Track active autofix
                self.active_autofixes[autofix.autofix_id] = autofix
                self.worker_assignments[worker_id] = autofix.autofix_id
                
                # Update user queue count
                user_id = autofix.user_id
                if user_id in self.metrics["user_queue_counts"]:
                    self.metrics["user_queue_counts"][user_id] -= 1
                
                # Calculate queue time
                if autofix.queued_at:
                    queue_time = (autofix.started_at - autofix.queued_at).total_seconds()
                    self._update_average_time("queue_time", queue_time)
                
                logger.info(f"Assigned autofix {autofix.autofix_id} to worker {worker_id}")
                return autofix
                
            except asyncio.QueueEmpty:
                continue
        
        return None
    
    async def complete_autofix(
        self,
        autofix_id: str,
        success: bool = True,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """Mark an autofix as completed"""
        
        if autofix_id not in self.active_autofixes:
            logger.warning(f"Attempted to complete unknown autofix: {autofix_id}")
            return
        
        autofix = self.active_autofixes[autofix_id]
        
        # Update autofix status
        autofix.status = AutofixStatus.COMPLETED if success else AutofixStatus.FAILED
        completion_time = datetime.now(timezone.utc)
        
        # Calculate processing time
        if autofix.started_at:
            processing_time = (completion_time - autofix.started_at).total_seconds()
            self._update_average_time("processing_time", processing_time)
        
        # Update metrics
        if success:
            self.metrics["total_processed"] += 1
        else:
            self.metrics["total_failed"] += 1
        
        # Clean up
        del self.active_autofixes[autofix_id]
        if autofix.worker_id and autofix.worker_id in self.worker_assignments:
            del self.worker_assignments[autofix.worker_id]
        
        # Store completion in Redis
        await self._update_autofix_in_redis(autofix_id, {
            "status": autofix.status.value,
            "completed_at": completion_time.isoformat(),
            "success": success,
            "result": result,
            "error": error
        })
        
        logger.info(f"Autofix {autofix_id} completed: {'success' if success else 'failed'}")
    
    async def get_autofix_status(self, autofix_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed status of an autofix"""
        
        logger.debug(f"get_autofix_status called for {autofix_id}")
        logger.info(f"DEBUG get_autofix_status: checking autofix_id={autofix_id}, active_autofixes={list(self.active_autofixes.keys())}")
        
        # Check active autofixes first
        if autofix_id in self.active_autofixes:
            logger.info(f"🔥 FOUND ACTIVE AUTOFIX: {autofix_id} in active_autofixes")
            autofix = self.active_autofixes[autofix_id]
            
            # CRITICAL FIX: Check Redis for real-time progress updates even for active jobs
            progress_data = {}
            if self.redis:
                try:
                    progress_key = f"autofix_progress:{autofix_id}"
                    progress_raw = await self.redis.get(progress_key)
                    progress_data = json.loads(progress_raw) if progress_raw else {}
                    logger.debug(f"Retrieved progress data for active job {autofix_id}: {progress_data}")
                except Exception as e:
                    logger.warning(f"Failed to get progress data for active autofix {autofix_id}: {e}")
            
            # Use progress data if available, otherwise defaults
            final_progress = progress_data.get("progress", 0)
            final_message = progress_data.get("message", "Processing...")
            
            logger.debug(f"Active job {autofix_id} returning progress={final_progress}, message='{final_message}'")
            
            return {
                "job_id": autofix_id,
                "autofix_id": autofix_id,
                "status": autofix.status.value,
                "progress": final_progress,
                "message": final_message,
                "queue_position": 0,  # Active autofixes are not in queue
                "estimated_wait_time": 0,
                "started_at": autofix.started_at.isoformat() if autofix.started_at else None,
                "worker_id": autofix.worker_id,
                "processing_time": (datetime.now(timezone.utc) - autofix.started_at).total_seconds() if autofix.started_at else 0,
                "updated_at": progress_data.get("updated_at"),
                "scan_id": autofix.scan_id,
                "created_at": autofix.queued_at.isoformat() if autofix.queued_at else None,
                "completed_at": None,
                "failed_at": None,
                "cancelled_at": None,
                "result": {},
                "error_message": None
            }
        
        # Check Redis for completed autofixes
        return await self._get_autofix_from_redis(autofix_id)
    
    async def get_queue_statistics(self) -> Dict[str, Any]:
        """Get comprehensive autofix queue statistics"""
        
        system_health = await self.resource_monitor.get_system_health()
        
        # Current queue sizes by priority
        queue_sizes = {
            priority.name: queue.qsize()
            for priority, queue in self.queues.items()
        }
        
        # Active autofix information
        active_autofixes_info = []
        for autofix in self.active_autofixes.values():
            active_autofixes_info.append({
                "autofix_id": autofix.autofix_id,
                "scan_id": autofix.scan_id,
                "repo": autofix.repo_full_name,
                "priority": autofix.priority.name,
                "worker_id": autofix.worker_id,
                "processing_time": (datetime.now(timezone.utc) - autofix.started_at).total_seconds() if autofix.started_at else 0
            })
        
        return {
            "queue_sizes": queue_sizes,
            "total_queued": sum(queue_sizes.values()),
            "active_autofixes": len(self.active_autofixes),
            "active_autofixes_info": active_autofixes_info,
            "system_health": system_health,
            "circuit_breaker": self.circuit_breaker.get_status(),
            "metrics": self.metrics,
            "capacity": {
                "max_concurrent": self.resource_monitor.calculate_optimal_concurrency(len(self.active_autofixes)),
                "current_utilization": len(self.active_autofixes)
            }
        }
    
    def _can_accept_request(self, system_health: Dict[str, Any], user_tier: str) -> bool:
        """Check if system can accept new autofix requests"""
        
        # Check system health thresholds
        if not system_health.get("cpu", {}).get("healthy", False):
            return False
        if not system_health.get("memory", {}).get("healthy", False):
            return False
        
        # Check total queue size
        total_queued = sum(q.qsize() for q in self.queues.values())
        if total_queued >= self.max_queue_size:
            return False
        
        # Premium users get priority during high load
        if user_tier in ["pro", "enterprise"]:
            return total_queued < self.max_queue_size * 0.9
        
        # Free tier has more restrictions during high load
        cpu_usage = system_health.get("cpu", {}).get("current", 0)
        if cpu_usage > 75 and total_queued > self.max_queue_size * 0.4:  # Stricter than scans
            return False
        
        return True
    
    def _get_user_autofix_limit(self, user_tier: str) -> int:
        """Get autofix limit based on user tier"""
        limits = {
            "free": 2,      # Lower than scans
            "pro": 8,       # Lower than scans
            "enterprise": 25  # Lower than scans
        }
        return limits.get(user_tier, 2)
    
    async def _calculate_queue_metrics(self, priority: AutofixPriority, user_tier: str) -> Dict[str, Any]:
        """Calculate queue position and estimated wait time"""
        
        # Count autofixes with higher or equal priority
        position = 0
        for p in AutofixPriority:
            if p.value <= priority.value:
                position += self.queues[p].qsize()
        
        # Estimate wait time based on processing history (autofixes take longer)
        avg_processing_time = self.metrics.get("average_processing_time", 900)  # 15 minutes default
        concurrent_capacity = self.resource_monitor.calculate_optimal_concurrency(len(self.active_autofixes))
        
        # Calculate estimated wait time
        estimated_wait = (position / max(1, concurrent_capacity)) * avg_processing_time
        
        # Premium users get priority
        if user_tier in ["pro", "enterprise"]:
            estimated_wait *= 0.8  # 20% faster processing
        
        completion_time = datetime.now(timezone.utc) + timedelta(seconds=estimated_wait)
        
        return {
            "position": position,
            "wait_time": int(estimated_wait),
            "completion_time": completion_time,
            "concurrent_capacity": concurrent_capacity
        }
    
    def _update_average_time(self, metric_type: str, new_time: float):
        """Update average time metrics using exponential smoothing"""
        alpha = 0.1  # Smoothing factor
        current_avg = self.metrics.get(f"average_{metric_type}", new_time)
        self.metrics[f"average_{metric_type}"] = alpha * new_time + (1 - alpha) * current_avg
    
    async def _persist_autofix_to_redis(self, autofix: QueuedAutofix):
        """Persist autofix information to Redis"""
        if not self.redis:
            return
        
        try:
            autofix_data = asdict(autofix)
            # Convert datetime objects to strings
            for key, value in autofix_data.items():
                if isinstance(value, datetime):
                    autofix_data[key] = value.isoformat()
                elif isinstance(value, AutofixPriority):
                    autofix_data[key] = value.name
                elif isinstance(value, AutofixStatus):
                    autofix_data[key] = value.value
            
            await self.redis.setex(
                f"autofix:{autofix.autofix_id}",
                7200,  # 2 hours TTL (longer than scans)
                json.dumps(autofix_data, default=str)
            )
        except Exception as e:
            logger.warning(f"Failed to persist autofix to Redis: {e}")
    
    async def _update_autofix_in_redis(self, autofix_id: str, updates: Dict[str, Any]):
        """Update autofix information in Redis"""
        if not self.redis:
            return
        
        try:
            key = f"autofix:{autofix_id}"
            existing_data = await self.redis.get(key)
            
            if existing_data:
                autofix_data = json.loads(existing_data)
                autofix_data.update(updates)
                await self.redis.setex(key, 7200, json.dumps(autofix_data, default=str))
        except Exception as e:
            logger.warning(f"Failed to update autofix in Redis: {e}")
    
    async def _attempt_redis_reconnection(self) -> None:
        """Attempt to reconnect to Redis if connection was lost"""
        try:
            import sys
            import os
            
            # Add proper path for core module
            backend_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            if backend_path not in sys.path:
                sys.path.insert(0, backend_path)
            
            from core.redis import get_redis_client
            redis_client = await get_redis_client()
            
            if redis_client:
                self.redis = redis_client
                logger.info("✅ Redis reconnection successful for autofix queue")
            else:
                logger.warning("⚠️ Redis reconnection failed - client still None")
                
        except Exception as e:
            logger.error(f"Redis reconnection attempt failed: {e}")
    
    async def _get_autofix_from_redis(self, autofix_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve autofix information from Redis with backward compatibility"""
        if not self.redis:
            logger.warning(f"Redis not available for autofix {autofix_id}")
            return None
        
        return await self._get_autofix_from_redis_inner(autofix_id)
    
    async def _get_autofix_from_redis_inner(self, autofix_id: str) -> Optional[Dict[str, Any]]:
        """Inner Redis retrieval method (separated for retry logic)"""
        try:
            # First try new enterprise format
            key = f"autofix:{autofix_id}"
            data = await self.redis.get(key)
            if data:
                job_data = json.loads(data)
                
                # CRITICAL FIX: Always get progress data to ensure it's available throughout the method
                progress_key = f"autofix_progress:{autofix_id}"
                progress_raw = await self.redis.get(progress_key)
                progress_data = json.loads(progress_raw) if progress_raw else {}
                logger.debug(f"Retrieved progress_raw for {autofix_id}: {progress_raw}")
                logger.debug(f"Parsed progress_data for {autofix_id}: {progress_data}")
                
                # Get results data
                results_key = f"autofix_results:{autofix_id}"
                results_raw = await self.redis.get(results_key)
                results_data = json.loads(results_raw) if results_raw else {}
                
                # If this is basic job metadata, we need to enrich it with progress/results data
                # Check if this has completion data, if not, get it from other keys
                if not job_data.get("result") or not isinstance(job_data.get("result"), dict) or not job_data.get("result", {}).get("pr_url"):
                    # If we have rich progress data for completed jobs, merge it
                    if progress_data and job_data.get("status") == "completed":
                        # Enhance the result data with progress info
                        if isinstance(job_data.get("result"), dict):
                            result_data = job_data["result"]
                            
                            # Add rich fields from progress data
                            if progress_data.get("pr_url"):
                                result_data["pr_url"] = progress_data["pr_url"]
                            if progress_data.get("fixed_count") is not None:
                                result_data["fixed_count"] = progress_data["fixed_count"]
                            if progress_data.get("fixed_files"):
                                result_data["fixed_files"] = progress_data["fixed_files"]
                            if progress_data.get("issues_found") is not None:
                                result_data["issues_found"] = progress_data["issues_found"]
                            if progress_data.get("metrics"):
                                result_data["metrics"] = progress_data["metrics"]
                            if progress_data.get("message"):
                                result_data["message"] = progress_data["message"]
                            
                            job_data["result"] = result_data
                        
                        # Update progress and message from progress data
                        if progress_data.get("progress") is not None:
                            job_data["progress"] = progress_data["progress"]
                        if progress_data.get("message"):
                            job_data["message"] = progress_data["message"]
                
                # Convert to expected API format
                # CRITICAL FIX: For completed jobs, ensure progress is 100 and rich result data is included
                if job_data.get("status") == "completed":
                    result_data = job_data.get("result", {})
                    
                    # Enhance result with progress data for completed jobs
                    if progress_data:
                        if progress_data.get("pr_url") and not result_data.get("pr_url"):
                            result_data["pr_url"] = progress_data["pr_url"]
                        if progress_data.get("fixed_count") is not None and not result_data.get("fixed_count"):
                            result_data["fixed_count"] = progress_data["fixed_count"]
                        if progress_data.get("fixed_files") and not result_data.get("fixed_files"):
                            result_data["fixed_files"] = progress_data["fixed_files"]
                        if progress_data.get("issues_found") is not None and not result_data.get("issues_found"):
                            result_data["issues_found"] = progress_data["issues_found"]
                        if progress_data.get("metrics") and not result_data.get("metrics"):
                            result_data["metrics"] = progress_data["metrics"]
                        if progress_data.get("message") and not result_data.get("message"):
                            result_data["message"] = progress_data["message"]
                        if progress_data.get("worker_id") and not result_data.get("worker_id"):
                            result_data["worker_id"] = progress_data["worker_id"]
                    
                    return {
                        "job_id": autofix_id,
                        "status": "completed",
                        "progress": 100,  # FIXED: Always 100 for completed jobs
                        "message": progress_data.get("message", "Auto-fix completed successfully!") if progress_data else "Auto-fix completed successfully!",
                        "scan_id": job_data.get("scan_id"),
                        "repo_full_name": job_data.get("repo_full_name"),
                        "branch": job_data.get("autofix_config", {}).get("scan_data", {}).get("branch"),
                        "user_id": job_data.get("user_id"),
                        "created_at": job_data.get("queued_at"),
                        "started_at": job_data.get("started_at"),
                        "completed_at": job_data.get("completed_at"),
                        "failed_at": job_data.get("failed_at"),
                        "cancelled_at": job_data.get("cancelled_at"),
                        "updated_at": progress_data.get("updated_at") if progress_data else None,
                        "worker_id": result_data.get("worker_id", job_data.get("worker_id")),
                        "queue_position": 0,  # Completed jobs are not in queue
                        "result": result_data,
                        "error_message": job_data.get("error"),
                        "estimated_duration": None,
                        "priority": job_data.get("priority", "normal").lower(),
                        "severity_filter": job_data.get("autofix_config", {}).get("severity_filter", []),
                        "create_pr": job_data.get("autofix_config", {}).get("create_pr", True)
                    }
                else:
                    # Non-completed jobs
                    return {
                        "job_id": autofix_id,
                        "status": job_data.get("status", "unknown"),
                        "progress": progress_data.get("progress", 0) if progress_data else 0,
                        "message": progress_data.get("message", "Processing...") if progress_data else "Processing...",
                        "scan_id": job_data.get("scan_id"),
                        "repo_full_name": job_data.get("repo_full_name"),
                        "branch": job_data.get("autofix_config", {}).get("scan_data", {}).get("branch"),
                        "user_id": job_data.get("user_id"),
                        "created_at": job_data.get("queued_at"),
                        "started_at": job_data.get("started_at"),
                        "completed_at": job_data.get("completed_at"),
                        "failed_at": job_data.get("failed_at"),
                        "cancelled_at": job_data.get("cancelled_at"),
                        "updated_at": progress_data.get("updated_at") if progress_data else None,
                        "worker_id": job_data.get("worker_id"),
                        "queue_position": job_data.get("queue_position", 0),
                        "result": job_data.get("result", {}),
                        "error_message": job_data.get("error"),
                        "estimated_duration": None,
                        "priority": job_data.get("priority", "normal").lower(),
                        "severity_filter": job_data.get("autofix_config", {}).get("severity_filter", []),
                        "create_pr": job_data.get("autofix_config", {}).get("create_pr", True)
                    }
            
            # BACKWARD COMPATIBILITY: Try old autofix queue formats
            # Check for results first (completed jobs) - these are JSON strings
            results_key = f"autofix_results:{autofix_id}"
            results_raw = await self.redis.get(results_key)
            results_data = json.loads(results_raw) if results_raw else {}
            
            # Check for progress data (might have status info) - also JSON strings
            progress_key = f"autofix_progress:{autofix_id}"
            progress_raw = await self.redis.get(progress_key)
            progress_data = json.loads(progress_raw) if progress_raw else {}
            logger.debug(f"Legacy fallback - progress_raw for {autofix_id}: {progress_raw}")
            logger.debug(f"Legacy fallback - progress_data for {autofix_id}: {progress_data}")
            
            # If we have either results or progress, construct compatible response
            if results_data or progress_data:
                # Merge data with priority to results
                merged_data = {}
                merged_data.update(progress_data)
                merged_data.update(results_data)
                
                # Extract and enhance result data for frontend compatibility
                result_data = merged_data.get("result", merged_data.get("output", {}))
                if isinstance(result_data, dict):
                    # Enrich result data with fields from progress_data for completed jobs
                    if progress_data and merged_data.get("status") == "completed":
                        # Add all the rich fields from progress data
                        if progress_data.get("pr_url"):
                            result_data["pr_url"] = progress_data["pr_url"]
                        if progress_data.get("fixed_count") is not None:
                            result_data["fixed_count"] = progress_data["fixed_count"]
                        if progress_data.get("fixed_files"):
                            result_data["fixed_files"] = progress_data["fixed_files"]
                        if progress_data.get("issues_found") is not None:
                            result_data["issues_found"] = progress_data["issues_found"]
                        if progress_data.get("metrics"):
                            result_data["metrics"] = progress_data["metrics"]
                        if progress_data.get("message"):
                            result_data["message"] = progress_data["message"]
                        if progress_data.get("worker_id"):
                            result_data["worker_id"] = progress_data["worker_id"]
                
                # Convert to expected format
                # CRITICAL FIX: Ensure completed jobs show progress 100 and proper status
                final_status = merged_data.get("status", "completed" if results_data else "unknown")
                final_progress = int(merged_data.get("progress", 100 if final_status == "completed" else 0))
                final_message = merged_data.get("message", merged_data.get("status_message", "Auto-fix completed successfully!" if final_status == "completed" else "Processing..."))
                
                status_info = {
                    "job_id": autofix_id,  # Frontend expects job_id, not autofix_id
                    "status": final_status,
                    "progress": final_progress,
                    "message": final_message,
                    "scan_id": merged_data.get("scan_id"),
                    "repo_full_name": merged_data.get("repo_full_name"),
                    "branch": merged_data.get("branch"),
                    "user_id": merged_data.get("user_id"),
                    "created_at": merged_data.get("created_at", merged_data.get("queued_at")),
                    "started_at": merged_data.get("started_at"),
                    "completed_at": merged_data.get("completed_at", merged_data.get("end_time")),
                    "failed_at": merged_data.get("failed_at"),
                    "cancelled_at": merged_data.get("cancelled_at"),
                    "updated_at": merged_data.get("updated_at"),
                    "worker_id": merged_data.get("worker_id"),
                    "queue_position": 0,  # Legacy jobs are no longer in queue
                    "result": result_data,
                    "error_message": merged_data.get("error_message"),
                    "estimated_duration": merged_data.get("estimated_duration"),
                    "priority": merged_data.get("priority", "normal"),
                    "severity_filter": merged_data.get("severity_filter", []),
                    "create_pr": merged_data.get("create_pr", True)
                }
                
                logger.info(f"Retrieved legacy autofix data for {autofix_id}: status={status_info['status']}")
                return status_info
            
            return None
            
        except Exception as e:
            logger.warning(f"Failed to get autofix from Redis: {e}")
            # Try to reconnect Redis on failure
            if "redis" in str(e).lower() or "connection" in str(e).lower():
                logger.info(f"Redis connection issue detected, attempting reconnection for job {autofix_id}")
                await self._attempt_redis_reconnection()
                # Retry once after reconnection
                if self.redis:
                    try:
                        return await self._get_autofix_from_redis_inner(autofix_id)
                    except Exception as retry_e:
                        logger.error(f"Retry failed for {autofix_id}: {retry_e}")
            return None
    
    # COMPATIBILITY METHODS FOR ROUTES.PY
    # These methods provide compatibility with the basic autofix queue interface
    
    async def enqueue_autofix_job(
        self,
        scan_id: str,
        user_id: int,
        repo_full_name: str,
        autofix_data: Dict[str, Any],
        priority: AutofixPriority = AutofixPriority.HIGH,
        db: Optional[AsyncSession] = None
    ) -> str:
        """
        Compatibility method for routes.py - enqueue an autofix job
        Maps to the enterprise enqueue_autofix method
        """
        result = await self.enqueue_autofix(
            scan_id=scan_id,
            user_id=user_id,
            repo_full_name=repo_full_name,
            autofix_config=autofix_data,
            priority=priority,
            client_ip=None,  # Could get from request context if needed
            user_tier="free"  # Could get from user model if needed
        )
        
        if result.get("success"):
            return result["autofix_id"]
        else:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=503,
                detail=result.get("error", "Failed to enqueue autofix job")
            )
    
    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Compatibility method for routes.py - get job status
        Maps to the enterprise get_autofix_status method
        """
        
        logger.debug(f"get_job_status called for {job_id}")
        
        # If Redis is not available, try to reconnect before giving up
        if not self.redis:
            logger.warning(f"Redis client not available for job {job_id}, attempting to reconnect...")
            await self._attempt_redis_reconnection()
        
        return await self.get_autofix_status(job_id)
    
    async def cancel_job(self, job_id: str, db: Optional[AsyncSession] = None) -> bool:
        """
        Compatibility method for routes.py - cancel a job
        """
        try:
            # Check if autofix is in active processing
            if job_id in self.active_autofixes:
                autofix = self.active_autofixes[job_id]
                autofix.status = AutofixStatus.CANCELLED
                
                # Move to completed
                await self.complete_autofix(job_id, success=False, error="Cancelled by user")
                logger.info(f"Cancelled active autofix: {job_id}")
                return True
            
            # Check if autofix is in queue and remove it
            for priority, queue in self.queues.items():
                temp_items = []
                cancelled = False
                
                # Drain queue and check each item
                while not queue.empty():
                    try:
                        autofix = queue.get_nowait()
                        if autofix.autofix_id == job_id:
                            autofix.status = AutofixStatus.CANCELLED
                            cancelled = True
                            logger.info(f"Cancelled queued autofix: {job_id}")
                        else:
                            temp_items.append(autofix)
                    except asyncio.QueueEmpty:
                        break
                
                # Put back non-cancelled items
                for item in temp_items:
                    await queue.put(item)
                
                if cancelled:
                    # Update Redis with cancelled status
                    if self.redis:
                        await self.redis.hset(
                            f"autofix:{job_id}",
                            mapping={
                                "status": AutofixStatus.CANCELLED.value,
                                "cancelled_at": datetime.now(timezone.utc).isoformat(),
                                "error": "Cancelled by user"
                            }
                        )
                    return True
            
            logger.warning(f"Autofix job not found for cancellation: {job_id}")
            return False
            
        except Exception as e:
            logger.error(f"Error cancelling autofix job {job_id}: {e}")
            return False
    
    async def get_user_jobs(self, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Compatibility method for routes.py - get user's autofix jobs
        """
        try:
            jobs = []
            
            # Get jobs from Redis (completed/failed jobs)
            if self.redis:
                pattern = f"autofix:*"
                async for key in self.redis.scan_iter(match=pattern):
                    try:
                        job_data = await self.redis.hgetall(key)
                        if job_data and int(job_data.get("user_id", 0)) == user_id:
                            jobs.append({
                                "job_id": job_data.get("autofix_id"),
                                "scan_id": job_data.get("scan_id"),
                                "repo_full_name": job_data.get("repo_full_name"),
                                "status": job_data.get("status"),
                                "created_at": job_data.get("queued_at"),
                                "completed_at": job_data.get("completed_at"),
                                "error": job_data.get("error")
                            })
                    except Exception as e:
                        logger.debug(f"Error processing job data from {key}: {e}")
                        continue
            
            # Also check active autofixes
            for autofix_id, autofix in self.active_autofixes.items():
                if autofix.user_id == user_id:
                    jobs.append({
                        "job_id": autofix_id,
                        "scan_id": autofix.scan_id,
                        "repo_full_name": autofix.repo_full_name,
                        "status": autofix.status.value,
                        "created_at": autofix.queued_at.isoformat() if autofix.queued_at else None,
                        "started_at": autofix.started_at.isoformat() if autofix.started_at else None,
                        "worker_id": autofix.worker_id
                    })
            
            # Sort by creation time and limit
            jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return jobs[:limit]
            
        except Exception as e:
            logger.error(f"Error getting user jobs for user {user_id}: {e}")
            return []
    
    async def get_queue_stats(self) -> Dict[str, int]:
        """
        Compatibility method for routes.py - get queue statistics
        Maps to simplified version of get_queue_statistics
        """
        try:
            full_stats = await self.get_queue_statistics()
            
            # Return simplified stats matching basic queue format
            return {
                "total_queued": full_stats.get("total_queued", 0),
                "active_jobs": full_stats.get("active_autofixes", 0),
                "completed_today": full_stats.get("completed_today", 0),
                "failed_today": full_stats.get("failed_today", 0)
            }
        except Exception as e:
            logger.error(f"Error getting queue stats: {e}")
            return {
                "total_queued": 0,
                "active_jobs": 0,
                "completed_today": 0,
                "failed_today": 0
            }
    
    async def dequeue_job(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """
        Compatibility method for autofix workers - dequeue a job for processing
        Maps to the enterprise get_next_autofix method
        """
        try:
            autofix = await self.get_next_autofix(worker_id)
            
            if autofix:
                # Convert QueuedAutofix to dict format expected by workers
                return {
                    "id": autofix.autofix_id,
                    "scan_id": autofix.scan_id,
                    "user_id": autofix.user_id,
                    "repo_full_name": autofix.repo_full_name,
                    "autofix_data": autofix.autofix_config,
                    "status": autofix.status.value,
                    "created_at": autofix.queued_at.isoformat() if autofix.queued_at else None,
                    "worker_id": worker_id
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error dequeuing job for worker {worker_id}: {e}")
            return None
    
    async def update_job_progress(self, job_id: str, progress: int, message: str = None):
        """
        Compatibility method for autofix workers - update job progress
        This method stores progress in Redis for real-time tracking
        """
        try:
            if not self.redis:
                logger.warning(f"Redis not available for progress update: {job_id}")
                return
                
            progress_data = {
                "progress": progress,
                "message": message or f"Progress: {progress}%",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Store progress data in Redis
            progress_key = f"autofix_progress:{job_id}"
            await self.redis.setex(
                progress_key,
                7200,  # 2 hours TTL
                json.dumps(progress_data)
            )
            
            logger.debug(f"Updated progress for job {job_id}: {progress}% - {message}")
            
        except Exception as e:
            logger.error(f"Failed to update progress for job {job_id}: {e}")
    
    async def mark_job_completed(self, job_id: str, result: Dict[str, Any], db: Optional[AsyncSession] = None):
        """
        Compatibility method for autofix workers - mark job as completed
        """
        try:
            await self.complete_autofix(job_id, success=True, result=result)
            logger.info(f"Marked autofix job {job_id} as completed")
            
        except Exception as e:
            logger.error(f"Failed to mark job {job_id} as completed: {e}")
    
    async def mark_job_failed(self, job_id: str, error_msg: str, retry: bool = True, db: Optional[AsyncSession] = None):
        """
        Compatibility method for autofix workers - mark job as failed
        """
        try:
            await self.complete_autofix(job_id, success=False, error=error_msg)
            logger.info(f"Marked autofix job {job_id} as failed: {error_msg}")
            
        except Exception as e:
            logger.error(f"Failed to mark job {job_id} as failed: {e}")
    
    async def _cleanup_loop(self):
        """Background task for cleaning up expired autofixes"""
        while self._running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Clean up old active autofixes (timeout after 2 hours)
                expired_autofixes = []
                for autofix_id, autofix in self.active_autofixes.items():
                    if autofix.started_at and (current_time - autofix.started_at).total_seconds() > 7200:
                        expired_autofixes.append(autofix_id)
                
                for autofix_id in expired_autofixes:
                    logger.warning(f"Cleaning up expired autofix: {autofix_id}")
                    await self.complete_autofix(autofix_id, success=False, error="Autofix timeout")
                
                # Reset user queue counts periodically
                self.metrics["user_queue_counts"] = {
                    user_id: max(0, count - 1)
                    for user_id, count in self.metrics["user_queue_counts"].items()
                    if count > 0
                }
                
                await asyncio.sleep(self.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in autofix cleanup loop: {e}")
                await asyncio.sleep(60)
    
    async def _metrics_loop(self):
        """Background task for updating autofix metrics"""
        while self._running:
            try:
                # Update system metrics
                system_health = await self.resource_monitor.get_system_health()
                
                # Log queue statistics
                queue_stats = await self.get_queue_statistics()
                logger.info(
                    f"Autofix Queue Stats - Total: {queue_stats['total_queued']}, "
                    f"Active: {queue_stats['active_autofixes']}, "
                    f"CPU: {system_health.get('cpu', {}).get('current', 0):.1f}%, "
                    f"Memory: {system_health.get('memory', {}).get('current', 0):.1f}%"
                )
                
                await asyncio.sleep(self.metrics_interval)
                
            except Exception as e:
                logger.error(f"Error in autofix metrics loop: {e}")
                await asyncio.sleep(60)


# Global instance
_enterprise_autofix_queue_manager: Optional[EnterpriseAutofixQueueManager] = None


async def get_enterprise_autofix_queue_manager() -> EnterpriseAutofixQueueManager:
    """Get or create the global enterprise autofix queue manager"""
    global _enterprise_autofix_queue_manager
    
    if _enterprise_autofix_queue_manager is None:
        # Import Redis client to ensure persistence works
        try:
            import sys
            import os
            
            # Add proper path for core module
            backend_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            if backend_path not in sys.path:
                sys.path.insert(0, backend_path)
            
            from core.redis import get_redis_client
            redis_client = await get_redis_client()
            
            if redis_client:
                logger.info("✅ Redis client initialized successfully for autofix queue")
            else:
                logger.warning("⚠️ Redis client not available, autofix persistence disabled")
            
            _enterprise_autofix_queue_manager = EnterpriseAutofixQueueManager(redis_client=redis_client)
            await _enterprise_autofix_queue_manager.start()
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis client for autofix queue: {e}")
            
            # Try multiple times with exponential backoff before giving up
            redis_client = None
            for attempt in range(3):
                try:
                    await asyncio.sleep(2 ** attempt)  # 1s, 2s, 4s delays
                    logger.info(f"Redis reconnection attempt {attempt + 1}/3...")
                    redis_client = await get_redis_client()
                    if redis_client:
                        logger.info(f"✅ Redis reconnection successful on attempt {attempt + 1}")
                        break
                except Exception as retry_e:
                    logger.warning(f"Redis reconnection attempt {attempt + 1} failed: {retry_e}")
            
            if not redis_client:
                logger.critical("❌ CRITICAL: Failed to connect to Redis after 3 attempts. Autofix status endpoint will not work!")
            
            # Create manager with whatever Redis client we have (could be None)
            _enterprise_autofix_queue_manager = EnterpriseAutofixQueueManager(redis_client=redis_client)
            await _enterprise_autofix_queue_manager.start()
    
    return _enterprise_autofix_queue_manager


async def shutdown_enterprise_autofix_queue_manager():
    """Shutdown the global enterprise autofix queue manager"""
    global _enterprise_autofix_queue_manager
    
    if _enterprise_autofix_queue_manager:
        await _enterprise_autofix_queue_manager.stop()
        _enterprise_autofix_queue_manager = None


async def reset_enterprise_autofix_queue_manager():
    """Reset the global enterprise autofix queue manager to force reinitialization with Redis"""
    global _enterprise_autofix_queue_manager
    
    logger.info("🔄 Forcing reset of enterprise autofix queue manager for Redis fix")
    
    if _enterprise_autofix_queue_manager:
        await _enterprise_autofix_queue_manager.stop()
        _enterprise_autofix_queue_manager = None
        logger.info("✅ Old queue manager stopped and reset")
    
    # Force recreation with Redis client
    return await get_enterprise_autofix_queue_manager()