"""
⚠️ DEPRECATED: Enterprise-Grade Concurrent Scanning Queue Manager

WARNING: This queue system is deprecated in favor of the Fortress Unified Queue System.
Please use USE_FORTRESS_QUEUES=true instead of USE_ENTERPRISE_QUEUES=true.

The Fortress system provides:
- Simpler architecture with direct polling (no pub/sub complexity)
- Better reliability and faster scan processing  
- Unified job handling for all scan types
- Single queue system that replaces all fragmented components

Migration: Set USE_FORTRESS_QUEUES=true in your environment configuration.

Legacy Features (still supported but deprecated):
Handles 100+ concurrent scan requests with graceful degradation, user notifications, and resource management.
Designed for production scale like major tech companies (GitHub, GitLab, Snyk).
"""

import asyncio
import json
import logging
import time
import uuid
import warnings
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import psutil
import hashlib

logger = logging.getLogger(__name__)

# Issue deprecation warning at module level
warnings.warn(
    "Enterprise Queue Manager is deprecated. Please use USE_FORTRESS_QUEUES=true instead of USE_ENTERPRISE_QUEUES=true. "
    "The Fortress system provides better reliability and simpler architecture.",
    DeprecationWarning,
    stacklevel=2
)


class ScanPriority(Enum):
    """Scan priority levels for enterprise queue management"""
    CRITICAL = 0     # Security incidents, production issues
    HIGH = 1         # PR scans, scheduled security checks
    NORMAL = 2       # Manual scans, dashboard requests  
    LOW = 3          # Bulk operations, background scans


class ScanStatus(Enum):
    """Enhanced scan status tracking"""
    QUEUED = "queued"
    WAITING = "waiting"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class QueuedScan:
    """Enhanced scan request with enterprise features"""
    scan_id: str
    user_id: int
    repo_full_name: str
    priority: ScanPriority
    scan_type: str
    scan_config: Dict[str, Any]
    
    # Queue management
    queue_position: int = 0
    estimated_wait_time: int = 0  # seconds
    estimated_completion_time: Optional[datetime] = None
    
    # Status tracking
    status: ScanStatus = ScanStatus.QUEUED
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


class ResourceMonitor:
    """Real-time resource monitoring for intelligent queue management"""
    
    def __init__(self):
        self.cpu_threshold = 85.0  # CPU usage threshold
        self.memory_threshold = 85.0  # Memory usage threshold
        self.redis_connection_threshold = 150  # Max Redis connections
        self.max_concurrent_scans = 50  # Dynamic limit
        self.history_size = 60  # Keep 60 data points
        
        # Resource history for trend analysis
        self.cpu_history = []
        self.memory_history = []
        self.scan_duration_history = []
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
            logger.error(f"Failed to get system health: {e}")
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
    
    def calculate_optimal_concurrency(self, current_scans: int) -> int:
        """Calculate optimal concurrent scan limit based on system resources"""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Base limit on CPU cores
            cpu_cores = psutil.cpu_count()
            base_limit = max(8, cpu_cores * 2)
            
            # Adjust for current resource usage
            cpu_factor = max(0.2, (100 - cpu_percent) / 100)
            memory_factor = max(0.2, (100 - memory.percent) / 100)
            
            # Calculate adjusted limit
            adjusted_limit = int(base_limit * cpu_factor * memory_factor)
            
            # Apply boundaries
            min_limit = 5  # Always allow at least 5 scans
            max_limit = 100  # Cap at 100 for safety
            
            optimal = max(min_limit, min(max_limit, adjusted_limit))
            
            logger.info(
                f"Resource-based concurrency calculation: "
                f"CPU: {cpu_percent}%, Memory: {memory.percent}%, "
                f"Cores: {cpu_cores}, Optimal: {optimal}"
            )
            
            return optimal
            
        except Exception as e:
            logger.error(f"Failed to calculate optimal concurrency: {e}")
            return 10  # Conservative fallback


class CircuitBreaker:
    """Circuit breaker for protecting against system overload"""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        
    def can_execute(self) -> bool:
        """Check if operations can proceed"""
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
        """Record successful operation"""
        if self.state == "HALF_OPEN":
            self.state = "CLOSED"
        self.failure_count = 0
    
    def record_failure(self):
        """Record failed operation"""
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


class EnterpriseQueueManager:
    """Enterprise-grade queue manager for concurrent scanning at scale"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        
        # Queue management
        self.queues = {
            ScanPriority.CRITICAL: asyncio.Queue(),
            ScanPriority.HIGH: asyncio.Queue(),
            ScanPriority.NORMAL: asyncio.Queue(),
            ScanPriority.LOW: asyncio.Queue()
        }
        
        # Active scans tracking
        self.active_scans: Dict[str, QueuedScan] = {}
        self.worker_assignments: Dict[str, str] = {}  # worker_id -> scan_id
        
        # Enterprise components
        self.resource_monitor = ResourceMonitor()
        self.circuit_breaker = CircuitBreaker()
        
        # Configuration
        self.max_queue_size = 1000  # Total queue size limit
        self.max_user_queue_size = 10  # Per-user queue limit
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
            "priority_distribution": {p.name: 0 for p in ScanPriority}
        }
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.metrics_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("Enterprise Queue Manager initialized")
    
    async def start(self):
        """Start the queue manager and background tasks"""
        self._running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.metrics_task = asyncio.create_task(self._metrics_loop())
        logger.info("Enterprise Queue Manager started")
    
    async def stop(self):
        """Stop the queue manager gracefully"""
        self._running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if self.metrics_task:
            self.metrics_task.cancel()
        
        # Wait for active scans to complete (with timeout)
        if self.active_scans:
            logger.info(f"Waiting for {len(self.active_scans)} active scans to complete...")
            await asyncio.sleep(5)  # Give scans time to complete
        
        logger.info("Enterprise Queue Manager stopped")
    
    async def enqueue_scan(
        self,
        user_id: int,
        repo_full_name: str,
        scan_config: Dict[str, Any],
        priority: ScanPriority = ScanPriority.NORMAL,
        scan_type: str = "manual",
        client_ip: Optional[str] = None,
        user_tier: str = "free"
    ) -> Dict[str, Any]:
        """Enqueue a scan with enterprise-grade queue management"""
        
        # Check circuit breaker
        if not self.circuit_breaker.can_execute():
            return {
                "success": False,
                "error": "System temporarily unavailable due to overload",
                "retry_after": 60,
                "circuit_breaker_state": self.circuit_breaker.state
            }
        
        try:
            # Generate unique scan ID
            scan_id = str(uuid.uuid4())
            
            # Check system capacity
            system_health = await self.resource_monitor.get_system_health()
            if not self._can_accept_request(system_health, user_tier):
                return {
                    "success": False,
                    "error": "System at capacity. Please try again later.",
                    "system_health": system_health,
                    "estimated_retry_time": 300  # 5 minutes
                }
            
            # Check per-user limits
            user_queue_count = self.metrics["user_queue_counts"].get(user_id, 0)
            max_user_scans = self._get_user_scan_limit(user_tier)
            
            if user_queue_count >= max_user_scans:
                return {
                    "success": False,
                    "error": f"User queue limit reached ({max_user_scans} scans)",
                    "user_tier": user_tier,
                    "current_queue_count": user_queue_count
                }
            
            # Create queued scan
            queued_scan = QueuedScan(
                scan_id=scan_id,
                user_id=user_id,
                repo_full_name=repo_full_name,
                priority=priority,
                scan_type=scan_type,
                scan_config=scan_config,
                client_ip=client_ip,
                user_tier=user_tier
            )
            
            # Calculate queue position and wait time
            queue_info = await self._calculate_queue_metrics(priority, user_tier)
            queued_scan.queue_position = queue_info["position"]
            queued_scan.estimated_wait_time = queue_info["wait_time"]
            queued_scan.estimated_completion_time = queue_info["completion_time"]
            
            # Add to appropriate priority queue
            await self.queues[priority].put(queued_scan)
            
            # Update metrics
            self.metrics["total_queued"] += 1
            self.metrics["priority_distribution"][priority.name] += 1
            self.metrics["user_queue_counts"][user_id] = user_queue_count + 1
            
            # Update peak queue size
            total_queued = sum(q.qsize() for q in self.queues.values())
            self.metrics["peak_queue_size"] = max(self.metrics["peak_queue_size"], total_queued)
            
            # Store in Redis for persistence
            await self._persist_scan_to_redis(queued_scan)
            
            # CRITICAL FIX: Publish event notification to wake up workers immediately
            await self._publish_scan_job_available(queued_scan)
            
            self.circuit_breaker.record_success()
            
            logger.info(
                f"Scan queued successfully: {scan_id} for user {user_id}, "
                f"priority: {priority.name}, position: {queued_scan.queue_position}"
            )
            
            return {
                "success": True,
                "scan_id": scan_id,
                "status": "queued",
                "queue_position": queued_scan.queue_position,
                "estimated_wait_time": queued_scan.estimated_wait_time,
                "estimated_completion_time": queued_scan.estimated_completion_time.isoformat() if queued_scan.estimated_completion_time else None,
                "priority": priority.name,
                "message": "Scan queued successfully. You will be notified when processing begins.",
                "queue_info": queue_info
            }
            
        except Exception as e:
            logger.error(f"Failed to enqueue scan: {e}")
            self.circuit_breaker.record_failure()
            return {
                "success": False,
                "error": f"Failed to queue scan: {str(e)}",
                "scan_id": None
            }
    
    async def get_next_scan(self, worker_id: str) -> Optional[QueuedScan]:
        """Get the next scan for processing (priority-based)"""
        
        # Check if worker can handle more scans
        current_load = len([s for s in self.active_scans.values() if s.worker_id == worker_id])
        if current_load >= 3:  # Max 3 scans per worker
            return None
        
        # Try each priority queue in order
        for priority in ScanPriority:
            queue = self.queues[priority]
            
            try:
                # Non-blocking get
                scan = queue.get_nowait()
                
                # Update scan status
                scan.status = ScanStatus.PROCESSING
                scan.worker_id = worker_id
                scan.started_at = datetime.now(timezone.utc)
                
                # Track active scan
                self.active_scans[scan.scan_id] = scan
                self.worker_assignments[worker_id] = scan.scan_id
                
                # Update user queue count
                user_id = scan.user_id
                if user_id in self.metrics["user_queue_counts"]:
                    self.metrics["user_queue_counts"][user_id] -= 1
                
                # Calculate queue time
                if scan.queued_at:
                    queue_time = (scan.started_at - scan.queued_at).total_seconds()
                    self._update_average_time("queue_time", queue_time)
                
                logger.info(f"Assigned scan {scan.scan_id} to worker {worker_id}")
                return scan
                
            except asyncio.QueueEmpty:
                continue
        
        return None
    
    async def complete_scan(
        self,
        scan_id: str,
        success: bool = True,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ):
        """Mark a scan as completed"""
        
        if scan_id not in self.active_scans:
            logger.warning(f"Attempted to complete unknown scan: {scan_id}")
            return
        
        scan = self.active_scans[scan_id]
        
        # Update scan status
        scan.status = ScanStatus.COMPLETED if success else ScanStatus.FAILED
        completion_time = datetime.now(timezone.utc)
        
        # Calculate processing time
        if scan.started_at:
            processing_time = (completion_time - scan.started_at).total_seconds()
            self._update_average_time("processing_time", processing_time)
        
        # Update metrics
        if success:
            self.metrics["total_processed"] += 1
        else:
            self.metrics["total_failed"] += 1
        
        # Clean up
        del self.active_scans[scan_id]
        if scan.worker_id and scan.worker_id in self.worker_assignments:
            del self.worker_assignments[scan.worker_id]
        
        # Store completion in Redis
        await self._update_scan_in_redis(scan_id, {
            "status": scan.status.value,
            "completed_at": completion_time.isoformat(),
            "success": success,
            "result": result,
            "error": error
        })
        
        logger.info(f"Scan {scan_id} completed: {'success' if success else 'failed'}")
    
    async def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed status of a scan"""
        
        # Check active scans first
        if scan_id in self.active_scans:
            scan = self.active_scans[scan_id]
            return {
                "scan_id": scan_id,
                "status": scan.status.value,
                "queue_position": 0,  # Active scans are not in queue
                "estimated_wait_time": 0,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "worker_id": scan.worker_id,
                "processing_time": (datetime.now(timezone.utc) - scan.started_at).total_seconds() if scan.started_at else 0
            }
        
        # Check Redis for completed scans
        return await self._get_scan_from_redis(scan_id)
    
    async def get_queue_statistics(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        
        system_health = await self.resource_monitor.get_system_health()
        
        # Current queue sizes by priority
        queue_sizes = {
            priority.name: queue.qsize()
            for priority, queue in self.queues.items()
        }
        
        # Active scan information
        active_scans_info = []
        for scan in self.active_scans.values():
            active_scans_info.append({
                "scan_id": scan.scan_id,
                "repo": scan.repo_full_name,
                "priority": scan.priority.name,
                "worker_id": scan.worker_id,
                "processing_time": (datetime.now(timezone.utc) - scan.started_at).total_seconds() if scan.started_at else 0
            })
        
        return {
            "queue_sizes": queue_sizes,
            "total_queued": sum(queue_sizes.values()),
            "active_scans": len(self.active_scans),
            "active_scans_info": active_scans_info,
            "system_health": system_health,
            "circuit_breaker": self.circuit_breaker.get_status(),
            "metrics": self.metrics,
            "capacity": {
                "max_concurrent": self.resource_monitor.calculate_optimal_concurrency(len(self.active_scans)),
                "current_utilization": len(self.active_scans)
            }
        }
    
    def _can_accept_request(self, system_health: Dict[str, Any], user_tier: str) -> bool:
        """Check if system can accept new requests"""
        
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
        if cpu_usage > 70 and total_queued > self.max_queue_size * 0.5:
            return False
        
        return True
    
    def _get_user_scan_limit(self, user_tier: str) -> int:
        """Get scan limit based on user tier"""
        limits = {
            "free": 5,
            "pro": 15,
            "enterprise": 50
        }
        return limits.get(user_tier, 5)
    
    async def _calculate_queue_metrics(self, priority: ScanPriority, user_tier: str) -> Dict[str, Any]:
        """Calculate queue position and estimated wait time"""
        
        # Count scans with higher or equal priority
        position = 0
        for p in ScanPriority:
            if p.value <= priority.value:
                position += self.queues[p].qsize()
        
        # Estimate wait time based on processing history
        avg_processing_time = self.metrics.get("average_processing_time", 300)  # 5 minutes default
        concurrent_capacity = self.resource_monitor.calculate_optimal_concurrency(len(self.active_scans))
        
        # Calculate estimated wait time
        estimated_wait = (position / max(1, concurrent_capacity)) * avg_processing_time
        
        # Premium users get priority
        if user_tier in ["pro", "enterprise"]:
            estimated_wait *= 0.7  # 30% faster processing
        
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
    
    async def _persist_scan_to_redis(self, scan: QueuedScan):
        """Persist scan information to Redis"""
        if not self.redis:
            return
        
        try:
            scan_data = asdict(scan)
            # Convert datetime objects to strings
            for key, value in scan_data.items():
                if isinstance(value, datetime):
                    scan_data[key] = value.isoformat()
                elif isinstance(value, ScanPriority):
                    scan_data[key] = value.name
                elif isinstance(value, ScanStatus):
                    scan_data[key] = value.value
            
            await self.redis.setex(
                f"scan:{scan.scan_id}",
                3600,  # 1 hour TTL
                json.dumps(scan_data, default=str)
            )
        except Exception as e:
            logger.warning(f"Failed to persist scan to Redis: {e}")
    
    async def _update_scan_in_redis(self, scan_id: str, updates: Dict[str, Any]):
        """Update scan information in Redis"""
        if not self.redis:
            return
        
        try:
            key = f"scan:{scan_id}"
            existing_data = await self.redis.get(key)
            
            if existing_data:
                scan_data = json.loads(existing_data)
                scan_data.update(updates)
                await self.redis.setex(key, 3600, json.dumps(scan_data, default=str))
        except Exception as e:
            logger.warning(f"Failed to update scan in Redis: {e}")
    
    async def _get_scan_from_redis(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan information from Redis"""
        if not self.redis:
            return None
        
        try:
            key = f"scan:{scan_id}"
            data = await self.redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.warning(f"Failed to get scan from Redis: {e}")
            return None
    
    async def _publish_scan_job_available(self, scan: QueuedScan):
        """CRITICAL FIX: Publish notification to wake up workers immediately"""
        try:
            from ..event_driven.worker_events import event_system
            
            job_data = {
                "id": scan.scan_id,
                "repo_full_name": scan.repo_full_name,
                "scan_type": scan.scan_type,
                "priority": scan.priority.name,
                "created_at": scan.queued_at.isoformat() if scan.queued_at else None,
                "user_id": scan.user_id
            }
            
            success = await event_system.publish_scan_job_available(job_data)
            
            if success:
                logger.info(f"✅ Published scan job notification for {scan.scan_id}")
            else:
                logger.warning(f"⚠️ Failed to publish scan job notification for {scan.scan_id}")
                
        except Exception as e:
            logger.error(f"Error publishing scan job notification for {scan.scan_id}: {e}")
    
    async def _cleanup_loop(self):
        """Background task for cleaning up expired scans"""
        while self._running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Clean up old active scans (timeout after 1 hour)
                expired_scans = []
                for scan_id, scan in self.active_scans.items():
                    if scan.started_at and (current_time - scan.started_at).total_seconds() > 3600:
                        expired_scans.append(scan_id)
                
                for scan_id in expired_scans:
                    logger.warning(f"Cleaning up expired scan: {scan_id}")
                    await self.complete_scan(scan_id, success=False, error="Scan timeout")
                
                # Reset user queue counts periodically
                self.metrics["user_queue_counts"] = {
                    user_id: max(0, count - 1)
                    for user_id, count in self.metrics["user_queue_counts"].items()
                    if count > 0
                }
                
                await asyncio.sleep(self.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(60)
    
    async def _metrics_loop(self):
        """Background task for updating metrics"""
        while self._running:
            try:
                # Update system metrics
                system_health = await self.resource_monitor.get_system_health()
                
                # Log queue statistics
                queue_stats = await self.get_queue_statistics()
                logger.info(
                    f"Queue Stats - Total: {queue_stats['total_queued']}, "
                    f"Active: {queue_stats['active_scans']}, "
                    f"CPU: {system_health.get('cpu', {}).get('current', 0):.1f}%, "
                    f"Memory: {system_health.get('memory', {}).get('current', 0):.1f}%"
                )
                
                await asyncio.sleep(self.metrics_interval)
                
            except Exception as e:
                logger.error(f"Error in metrics loop: {e}")
                await asyncio.sleep(60)


# Global instance
_enterprise_queue_manager: Optional[EnterpriseQueueManager] = None


async def get_enterprise_queue_manager() -> EnterpriseQueueManager:
    """Get or create the global enterprise queue manager"""
    global _enterprise_queue_manager
    
    if _enterprise_queue_manager is None:
        try:
            from core.redis import get_redis_client
            redis_client = await get_redis_client()
        except Exception as e:
            logger.warning(f"Failed to get Redis client: {e}")
            redis_client = None
        
        _enterprise_queue_manager = EnterpriseQueueManager(redis_client)
        await _enterprise_queue_manager.start()
    
    return _enterprise_queue_manager


async def shutdown_enterprise_queue_manager():
    """Shutdown the global enterprise queue manager"""
    global _enterprise_queue_manager
    
    if _enterprise_queue_manager:
        await _enterprise_queue_manager.stop()
        _enterprise_queue_manager = None