"""
Enterprise-Grade Webhook Queue Manager
Handles concurrent webhook processing with graceful degradation, retry mechanisms, and resource management.
Applies enterprise patterns for reliable webhook delivery and processing.
"""

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import psutil
import hashlib
import aiohttp

from ..event_driven.worker_events import event_system

logger = logging.getLogger(__name__)


class WebhookPriority(Enum):
    """Webhook priority levels for enterprise queue management"""
    CRITICAL = 0     # Security alerts, system notifications
    HIGH = 1         # User-triggered webhooks
    NORMAL = 2       # Standard integrations
    LOW = 3          # Background notifications


class WebhookStatus(Enum):
    """Enhanced webhook status tracking"""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"
    RETRY = "retry"


@dataclass
class QueuedWebhook:
    """Enhanced webhook request with enterprise features"""
    webhook_id: str
    webhook_url: str
    payload: Dict[str, Any]
    headers: Dict[str, str]
    priority: WebhookPriority
    
    # Queue management
    queue_position: int = 0
    estimated_wait_time: int = 0  # seconds
    
    # Status tracking
    status: WebhookStatus = WebhookStatus.QUEUED
    worker_id: Optional[str] = None
    started_at: Optional[datetime] = None
    queued_at: datetime = None
    
    # Retry mechanism
    retry_count: int = 0
    max_retries: int = 3
    retry_delay: int = 60  # seconds
    
    # Performance tracking
    response_time: float = 0.0
    response_status: Optional[int] = None
    
    # Enterprise features
    timeout: int = 30
    user_id: Optional[int] = None
    source: str = "system"  # system, user, integration
    
    def __post_init__(self):
        if self.queued_at is None:
            self.queued_at = datetime.now(timezone.utc)


class WebhookResourceMonitor:
    """Resource monitoring for webhook processing"""
    
    def __init__(self):
        self.max_concurrent_webhooks = 100  # Higher than scans/autofixes
        self.network_threshold = 10 * 1024 * 1024  # 10MB/s
        self.history_size = 60
        
        # Performance history
        self.response_time_history = []
        self.success_rate_history = []
        self.network_usage_history = []
        
    async def get_system_health(self) -> Dict[str, Any]:
        """Get system health focused on network and webhook processing"""
        try:
            # Basic system metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            network = psutil.net_io_counters()
            
            # Calculate network throughput
            current_time = time.time()
            if hasattr(self, '_last_network_check'):
                time_delta = current_time - self._last_network_check
                bytes_delta = network.bytes_sent - self._last_network_bytes
                network_throughput = bytes_delta / time_delta if time_delta > 0 else 0
            else:
                network_throughput = 0
            
            self._last_network_check = current_time
            self._last_network_bytes = network.bytes_sent
            
            return {
                "cpu": {
                    "current": cpu_percent,
                    "healthy": cpu_percent < 80
                },
                "memory": {
                    "current": memory.percent,
                    "healthy": memory.percent < 85
                },
                "network": {
                    "throughput_bps": network_throughput,
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "healthy": network_throughput < self.network_threshold
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get system health for webhooks: {e}")
            return {
                "cpu": {"healthy": False, "error": str(e)},
                "memory": {"healthy": False, "error": str(e)},
                "network": {"healthy": False, "error": str(e)},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    def calculate_optimal_concurrency(self, current_webhooks: int) -> int:
        """Calculate optimal webhook concurrency based on network capacity"""
        try:
            # Base on CPU cores but prioritize network capacity
            cpu_cores = psutil.cpu_count()
            base_limit = max(20, cpu_cores * 5)  # Higher than scans
            
            # Network-based adjustment
            if hasattr(self, '_last_network_check'):
                avg_response_time = sum(self.response_time_history) / len(self.response_time_history) if self.response_time_history else 1.0
                network_factor = min(1.0, 5.0 / max(0.1, avg_response_time))  # Faster responses = more concurrent
                adjusted_limit = int(base_limit * network_factor)
            else:
                adjusted_limit = base_limit
            
            # Apply boundaries
            min_limit = 10
            max_limit = 200
            
            return max(min_limit, min(max_limit, adjusted_limit))
            
        except Exception as e:
            logger.error(f"Failed to calculate optimal webhook concurrency: {e}")
            return 50


class WebhookCircuitBreaker:
    """Circuit breaker for webhook processing"""
    
    def __init__(self, failure_threshold: int = 10, timeout: int = 300):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "CLOSED"
        
    def can_execute(self) -> bool:
        """Check if webhook operations can proceed"""
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
        """Record successful webhook operation"""
        if self.state == "HALF_OPEN":
            self.state = "CLOSED"
        self.failure_count = max(0, self.failure_count - 1)
    
    def record_failure(self):
        """Record failed webhook operation"""
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


class EnterpriseWebhookQueueManager:
    """Enterprise-grade queue manager for webhook processing"""
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        
        # Queue management
        self.queues = {
            WebhookPriority.CRITICAL: asyncio.Queue(),
            WebhookPriority.HIGH: asyncio.Queue(),
            WebhookPriority.NORMAL: asyncio.Queue(),
            WebhookPriority.LOW: asyncio.Queue()
        }
        
        # Active webhooks tracking
        self.active_webhooks: Dict[str, QueuedWebhook] = {}
        self.worker_assignments: Dict[str, str] = {}
        
        # Enterprise components
        self.resource_monitor = WebhookResourceMonitor()
        self.circuit_breaker = WebhookCircuitBreaker()
        
        # Configuration with safety bounds
        self.max_queue_size = 2000
        self.max_user_queue_size = 50
        
        # SAFETY: Enforce minimum intervals to prevent Redis cost explosion
        raw_cleanup_interval = int(os.getenv("WEBHOOK_CLEANUP_INTERVAL", "300"))  # Default 5 minutes
        self.cleanup_interval = max(120, min(raw_cleanup_interval, 3600))  # 2-60 minutes
        
        raw_metrics_interval = int(os.getenv("WEBHOOK_METRICS_INTERVAL", "180"))  # Default 3 minutes  
        self.metrics_interval = max(60, min(raw_metrics_interval, 1800))  # 1-30 minutes
        
        # Metrics
        self.metrics = {
            "total_queued": 0,
            "total_processed": 0,
            "total_failed": 0,
            "average_response_time": 0.0,
            "success_rate": 100.0,
            "peak_queue_size": 0,
            "user_queue_counts": {},
            "priority_distribution": {p.name: 0 for p in WebhookPriority},
            "retry_counts": 0
        }
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.metrics_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("Enterprise Webhook Queue Manager initialized")
        logger.info(f"SAFETY: Cleanup interval: {self.cleanup_interval}s, Metrics interval: {self.metrics_interval}s")
    
    async def start(self):
        """Start the webhook queue manager"""
        self._running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.metrics_task = asyncio.create_task(self._metrics_loop())
        logger.info("Enterprise Webhook Queue Manager started")
    
    async def stop(self):
        """Stop the webhook queue manager"""
        self._running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if self.metrics_task:
            self.metrics_task.cancel()
        
        # Wait for active webhooks to complete
        if self.active_webhooks:
            logger.info(f"Waiting for {len(self.active_webhooks)} active webhooks to complete...")
            await asyncio.sleep(30)
        
        logger.info("Enterprise Webhook Queue Manager stopped")
    
    async def enqueue_webhook(
        self,
        webhook_url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str] = None,
        priority: WebhookPriority = WebhookPriority.NORMAL,
        user_id: Optional[int] = None,
        source: str = "system",
        timeout: int = 30,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """Enqueue a webhook for processing"""
        
        # Check circuit breaker
        if not self.circuit_breaker.can_execute():
            return {
                "success": False,
                "error": "Webhook system temporarily unavailable",
                "retry_after": 300,
                "circuit_breaker_state": self.circuit_breaker.state
            }
        
        try:
            webhook_id = str(uuid.uuid4())
            
            # Check system capacity
            system_health = await self.resource_monitor.get_system_health()
            if not self._can_accept_request(system_health):
                return {
                    "success": False,
                    "error": "Webhook system at capacity",
                    "system_health": system_health,
                    "estimated_retry_time": 300
                }
            
            # Check per-user limits
            if user_id:
                user_queue_count = self.metrics["user_queue_counts"].get(user_id, 0)
                if user_queue_count >= self.max_user_queue_size:
                    return {
                        "success": False,
                        "error": f"User webhook queue limit reached ({self.max_user_queue_size})",
                        "current_queue_count": user_queue_count
                    }
            
            # Create queued webhook
            queued_webhook = QueuedWebhook(
                webhook_id=webhook_id,
                webhook_url=webhook_url,
                payload=payload,
                headers=headers or {},
                priority=priority,
                user_id=user_id,
                source=source,
                timeout=timeout,
                max_retries=max_retries
            )
            
            # Calculate queue metrics
            queue_info = await self._calculate_queue_metrics(priority)
            queued_webhook.queue_position = queue_info["position"]
            queued_webhook.estimated_wait_time = queue_info["wait_time"]
            
            # Add to queue
            await self.queues[priority].put(queued_webhook)
            
            # Update metrics
            self.metrics["total_queued"] += 1
            self.metrics["priority_distribution"][priority.name] += 1
            
            if user_id:
                self.metrics["user_queue_counts"][user_id] = user_queue_count + 1
            
            total_queued = sum(q.qsize() for q in self.queues.values())
            self.metrics["peak_queue_size"] = max(self.metrics["peak_queue_size"], total_queued)
            
            # Store in Redis
            await self._persist_webhook_to_redis(queued_webhook)
            
            # WEBHOOK EVENT OPTIMIZATION: Publish event to wake up workers instantly
            event_data = {
                "webhook_id": webhook_id,
                "webhook_url": webhook_url,
                "priority": priority.name,
                "source": source,
                "user_id": user_id,
                "queued_at": queued_webhook.queued_at.isoformat() if queued_webhook.queued_at else None
            }
            
            # Publish webhook job available event
            event_published = await event_system.publish_webhook_job_available(event_data)
            if event_published:
                logger.info(f"✅ Published webhook event and queued: {webhook_id} to {webhook_url[:50]}...")
            else:
                logger.info(f"⚠️  Webhook queued (event publish failed): {webhook_id} to {webhook_url[:50]}...")
            
            self.circuit_breaker.record_success()
            
            return {
                "success": True,
                "webhook_id": webhook_id,
                "status": "queued",
                "queue_position": queued_webhook.queue_position,
                "estimated_wait_time": queued_webhook.estimated_wait_time,
                "priority": priority.name
            }
            
        except Exception as e:
            logger.error(f"Failed to enqueue webhook: {e}")
            self.circuit_breaker.record_failure()
            return {
                "success": False,
                "error": str(e),
                "webhook_id": None
            }
    
    async def get_next_webhook(self, worker_id: str) -> Optional[QueuedWebhook]:
        """Get next webhook for processing"""
        
        # Check worker load
        current_load = len([w for w in self.active_webhooks.values() if w.worker_id == worker_id])
        if current_load >= 10:  # High concurrency for webhooks
            return None
        
        # Try each priority queue
        for priority in WebhookPriority:
            queue = self.queues[priority]
            
            try:
                webhook = queue.get_nowait()
                
                # Update status
                webhook.status = WebhookStatus.PROCESSING
                webhook.worker_id = worker_id
                webhook.started_at = datetime.now(timezone.utc)
                
                # Track active webhook
                self.active_webhooks[webhook.webhook_id] = webhook
                self.worker_assignments[worker_id] = webhook.webhook_id
                
                # Update user queue count
                if webhook.user_id and webhook.user_id in self.metrics["user_queue_counts"]:
                    self.metrics["user_queue_counts"][webhook.user_id] -= 1
                
                logger.info(f"Assigned webhook {webhook.webhook_id} to worker {worker_id}")
                return webhook
                
            except asyncio.QueueEmpty:
                continue
        
        return None
    
    async def complete_webhook(
        self,
        webhook_id: str,
        success: bool = True,
        response_status: Optional[int] = None,
        response_time: float = 0.0,
        error: Optional[str] = None,
        should_retry: bool = False
    ):
        """Mark webhook as completed or schedule retry"""
        
        if webhook_id not in self.active_webhooks:
            logger.warning(f"Attempted to complete unknown webhook: {webhook_id}")
            return
        
        webhook = self.active_webhooks[webhook_id]
        
        # Check if should retry
        if not success and should_retry and webhook.retry_count < webhook.max_retries:
            webhook.retry_count += 1
            webhook.status = WebhookStatus.RETRY
            
            # Re-queue with delay (using asyncio.sleep in a separate task)
            asyncio.create_task(self._schedule_retry(webhook))
            
            logger.info(f"Webhook {webhook_id} scheduled for retry {webhook.retry_count}/{webhook.max_retries}")
            return
        
        # Complete webhook
        webhook.status = WebhookStatus.COMPLETED if success else WebhookStatus.FAILED
        webhook.response_status = response_status
        webhook.response_time = response_time
        
        # Update metrics
        if success:
            self.metrics["total_processed"] += 1
            self.circuit_breaker.record_success()
        else:
            self.metrics["total_failed"] += 1
            self.circuit_breaker.record_failure()
        
        # Update averages
        if response_time > 0:
            self._update_average_response_time(response_time)
        
        self._update_success_rate(success)
        
        # Clean up
        del self.active_webhooks[webhook_id]
        if webhook.worker_id and webhook.worker_id in self.worker_assignments:
            del self.worker_assignments[webhook.worker_id]
        
        # Store in Redis
        await self._update_webhook_in_redis(webhook_id, {
            "status": webhook.status.value,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "success": success,
            "response_status": response_status,
            "response_time": response_time,
            "error": error
        })
        
        logger.info(f"Webhook {webhook_id} completed: {'success' if success else 'failed'}")
    
    async def _schedule_retry(self, webhook: QueuedWebhook):
        """Schedule webhook for retry after delay"""
        try:
            await asyncio.sleep(webhook.retry_delay * webhook.retry_count)  # Exponential backoff
            
            # Reset status and re-queue
            webhook.status = WebhookStatus.QUEUED
            webhook.worker_id = None
            webhook.started_at = None
            webhook.queued_at = datetime.now(timezone.utc)
            
            await self.queues[webhook.priority].put(webhook)
            self.metrics["retry_counts"] += 1
            
            logger.info(f"Webhook {webhook.webhook_id} re-queued for retry")
            
        except Exception as e:
            logger.error(f"Failed to schedule webhook retry: {e}")
    
    async def get_webhook_status(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """Get webhook status"""
        
        # Check active webhooks
        if webhook_id in self.active_webhooks:
            webhook = self.active_webhooks[webhook_id]
            return {
                "webhook_id": webhook_id,
                "status": webhook.status.value,
                "started_at": webhook.started_at.isoformat() if webhook.started_at else None,
                "worker_id": webhook.worker_id,
                "retry_count": webhook.retry_count,
                "processing_time": (datetime.now(timezone.utc) - webhook.started_at).total_seconds() if webhook.started_at else 0
            }
        
        # Check Redis
        return await self._get_webhook_from_redis(webhook_id)
    
    async def get_queue_statistics(self) -> Dict[str, Any]:
        """Get webhook queue statistics"""
        
        system_health = await self.resource_monitor.get_system_health()
        
        queue_sizes = {
            priority.name: queue.qsize()
            for priority, queue in self.queues.items()
        }
        
        active_webhooks_info = []
        for webhook in self.active_webhooks.values():
            active_webhooks_info.append({
                "webhook_id": webhook.webhook_id,
                "url": webhook.webhook_url[:50] + "..." if len(webhook.webhook_url) > 50 else webhook.webhook_url,
                "priority": webhook.priority.name,
                "worker_id": webhook.worker_id,
                "processing_time": (datetime.now(timezone.utc) - webhook.started_at).total_seconds() if webhook.started_at else 0,
                "retry_count": webhook.retry_count
            })
        
        return {
            "queue_sizes": queue_sizes,
            "total_queued": sum(queue_sizes.values()),
            "active_webhooks": len(self.active_webhooks),
            "active_webhooks_info": active_webhooks_info,
            "system_health": system_health,
            "circuit_breaker": self.circuit_breaker.get_status(),
            "metrics": self.metrics,
            "capacity": {
                "max_concurrent": self.resource_monitor.calculate_optimal_concurrency(len(self.active_webhooks)),
                "current_utilization": len(self.active_webhooks)
            }
        }
    
    def _can_accept_request(self, system_health: Dict[str, Any]) -> bool:
        """Check if system can accept webhook requests"""
        
        # Check system health
        if not system_health.get("cpu", {}).get("healthy", False):
            return False
        if not system_health.get("memory", {}).get("healthy", False):
            return False
        if not system_health.get("network", {}).get("healthy", True):
            return False
        
        # Check queue size
        total_queued = sum(q.qsize() for q in self.queues.values())
        return total_queued < self.max_queue_size
    
    async def _calculate_queue_metrics(self, priority: WebhookPriority) -> Dict[str, Any]:
        """Calculate queue position and wait time"""
        
        position = 0
        for p in WebhookPriority:
            if p.value <= priority.value:
                position += self.queues[p].qsize()
        
        # Webhooks process faster than scans/autofixes
        avg_processing_time = self.metrics.get("average_response_time", 5.0)
        concurrent_capacity = self.resource_monitor.calculate_optimal_concurrency(len(self.active_webhooks))
        
        estimated_wait = (position / max(1, concurrent_capacity)) * avg_processing_time
        
        return {
            "position": position,
            "wait_time": int(estimated_wait),
            "concurrent_capacity": concurrent_capacity
        }
    
    def _update_average_response_time(self, response_time: float):
        """Update average response time"""
        alpha = 0.1
        current_avg = self.metrics.get("average_response_time", response_time)
        self.metrics["average_response_time"] = alpha * response_time + (1 - alpha) * current_avg
    
    def _update_success_rate(self, success: bool):
        """Update success rate"""
        alpha = 0.05
        current_rate = self.metrics.get("success_rate", 100.0)
        new_rate = 100.0 if success else 0.0
        self.metrics["success_rate"] = alpha * new_rate + (1 - alpha) * current_rate
    
    async def _persist_webhook_to_redis(self, webhook: QueuedWebhook):
        """Persist webhook to Redis"""
        if not self.redis:
            return
        
        try:
            webhook_data = asdict(webhook)
            for key, value in webhook_data.items():
                if isinstance(value, datetime):
                    webhook_data[key] = value.isoformat()
                elif isinstance(value, WebhookPriority):
                    webhook_data[key] = value.name
                elif isinstance(value, WebhookStatus):
                    webhook_data[key] = value.value
            
            await self.redis.setex(
                f"webhook:{webhook.webhook_id}",
                1800,  # 30 minutes
                json.dumps(webhook_data, default=str)
            )
        except Exception as e:
            logger.warning(f"Failed to persist webhook to Redis: {e}")
    
    async def _update_webhook_in_redis(self, webhook_id: str, updates: Dict[str, Any]):
        """Update webhook in Redis"""
        if not self.redis:
            return
        
        try:
            key = f"webhook:{webhook_id}"
            existing_data = await self.redis.get(key)
            
            if existing_data:
                webhook_data = json.loads(existing_data)
                webhook_data.update(updates)
                await self.redis.setex(key, 1800, json.dumps(webhook_data, default=str))
        except Exception as e:
            logger.warning(f"Failed to update webhook in Redis: {e}")
    
    async def _get_webhook_from_redis(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """Get webhook from Redis"""
        if not self.redis:
            return None
        
        try:
            key = f"webhook:{webhook_id}"
            data = await self.redis.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.warning(f"Failed to get webhook from Redis: {e}")
            return None
    
    async def _cleanup_loop(self):
        """Cleanup expired webhooks"""
        while self._running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Clean up expired webhooks (timeout after 10 minutes)
                expired_webhooks = []
                for webhook_id, webhook in self.active_webhooks.items():
                    if webhook.started_at and (current_time - webhook.started_at).total_seconds() > 600:
                        expired_webhooks.append(webhook_id)
                
                for webhook_id in expired_webhooks:
                    logger.warning(f"Cleaning up expired webhook: {webhook_id}")
                    await self.complete_webhook(webhook_id, success=False, error="Webhook timeout")
                
                await asyncio.sleep(self.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in webhook cleanup loop: {e}")
                await asyncio.sleep(max(60, self.cleanup_interval // 2))  # Safe error recovery
    
    async def _metrics_loop(self):
        """Update webhook metrics"""
        while self._running:
            try:
                system_health = await self.resource_monitor.get_system_health()
                queue_stats = await self.get_queue_statistics()
                
                logger.info(
                    f"Webhook Stats - Queued: {queue_stats['total_queued']}, "
                    f"Active: {queue_stats['active_webhooks']}, "
                    f"Success Rate: {self.metrics['success_rate']:.1f}%"
                )
                
                await asyncio.sleep(self.metrics_interval)
                
            except Exception as e:
                logger.error(f"Error in webhook metrics loop: {e}")
                await asyncio.sleep(max(60, self.metrics_interval // 2))  # Safe error recovery


# Global instance
_enterprise_webhook_queue_manager: Optional[EnterpriseWebhookQueueManager] = None


async def get_enterprise_webhook_queue_manager() -> EnterpriseWebhookQueueManager:
    """Get or create the global webhook queue manager"""
    global _enterprise_webhook_queue_manager
    
    if _enterprise_webhook_queue_manager is None:
        try:
            from core.redis import get_redis_client
            redis_client = await get_redis_client()
        except Exception as e:
            logger.warning(f"Failed to get Redis client for webhooks: {e}")
            redis_client = None
        
        _enterprise_webhook_queue_manager = EnterpriseWebhookQueueManager(redis_client)
        await _enterprise_webhook_queue_manager.start()
    
    return _enterprise_webhook_queue_manager


async def shutdown_enterprise_webhook_queue_manager():
    """Shutdown the global webhook queue manager"""
    global _enterprise_webhook_queue_manager
    
    if _enterprise_webhook_queue_manager:
        await _enterprise_webhook_queue_manager.stop()
        _enterprise_webhook_queue_manager = None