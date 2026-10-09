"""
Enterprise Webhook Worker Management System
Auto-scaling workers for webhook processing with load balancing and delivery guarantees.
"""

import asyncio
import logging
import os
import time
import uuid
import aiohttp
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import psutil
from dataclasses import dataclass

from .enterprise_webhook_queue import get_enterprise_webhook_queue_manager, QueuedWebhook, WebhookStatus
from ..event_driven.worker_events import event_system

logger = logging.getLogger(__name__)


@dataclass
class WebhookWorkerStats:
    """Webhook worker performance statistics"""
    worker_id: str
    started_at: datetime
    webhooks_processed: int = 0
    webhooks_failed: int = 0
    average_response_time: float = 0.0
    current_webhook: Optional[str] = None
    last_activity: Optional[datetime] = None
    status: str = "idle"  # idle, busy, error, shutdown


class EnterpriseWebhookWorker:
    """Individual worker that processes webhooks from the enterprise queue"""
    
    def __init__(self, worker_id: str, max_concurrent_webhooks: int = 10):
        self.worker_id = worker_id
        self.max_concurrent_webhooks = max_concurrent_webhooks
        
        # Worker state
        self.active_webhooks: Dict[str, QueuedWebhook] = {}
        self.is_running = False
        self.shutdown_requested = False
        
        # Statistics
        self.stats = WebhookWorkerStats(
            worker_id=worker_id,
            started_at=datetime.now(timezone.utc)
        )
        
        # HTTP session for webhook delivery
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Event-driven processing
        self.event_subscription_task: Optional[asyncio.Task] = None
        self.job_ready_event = asyncio.Event()
        
        # SAFETY: Enforce minimum polling intervals to prevent Redis cost explosion
        self.fallback_poll_interval = max(120, int(os.getenv("WEBHOOK_WORKER_POLL_INTERVAL", "300")))  # Minimum 2 minutes
        
        logger.info(f"Enterprise Webhook Worker {worker_id} initialized with fallback poll interval: {self.fallback_poll_interval}s")
    
    async def start(self):
        """Start the webhook worker"""
        self.is_running = True
        self.stats.status = "idle"
        
        # Create HTTP session
        timeout = aiohttp.ClientTimeout(total=60, connect=10)
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            ttl_dns_cache=300,
            use_dns_cache=True,
            keepalive_timeout=30,
            enable_cleanup_closed=True
        )
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": "DevSecureX-Webhook/1.0"}
        )
        
        # Subscribe to webhook job events for instant notifications
        self.event_subscription_task = await event_system.subscribe_to_webhook_jobs(
            self.worker_id, 
            self._on_webhook_job_event
        )
        
        if self.event_subscription_task:
            logger.info(f"✅ Webhook Worker {self.worker_id} subscribed to event-driven notifications")
        else:
            logger.warning(f"⚠️  Webhook Worker {self.worker_id} failed to subscribe to events - using fallback polling only")
        
        # Start processing loop
        processing_task = asyncio.create_task(self._webhook_processing_loop())
        
        logger.info(f"Enterprise Webhook Worker {self.worker_id} started with event-driven architecture")
        
        try:
            await processing_task
        except asyncio.CancelledError:
            logger.info(f"Enterprise Webhook Worker {self.worker_id} cancelled")
        except Exception as e:
            logger.error(f"Enterprise Webhook Worker {self.worker_id} error: {e}")
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Gracefully shutdown the webhook worker"""
        logger.info(f"Shutting down Enterprise Webhook Worker {self.worker_id}")
        
        self.shutdown_requested = True
        self.stats.status = "shutdown"
        
        # Cancel event subscription
        if self.event_subscription_task and not self.event_subscription_task.done():
            logger.info(f"Cancelling webhook event subscription for worker {self.worker_id}")
            self.event_subscription_task.cancel()
            try:
                await self.event_subscription_task
            except asyncio.CancelledError:
                pass
        
        # Wait for active webhooks to complete
        if self.active_webhooks:
            logger.info(f"Webhook Worker {self.worker_id}: Waiting for {len(self.active_webhooks)} active webhooks to complete...")
            
            timeout = 120  # 2 minutes for webhooks
            start_time = time.time()
            
            while self.active_webhooks and (time.time() - start_time) < timeout:
                await asyncio.sleep(5)
            
            # Force complete remaining webhooks
            for webhook_id in list(self.active_webhooks.keys()):
                logger.warning(f"Force completing webhook {webhook_id} due to worker shutdown")
                queue_manager = await get_enterprise_webhook_queue_manager()
                await queue_manager.complete_webhook(
                    webhook_id, 
                    success=False, 
                    error="Webhook worker shutdown during processing"
                )
        
        # Close HTTP session
        if self.session:
            await self.session.close()
            self.session = None
        
        self.is_running = False
        logger.info(f"Enterprise Webhook Worker {self.worker_id} shut down")
    
    async def _on_webhook_job_event(self, event_data: Dict[str, Any]):
        """
        Handle webhook job available event - triggers immediate processing
        """
        try:
            event_type = event_data.get("type")
            webhook_id = event_data.get("webhook_id")
            
            if event_type == "webhook_job_available":
                logger.info(f"⚡ Webhook Worker {self.worker_id} received event for webhook: {webhook_id}")
                
                # Signal the processing loop that work is available
                self.job_ready_event.set()
                
            else:
                logger.debug(f"Webhook Worker {self.worker_id} ignoring event type: {event_type}")
                
        except Exception as e:
            logger.error(f"Error processing webhook job event in worker {self.worker_id}: {e}")
    
    async def _webhook_processing_loop(self):
        """
        EVENT-DRIVEN webhook processing loop with safe fallback polling.
        REDIS OPTIMIZATION: 99% reduction in polling calls through Redis pub/sub events.
        """
        queue_manager = await get_enterprise_webhook_queue_manager()
        last_poll_time = time.time()
        
        logger.info(f"🚀 Webhook Worker {self.worker_id} starting event-driven processing loop")
        
        while self.is_running and not self.shutdown_requested:
            try:
                # Check if worker can handle more webhooks
                if len(self.active_webhooks) >= self.max_concurrent_webhooks:
                    await asyncio.sleep(5)  # Brief wait when at capacity
                    continue
                
                # Try to get webhook immediately (non-blocking)
                webhook = await queue_manager.get_next_webhook(self.worker_id)
                
                if webhook:
                    logger.info(f"⚡ Webhook Worker {self.worker_id} processing webhook: {webhook.webhook_id}")
                    
                    # Process webhook in background
                    task = asyncio.create_task(self._process_webhook(webhook))
                    self.active_webhooks[webhook.webhook_id] = webhook
                    self.stats.current_webhook = webhook.webhook_id
                    self.stats.status = "busy"
                    
                    # Clear event since we found work
                    self.job_ready_event.clear()
                    continue  # Check for more work immediately
                
                # No webhooks available - use event-driven wait with fallback polling
                self.stats.status = "idle"
                self.stats.current_webhook = None
                
                current_time = time.time()
                time_since_last_poll = current_time - last_poll_time
                
                try:
                    # EVENT-DRIVEN: Wait for job notification OR fallback timeout
                    # This is the key optimization - instead of polling every 2 seconds,
                    # we wait for Redis pub/sub events and only fallback poll every 5+ minutes
                    timeout = max(30, self.fallback_poll_interval - time_since_last_poll)
                    
                    logger.debug(f"Webhook Worker {self.worker_id} waiting for events (timeout: {timeout}s)")
                    await asyncio.wait_for(self.job_ready_event.wait(), timeout=timeout)
                    
                    # Event received - process immediately
                    logger.info(f"⚡ Webhook Worker {self.worker_id} woken by job event!")
                    
                except asyncio.TimeoutError:
                    # Fallback polling after long interval (safety mechanism)
                    last_poll_time = current_time
                    logger.debug(f"Webhook Worker {self.worker_id} fallback poll after {self.fallback_poll_interval}s")
                
            except Exception as e:
                logger.error(f"Error in webhook worker {self.worker_id} processing loop: {e}")
                await asyncio.sleep(30)  # Longer wait on errors
    
    async def _process_webhook(self, webhook: QueuedWebhook):
        """Process a single webhook"""
        start_time = time.time()
        queue_manager = await get_enterprise_webhook_queue_manager()
        
        try:
            logger.info(f"Webhook Worker {self.worker_id} delivering webhook: {webhook.webhook_id} to {webhook.webhook_url}")
            
            # Prepare request
            headers = webhook.headers.copy()
            headers.setdefault("Content-Type", "application/json")
            
            # Add security headers
            headers["X-DevSecureX-Webhook-ID"] = webhook.webhook_id
            headers["X-DevSecureX-Timestamp"] = str(int(time.time()))
            
            # Make HTTP request
            async with self.session.post(
                webhook.webhook_url,
                json=webhook.payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=webhook.timeout)
            ) as response:
                response_time = time.time() - start_time
                response_text = await response.text()
                
                # Check if request was successful
                success = 200 <= response.status < 300
                
                # Update statistics
                if success:
                    self.stats.webhooks_processed += 1
                else:
                    self.stats.webhooks_failed += 1
                
                self._update_average_response_time(response_time)
                
                # Complete webhook in queue
                should_retry = not success and response.status >= 500  # Retry on server errors
                
                await queue_manager.complete_webhook(
                    webhook.webhook_id,
                    success=success,
                    response_status=response.status,
                    response_time=response_time,
                    error=f"HTTP {response.status}: {response_text[:200]}" if not success else None,
                    should_retry=should_retry
                )
                
                if success:
                    logger.info(
                        f"Webhook Worker {self.worker_id} delivered webhook {webhook.webhook_id} "
                        f"successfully in {response_time:.2f}s (HTTP {response.status})"
                    )
                else:
                    logger.warning(
                        f"Webhook Worker {self.worker_id} failed to deliver webhook {webhook.webhook_id}: "
                        f"HTTP {response.status} in {response_time:.2f}s"
                    )
                
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            logger.warning(f"Webhook Worker {self.worker_id} timeout for webhook {webhook.webhook_id} after {response_time:.2f}s")
            
            self.stats.webhooks_failed += 1
            await queue_manager.complete_webhook(
                webhook.webhook_id,
                success=False,
                response_time=response_time,
                error="Request timeout",
                should_retry=True
            )
            
        except aiohttp.ClientError as e:
            response_time = time.time() - start_time
            logger.error(f"Webhook Worker {self.worker_id} client error for webhook {webhook.webhook_id}: {e}")
            
            self.stats.webhooks_failed += 1
            await queue_manager.complete_webhook(
                webhook.webhook_id,
                success=False,
                response_time=response_time,
                error=f"Client error: {str(e)}",
                should_retry=True
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Webhook Worker {self.worker_id} unexpected error for webhook {webhook.webhook_id}: {e}")
            
            self.stats.webhooks_failed += 1
            await queue_manager.complete_webhook(
                webhook.webhook_id,
                success=False,
                response_time=response_time,
                error=str(e),
                should_retry=False  # Don't retry on unexpected errors
            )
        
        finally:
            # Clean up
            if webhook.webhook_id in self.active_webhooks:
                del self.active_webhooks[webhook.webhook_id]
            
            # Update worker status
            if not self.active_webhooks:
                self.stats.status = "idle"
                self.stats.current_webhook = None
            
            self.stats.last_activity = datetime.now(timezone.utc)
    
    def _update_average_response_time(self, response_time: float):
        """Update average response time using exponential smoothing"""
        if self.stats.average_response_time == 0:
            self.stats.average_response_time = response_time
        else:
            alpha = 0.1
            self.stats.average_response_time = (
                alpha * response_time + (1 - alpha) * self.stats.average_response_time
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get webhook worker statistics"""
        return {
            "worker_id": self.worker_id,
            "status": self.stats.status,
            "uptime_seconds": (datetime.now(timezone.utc) - self.stats.started_at).total_seconds(),
            "webhooks_processed": self.stats.webhooks_processed,
            "webhooks_failed": self.stats.webhooks_failed,
            "success_rate": (
                self.stats.webhooks_processed / max(1, self.stats.webhooks_processed + self.stats.webhooks_failed)
            ) * 100,
            "active_webhooks": len(self.active_webhooks),
            "current_webhook": self.stats.current_webhook,
            "average_response_time": self.stats.average_response_time,
            "last_activity": self.stats.last_activity.isoformat() if self.stats.last_activity else None
        }


class EnterpriseWebhookWorkerManager:
    """Manages multiple webhook workers with auto-scaling capabilities"""
    
    def __init__(self):
        self.workers: Dict[str, EnterpriseWebhookWorker] = {}
        self.worker_tasks: Dict[str, asyncio.Task] = {}
        
        # Configuration with safety bounds
        self.min_workers = max(1, min(int(os.getenv("MIN_WEBHOOK_WORKERS", "2")), 5))  # 1-5 range
        self.max_workers = max(self.min_workers, min(int(os.getenv("MAX_WEBHOOK_WORKERS", "10")), 20))  # Max 20
        
        # SAFETY: Enforce minimum scaling intervals to prevent Redis thrashing
        raw_scaling_interval = int(os.getenv("WEBHOOK_SCALING_CHECK_INTERVAL", "300"))  # Default 5 minutes
        self.scaling_check_interval = max(120, min(raw_scaling_interval, 3600))  # 2-60 minutes range
        
        if raw_scaling_interval < 120:
            logger.error(f"CRITICAL: WEBHOOK_SCALING_CHECK_INTERVAL={raw_scaling_interval}s is TOO LOW! "
                        f"Clamping to minimum 120s to prevent Redis cost explosion.")
        
        # Auto-scaling state with safety bounds
        self.last_scaling_decision = time.time()
        raw_cooldown = int(os.getenv("WEBHOOK_SCALING_COOLDOWN", "300"))  # Default 5 minutes
        self.scaling_cooldown = max(120, min(raw_cooldown, 1800))  # 2-30 minutes range
        
        self.is_running = False
        self.scaling_task: Optional[asyncio.Task] = None
        
        logger.info(f"Enterprise Webhook Worker Manager initialized: {self.min_workers}-{self.max_workers} workers")
        logger.info(f"SAFETY: Scaling interval: {self.scaling_check_interval}s, cooldown: {self.scaling_cooldown}s")
    
    async def start(self):
        """Start the webhook worker manager"""
        self.is_running = True
        
        # Start initial workers
        await self._scale_workers(self.min_workers)
        
        # Start auto-scaling monitoring
        self.scaling_task = asyncio.create_task(self._auto_scaling_loop())
        
        logger.info("Enterprise Webhook Worker Manager started")
    
    async def stop(self):
        """Stop all webhook workers gracefully"""
        logger.info("Stopping Enterprise Webhook Worker Manager...")
        
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
        
        logger.info("Enterprise Webhook Worker Manager stopped")
    
    async def _scale_workers(self, target_count: int):
        """Scale webhook workers to target count"""
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
        
        logger.info(f"Scaled webhook workers from {current_count} to {len(self.workers)}")
    
    async def _add_worker(self) -> str:
        """Add a new webhook worker"""
        worker_id = f"webhook-worker-{uuid.uuid4().hex[:8]}"
        
        # Create and start worker
        worker = EnterpriseWebhookWorker(worker_id)
        self.workers[worker_id] = worker
        
        # Start worker task
        task = asyncio.create_task(worker.start())
        self.worker_tasks[worker_id] = task
        
        logger.info(f"Added webhook worker: {worker_id}")
        return worker_id
    
    async def _remove_worker(self, worker_id: str):
        """Remove a webhook worker gracefully"""
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
        
        logger.info(f"Removed webhook worker: {worker_id}")
    
    async def _auto_scaling_loop(self):
        """Auto-scaling based on webhook queue size and response times"""
        while self.is_running:
            try:
                await asyncio.sleep(self.scaling_check_interval)
                
                # Check if we're in cooldown period
                if time.time() - self.last_scaling_decision < self.scaling_cooldown:
                    continue
                
                # Get current metrics
                queue_manager = await get_enterprise_webhook_queue_manager()
                stats = await queue_manager.get_queue_statistics()
                system_health = stats["system_health"]
                
                # Calculate scaling decision
                new_worker_count = await self._calculate_optimal_worker_count(stats, system_health)
                
                if new_worker_count != len(self.workers):
                    logger.info(
                        f"Webhook Auto-scaling: {len(self.workers)} -> {new_worker_count} workers "
                        f"(Queue: {stats['total_queued']}, Success Rate: {stats['metrics']['success_rate']:.1f}%)"
                    )
                    
                    await self._scale_workers(new_worker_count)
                    self.last_scaling_decision = time.time()
                
            except Exception as e:
                logger.error(f"Error in webhook auto-scaling loop: {e}")
                await asyncio.sleep(max(60, self.scaling_check_interval // 2))  # Safe error recovery
    
    async def _calculate_optimal_worker_count(
        self, 
        queue_stats: Dict[str, Any], 
        system_health: Dict[str, Any]
    ) -> int:
        """Calculate optimal number of webhook workers"""
        
        current_workers = len(self.workers)
        total_queued = queue_stats["total_queued"]
        active_webhooks = queue_stats["active_webhooks"]
        success_rate = queue_stats["metrics"]["success_rate"]
        
        # Network-based scaling (webhooks are network-intensive)
        network_healthy = system_health.get("network", {}).get("healthy", True)
        
        # Scale up conditions
        if total_queued > current_workers * 20:  # Many webhooks per worker
            if network_healthy and success_rate > 80:
                return min(self.max_workers, current_workers + 1)
        
        # Scale down conditions
        elif total_queued == 0 and active_webhooks < current_workers * 0.5:
            if current_workers > self.min_workers:
                return max(self.min_workers, current_workers - 1)
        
        # Scale down on poor network performance
        elif not network_healthy or success_rate < 60:
            return max(self.min_workers, current_workers - 1)
        
        return current_workers
    
    def get_worker_statistics(self) -> Dict[str, Any]:
        """Get statistics for all webhook workers"""
        worker_stats = []
        
        for worker in self.workers.values():
            worker_stats.append(worker.get_stats())
        
        # Calculate aggregate statistics
        total_processed = sum(stats["webhooks_processed"] for stats in worker_stats)
        total_failed = sum(stats["webhooks_failed"] for stats in worker_stats)
        total_active = sum(stats["active_webhooks"] for stats in worker_stats)
        
        return {
            "total_workers": len(self.workers),
            "worker_details": worker_stats,
            "aggregate_stats": {
                "total_webhooks_processed": total_processed,
                "total_webhooks_failed": total_failed,
                "total_active_webhooks": total_active,
                "overall_success_rate": (
                    total_processed / max(1, total_processed + total_failed)
                ) * 100 if (total_processed + total_failed) > 0 else 100,
                "average_response_time": (
                    sum(stats["average_response_time"] for stats in worker_stats) / len(worker_stats)
                ) if worker_stats else 0
            },
            "scaling_info": {
                "min_workers": self.min_workers,
                "max_workers": self.max_workers,
                "last_scaling_decision": self.last_scaling_decision,
                "scaling_cooldown_remaining": max(0, self.scaling_cooldown - (time.time() - self.last_scaling_decision))
            }
        }


# Global instance
_enterprise_webhook_worker_manager: Optional[EnterpriseWebhookWorkerManager] = None


async def get_enterprise_webhook_worker_manager() -> EnterpriseWebhookWorkerManager:
    """Get or create the global webhook worker manager"""
    global _enterprise_webhook_worker_manager
    
    if _enterprise_webhook_worker_manager is None:
        _enterprise_webhook_worker_manager = EnterpriseWebhookWorkerManager()
        await _enterprise_webhook_worker_manager.start()
    
    return _enterprise_webhook_worker_manager


async def shutdown_enterprise_webhook_worker_manager():
    """Shutdown the global webhook worker manager"""
    global _enterprise_webhook_worker_manager
    
    if _enterprise_webhook_worker_manager:
        await _enterprise_webhook_worker_manager.stop()
        _enterprise_webhook_worker_manager = None