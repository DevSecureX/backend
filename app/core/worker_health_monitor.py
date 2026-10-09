"""
Worker Health Monitoring System for DevSecureX
Comprehensive worker health monitoring, dead worker detection, and auto-restart mechanisms
"""

import asyncio
import logging
import time
import json
import os
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class WorkerState(Enum):
    """Worker state definitions"""
    STARTING = "starting"
    READY = "ready"
    ACTIVE = "active"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    DEAD = "dead"


class HealthStatus(Enum):
    """Worker health status"""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    DEAD = "dead"


@dataclass
class WorkerMetrics:
    """Worker performance metrics"""
    worker_id: str
    worker_type: str
    state: WorkerState
    health_status: HealthStatus
    last_heartbeat: float
    jobs_processed: int
    jobs_failed: int
    average_job_duration: float
    memory_usage_mb: float
    cpu_usage_percent: float
    uptime_seconds: float
    restart_count: int
    last_error: Optional[str] = None
    last_job_timestamp: Optional[float] = None


class WorkerHealthMonitor:
    """
    CRITICAL FIX: Comprehensive worker health monitoring system
    Implements dead worker detection, automatic restart, and health metrics
    """
    
    def __init__(self):
        self.workers: Dict[str, WorkerMetrics] = {}
        self.worker_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.health_thresholds = {
            "heartbeat_timeout": float(os.getenv("WORKER_HEARTBEAT_TIMEOUT", "300")),  # 5 minutes
            "dead_worker_threshold": float(os.getenv("DEAD_WORKER_THRESHOLD", "600")),  # 10 minutes
            "high_failure_rate": float(os.getenv("HIGH_FAILURE_RATE_THRESHOLD", "0.5")),  # 50%
            "high_memory_usage": float(os.getenv("HIGH_MEMORY_THRESHOLD_MB", "1024")),  # 1GB
            "high_cpu_usage": float(os.getenv("HIGH_CPU_THRESHOLD", "90")),  # 90%
        }
        
        # Auto-restart configuration
        self.auto_restart_enabled = os.getenv("WORKER_AUTO_RESTART", "true").lower() == "true"
        self.max_restart_attempts = int(os.getenv("MAX_WORKER_RESTARTS", "3"))
        self.restart_cooldown = float(os.getenv("RESTART_COOLDOWN_SECONDS", "60"))
        
        # Monitoring state
        self.monitoring_active = False
        self.monitoring_task: Optional[asyncio.Task] = None
        self.monitoring_interval = float(os.getenv("WORKER_MONITOR_INTERVAL", "30"))  # 30 seconds
        
        # Dead worker tracking
        self.dead_workers: Set[str] = set()
        self.restart_attempts: Dict[str, int] = defaultdict(int)
        self.last_restart_time: Dict[str, float] = {}
        
        # Health statistics
        self.health_stats = {
            "total_workers_monitored": 0,
            "healthy_workers": 0,
            "warning_workers": 0,
            "critical_workers": 0,
            "dead_workers": 0,
            "total_restarts": 0,
            "successful_restarts": 0,
            "failed_restarts": 0
        }
        
        # Event callbacks
        self.event_callbacks = {
            "worker_died": [],
            "worker_recovered": [],
            "worker_restarted": [],
            "high_failure_rate": [],
            "resource_critical": []
        }
        
        logger.info(f"Worker Health Monitor initialized (auto-restart: {self.auto_restart_enabled})")
    
    async def start_monitoring(self):
        """Start the health monitoring system"""
        if self.monitoring_active:
            logger.warning("Worker health monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info(f"Started worker health monitoring (interval: {self.monitoring_interval}s)")
    
    async def stop_monitoring(self):
        """Stop the health monitoring system"""
        if not self.monitoring_active:
            return
        
        self.monitoring_active = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped worker health monitoring")
    
    async def register_worker(self, worker_id: str, worker_type: str, initial_state: WorkerState = WorkerState.STARTING):
        """Register a new worker for monitoring"""
        current_time = time.time()
        
        self.workers[worker_id] = WorkerMetrics(
            worker_id=worker_id,
            worker_type=worker_type,
            state=initial_state,
            health_status=HealthStatus.HEALTHY,
            last_heartbeat=current_time,
            jobs_processed=0,
            jobs_failed=0,
            average_job_duration=0.0,
            memory_usage_mb=0.0,
            cpu_usage_percent=0.0,
            uptime_seconds=0.0,
            restart_count=0
        )
        
        self.health_stats["total_workers_monitored"] += 1
        logger.info(f"Registered worker {worker_id} ({worker_type}) for health monitoring")
    
    async def update_worker_heartbeat(self, worker_id: str, state: Optional[WorkerState] = None, 
                                    job_metrics: Optional[Dict[str, Any]] = None,
                                    resource_metrics: Optional[Dict[str, Any]] = None):
        """Update worker heartbeat and metrics"""
        if worker_id not in self.workers:
            logger.warning(f"Heartbeat received from unregistered worker: {worker_id}")
            return
        
        current_time = time.time()
        worker = self.workers[worker_id]
        
        # Update basic metrics
        worker.last_heartbeat = current_time
        if state:
            worker.state = state
        
        # Update job metrics if provided
        if job_metrics:
            worker.jobs_processed = job_metrics.get("jobs_processed", worker.jobs_processed)
            worker.jobs_failed = job_metrics.get("jobs_failed", worker.jobs_failed)
            worker.average_job_duration = job_metrics.get("average_duration", worker.average_job_duration)
            if job_metrics.get("last_job_timestamp"):
                worker.last_job_timestamp = job_metrics["last_job_timestamp"]
        
        # Update resource metrics if provided
        if resource_metrics:
            worker.memory_usage_mb = resource_metrics.get("memory_mb", worker.memory_usage_mb)
            worker.cpu_usage_percent = resource_metrics.get("cpu_percent", worker.cpu_usage_percent)
        
        # Calculate uptime
        if hasattr(worker, '_start_time'):
            worker.uptime_seconds = current_time - worker._start_time
        else:
            worker._start_time = current_time
        
        # Update health status
        await self._update_worker_health_status(worker_id)
        
        # Remove from dead workers if it was there
        if worker_id in self.dead_workers:
            self.dead_workers.remove(worker_id)
            logger.info(f"Worker {worker_id} recovered from dead state")
            await self._trigger_event("worker_recovered", {"worker_id": worker_id})
        
        # Store in history
        self.worker_history[worker_id].append({
            "timestamp": current_time,
            "state": state.value if state else worker.state.value,
            "health": worker.health_status.value,
            "jobs_processed": worker.jobs_processed,
            "memory_mb": worker.memory_usage_mb
        })
    
    async def report_worker_error(self, worker_id: str, error_message: str):
        """Report a worker error for health tracking"""
        if worker_id not in self.workers:
            return
        
        worker = self.workers[worker_id]
        worker.last_error = error_message
        
        logger.warning(f"Worker {worker_id} reported error: {error_message}")
        await self._update_worker_health_status(worker_id)
    
    async def unregister_worker(self, worker_id: str):
        """Unregister a worker from monitoring"""
        if worker_id in self.workers:
            del self.workers[worker_id]
            logger.info(f"Unregistered worker {worker_id} from health monitoring")
        
        self.dead_workers.discard(worker_id)
        self.restart_attempts.pop(worker_id, None)
        self.last_restart_time.pop(worker_id, None)
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                await self._check_worker_health()
                await self._detect_dead_workers()
                await self._update_health_statistics()
                await asyncio.sleep(self.monitoring_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in worker health monitoring loop: {e}")
                await asyncio.sleep(self.monitoring_interval)
    
    async def _check_worker_health(self):
        """Check health of all registered workers"""
        current_time = time.time()
        
        for worker_id, worker in self.workers.items():
            # Check heartbeat timeout
            heartbeat_age = current_time - worker.last_heartbeat
            
            if heartbeat_age > self.health_thresholds["heartbeat_timeout"]:
                if worker.health_status != HealthStatus.CRITICAL:
                    logger.warning(f"Worker {worker_id} heartbeat timeout ({heartbeat_age:.1f}s)")
                    worker.health_status = HealthStatus.CRITICAL
            
            # Update health status based on metrics
            await self._update_worker_health_status(worker_id)
    
    async def _detect_dead_workers(self):
        """Detect and handle dead workers"""
        current_time = time.time()
        
        for worker_id, worker in list(self.workers.items()):
            heartbeat_age = current_time - worker.last_heartbeat
            
            # Check if worker is dead
            if heartbeat_age > self.health_thresholds["dead_worker_threshold"]:
                if worker_id not in self.dead_workers:
                    logger.error(f"Worker {worker_id} detected as DEAD (no heartbeat for {heartbeat_age:.1f}s)")
                    worker.state = WorkerState.DEAD
                    worker.health_status = HealthStatus.DEAD
                    self.dead_workers.add(worker_id)
                    
                    await self._trigger_event("worker_died", {
                        "worker_id": worker_id,
                        "worker_type": worker.worker_type,
                        "last_heartbeat_age": heartbeat_age
                    })
                    
                    # Attempt auto-restart if enabled
                    if self.auto_restart_enabled:
                        await self._attempt_worker_restart(worker_id)
    
    async def _attempt_worker_restart(self, worker_id: str):
        """Attempt to restart a dead worker"""
        current_time = time.time()
        
        # Check restart limits
        if self.restart_attempts[worker_id] >= self.max_restart_attempts:
            logger.error(f"Worker {worker_id} exceeded max restart attempts ({self.max_restart_attempts})")
            return False
        
        # Check restart cooldown
        if worker_id in self.last_restart_time:
            cooldown_remaining = self.restart_cooldown - (current_time - self.last_restart_time[worker_id])
            if cooldown_remaining > 0:
                logger.debug(f"Worker {worker_id} restart cooldown: {cooldown_remaining:.1f}s remaining")
                return False
        
        logger.info(f"Attempting to restart worker {worker_id} (attempt {self.restart_attempts[worker_id] + 1}/{self.max_restart_attempts})")
        
        try:
            # Attempt restart (this would need to be implemented based on worker management system)
            success = await self._restart_worker(worker_id)
            
            self.restart_attempts[worker_id] += 1
            self.last_restart_time[worker_id] = current_time
            self.health_stats["total_restarts"] += 1
            
            if success:
                self.health_stats["successful_restarts"] += 1
                logger.info(f"Successfully restarted worker {worker_id}")
                await self._trigger_event("worker_restarted", {"worker_id": worker_id})
                return True
            else:
                self.health_stats["failed_restarts"] += 1
                logger.error(f"Failed to restart worker {worker_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error restarting worker {worker_id}: {e}")
            self.health_stats["failed_restarts"] += 1
            return False
    
    async def _restart_worker(self, worker_id: str) -> bool:
        """Restart a specific worker using the appropriate management system"""
        try:
            logger.info(f"Attempting to restart worker {worker_id}")
            
            # Get worker info to determine restart method
            if worker_id not in self.workers:
                logger.error(f"Cannot restart unknown worker: {worker_id}")
                return False
                
            worker = self.workers[worker_id]
            worker_type = worker.worker_type
            
            # Restart based on worker type
            restart_success = False
            
            if worker_type == "unified_worker":
                restart_success = await self._restart_unified_worker(worker_id)
            elif worker_type == "autofix_worker":
                restart_success = await self._restart_autofix_worker(worker_id)
            elif worker_type == "scan_worker":
                restart_success = await self._restart_scan_worker(worker_id)
            else:
                logger.warning(f"Unknown worker type for restart: {worker_type}")
                restart_success = await self._restart_generic_worker(worker_id)
            
            if restart_success:
                # Update worker metrics on successful restart
                worker.restart_count += 1
                worker.state = WorkerState.STARTING
                worker.health_status = HealthStatus.HEALTHY
                worker.last_heartbeat = time.time()
                logger.info(f"Successfully restarted worker {worker_id}")
            else:
                logger.error(f"Failed to restart worker {worker_id}")
                
            return restart_success
            
        except Exception as e:
            logger.error(f"Error during worker restart {worker_id}: {e}")
            return False
    
    async def _restart_unified_worker(self, worker_id: str) -> bool:
        """Restart a unified scan worker"""
        try:
            # Stop the existing worker gracefully
            from scans.unified_queue.unified_worker import stop_unified_worker
            await stop_unified_worker(worker_id)
            
            # Wait a moment for cleanup
            await asyncio.sleep(2)
            
            # Start a new worker with the same ID
            openai_api_key = os.getenv("OPENAI_API_KEY")
            if not openai_api_key:
                logger.error("Cannot restart unified worker - OPENAI_API_KEY not configured")
                return False
                
            from scans.unified_queue.unified_worker import start_unified_worker
            new_worker = await start_unified_worker(worker_id, openai_api_key)
            
            return new_worker is not None
            
        except Exception as e:
            logger.error(f"Failed to restart unified worker {worker_id}: {e}")
            return False
    
    async def _restart_autofix_worker(self, worker_id: str) -> bool:
        """Restart an autofix worker"""
        try:
            # For autofix workers, use the on-demand manager to ensure availability
            from scans.autofix_queue.on_demand_manager import ensure_autofix_workers_available
            
            # This will restart workers if needed
            workers_available = await ensure_autofix_workers_available(f"restart_{worker_id}")
            return workers_available
            
        except Exception as e:
            logger.error(f"Failed to restart autofix worker {worker_id}: {e}")
            return False
    
    async def _restart_scan_worker(self, worker_id: str) -> bool:
        """Restart a legacy scan worker"""
        try:
            # For legacy scan workers, use the worker manager
            from scans.workers.manager import restart_worker
            return await restart_worker(worker_id)
            
        except ImportError:
            logger.warning("Legacy scan worker manager not available")
            return False
        except Exception as e:
            logger.error(f"Failed to restart scan worker {worker_id}: {e}")
            return False
    
    async def _restart_generic_worker(self, worker_id: str) -> bool:
        """Generic worker restart using process management"""
        try:
            # Try to restart using supervisor if available
            if await self._restart_via_supervisor(worker_id):
                return True
                
            # Try to restart using systemd if available
            if await self._restart_via_systemd(worker_id):
                return True
                
            # Try to restart using Docker if available
            if await self._restart_via_docker(worker_id):
                return True
                
            logger.warning(f"No suitable restart method found for worker {worker_id}")
            return False
            
        except Exception as e:
            logger.error(f"Generic worker restart failed for {worker_id}: {e}")
            return False
    
    async def _restart_via_supervisor(self, worker_id: str) -> bool:
        """Restart worker using supervisord"""
        try:
            import asyncio
            import subprocess
            
            # Check if supervisorctl is available
            result = await asyncio.create_subprocess_exec(
                "which", "supervisorctl",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await result.wait()
            
            if result.returncode != 0:
                return False
            
            # Try to restart the worker service
            service_name = f"devsecurex-worker-{worker_id}"
            restart_cmd = ["supervisorctl", "restart", service_name]
            
            process = await asyncio.create_subprocess_exec(
                *restart_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"Successfully restarted worker {worker_id} via supervisor")
                return True
            else:
                logger.debug(f"Supervisor restart failed for {worker_id}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.debug(f"Supervisor restart not available for {worker_id}: {e}")
            return False
    
    async def _restart_via_systemd(self, worker_id: str) -> bool:
        """Restart worker using systemd"""
        try:
            import asyncio
            
            # Check if systemctl is available
            result = await asyncio.create_subprocess_exec(
                "which", "systemctl",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await result.wait()
            
            if result.returncode != 0:
                return False
            
            # Try to restart the worker service
            service_name = f"devsecurex-worker-{worker_id}.service"
            restart_cmd = ["systemctl", "restart", service_name]
            
            process = await asyncio.create_subprocess_exec(
                *restart_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"Successfully restarted worker {worker_id} via systemd")
                return True
            else:
                logger.debug(f"Systemd restart failed for {worker_id}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.debug(f"Systemd restart not available for {worker_id}: {e}")
            return False
    
    async def _restart_via_docker(self, worker_id: str) -> bool:
        """Restart worker using Docker"""
        try:
            import asyncio
            
            # Check if docker is available
            result = await asyncio.create_subprocess_exec(
                "which", "docker",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await result.wait()
            
            if result.returncode != 0:
                return False
            
            # Try to restart the worker container
            container_name = f"devsecurex-worker-{worker_id}"
            restart_cmd = ["docker", "restart", container_name]
            
            process = await asyncio.create_subprocess_exec(
                *restart_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                logger.info(f"Successfully restarted worker {worker_id} via Docker")
                return True
            else:
                logger.debug(f"Docker restart failed for {worker_id}: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.debug(f"Docker restart not available for {worker_id}: {e}")
            return False
    
    async def _update_worker_health_status(self, worker_id: str):
        """Update worker health status based on current metrics"""
        if worker_id not in self.workers:
            return
        
        worker = self.workers[worker_id]
        current_time = time.time()
        
        # Calculate failure rate
        failure_rate = 0.0
        if worker.jobs_processed > 0:
            failure_rate = worker.jobs_failed / worker.jobs_processed
        
        # Determine health status
        if worker_id in self.dead_workers:
            worker.health_status = HealthStatus.DEAD
        elif (current_time - worker.last_heartbeat) > self.health_thresholds["heartbeat_timeout"]:
            worker.health_status = HealthStatus.CRITICAL
        elif (failure_rate > self.health_thresholds["high_failure_rate"] or 
              worker.memory_usage_mb > self.health_thresholds["high_memory_usage"] or
              worker.cpu_usage_percent > self.health_thresholds["high_cpu_usage"]):
            if worker.health_status != HealthStatus.CRITICAL:
                worker.health_status = HealthStatus.WARNING
        else:
            worker.health_status = HealthStatus.HEALTHY
    
    async def _update_health_statistics(self):
        """Update overall health statistics"""
        stats = {status: 0 for status in HealthStatus}
        
        for worker in self.workers.values():
            stats[worker.health_status] += 1
        
        self.health_stats.update({
            "healthy_workers": stats[HealthStatus.HEALTHY],
            "warning_workers": stats[HealthStatus.WARNING], 
            "critical_workers": stats[HealthStatus.CRITICAL],
            "dead_workers": stats[HealthStatus.DEAD]
        })
    
    async def _trigger_event(self, event_type: str, event_data: Dict[str, Any]):
        """Trigger event callbacks"""
        if event_type in self.event_callbacks:
            for callback in self.event_callbacks[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event_data)
                    else:
                        callback(event_data)
                except Exception as e:
                    logger.error(f"Error in event callback {event_type}: {e}")
    
    def add_event_callback(self, event_type: str, callback):
        """Add event callback for worker health events"""
        if event_type in self.event_callbacks:
            self.event_callbacks[event_type].append(callback)
    
    def get_worker_health(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Get health information for a specific worker"""
        if worker_id not in self.workers:
            return None
        
        worker = self.workers[worker_id]
        current_time = time.time()
        
        return {
            "worker_id": worker_id,
            "worker_type": worker.worker_type,
            "state": worker.state.value,
            "health_status": worker.health_status.value,
            "uptime_seconds": worker.uptime_seconds,
            "heartbeat_age_seconds": current_time - worker.last_heartbeat,
            "jobs_processed": worker.jobs_processed,
            "jobs_failed": worker.jobs_failed,
            "failure_rate": worker.jobs_failed / max(1, worker.jobs_processed),
            "average_job_duration": worker.average_job_duration,
            "memory_usage_mb": worker.memory_usage_mb,
            "cpu_usage_percent": worker.cpu_usage_percent,
            "restart_count": worker.restart_count,
            "last_error": worker.last_error,
            "is_dead": worker_id in self.dead_workers
        }
    
    def get_all_workers_health(self) -> Dict[str, Any]:
        """Get health information for all workers"""
        workers_health = {}
        
        for worker_id in self.workers.keys():
            workers_health[worker_id] = self.get_worker_health(worker_id)
        
        return {
            "workers": workers_health,
            "statistics": self.health_stats.copy(),
            "thresholds": self.health_thresholds.copy(),
            "monitoring_active": self.monitoring_active,
            "auto_restart_enabled": self.auto_restart_enabled
        }
    
    def get_worker_history(self, worker_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get worker health history"""
        if worker_id not in self.worker_history:
            return []
        
        history = list(self.worker_history[worker_id])
        return history[-limit:] if len(history) > limit else history
    
    def get_dead_workers(self) -> List[str]:
        """Get list of dead workers"""
        return list(self.dead_workers)
    
    async def force_worker_restart(self, worker_id: str) -> bool:
        """Force restart a worker (admin operation)"""
        if worker_id not in self.workers:
            logger.error(f"Cannot restart unknown worker: {worker_id}")
            return False
        
        logger.info(f"Force restarting worker {worker_id}")
        return await self._attempt_worker_restart(worker_id)


# Global worker health monitor instance
_worker_health_monitor = WorkerHealthMonitor()


async def get_worker_health_monitor() -> WorkerHealthMonitor:
    """Get the global worker health monitor"""
    return _worker_health_monitor


async def start_worker_health_monitoring():
    """Start the global worker health monitoring system"""
    monitor = await get_worker_health_monitor()
    await monitor.start_monitoring()


async def stop_worker_health_monitoring():
    """Stop the global worker health monitoring system"""
    monitor = await get_worker_health_monitor()
    await monitor.stop_monitoring()