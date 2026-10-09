"""
Comprehensive Task Lifecycle Management and Monitoring

Features:
- Real-time task progress tracking
- Performance analytics and insights
- SLA monitoring and alerting
- Resource utilization tracking
- Predictive analytics for capacity planning
- Comprehensive metrics dashboard
"""

import asyncio
import json
import logging
import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque

from core.redis import get_redis_client
from core.utils import utc_now_iso

logger = logging.getLogger(__name__)

class MetricType(Enum):
    """Types of metrics collected"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"

class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

@dataclass
class TaskMetrics:
    """Comprehensive task metrics"""
    # Throughput metrics
    tasks_enqueued_total: int = 0
    tasks_completed_total: int = 0
    tasks_failed_total: int = 0
    tasks_cancelled_total: int = 0
    tasks_expired_total: int = 0
    
    # Current state metrics
    tasks_queued_current: int = 0
    tasks_processing_current: int = 0
    workers_active_current: int = 0
    workers_idle_current: int = 0
    
    # Performance metrics
    average_queue_time_seconds: float = 0.0
    average_processing_time_seconds: float = 0.0
    average_total_time_seconds: float = 0.0
    p95_queue_time_seconds: float = 0.0
    p95_processing_time_seconds: float = 0.0
    
    # Reliability metrics
    success_rate_percentage: float = 100.0
    sla_compliance_percentage: float = 100.0
    worker_utilization_percentage: float = 0.0
    
    # Resource metrics
    total_cpu_hours_used: float = 0.0
    total_memory_mb_hours_used: float = 0.0
    cost_per_task_dollars: float = 0.0
    
    # Predictive metrics
    predicted_queue_size_5min: int = 0
    predicted_worker_shortage_5min: bool = False
    capacity_utilization_percentage: float = 0.0

@dataclass
class SLAMetrics:
    """SLA compliance metrics"""
    target_completion_time_seconds: int = 300  # 5 minutes default
    target_success_rate_percentage: float = 99.0
    target_availability_percentage: float = 99.9
    
    # Current compliance
    completion_time_compliance: float = 0.0
    success_rate_compliance: float = 0.0
    availability_compliance: float = 0.0
    
    # Violations
    completion_time_violations: int = 0
    success_rate_violations: int = 0
    availability_violations: int = 0

@dataclass
class Alert:
    """System alert"""
    alert_id: str
    level: AlertLevel
    title: str
    message: str
    metric: str
    threshold: float
    current_value: float
    created_at: str
    resolved_at: Optional[str] = None
    acknowledged: bool = False

class TaskMonitor:
    """Comprehensive task monitoring and analytics system"""
    
    def __init__(self, redis_key_prefix: str = "task_monitor"):
        self.redis_key_prefix = redis_key_prefix
        
        # Redis keys
        self.metrics_key = f"{redis_key_prefix}:metrics"
        self.timeseries_key = f"{redis_key_prefix}:timeseries"
        self.alerts_key = f"{redis_key_prefix}:alerts"
        self.sla_key = f"{redis_key_prefix}:sla"
        self.performance_key = f"{redis_key_prefix}:performance"
        
        # Monitoring configuration
        self.monitoring_config = {
            'collection_interval': 30,    # Seconds
            'retention_hours': 168,       # 7 days
            'alert_check_interval': 60,   # Seconds
            'sla_window_minutes': 60,     # SLA compliance window
            'performance_window_minutes': 15,  # Performance metrics window
            'prediction_window_minutes': 5     # Prediction horizon
        }
        
        # Alert thresholds
        self.alert_thresholds = {
            'queue_size_critical': 100,
            'queue_time_warning': 300,     # 5 minutes
            'queue_time_critical': 600,    # 10 minutes
            'success_rate_warning': 95.0,  # 95%
            'success_rate_critical': 90.0, # 90%
            'worker_utilization_warning': 90.0,  # 90%
            'worker_utilization_critical': 95.0, # 95%
            'sla_compliance_warning': 95.0,
            'sla_compliance_critical': 90.0,
            'resource_usage_warning': 80.0,
            'resource_usage_critical': 90.0
        }
        
        # State tracking
        self.current_metrics = TaskMetrics()
        self.sla_metrics = SLAMetrics()
        self.active_alerts: Dict[str, Alert] = {}
        self.metrics_history = deque(maxlen=1000)  # Keep last 1000 data points
        self.performance_buffer = deque(maxlen=100)  # Performance calculations
        
        # Running state
        self.running = False
        self._monitoring_task = None
        self._alert_task = None
    
    async def start(self):
        """Start the task monitoring system"""
        if self.running:
            logger.warning("TaskMonitor already running")
            return
        
        self.running = True
        logger.info("Starting TaskMonitor")
        
        # Start monitoring tasks
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._alert_task = asyncio.create_task(self._alert_loop())
        
        logger.info("TaskMonitor started successfully")
    
    async def stop(self):
        """Stop the task monitoring system"""
        if not self.running:
            return
        
        logger.info("Stopping TaskMonitor...")
        self.running = False
        
        # Cancel monitoring tasks
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self._alert_task:
            self._alert_task.cancel()
            try:
                await self._alert_task
            except asyncio.CancelledError:
                pass
        
        logger.info("TaskMonitor stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        
        while self.running:
            try:
                # Collect metrics
                await self._collect_metrics()
                
                # Calculate performance metrics
                await self._calculate_performance_metrics()
                
                # Update SLA metrics
                await self._update_sla_metrics()
                
                # Store metrics
                await self._store_metrics()
                
                # Predictive analytics
                await self._update_predictions()
                
                # Cleanup old data
                await self._cleanup_old_data()
                
                await asyncio.sleep(self.monitoring_config['collection_interval'])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                await asyncio.sleep(10)
    
    async def _alert_loop(self):
        """Alert checking loop"""
        
        while self.running:
            try:
                # Check all alert conditions
                await self._check_alerts()
                
                # Process active alerts
                await self._process_alerts()
                
                await asyncio.sleep(self.monitoring_config['alert_check_interval'])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in alert loop: {e}", exc_info=True)
                await asyncio.sleep(30)
    
    async def _collect_metrics(self):
        """Collect current metrics from all components"""
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                logger.warning("Redis unavailable for metrics collection")
                return
            
            # Get queue metrics (assuming we have access to queue manager)
            from .priority_queue import PriorityTaskQueue
            from .auto_scaling_manager import AutoScalingTaskManager
            
            # This would be injected in real implementation
            # For now, simulate metrics collection
            
            # Collect from multiple sources
            queue_stats = await self._get_queue_stats(redis_client)
            worker_stats = await self._get_worker_stats(redis_client)
            system_stats = await self._get_system_stats(redis_client)
            
            # Update current metrics
            await self._update_current_metrics(queue_stats, worker_stats, system_stats)
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}", exc_info=True)
    
    async def _get_queue_stats(self, redis_client) -> Dict[str, Any]:
        """Get queue statistics"""
        
        try:
            # Get queue sizes by priority
            queue_sizes = {}
            total_queued = 0
            
            priorities = ['critical', 'high', 'normal', 'low', 'background']
            for priority in priorities:
                queue_key = f"task_queue:{priority}"
                size = await redis_client.zcard(queue_key) or 0
                queue_sizes[priority] = size
                total_queued += size
            
            # Get processing and completed counts
            processing_count = await redis_client.hlen("task_queue:processing") or 0
            completed_count = await redis_client.hlen("task_queue:completed") or 0
            failed_count = await redis_client.hlen("task_queue:failed") or 0
            
            return {
                'queue_sizes': queue_sizes,
                'total_queued': total_queued,
                'processing': processing_count,
                'completed': completed_count,
                'failed': failed_count
            }
            
        except Exception as e:
            logger.error(f"Error getting queue stats: {e}", exc_info=True)
            return {}
    
    async def _get_worker_stats(self, redis_client) -> Dict[str, Any]:
        """Get worker statistics"""
        
        try:
            # Get all workers
            workers_data = await redis_client.hgetall("worker_coordinator:workers") or {}
            
            status_counts = defaultdict(int)
            total_utilization = 0.0
            active_workers = 0
            
            for worker_data_json in workers_data.values():
                try:
                    worker_data = json.loads(worker_data_json)
                    status = worker_data.get('status', 'unknown')
                    status_counts[status] += 1
                    
                    if status in ['active', 'busy', 'idle']:
                        current_tasks = len(worker_data.get('current_tasks', []))
                        max_tasks = worker_data.get('capabilities', {}).get('max_concurrent_tasks', 1)
                        utilization = current_tasks / max_tasks
                        total_utilization += utilization
                        active_workers += 1
                        
                except Exception as e:
                    logger.warning(f"Error parsing worker data: {e}")
            
            avg_utilization = (total_utilization / max(active_workers, 1)) * 100
            
            return {
                'status_counts': dict(status_counts),
                'total_workers': len(workers_data),
                'active_workers': active_workers,
                'average_utilization': avg_utilization
            }
            
        except Exception as e:
            logger.error(f"Error getting worker stats: {e}", exc_info=True)
            return {}
    
    async def _get_system_stats(self, redis_client) -> Dict[str, Any]:
        """Get system-level statistics"""
        
        try:
            # Get system metrics
            metrics_data = await redis_client.hgetall("autoscaling:metrics") or {}
            
            return {
                'tasks_enqueued': int(metrics_data.get('tasks_enqueued', 0)),
                'tasks_completed': int(metrics_data.get('tasks_completed', 0)),
                'tasks_failed': int(metrics_data.get('tasks_failed', 0)),
                'scaling_actions': int(metrics_data.get('total_scaling_actions', 0)),
                'average_wait_time': float(metrics_data.get('average_wait_time', 0))
            }
            
        except Exception as e:
            logger.error(f"Error getting system stats: {e}", exc_info=True)
            return {}
    
    async def _update_current_metrics(
        self, 
        queue_stats: Dict[str, Any], 
        worker_stats: Dict[str, Any], 
        system_stats: Dict[str, Any]
    ):
        """Update current metrics based on collected data"""
        
        # Update counters
        self.current_metrics.tasks_enqueued_total = system_stats.get('tasks_enqueued', 0)
        self.current_metrics.tasks_completed_total = system_stats.get('tasks_completed', 0)
        self.current_metrics.tasks_failed_total = system_stats.get('tasks_failed', 0)
        
        # Update current state
        self.current_metrics.tasks_queued_current = queue_stats.get('total_queued', 0)
        self.current_metrics.tasks_processing_current = queue_stats.get('processing', 0)
        self.current_metrics.workers_active_current = worker_stats.get('active_workers', 0)
        
        # Calculate derived metrics
        total_tasks = self.current_metrics.tasks_completed_total + self.current_metrics.tasks_failed_total
        if total_tasks > 0:
            self.current_metrics.success_rate_percentage = (
                self.current_metrics.tasks_completed_total / total_tasks
            ) * 100
        
        # Update utilization
        self.current_metrics.worker_utilization_percentage = worker_stats.get('average_utilization', 0)
        
        # Update timing metrics
        self.current_metrics.average_queue_time_seconds = system_stats.get('average_wait_time', 0)
        
        # Add to history
        self.metrics_history.append({
            'timestamp': utc_now_iso(),
            'metrics': asdict(self.current_metrics)
        })
    
    async def _calculate_performance_metrics(self):
        """Calculate advanced performance metrics"""
        
        if len(self.metrics_history) < 2:
            return
        
        try:
            # Get recent metrics for calculations
            recent_metrics = list(self.metrics_history)[-60:]  # Last hour
            
            # Calculate percentiles for queue times
            queue_times = []
            processing_times = []
            
            for entry in recent_metrics:
                metrics = entry['metrics']
                queue_times.append(metrics.get('average_queue_time_seconds', 0))
                processing_times.append(metrics.get('average_processing_time_seconds', 0))
            
            if queue_times:
                self.current_metrics.p95_queue_time_seconds = self._calculate_percentile(queue_times, 95)
            
            if processing_times:
                self.current_metrics.p95_processing_time_seconds = self._calculate_percentile(processing_times, 95)
            
            # Calculate throughput trend
            if len(recent_metrics) >= 5:
                recent_completed = [m['metrics']['tasks_completed_total'] for m in recent_metrics[-5:]]
                throughput_trend = self._calculate_trend(recent_completed)
                
                # Store in performance buffer for predictions
                self.performance_buffer.append({
                    'timestamp': time.time(),
                    'queue_size': self.current_metrics.tasks_queued_current,
                    'throughput': throughput_trend,
                    'worker_count': self.current_metrics.workers_active_current
                })
            
        except Exception as e:
            logger.error(f"Error calculating performance metrics: {e}", exc_info=True)
    
    def _calculate_percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile for a list of values"""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        k = (len(sorted_values) - 1) * percentile / 100
        f = int(k)
        c = k - f
        
        if f == len(sorted_values) - 1:
            return sorted_values[f]
        
        return sorted_values[f] * (1 - c) + sorted_values[f + 1] * c
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend slope for a series of values"""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        sum_x = sum(range(n))
        sum_y = sum(values)
        sum_xy = sum(i * values[i] for i in range(n))
        sum_x2 = sum(i * i for i in range(n))
        
        try:
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            return slope
        except ZeroDivisionError:
            return 0.0
    
    async def _update_sla_metrics(self):
        """Update SLA compliance metrics"""
        
        try:
            # Calculate completion time compliance
            target_time = self.sla_metrics.target_completion_time_seconds
            current_time = self.current_metrics.average_total_time_seconds
            
            if current_time <= target_time:
                self.sla_metrics.completion_time_compliance = 100.0
            else:
                # Calculate percentage of how much over target we are
                self.sla_metrics.completion_time_compliance = max(0, 100 - ((current_time - target_time) / target_time * 100))
            
            # Success rate compliance
            success_rate = self.current_metrics.success_rate_percentage
            target_success = self.sla_metrics.target_success_rate_percentage
            
            self.sla_metrics.success_rate_compliance = min(100, (success_rate / target_success) * 100)
            
            # Availability compliance (simplified - based on worker availability)
            active_workers = self.current_metrics.workers_active_current
            if active_workers > 0:
                self.sla_metrics.availability_compliance = 100.0
            else:
                self.sla_metrics.availability_compliance = 0.0
            
        except Exception as e:
            logger.error(f"Error updating SLA metrics: {e}", exc_info=True)
    
    async def _update_predictions(self):
        """Update predictive metrics"""
        
        try:
            if len(self.performance_buffer) < 5:
                return
            
            # Simple linear prediction for queue size
            recent_queue_sizes = [p['queue_size'] for p in list(self.performance_buffer)[-5:]]
            queue_trend = self._calculate_trend(recent_queue_sizes)
            
            # Predict queue size in 5 minutes (10 data points ahead if collecting every 30s)
            current_queue = self.current_metrics.tasks_queued_current
            predicted_queue = max(0, current_queue + (queue_trend * 10))
            
            self.current_metrics.predicted_queue_size_5min = int(predicted_queue)
            
            # Predict worker shortage
            current_workers = self.current_metrics.workers_active_current
            current_utilization = self.current_metrics.worker_utilization_percentage
            
            if predicted_queue > current_queue * 1.5 and current_utilization > 80:
                self.current_metrics.predicted_worker_shortage_5min = True
            else:
                self.current_metrics.predicted_worker_shortage_5min = False
            
            # Calculate capacity utilization
            max_capacity = current_workers * 2  # Assume 2 tasks per worker max
            current_load = self.current_metrics.tasks_processing_current + self.current_metrics.tasks_queued_current
            
            if max_capacity > 0:
                self.current_metrics.capacity_utilization_percentage = min(100, (current_load / max_capacity) * 100)
            
        except Exception as e:
            logger.error(f"Error updating predictions: {e}", exc_info=True)
    
    async def _check_alerts(self):
        """Check all alert conditions"""
        
        alerts_to_create = []
        
        try:
            # Queue size alerts
            if self.current_metrics.tasks_queued_current >= self.alert_thresholds['queue_size_critical']:
                alerts_to_create.append(self._create_alert(
                    'queue_size_critical',
                    AlertLevel.CRITICAL,
                    'Critical Queue Size',
                    f'Queue size {self.current_metrics.tasks_queued_current} exceeds critical threshold',
                    'tasks_queued_current',
                    self.alert_thresholds['queue_size_critical'],
                    self.current_metrics.tasks_queued_current
                ))
            
            # Queue time alerts
            if self.current_metrics.p95_queue_time_seconds >= self.alert_thresholds['queue_time_critical']:
                alerts_to_create.append(self._create_alert(
                    'queue_time_critical',
                    AlertLevel.CRITICAL,
                    'Critical Queue Wait Time',
                    f'P95 queue time {self.current_metrics.p95_queue_time_seconds:.1f}s exceeds threshold',
                    'p95_queue_time_seconds',
                    self.alert_thresholds['queue_time_critical'],
                    self.current_metrics.p95_queue_time_seconds
                ))
            elif self.current_metrics.p95_queue_time_seconds >= self.alert_thresholds['queue_time_warning']:
                alerts_to_create.append(self._create_alert(
                    'queue_time_warning',
                    AlertLevel.WARNING,
                    'High Queue Wait Time',
                    f'P95 queue time {self.current_metrics.p95_queue_time_seconds:.1f}s exceeds warning threshold',
                    'p95_queue_time_seconds',
                    self.alert_thresholds['queue_time_warning'],
                    self.current_metrics.p95_queue_time_seconds
                ))
            
            # Success rate alerts
            if self.current_metrics.success_rate_percentage <= self.alert_thresholds['success_rate_critical']:
                alerts_to_create.append(self._create_alert(
                    'success_rate_critical',
                    AlertLevel.CRITICAL,
                    'Critical Success Rate',
                    f'Success rate {self.current_metrics.success_rate_percentage:.1f}% below critical threshold',
                    'success_rate_percentage',
                    self.alert_thresholds['success_rate_critical'],
                    self.current_metrics.success_rate_percentage
                ))
            elif self.current_metrics.success_rate_percentage <= self.alert_thresholds['success_rate_warning']:
                alerts_to_create.append(self._create_alert(
                    'success_rate_warning',
                    AlertLevel.WARNING,
                    'Low Success Rate',
                    f'Success rate {self.current_metrics.success_rate_percentage:.1f}% below warning threshold',
                    'success_rate_percentage',
                    self.alert_thresholds['success_rate_warning'],
                    self.current_metrics.success_rate_percentage
                ))
            
            # Worker utilization alerts
            if self.current_metrics.worker_utilization_percentage >= self.alert_thresholds['worker_utilization_critical']:
                alerts_to_create.append(self._create_alert(
                    'worker_utilization_critical',
                    AlertLevel.CRITICAL,
                    'Critical Worker Utilization',
                    f'Worker utilization {self.current_metrics.worker_utilization_percentage:.1f}% exceeds critical threshold',
                    'worker_utilization_percentage',
                    self.alert_thresholds['worker_utilization_critical'],
                    self.current_metrics.worker_utilization_percentage
                ))
            elif self.current_metrics.worker_utilization_percentage >= self.alert_thresholds['worker_utilization_warning']:
                alerts_to_create.append(self._create_alert(
                    'worker_utilization_warning',
                    AlertLevel.WARNING,
                    'High Worker Utilization',
                    f'Worker utilization {self.current_metrics.worker_utilization_percentage:.1f}% exceeds warning threshold',
                    'worker_utilization_percentage',
                    self.alert_thresholds['worker_utilization_warning'],
                    self.current_metrics.worker_utilization_percentage
                ))
            
            # SLA compliance alerts
            sla_compliance = min(
                self.sla_metrics.completion_time_compliance,
                self.sla_metrics.success_rate_compliance,
                self.sla_metrics.availability_compliance
            )
            
            if sla_compliance <= self.alert_thresholds['sla_compliance_critical']:
                alerts_to_create.append(self._create_alert(
                    'sla_compliance_critical',
                    AlertLevel.CRITICAL,
                    'Critical SLA Breach',
                    f'SLA compliance {sla_compliance:.1f}% below critical threshold',
                    'sla_compliance',
                    self.alert_thresholds['sla_compliance_critical'],
                    sla_compliance
                ))
            elif sla_compliance <= self.alert_thresholds['sla_compliance_warning']:
                alerts_to_create.append(self._create_alert(
                    'sla_compliance_warning',
                    AlertLevel.WARNING,
                    'SLA Compliance Warning',
                    f'SLA compliance {sla_compliance:.1f}% below warning threshold',
                    'sla_compliance',
                    self.alert_thresholds['sla_compliance_warning'],
                    sla_compliance
                ))
            
            # Predictive alerts
            if self.current_metrics.predicted_worker_shortage_5min:
                alerts_to_create.append(self._create_alert(
                    'predicted_worker_shortage',
                    AlertLevel.WARNING,
                    'Predicted Worker Shortage',
                    'Worker shortage predicted in next 5 minutes based on queue growth trend',
                    'predicted_worker_shortage_5min',
                    1.0,
                    1.0
                ))
            
            # Create new alerts
            for alert in alerts_to_create:
                await self._create_or_update_alert(alert)
            
            # Check for resolved alerts
            await self._check_resolved_alerts()
            
        except Exception as e:
            logger.error(f"Error checking alerts: {e}", exc_info=True)
    
    def _create_alert(
        self,
        alert_key: str,
        level: AlertLevel,
        title: str,
        message: str,
        metric: str,
        threshold: float,
        current_value: float
    ) -> Alert:
        """Create an alert object"""
        
        alert_id = f"{alert_key}_{int(time.time())}"
        
        return Alert(
            alert_id=alert_id,
            level=level,
            title=title,
            message=message,
            metric=metric,
            threshold=threshold,
            current_value=current_value,
            created_at=utc_now_iso()
        )
    
    async def _create_or_update_alert(self, alert: Alert):
        """Create or update an alert"""
        
        try:
            # Check if similar alert already exists
            existing_key = f"{alert.metric}_{alert.level.value}"
            
            if existing_key in self.active_alerts:
                # Update existing alert
                existing_alert = self.active_alerts[existing_key]
                existing_alert.current_value = alert.current_value
                existing_alert.message = alert.message
            else:
                # Create new alert
                self.active_alerts[existing_key] = alert
                
                # Store in Redis
                redis_client = await get_redis_client()
                if redis_client:
                    await redis_client.hset(
                        self.alerts_key,
                        existing_key,
                        json.dumps({
                    **asdict(alert),
                    'level': alert.level.value  # Convert enum to string
                })
                    )
                
                logger.warning(f"Alert created: {alert.title} - {alert.message}")
                
                # Here you would integrate with alerting systems (email, Slack, etc.)
                await self._send_alert_notification(alert)
            
        except Exception as e:
            logger.error(f"Error creating/updating alert: {e}", exc_info=True)
    
    async def _check_resolved_alerts(self):
        """Check if any active alerts have been resolved"""
        
        resolved_alerts = []
        
        for alert_key, alert in list(self.active_alerts.items()):
            try:
                # Check if alert condition is resolved
                is_resolved = False
                
                if alert.metric == 'tasks_queued_current':
                    is_resolved = self.current_metrics.tasks_queued_current < alert.threshold
                elif alert.metric == 'p95_queue_time_seconds':
                    is_resolved = self.current_metrics.p95_queue_time_seconds < alert.threshold
                elif alert.metric == 'success_rate_percentage':
                    is_resolved = self.current_metrics.success_rate_percentage > alert.threshold
                elif alert.metric == 'worker_utilization_percentage':
                    is_resolved = self.current_metrics.worker_utilization_percentage < alert.threshold
                elif alert.metric == 'predicted_worker_shortage_5min':
                    is_resolved = not self.current_metrics.predicted_worker_shortage_5min
                
                if is_resolved:
                    alert.resolved_at = utc_now_iso()
                    resolved_alerts.append(alert_key)
                    
                    logger.info(f"Alert resolved: {alert.title}")
                    await self._send_alert_resolution_notification(alert)
            
            except Exception as e:
                logger.error(f"Error checking alert resolution for {alert_key}: {e}", exc_info=True)
        
        # Remove resolved alerts
        for alert_key in resolved_alerts:
            self.active_alerts.pop(alert_key, None)
            
            # Remove from Redis
            try:
                redis_client = await get_redis_client()
                if redis_client:
                    await redis_client.hdel(self.alerts_key, alert_key)
            except Exception as e:
                logger.warning(f"Error removing resolved alert from Redis: {e}")
    
    async def _send_alert_notification(self, alert: Alert):
        """Send alert notification (placeholder for integration)"""
        # This would integrate with your alerting system
        # For now, just log the alert
        logger.warning(f"ALERT [{alert.level.value.upper()}]: {alert.title} - {alert.message}")
    
    async def _send_alert_resolution_notification(self, alert: Alert):
        """Send alert resolution notification"""
        logger.info(f"RESOLVED [{alert.level.value.upper()}]: {alert.title}")
    
    async def _process_alerts(self):
        """Process active alerts (escalation, acknowledgment, etc.)"""
        
        try:
            current_time = datetime.utcnow()
            
            for alert in self.active_alerts.values():
                created_time = datetime.fromisoformat(alert.created_at)
                # Ensure both times are offset-naive for comparison
                if created_time.tzinfo is not None:
                    created_time = created_time.replace(tzinfo=None)
                age_minutes = (current_time - created_time).total_seconds() / 60
                
                # Escalate critical alerts after 5 minutes
                if (alert.level == AlertLevel.CRITICAL and 
                    age_minutes >= 5 and 
                    not alert.acknowledged):
                    
                    # This would escalate to emergency level and notify additional people
                    logger.critical(f"ESCALATED ALERT: {alert.title} has been unresolved for {age_minutes:.1f} minutes")
            
        except Exception as e:
            logger.error(f"Error processing alerts: {e}", exc_info=True)
    
    async def _store_metrics(self):
        """Store metrics in Redis for persistence and analytics"""
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return
            
            timestamp = int(time.time())
            
            # Store current metrics
            await redis_client.hset(
                self.metrics_key,
                mapping={
                    'timestamp': timestamp,
                    'metrics': json.dumps(asdict(self.current_metrics)),
                    'sla_metrics': json.dumps(asdict(self.sla_metrics))
                }
            )
            
            # Store in time series for historical analysis
            time_series_key = f"{self.timeseries_key}:{timestamp}"
            await redis_client.set(
                time_series_key,
                json.dumps({
                    'timestamp': timestamp,
                    'metrics': asdict(self.current_metrics),
                    'sla_metrics': asdict(self.sla_metrics)
                }),
                ex=self.monitoring_config['retention_hours'] * 3600
            )
            
        except Exception as e:
            logger.error(f"Error storing metrics: {e}", exc_info=True)
    
    async def _cleanup_old_data(self):
        """Clean up old monitoring data"""
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return
            
            # Clean up old time series data
            cutoff_time = int(time.time()) - (self.monitoring_config['retention_hours'] * 3600)
            
            # Get all time series keys using SCAN instead of expensive KEYS operation
            pattern = f"{self.timeseries_key}:*"
            keys = await self._scan_keys(redis_client, pattern)
            
            for key in keys:
                try:
                    # Extract timestamp from key
                    timestamp = int(key.split(':')[-1])
                    if timestamp < cutoff_time:
                        await redis_client.delete(key)
                except (ValueError, IndexError):
                    # Invalid key format, skip
                    pass
            
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}", exc_info=True)
    
    # Public API methods
    
    async def get_current_metrics(self) -> TaskMetrics:
        """Get current task metrics"""
        return self.current_metrics
    
    async def get_sla_metrics(self) -> SLAMetrics:
        """Get SLA compliance metrics"""
        return self.sla_metrics
    
    async def get_active_alerts(self) -> List[Alert]:
        """Get list of active alerts"""
        return list(self.active_alerts.values())
    
    async def acknowledge_alert(self, alert_key: str) -> bool:
        """Acknowledge an alert"""
        
        if alert_key in self.active_alerts:
            self.active_alerts[alert_key].acknowledged = True
            
            # Update in Redis
            try:
                redis_client = await get_redis_client()
                if redis_client:
                    alert_data = asdict(self.active_alerts[alert_key])
                    await redis_client.hset(self.alerts_key, alert_key, json.dumps(alert_data))
                
                logger.info(f"Alert {alert_key} acknowledged")
                return True
            except Exception as e:
                logger.error(f"Error acknowledging alert {alert_key}: {e}", exc_info=True)
                return False
        
        return False
    
    async def get_historical_metrics(
        self, 
        start_time: datetime, 
        end_time: datetime,
        interval_minutes: int = 5
    ) -> List[Dict[str, Any]]:
        """Get historical metrics for a time range"""
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return []
            
            historical_data = []
            current_time = int(start_time.timestamp())
            end_timestamp = int(end_time.timestamp())
            interval_seconds = interval_minutes * 60
            
            while current_time <= end_timestamp:
                time_series_key = f"{self.timeseries_key}:{current_time}"
                data = await redis_client.get(time_series_key)
                
                if data:
                    try:
                        historical_data.append(json.loads(data))
                    except json.JSONDecodeError:
                        pass
                
                current_time += interval_seconds
            
            return historical_data
            
        except Exception as e:
            logger.error(f"Error getting historical metrics: {e}", exc_info=True)
            return []
    
    async def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        
        try:
            # Calculate various performance indicators
            total_tasks = (self.current_metrics.tasks_completed_total + 
                         self.current_metrics.tasks_failed_total)
            
            report = {
                'timestamp': utc_now_iso(),
                'summary': {
                    'total_tasks_processed': total_tasks,
                    'current_queue_size': self.current_metrics.tasks_queued_current,
                    'active_workers': self.current_metrics.workers_active_current,
                    'success_rate': self.current_metrics.success_rate_percentage,
                    'average_queue_time': self.current_metrics.average_queue_time_seconds,
                    'worker_utilization': self.current_metrics.worker_utilization_percentage
                },
                'sla_compliance': {
                    'completion_time': self.sla_metrics.completion_time_compliance,
                    'success_rate': self.sla_metrics.success_rate_compliance,
                    'availability': self.sla_metrics.availability_compliance,
                    'overall': min(
                        self.sla_metrics.completion_time_compliance,
                        self.sla_metrics.success_rate_compliance,
                        self.sla_metrics.availability_compliance
                    )
                },
                'performance_metrics': {
                    'p95_queue_time': self.current_metrics.p95_queue_time_seconds,
                    'p95_processing_time': self.current_metrics.p95_processing_time_seconds,
                    'capacity_utilization': self.current_metrics.capacity_utilization_percentage
                },
                'predictions': {
                    'queue_size_5min': self.current_metrics.predicted_queue_size_5min,
                    'worker_shortage_predicted': self.current_metrics.predicted_worker_shortage_5min
                },
                'active_alerts': len(self.active_alerts),
                'alert_summary': {
                    level.value: len([a for a in self.active_alerts.values() if a.level == level])
                    for level in AlertLevel
                }
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating performance report: {e}", exc_info=True)
            return {'error': str(e)}
    
    async def update_alert_thresholds(self, new_thresholds: Dict[str, float]) -> bool:
        """Update alert thresholds"""
        
        try:
            for key, value in new_thresholds.items():
                if key in self.alert_thresholds:
                    old_value = self.alert_thresholds[key]
                    self.alert_thresholds[key] = value
                    logger.info(f"Updated alert threshold {key}: {old_value} -> {value}")
            
            # Store in Redis
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hset(
                    f"{self.redis_key_prefix}:config",
                    'alert_thresholds',
                    json.dumps(self.alert_thresholds)
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating alert thresholds: {e}", exc_info=True)
            return False
    
    async def _scan_keys(self, redis_client, pattern: str) -> List[str]:
        """Use SCAN instead of KEYS to avoid blocking Redis"""
        try:
            keys = []
            cursor = 0
            while True:
                cursor, partial_keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
                keys.extend(partial_keys)
                if cursor == 0:
                    break
            return keys
        except Exception as e:
            logger.warning(f"SCAN operation failed, falling back to empty list: {e}")
            return []