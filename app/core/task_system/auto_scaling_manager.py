"""
Auto-Scaling Task Manager with Dynamic Worker Pool Management

Features:
- Dynamic scaling from 2-15 workers based on real-time load
- Intelligent load balancing and resource management
- Worker health monitoring with automatic recovery
- Predictive scaling based on historical patterns
- Resource optimization and cost control
- Integration with existing DevSecureX worker systems
"""

import asyncio
import json
import logging
import os
import time
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
from collections import deque, defaultdict

from core.redis import get_redis_client
from core.utils import utc_now_iso
from .priority_queue import PriorityTaskQueue, TaskPriority, TaskType
from .retry_handler import RetryHandler, RetryPolicy
from .worker_coordinator import WorkerCoordinator, WorkerStatus, WorkerCapabilities

logger = logging.getLogger(__name__)

class ScalingPolicy(Enum):
    """Auto-scaling policies"""
    REACTIVE = "reactive"          # Scale based on current queue size
    PREDICTIVE = "predictive"      # Scale based on predicted load
    AGGRESSIVE = "aggressive"      # Scale up quickly, down slowly
    CONSERVATIVE = "conservative"  # Scale slowly in both directions
    COST_OPTIMIZED = "cost_optimized"  # Minimize costs while maintaining SLA

class WorkerType(Enum):
    """Worker specialization types"""
    GENERAL = "general"           # Can handle any task type
    SECURITY_SCAN = "security_scan"  # Specialized for security scanning
    AUTOFIX = "autofix"          # Specialized for auto-fix tasks
    REPORT = "report"            # Specialized for report generation
    LIGHTWEIGHT = "lightweight"  # For low-resource tasks

@dataclass
class ScalingMetrics:
    """Metrics used for scaling decisions"""
    queue_size_total: int = 0
    queue_size_by_priority: Dict[str, int] = None
    active_workers: int = 0
    processing_tasks: int = 0
    average_task_duration: float = 0.0
    tasks_per_minute: float = 0.0
    worker_utilization: float = 0.0
    failed_tasks_rate: float = 0.0
    estimated_wait_time: float = 0.0
    
    def __post_init__(self):
        if self.queue_size_by_priority is None:
            self.queue_size_by_priority = {}

@dataclass
class ScalingDecision:
    """Scaling decision with reasoning"""
    action: str  # "scale_up", "scale_down", "no_action"
    target_workers: int
    reasoning: str
    confidence: float
    priority_level: str
    estimated_cost_impact: float = 0.0

@dataclass
class WorkerPool:
    """Worker pool configuration"""
    worker_type: WorkerType
    min_workers: int
    max_workers: int
    current_workers: int
    target_workers: int
    specialized_tasks: List[TaskType]
    resource_requirements: Dict[str, Any]

class AutoScalingTaskManager:
    """Enterprise auto-scaling task manager"""
    
    def __init__(
        self,
        min_workers: int = 2,
        max_workers: int = 15,
        scaling_policy: ScalingPolicy = ScalingPolicy.REACTIVE,
        redis_key_prefix: str = "autoscaling"
    ):
        self.min_workers = max(1, min_workers)
        self.max_workers = min(50, max_workers)  # Hard limit for safety
        self.scaling_policy = scaling_policy
        self.redis_key_prefix = redis_key_prefix
        
        # Core components
        self.task_queue = PriorityTaskQueue(f"{redis_key_prefix}:queue")
        self.retry_handler = RetryHandler(f"{redis_key_prefix}:retry")
        self.worker_coordinator = WorkerCoordinator(f"{redis_key_prefix}:workers")
        
        # Redis keys
        self.metrics_key = f"{redis_key_prefix}:metrics"
        self.scaling_history_key = f"{redis_key_prefix}:scaling_history"
        self.config_key = f"{redis_key_prefix}:config"
        
        # Worker pools by type
        self.worker_pools = {
            WorkerType.GENERAL: WorkerPool(
                worker_type=WorkerType.GENERAL,
                min_workers=1,
                max_workers=max_workers // 2,
                current_workers=0,
                target_workers=min_workers,
                specialized_tasks=[],
                resource_requirements={"cpu": 1.0, "memory": 512}
            ),
            WorkerType.SECURITY_SCAN: WorkerPool(
                worker_type=WorkerType.SECURITY_SCAN,
                min_workers=1,
                max_workers=max_workers // 3,
                current_workers=0,
                target_workers=1,
                specialized_tasks=[TaskType.SECURITY_SCAN],
                resource_requirements={"cpu": 2.0, "memory": 1024}
            ),
            WorkerType.AUTOFIX: WorkerPool(
                worker_type=WorkerType.AUTOFIX,
                min_workers=0,
                max_workers=max_workers // 4,
                current_workers=0,
                target_workers=0,
                specialized_tasks=[TaskType.AUTOFIX],
                resource_requirements={"cpu": 1.5, "memory": 768}
            )
        }
        
        # Scaling configuration
        self.scaling_config = {
            'scale_up_threshold': 5,        # Queue items per worker
            'scale_down_threshold': 1,      # Queue items per worker
            'scale_up_cooldown': 60,        # Seconds
            'scale_down_cooldown': 300,     # Seconds
            'max_scale_up_rate': 3,         # Workers per scale operation
            'max_scale_down_rate': 2,       # Workers per scale operation
            'utilization_target': 0.7,     # Target worker utilization
            'emergency_scale_threshold': 20, # Immediate scaling trigger
            'health_check_interval': 0,   # EMERGENCY FIX: 10 minutes instead of 30 seconds
            'metrics_window': 300,          # Seconds for averaging metrics
            'predictive_window': 600        # Seconds for predictive analysis
        }
        
        # State tracking
        self.last_scaling_action = 0
        self.scaling_history = deque(maxlen=100)
        self.metrics_history = deque(maxlen=60)  # Last hour of metrics
        self.running = False
        self._management_task = None
        
        # Performance tracking
        self.performance_metrics = {
            'total_tasks_processed': 0,
            'total_scaling_actions': 0,
            'average_response_time': 0.0,
            'worker_hours_saved': 0.0,
            'cost_optimization_percentage': 0.0
        }
    
    async def start(self):
        """Start the auto-scaling manager"""
        if self.running:
            logger.warning("AutoScalingTaskManager already running")
            return
        
        self.running = True
        logger.info(f"Starting AutoScalingTaskManager with {self.min_workers}-{self.max_workers} workers")
        
        # Start management loop
        self._management_task = asyncio.create_task(self._management_loop())
        
        # Initialize minimum workers
        await self._ensure_minimum_workers()
        
        logger.info("AutoScalingTaskManager started successfully")
    
    async def stop(self):
        """Stop the auto-scaling manager"""
        if not self.running:
            return
        
        logger.info("Stopping AutoScalingTaskManager...")
        self.running = False
        
        # Cancel management task
        if self._management_task:
            self._management_task.cancel()
            try:
                await self._management_task
            except asyncio.CancelledError:
                pass
        
        # Stop all workers gracefully
        await self.worker_coordinator.stop_all_workers()
        
        logger.info("AutoScalingTaskManager stopped")
    
    async def _management_loop(self):
        """Main management loop for auto-scaling and health monitoring"""
        
        while self.running:
            try:
                # Collect metrics
                metrics = await self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Make scaling decision
                scaling_decision = await self._make_scaling_decision(metrics)
                
                # Execute scaling if needed
                if scaling_decision.action != "no_action":
                    await self._execute_scaling_decision(scaling_decision)
                
                # Health check workers
                await self._health_check_workers()
                
                # Cleanup stale tasks and optimize queues
                await self._maintenance_tasks()
                
                # Update performance metrics
                await self._update_performance_metrics(metrics)
                
                # Wait for next cycle
                await asyncio.sleep(self.scaling_config['health_check_interval'])
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto-scaling management loop: {e}", exc_info=True)
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _collect_metrics(self) -> ScalingMetrics:
        """Collect comprehensive metrics for scaling decisions"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            logger.warning("Redis unavailable for metrics collection")
            return ScalingMetrics()
        
        try:
            # Get queue statistics
            queue_stats = await self.task_queue.get_queue_stats()
            
            # Get worker statistics
            worker_stats = await self.worker_coordinator.get_all_worker_stats()
            
            # Calculate derived metrics
            active_workers = len([w for w in worker_stats.values() if w.get('status') == WorkerStatus.ACTIVE.value])
            processing_tasks = queue_stats.get('processing', 0)
            
            # Calculate utilization
            worker_utilization = processing_tasks / max(active_workers, 1)
            
            # Get historical data for trend analysis
            avg_task_duration = await self._calculate_average_task_duration()
            tasks_per_minute = queue_stats.get('metrics', {}).get('tasks_completed', 0) / max(1, time.time() / 60)
            
            # Estimate wait time
            total_queued = queue_stats.get('total_queued', 0)
            estimated_wait_time = (total_queued * avg_task_duration) / max(active_workers, 1)
            
            # Failed tasks rate
            total_completed = queue_stats.get('metrics', {}).get('tasks_completed', 0)
            total_failed = queue_stats.get('metrics', {}).get('tasks_failed', 0)
            failed_tasks_rate = total_failed / max(total_completed + total_failed, 1)
            
            metrics = ScalingMetrics(
                queue_size_total=total_queued,
                queue_size_by_priority=queue_stats.get('queue_sizes', {}),
                active_workers=active_workers,
                processing_tasks=processing_tasks,
                average_task_duration=avg_task_duration,
                tasks_per_minute=tasks_per_minute,
                worker_utilization=worker_utilization,
                failed_tasks_rate=failed_tasks_rate,
                estimated_wait_time=estimated_wait_time
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}", exc_info=True)
            return ScalingMetrics()
    
    async def _make_scaling_decision(self, metrics: ScalingMetrics) -> ScalingDecision:
        """Make intelligent scaling decision based on current metrics and policy"""
        
        current_time = time.time()
        
        # Check cooldown periods
        time_since_last_scaling = current_time - self.last_scaling_action
        
        # Emergency scaling (bypass cooldowns)
        if metrics.queue_size_total >= self.scaling_config['emergency_scale_threshold']:
            return ScalingDecision(
                action="scale_up",
                target_workers=min(self.max_workers, metrics.active_workers + self.scaling_config['max_scale_up_rate']),
                reasoning=f"Emergency scaling: Queue size {metrics.queue_size_total} exceeds threshold",
                confidence=1.0,
                priority_level="emergency"
            )
        
        # Apply scaling policy
        if self.scaling_policy == ScalingPolicy.REACTIVE:
            return await self._reactive_scaling_decision(metrics, time_since_last_scaling)
        elif self.scaling_policy == ScalingPolicy.PREDICTIVE:
            return await self._predictive_scaling_decision(metrics, time_since_last_scaling)
        elif self.scaling_policy == ScalingPolicy.AGGRESSIVE:
            return await self._aggressive_scaling_decision(metrics, time_since_last_scaling)
        elif self.scaling_policy == ScalingPolicy.CONSERVATIVE:
            return await self._conservative_scaling_decision(metrics, time_since_last_scaling)
        elif self.scaling_policy == ScalingPolicy.COST_OPTIMIZED:
            return await self._cost_optimized_scaling_decision(metrics, time_since_last_scaling)
        
        return ScalingDecision(action="no_action", target_workers=metrics.active_workers, reasoning="Unknown policy", confidence=0.0, priority_level="normal")
    
    async def _reactive_scaling_decision(self, metrics: ScalingMetrics, time_since_last_scaling: float) -> ScalingDecision:
        """Reactive scaling based on current queue size and worker utilization"""
        
        # Calculate queue pressure
        queue_per_worker = metrics.queue_size_total / max(metrics.active_workers, 1)
        
        # Scale up conditions
        if (queue_per_worker > self.scaling_config['scale_up_threshold'] and 
            time_since_last_scaling > self.scaling_config['scale_up_cooldown'] and
            metrics.active_workers < self.max_workers):
            
            # Calculate optimal workers needed
            optimal_workers = math.ceil(metrics.queue_size_total / self.scaling_config['scale_up_threshold'])
            scale_up_amount = min(
                self.scaling_config['max_scale_up_rate'],
                optimal_workers - metrics.active_workers,
                self.max_workers - metrics.active_workers
            )
            
            return ScalingDecision(
                action="scale_up",
                target_workers=metrics.active_workers + scale_up_amount,
                reasoning=f"Queue pressure {queue_per_worker:.1f} > {self.scaling_config['scale_up_threshold']}",
                confidence=min(0.9, queue_per_worker / self.scaling_config['scale_up_threshold']),
                priority_level="normal"
            )
        
        # Scale down conditions
        elif (queue_per_worker < self.scaling_config['scale_down_threshold'] and 
              time_since_last_scaling > self.scaling_config['scale_down_cooldown'] and
              metrics.active_workers > self.min_workers and
              metrics.worker_utilization < 0.5):
            
            scale_down_amount = min(
                self.scaling_config['max_scale_down_rate'],
                metrics.active_workers - self.min_workers
            )
            
            return ScalingDecision(
                action="scale_down",
                target_workers=metrics.active_workers - scale_down_amount,
                reasoning=f"Low queue pressure {queue_per_worker:.1f} and utilization {metrics.worker_utilization:.2f}",
                confidence=0.7,
                priority_level="normal",
                estimated_cost_impact=-scale_down_amount * 0.10  # Estimated hourly cost savings
            )
        
        return ScalingDecision(
            action="no_action",
            target_workers=metrics.active_workers,
            reasoning="Within acceptable thresholds",
            confidence=0.8,
            priority_level="normal"
        )
    
    async def _predictive_scaling_decision(self, metrics: ScalingMetrics, time_since_last_scaling: float) -> ScalingDecision:
        """Predictive scaling based on historical patterns and trends"""
        
        if len(self.metrics_history) < 5:
            # Fall back to reactive if not enough history
            return await self._reactive_scaling_decision(metrics, time_since_last_scaling)
        
        # Analyze trends
        recent_metrics = list(self.metrics_history)[-5:]
        queue_trend = self._calculate_trend([m.queue_size_total for m in recent_metrics])
        utilization_trend = self._calculate_trend([m.worker_utilization for m in recent_metrics])
        
        # Predict future load
        predicted_queue_size = metrics.queue_size_total + (queue_trend * 3)  # 3 cycles ahead
        predicted_utilization = metrics.worker_utilization + (utilization_trend * 3)
        
        # Make decision based on predictions
        if predicted_queue_size > metrics.queue_size_total * 1.5 and metrics.active_workers < self.max_workers:
            workers_needed = math.ceil(predicted_queue_size / self.scaling_config['scale_up_threshold'])
            scale_amount = min(
                self.scaling_config['max_scale_up_rate'],
                workers_needed - metrics.active_workers,
                self.max_workers - metrics.active_workers
            )
            
            return ScalingDecision(
                action="scale_up",
                target_workers=metrics.active_workers + scale_amount,
                reasoning=f"Predicted queue growth: {predicted_queue_size:.0f} (trend: {queue_trend:+.1f})",
                confidence=0.75,
                priority_level="predictive"
            )
        
        elif (predicted_utilization < 0.3 and 
              predicted_queue_size < metrics.queue_size_total * 0.7 and 
              metrics.active_workers > self.min_workers):
            
            scale_amount = min(self.scaling_config['max_scale_down_rate'], metrics.active_workers - self.min_workers)
            
            return ScalingDecision(
                action="scale_down",
                target_workers=metrics.active_workers - scale_amount,
                reasoning=f"Predicted low utilization: {predicted_utilization:.2f}",
                confidence=0.6,
                priority_level="predictive",
                estimated_cost_impact=-scale_amount * 0.10
            )
        
        # If no predictive action needed, fall back to reactive
        return await self._reactive_scaling_decision(metrics, time_since_last_scaling)
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend slope for a series of values"""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        sum_x = sum(range(n))
        sum_y = sum(values)
        sum_xy = sum(i * values[i] for i in range(n))
        sum_x2 = sum(i * i for i in range(n))
        
        # Linear regression slope
        try:
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            return slope
        except ZeroDivisionError:
            return 0.0
    
    async def _aggressive_scaling_decision(self, metrics: ScalingMetrics, time_since_last_scaling: float) -> ScalingDecision:
        """Aggressive scaling - scale up quickly, down slowly"""
        
        # Reduced cooldowns for scale up, increased for scale down
        scale_up_cooldown = self.scaling_config['scale_up_cooldown'] * 0.5
        scale_down_cooldown = self.scaling_config['scale_down_cooldown'] * 2.0
        
        queue_per_worker = metrics.queue_size_total / max(metrics.active_workers, 1)
        
        # More aggressive scale up
        if (queue_per_worker > self.scaling_config['scale_up_threshold'] * 0.7 and 
            time_since_last_scaling > scale_up_cooldown):
            
            scale_amount = min(
                self.scaling_config['max_scale_up_rate'] * 2,  # Double the scale rate
                self.max_workers - metrics.active_workers
            )
            
            return ScalingDecision(
                action="scale_up",
                target_workers=metrics.active_workers + scale_amount,
                reasoning=f"Aggressive scaling: Queue pressure {queue_per_worker:.1f}",
                confidence=0.8,
                priority_level="aggressive"
            )
        
        # Conservative scale down
        elif (queue_per_worker < self.scaling_config['scale_down_threshold'] * 0.5 and 
              time_since_last_scaling > scale_down_cooldown and
              metrics.worker_utilization < 0.3):
            
            scale_amount = 1  # Scale down one at a time
            
            return ScalingDecision(
                action="scale_down",
                target_workers=metrics.active_workers - scale_amount,
                reasoning=f"Conservative scale down: Very low utilization {metrics.worker_utilization:.2f}",
                confidence=0.6,
                priority_level="conservative"
            )
        
        return ScalingDecision(action="no_action", target_workers=metrics.active_workers, reasoning="Aggressive policy - no action", confidence=0.7, priority_level="normal")
    
    async def _conservative_scaling_decision(self, metrics: ScalingMetrics, time_since_last_scaling: float) -> ScalingDecision:
        """Conservative scaling - scale slowly in both directions"""
        
        # Increased cooldowns
        scale_up_cooldown = self.scaling_config['scale_up_cooldown'] * 2.0
        scale_down_cooldown = self.scaling_config['scale_down_cooldown'] * 1.5
        
        queue_per_worker = metrics.queue_size_total / max(metrics.active_workers, 1)
        
        # Conservative scale up (higher threshold)
        if (queue_per_worker > self.scaling_config['scale_up_threshold'] * 1.5 and 
            time_since_last_scaling > scale_up_cooldown and
            metrics.worker_utilization > 0.8):
            
            return ScalingDecision(
                action="scale_up",
                target_workers=metrics.active_workers + 1,  # One at a time
                reasoning=f"Conservative scale up: High queue pressure {queue_per_worker:.1f} and utilization {metrics.worker_utilization:.2f}",
                confidence=0.9,
                priority_level="conservative"
            )
        
        # Conservative scale down (very low threshold)
        elif (queue_per_worker < self.scaling_config['scale_down_threshold'] * 0.3 and 
              time_since_last_scaling > scale_down_cooldown and
              metrics.worker_utilization < 0.2 and
              len(self.metrics_history) >= 10):  # Require more history
            
            # Ensure sustained low load
            recent_utilization = [m.worker_utilization for m in list(self.metrics_history)[-5:]]
            if all(u < 0.3 for u in recent_utilization):
                return ScalingDecision(
                    action="scale_down",
                    target_workers=metrics.active_workers - 1,
                    reasoning=f"Sustained low utilization: {metrics.worker_utilization:.2f}",
                    confidence=0.8,
                    priority_level="conservative"
                )
        
        return ScalingDecision(action="no_action", target_workers=metrics.active_workers, reasoning="Conservative policy - maintaining stability", confidence=0.85, priority_level="normal")
    
    async def _cost_optimized_scaling_decision(self, metrics: ScalingMetrics, time_since_last_scaling: float) -> ScalingDecision:
        """Cost-optimized scaling balancing performance and cost"""
        
        # Calculate cost per task
        hourly_worker_cost = 0.10  # Estimated cost per worker per hour
        current_hourly_cost = metrics.active_workers * hourly_worker_cost
        
        # Calculate current efficiency
        if metrics.tasks_per_minute > 0:
            cost_per_task = (current_hourly_cost / 60) / metrics.tasks_per_minute
            target_cost_per_task = 0.05  # Target cost per task
        else:
            cost_per_task = float('inf')
            target_cost_per_task = 0.05
        
        # SLA requirements
        max_acceptable_wait_time = 300  # 5 minutes
        
        # Cost-optimized decisions
        if metrics.estimated_wait_time > max_acceptable_wait_time:
            # SLA breach - must scale up regardless of cost
            workers_needed = math.ceil(metrics.queue_size_total / self.scaling_config['scale_up_threshold'])
            scale_amount = min(
                workers_needed - metrics.active_workers,
                self.max_workers - metrics.active_workers
            )
            
            return ScalingDecision(
                action="scale_up",
                target_workers=metrics.active_workers + scale_amount,
                reasoning=f"SLA breach: Wait time {metrics.estimated_wait_time:.0f}s > {max_acceptable_wait_time}s",
                confidence=1.0,
                priority_level="sla",
                estimated_cost_impact=scale_amount * hourly_worker_cost
            )
        
        elif cost_per_task > target_cost_per_task * 1.5 and metrics.active_workers > self.min_workers:
            # Cost too high - scale down if possible
            potential_workers = metrics.active_workers - 1
            potential_wait_time = (metrics.queue_size_total * metrics.average_task_duration) / max(potential_workers, 1)
            
            if potential_wait_time < max_acceptable_wait_time:
                return ScalingDecision(
                    action="scale_down",
                    target_workers=potential_workers,
                    reasoning=f"Cost optimization: {cost_per_task:.3f} > target {target_cost_per_task:.3f}",
                    confidence=0.7,
                    priority_level="cost",
                    estimated_cost_impact=-hourly_worker_cost
                )
        
        elif (cost_per_task < target_cost_per_task * 0.5 and 
              metrics.estimated_wait_time < max_acceptable_wait_time * 0.3):
            # Very efficient - could scale up for better throughput if cost-effective
            potential_workers = metrics.active_workers + 1
            potential_cost_per_task = ((potential_workers * hourly_worker_cost) / 60) / max(metrics.tasks_per_minute * 1.2, 1)  # Assume 20% throughput increase
            
            if potential_cost_per_task < target_cost_per_task and potential_workers <= self.max_workers:
                return ScalingDecision(
                    action="scale_up",
                    target_workers=potential_workers,
                    reasoning=f"Cost-effective throughput improvement opportunity",
                    confidence=0.6,
                    priority_level="optimization",
                    estimated_cost_impact=hourly_worker_cost
                )
        
        return ScalingDecision(
            action="no_action",
            target_workers=metrics.active_workers,
            reasoning=f"Cost optimized: ${cost_per_task:.3f} per task, {metrics.estimated_wait_time:.0f}s wait time",
            confidence=0.8,
            priority_level="normal"
        )
    
    async def _execute_scaling_decision(self, decision: ScalingDecision):
        """Execute the scaling decision"""
        
        try:
            current_workers = await self.worker_coordinator.get_active_worker_count()
            
            if decision.action == "scale_up":
                workers_to_add = decision.target_workers - current_workers
                added_workers = await self._scale_up_workers(workers_to_add)
                
                logger.info(f"Scaled up {added_workers} workers (target: {decision.target_workers}). Reasoning: {decision.reasoning}")
                
            elif decision.action == "scale_down":
                workers_to_remove = current_workers - decision.target_workers
                removed_workers = await self._scale_down_workers(workers_to_remove)
                
                logger.info(f"Scaled down {removed_workers} workers (target: {decision.target_workers}). Reasoning: {decision.reasoning}")
            
            # Record scaling action
            self.last_scaling_action = time.time()
            
            # Update scaling history
            scaling_record = {
                'timestamp': utc_now_iso(),
                'action': decision.action,
                'from_workers': current_workers,
                'to_workers': decision.target_workers,
                'reasoning': decision.reasoning,
                'confidence': decision.confidence,
                'priority_level': decision.priority_level,
                'cost_impact': decision.estimated_cost_impact
            }
            
            self.scaling_history.append(scaling_record)
            
            # Store in Redis for persistence
            await self._store_scaling_record(scaling_record)
            
            self.performance_metrics['total_scaling_actions'] += 1
            
        except Exception as e:
            logger.error(f"Error executing scaling decision: {e}", exc_info=True)
    
    async def _scale_up_workers(self, count: int) -> int:
        """Scale up workers intelligently based on task types and load"""
        
        if count <= 0:
            return 0
        
        added_workers = 0
        
        try:
            # Determine what types of workers to add based on queue composition
            queue_stats = await self.task_queue.get_queue_stats()
            task_type_distribution = await self._analyze_queue_composition()
            
            # Add workers based on task type demand
            for task_type, demand_percentage in task_type_distribution.items():
                if added_workers >= count:
                    break
                
                workers_for_type = max(1, int(count * demand_percentage))
                worker_type = self._get_optimal_worker_type(task_type)
                
                # Add workers of this type
                for _ in range(min(workers_for_type, count - added_workers)):
                    worker_id = await self._create_worker(worker_type)
                    if worker_id:
                        added_workers += 1
                    else:
                        logger.warning(f"Failed to create worker of type {worker_type}")
                        break
            
            # If we still need more workers, add general workers
            while added_workers < count:
                worker_id = await self._create_worker(WorkerType.GENERAL)
                if worker_id:
                    added_workers += 1
                else:
                    break
            
            return added_workers
            
        except Exception as e:
            logger.error(f"Error scaling up workers: {e}", exc_info=True)
            return added_workers
    
    async def _scale_down_workers(self, count: int) -> int:
        """Scale down workers gracefully"""
        
        if count <= 0:
            return 0
        
        try:
            # Get current workers and their status
            all_workers = await self.worker_coordinator.get_all_worker_stats()
            
            # Sort workers by priority for removal (idle first, then by utilization)
            workers_by_priority = []
            
            for worker_id, stats in all_workers.items():
                if stats.get('status') != WorkerStatus.ACTIVE.value:
                    continue
                
                priority_score = 0
                
                # Prioritize idle workers
                if stats.get('current_task_count', 0) == 0:
                    priority_score += 100
                
                # Consider utilization (lower utilization = higher priority for removal)
                utilization = stats.get('utilization', 0.0)
                priority_score += (1.0 - utilization) * 50
                
                # Consider worker age (newer workers first)
                uptime = stats.get('uptime_seconds', 0)
                priority_score += max(0, 3600 - uptime) / 3600 * 25
                
                workers_by_priority.append((worker_id, priority_score))
            
            # Sort by priority (highest first)
            workers_by_priority.sort(key=lambda x: x[1], reverse=True)
            
            # Remove workers
            removed_workers = 0
            
            for worker_id, _ in workers_by_priority[:count]:
                if await self._remove_worker(worker_id):
                    removed_workers += 1
                    logger.info(f"Removed worker {worker_id}")
                else:
                    logger.warning(f"Failed to remove worker {worker_id}")
            
            return removed_workers
            
        except Exception as e:
            logger.error(f"Error scaling down workers: {e}", exc_info=True)
            return 0
    
    async def _analyze_queue_composition(self) -> Dict[TaskType, float]:
        """Analyze queue composition to determine optimal worker types"""
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return {TaskType.SECURITY_SCAN: 0.8, TaskType.AUTOFIX: 0.2}  # Default distribution
            
            task_type_counts = defaultdict(int)
            total_tasks = 0
            
            # Analyze all priority queues
            for priority in TaskPriority:
                queue_key = self.task_queue.queue_keys[priority]
                tasks = await redis_client.zrange(queue_key, 0, -1)
                
                for task_json in tasks:
                    try:
                        task_data = json.loads(task_json)
                        task_type = TaskType(task_data.get('type', 'security_scan'))
                        task_type_counts[task_type] += 1
                        total_tasks += 1
                    except Exception as e:
                        logger.warning(f"Error parsing task for composition analysis: {e}")
            
            # Calculate distribution percentages
            if total_tasks == 0:
                return {TaskType.SECURITY_SCAN: 0.8, TaskType.AUTOFIX: 0.2}
            
            distribution = {}
            for task_type, count in task_type_counts.items():
                distribution[task_type] = count / total_tasks
            
            return distribution
            
        except Exception as e:
            logger.error(f"Error analyzing queue composition: {e}", exc_info=True)
            return {TaskType.SECURITY_SCAN: 0.8, TaskType.AUTOFIX: 0.2}
    
    def _get_optimal_worker_type(self, task_type: TaskType) -> WorkerType:
        """Get optimal worker type for a task type"""
        
        mapping = {
            TaskType.SECURITY_SCAN: WorkerType.SECURITY_SCAN,
            TaskType.AUTOFIX: WorkerType.AUTOFIX,
            TaskType.REPORT_GENERATION: WorkerType.REPORT,
            TaskType.NOTIFICATION: WorkerType.LIGHTWEIGHT,
            TaskType.CLEANUP: WorkerType.LIGHTWEIGHT,
            TaskType.ANALYTICS: WorkerType.GENERAL,
        }
        
        return mapping.get(task_type, WorkerType.GENERAL)
    
    async def _create_worker(self, worker_type: WorkerType) -> Optional[str]:
        """Create a new worker of the specified type"""
        
        try:
            # Create worker capabilities based on type
            capabilities = WorkerCapabilities(
                max_concurrent_tasks=self._get_max_concurrent_tasks(worker_type),
                supported_task_types=self._get_supported_task_types(worker_type),
                resource_limits=self.worker_pools[worker_type].resource_requirements,
                tags=self._get_worker_tags(worker_type)
            )
            
            # Create worker through coordinator
            worker_id = await self.worker_coordinator.create_worker(
                worker_type=worker_type.value,
                capabilities=capabilities
            )
            
            if worker_id:
                # Update pool counts
                self.worker_pools[worker_type].current_workers += 1
                logger.info(f"Created worker {worker_id} of type {worker_type.value}")
            
            return worker_id
            
        except Exception as e:
            logger.error(f"Error creating worker of type {worker_type}: {e}", exc_info=True)
            return None
    
    async def _remove_worker(self, worker_id: str) -> bool:
        """Remove a worker gracefully"""
        
        try:
            # Get worker info to update pool counts
            worker_stats = await self.worker_coordinator.get_worker_stats(worker_id)
            if worker_stats:
                worker_type_str = worker_stats.get('worker_type', 'general')
                try:
                    worker_type = WorkerType(worker_type_str)
                    if self.worker_pools[worker_type].current_workers > 0:
                        self.worker_pools[worker_type].current_workers -= 1
                except (ValueError, KeyError):
                    logger.warning(f"Unknown worker type {worker_type_str} for worker {worker_id}")
            
            # Remove through coordinator
            success = await self.worker_coordinator.remove_worker(worker_id)
            
            if success:
                logger.info(f"Removed worker {worker_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error removing worker {worker_id}: {e}", exc_info=True)
            return False
    
    def _get_max_concurrent_tasks(self, worker_type: WorkerType) -> int:
        """Get max concurrent tasks for worker type"""
        return {
            WorkerType.GENERAL: 2,
            WorkerType.SECURITY_SCAN: 1,  # CPU intensive
            WorkerType.AUTOFIX: 1,        # Complex processing
            WorkerType.REPORT: 3,         # I/O bound
            WorkerType.LIGHTWEIGHT: 5     # Simple tasks
        }.get(worker_type, 2)
    
    def _get_supported_task_types(self, worker_type: WorkerType) -> List[str]:
        """Get supported task types for worker type"""
        return {
            WorkerType.GENERAL: [t.value for t in TaskType],
            WorkerType.SECURITY_SCAN: [TaskType.SECURITY_SCAN.value],
            WorkerType.AUTOFIX: [TaskType.AUTOFIX.value],
            WorkerType.REPORT: [TaskType.REPORT_GENERATION.value, TaskType.ANALYTICS.value],
            WorkerType.LIGHTWEIGHT: [TaskType.NOTIFICATION.value, TaskType.CLEANUP.value]
        }.get(worker_type, [])
    
    def _get_worker_tags(self, worker_type: WorkerType) -> List[str]:
        """Get worker tags for routing"""
        return {
            WorkerType.GENERAL: ["general", "cpu", "memory"],
            WorkerType.SECURITY_SCAN: ["security", "scan", "cpu-intensive"],
            WorkerType.AUTOFIX: ["autofix", "git", "ai"],
            WorkerType.REPORT: ["report", "io-intensive"],
            WorkerType.LIGHTWEIGHT: ["lightweight", "fast"]
        }.get(worker_type, ["general"])
    
    async def _health_check_workers(self):
        """Perform health checks on all workers"""
        
        try:
            unhealthy_workers = await self.worker_coordinator.health_check_all_workers()
            
            for worker_id in unhealthy_workers:
                logger.warning(f"Worker {worker_id} failed health check, attempting recovery")
                
                # Try to recover worker
                recovered = await self.worker_coordinator.recover_worker(worker_id)
                
                if not recovered:
                    logger.error(f"Failed to recover worker {worker_id}, removing it")
                    await self._remove_worker(worker_id)
                    
                    # If we're below minimum workers, add a new one
                    current_workers = await self.worker_coordinator.get_active_worker_count()
                    if current_workers < self.min_workers:
                        await self._create_worker(WorkerType.GENERAL)
                        
        except Exception as e:
            logger.error(f"Error during worker health checks: {e}", exc_info=True)
    
    async def _ensure_minimum_workers(self):
        """Ensure minimum number of workers are running"""
        
        try:
            current_workers = await self.worker_coordinator.get_active_worker_count()
            
            if current_workers < self.min_workers:
                workers_needed = self.min_workers - current_workers
                logger.info(f"Starting {workers_needed} workers to reach minimum of {self.min_workers}")
                
                for _ in range(workers_needed):
                    await self._create_worker(WorkerType.GENERAL)
                    
        except Exception as e:
            logger.error(f"Error ensuring minimum workers: {e}", exc_info=True)
    
    async def _maintenance_tasks(self):
        """Perform periodic maintenance tasks"""
        
        try:
            # Cleanup expired tasks
            expired_count = await self.task_queue.cleanup_expired_tasks()
            
            # Cleanup old retry records
            retry_cleanup_count = await self.retry_handler.cleanup_old_records()
            
            if expired_count > 0 or retry_cleanup_count > 0:
                logger.info(f"Maintenance: Cleaned {expired_count} expired tasks, {retry_cleanup_count} old retry records")
                
        except Exception as e:
            logger.error(f"Error during maintenance tasks: {e}", exc_info=True)
    
    async def _calculate_average_task_duration(self) -> float:
        """Calculate average task duration from recent metrics"""
        
        if not self.metrics_history:
            return 120.0  # Default 2 minutes
        
        recent_metrics = list(self.metrics_history)[-10:]  # Last 10 data points
        
        # This is a simplified calculation
        # In production, you'd track actual task durations
        total_processing_time = sum(m.processing_tasks * 60 for m in recent_metrics)  # Assume 60s per active task
        total_completed_tasks = max(1, sum(getattr(m, 'completed_tasks', 0) for m in recent_metrics))
        
        return total_processing_time / total_completed_tasks
    
    async def _update_performance_metrics(self, current_metrics: ScalingMetrics):
        """Update performance tracking metrics"""
        
        try:
            # Update total tasks processed (estimate)
            self.performance_metrics['total_tasks_processed'] += max(0, current_metrics.processing_tasks)
            
            # Update average response time
            if current_metrics.estimated_wait_time > 0:
                alpha = 0.1  # Exponential moving average factor
                self.performance_metrics['average_response_time'] = (
                    self.performance_metrics['average_response_time'] * (1 - alpha) +
                    current_metrics.estimated_wait_time * alpha
                )
            
            # Calculate cost optimization (simplified)
            optimal_workers = max(self.min_workers, current_metrics.queue_size_total // 3)
            if optimal_workers > 0:
                efficiency = min(1.0, optimal_workers / max(current_metrics.active_workers, 1))
                self.performance_metrics['cost_optimization_percentage'] = efficiency * 100
            
        except Exception as e:
            logger.error(f"Error updating performance metrics: {e}", exc_info=True)
    
    async def _store_scaling_record(self, record: Dict[str, Any]):
        """Store scaling record in Redis for analytics"""
        
        try:
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.lpush(self.scaling_history_key, json.dumps(record))
                # Keep only last 1000 records
                await redis_client.ltrim(self.scaling_history_key, 0, 999)
        except Exception as e:
            logger.warning(f"Failed to store scaling record: {e}")
    
    # Public API methods
    
    async def enqueue_task(self, **kwargs) -> str:
        """Enqueue a task - delegates to priority queue"""
        return await self.task_queue.enqueue_task(**kwargs)
    
    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status - delegates to priority queue"""
        return await self.task_queue.get_task_status(task_id)
    
    async def get_system_stats(self) -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        
        try:
            # Get component stats
            queue_stats = await self.task_queue.get_queue_stats()
            retry_stats = await self.retry_handler.get_retry_stats()
            worker_stats = await self.worker_coordinator.get_system_stats()
            
            # Get current metrics
            current_metrics = await self._collect_metrics()
            
            # Build comprehensive stats
            system_stats = {
                'timestamp': utc_now_iso(),
                'auto_scaling': {
                    'policy': self.scaling_policy.value,
                    'min_workers': self.min_workers,
                    'max_workers': self.max_workers,
                    'current_workers': current_metrics.active_workers,
                    'worker_utilization': current_metrics.worker_utilization,
                    'last_scaling_action': self.last_scaling_action,
                    'total_scaling_actions': self.performance_metrics['total_scaling_actions']
                },
                'queue': queue_stats,
                'retry': retry_stats,
                'workers': worker_stats,
                'performance': self.performance_metrics,
                'metrics': asdict(current_metrics),
                'worker_pools': {
                    name: asdict(pool) for name, pool in self.worker_pools.items()
                }
            }
            
            return system_stats
            
        except Exception as e:
            logger.error(f"Error getting system stats: {e}", exc_info=True)
            return {'error': str(e)}
    
    async def get_scaling_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent scaling history"""
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return list(self.scaling_history)[-limit:]
            
            history_json = await redis_client.lrange(self.scaling_history_key, 0, limit - 1)
            history = []
            
            for record_json in history_json:
                try:
                    history.append(json.loads(record_json))
                except Exception as e:
                    logger.warning(f"Error parsing scaling history record: {e}")
            
            return history
            
        except Exception as e:
            logger.error(f"Error getting scaling history: {e}", exc_info=True)
            return []
    
    async def update_scaling_config(self, config_updates: Dict[str, Any]) -> bool:
        """Update scaling configuration"""
        
        try:
            for key, value in config_updates.items():
                if key in self.scaling_config:
                    old_value = self.scaling_config[key]
                    self.scaling_config[key] = value
                    logger.info(f"Updated scaling config {key}: {old_value} -> {value}")
            
            # Store updated config in Redis
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hset(self.config_key, mapping=self.scaling_config)
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating scaling config: {e}", exc_info=True)
            return False