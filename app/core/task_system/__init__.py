"""
DevSecureX Phase 4: Enterprise Auto-Scaling Background Task Processing System

This module provides world-class background task processing with:
- Dynamic auto-scaling from 2-15 workers based on load
- Advanced priority queuing with intelligent routing
- Exponential backoff retry logic with dead letter queues
- Distributed task processing with worker coordination
- Comprehensive task lifecycle management
- Real-time monitoring and health checks
"""

from .auto_scaling_manager import AutoScalingTaskManager
from .priority_queue import PriorityTaskQueue, TaskPriority, TaskType
from .retry_handler import RetryHandler, RetryPolicy
from .worker_coordinator import WorkerCoordinator
from .task_monitor import TaskMonitor, TaskMetrics

__all__ = [
    'AutoScalingTaskManager',
    'PriorityTaskQueue', 
    'TaskPriority',
    'TaskType',
    'RetryHandler',
    'RetryPolicy', 
    'WorkerCoordinator',
    'TaskMonitor',
    'TaskMetrics'
]

# Version and metadata
__version__ = "4.0.0"
__phase__ = "Phase 4: Background Task Processing & Auto-Scaling"