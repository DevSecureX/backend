"""
UNIFIED QUEUE SYSTEM - THE FORTRESS

This module contains the TRUE unified queue system that replaces all fragmented
queue managers and workers. One system, one queue, one worker - fortress-like reliability.

Key Components:
- UnifiedScanQueueManager: Single queue system for ALL scan operations
- UnifiedScanWorker: Single worker system that handles ALL job types
- No subscriptions, no pub/sub, no fragmentation - just reliable direct polling

Usage:
    from app.scans.unified_queue import get_unified_queue_manager, start_unified_worker
    
    # Queue a scan
    queue_manager = await get_unified_queue_manager()
    job_id = await queue_manager.enqueue_scan(...)
    
    # Start a worker
    worker = await start_unified_worker("worker-1", openai_api_key)
"""

from .unified_queue_manager import (
    UnifiedScanQueueManager,
    UnifiedScanJob,
    UnifiedJobStatus,
    UnifiedJobPriority,
    get_unified_queue_manager,
    shutdown_unified_queue_manager
)

from .unified_worker import (
    UnifiedScanWorker,
    start_unified_worker,
    stop_unified_worker,
    stop_all_unified_workers
)

__all__ = [
    "UnifiedScanQueueManager",
    "UnifiedScanJob", 
    "UnifiedJobStatus",
    "UnifiedJobPriority",
    "get_unified_queue_manager",
    "shutdown_unified_queue_manager",
    "UnifiedScanWorker",
    "start_unified_worker",
    "stop_unified_worker",
    "stop_all_unified_workers"
]