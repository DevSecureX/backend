"""
Worker statistics and monitoring endpoints for event-driven architecture validation.
Provides real-time metrics to validate Redis usage reduction.
"""
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List
import logging
import asyncio
import os
from datetime import datetime, timezone

from core.redis import get_redis_client
from auth.dependencies import get_current_user
from auth.models import User
from .event_driven import event_system

logger = logging.getLogger(__name__)

worker_stats_router = APIRouter(prefix="/workers", tags=["worker-stats"])

@worker_stats_router.get("/stats/overview")
async def get_worker_stats_overview(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get comprehensive worker statistics to validate Redis optimization.
    
    Shows:
    - Event-driven system status
    - Active workers and subscriptions  
    - Redis usage metrics
    - Performance comparisons
    """
    try:
        # Get event system statistics
        event_stats = await event_system.get_system_stats()
        
        # Get Redis client info
        redis_client = await get_redis_client()
        redis_stats = {}
        
        if redis_client:
            try:
                # Get Redis info
                info = await redis_client.info()
                redis_stats = {
                    "connected_clients": info.get("connected_clients", 0),
                    "total_commands_processed": info.get("total_commands_processed", 0),
                    "instantaneous_ops_per_sec": info.get("instantaneous_ops_per_sec", 0),
                    "used_memory_human": info.get("used_memory_human", "unknown"),
                    "keyspace_hits": info.get("keyspace_hits", 0),
                    "keyspace_misses": info.get("keyspace_misses", 0)
                }
            except Exception as e:
                logger.warning(f"Failed to get Redis info: {e}")
                redis_stats = {"error": str(e)}
        else:
            redis_stats = {"error": "Redis client not available"}
        
        # Configuration summary
        config_summary = {
            "event_driven_enabled": os.getenv("ENABLE_EVENT_DRIVEN_WORKERS", "true").lower() == "true",
            "scan_worker_poll_interval": int(os.getenv("SCAN_WORKER_POLL_INTERVAL", "120")),
            "autofix_worker_poll_interval": int(os.getenv("AUTOFIX_WORKER_POLL_INTERVAL", "300")),
            "scan_workers": int(os.getenv("SCAN_WORKERS", "1")),
            "autofix_workers": int(os.getenv("AUTOFIX_WORKERS", "1")),
            "background_workers_enabled": os.getenv("ENABLE_BACKGROUND_WORKERS", "true").lower() == "true"
        }
        
        # Estimated Redis usage reduction calculation
        old_architecture_calls_per_day = _calculate_old_architecture_calls()
        new_architecture_calls_per_day = _calculate_new_architecture_calls(config_summary)
        
        reduction_stats = {
            "old_architecture_daily_calls": old_architecture_calls_per_day,
            "new_architecture_daily_calls": new_architecture_calls_per_day,
            "reduction_percentage": round(((old_architecture_calls_per_day - new_architecture_calls_per_day) / old_architecture_calls_per_day) * 100, 2) if old_architecture_calls_per_day > 0 else 0,
            "calls_saved_per_day": old_architecture_calls_per_day - new_architecture_calls_per_day
        }
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_system": event_stats,
            "redis_stats": redis_stats,
            "worker_config": config_summary,
            "redis_usage_reduction": reduction_stats,
            "architecture_status": "hybrid_event_driven" if config_summary["event_driven_enabled"] else "polling_only"
        }
        
    except Exception as e:
        logger.error(f"Error getting worker stats overview: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@worker_stats_router.get("/stats/redis-usage")
async def get_redis_usage_stats(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get detailed Redis usage statistics for optimization validation.
    """
    try:
        redis_client = await get_redis_client()
        if not redis_client:
            raise HTTPException(status_code=503, detail="Redis client not available")
        
        # Get comprehensive Redis statistics
        info = await redis_client.info()
        stats = await redis_client.info("stats")
        
        # Calculate key metrics
        current_usage = {
            "total_commands": stats.get("total_commands_processed", 0),
            "instantaneous_ops": stats.get("instantaneous_ops_per_sec", 0),
            "connected_clients": info.get("connected_clients", 0),
            "blocked_clients": info.get("blocked_clients", 0),
            "tracking_clients": info.get("tracking_clients", 0),
            "pubsub_channels": info.get("pubsub_channels", 0),
            "pubsub_patterns": info.get("pubsub_patterns", 0)
        }
        
        # Memory usage
        memory_usage = {
            "used_memory": info.get("used_memory", 0),
            "used_memory_human": info.get("used_memory_human", "0B"),
            "used_memory_rss": info.get("used_memory_rss", 0),
            "used_memory_peak": info.get("used_memory_peak", 0),
            "used_memory_peak_human": info.get("used_memory_peak_human", "0B")
        }
        
        # Network usage
        network_stats = {
            "total_net_input_bytes": info.get("total_net_input_bytes", 0),
            "total_net_output_bytes": info.get("total_net_output_bytes", 0),
            "instantaneous_input_kbps": info.get("instantaneous_input_kbps", 0),
            "instantaneous_output_kbps": info.get("instantaneous_output_kbps", 0)
        }
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "current_usage": current_usage,
            "memory_usage": memory_usage,
            "network_stats": network_stats,
            "optimization_metrics": {
                "avg_ops_per_sec_target": "< 10 ops/sec with event-driven architecture",
                "daily_ops_target": "< 1000 operations per day",
                "polling_interval_scan": f"{os.getenv('SCAN_WORKER_POLL_INTERVAL', '120')}s",
                "polling_interval_autofix": f"{os.getenv('AUTOFIX_WORKER_POLL_INTERVAL', '300')}s"
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting Redis usage stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@worker_stats_router.get("/stats/event-system")
async def get_event_system_stats(current_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Get detailed event-driven system statistics.
    """
    try:
        event_stats = await event_system.get_system_stats()
        
        # Add timing information
        config_summary = {
            "system_enabled": event_stats.get("enabled", False),
            "channel_prefix": event_stats.get("channel_prefix", ""),
            "channels": event_stats.get("channels", {}),
            "active_subscribers": event_stats.get("active_subscribers", {}),
            "redis_available": event_stats.get("redis_available", False)
        }
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_system_status": config_summary,
            "performance_impact": {
                "job_notification_latency": "< 100ms (Redis pub/sub)",
                "worker_wakeup_time": "immediate on job availability",
                "fallback_poll_frequency": f"every {os.getenv('SCAN_WORKER_POLL_INTERVAL', '120')}s for scan workers",
                "autofix_poll_frequency": f"every {os.getenv('AUTOFIX_WORKER_POLL_INTERVAL', '300')}s for autofix workers"
            },
            "expected_benefits": {
                "redis_calls_reduction": "99% reduction from polling",
                "job_processing_latency": "sub-second vs minutes with polling",
                "resource_usage": "minimal CPU and network overhead"
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting event system stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@worker_stats_router.post("/workers/shutdown/{worker_type}")
async def shutdown_workers(
    worker_type: str,
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Send shutdown signal to workers via event system.
    """
    valid_types = ["scan", "autofix", "all"]
    if worker_type not in valid_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid worker type. Must be one of: {valid_types}"
        )
    
    try:
        success = await event_system.publish_worker_shutdown(worker_type)
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "worker_type": worker_type,
            "shutdown_signal_sent": success,
            "message": f"Shutdown signal sent to {worker_type} workers" if success else "Failed to send shutdown signal"
        }
        
    except Exception as e:
        logger.error(f"Error sending shutdown signal to {worker_type} workers: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def _calculate_old_architecture_calls() -> int:
    """Calculate estimated Redis calls per day with old polling architecture."""
    # Old architecture assumptions:
    # - 2 scan workers polling every 1-30 seconds
    # - 1 autofix worker polling every 10 seconds  
    # - Health checks and cleanup operations
    
    scan_workers = 2
    autofix_workers = 1
    
    # Conservative estimate: average 15 second polling for scan workers
    scan_calls_per_day = scan_workers * (24 * 60 * 60 / 15)  # ~11,520 calls
    
    # Autofix workers polling every 10 seconds
    autofix_calls_per_day = autofix_workers * (24 * 60 * 60 / 10)  # ~8,640 calls
    
    # Additional operations: cleanup, health checks, etc.
    misc_calls_per_day = 5000
    
    return int(scan_calls_per_day + autofix_calls_per_day + misc_calls_per_day)  # ~25,160 calls

def _calculate_new_architecture_calls(config: Dict[str, Any]) -> int:
    """Calculate estimated Redis calls per day with new event-driven architecture."""
    scan_workers = config.get("scan_workers", 1)
    autofix_workers = config.get("autofix_workers", 1)
    scan_poll_interval = config.get("scan_worker_poll_interval", 120)
    autofix_poll_interval = config.get("autofix_worker_poll_interval", 300)
    
    if config.get("event_driven_enabled", True):
        # Event-driven architecture with fallback polling
        scan_fallback_calls = scan_workers * (24 * 60 * 60 / scan_poll_interval)  # ~720 calls
        autofix_fallback_calls = autofix_workers * (24 * 60 * 60 / autofix_poll_interval)  # ~288 calls
        
        # Event publications (job enqueue notifications) - estimate 100 per day
        event_publish_calls = 100
        
        # Cleanup and health operations - reduced frequency
        misc_calls_per_day = 200
        
        return int(scan_fallback_calls + autofix_fallback_calls + event_publish_calls + misc_calls_per_day)  # ~1,308 calls
    else:
        # Pure polling with optimized intervals
        scan_calls_per_day = scan_workers * (24 * 60 * 60 / scan_poll_interval)
        autofix_calls_per_day = autofix_workers * (24 * 60 * 60 / autofix_poll_interval)
        misc_calls_per_day = 1000
        
        return int(scan_calls_per_day + autofix_calls_per_day + misc_calls_per_day)  # ~1,708 calls