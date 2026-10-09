"""
Event System Health Check Endpoint
Provides detailed health monitoring for the event-driven worker system
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging

from scans.event_driven.worker_events import event_system
from scans.event_driven.diagnostics import diagnostics, run_quick_health_check, monitor_events, stress_test
from core.redis_optimized import get_redis_optimizer

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/event-system")
async def get_event_system_health() -> Dict[str, Any]:
    """
    Get comprehensive health status of the event-driven worker system.
    
    Returns detailed metrics about:
    - Event system status and configuration
    - Redis connection health
    - Subscription status
    - Connection optimization metrics
    """
    try:
        # Get event system stats
        event_stats = await event_system.get_system_stats()
        
        # Get Redis optimizer health
        redis_health = {"status": "unavailable"}
        optimizer = await get_redis_optimizer()
        if optimizer and optimizer.enabled:
            redis_health = await optimizer.health_check()
            perf_stats = await optimizer.get_performance_stats()
            redis_health["performance"] = {
                "l1l2_cache_stats": perf_stats.get("l1l2_cache_stats", {}),
                "pool_count": len(perf_stats.get("pool_stats", {})),
                "circuit_breakers": len(perf_stats.get("circuit_breaker_stats", {}))
            }
        
        # Calculate overall health score
        health_score = 100
        issues = []
        
        # Check event system
        if not event_stats["enabled"]:
            health_score -= 50
            issues.append("Event system is disabled")
        
        # Check Redis connectivity
        if redis_health["status"] != "healthy":
            health_score -= 30
            issues.append(f"Redis status: {redis_health['status']}")
        
        # Check active subscribers
        total_subscribers = sum(event_stats["active_subscribers"].values())
        if total_subscribers == 0:
            health_score -= 10
            issues.append("No active subscribers")
        
        # Check subscription health
        sub_health = event_stats.get("subscription_health", {})
        if sub_health.get("failed_tasks", 0) > 0:
            health_score -= 5
            issues.append(f"Failed subscription tasks: {sub_health['failed_tasks']}")
        
        # Determine overall status
        if health_score >= 90:
            overall_status = "healthy"
        elif health_score >= 70:
            overall_status = "degraded"
        else:
            overall_status = "unhealthy"
        
        return {
            "status": overall_status,
            "health_score": health_score,
            "issues": issues,
            "event_system": event_stats,
            "redis_health": redis_health,
            "recommendations": _get_health_recommendations(event_stats, redis_health, issues),
            "timestamp": event_stats.get("timestamp")
        }
        
    except Exception as e:
        logger.error(f"Event system health check failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Health check failed: {str(e)}"
        )

def _get_health_recommendations(event_stats: Dict, redis_health: Dict, issues: list) -> list:
    """Generate health recommendations based on current status"""
    recommendations = []
    
    if not event_stats["enabled"]:
        recommendations.append("Enable event-driven workers by setting ENABLE_EVENT_DRIVEN_WORKERS=true")
    
    if redis_health["status"] != "healthy":
        recommendations.append("Check Redis connection configuration and ensure Redis server is running")
    
    total_subscribers = sum(event_stats["active_subscribers"].values())
    if total_subscribers == 0:
        recommendations.append("Start worker processes to establish event subscriptions")
    
    sub_health = event_stats.get("subscription_health", {})
    if sub_health.get("failed_tasks", 0) > 0:
        recommendations.append("Check worker logs for subscription errors and restart affected workers")
    
    # Connection optimization recommendations
    conn_opt = event_stats.get("connection_optimization", {})
    if conn_opt.get("persistent_connections", 0) > 20:
        recommendations.append("Consider increasing WORKER_CONNECTION_REUSE_TIME to reduce connection churn")
    
    if not recommendations:
        recommendations.append("Event system is operating optimally")
    
    return recommendations

@router.get("/event-system/metrics")
async def get_event_system_metrics() -> Dict[str, Any]:
    """
    Get detailed metrics for monitoring and alerting.
    
    Returns metrics suitable for monitoring systems like Prometheus.
    """
    try:
        event_stats = await event_system.get_system_stats()
        
        # Extract key metrics
        metrics = {
            "event_system_enabled": 1 if event_stats["enabled"] else 0,
            "total_active_subscribers": sum(event_stats["active_subscribers"].values()),
            "scan_workers_subscribed": event_stats["active_subscribers"].get("scan_workers", 0),
            "autofix_workers_subscribed": event_stats["active_subscribers"].get("autofix_workers", 0),
            "webhook_workers_subscribed": event_stats["active_subscribers"].get("webhook_workers", 0),
            "redis_available": 1 if event_stats["redis_available"] else 0
        }
        
        # Add subscription health metrics
        sub_health = event_stats.get("subscription_health", {})
        metrics.update({
            "total_subscriptions": sub_health.get("total_subscriptions", 0),
            "active_subscription_tasks": sub_health.get("active_tasks", 0),
            "failed_subscription_tasks": sub_health.get("failed_tasks", 0),
            "cleanup_tasks_pending": sub_health.get("cleanup_tasks_pending", 0),
            "subscription_monitoring_active": 1 if sub_health.get("monitoring_active", False) else 0
        })
        
        # Add connection optimization metrics
        conn_opt = event_stats.get("connection_optimization", {})
        metrics.update({
            "persistent_connections_count": conn_opt.get("persistent_connections", 0),
            "connection_reuse_time_seconds": conn_opt.get("connection_reuse_time_seconds", 0),
            "autofix_poll_interval_seconds": conn_opt.get("autofix_fallback_poll_interval_seconds", 0),
            "webhook_poll_interval_seconds": conn_opt.get("webhook_fallback_poll_interval_seconds", 0),
            "worker_ping_interval_seconds": conn_opt.get("worker_ping_interval_seconds", 0)
        })
        
        return {
            "metrics": metrics,
            "labels": {
                "service": "devsecurex-backend",
                "component": "event-system"
            }
        }
        
    except Exception as e:
        logger.error(f"Event system metrics collection failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Metrics collection failed: {str(e)}"
        )

@router.get("/event-system/diagnostics")
async def run_event_system_diagnostics() -> Dict[str, Any]:
    """
    Run comprehensive diagnostic tests on the event system.
    
    Returns detailed analysis of:
    - Redis connectivity and pub/sub functionality
    - Subscription mechanism reliability
    - Event publishing effectiveness
    - End-to-end event flow verification
    - Real subscriber count validation
    """
    try:
        diagnosis = await run_quick_health_check()
        return diagnosis
        
    except Exception as e:
        logger.error(f"Event system diagnostics failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Diagnostics failed: {str(e)}"
        )

@router.get("/event-system/monitor")
async def monitor_live_events(duration: int = 60) -> Dict[str, Any]:
    """
    Monitor live event activity for debugging.
    
    Args:
        duration: Monitoring duration in seconds (default: 60, max: 300)
    
    Returns real-time event monitoring data.
    """
    try:
        # Limit duration to prevent long-running requests
        duration = min(max(duration, 10), 300)  # Between 10 and 300 seconds
        
        monitoring_result = await monitor_events(duration)
        return monitoring_result
        
    except Exception as e:
        logger.error(f"Event monitoring failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Monitoring failed: {str(e)}"
        )

@router.get("/event-system/stress-test")
async def run_stress_test(workers: int = 5, duration: int = 30) -> Dict[str, Any]:
    """
    Run stress test with multiple simultaneous subscriptions.
    
    Args:
        workers: Number of test workers (default: 5, max: 20)
        duration: Test duration in seconds (default: 30, max: 120)
    
    Returns stress test results and performance metrics.
    """
    try:
        # Limit parameters to prevent resource exhaustion
        workers = min(max(workers, 1), 20)  # Between 1 and 20 workers
        duration = min(max(duration, 10), 120)  # Between 10 and 120 seconds
        
        stress_result = await stress_test(workers, duration)
        return stress_result
        
    except Exception as e:
        logger.error(f"Stress test failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Stress test failed: {str(e)}"
        )

@router.get("/event-system/debug")
async def get_debug_information() -> Dict[str, Any]:
    """
    Get detailed debug information for troubleshooting.
    
    Returns:
    - Current system configuration
    - Active subscriptions and connections
    - Redis pub/sub channel status
    - Recent error history
    """
    try:
        from core.redis import get_redis_client
        
        debug_info = {
            "timestamp": event_system.get_system_stats().get("timestamp"),
            "configuration": {
                "enabled": event_system.enabled,
                "channel_prefix": event_system.channel_prefix,
                "channels": {
                    "scan_jobs": event_system.scan_channel,
                    "autofix_jobs": event_system.autofix_channel,
                    "webhook_jobs": event_system.webhook_channel,
                    "control": event_system.control_channel
                }
            },
            "redis_status": {"available": False, "subscriber_counts": {}}
        }
        
        # Get detailed event system stats
        system_stats = await event_system.get_system_stats()
        debug_info["system_stats"] = system_stats
        
        # Get Redis subscriber counts
        redis_client = await get_redis_client()
        if redis_client:
            debug_info["redis_status"]["available"] = True
            
            # Check subscriber counts for all channels
            channels = [
                event_system.scan_channel,
                event_system.autofix_channel,
                event_system.webhook_channel,
                event_system.control_channel
            ]
            
            for channel in channels:
                try:
                    subscribers = await redis_client.pubsub_numsub(channel)
                    count = subscribers.get(channel.encode() if isinstance(channel, str) else channel, 0)
                    debug_info["redis_status"]["subscriber_counts"][channel] = count
                except Exception as e:
                    debug_info["redis_status"]["subscriber_counts"][channel] = f"error: {e}"
        
        return debug_info
        
    except Exception as e:
        logger.error(f"Debug information collection failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Debug info collection failed: {str(e)}"
        )

@router.post("/event-system/test-publish")
async def test_event_publishing() -> Dict[str, Any]:
    """
    Test event publishing by sending a test event.
    
    Returns:
    - Event publishing success status
    - Subscriber count at time of publishing
    - Event delivery confirmation
    """
    try:
        from datetime import datetime
        import time
        
        # Create test job data
        test_job_data = {
            "id": f"test_event_{int(time.time())}",
            "repo_full_name": "test/event-publishing",
            "scan_type": "manual",
            "priority": 2,
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Get subscriber count before publishing
        redis_client = await get_redis_client()
        subscribers_before = 0
        if redis_client:
            subs = await redis_client.pubsub_numsub(event_system.scan_channel)
            subscribers_before = subs.get(event_system.scan_channel.encode(), 0)
        
        # Publish test event
        publish_success = await event_system.publish_scan_job_available(test_job_data)
        
        return {
            "test_job_id": test_job_data["id"],
            "publish_success": publish_success,
            "subscribers_at_publish": subscribers_before,
            "channel": event_system.scan_channel,
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Test event published successfully" if publish_success else "Test event publishing failed"
        }
        
    except Exception as e:
        logger.error(f"Test event publishing failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Test publishing failed: {str(e)}"
        )