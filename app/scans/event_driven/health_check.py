"""
Event-driven system health check and diagnostics
"""
import asyncio
import json
import logging
from typing import Dict, Any, Optional

from core.redis import get_redis_client
from .worker_events import event_system

logger = logging.getLogger(__name__)

async def check_event_system_health() -> Dict[str, Any]:
    """
    Comprehensive health check for the event-driven worker system
    """
    health_status = {
        "status": "unknown",
        "timestamp": asyncio.get_event_loop().time(),
        "components": {
            "event_system": {"status": "unknown"},
            "redis_connectivity": {"status": "unknown"},
            "pubsub_channels": {"status": "unknown"},
            "worker_subscriptions": {"status": "unknown"}
        },
        "recommendations": []
    }
    
    try:
        # 1. Check if event system is enabled
        if not event_system.enabled:
            health_status["status"] = "disabled"
            health_status["components"]["event_system"]["status"] = "disabled"
            health_status["recommendations"].append(
                "Set ENABLE_EVENT_DRIVEN_WORKERS=true to enable instant job processing"
            )
            return health_status
        
        health_status["components"]["event_system"]["status"] = "enabled"
        
        # 2. Check Redis connectivity
        redis_client = await get_redis_client()
        if not redis_client:
            health_status["status"] = "unhealthy"
            health_status["components"]["redis_connectivity"]["status"] = "failed"
            health_status["components"]["redis_connectivity"]["error"] = "Redis client not available"
            health_status["recommendations"].append("Check Redis URL configuration and connectivity")
            return health_status
        
        # Test Redis connection
        try:
            await redis_client.ping()
            health_status["components"]["redis_connectivity"]["status"] = "healthy"
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["components"]["redis_connectivity"]["status"] = "failed"
            health_status["components"]["redis_connectivity"]["error"] = str(e)
            health_status["recommendations"].append("Fix Redis connectivity issues")
            return health_status
        
        # 3. Check pub/sub channels
        try:
            channels_info = await redis_client.pubsub_channels(f"{event_system.channel_prefix}:*")
            health_status["components"]["pubsub_channels"]["status"] = "available"
            health_status["components"]["pubsub_channels"]["active_channels"] = len(channels_info)
            health_status["components"]["pubsub_channels"]["channels"] = list(channels_info)
        except Exception as e:
            health_status["components"]["pubsub_channels"]["status"] = "error"
            health_status["components"]["pubsub_channels"]["error"] = str(e)
            health_status["recommendations"].append("Check Redis pub/sub functionality")
        
        # 4. Get system stats
        try:
            system_stats = await event_system.get_system_stats()
            health_status["system_stats"] = system_stats
            
            # Check for active subscribers
            total_subscribers = sum(system_stats["active_subscribers"].values())
            if total_subscribers == 0:
                health_status["recommendations"].append(
                    "No active worker subscriptions found - check if workers are started"
                )
            else:
                health_status["components"]["worker_subscriptions"]["status"] = "active"
                health_status["components"]["worker_subscriptions"]["count"] = total_subscribers
                
        except Exception as e:
            logger.warning(f"Failed to get event system stats: {e}")
        
        # 5. Test event publishing (if we have subscribers)
        try:
            test_event = {
                "id": "health_check_test",
                "repo_full_name": "test/health-check",
                "scan_type": "health_check",
                "priority": 999,
                "created_at": asyncio.get_event_loop().time()
            }
            
            # This will return the number of subscribers who received the message
            published = await event_system.publish_scan_job_available(test_event)
            
            if published:
                health_status["components"]["event_publishing"] = {
                    "status": "working",
                    "test_published": True
                }
            else:
                health_status["components"]["event_publishing"] = {
                    "status": "no_subscribers",
                    "test_published": False
                }
                
        except Exception as e:
            health_status["components"]["event_publishing"] = {
                "status": "failed",
                "error": str(e)
            }
        
        # Overall health determination
        failed_components = [
            comp for comp, info in health_status["components"].items() 
            if info.get("status") in ["failed", "error"]
        ]
        
        if not failed_components:
            health_status["status"] = "healthy"
        else:
            health_status["status"] = "unhealthy"
            health_status["failed_components"] = failed_components
        
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        health_status["status"] = "error"
        health_status["error"] = str(e)
        return health_status

async def diagnose_event_system_issues() -> Dict[str, Any]:
    """
    Diagnose common issues with the event-driven system
    """
    diagnosis = {
        "timestamp": asyncio.get_event_loop().time(),
        "issues_found": [],
        "recommendations": [],
        "redis_info": {},
        "worker_status": {}
    }
    
    try:
        # Get basic health check first
        health = await check_event_system_health()
        diagnosis["health_status"] = health["status"]
        
        # Check Redis configuration
        redis_client = await get_redis_client()
        if redis_client:
            try:
                redis_info = await redis_client.info()
                diagnosis["redis_info"] = {
                    "version": redis_info.get("redis_version"),
                    "memory_used": redis_info.get("used_memory_human"),
                    "connected_clients": redis_info.get("connected_clients"),
                    "pubsub_channels": redis_info.get("pubsub_channels", 0),
                    "pubsub_patterns": redis_info.get("pubsub_patterns", 0)
                }
                
                if redis_info.get("pubsub_channels", 0) == 0:
                    diagnosis["issues_found"].append("No pub/sub channels found - workers may not be subscribed")
                
            except Exception as e:
                diagnosis["issues_found"].append(f"Failed to get Redis info: {e}")
        
        # Check for common configuration issues
        import os
        
        event_driven_enabled = os.getenv("ENABLE_EVENT_DRIVEN_WORKERS", "true").lower() == "true"
        workers_enabled = os.getenv("ENABLE_BACKGROUND_WORKERS", "false").lower() == "true"
        
        if not event_driven_enabled:
            diagnosis["issues_found"].append("Event-driven workers disabled (ENABLE_EVENT_DRIVEN_WORKERS=false)")
            diagnosis["recommendations"].append("Set ENABLE_EVENT_DRIVEN_WORKERS=true")
        
        if not workers_enabled:
            diagnosis["issues_found"].append("Background workers disabled (ENABLE_BACKGROUND_WORKERS=false)")
            diagnosis["recommendations"].append("Set ENABLE_BACKGROUND_WORKERS=true")
        
        # Check Redis URL
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            diagnosis["issues_found"].append("No REDIS_URL configured")
            diagnosis["recommendations"].append("Configure REDIS_URL environment variable")
        
        return diagnosis
        
    except Exception as e:
        logger.error(f"Diagnosis failed: {e}", exc_info=True)
        diagnosis["error"] = str(e)
        return diagnosis

async def test_event_delivery(timeout: float = 5.0) -> Dict[str, Any]:
    """
    Test event delivery end-to-end
    """
    test_result = {
        "timestamp": asyncio.get_event_loop().time(),
        "test_passed": False,
        "delivery_time_ms": None,
        "subscribers_notified": 0,
        "error": None
    }
    
    try:
        start_time = asyncio.get_event_loop().time()
        
        test_job_data = {
            "id": f"test-event-{int(start_time)}",
            "repo_full_name": "test/event-delivery",
            "scan_type": "test",
            "priority": 999,
            "created_at": start_time
        }
        
        # Publish test event
        published = await event_system.publish_scan_job_available(test_job_data)
        
        end_time = asyncio.get_event_loop().time()
        delivery_time = (end_time - start_time) * 1000  # Convert to milliseconds
        
        test_result["delivery_time_ms"] = round(delivery_time, 2)
        test_result["subscribers_notified"] = published if isinstance(published, bool) and published else 0
        test_result["test_passed"] = published is True
        
        if not test_result["test_passed"]:
            test_result["error"] = "Event publishing failed or no subscribers"
        
        return test_result
        
    except Exception as e:
        test_result["error"] = str(e)
        return test_result