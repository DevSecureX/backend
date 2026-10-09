"""
Unified Queue System Monitoring API
Provides comprehensive monitoring and health checks for all enterprise queue systems.
"""

from fastapi import APIRouter, HTTPException, status
from typing import Dict, Any, Optional
import logging
from datetime import datetime, timezone
import asyncio

logger = logging.getLogger(__name__)

# Create router for unified queue monitoring
router = APIRouter(
    prefix="/monitoring/queues",
    tags=["Queue Monitoring"],
    responses={
        404: {"description": "Queue system not found"},
        500: {"description": "Internal server error"}
    }
)


@router.get("/health", summary="Get health status of all queue systems")
async def get_all_queue_health():
    """Get comprehensive health status of all enterprise queue systems"""
    
    health_status = {
        "overall_status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "systems": {}
    }
    
    unhealthy_systems = 0
    total_systems = 0
    
    # Check main scanning queue system
    try:
        from scans.queue.enterprise_queue_manager import get_enterprise_queue_manager
        from scans.workers.enterprise_worker_manager import get_enterprise_worker_manager
        
        queue_manager = await get_enterprise_queue_manager()
        worker_manager = await get_enterprise_worker_manager()
        
        queue_stats = await queue_manager.get_queue_statistics()
        worker_stats = worker_manager.get_worker_statistics()
        
        system_healthy = (
            queue_stats["system_health"]["overall"]["healthy"] and
            queue_stats["circuit_breaker"]["state"] == "CLOSED"
        )
        
        if not system_healthy:
            unhealthy_systems += 1
        
        health_status["systems"]["scanning"] = {
            "status": "healthy" if system_healthy else "unhealthy",
            "queue_size": queue_stats["total_queued"],
            "active_workers": worker_stats["total_workers"],
            "active_scans": queue_stats["active_scans"],
            "circuit_breaker": queue_stats["circuit_breaker"]["state"],
            "system_health": queue_stats["system_health"]["overall"]
        }
        
        total_systems += 1
        
    except Exception as e:
        logger.error(f"Failed to check scanning queue health: {e}")
        health_status["systems"]["scanning"] = {
            "status": "error",
            "error": str(e)
        }
        unhealthy_systems += 1
        total_systems += 1
    
    # Check autofix queue system
    try:
        from scans.autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
        from scans.autofix_queue.enterprise_autofix_worker_manager import get_enterprise_autofix_worker_manager
        
        autofix_queue_manager = await get_enterprise_autofix_queue_manager()
        autofix_worker_manager = await get_enterprise_autofix_worker_manager()
        
        autofix_stats = await autofix_queue_manager.get_queue_statistics()
        autofix_worker_stats = autofix_worker_manager.get_worker_statistics()
        
        system_healthy = (
            autofix_stats["system_health"]["overall"]["healthy"] and
            autofix_stats["circuit_breaker"]["state"] == "CLOSED"
        )
        
        if not system_healthy:
            unhealthy_systems += 1
        
        health_status["systems"]["autofix"] = {
            "status": "healthy" if system_healthy else "unhealthy",
            "queue_size": autofix_stats["total_queued"],
            "active_workers": autofix_worker_stats["total_workers"],
            "active_autofixes": autofix_stats["active_autofixes"],
            "circuit_breaker": autofix_stats["circuit_breaker"]["state"],
            "system_health": autofix_stats["system_health"]["overall"]
        }
        
        total_systems += 1
        
    except Exception as e:
        logger.error(f"Failed to check autofix queue health: {e}")
        health_status["systems"]["autofix"] = {
            "status": "error",
            "error": str(e)
        }
        unhealthy_systems += 1
        total_systems += 1
    
    # Check webhook queue system
    try:
        from scans.webhooks.enterprise_webhook_queue import get_enterprise_webhook_queue_manager
        from scans.webhooks.enterprise_webhook_worker_manager import get_enterprise_webhook_worker_manager
        
        webhook_queue_manager = await get_enterprise_webhook_queue_manager()
        webhook_worker_manager = await get_enterprise_webhook_worker_manager()
        
        webhook_stats = await webhook_queue_manager.get_queue_statistics()
        webhook_worker_stats = webhook_worker_manager.get_worker_statistics()
        
        system_healthy = (
            webhook_stats["system_health"]["overall"]["healthy"] and
            webhook_stats["circuit_breaker"]["state"] in ["CLOSED", "HALF_OPEN"]  # Webhooks can handle half-open
        )
        
        if not system_healthy:
            unhealthy_systems += 1
        
        health_status["systems"]["webhook"] = {
            "status": "healthy" if system_healthy else "unhealthy",
            "queue_size": webhook_stats["total_queued"],
            "active_workers": webhook_worker_stats["total_workers"],
            "active_webhooks": webhook_stats["active_webhooks"],
            "circuit_breaker": webhook_stats["circuit_breaker"]["state"],
            "success_rate": webhook_stats["metrics"]["success_rate"]
        }
        
        total_systems += 1
        
    except Exception as e:
        logger.error(f"Failed to check webhook queue health: {e}")
        health_status["systems"]["webhook"] = {
            "status": "error",
            "error": str(e)
        }
        unhealthy_systems += 1
        total_systems += 1
    
    # Check unified task queue system
    try:
        from core.task_system.enterprise_task_queue_manager import get_enterprise_task_queue_manager
        
        task_queue_manager = await get_enterprise_task_queue_manager()
        task_stats = await task_queue_manager.get_queue_statistics()
        
        system_healthy = task_stats["system_health"]["overall"]["healthy"]
        
        if not system_healthy:
            unhealthy_systems += 1
        
        health_status["systems"]["unified_tasks"] = {
            "status": "healthy" if system_healthy else "unhealthy",
            "total_queued": task_stats["total_queued"],
            "active_tasks": task_stats["active_tasks"],
            "system_health": task_stats["system_health"]["overall"],
            "task_types": task_stats["active_tasks_by_type"]
        }
        
        total_systems += 1
        
    except Exception as e:
        logger.error(f"Failed to check unified task queue health: {e}")
        health_status["systems"]["unified_tasks"] = {
            "status": "error",
            "error": str(e)
        }
        unhealthy_systems += 1
        total_systems += 1
    
    # Calculate overall health
    if unhealthy_systems == 0:
        health_status["overall_status"] = "healthy"
    elif unhealthy_systems < total_systems / 2:
        health_status["overall_status"] = "degraded"
    else:
        health_status["overall_status"] = "unhealthy"
    
    health_status["summary"] = {
        "total_systems": total_systems,
        "healthy_systems": total_systems - unhealthy_systems,
        "unhealthy_systems": unhealthy_systems,
        "health_percentage": ((total_systems - unhealthy_systems) / total_systems * 100) if total_systems > 0 else 0
    }
    
    return health_status


@router.get("/statistics", summary="Get comprehensive statistics for all queue systems")
async def get_all_queue_statistics():
    """Get detailed statistics for all enterprise queue systems"""
    
    statistics = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "systems": {}
    }
    
    # Gather statistics from all systems in parallel
    async def get_scanning_stats():
        try:
            from scans.queue.enterprise_queue_manager import get_enterprise_queue_manager
            from scans.workers.enterprise_worker_manager import get_enterprise_worker_manager
            
            queue_manager = await get_enterprise_queue_manager()
            worker_manager = await get_enterprise_worker_manager()
            
            return {
                "queue": await queue_manager.get_queue_statistics(),
                "workers": worker_manager.get_worker_statistics()
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def get_autofix_stats():
        try:
            from scans.autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
            from scans.autofix_queue.enterprise_autofix_worker_manager import get_enterprise_autofix_worker_manager
            
            queue_manager = await get_enterprise_autofix_queue_manager()
            worker_manager = await get_enterprise_autofix_worker_manager()
            
            return {
                "queue": await queue_manager.get_queue_statistics(),
                "workers": worker_manager.get_worker_statistics()
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def get_webhook_stats():
        try:
            from scans.webhooks.enterprise_webhook_queue import get_enterprise_webhook_queue_manager
            from scans.webhooks.enterprise_webhook_worker_manager import get_enterprise_webhook_worker_manager
            
            queue_manager = await get_enterprise_webhook_queue_manager()
            worker_manager = await get_enterprise_webhook_worker_manager()
            
            return {
                "queue": await queue_manager.get_queue_statistics(),
                "workers": worker_manager.get_worker_statistics()
            }
        except Exception as e:
            return {"error": str(e)}
    
    async def get_task_stats():
        try:
            from core.task_system.enterprise_task_queue_manager import get_enterprise_task_queue_manager
            
            queue_manager = await get_enterprise_task_queue_manager()
            return await queue_manager.get_queue_statistics()
        except Exception as e:
            return {"error": str(e)}
    
    # Run all statistics gathering in parallel
    scanning_stats, autofix_stats, webhook_stats, task_stats = await asyncio.gather(
        get_scanning_stats(),
        get_autofix_stats(),
        get_webhook_stats(),
        get_task_stats(),
        return_exceptions=True
    )
    
    statistics["systems"] = {
        "scanning": scanning_stats,
        "autofix": autofix_stats,
        "webhook": webhook_stats,
        "unified_tasks": task_stats
    }
    
    # Calculate aggregate statistics
    total_queued = 0
    total_active = 0
    total_workers = 0
    
    for system_name, system_stats in statistics["systems"].items():
        if isinstance(system_stats, dict) and "error" not in system_stats:
            if system_name == "unified_tasks":
                total_queued += system_stats.get("total_queued", 0)
                total_active += system_stats.get("active_tasks", 0)
            else:
                queue_stats = system_stats.get("queue", {})
                worker_stats = system_stats.get("workers", {})
                
                total_queued += queue_stats.get("total_queued", 0)
                total_active += queue_stats.get("active_scans", queue_stats.get("active_autofixes", queue_stats.get("active_webhooks", 0)))
                total_workers += worker_stats.get("total_workers", 0)
    
    statistics["aggregates"] = {
        "total_queued_items": total_queued,
        "total_active_items": total_active,
        "total_workers": total_workers
    }
    
    return statistics


@router.get("/scanning", summary="Get detailed scanning queue statistics")
async def get_scanning_queue_stats():
    """Get detailed statistics for the scanning queue system"""
    try:
        from scans.queue.enterprise_queue_manager import get_enterprise_queue_manager
        from scans.workers.enterprise_worker_manager import get_enterprise_worker_manager
        
        queue_manager = await get_enterprise_queue_manager()
        worker_manager = await get_enterprise_worker_manager()
        
        return {
            "queue": await queue_manager.get_queue_statistics(),
            "workers": worker_manager.get_worker_statistics()
        }
    except Exception as e:
        logger.error(f"Failed to get scanning queue stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scanning queue statistics: {str(e)}"
        )


@router.get("/autofix", summary="Get detailed autofix queue statistics")
async def get_autofix_queue_stats():
    """Get detailed statistics for the autofix queue system"""
    try:
        from scans.autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
        from scans.autofix_queue.enterprise_autofix_worker_manager import get_enterprise_autofix_worker_manager
        
        queue_manager = await get_enterprise_autofix_queue_manager()
        worker_manager = await get_enterprise_autofix_worker_manager()
        
        return {
            "queue": await queue_manager.get_queue_statistics(),
            "workers": worker_manager.get_worker_statistics()
        }
    except Exception as e:
        logger.error(f"Failed to get autofix queue stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get autofix queue statistics: {str(e)}"
        )


@router.get("/webhook", summary="Get detailed webhook queue statistics")
async def get_webhook_queue_stats():
    """Get detailed statistics for the webhook queue system"""
    try:
        from scans.webhooks.enterprise_webhook_queue import get_enterprise_webhook_queue_manager
        from scans.webhooks.enterprise_webhook_worker_manager import get_enterprise_webhook_worker_manager
        
        queue_manager = await get_enterprise_webhook_queue_manager()
        worker_manager = await get_enterprise_webhook_worker_manager()
        
        return {
            "queue": await queue_manager.get_queue_statistics(),
            "workers": worker_manager.get_worker_statistics()
        }
    except Exception as e:
        logger.error(f"Failed to get webhook queue stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get webhook queue statistics: {str(e)}"
        )


@router.get("/tasks", summary="Get detailed unified task queue statistics")
async def get_unified_task_stats():
    """Get detailed statistics for the unified task queue system"""
    try:
        from core.task_system.enterprise_task_queue_manager import get_enterprise_task_queue_manager
        
        queue_manager = await get_enterprise_task_queue_manager()
        return await queue_manager.get_queue_statistics()
    except Exception as e:
        logger.error(f"Failed to get unified task stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get unified task statistics: {str(e)}"
        )


@router.post("/scanning/workers/scale", summary="Scale scanning workers")
async def scale_scanning_workers(target_workers: int):
    """Scale the number of scanning workers"""
    try:
        from scans.workers.enterprise_worker_manager import get_enterprise_worker_manager
        
        worker_manager = await get_enterprise_worker_manager()
        await worker_manager._scale_workers(target_workers)
        
        return {
            "success": True,
            "message": f"Scanning workers scaled to {target_workers}",
            "current_workers": len(worker_manager.workers)
        }
    except Exception as e:
        logger.error(f"Failed to scale scanning workers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scale scanning workers: {str(e)}"
        )


@router.post("/autofix/workers/scale", summary="Scale autofix workers")
async def scale_autofix_workers(target_workers: int):
    """Scale the number of autofix workers"""
    try:
        from scans.autofix_queue.enterprise_autofix_worker_manager import get_enterprise_autofix_worker_manager
        
        worker_manager = await get_enterprise_autofix_worker_manager()
        await worker_manager._scale_workers(target_workers)
        
        return {
            "success": True,
            "message": f"Autofix workers scaled to {target_workers}",
            "current_workers": len(worker_manager.workers)
        }
    except Exception as e:
        logger.error(f"Failed to scale autofix workers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scale autofix workers: {str(e)}"
        )


@router.post("/webhook/workers/scale", summary="Scale webhook workers")
async def scale_webhook_workers(target_workers: int):
    """Scale the number of webhook workers"""
    try:
        from scans.webhooks.enterprise_webhook_worker_manager import get_enterprise_webhook_worker_manager
        
        worker_manager = await get_enterprise_webhook_worker_manager()
        await worker_manager._scale_workers(target_workers)
        
        return {
            "success": True,
            "message": f"Webhook workers scaled to {target_workers}",
            "current_workers": len(worker_manager.workers)
        }
    except Exception as e:
        logger.error(f"Failed to scale webhook workers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to scale webhook workers: {str(e)}"
        )


@router.get("/circuit-breakers", summary="Get circuit breaker status for all systems")
async def get_circuit_breaker_status():
    """Get circuit breaker status for all enterprise queue systems"""
    
    circuit_breakers = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "systems": {}
    }
    
    # Check scanning system circuit breaker
    try:
        from scans.queue.enterprise_queue_manager import get_enterprise_queue_manager
        queue_manager = await get_enterprise_queue_manager()
        stats = await queue_manager.get_queue_statistics()
        circuit_breakers["systems"]["scanning"] = stats["circuit_breaker"]
    except Exception as e:
        circuit_breakers["systems"]["scanning"] = {"error": str(e)}
    
    # Check autofix system circuit breaker
    try:
        from scans.autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
        queue_manager = await get_enterprise_autofix_queue_manager()
        stats = await queue_manager.get_queue_statistics()
        circuit_breakers["systems"]["autofix"] = stats["circuit_breaker"]
    except Exception as e:
        circuit_breakers["systems"]["autofix"] = {"error": str(e)}
    
    # Check webhook system circuit breaker
    try:
        from scans.webhooks.enterprise_webhook_queue import get_enterprise_webhook_queue_manager
        queue_manager = await get_enterprise_webhook_queue_manager()
        stats = await queue_manager.get_queue_statistics()
        circuit_breakers["systems"]["webhook"] = stats["circuit_breaker"]
    except Exception as e:
        circuit_breakers["systems"]["webhook"] = {"error": str(e)}
    
    # Check unified task system circuit breaker
    try:
        from core.task_system.enterprise_task_queue_manager import get_enterprise_task_queue_manager
        queue_manager = await get_enterprise_task_queue_manager()
        stats = await queue_manager.get_queue_statistics()
        circuit_breakers["systems"]["unified_tasks"] = stats["circuit_breaker"]
    except Exception as e:
        circuit_breakers["systems"]["unified_tasks"] = {"error": str(e)}
    
    return circuit_breakers


@router.get("/system-health", summary="Get system resource health across all queues")
async def get_system_health():
    """Get comprehensive system resource health for all queue systems"""
    
    system_health = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "systems": {}
    }
    
    # Get system health from all queue managers
    systems_to_check = [
        ("scanning", "scans.queue.enterprise_queue_manager", "get_enterprise_queue_manager"),
        ("autofix", "scans.autofix_queue.enterprise_autofix_queue", "get_enterprise_autofix_queue_manager"),
        ("webhook", "scans.webhooks.enterprise_webhook_queue", "get_enterprise_webhook_queue_manager"),
        ("unified_tasks", "core.task_system.enterprise_task_queue_manager", "get_enterprise_task_queue_manager")
    ]
    
    for system_name, module_path, manager_function in systems_to_check:
        try:
            module = __import__(module_path, fromlist=[manager_function])
            get_manager = getattr(module, manager_function)
            
            queue_manager = await get_manager()
            stats = await queue_manager.get_queue_statistics()
            
            system_health["systems"][system_name] = stats["system_health"]
        except Exception as e:
            system_health["systems"][system_name] = {"error": str(e)}
    
    # Calculate overall system health
    healthy_systems = 0
    total_systems = len(systems_to_check)
    
    for system_stats in system_health["systems"].values():
        if isinstance(system_stats, dict) and system_stats.get("overall", {}).get("healthy", False):
            healthy_systems += 1
    
    system_health["overall"] = {
        "healthy_systems": healthy_systems,
        "total_systems": total_systems,
        "health_percentage": (healthy_systems / total_systems * 100) if total_systems > 0 else 0,
        "status": "healthy" if healthy_systems == total_systems else ("degraded" if healthy_systems > 0 else "unhealthy")
    }
    
    return system_health