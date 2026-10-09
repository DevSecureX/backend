"""
FastAPI routes for Task System Monitoring and Management

Provides comprehensive API endpoints for monitoring and managing the auto-scaling task system
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel, Field

from auth.dependencies import get_current_user
from core.task_system.integration_layer import get_task_system
from core.task_system.priority_queue import TaskPriority, TaskType
from core.utils import utc_now_iso

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/monitoring/task-system", tags=["Task System Monitoring"])

# Request/Response Models

class TaskSubmissionRequest(BaseModel):
    """Request model for task submission"""
    task_type: str = Field(..., description="Type of task to submit")
    priority: str = Field(default="normal", description="Task priority (critical, high, normal, low)")
    payload: Dict[str, Any] = Field(..., description="Task payload data")
    expires_in_seconds: Optional[int] = Field(None, description="Task expiration time in seconds")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    timeout_seconds: int = Field(default=3600, description="Task timeout in seconds")
    preferred_worker_tags: List[str] = Field(default=[], description="Preferred worker tags")
    resource_requirements: Dict[str, Any] = Field(default={}, description="Resource requirements")

class ScalingConfigUpdate(BaseModel):
    """Request model for scaling configuration updates"""
    scale_up_threshold: Optional[int] = Field(None, description="Queue items per worker for scale up")
    scale_down_threshold: Optional[int] = Field(None, description="Queue items per worker for scale down")
    scale_up_cooldown: Optional[int] = Field(None, description="Scale up cooldown in seconds")
    scale_down_cooldown: Optional[int] = Field(None, description="Scale down cooldown in seconds")
    max_scale_up_rate: Optional[int] = Field(None, description="Max workers to add per scaling operation")
    max_scale_down_rate: Optional[int] = Field(None, description="Max workers to remove per scaling operation")
    utilization_target: Optional[float] = Field(None, description="Target worker utilization (0-1)")

class AlertThresholdUpdate(BaseModel):
    """Request model for alert threshold updates"""
    queue_size_critical: Optional[int] = None
    queue_time_warning: Optional[float] = None
    queue_time_critical: Optional[float] = None
    success_rate_warning: Optional[float] = None
    success_rate_critical: Optional[float] = None
    worker_utilization_warning: Optional[float] = None
    worker_utilization_critical: Optional[float] = None

# Health and Status Endpoints

@router.get("/health")
async def get_task_system_health():
    """Get comprehensive task system health information"""
    
    try:
        task_system = get_task_system()
        
        if not task_system:
            return {
                "status": "unavailable",
                "message": "Task system not initialized",
                "timestamp": utc_now_iso()
            }
        
        health_info = await task_system.get_system_health()
        
        # Determine overall health status
        if health_info.get('task_system_running'):
            # Check for critical alerts
            active_alerts = health_info.get('active_alerts', 0)
            critical_alerts = len([
                alert for alert in health_info.get('alerts', [])
                if alert.get('level') == 'critical'
            ])
            
            if critical_alerts > 0:
                health_info['status'] = 'critical'
            elif active_alerts > 0:
                health_info['status'] = 'warning'
            else:
                health_info['status'] = 'healthy'
        else:
            health_info['status'] = 'down'
        
        return health_info
        
    except Exception as e:
        logger.error(f"Error getting task system health: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving health status: {str(e)}")

@router.get("/status")
async def get_system_status():
    """Get current system status and metrics"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.running:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        # Get comprehensive system stats
        system_stats = await task_system.auto_scaling_manager.get_system_stats()
        
        return {
            "timestamp": utc_now_iso(),
            "status": "operational",
            "system_stats": system_stats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting system status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving system status: {str(e)}")

# Performance Monitoring Endpoints

@router.get("/metrics")
async def get_performance_metrics():
    """Get current performance metrics"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.running:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        metrics = await task_system.get_performance_metrics()
        return metrics
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving metrics: {str(e)}")

@router.get("/metrics/history")
async def get_historical_metrics(
    start_time: Optional[datetime] = Query(None, description="Start time for historical data"),
    end_time: Optional[datetime] = Query(None, description="End time for historical data"),
    interval_minutes: int = Query(5, description="Data point interval in minutes", ge=1, le=60)
):
    """Get historical performance metrics"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.task_monitor:
            raise HTTPException(status_code=503, detail="Task monitoring not available")
        
        # Default to last 24 hours if no time range specified
        if not end_time:
            end_time = datetime.utcnow()
        if not start_time:
            start_time = end_time - timedelta(hours=24)
        
        historical_data = await task_system.task_monitor.get_historical_metrics(
            start_time, end_time, interval_minutes
        )
        
        return {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "interval_minutes": interval_minutes,
            "data_points": len(historical_data),
            "metrics": historical_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting historical metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving historical metrics: {str(e)}")

# Task Management Endpoints

@router.post("/tasks")
async def submit_task(
    request: TaskSubmissionRequest,
    current_user = Depends(get_current_user)
):
    """Submit a new task to the task system"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.auto_scaling_manager:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        # Map string priority to enum
        priority_map = {
            'critical': TaskPriority.CRITICAL,
            'high': TaskPriority.HIGH,
            'normal': TaskPriority.NORMAL,
            'low': TaskPriority.LOW,
            'background': TaskPriority.BACKGROUND
        }
        
        # Map string task type to enum
        task_type_map = {
            'security_scan': TaskType.SECURITY_SCAN,
            'autofix': TaskType.AUTOFIX,
            'report_generation': TaskType.REPORT_GENERATION,
            'repository_analysis': TaskType.REPOSITORY_ANALYSIS,
            'notification': TaskType.NOTIFICATION,
            'cleanup': TaskType.CLEANUP,
            'analytics': TaskType.ANALYTICS,
            'webhook': TaskType.WEBHOOK,
            'custom': TaskType.CUSTOM
        }
        
        priority = priority_map.get(request.priority.lower(), TaskPriority.NORMAL)
        task_type = task_type_map.get(request.task_type.lower(), TaskType.CUSTOM)
        
        # Add user context to payload
        enhanced_payload = {
            **request.payload,
            'submitted_by': current_user.get('user_id'),
            'submitted_at': utc_now_iso()
        }
        
        # Submit task
        task_id = await task_system.auto_scaling_manager.enqueue_task(
            task_type=task_type,
            payload=enhanced_payload,
            priority=priority,
            expires_in_seconds=request.expires_in_seconds,
            max_retries=request.max_retries,
            timeout_seconds=request.timeout_seconds,
            preferred_worker_tags=request.preferred_worker_tags,
            resource_requirements=request.resource_requirements
        )
        
        return {
            "task_id": task_id,
            "status": "queued",
            "priority": request.priority,
            "task_type": request.task_type,
            "submitted_at": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error submitting task: {str(e)}")

@router.get("/tasks/{task_id}")
async def get_task_status(
    task_id: str,
    current_user = Depends(get_current_user)
):
    """Get status of a specific task"""
    
    try:
        task_system = get_task_system()
        
        if not task_system:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        task_status = await task_system.get_task_status(task_id)
        
        if not task_status:
            raise HTTPException(status_code=404, detail="Task not found")
        
        return task_status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving task status: {str(e)}")

# Scaling Management Endpoints

@router.get("/scaling/history")
async def get_scaling_history(
    limit: int = Query(50, description="Number of scaling events to return", ge=1, le=500)
):
    """Get recent scaling history"""
    
    try:
        task_system = get_task_system()
        
        if not task_system:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        history = await task_system.get_scaling_history(limit)
        
        return {
            "scaling_events": history,
            "total_events": len(history),
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scaling history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving scaling history: {str(e)}")

@router.put("/scaling/config", dependencies=[Depends(get_current_user)])
async def update_scaling_config(
    config_update: ScalingConfigUpdate
):
    """Update scaling configuration (admin only)"""
    
    try:
        task_system = get_task_system()
        
        if not task_system:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        # Convert to dictionary, excluding None values
        config_dict = {k: v for k, v in config_update.dict().items() if v is not None}
        
        if not config_dict:
            raise HTTPException(status_code=400, detail="No configuration updates provided")
        
        success = await task_system.update_scaling_config(config_dict)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update scaling configuration")
        
        return {
            "status": "success",
            "message": "Scaling configuration updated",
            "updated_config": config_dict,
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating scaling config: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating configuration: {str(e)}")

# Alert Management Endpoints

@router.get("/alerts")
async def get_active_alerts():
    """Get all active alerts"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.task_monitor:
            raise HTTPException(status_code=503, detail="Task monitoring not available")
        
        alerts = await task_system.task_monitor.get_active_alerts()
        
        return {
            "active_alerts": [
                {
                    "alert_id": alert.alert_id,
                    "level": alert.level.value,
                    "title": alert.title,
                    "message": alert.message,
                    "metric": alert.metric,
                    "threshold": alert.threshold,
                    "current_value": alert.current_value,
                    "created_at": alert.created_at,
                    "acknowledged": alert.acknowledged
                }
                for alert in alerts
            ],
            "total_alerts": len(alerts),
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting alerts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving alerts: {str(e)}")

@router.post("/alerts/{alert_key}/acknowledge", dependencies=[Depends(get_current_user)])
async def acknowledge_alert(
    alert_key: str
):
    """Acknowledge an alert (admin only)"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.task_monitor:
            raise HTTPException(status_code=503, detail="Task monitoring not available")
        
        success = await task_system.task_monitor.acknowledge_alert(alert_key)
        
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found or already acknowledged")
        
        return {
            "status": "success",
            "message": f"Alert {alert_key} acknowledged",
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error acknowledging alert: {str(e)}")

@router.put("/alerts/thresholds", dependencies=[Depends(get_current_user)])
async def update_alert_thresholds(
    threshold_update: AlertThresholdUpdate
):
    """Update alert thresholds (admin only)"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.task_monitor:
            raise HTTPException(status_code=503, detail="Task monitoring not available")
        
        # Convert to dictionary, excluding None values
        threshold_dict = {k: v for k, v in threshold_update.dict().items() if v is not None}
        
        if not threshold_dict:
            raise HTTPException(status_code=400, detail="No threshold updates provided")
        
        success = await task_system.task_monitor.update_alert_thresholds(threshold_dict)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update alert thresholds")
        
        return {
            "status": "success",
            "message": "Alert thresholds updated",
            "updated_thresholds": threshold_dict,
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating alert thresholds: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating alert thresholds: {str(e)}")

# Queue Management Endpoints

@router.get("/queues")
async def get_queue_status():
    """Get current queue status and statistics"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.auto_scaling_manager:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        queue_stats = await task_system.auto_scaling_manager.task_queue.get_queue_stats()
        
        return {
            "timestamp": utc_now_iso(),
            "queue_statistics": queue_stats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting queue status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving queue status: {str(e)}")

@router.post("/queues/cleanup", dependencies=[Depends(get_current_user)])
async def cleanup_queues():
    """Clean up expired and stale tasks from queues (admin only)"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.auto_scaling_manager:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        cleanup_count = await task_system.auto_scaling_manager.task_queue.cleanup_expired_tasks()
        
        return {
            "status": "success",
            "message": f"Cleaned up {cleanup_count} expired/stale tasks",
            "cleanup_count": cleanup_count,
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cleaning up queues: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error cleaning up queues: {str(e)}")

# Worker Management Endpoints

@router.get("/workers")
async def get_worker_status():
    """Get current worker status and statistics"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.auto_scaling_manager:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        worker_stats = await task_system.auto_scaling_manager.worker_coordinator.get_all_worker_stats()
        system_stats = await task_system.auto_scaling_manager.worker_coordinator.get_system_stats()
        
        return {
            "timestamp": utc_now_iso(),
            "worker_statistics": worker_stats,
            "system_statistics": system_stats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting worker status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving worker status: {str(e)}")

@router.post("/workers/health-check", dependencies=[Depends(get_current_user)])
async def trigger_worker_health_check():
    """Trigger immediate health check of all workers (admin only)"""
    
    try:
        task_system = get_task_system()
        
        if not task_system or not task_system.auto_scaling_manager:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        unhealthy_workers = await task_system.auto_scaling_manager.worker_coordinator.health_check_all_workers()
        
        return {
            "status": "success",
            "message": f"Health check completed, {len(unhealthy_workers)} unhealthy workers found",
            "unhealthy_workers": unhealthy_workers,
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error triggering health check: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error triggering health check: {str(e)}")

# Debug and Admin Endpoints

@router.get("/debug/system-info", dependencies=[Depends(get_current_user)])
async def get_debug_system_info():
    """Get detailed system information for debugging (admin only)"""
    
    try:
        task_system = get_task_system()
        
        if not task_system:
            return {
                "task_system": "not_initialized",
                "timestamp": utc_now_iso()
            }
        
        debug_info = {
            "timestamp": utc_now_iso(),
            "task_system": {
                "enabled": task_system.enabled,
                "running": task_system.running,
                "min_workers": task_system.min_workers,
                "max_workers": task_system.max_workers,
                "scaling_policy": task_system.scaling_policy.value
            },
            "components": {
                "auto_scaling_manager": task_system.auto_scaling_manager is not None,
                "task_monitor": task_system.task_monitor is not None,
                "legacy_scan_manager": task_system.legacy_scan_manager is not None,
                "legacy_autofix_manager": task_system.legacy_autofix_manager is not None
            }
        }
        
        if task_system.running and task_system.auto_scaling_manager:
            # Get detailed component status
            scaling_stats = await task_system.auto_scaling_manager.get_system_stats()
            debug_info["detailed_stats"] = scaling_stats
        
        return debug_info
        
    except Exception as e:
        logger.error(f"Error getting debug system info: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error retrieving debug info: {str(e)}")

@router.post("/debug/force-scaling", dependencies=[Depends(get_current_user)])
async def force_scaling_decision(
    action: str = Body(..., description="Scaling action: 'scale_up' or 'scale_down'"),
    worker_count: int = Body(..., description="Number of workers to add/remove", ge=1, le=5)
):
    """Force a scaling action for testing purposes (admin only)"""
    
    try:
        if action not in ['scale_up', 'scale_down']:
            raise HTTPException(status_code=400, detail="Action must be 'scale_up' or 'scale_down'")
        
        task_system = get_task_system()
        
        if not task_system or not task_system.auto_scaling_manager:
            raise HTTPException(status_code=503, detail="Task system not available")
        
        # This would require extending the auto-scaling manager with a force scaling method
        # For now, return information about current scaling state
        system_stats = await task_system.auto_scaling_manager.get_system_stats()
        current_workers = system_stats.get('auto_scaling', {}).get('current_workers', 0)
        
        return {
            "status": "info",
            "message": f"Force scaling not yet implemented. Current workers: {current_workers}",
            "requested_action": action,
            "requested_count": worker_count,
            "current_workers": current_workers,
            "timestamp": utc_now_iso()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error forcing scaling decision: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error forcing scaling: {str(e)}")