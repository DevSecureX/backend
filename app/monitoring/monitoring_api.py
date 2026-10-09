"""
Basic Monitoring API Endpoints
Simple system health and metrics endpoints (enterprise monitoring disabled).
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import psutil
import asyncio

from auth.dependencies import get_current_user
from auth.models import User
# Enterprise monitoring disabled - using basic stub implementation

# Pydantic Models
class SystemHealthResponse(BaseModel):
    """System health status response"""
    timestamp: str
    system_health: Dict[str, Any]
    active_alerts: List[Dict[str, Any]]
    alert_summary: Dict[str, Any]
    metrics_collected: int
    monitoring_status: str


class AlertResponse(BaseModel):
    """Alert information response"""
    alert_id: str
    name: str
    description: str
    severity: str
    triggered_at: Optional[str] = None
    trigger_count: int


class MetricSummary(BaseModel):
    """Metric summary statistics"""
    count: int
    min: float
    max: float
    avg: float
    current: float


class MetricChartData(BaseModel):
    """Time-series data for charts"""
    timestamp: str
    value: float


# Initialize router
monitoring_api_router = APIRouter(prefix="/monitoring", tags=["monitoring"])


@monitoring_api_router.get("/dashboard", response_model=SystemHealthResponse)
async def get_monitoring_dashboard(
    user: User = Depends(get_current_user)
) -> SystemHealthResponse:
    """
    Get basic monitoring dashboard data (enterprise monitoring disabled)
    
    Returns:
    - Basic system health metrics
    - No active alerts (enterprise monitoring disabled)
    - Basic system status
    """
    try:
        # Basic system metrics using psutil
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        dashboard_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system_health": {
                "cpu_usage_percent": cpu_percent,
                "memory_usage_percent": memory.percent,
                "status": "basic_monitoring"
            },
            "active_alerts": [],  # No alerts in basic mode
            "alert_summary": {
                "total": 0,
                "critical": 0,
                "warning": 0,
                "info": 0
            },
            "metrics_collected": 2,  # CPU and memory only
            "monitoring_status": "basic_mode_enabled"
        }
        
        return SystemHealthResponse(**dashboard_data)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get dashboard data: {str(e)}"
        )


@monitoring_api_router.get("/alerts")
async def get_active_alerts(
    user: User = Depends(get_current_user)
) -> List[AlertResponse]:
    """Get list of currently active alerts (enterprise monitoring disabled)"""
    # Return empty list - no alerts in basic monitoring mode
    return []


@monitoring_api_router.get("/metrics/{metric_name}/summary")
async def get_metric_summary(
    metric_name: str,
    hours: int = Query(default=1, ge=1, le=24, description="Hours of history to analyze"),
    user: User = Depends(get_current_user)
) -> Optional[MetricSummary]:
    """Get statistical summary for a specific metric (enterprise monitoring disabled)"""
    # Return basic stub data based on metric name
    if metric_name in ["cpu_usage_percent", "memory_usage_percent"]:
        if metric_name == "cpu_usage_percent":
            cpu_percent = psutil.cpu_percent()
            return MetricSummary(
                count=1,
                min=cpu_percent,
                max=cpu_percent,
                avg=cpu_percent,
                current=cpu_percent
            )
        elif metric_name == "memory_usage_percent":
            memory_percent = psutil.virtual_memory().percent
            return MetricSummary(
                count=1,
                min=memory_percent,
                max=memory_percent,
                avg=memory_percent,
                current=memory_percent
            )
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Metric '{metric_name}' not available in basic monitoring mode"
    )


@monitoring_api_router.get("/metrics/charts")
async def get_metrics_charts(
    hours: int = Query(default=1, ge=1, le=24, description="Hours of history for charts"),
    user: User = Depends(get_current_user)
) -> Dict[str, List[MetricChartData]]:
    """Get time-series data for monitoring charts (enterprise monitoring disabled)"""
    # Return basic stub chart data
    current_time = datetime.now(timezone.utc)
    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory().percent
    
    return {
        "cpu_usage_percent": [
            MetricChartData(
                timestamp=current_time.isoformat(),
                value=cpu_percent
            )
        ],
        "memory_usage_percent": [
            MetricChartData(
                timestamp=current_time.isoformat(),
                value=memory_percent
            )
        ]
    }


@monitoring_api_router.get("/system/health")
async def get_system_health(
    user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get detailed system health information (enterprise monitoring disabled)"""
    try:
        # Basic system metrics using psutil
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        # Calculate basic health status
        cpu_healthy = cpu_percent < 85
        memory_healthy = memory.percent < 85
        
        overall_healthy = cpu_healthy and memory_healthy
        
        return {
            "overall_status": "healthy" if overall_healthy else "degraded",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "cpu": {
                    "healthy": cpu_healthy,
                    "usage_percent": cpu_percent
                },
                "memory": {
                    "healthy": memory_healthy,
                    "usage_percent": memory.percent,
                    "available_gb": round(memory.available / (1024**3), 2)
                },
                "queue": {
                    "healthy": True,
                    "size": 0,
                    "active_scans": 0
                },
                "workers": {
                    "healthy": True,
                    "count": 0
                },
                "redis": {
                    "healthy": True,
                    "connected_clients": 0,
                    "ops_per_sec": 0
                }
            },
            "active_alerts_count": 0,
            "circuit_breaker_open": False,
            "monitoring_mode": "basic"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system health: {str(e)}"
        )


@monitoring_api_router.get("/metrics/list")
async def list_available_metrics(
    user: User = Depends(get_current_user)
) -> Dict[str, List[str]]:
    """Get list of all available metrics grouped by category (enterprise monitoring disabled)"""
    # Return only basic metrics available in stub mode
    return {
        "system": [
            "cpu_usage_percent",
            "memory_usage_percent"
        ],
        "queue": [],  # No queue metrics in basic mode
        "workers": [],  # No worker metrics in basic mode
        "redis": [],  # No redis metrics in basic mode
        "total_available": 2,
        "monitoring_mode": "basic"
    }


@monitoring_api_router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Acknowledge an active alert (enterprise monitoring disabled)"""
    # No alerts in basic monitoring mode
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Alert system disabled - enterprise monitoring not available"
    )


@monitoring_api_router.get("/performance/summary")
async def get_performance_summary(
    hours: int = Query(default=1, ge=1, le=24, description="Hours of history to analyze"),
    user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get performance summary with key metrics (enterprise monitoring disabled)"""
    try:
        # Basic system metrics
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        # Create basic summaries
        summaries = {
            "cpu_usage_percent": {
                "count": 1,
                "min": cpu_percent,
                "max": cpu_percent,
                "avg": cpu_percent,
                "current": cpu_percent
            },
            "memory_usage_percent": {
                "count": 1,
                "min": memory.percent,
                "max": memory.percent,
                "avg": memory.percent,
                "current": memory.percent
            }
        }
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "period_hours": hours,
            "key_metrics": summaries,
            "derived_metrics": {
                "estimated_scan_throughput_per_hour": 0,
                "system_load_score": (cpu_percent * 0.5 + memory.percent * 0.5),
                "efficiency_score": max(0, 100 - (cpu_percent * 0.3 + memory.percent * 0.3))
            },
            "recommendations": _generate_performance_recommendations(summaries),
            "monitoring_mode": "basic"
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get performance summary: {str(e)}"
        )


def _generate_performance_recommendations(summaries: Dict[str, Dict[str, float]]) -> List[str]:
    """Generate performance recommendations based on metrics"""
    recommendations = []
    
    # CPU recommendations
    cpu_avg = summaries.get("cpu_usage_percent", {}).get("avg", 0)
    if cpu_avg > 80:
        recommendations.append("Consider scaling up CPU resources or reducing concurrent scans")
    elif cpu_avg < 30:
        recommendations.append("CPU utilization is low - consider increasing concurrent scans")
    
    # Memory recommendations
    memory_avg = summaries.get("memory_usage_percent", {}).get("avg", 0)
    if memory_avg > 80:
        recommendations.append("Memory usage is high - consider increasing memory or optimizing scan processes")
    
    # Queue recommendations
    queue_avg = summaries.get("queue_size_total", {}).get("avg", 0)
    if queue_avg > 50:
        recommendations.append("Queue size is consistently high - consider adding more workers")
    elif queue_avg > 100:
        recommendations.append("Queue size is very high - urgent scaling needed")
    
    # Worker recommendations
    workers_avg = summaries.get("active_workers", {}).get("avg", 0)
    scans_avg = summaries.get("active_scans", {}).get("avg", 0)
    if workers_avg > 0 and scans_avg / workers_avg < 0.5:
        recommendations.append("Workers appear underutilized - consider reducing worker count")
    
    # Scan duration recommendations
    duration_avg = summaries.get("average_scan_duration", {}).get("avg", 0)
    if duration_avg > 600:  # 10 minutes
        recommendations.append("Average scan duration is high - consider optimizing scan tools or reducing scope")
    
    return recommendations if recommendations else ["System performance appears optimal"]


# Export router
__all__ = ["monitoring_api_router"]