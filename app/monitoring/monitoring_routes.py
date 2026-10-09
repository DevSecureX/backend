"""
FastAPI Routes for Monitoring and Observability

Comprehensive monitoring endpoints for:
- Prometheus metrics exposure
- Health checks and system status
- SLA compliance monitoring
- Performance analytics
- Distributed tracing information
- Log aggregation and querying
- Grafana dashboard management
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Response, Request
from pydantic import BaseModel, Field

from auth.dependencies import get_current_user
from monitoring.prometheus_metrics import get_metrics
from monitoring.comprehensive_health import get_health_system
# from monitoring.sla_performance_analytics import get_sla_monitor

# Mock function for temporarily disabled SLA monitoring
def get_sla_monitor():
    """Mock SLA monitor for testing"""
    return None
from monitoring.structured_logging import get_logger, get_log_aggregator, LogQuery
from monitoring.opentelemetry_tracing import get_tracer
from monitoring.grafana_dashboards import get_dashboard_generator
from core.utils import utc_now_iso

logger_instance = get_logger()
logger = logger_instance.get_logger()

router = APIRouter(prefix="/monitoring", tags=["Monitoring & Observability"])

# ===========================================
# REQUEST/RESPONSE MODELS
# ===========================================

class HealthCheckResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: str
    components: Dict[str, Any]
    recommendations: List[str]

class SLASummaryResponse(BaseModel):
    """SLA summary response model"""
    overall_compliance: float
    total_slas: int
    compliant_slas: int
    violation_slas: int
    active_violations: int
    sla_details: List[Dict[str, Any]]

class LogQueryRequest(BaseModel):
    """Log query request model"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    level: Optional[str] = None
    component: Optional[str] = None
    correlation_id: Optional[str] = None
    event_type: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)

class MetricsConfig(BaseModel):
    """Metrics configuration model"""
    enabled: bool
    collection_interval: int
    retention_days: int

# ===========================================
# PROMETHEUS METRICS ENDPOINTS
# ===========================================

@router.get("/metrics")
async def prometheus_metrics(response: Response):
    """Expose Prometheus metrics"""
    
    try:
        metrics = get_metrics()
        metrics_content = metrics.generate_metrics()
        
        response.headers["Content-Type"] = metrics.get_content_type()
        return Response(content=metrics_content, media_type=metrics.get_content_type())
        
    except Exception as e:
        logger.error(f"Error generating Prometheus metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error generating metrics: {str(e)}")

@router.get("/metrics/config")
async def get_metrics_config(current_user = Depends(get_current_user)):
    """Get current metrics configuration"""
    
    try:
        metrics = get_metrics()
        
        config = {
            "enabled": True,
            "total_metrics": len(metrics.counters) + len(metrics.gauges) + len(metrics.histograms),
            "counters": len(metrics.counters),
            "gauges": len(metrics.gauges),
            "histograms": len(metrics.histograms),
            "summaries": len(metrics.summaries),
            "info_metrics": len(metrics.info_metrics)
        }
        
        return config
        
    except Exception as e:
        logger.error(f"Error getting metrics config: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# HEALTH CHECK ENDPOINTS
# ===========================================

@router.get("/health")
async def system_health():
    """Get comprehensive system health"""
    
    try:
        health_system = get_health_system()
        health_result = await health_system.run_all_checks()
        
        return {
            "overall_status": health_result.overall_status.value,
            "timestamp": health_result.timestamp,
            "healthy_components": health_result.healthy_components,
            "degraded_components": health_result.degraded_components,
            "unhealthy_components": health_result.unhealthy_components,
            "critical_components": health_result.critical_components,
            "total_components": health_result.total_components,
            "check_duration_ms": health_result.check_duration_ms,
            "sla_compliance": health_result.sla_compliance,
            "recommendations": health_result.recommendations,
            "components": [
                {
                    "component": comp.component,
                    "type": comp.component_type.value,
                    "status": comp.status.value,
                    "message": comp.message,
                    "duration_ms": comp.check_duration_ms,
                    "recommendations": comp.recommendations or []
                }
                for comp in health_result.components
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting system health: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health/quick")
async def quick_health():
    """Get quick health check (critical components only)"""
    
    try:
        health_system = get_health_system()
        quick_result = await health_system.get_quick_health()
        
        return quick_result
        
    except Exception as e:
        logger.error(f"Error getting quick health: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health/component/{component_name}")
async def component_health(
    component_name: str,
    hours: int = Query(default=24, ge=1, le=168)
):
    """Get health history for a specific component"""
    
    try:
        health_system = get_health_system()
        history = health_system.get_component_history(component_name, hours)
        
        if not history:
            raise HTTPException(status_code=404, detail=f"Component '{component_name}' not found")
        
        return {
            "component": component_name,
            "period_hours": hours,
            "total_checks": len(history),
            "history": history
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting component health: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# SLA MONITORING ENDPOINTS
# ===========================================

# Temporarily disabled - SLA monitoring
# @router.get("/sla")
# async def sla_summary():
#     """Get SLA compliance summary"""
#     
#     try:
#         sla_monitor = get_sla_monitor()
#         if not sla_monitor:
#             return {"message": "SLA monitoring temporarily disabled", "slas": []}
#         summary = await sla_monitor.get_sla_summary()
#         
#         return summary
#         
#     except Exception as e:
#         logger.error(f"Error getting SLA summary: {e}", exc_info=True)
#         raise HTTPException(status_code=500, detail=str(e))

# @router.get("/sla/violations")
# async def sla_violations(
#     hours: int = Query(default=24, ge=1, le=168)
# ):
#     """Get SLA violation history"""
#     
#     try:
#         sla_monitor = get_sla_monitor()
#         violations = sla_monitor.get_violation_history(hours)
#         
#         return {
#             "period_hours": hours,
#             "total_violations": len(violations),
#             "violations": violations
#         }
#         
#     except Exception as e:
#         logger.error(f"Error getting SLA violations: {e}", exc_info=True)
#         raise HTTPException(status_code=500, detail=str(e))

# @router.get("/sla/analytics")
# async def sla_analytics():
#     """Get performance analytics"""
#     
#     try:
#         sla_monitor = get_sla_monitor()
#         analytics = await sla_monitor.get_performance_analytics()
#         
#         if not analytics:
#             return {
#                 "status": "no_data",
#                 "message": "Performance analytics not yet available"
#             }
#         
#         return {
#             "status": "available",
#             "analytics": {
#                 "timestamp": analytics.timestamp,
#                 "analysis_period_hours": analytics.analysis_period_hours,
#                 "trends": {
#                     "availability": analytics.availability_trend,
#                     "response_time": analytics.response_time_trend,
#                     "throughput": analytics.throughput_trend,
#                     "error_rate": analytics.error_rate_trend
#                 },
#                 "predictions": {
#                     "violations": analytics.predicted_violations,
#                     "capacity_forecast": analytics.capacity_forecast
#                 },
#                 "recommendations": {
#                     "performance": analytics.performance_recommendations,
#                     "capacity": analytics.capacity_recommendations,
#                     "optimization": analytics.optimization_opportunities
#                 },
#                 "business_impact": {
#                     "estimated_impact": analytics.estimated_business_impact,
#                     "violation_cost": analytics.cost_of_violations,
#                     "availability_score": analytics.availability_score
#                 }
#             }
#         }
#         
#     except Exception as e:
#         logger.error(f"Error getting SLA analytics: {e}", exc_info=True)
#         raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# LOGGING ENDPOINTS
# ===========================================

@router.post("/logs/query")
async def query_logs(
    query: LogQueryRequest,
    current_user = Depends(get_current_user)
):
    """Query structured logs"""
    
    try:
        log_aggregator = get_log_aggregator()
        
        # Get recent logs
        recent_logs = log_aggregator.get_recent_logs(query.limit)
        
        # Apply filters
        filtered_logs = recent_logs
        
        if query.level:
            filtered_logs = [
                log for log in filtered_logs 
                if log.get('level', '').lower() == query.level.lower()
            ]
        
        if query.component:
            filtered_logs = [
                log for log in filtered_logs 
                if log.get('component') == query.component
            ]
        
        if query.correlation_id:
            filtered_logs = [
                log for log in filtered_logs 
                if log.get('correlation_id') == query.correlation_id
            ]
        
        if query.event_type:
            filtered_logs = [
                log for log in filtered_logs 
                if log.get('event_type') == query.event_type
            ]
        
        # Time filtering
        if query.start_time or query.end_time:
            time_filtered = []
            for log in filtered_logs:
                log_time = log.get('timestamp')
                if log_time:
                    try:
                        log_dt = datetime.fromisoformat(log_time)
                        if query.start_time and log_dt < query.start_time:
                            continue
                        if query.end_time and log_dt > query.end_time:
                            continue
                        time_filtered.append(log)
                    except ValueError:
                        continue
            filtered_logs = time_filtered
        
        return {
            "total_logs": len(filtered_logs),
            "query": query.dict(),
            "logs": filtered_logs[:query.limit]
        }
        
    except Exception as e:
        logger.error(f"Error querying logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs/security")
async def security_logs(
    hours: int = Query(default=24, ge=1, le=168),
    current_user = Depends(get_current_user)
):
    """Get security event logs"""
    
    try:
        security_events = LogQuery.get_security_events(hours)
        
        return {
            "period_hours": hours,
            "total_events": len(security_events),
            "events": security_events
        }
        
    except Exception as e:
        logger.error(f"Error getting security logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs/performance")
async def performance_logs(
    threshold_ms: float = Query(default=5000, ge=100),
    current_user = Depends(get_current_user)
):
    """Get performance issue logs"""
    
    try:
        performance_issues = LogQuery.get_performance_issues(threshold_ms)
        
        return {
            "threshold_ms": threshold_ms,
            "total_issues": len(performance_issues),
            "issues": performance_issues
        }
        
    except Exception as e:
        logger.error(f"Error getting performance logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs/errors")
async def error_logs(
    hours: int = Query(default=24, ge=1, le=168),
    current_user = Depends(get_current_user)
):
    """Get error logs"""
    
    try:
        error_logs = LogQuery.get_error_logs(hours)
        
        return {
            "period_hours": hours,
            "total_errors": len(error_logs),
            "errors": error_logs
        }
        
    except Exception as e:
        logger.error(f"Error getting error logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs/correlation/{correlation_id}")
async def correlation_logs(
    correlation_id: str,
    current_user = Depends(get_current_user)
):
    """Get all logs for a correlation ID"""
    
    try:
        correlated_logs = LogQuery.get_correlation_logs(correlation_id)
        
        return {
            "correlation_id": correlation_id,
            "total_logs": len(correlated_logs),
            "logs": correlated_logs
        }
        
    except Exception as e:
        logger.error(f"Error getting correlation logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# TRACING ENDPOINTS
# ===========================================

@router.get("/tracing/status")
async def tracing_status():
    """Get distributed tracing status"""
    
    try:
        tracer = get_tracer()
        stats = tracer.get_performance_stats()
        
        return {
            "status": "available" if stats['enabled'] else "disabled",
            "service_name": stats['service_name'],
            "initialized": stats['initialized'],
            "performance": {
                "spans_created": stats['spans_created'],
                "spans_exported": stats['spans_exported'],
                "export_errors": stats['export_errors'],
                "average_span_duration": stats['average_span_duration']
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting tracing status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/tracing/current")
async def current_trace_info():
    """Get current trace information"""
    
    try:
        tracer = get_tracer()
        trace_id = tracer.get_trace_id()
        span_id = tracer.get_span_id()
        
        return {
            "trace_id": trace_id,
            "span_id": span_id,
            "active": trace_id is not None
        }
        
    except Exception as e:
        logger.error(f"Error getting current trace info: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# GRAFANA DASHBOARD ENDPOINTS
# ===========================================

@router.get("/dashboards")
async def list_dashboards(current_user = Depends(get_current_user)):
    """List available Grafana dashboards"""
    
    try:
        dashboard_generator = get_dashboard_generator()
        
        dashboards = [
            {
                "name": "system_overview",
                "title": "DevSecureX - System Overview",
                "description": "Comprehensive system health and performance overview"
            },
            {
                "name": "database_performance",
                "title": "DevSecureX - Database Performance",
                "description": "Database connection pools, query performance, and optimization metrics"
            },
            {
                "name": "redis_caching",
                "title": "DevSecureX - Redis & Caching",
                "description": "Redis performance, cache hit rates, and multi-level cache metrics"
            },
            {
                "name": "security_scanning",
                "title": "DevSecureX - Security Scanning",
                "description": "Security scan performance, vulnerability detection, and tool metrics"
            },
            {
                "name": "task_system",
                "title": "DevSecureX - Task System",
                "description": "Background task processing, worker scaling, and queue management"
            },
            {
                "name": "sla_compliance",
                "title": "DevSecureX - SLA Compliance",
                "description": "Service level agreement monitoring and compliance tracking"
            }
        ]
        
        return {
            "total_dashboards": len(dashboards),
            "dashboards": dashboards
        }
        
    except Exception as e:
        logger.error(f"Error listing dashboards: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboards/{dashboard_name}")
async def get_dashboard(
    dashboard_name: str,
    current_user = Depends(get_current_user)
):
    """Get specific dashboard configuration"""
    
    try:
        dashboard_generator = get_dashboard_generator()
        
        dashboard_methods = {
            "system_overview": dashboard_generator.create_system_overview_dashboard,
            "database_performance": dashboard_generator.create_database_performance_dashboard,
            "redis_caching": dashboard_generator.create_redis_caching_dashboard,
            "security_scanning": dashboard_generator.create_security_scanning_dashboard,
            "task_system": dashboard_generator.create_task_system_dashboard,
            "sla_compliance": dashboard_generator.create_sla_compliance_dashboard
        }
        
        if dashboard_name not in dashboard_methods:
            raise HTTPException(status_code=404, detail=f"Dashboard '{dashboard_name}' not found")
        
        dashboard = dashboard_methods[dashboard_name]()
        
        return dashboard
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting dashboard: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/dashboards/export", dependencies=[Depends(get_current_user)])
async def export_dashboards(
    output_dir: str = Query(default="./monitoring/grafana")
):
    """Export all dashboards to files (admin only)"""
    
    try:
        dashboard_generator = get_dashboard_generator()
        dashboard_generator.export_dashboards_config(output_dir)
        
        return {
            "status": "success",
            "message": f"Dashboards exported to {output_dir}",
            "timestamp": utc_now_iso()
        }
        
    except Exception as e:
        logger.error(f"Error exporting dashboards: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# SYSTEM MONITORING ENDPOINTS
# ===========================================

@router.get("/system/overview")
async def system_overview():
    """Get comprehensive system monitoring overview"""
    
    try:
        # Gather data from all monitoring systems
        health_system = get_health_system()
        sla_monitor = get_sla_monitor()
        tracer = get_tracer()
        
        # Get quick health
        health_summary = await health_system.get_quick_health()
        
        # Get SLA summary
        sla_summary = await sla_monitor.get_sla_summary()
        
        # Get tracing status
        tracing_stats = tracer.get_performance_stats()
        
        # System summary
        system_summary = health_system.get_system_summary()
        
        overview = {
            "timestamp": utc_now_iso(),
            "system_health": {
                "overall_healthy": health_summary.get('healthy', False),
                "checked_components": health_summary.get('checked_components', 0),
                "healthy_components": health_summary.get('healthy_components', 0)
            },
            "sla_compliance": {
                "overall_compliance": sla_summary.get('overall_compliance', 0),
                "total_slas": sla_summary.get('total_slas', 0),
                "active_violations": sla_summary.get('active_violations', 0)
            },
            "monitoring_systems": {
                "tracing_enabled": tracing_stats.get('enabled', False),
                "spans_created": tracing_stats.get('spans_created', 0),
                "total_components": system_summary.get('total_components', 0),
                "critical_components": system_summary.get('critical_components', 0)
            },
            "recommendations": []
        }
        
        # Add recommendations based on status
        if not health_summary.get('healthy', True):
            overview['recommendations'].append("Investigate unhealthy system components")
        
        if sla_summary.get('active_violations', 0) > 0:
            overview['recommendations'].append(f"Address {sla_summary.get('active_violations')} active SLA violations")
        
        if sla_summary.get('overall_compliance', 100) < 95:
            overview['recommendations'].append("Review SLA compliance and performance issues")
        
        return overview
        
    except Exception as e:
        logger.error(f"Error getting system overview: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# MONITORING CONFIGURATION ENDPOINTS
# ===========================================

@router.get("/config")
async def monitoring_config(current_user = Depends(get_current_user)):
    """Get monitoring system configuration"""
    
    try:
        config = {
            "prometheus": {
                "enabled": True,
                "endpoint": "/monitoring/metrics"
            },
            "health_checks": {
                "enabled": True,
                "interval_seconds": 60,
                "endpoint": "/monitoring/health"
            },
            "sla_monitoring": {
                "enabled": True,
                "check_interval_seconds": 60
            },
            "tracing": {
                "enabled": True,
                "service_name": "devsecurex-backend"
            },
            "logging": {
                "structured": True,
                "correlation_tracking": True,
                "level": "INFO"
            }
        }
        
        return config
        
    except Exception as e:
        logger.error(f"Error getting monitoring config: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ===========================================
# REAL-TIME MONITORING ENDPOINTS
# ===========================================

@router.get("/realtime/status")
async def realtime_status():
    """Get real-time system status"""
    
    try:
        # This could be extended with WebSocket support for real-time updates
        status = {
            "timestamp": utc_now_iso(),
            "status": "operational",
            "uptime_seconds": 0,  # Would calculate actual uptime
            "active_connections": 0,  # Would get from connection pool
            "current_load": 0.0,  # Would get from system metrics
            "queue_sizes": {},  # Would get from task system
            "error_rate": 0.0   # Would calculate from recent errors
        }
        
        return status
        
    except Exception as e:
        logger.error(f"Error getting real-time status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# Add monitoring middleware to track API performance - DISABLED (APIRouter doesn't support middleware)
# @router.middleware("http")
# async def monitoring_middleware(request: Request, call_next):
#     """Middleware to track API performance metrics"""
#     
#     start_time = time.time()
#     
#     try:
#         # Get metrics instance
#         metrics = get_metrics()
#         
#         # Track request
#         with metrics.time_http_request(
#             request.method, 
#             request.url.path
#         ) as set_status:
#             response = await call_next(request)
#             set_status(response.status_code)
#             
#         return response
#         
#     except Exception as e:
#         # Record error metrics
#         logger.error(f"Error in monitoring middleware: {e}", exc_info=True)
#         response = await call_next(request)
#         return response