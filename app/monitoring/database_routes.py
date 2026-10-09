"""
Database Performance Monitoring Routes
Advanced monitoring endpoints for world-class database optimization
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import logging
from core.database import (
    get_connection_health, get_pool_status, get_query_performance_stats,
    get_transaction_stats, clear_query_cache, reset_metrics, engine_manager,
    db_metrics, query_cache, query_monitor, transaction_manager, pool_monitor,
    DatabaseOperation
)
from auth.dependencies import get_current_user
from core.utils import utc_now_iso

router = APIRouter(prefix="/monitoring/database", tags=["Database Monitoring"])
logger = logging.getLogger(__name__)

@router.get("/health/comprehensive", response_model=Dict[str, Any])
async def get_comprehensive_database_health(admin_user=Depends(get_current_user)):
    """
    Get comprehensive database health with all monitoring data
    Requires admin authentication
    """
    try:
        health_data = await get_connection_health()
        health_data["generated_at"] = utc_now_iso()
        health_data["monitoring_version"] = "2.0.0"
        
        return health_data
    except Exception as e:
        logger.error(f"Failed to get comprehensive database health: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@router.get("/pool/status", response_model=Dict[str, Any])
async def get_pool_detailed_status(admin_user=Depends(get_current_user)):
    """
    Get detailed connection pool status with health monitoring
    """
    try:
        pool_status = await get_pool_status()
        pool_status["timestamp"] = utc_now_iso()
        return pool_status
    except Exception as e:
        logger.error(f"Failed to get pool status: {e}")
        raise HTTPException(status_code=500, detail=f"Pool status check failed: {str(e)}")

@router.get("/performance/queries", response_model=Dict[str, Any])
async def get_query_performance(
    include_slow_queries: bool = Query(True, description="Include slow query details"),
    limit_slow_queries: int = Query(50, ge=1, le=500, description="Limit number of slow queries returned"),
    admin_user=Depends(get_current_user)
):
    """
    Get detailed query performance statistics with caching metrics
    """
    try:
        performance_stats = await get_query_performance_stats()
        
        # Limit slow queries if requested
        if not include_slow_queries:
            performance_stats["performance_stats"].pop("recent_slow_queries", None)
        elif "performance_stats" in performance_stats and "recent_slow_queries" in performance_stats["performance_stats"]:
            performance_stats["performance_stats"]["recent_slow_queries"] = \
                performance_stats["performance_stats"]["recent_slow_queries"][:limit_slow_queries]
        
        performance_stats["timestamp"] = utc_now_iso()
        return performance_stats
    except Exception as e:
        logger.error(f"Failed to get query performance: {e}")
        raise HTTPException(status_code=500, detail=f"Query performance check failed: {str(e)}")

@router.get("/transactions/stats", response_model=Dict[str, Any])
async def get_transaction_statistics(
    include_long_running: bool = Query(True, description="Include long-running transaction details"),
    admin_user=Depends(get_current_user)
):
    """
    Get comprehensive transaction management statistics
    """
    try:
        transaction_stats = await get_transaction_stats()
        
        if not include_long_running:
            transaction_stats.pop("long_running_transactions", None)
        
        transaction_stats["timestamp"] = utc_now_iso()
        return transaction_stats
    except Exception as e:
        logger.error(f"Failed to get transaction stats: {e}")
        raise HTTPException(status_code=500, detail=f"Transaction stats failed: {str(e)}")

@router.get("/engines/status", response_model=Dict[str, Any])
async def get_engine_status(admin_user=Depends(get_current_user)):
    """
    Get status of all database engines (primary and replicas)
    """
    try:
        engine_stats = engine_manager.get_engine_stats()
        engine_health = await engine_manager.check_all_engines_health()
        
        return {
            "timestamp": utc_now_iso(),
            "engine_stats": engine_stats,
            "engine_health": engine_health,
            "load_balancing_active": len(engine_stats.get("engines", [])) > 1
        }
    except Exception as e:
        logger.error(f"Failed to get engine status: {e}")
        raise HTTPException(status_code=500, detail=f"Engine status check failed: {str(e)}")

@router.get("/cache/stats", response_model=Dict[str, Any])
async def get_cache_statistics(admin_user=Depends(get_current_user)):
    """
    Get detailed query cache statistics
    """
    try:
        cache_stats = query_cache.get_stats()
        cache_stats["timestamp"] = utc_now_iso()
        cache_stats["cache_health"] = "healthy" if cache_stats["hit_rate_percent"] > 20 else "poor"
        
        return cache_stats
    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        raise HTTPException(status_code=500, detail=f"Cache stats failed: {str(e)}")

@router.get("/metrics/summary", response_model=Dict[str, Any])
async def get_metrics_summary(admin_user=Depends(get_current_user)):
    """
    Get summarized database metrics for dashboard display
    """
    try:
        all_metrics = db_metrics.get_metrics()
        
        summary = {
            "timestamp": utc_now_iso(),
            "connection_health": {
                "total_connections": all_metrics["total_connections"],
                "active_connections": all_metrics["active_connections"],
                "pool_efficiency": all_metrics["pool_efficiency"],
                "recent_errors": all_metrics["recent_errors"]
            },
            "query_performance": {
                "total_queries": all_metrics["query_count"],
                "failed_queries": all_metrics["failed_queries"],
                "cache_hit_rate": all_metrics["query_cache"]["hit_rate_percent"],
                "slow_queries_count": all_metrics["query_performance"]["slow_queries_count"]
            },
            "transaction_health": {
                "active_transactions": all_metrics["transaction_management"]["active_transactions"],
                "deadlock_events": all_metrics["transaction_management"]["deadlock_events"],
                "transaction_timeouts": all_metrics["transaction_management"]["transaction_timeouts"]
            },
            "overall_health": _calculate_overall_health(all_metrics)
        }
        
        return summary
    except Exception as e:
        logger.error(f"Failed to get metrics summary: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics summary failed: {str(e)}")

@router.post("/cache/clear")
async def clear_database_cache(admin_user=Depends(get_current_user)):
    """
    Clear query cache manually
    """
    try:
        await clear_query_cache()
        return {
            "message": "Query cache cleared successfully",
            "timestamp": utc_now_iso(),
            "cache_stats": query_cache.get_stats()
        }
    except Exception as e:
        logger.error(f"Failed to clear cache: {e}")
        raise HTTPException(status_code=500, detail=f"Cache clear failed: {str(e)}")

@router.post("/metrics/reset")
async def reset_database_metrics(admin_user=Depends(get_current_user)):
    """
    Reset database metrics (except active transactions)
    """
    try:
        await reset_metrics()
        return {
            "message": "Database metrics reset successfully",
            "timestamp": utc_now_iso(),
            "note": "Active transaction data preserved for safety"
        }
    except Exception as e:
        logger.error(f"Failed to reset metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics reset failed: {str(e)}")

@router.get("/optimization/recommendations", response_model=Dict[str, Any])
async def get_optimization_recommendations(admin_user=Depends(get_current_user)):
    """
    Get intelligent optimization recommendations based on current metrics
    """
    try:
        all_metrics = db_metrics.get_metrics()
        recommendations = _generate_optimization_recommendations(all_metrics)
        
        return {
            "timestamp": utc_now_iso(),
            "recommendations": recommendations,
            "metrics_analyzed": {
                "connection_pool": True,
                "query_performance": True,
                "cache_efficiency": True,
                "transaction_health": True
            }
        }
    except Exception as e:
        logger.error(f"Failed to generate recommendations: {e}")
        raise HTTPException(status_code=500, detail=f"Recommendations failed: {str(e)}")

@router.get("/alerts/active", response_model=Dict[str, Any])
async def get_active_alerts(admin_user=Depends(get_current_user)):
    """
    Get active database performance alerts
    """
    try:
        alerts = _check_database_alerts()
        
        return {
            "timestamp": utc_now_iso(),
            "alert_count": len(alerts),
            "alerts": alerts,
            "severity_counts": {
                "critical": len([a for a in alerts if a["severity"] == "critical"]),
                "warning": len([a for a in alerts if a["severity"] == "warning"]),
                "info": len([a for a in alerts if a["severity"] == "info"])
            }
        }
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Alerts check failed: {str(e)}")

# Helper functions for analysis

def _calculate_overall_health(metrics: Dict[str, Any]) -> str:
    """Calculate overall database health status"""
    score = 0
    max_score = 10
    
    # Connection health (25%)
    if metrics["pool_efficiency"] > 80:
        score += 2.5
    elif metrics["pool_efficiency"] > 60:
        score += 1.5
    elif metrics["pool_efficiency"] > 40:
        score += 1
    
    # Query performance (25%)
    if metrics["failed_queries"] == 0:
        score += 2.5
    elif metrics["failed_queries"] < 10:
        score += 1.5
    elif metrics["failed_queries"] < 50:
        score += 1
    
    # Cache efficiency (25%)
    cache_hit_rate = metrics["query_cache"]["hit_rate_percent"]
    if cache_hit_rate > 70:
        score += 2.5
    elif cache_hit_rate > 50:
        score += 1.5
    elif cache_hit_rate > 30:
        score += 1
    
    # Transaction health (25%)
    deadlocks = metrics["transaction_management"]["deadlock_events"]
    if deadlocks == 0:
        score += 2.5
    elif deadlocks < 5:
        score += 1.5
    elif deadlocks < 20:
        score += 1
    
    health_percentage = (score / max_score) * 100
    
    if health_percentage >= 90:
        return "excellent"
    elif health_percentage >= 75:
        return "good"
    elif health_percentage >= 50:
        return "fair"
    elif health_percentage >= 25:
        return "poor"
    else:
        return "critical"

def _generate_optimization_recommendations(metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate intelligent optimization recommendations"""
    recommendations = []
    
    # Pool efficiency recommendations
    pool_efficiency = metrics["pool_efficiency"]
    if pool_efficiency < 50:
        recommendations.append({
            "category": "connection_pool",
            "severity": "warning",
            "title": "Low Connection Pool Efficiency",
            "description": f"Pool efficiency is {pool_efficiency:.1f}%. Consider increasing pool size or optimizing query patterns.",
            "suggested_action": "Review DB_POOL_SIZE environment variable and connection usage patterns"
        })
    
    # Cache efficiency recommendations
    cache_hit_rate = metrics["query_cache"]["hit_rate_percent"]
    if cache_hit_rate < 30:
        recommendations.append({
            "category": "query_cache",
            "severity": "info",
            "title": "Low Cache Hit Rate",
            "description": f"Query cache hit rate is {cache_hit_rate:.1f}%. Consider increasing cache size or TTL.",
            "suggested_action": "Adjust DB_CACHE_SIZE or DB_CACHE_TTL environment variables"
        })
    
    # Deadlock recommendations
    deadlocks = metrics["transaction_management"]["deadlock_events"]
    if deadlocks > 10:
        recommendations.append({
            "category": "transactions",
            "severity": "warning" if deadlocks < 50 else "critical",
            "title": "Frequent Deadlocks Detected",
            "description": f"Detected {deadlocks} deadlock events. Review transaction ordering and locking patterns.",
            "suggested_action": "Optimize transaction logic and consider shorter transaction scopes"
        })
    
    # Slow query recommendations
    slow_query_count = metrics["query_performance"]["slow_queries_count"]
    if slow_query_count > 100:
        recommendations.append({
            "category": "query_performance",
            "severity": "warning",
            "title": "High Number of Slow Queries",
            "description": f"Detected {slow_query_count} slow queries. Review and optimize query performance.",
            "suggested_action": "Add database indexes, optimize query patterns, or adjust DB_SLOW_QUERY_THRESHOLD"
        })
    
    return recommendations

def _check_database_alerts() -> List[Dict[str, Any]]:
    """Check for active database alerts"""
    alerts = []
    
    try:
        all_metrics = db_metrics.get_metrics()
        
        # High connection usage alert
        if "pool_health" in all_metrics:
            pool_health = all_metrics["pool_health"]
            if pool_health.get("status") == "critical":
                alerts.append({
                    "severity": "critical",
                    "category": "connection_pool",
                    "title": "Critical Connection Pool Usage",
                    "message": f"Connection pool usage at {pool_health.get('max_usage_percent', 0):.1f}%",
                    "timestamp": utc_now_iso()
                })
            elif pool_health.get("status") == "warning":
                alerts.append({
                    "severity": "warning",
                    "category": "connection_pool",
                    "title": "High Connection Pool Usage",
                    "message": f"Connection pool usage at {pool_health.get('average_usage_percent', 0):.1f}%",
                    "timestamp": utc_now_iso()
                })
        
        # Long-running transactions alert
        long_running = all_metrics["long_running_transactions"]
        if len(long_running) > 5:
            alerts.append({
                "severity": "warning",
                "category": "transactions",
                "title": "Multiple Long-Running Transactions",
                "message": f"{len(long_running)} transactions running longer than expected",
                "timestamp": utc_now_iso()
            })
        
        # High error rate alert
        if all_metrics["failed_queries"] > 100:
            alerts.append({
                "severity": "critical" if all_metrics["failed_queries"] > 500 else "warning",
                "category": "query_errors",
                "title": "High Query Failure Rate",
                "message": f"{all_metrics['failed_queries']} failed queries detected",
                "timestamp": utc_now_iso()
            })
        
    except Exception as e:
        logger.error(f"Error checking database alerts: {e}")
        alerts.append({
            "severity": "warning",
            "category": "monitoring",
            "title": "Monitoring System Alert",
            "message": f"Error in alert system: {str(e)}",
            "timestamp": utc_now_iso()
        })
    
    return alerts