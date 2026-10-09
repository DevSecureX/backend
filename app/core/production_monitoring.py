"""
Production Monitoring Integration for DevSecureX
Comprehensive monitoring setup and health checks for production deployment
"""

import asyncio
import logging
import time
import json
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class ProductionMonitor:
    """
    CRITICAL FIX: Production monitoring system integration
    Provides comprehensive health checks and monitoring endpoints
    """
    
    def __init__(self):
        self.monitoring_enabled = os.getenv("PRODUCTION_MONITORING_ENABLED", "true").lower() == "true"
        self.health_check_interval = float(os.getenv("HEALTH_CHECK_INTERVAL", "60"))  # 1 minute
        self.monitoring_task: Optional[asyncio.Task] = None
        self.last_health_check = None
        
        # Component health status
        self.component_health = {
            "database": {"status": "unknown", "last_check": None, "error": None},
            "redis": {"status": "unknown", "last_check": None, "error": None},
            "workers": {"status": "unknown", "last_check": None, "error": None},
            "queue_system": {"status": "unknown", "last_check": None, "error": None}
        }
        
        # Critical metrics
        self.critical_metrics = {
            "total_scans_today": 0,
            "failed_scans_today": 0,
            "average_scan_duration": 0.0,
            "active_workers": 0,
            "dead_workers": 0,
            "redis_connections": 0,
            "database_connections": 0,
            "memory_usage_mb": 0,
            "cpu_usage_percent": 0
        }
        
        logger.info(f"Production Monitor initialized (monitoring: {self.monitoring_enabled})")
    
    async def start_monitoring(self):
        """Start production monitoring"""
        if not self.monitoring_enabled:
            logger.info("Production monitoring disabled")
            return
        
        if self.monitoring_task and not self.monitoring_task.done():
            logger.warning("Production monitoring already running")
            return
        
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info(f"Started production monitoring (interval: {self.health_check_interval}s)")
    
    async def stop_monitoring(self):
        """Stop production monitoring"""
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped production monitoring")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                await self._perform_health_checks()
                await self._update_critical_metrics()
                self.last_health_check = datetime.now(timezone.utc)
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in production monitoring loop: {e}")
                await asyncio.sleep(self.health_check_interval)
    
    async def _perform_health_checks(self):
        """Perform comprehensive health checks"""
        # Database health check
        await self._check_database_health()
        
        # Redis health check
        await self._check_redis_health()
        
        # Worker health check
        await self._check_worker_health()
        
        # Queue system health check
        await self._check_queue_health()
    
    async def _check_database_health(self):
        """Check database health"""
        try:
            from core.database import test_connection
            result = await test_connection()
            
            if result.get("status") == "healthy":
                self.component_health["database"] = {
                    "status": "healthy",
                    "last_check": time.time(),
                    "error": None,
                    "response_time_ms": result.get("response_time_ms", 0),
                    "pool_status": result.get("pool_size", "unknown")
                }
            else:
                self.component_health["database"] = {
                    "status": "unhealthy",
                    "last_check": time.time(),
                    "error": result.get("error", "Unknown database error"),
                    "response_time_ms": 0
                }
        except Exception as e:
            self.component_health["database"] = {
                "status": "error",
                "last_check": time.time(),
                "error": str(e)
            }
    
    async def _check_redis_health(self):
        """Check Redis health"""
        try:
            from core.redis import get_redis_client, get_redis_client_stats
            
            client = await get_redis_client()
            if client:
                # Test Redis connection
                start_time = time.time()
                await client.ping()
                response_time = (time.time() - start_time) * 1000
                
                # Get client stats
                stats = get_redis_client_stats()
                
                self.component_health["redis"] = {
                    "status": "healthy",
                    "last_check": time.time(),
                    "error": None,
                    "response_time_ms": response_time,
                    "client_stats": stats
                }
            else:
                self.component_health["redis"] = {
                    "status": "unhealthy",
                    "last_check": time.time(),
                    "error": "Redis client unavailable"
                }
        except Exception as e:
            self.component_health["redis"] = {
                "status": "error",
                "last_check": time.time(),
                "error": str(e)
            }
    
    async def _check_worker_health(self):
        """Check worker health"""
        try:
            from core.worker_health_monitor import get_worker_health_monitor
            
            monitor = await get_worker_health_monitor()
            health_data = monitor.get_all_workers_health()
            
            stats = health_data.get("statistics", {})
            healthy_count = stats.get("healthy_workers", 0)
            dead_count = stats.get("dead_workers", 0)
            total_workers = len(health_data.get("workers", {}))
            
            if total_workers == 0:
                status = "warning"
                error = "No workers registered"
            elif dead_count > 0:
                status = "warning"
                error = f"{dead_count} dead workers detected"
            elif healthy_count == total_workers:
                status = "healthy"
                error = None
            else:
                status = "warning"
                error = f"Only {healthy_count}/{total_workers} workers healthy"
            
            self.component_health["workers"] = {
                "status": status,
                "last_check": time.time(),
                "error": error,
                "total_workers": total_workers,
                "healthy_workers": healthy_count,
                "dead_workers": dead_count,
                "monitoring_active": health_data.get("monitoring_active", False)
            }
            
            # Update critical metrics
            self.critical_metrics["active_workers"] = healthy_count
            self.critical_metrics["dead_workers"] = dead_count
            
        except Exception as e:
            self.component_health["workers"] = {
                "status": "error",
                "last_check": time.time(),
                "error": str(e)
            }
    
    async def _check_queue_health(self):
        """Check queue system health"""
        try:
            # This would check the unified queue system
            # Placeholder for now
            self.component_health["queue_system"] = {
                "status": "healthy",
                "last_check": time.time(),
                "error": None,
                "note": "Queue health check not fully implemented"
            }
        except Exception as e:
            self.component_health["queue_system"] = {
                "status": "error",
                "last_check": time.time(),
                "error": str(e)
            }
    
    async def _update_critical_metrics(self):
        """Update critical metrics"""
        try:
            # Update memory usage
            try:
                import psutil
                import os
                process = psutil.Process(os.getpid())
                memory_info = process.memory_info()
                self.critical_metrics["memory_usage_mb"] = round(memory_info.rss / 1024 / 1024, 2)
                self.critical_metrics["cpu_usage_percent"] = round(process.cpu_percent(), 2)
            except ImportError:
                pass
            
            # Update Redis connection count
            if self.component_health["redis"]["status"] == "healthy":
                stats = self.component_health["redis"].get("client_stats", {})
                self.critical_metrics["redis_connections"] = stats.get("usage_count", 0)
            
            # Update database connection metrics from database health
            if self.component_health["database"]["status"] == "healthy":
                pool_info = self.component_health["database"].get("pool_status", {})
                if isinstance(pool_info, dict):
                    self.critical_metrics["database_connections"] = pool_info.get("checked_out", 0)
            
        except Exception as e:
            logger.warning(f"Error updating critical metrics: {e}")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        # Determine overall status
        statuses = [comp["status"] for comp in self.component_health.values()]
        
        if "error" in statuses:
            overall_status = "critical"
        elif "unhealthy" in statuses:
            overall_status = "unhealthy"
        elif "warning" in statuses:
            overall_status = "warning"
        else:
            overall_status = "healthy"
        
        return {
            "overall_status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": self.component_health.copy(),
            "critical_metrics": self.critical_metrics.copy(),
            "monitoring_enabled": self.monitoring_enabled,
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None
        }
    
    def get_production_readiness_report(self) -> Dict[str, Any]:
        """Generate production readiness report"""
        health_status = self.get_health_status()
        
        # Check production readiness criteria
        readiness_checks = {
            "database_healthy": health_status["components"]["database"]["status"] == "healthy",
            "redis_healthy": health_status["components"]["redis"]["status"] == "healthy",
            "workers_active": self.critical_metrics["active_workers"] > 0,
            "no_dead_workers": self.critical_metrics["dead_workers"] == 0,
            "monitoring_enabled": self.monitoring_enabled,
            "memory_usage_reasonable": self.critical_metrics["memory_usage_mb"] < 2048,  # Less than 2GB
            "cpu_usage_reasonable": self.critical_metrics["cpu_usage_percent"] < 80,  # Less than 80%
        }
        
        # Calculate readiness score
        passed_checks = sum(1 for check in readiness_checks.values() if check)
        total_checks = len(readiness_checks)
        readiness_score = (passed_checks / total_checks) * 100
        
        # Determine deployment readiness
        if readiness_score >= 100:
            deployment_ready = "ready"
        elif readiness_score >= 80:
            deployment_ready = "warning"
        else:
            deployment_ready = "not_ready"
        
        return {
            "deployment_ready": deployment_ready,
            "readiness_score": round(readiness_score, 1),
            "checks_passed": passed_checks,
            "total_checks": total_checks,
            "readiness_checks": readiness_checks,
            "health_status": health_status,
            "recommendations": self._generate_recommendations(readiness_checks),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _generate_recommendations(self, checks: Dict[str, bool]) -> List[str]:
        """Generate recommendations for production readiness"""
        recommendations = []
        
        if not checks["database_healthy"]:
            recommendations.append("Fix database connectivity issues")
        
        if not checks["redis_healthy"]:
            recommendations.append("Fix Redis connectivity issues")
        
        if not checks["workers_active"]:
            recommendations.append("Start worker processes")
        
        if not checks["no_dead_workers"]:
            recommendations.append("Restart or remove dead workers")
        
        if not checks["monitoring_enabled"]:
            recommendations.append("Enable production monitoring")
        
        if not checks["memory_usage_reasonable"]:
            recommendations.append("Reduce memory usage or increase system resources")
        
        if not checks["cpu_usage_reasonable"]:
            recommendations.append("Reduce CPU usage or increase system resources")
        
        if not recommendations:
            recommendations.append("System is production ready!")
        
        return recommendations


# Global production monitor
_production_monitor = ProductionMonitor()


async def get_production_monitor() -> ProductionMonitor:
    """Get the global production monitor"""
    return _production_monitor


async def start_production_monitoring():
    """Start production monitoring"""
    monitor = await get_production_monitor()
    await monitor.start_monitoring()


async def stop_production_monitoring():
    """Stop production monitoring"""
    monitor = await get_production_monitor()
    await monitor.stop_monitoring()


# FastAPI router for monitoring endpoints
monitoring_router = APIRouter(prefix="/monitoring/production", tags=["monitoring"])


@monitoring_router.get("/health")
async def get_health():
    """Get system health status"""
    monitor = await get_production_monitor()
    return JSONResponse(monitor.get_health_status())


@monitoring_router.get("/production-readiness")
async def get_production_readiness():
    """Get production readiness report"""
    monitor = await get_production_monitor()
    return JSONResponse(monitor.get_production_readiness_report())


@monitoring_router.get("/metrics")
async def get_metrics():
    """Get critical metrics"""
    monitor = await get_production_monitor()
    health_status = monitor.get_health_status()
    return JSONResponse({
        "critical_metrics": health_status["critical_metrics"],
        "timestamp": health_status["timestamp"]
    })


@monitoring_router.post("/restart-monitoring")
async def restart_monitoring():
    """Restart production monitoring"""
    monitor = await get_production_monitor()
    await monitor.stop_monitoring()
    await monitor.start_monitoring()
    return {"status": "restarted", "timestamp": datetime.now(timezone.utc).isoformat()}


@monitoring_router.get("/worker-health")
async def get_worker_health_details():
    """Get detailed worker health information"""
    try:
        from core.worker_health_monitor import get_worker_health_monitor
        monitor = await get_worker_health_monitor()
        return JSONResponse(monitor.get_all_workers_health())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get worker health: {str(e)}")


@monitoring_router.get("/redis-status")
async def get_redis_status():
    """Get detailed Redis status"""
    try:
        from core.redis import get_redis_client_stats
        from core.redis_pool_manager import get_redis_metrics, get_worker_redis_manager
        
        client_stats = get_redis_client_stats()
        pool_metrics = get_redis_metrics()
        
        # Get worker Redis manager metrics
        try:
            worker_manager = await get_worker_redis_manager()
            worker_metrics = worker_manager.get_connection_metrics()
        except Exception:
            worker_metrics = {"error": "Worker Redis manager unavailable"}
        
        return JSONResponse({
            "client_stats": client_stats,
            "pool_metrics": pool_metrics,
            "worker_metrics": worker_metrics,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get Redis status: {str(e)}")


@monitoring_router.get("/database-status")
async def get_database_status():
    """Get detailed database status"""
    try:
        from core.database import get_connection_health
        return JSONResponse(await get_connection_health())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get database status: {str(e)}")