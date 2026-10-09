"""
Separate health check module to avoid cluttering logs
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import os

from core.database import get_db
from core.utils import utc_now_iso

health_router = APIRouter(tags=["health"])

@health_router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Simple health check endpoint"""
    # Don't log health checks from Render's internal IPs to reduce noise
    return {
        "status": "ok",
        "timestamp": utc_now_iso(),
        "environment": os.getenv("APP_ENV", "unknown"),
        "version": os.getenv("APP_VERSION", "1.0.0")
    }

@health_router.get("/health/detailed")
async def detailed_health_check(db: AsyncSession = Depends(get_db)):
    """Detailed health check with advanced database metrics"""
    from core.database import get_connection_health
    
    status = {
        "status": "ok",
        "timestamp": utc_now_iso(),
        "environment": os.getenv("APP_ENV", "unknown"),
        "database": False,
        "redis": False
    }
    
    # Test database with basic query
    try:
        await db.execute(text("SELECT 1"))
        status["database"] = True
    except Exception as e:
        status["database"] = str(e)
    
    # Get advanced database health data
    try:
        status["database_advanced"] = await get_connection_health()
    except Exception as e:
        status["database_advanced"] = f"Advanced metrics error: {str(e)}"
    
    # Test Redis with optimizer support
    try:
        from core.cache import cache_health_check
        redis_health = await cache_health_check()
        status["redis"] = redis_health.get("redis_available", False)
        status["redis_detailed"] = redis_health
    except Exception as e:
        status["redis"] = f"Redis health check error: {str(e)}"
    
    return status

@health_router.get("/health/database")
async def database_health_check():
    """Dedicated database health endpoint with full metrics"""
    from core.database import get_connection_health
    
    try:
        health_data = await get_connection_health()
        return {
            "status": "healthy" if health_data["connection_test"]["status"] == "healthy" else "unhealthy",
            "timestamp": health_data["timestamp"],
            **health_data
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": utc_now_iso(),
            "error": str(e)
        }

@health_router.get("/health/database/metrics")
async def database_metrics():
    """Get current database performance metrics"""
    from core.database import db_metrics, get_pool_status
    
    try:
        pool_status = await get_pool_status()
        metrics = db_metrics.get_metrics()
        
        return {
            "timestamp": utc_now_iso(),
            "pool_status": pool_status,
            "performance_metrics": metrics,
            "status": "healthy"
        }
    except Exception as e:
        return {
            "timestamp": utc_now_iso(),
            "error": str(e),
            "status": "error"
        }

@health_router.get("/health/redis")
async def redis_health_check():
    """Comprehensive Redis health check with performance metrics"""
    try:
        from core.cache import cache_health_check
        return await cache_health_check()
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "redis_available": False,
            "redis_optimizer_enabled": False,
            "timestamp": utc_now_iso()
        }

@health_router.get("/health/performance")
async def performance_health_check():
    """Performance metrics including Redis optimization stats"""
    try:
        from core.redis_optimized import get_redis_optimizer
        from core.memory_optimizer import memory_health_check
        from core.timeout_monitoring import get_performance_summary
        
        performance_data = {
            "timestamp": utc_now_iso(),
            "memory": await memory_health_check(),
            "timeout_performance": get_performance_summary(),
            "redis_optimizer": None
        }
        
        # Get Redis optimizer performance stats
        try:
            redis_optimizer = await get_redis_optimizer()
            if redis_optimizer and redis_optimizer.enabled:
                performance_data["redis_optimizer"] = await redis_optimizer.get_performance_stats()
        except Exception as redis_error:
            performance_data["redis_optimizer"] = {"error": str(redis_error)}
        
        return performance_data
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": utc_now_iso()
        }