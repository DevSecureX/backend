import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from core.utils import utc_now_iso
from auth.routes import auth_router
from repos.routes import repos_router
from scans.routes import scans_router  # Import from main routes file
from custom_rules.routes import rules_router  # Custom rules API (modular)
from ai_assistant.routes import ai_router  # AI assistant router
from analytics.routes import router as analytics_router  # Analytics router
from issues.routes import issues_router  # Issue tracking router
from support.simple_routes import router as support_router  # Support & help router (simple version)
from cli_scan.routes import cli_scan_router  # CLI scanning API
from monitoring.database_routes import router as database_monitoring_router  # Database monitoring
from monitoring.task_system_routes import router as task_system_monitoring_router  # Task system monitoring
from monitoring.monitoring_routes import router as monitoring_router  # Main monitoring & Prometheus metrics
from monitoring.unified_queue_monitoring import router as unified_queue_monitoring_router  # Unified queue monitoring
from core.production_monitoring import monitoring_router as production_monitoring_router  # CRITICAL FIX: Production monitoring
# Models imported for SQLAlchemy table registration - DO NOT REMOVE
from support import models as support_models
from cli_scan import models as cli_scan_models
from ai_assistant.socket_manager import ai_socket_manager  # Socket.IO manager
from scans.workers.manager import start_background_workers, stop_background_workers
# Basic autofix workers removed - using enterprise autofix system only
from core.task_system.integration_layer import initialize_task_system, start_task_system, stop_task_system
from core.database import Base, test_connection, close_db
from core.redis import get_redis_client
from core.memory_optimizer import memory_health_check, MemoryMonitoringMiddleware
from core.timeout_monitoring import get_performance_summary
from core.rate_limiting import init_rate_limiter
# SQLAlchemy imports removed as they're not used in this file
from sqlalchemy.orm import configure_mappers

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment check for proper application configuration
def is_production_environment() -> bool:
    """Check if running in production environment"""
    app_env = os.getenv("APP_ENV", "development").lower()
    environment = os.getenv("ENVIRONMENT", "development").lower()
    return app_env == "production" or environment == "production"

def is_development_environment() -> bool:
    """Check if running in development environment with hot reload"""
    app_env = os.getenv("APP_ENV", "development").lower()
    environment = os.getenv("ENVIRONMENT", "development").lower()
    return app_env in ["local", "development"] or environment in ["local", "development"]

# Load CORS origins from environment variable with Firebase and production domains
default_origins = [
    # Local development
    "http://localhost:5173", "http://localhost:5174", "http://localhost:5175", 
    "http://localhost:5176", "http://localhost:5177", "http://localhost:8080",
    # Production domains
    "https://www.devsecurex.com", "https://devsecurex.com",
]

# Get additional origins from environment (for Firebase hosting domains)
env_origins = os.getenv("CORS_ORIGINS", "")
if env_origins:
    env_origins_list = [origin.strip().rstrip("/") for origin in env_origins.split(",")]
    cors_origins = env_origins_list + default_origins
else:
    cors_origins = default_origins

# Remove duplicates and empty strings
cors_origins = list(set([origin for origin in cors_origins if origin]))

# Security: Only log CORS origins count in production to avoid information disclosure
app_env = os.getenv("APP_ENV", "development").lower()
if app_env in ["development", "local"]:
    logger.info(f"CORS Origins loaded: {cors_origins}")
else:
    logger.info(f"CORS Origins loaded: {len(cors_origins)} domains configured")

# Lifespan setup for DB and Redis

# Update the lifespan function to start/stop background workers
@asynccontextmanager
async def lifespan(app: FastAPI):
    
    # Simple database setup
    try:
        # Import all model modules to register tables with SQLAlchemy
        logger.info("Importing SQLAlchemy models...")
        
        # These imports are required for SQLAlchemy table registration
        import auth.models  # noqa: F401
        import repos.models  # noqa: F401
        import scans.models  # noqa: F401
        import custom_rules.models  # noqa: F401
        import ai_assistant.models  # noqa: F401
        import support.models  # noqa: F401
        import cli_scan.models  # noqa: F401
        
        # Configure mappers to build relationships
        configure_mappers()
        
        logger.info(f"Models imported: {len(Base.metadata.tables)} tables registered")
        
        # Create database tables if they don't exist
        logger.info("Creating database tables...")
        from core.database import create_tables
        await create_tables()
        logger.info("Database tables created/verified successfully")
        
    except Exception as e:
        logger.error(f"Database setup error: {e}")
    
    # Initialize Prometheus metrics
    try:
        from monitoring.prometheus_metrics import init_metrics
        import os
        
        metrics = init_metrics()
        
        # Set application information for Prometheus
        app_version = os.getenv("APP_VERSION", "1.0.0")
        app_env = os.getenv("APP_ENV", "development")
        build_time = os.getenv("BUILD_TIME", utc_now_iso())
        
        metrics.set_app_info(
            version=app_version,
            environment=app_env, 
            build_time=build_time
        )
        
        logger.info("Prometheus metrics initialized successfully")
        
    except Exception as e:
        logger.error(f"Prometheus metrics initialization error: {e}")
    
    # CRITICAL FIX: Setup production signal handlers
    try:
        from core.signal_handlers import setup_production_signal_handlers
        setup_production_signal_handlers("devsecurex-main")
        logger.info("Production signal handlers configured")
    except Exception as e:
        logger.warning(f"Signal handlers setup failed: {e}")
    
    # CRITICAL FIX: Initialize production monitoring system
    try:
        from core.production_monitoring import start_production_monitoring
        from core.worker_health_monitor import start_worker_health_monitoring
        
        # Start worker health monitoring
        await start_worker_health_monitoring()
        logger.info("Worker health monitoring started")
        
        # Start production monitoring 
        await start_production_monitoring()
        logger.info("Production monitoring started")
        
    except Exception as e:
        logger.error(f"Production monitoring initialization error: {e}")
    
    # Initialize Redis optimizer for world-class caching performance with graceful degradation
    # NOTE: This replaces the legacy Redis client to prevent connection pool exhaustion
    try:
        from core.redis_optimized import initialize_redis_optimizer
        
        # Skip Redis initialization in production if not configured to avoid startup delays
        if is_production_environment() and not os.getenv("REDIS_URL"):
            logger.info("Redis not configured for production - running without caching")
            app.state.redis_optimizer = None
        else:
            redis_optimizer = await initialize_redis_optimizer()
            if redis_optimizer and redis_optimizer.enabled:
                logger.info("Redis optimizer initialized with multi-pool architecture")
                # Store optimizer reference for health checks
                app.state.redis_optimizer = redis_optimizer
            else:
                logger.info("Redis optimizer disabled or not available")
                app.state.redis_optimizer = None
    except Exception as e:
        logger.warning(f"Failed to initialize Redis optimizer: {e} - continuing without caching")
        app.state.redis_optimizer = None
    
    # Initialize rate limiter with Redis support (uses Redis optimizer if available)
    try:
        await init_rate_limiter()
        logger.info("Rate limiter initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize rate limiter: {e}")
    
    # Initialize worker systems based on environment configuration
    # CRITICAL FIX: Only start ONE worker system to prevent conflicts and resource waste
    app_env = os.getenv("APP_ENV", "development").lower()
    enable_workers = os.getenv("ENABLE_BACKGROUND_WORKERS", "false").lower() == "true"
    # Enterprise queues removed - only fortress and legacy systems supported
    use_fortress = os.getenv("USE_FORTRESS_QUEUES", "false").lower() == "true"
    
    worker_system_started = False
    app.state.enterprise_systems = None
    app.state.fortress_systems = None
    
    # Try fortress systems first if enabled (newest system)
    if use_fortress:
        try:
            # Main fortress scanning system
            from scans.queue.fortress_queue_manager import get_fortress_queue_manager
            from scans.workers.fortress_worker_manager import get_fortress_worker_manager
            
            logger.info("🏰 Initializing fortress-grade queue management systems...")
            logger.info(f"Environment: SCAN_WORKERS={os.getenv('SCAN_WORKERS')}, FORTRESS_WORKER_COUNT={os.getenv('FORTRESS_WORKER_COUNT')}")
            
            # 1. Initialize fortress scanning system
            logger.info("Initializing fortress scanning queue system...")
            fortress_queue_manager = await get_fortress_queue_manager()
            fortress_worker_manager = await get_fortress_worker_manager()
            logger.info("✅ Fortress scanning system initialized")
            
            # Store references in app state for health checks
            app.state.fortress_systems = {
                "scanning_queue": fortress_queue_manager,
                "scanning_workers": fortress_worker_manager
            }
            
            # Get worker stats to confirm fortress workers are running
            worker_stats = await fortress_worker_manager.get_worker_stats()
            logger.info(f"🎯 Fortress workers status: {worker_stats.get('workers_active', 0)} active workers")
            logger.info(f"🎯 Fortress worker IDs: {worker_stats.get('worker_ids', [])}")
            
            logger.info("🎉 Fortress-grade queue systems are ready!")
            worker_system_started = True
            
        except Exception as e:
            logger.error(f"Failed to initialize fortress systems: {e}")
            logger.info("Falling back to enterprise/legacy worker system...")
    
    # Enterprise systems removed - only fortress and legacy systems supported
    
    # Fallback to legacy workers if enterprise not enabled or failed
    if not worker_system_started and enable_workers:
        try:
            await start_background_workers()
            logger.info("✅ Legacy background scan workers started")
            worker_system_started = True
        except Exception as e:
            logger.warning(f"Failed to start legacy background workers: {e}")
    
    if not worker_system_started:
        logger.warning("⚠️  NO WORKER SYSTEM STARTED - Scans will be processed synchronously")
        logger.info(f"To enable workers: Set ENABLE_BACKGROUND_WORKERS=true (current: {enable_workers})")
        logger.info(f"For fortress: Set USE_FORTRESS_QUEUES=true (current: {use_fortress})")
        logger.info("Enterprise queues have been removed - use fortress or legacy workers")
        logger.info(f"Environment: {app_env}")
    
    logger.warning("DEBUG: Reached autofix initialization section in lifespan")
    
    # CRITICAL FIX: Initialize autofix workers proactively instead of on-demand
    logger.warning("DEBUG: About to initialize autofix worker system...")
    try:
        logger.warning("DEBUG: Importing autofix modules...")
        from scans.autofix_queue.on_demand_manager import get_on_demand_autofix_manager, ensure_autofix_workers_available
        logger.warning("DEBUG: Autofix modules imported successfully")
        
        autofix_workers_enabled = os.getenv("ENABLE_AUTOFIX_WORKERS", "true").lower() == "true"
        logger.warning(f"DEBUG: ENABLE_AUTOFIX_WORKERS={os.getenv('ENABLE_AUTOFIX_WORKERS')}, enabled={autofix_workers_enabled}")
        
        if autofix_workers_enabled:
            # Initialize the on-demand manager
            logger.info("🔧 Initializing autofix worker system...")
            logger.warning("DEBUG: About to get on-demand manager...")
            on_demand_manager = get_on_demand_autofix_manager()
            logger.warning("DEBUG: Got on-demand manager successfully")
            app.state.on_demand_autofix_manager = on_demand_manager
            
            # CRITICAL FIX: Start autofix workers proactively during application startup
            logger.info("🔧 Starting autofix workers proactively during startup...")
            logger.warning("DEBUG: About to ensure autofix workers available...")
            workers_ready = await ensure_autofix_workers_available("startup_proactive")
            logger.warning(f"DEBUG: ensure_autofix_workers_available returned: {workers_ready}")
            
            if workers_ready:
                logger.info("✅ Autofix workers started successfully during application startup")
                app.state.autofix_workers_started = True
            else:
                logger.warning("⚠️  Autofix workers failed to start during startup - will retry on-demand")
                app.state.autofix_workers_started = False
        else:
            logger.info("Autofix workers disabled via configuration (ENABLE_AUTOFIX_WORKERS=false)")
    except Exception as e:
        logger.error(f"Failed to initialize autofix system during startup: {e}", exc_info=True)
        logger.info("Autofix workers will remain on-demand only")
    
    yield
    
    # Shutdown fortress queue systems first (newest system)
    try:
        from scans.queue.fortress_queue_manager import shutdown_fortress_queue_manager
        from scans.workers.fortress_worker_manager import shutdown_fortress_worker_manager
        
        logger.info("🏰 Shutting down fortress queue systems...")
        
        # Shutdown fortress systems
        fortress_shutdown_tasks = [
            shutdown_fortress_worker_manager(),
            shutdown_fortress_queue_manager()
        ]
        
        import asyncio
        await asyncio.gather(*fortress_shutdown_tasks, return_exceptions=True)
        logger.info("✅ All fortress systems stopped")
        
    except Exception as e:
        logger.warning(f"Error shutting down fortress systems: {e}")
    
    # Enterprise queue system cleanup - these systems are still active
    try:
        # Simple autofix queue doesn't need shutdown functions
        logger.info("Shutting down active enterprise systems...")
        
        # Simple autofix queue system doesn't need shutdown (no persistent resources)
        enterprise_shutdown_tasks = [
            # No autofix shutdown needed for simple queue
        ]
        
        # Run shutdowns in parallel
        await asyncio.gather(*enterprise_shutdown_tasks, return_exceptions=True)
        logger.info("✅ Active enterprise systems stopped")
        
    except Exception as e:
        logger.warning(f"Error shutting down enterprise systems: {e}")
    
    # Stop task system and workers
    try:
        await stop_task_system()
        logger.info("Phase 4: Auto-scaling task system stopped")
    except Exception as e:
        logger.warning(f"Error stopping Phase 4 task system: {e}")
    
    # Also stop legacy workers if they were started
    try:
        await stop_background_workers()
        logger.info("Legacy background scan workers stopped")
    except Exception as e:
        logger.warning(f"Failed to stop legacy background workers: {e}")
    
    # Note: Basic autofix workers removed - enterprise autofix system handles shutdown
    
    # Cleanup Redis optimizer
    try:
        from core.redis_optimized import close_redis_optimizer
        await close_redis_optimizer()
        logger.info("Redis optimizer closed")
    except Exception as e:
        logger.warning(f"Redis optimizer cleanup warning: {e}")
    
    # Cleanup database connections
    try:
        await close_db()
        logger.info("Database connections closed")
    except Exception as e:
        logger.warning(f"Database cleanup warning: {e}")
    
    # Cleanup legacy Redis connection
    try:
        from core.redis import close_redis_client
        await close_redis_client()
        logger.info("Redis connection closed")
    except Exception as e:
        logger.warning(f"Redis cleanup error: {e}")

# Initialize FastAPI app
app = FastAPI(
    lifespan=lifespan,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Mount Socket.IO app for AI assistant
socket_app = ai_socket_manager.get_asgi_app()
app.mount("/socket.io", socket_app)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add memory monitoring middleware
app.add_middleware(MemoryMonitoringMiddleware)

# Add CLI error monitoring middleware for 500 error tracking and recovery
from cli_scan.error_monitoring import CLIErrorMonitoringMiddleware
app.add_middleware(CLIErrorMonitoringMiddleware)

# Add optimized performance middlewares
from core.middleware import add_performance_middlewares
add_performance_middlewares(app)

# Include routers
app.include_router(auth_router)
app.include_router(repos_router)
app.include_router(scans_router)  # Include scans router
app.include_router(rules_router)  # Include custom rules API
app.include_router(ai_router)  # Include AI assistant router
app.include_router(analytics_router)  # Include analytics router
app.include_router(issues_router)  # Include issue tracking router
app.include_router(support_router)  # Include support & help router (simple version)
app.include_router(cli_scan_router)  # Include CLI scanning API
app.include_router(monitoring_router)  # Include main monitoring & Prometheus metrics API
app.include_router(database_monitoring_router)  # Include database monitoring API
app.include_router(task_system_monitoring_router)  # Include Phase 4 task system monitoring API
app.include_router(unified_queue_monitoring_router)  # Include unified queue monitoring API
app.include_router(production_monitoring_router)  # CRITICAL FIX: Include production monitoring API

# Enterprise scanning routes removed - use main scans router with fortress queue
# Enterprise monitoring API removed with enterprise queue system
# from monitoring.monitoring_api import monitoring_api_router
# app.include_router(monitoring_api_router)  # Enterprise monitoring API disabled

# Prometheus metrics endpoint for monitoring (unauthenticated for Prometheus scraping)
@app.get("/metrics")
async def prometheus_metrics_endpoint():
    """Prometheus metrics endpoint for monitoring stack"""
    try:
        from monitoring.prometheus_metrics import get_metrics
        from fastapi import Response
        
        metrics = get_metrics()
        metrics_content = metrics.generate_metrics()
        
        return Response(
            content=metrics_content, 
            media_type=metrics.get_content_type(),
            headers={"Content-Type": metrics.get_content_type()}
        )
        
    except Exception as e:
        logger.error(f"Error generating Prometheus metrics: {e}")
        # Return empty metrics instead of error to avoid breaking Prometheus
        return Response(
            content="# No metrics available\n",
            media_type="text/plain"
        )

# Simple health check endpoint for Render
@app.get("/health")
async def health_check():
    """Simple health check that returns quickly for Render deployment."""
    import os
    return {
        "status": "ok",
        "timestamp": utc_now_iso(),
        "environment": os.getenv("APP_ENV", "unknown"),
        "version": "1.0.0",
        "hot_reload_test": "Hot reload is working correctly! 🚀"
    }

# Simple detailed health check
@app.get("/health/detailed")
async def detailed_health_check():
    import time
    import os
    
    start_time = time.time()
    status = {
        "status": "ok",
        "timestamp": utc_now_iso(),
        "environment": os.getenv("APP_ENV", "unknown"),
        "version": "1.0.0",
        "services": {
            "redis": {"status": "unknown", "response_time_ms": None},
            "database": {"status": "unknown", "response_time_ms": None}
        }
    }
    
    # Check Redis using the optimizer
    redis_start = time.time()
    try:
        # Use the Redis optimizer for health checks to prevent connection issues
        if hasattr(app.state, 'redis_optimizer') and app.state.redis_optimizer:
            redis_health = await app.state.redis_optimizer.health_check()
            status["services"]["redis"] = {
                "status": redis_health["status"],
                "response_time_ms": round((time.time() - redis_start) * 1000, 2),
                "pools_healthy": redis_health.get("pools_healthy", 0),
                "latency_ms": redis_health.get("latency_ms"),
                "memory_usage": redis_health.get("memory_usage")
            }
        else:
            # Fallback to legacy client if optimizer not available
            redis_client = await get_redis_client()
            if redis_client is not None:
                await redis_client.ping()
                status["services"]["redis"] = {
                    "status": "healthy",
                    "response_time_ms": round((time.time() - redis_start) * 1000, 2),
                    "note": "using_legacy_client"
                }
            else:
                status["services"]["redis"] = {
                    "status": "not_configured",
                    "response_time_ms": round((time.time() - redis_start) * 1000, 2)
                }
    except Exception as e:
        status["services"]["redis"] = {
            "status": "unhealthy", 
            "error": str(e),
            "response_time_ms": round((time.time() - redis_start) * 1000, 2)
        }
    
    # Check Database
    db_start = time.time()
    try:
        db_result = await test_connection()
        status["services"]["database"] = {
            "status": db_result["status"],
            "response_time_ms": round((time.time() - db_start) * 1000, 2)
        }
        if db_result["status"] != "healthy":
            status["services"]["database"]["error"] = db_result.get("error", "Unknown error")
            status["status"] = "degraded"
    except Exception as e:
        status["services"]["database"] = {
            "status": "unhealthy",
            "error": str(e),
            "response_time_ms": round((time.time() - db_start) * 1000, 2)
        }
        status["status"] = "degraded"
    
    # Add memory health check
    try:
        memory_health = await memory_health_check()
        status["services"]["memory"] = memory_health
    except Exception as e:
        status["services"]["memory"] = {
            "status": "error",
            "error": str(e)
        }
    
    # Overall status
    total_time = round((time.time() - start_time) * 1000, 2)
    status["total_response_time_ms"] = total_time
    
    return status

# Simple readiness probe
@app.get("/ready")
async def readiness_check():
    """
    Readiness probe - returns 200 only when the service is ready to handle requests
    """
    try:
        db_result = await test_connection()
        
        if db_result["status"] == "healthy":
            return {
                "status": "ready", 
                "timestamp": utc_now_iso()
            }
        else:
            from fastapi import HTTPException
            raise HTTPException(
                status_code=503, 
                detail=f"Service not ready - database {db_result['status']}: {db_result.get('error', 'Unknown error')}"
            )
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail=f"Service not ready: {str(e)}")

# Liveness probe for Render  
@app.get("/live")
async def liveness_check():
    """
    Liveness probe - returns 200 if the service is alive
    """
    return {"status": "alive", "timestamp": utc_now_iso()}

# Simple performance monitoring
@app.get("/monitoring/performance")
async def performance_monitoring():
    """
    Simple performance monitoring endpoint
    """
    try:
        performance_data = get_performance_summary()
        performance_data["timestamp"] = utc_now_iso()
        return performance_data
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"Performance monitoring unavailable: {str(e)}")

# Hot reload test endpoint - NEW!
@app.get("/test/hot-reload")
async def test_hot_reload():
    """Test endpoint to verify hot reload functionality"""
    return {
        "message": "Hot reload test endpoint created successfully!",
        "timestamp": utc_now_iso(),
        "status": "working"
    }

# CLI-specific health check endpoint
@app.get("/health/cli")
async def cli_health_check():
    """
    CLI-specific health check for CLI scan services
    """
    try:
        from cli_scan.error_monitoring import create_health_check_endpoint
        return await create_health_check_endpoint()
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": utc_now_iso()
        }

# Simple database health check
@app.get("/health/database")
async def database_health_check():
    """
    Simple database health check
    """
    try:
        result = await test_connection()
        result["timestamp"] = utc_now_iso()
        return result
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "timestamp": utc_now_iso()
        }

if __name__ == "__main__":
    import uvicorn
    
    # Get configuration from environment
    port = int(os.getenv('PORT', 8010))  # Keep 8010 as default for local development
    host = os.getenv('HOST', '0.0.0.0')
    
    # Set production environment if PORT is specified by the platform (typical for GCP Cloud Run)
    if os.getenv('PORT') and not os.getenv('APP_ENV'):
        os.environ['APP_ENV'] = 'production'
        os.environ['TESTING_MODE'] = 'false'
        logger.info(f"Production mode auto-detected via Cloud Run PORT environment variable: {port}")
    
    # Environment-specific uvicorn configuration
    if is_production_environment():
        logger.info(f"Starting DevSecureX Backend in production mode on {host}:{port}")
        uvicorn.run(
            app,
            host=host,
            port=port,
            workers=1,  # Single worker for memory efficiency
            loop="auto",
            http="auto",
            access_log=False,  # Reduce log noise in production
            log_level="info",
            reload=False,  # Explicitly disable reload in production
            # Extended timeouts for long-running operations (scans can take 10-15 minutes)
            timeout_keep_alive=120,        # Keep connections alive for 2 minutes
            timeout_graceful_shutdown=60,  # Allow 1 minute for graceful shutdown
            # Limit concurrent connections to prevent resource exhaustion
            limit_concurrency=int(os.getenv('UVICORN_LIMIT_CONCURRENCY', '100')),
            # Enable backlog for handling connection spikes
            backlog=2048
        )
    elif is_development_environment():
        logger.info(f"Starting DevSecureX Backend in development mode with hot reload on {host}:{port}")
        # Development server with hot reload enabled
        reload_enabled = os.getenv('UVICORN_RELOAD', 'true').lower() == 'true'
        reload_dirs = ['/app'] if reload_enabled else None
        reload_excludes = ['__pycache__', '.pytest_cache', '.git', '*.pyc', '*.pyo'] if reload_enabled else None
        
        uvicorn.run(
            "main:app",  # Use import string for reload to work
            host=host,
            port=port,
            reload=reload_enabled,
            reload_dirs=reload_dirs,
            reload_excludes=reload_excludes,
            log_level=os.getenv('LOG_LEVEL', 'DEBUG').lower(),
            timeout_keep_alive=120,  # Keep connections alive for 2 minutes
            limit_concurrency=int(os.getenv('UVICORN_LIMIT_CONCURRENCY', '50'))  # Lower for development
        )
    else:
        # Fallback configuration
        logger.info(f"Starting DevSecureX Backend in default mode on {host}:{port}")
        uvicorn.run(
            app, 
            host=host, 
            port=port,
            timeout_keep_alive=120,
            limit_concurrency=int(os.getenv('UVICORN_LIMIT_CONCURRENCY', '50'))
        )