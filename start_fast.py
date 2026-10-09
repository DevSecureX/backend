#!/usr/bin/env python3
"""
Fast startup entrypoint for Cloud Run deployment
Binds to port immediately for health checks, initializes services in background
"""
import os
import sys
import asyncio
import logging
from pathlib import Path

# Add the app directory to Python path
app_dir = Path(__file__).parent / "app"
if str(app_dir) not in sys.path:
    sys.path.insert(0, str(app_dir))

# Configure production logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_minimal_app():
    """Create a minimal FastAPI app that binds quickly but includes all routes"""
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from core.utils import utc_now_iso
    
    # Create app with full route registration
    app = FastAPI(
        title="DevSecureX Backend",
        description="Security scanning and automation platform", 
        version="1.0.0",
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Load CORS origins from environment variable with Firebase and production domains
    default_origins = [
        # Local development
        "http://localhost:5173", "http://localhost:5174", "http://localhost:5175", 
        "http://localhost:5176", "http://localhost:5177", "http://localhost:8080",
        "http://localhost:3000",
        # Production domains
        "https://www.devsecurex.com", "https://devsecurex.com",
        "https://app.devsecurex.com",
        "https://your-frontend-domain.com"
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

    # Add CORS Middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )
    
    # Include ALL API routers IMMEDIATELY during app creation
    # This ensures they appear in OpenAPI spec and are available right away
    try:
        logger.info("🔄 Loading all API routes during app creation...")
        
        # Import all route handlers
        from auth.routes import auth_router
        from repos.routes import repos_router
        from scans.routes import scans_router
        from custom_rules.routes import rules_router
        from ai_assistant.routes import ai_router
        from analytics.routes import router as analytics_router
        from issues.routes import issues_router
        from support.simple_routes import router as support_router
        from cli_scan.routes import cli_scan_router
        from monitoring.database_routes import router as database_monitoring_router
        from monitoring.task_system_routes import router as task_system_monitoring_router
        from monitoring.monitoring_routes import router as monitoring_router
        from monitoring.unified_queue_monitoring import router as unified_queue_monitoring_router
        
        # Import enterprise routers
        # from scans.enterprise_scan_routes import enterprise_router  # Module doesn't exist - commented out
        from monitoring.monitoring_api import monitoring_api_router
        
        # Add all routers (routes already have their own prefixes defined)
        app.include_router(auth_router)
        app.include_router(repos_router)
        app.include_router(scans_router)
        app.include_router(rules_router)
        app.include_router(ai_router)
        app.include_router(analytics_router)
        app.include_router(issues_router)
        app.include_router(support_router)
        app.include_router(cli_scan_router)
        app.include_router(database_monitoring_router)
        app.include_router(task_system_monitoring_router)
        app.include_router(monitoring_router)
        app.include_router(unified_queue_monitoring_router)
        
        # Include enterprise routers
        # app.include_router(enterprise_router)  # Module doesn't exist - commented out
        app.include_router(monitoring_api_router)
        
        # Mount Socket.IO app for AI assistant
        try:
            from ai_assistant.socket_manager import ai_socket_manager
            socket_app = ai_socket_manager.get_asgi_app()
            app.mount("/socket.io", socket_app)
            logger.info("✅ Socket.IO mounted successfully")
        except Exception as e:
            logger.warning(f"Failed to mount Socket.IO: {e}")
        
        logger.info("✅ All API routes loaded successfully during app creation")
        
    except Exception as e:
        logger.error(f"❌ Failed to load routes during app creation: {e}")
        # Don't crash - let the app start with basic routes and handle errors gracefully
    
    # Essential health check endpoint - override any route conflicts
    @app.get("/health")
    async def health_check():
        """Immediate health check for Cloud Run with worker status"""
        initialization_complete = getattr(app.state, 'initialization_complete', False)
        initialization_error = getattr(app.state, 'initialization_error', None)
        
        # Check worker status
        worker_status = "unknown"
        worker_count = 0
        autofix_status = "unknown"
        
        if hasattr(app.state, 'enterprise_systems') and app.state.enterprise_systems:
            try:
                scanning_workers = app.state.enterprise_systems.get('scanning_workers')
                if scanning_workers and hasattr(scanning_workers, 'get_worker_count'):
                    worker_count = scanning_workers.get_worker_count()
                    worker_status = "enterprise_active" if worker_count > 0 else "enterprise_idle"
            except Exception as e:
                worker_status = f"enterprise_error: {str(e)}"
        
        # Check autofix worker status (on-demand system)
        if hasattr(app.state, 'on_demand_autofix_manager'):
            try:
                autofix_manager = app.state.on_demand_autofix_manager
                autofix_status_info = autofix_manager.get_status()
                autofix_status = autofix_status_info.get("status", "unknown")
            except Exception as e:
                autofix_status = f"error: {str(e)}"
        elif hasattr(app.state, 'autofix_workers_enabled'):
            autofix_status = "disabled" if not app.state.autofix_workers_enabled else "not_initialized"
        
        # Always return 200 for Cloud Run health checks
        response = {
            "status": "ok",
            "timestamp": utc_now_iso(),
            "environment": os.getenv("APP_ENV", "unknown"),
            "version": "1.0.0",
            "initialization": {
                "complete": initialization_complete,
                "error": initialization_error
            },
            "workers": {
                "scan_workers": {
                    "status": worker_status,
                    "count": worker_count
                },
                "autofix_workers": {
                    "status": autofix_status,
                    "type": "on_demand"
                }
            },
            "server": "ready"
        }
        return response
    
    @app.get("/")
    async def root():
        """Root endpoint"""
        return {"message": "DevSecureX Backend API", "status": "running"}
    
    @app.get("/ready")
    async def ready_check():
        """Readiness check for load balancers"""
        initialization_complete = getattr(app.state, 'initialization_complete', False)
        initialization_error = getattr(app.state, 'initialization_error', None)
        
        # Include detailed readiness info for debugging
        worker_info = {
            "scan_workers": {},
            "autofix_workers": {}
        }
        
        if hasattr(app.state, 'enterprise_systems') and app.state.enterprise_systems:
            try:
                scanning_workers = app.state.enterprise_systems.get('scanning_workers')
                if scanning_workers:
                    worker_info["scan_workers"] = {
                        "type": "enterprise",
                        "count": getattr(scanning_workers, 'get_worker_count', lambda: 0)(),
                        "active": True
                    }
            except Exception as e:
                worker_info["scan_workers"] = {
                    "type": "enterprise", 
                    "error": str(e),
                    "active": False
                }
        
        # Add autofix worker info
        if hasattr(app.state, 'on_demand_autofix_manager'):
            try:
                autofix_manager = app.state.on_demand_autofix_manager
                autofix_status_info = autofix_manager.get_status()
                worker_info["autofix_workers"] = {
                    "type": "on_demand",
                    "status": autofix_status_info.get("status", "unknown"),
                    "enabled": autofix_status_info.get("enabled", False),
                    "active": autofix_status_info.get("workers_active", False)
                }
            except Exception as e:
                worker_info["autofix_workers"] = {
                    "type": "on_demand",
                    "error": str(e),
                    "active": False
                }
        elif hasattr(app.state, 'autofix_workers_enabled'):
            worker_info["autofix_workers"] = {
                "type": "on_demand",
                "enabled": app.state.autofix_workers_enabled,
                "status": "disabled" if not app.state.autofix_workers_enabled else "not_initialized"
            }
        
        return {
            "ready": initialization_complete and not initialization_error,
            "timestamp": utc_now_iso(),
            "version": "1.0.0",
            "initialization": {
                "complete": initialization_complete,
                "error": initialization_error
            },
            "workers": worker_info
        }
    
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
    
    # Initialize app state
    app.state.initialization_complete = False
    app.state.initialization_error = None
    
    return app

async def background_initialization(app):
    """Initialize heavy services in background after port is bound"""
    try:
        logger.info("🔄 Starting background initialization...")
        
        # Simple initialization without complex lifespan management
        # Import models for SQLAlchemy registration
        try:
            import auth.models  # noqa: F401
            import repos.models  # noqa: F401
            import scans.models  # noqa: F401
            import custom_rules.models  # noqa: F401
            import ai_assistant.models  # noqa: F401
            import support.models  # noqa: F401
            import cli_scan.models  # noqa: F401
            
            from sqlalchemy.orm import configure_mappers
            configure_mappers()
            logger.info("✅ Models registered successfully")
        except Exception as e:
            logger.warning(f"Model registration failed: {e}")
        
        # Database connection and table creation
        try:
            from core.database import test_connection, create_tables, Base
            logger.info("Testing database connection...")
            await test_connection()
            logger.info("✅ Database connection successful")
            
            logger.info(f"Models imported: {len(Base.metadata.tables)} tables registered")
            
            # Create database tables
            logger.info("Creating database tables...")
            await create_tables()
            logger.info("✅ Database tables created/verified successfully")
        except Exception as e:
            logger.error(f"❌ Database connection/setup failed: {e}")
            # Continue anyway - let the application handle DB errors gracefully
        
        # Initialize Redis if available
        try:
            from core.redis_optimized import initialize_redis_optimizer
            redis_optimizer = await initialize_redis_optimizer()
            if redis_optimizer and redis_optimizer.enabled:
                app.state.redis_optimizer = redis_optimizer
                logger.info("✅ Redis optimizer initialized")
            else:
                app.state.redis_optimizer = None
                logger.info("Redis optimizer not available")
        except Exception as e:
            logger.warning(f"Redis initialization failed: {e}")
            app.state.redis_optimizer = None
        
        # Initialize rate limiter
        try:
            from core.rate_limiting import init_rate_limiter
            await init_rate_limiter()
            logger.info("✅ Rate limiter initialized")
        except Exception as e:
            logger.warning(f"Rate limiter initialization failed: {e}")
        
        # CRITICAL FIX: Initialize worker systems based on environment configuration
        # Priority: Fortress → Enterprise → Legacy
        app_env = os.getenv("APP_ENV", "development").lower()
        enable_workers = os.getenv("ENABLE_BACKGROUND_WORKERS", "true").lower() == "true"
        use_enterprise = os.getenv("USE_ENTERPRISE_QUEUES", "false").lower() == "true"
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
                
                logger.info("🎉 Fortress-grade queue systems are ready!")
                worker_system_started = True
                
            except Exception as e:
                logger.error(f"Failed to initialize fortress systems: {e}")
                logger.info("Falling back to enterprise queue systems...")
        
        # Try enterprise systems if fortress not enabled or failed
        if not worker_system_started and use_enterprise:
            try:
                logger.info("🔄 Initializing enterprise queue systems...")
                
                # Initialize ALL enterprise queue systems (same as main.py)
                from scans.queue.enterprise_queue_manager import get_enterprise_queue_manager
                from scans.workers.enterprise_worker_manager import get_enterprise_worker_manager
                from scans.autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
                from scans.webhooks.enterprise_webhook_queue import get_enterprise_webhook_queue_manager
                from scans.webhooks.enterprise_webhook_worker_manager import get_enterprise_webhook_worker_manager
                from core.task_system.enterprise_task_queue_manager import get_enterprise_task_queue_manager
                from monitoring.enterprise_monitoring import get_enterprise_monitoring
                
                # 1. Initialize main scanning system
                logger.info("Initializing enterprise scanning queue system...")
                scanning_queue_manager = await get_enterprise_queue_manager()
                scanning_worker_manager = await get_enterprise_worker_manager()
                logger.info("✅ Enterprise scanning system initialized")
                
                # 2. Initialize simple autofix queue system (restored from prod-release)
                logger.info("Initializing simple autofix queue system...")
                from scans.autofix_queue.manager import AutofixQueueManager
                autofix_queue_manager = AutofixQueueManager()
                logger.info("✅ Simple autofix queue system initialized (prod-release compatibility)")
                logger.info("🎯 Autofix UX restored: 11-stage progress tracking, complete data structure, seamless frontend integration")
                
                # 3. Initialize webhook queue system
                logger.info("Initializing enterprise webhook queue system...")
                webhook_queue_manager = await get_enterprise_webhook_queue_manager()
                webhook_worker_manager = await get_enterprise_webhook_worker_manager()
                logger.info("✅ Enterprise webhook system initialized")
                
                # 4. Initialize unified task queue system
                logger.info("Initializing unified enterprise task system...")
                task_queue_manager = await get_enterprise_task_queue_manager()
                logger.info("✅ Unified enterprise task system initialized")
                
                # 5. Initialize enterprise monitoring
                logger.info("Initializing enterprise monitoring system...")
                monitoring = await get_enterprise_monitoring()
                logger.info("✅ Enterprise monitoring system initialized")
                
                # 6. PHASE 3: Initialize event-driven monitoring system
                logger.info("🎯 PHASE 3: Initializing event-driven monitoring system...")
                try:
                    from monitoring.event_driven_monitoring import start_event_driven_monitoring, get_event_driven_monitoring
                    
                    # Start the event-driven monitoring system
                    event_monitoring_task = asyncio.create_task(start_event_driven_monitoring())
                    
                    # Store reference for health checks
                    app.state.event_monitoring = get_event_driven_monitoring()
                    logger.info("✅ PHASE 3: Event-driven monitoring system initialized")
                    logger.info("📊 PHASE 3: Extended intervals - Health:5min, Resources:3min, DB:10min, Redis:30min")
                    
                except Exception as e:
                    logger.error(f"❌ PHASE 3: Failed to initialize event-driven monitoring: {e}")
                    app.state.event_monitoring = None
                
                # Store references in app state for health checks
                app.state.enterprise_systems = {
                    "scanning_queue": scanning_queue_manager,
                    "scanning_workers": scanning_worker_manager,
                    "autofix_queue": autofix_queue_manager,
                    "autofix_workers_enabled": True,  # Workers will start on-demand
                    "webhook_queue": webhook_queue_manager,
                    "webhook_workers": webhook_worker_manager,
                    "unified_tasks": task_queue_manager,
                    "monitoring": monitoring
                }
                
                logger.info("🎉 ALL enterprise-grade queue systems are ready!")
                logger.info("📊 Features enabled: Auto-scaling, Circuit breakers, Resource monitoring")
                worker_system_started = True
                
            except Exception as e:
                logger.error(f"Failed to initialize enterprise systems: {e}")
                logger.info("Falling back to legacy worker system...")
        
        # Fallback to legacy workers if fortress and enterprise not enabled or failed
        if not worker_system_started and enable_workers:
            try:
                from scans.workers.manager import start_background_workers
                await start_background_workers()
                logger.info("✅ Legacy background scan workers started")
                worker_system_started = True
            except Exception as e:
                logger.warning(f"Failed to start legacy background workers: {e}")
        
        if not worker_system_started:
            logger.warning("⚠️  NO WORKER SYSTEM STARTED - Scans will be processed synchronously")
            logger.info(f"To enable workers: Set ENABLE_BACKGROUND_WORKERS=true (current: {enable_workers})")
            logger.info(f"For fortress: Set USE_FORTRESS_QUEUES=true (current: {use_fortress})")
            logger.info(f"For enterprise: Set USE_ENTERPRISE_QUEUES=true (current: {use_enterprise})")
            logger.info(f"Environment: {app_env}")
            app.state.initialization_error = "No worker system started - scans will be processed synchronously"
        
        # CRITICAL FIX: Start autofix workers proactively during startup instead of on-demand
        try:
            from scans.autofix_queue.on_demand_manager import get_on_demand_autofix_manager, ensure_autofix_workers_available
            app.state.autofix_workers_enabled = os.getenv("ENABLE_AUTOFIX_WORKERS", "true").lower() == "true"
            app.state.autofix_workers_started = False
            
            if app.state.autofix_workers_enabled:
                # Initialize the on-demand manager
                on_demand_manager = get_on_demand_autofix_manager()
                app.state.on_demand_autofix_manager = on_demand_manager
                
                # CRITICAL FIX: Proactively start autofix workers during application startup
                logger.info("🔧 Starting autofix workers proactively during application startup...")
                workers_ready = await ensure_autofix_workers_available("startup_proactive")
                
                if workers_ready:
                    app.state.autofix_workers_started = True
                    logger.info("✅ Autofix workers started successfully during application startup")
                else:
                    logger.warning("⚠️  Autofix workers failed to start during startup - will retry on-demand")
                    app.state.autofix_workers_started = False
            else:
                logger.info("Autofix workers disabled via configuration")
        except Exception as e:
            logger.error(f"Failed to initialize autofix system: {e}")
            app.state.autofix_workers_enabled = False
            app.state.autofix_workers_started = False
        
        # Routes are already added during app creation
        # No need to add them again here
        logger.info("Routes already loaded during app creation")
        
        logger.info("✅ Background initialization completed")
        app.state.initialization_complete = True
            
    except Exception as e:
        logger.error(f"❌ Background initialization failed: {e}")
        app.state.initialization_error = str(e)

# Route loading function removed - routes are now loaded during app creation
# This ensures they're available immediately and included in OpenAPI spec

def main():
    """Main fast startup entrypoint"""
    logger.info("🚀 Starting DevSecureX Backend (Fast Cloud Run mode)...")
    
    # Create minimal app that can respond to health checks immediately
    app = create_minimal_app()
    
    # Get configuration from environment
    port = int(os.getenv('PORT', 8080))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"⚡ Starting server on {host}:{port} (Fast startup mode)")
    
    # Create background initialization task
    async def start_background_init():
        """Start background initialization after server is ready"""
        logger.info("🔄 Server started, beginning background initialization...")
        try:
            # Give the server a moment to fully bind to the port
            await asyncio.sleep(0.1)
            await background_initialization(app)
        except Exception as e:
            logger.error(f"❌ Failed to complete background initialization: {e}")
            app.state.initialization_error = str(e)
    
    # Store the initialization task for later execution
    app.state.background_init_task = start_background_init
    
    # Import uvicorn
    import uvicorn
    
    # Create a custom server to handle background initialization and graceful shutdown
    class FastStartupServer(uvicorn.Server):
        async def startup(self, sockets=None):
            """Override startup to trigger background initialization"""
            # Call parent startup first
            await super().startup(sockets)
            
            # Trigger background initialization after server is ready
            if hasattr(self.config.app.state, 'background_init_task'):
                asyncio.create_task(self.config.app.state.background_init_task())
        
        async def shutdown(self, sockets=None):
            """Override shutdown to gracefully stop workers"""
            logger.info("🔄 Gracefully shutting down workers...")
            
            try:
                # Shutdown fortress systems first (newest system)
                if hasattr(self.config.app.state, 'fortress_systems') and self.config.app.state.fortress_systems:
                    try:
                        from scans.queue.fortress_queue_manager import shutdown_fortress_queue_manager
                        from scans.workers.fortress_worker_manager import shutdown_fortress_worker_manager
                        
                        logger.info("🏰 Shutting down fortress queue systems...")
                        
                        # Shutdown fortress systems
                        fortress_shutdown_tasks = [
                            shutdown_fortress_worker_manager(),
                            shutdown_fortress_queue_manager()
                        ]
                        
                        await asyncio.gather(*fortress_shutdown_tasks, return_exceptions=True)
                        logger.info("✅ All fortress systems stopped")
                        
                    except Exception as e:
                        logger.warning(f"Error shutting down fortress systems: {e}")
                
                # Shutdown enterprise systems if they exist
                if hasattr(self.config.app.state, 'enterprise_systems') and self.config.app.state.enterprise_systems:
                    from scans.queue.enterprise_queue_manager import shutdown_enterprise_queue_manager
                    from scans.workers.enterprise_worker_manager import shutdown_enterprise_worker_manager
                    # Simple autofix queue doesn't need shutdown (no persistent resources)
                    from scans.webhooks.enterprise_webhook_queue import shutdown_enterprise_webhook_queue_manager
                    from scans.webhooks.enterprise_webhook_worker_manager import shutdown_enterprise_webhook_worker_manager
                    from core.task_system.enterprise_task_queue_manager import shutdown_enterprise_task_queue_manager
                    from monitoring.enterprise_monitoring import shutdown_enterprise_monitoring
                    
                    # Shutdown in parallel for speed
                    shutdown_tasks = [
                        shutdown_enterprise_monitoring(),
                        shutdown_enterprise_worker_manager(),
                        shutdown_enterprise_webhook_worker_manager(),
                        shutdown_enterprise_queue_manager(),
                        # Simple autofix queue shutdown not needed
                        shutdown_enterprise_webhook_queue_manager(),
                        shutdown_enterprise_task_queue_manager()
                    ]
                    
                    await asyncio.gather(*shutdown_tasks, return_exceptions=True)
                    logger.info("✅ Enterprise systems shutdown complete")
                    
                    # Note: Autofix workers use on-demand system and will shut down automatically if running
                
                # PHASE 3: Shutdown event-driven monitoring
                if hasattr(self.config.app.state, 'event_monitoring') and self.config.app.state.event_monitoring:
                    try:
                        from monitoring.event_driven_monitoring import stop_event_driven_monitoring
                        await stop_event_driven_monitoring()
                        logger.info("✅ PHASE 3: Event-driven monitoring shutdown complete")
                    except Exception as e:
                        logger.warning(f"PHASE 3: Event monitoring shutdown warning: {e}")
                
                # Shutdown legacy workers as fallback
                try:
                    from scans.workers.manager import stop_background_workers
                    # Note: Basic autofix workers removed - only legacy scan workers shutdown needed
                    
                    await stop_background_workers()
                    logger.info("✅ Legacy workers shutdown complete")
                except Exception as e:
                    logger.warning(f"Legacy worker shutdown warning: {e}")
                
                # Cleanup Redis connections
                try:
                    from core.redis_optimized import close_redis_optimizer
                    from core.redis import close_redis_client
                    
                    await asyncio.gather(
                        close_redis_optimizer(),
                        close_redis_client(),
                        return_exceptions=True
                    )
                    logger.info("✅ Redis connections closed")
                except Exception as e:
                    logger.warning(f"Redis cleanup warning: {e}")
                
            except Exception as e:
                logger.error(f"Error during graceful shutdown: {e}")
            
            # Call parent shutdown
            await super().shutdown(sockets)
    
    # Create server configuration
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        workers=1,
        loop="auto",
        http="auto",
        access_log=False,
        log_level="info",
        timeout_keep_alive=120,
        timeout_graceful_shutdown=60,
        limit_concurrency=int(os.getenv('UVICORN_LIMIT_CONCURRENCY', '100')),
        backlog=2048
    )
    
    # Start server with custom startup behavior
    server = FastStartupServer(config)
    server.run()

if __name__ == "__main__":
    main()