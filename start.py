#!/usr/bin/env python3
"""
Production entrypoint for DevSecureX Backend
Optimized for GCP Cloud Build deployment
"""
import os
import sys
import asyncio
import logging
from pathlib import Path

# Add current directory to Python path (Docker context is already /app)
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

# Configure production logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def validate_essential_env_vars() -> bool:
    """Validate essential environment variables for production"""
    essential_vars = [
        'SECRET_KEY',
        'ENCRYPTION_KEY',
        'DATABASE_URL'
    ]
    
    missing_vars = []
    for var in essential_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.error(f"Missing essential environment variables: {', '.join(missing_vars)}")
        return False
    
    # Optional environment variables - log warnings but don't fail
    optional_vars = {
        'REDIS_URL': "Redis caching will be disabled"
    }
    
    for var, message in optional_vars.items():
        if not os.getenv(var):
            logger.warning(f"{var} not set - {message}")
    
    logger.info("Essential environment variables validated")
    return True

async def verify_database_connection():
    """Verify database connectivity before starting server"""
    try:
        # Dynamic import handling for both Docker and production environments
        try:
            # Try Docker container structure first
            from core.database import test_connection
        except ImportError:
            # This shouldn't happen since core should always be available, but adding for safety
            logger.error("Failed to import core.database - database verification skipped")
            return True  # Skip verification rather than fail startup
            
        result = await test_connection()
        if result["status"] == "healthy":
            logger.info("Database connection verified successfully")
            return True
        else:
            logger.error(f"Database connection failed: {result.get('error', 'Unknown error')}")
            return False
    except Exception as e:
        logger.error(f"Database verification error: {e}")
        return False

def configure_production_environment():
    """Configure environment for production deployment"""
    # Set production mode
    os.environ.setdefault('APP_ENV', 'production')
    os.environ.setdefault('TESTING_MODE', 'false')
    
    # Configure logging level
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    logging.getLogger().setLevel(getattr(logging, log_level))
    
    # Suppress noisy loggers in production
    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)
    logging.getLogger('httpx').setLevel(logging.WARNING)
    
    logger.info(f"Production environment configured - LOG_LEVEL: {log_level}")

def main():
    """Main production entrypoint"""
    logger.info("🚀 Starting DevSecureX Backend for production deployment...")
    
    # CRITICAL FIX: Setup production signal handlers
    try:
        from app.core.signal_handlers import setup_production_signal_handlers
        setup_production_signal_handlers("devsecurex-backend")
    except ImportError:
        logger.warning("Signal handlers not available - continuing without graceful shutdown")
    
    # Configure production environment
    configure_production_environment()
    
    # Validate environment variables
    if not validate_essential_env_vars():
        sys.exit(1)
    
    # Verify database connection synchronously
    async def verify_db():
        return await verify_database_connection()
    
    if not asyncio.run(verify_db()):
        logger.error("Database verification failed - exiting")
        sys.exit(1)
    
    # Import and run the FastAPI app
    import uvicorn
    
    # Dynamic import handling for both Docker and production environments
    try:
        # Try Docker container structure first (main.py is in /app/)
        from main import app
        logger.info("FastAPI app imported from main module (Docker environment)")
    except ImportError:
        # Fallback to production structure (main.py is in /app/app/)
        from app.main import app
        logger.info("FastAPI app imported from app.main module (production environment)")
    
    # Get configuration from environment (Cloud Run will override PORT automatically)
    port = int(os.getenv('PORT', 8080))  # Default to 8080 for Cloud Run compatibility
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting server on {host}:{port} (PORT set by Cloud Run: {os.getenv('PORT') is not None})")
    
    # Production-optimized uvicorn configuration using Server (async-compatible)
    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        loop="auto",
        http="auto", 
        access_log=False,  # Reduce log noise
        log_level="info",
        # Extended timeouts for long-running operations
        timeout_keep_alive=120,
        timeout_graceful_shutdown=60,
        # Resource limits
        limit_concurrency=int(os.getenv('UVICORN_LIMIT_CONCURRENCY', '100')),
        backlog=2048
    )
    server = uvicorn.Server(config)
    asyncio.run(server.serve())

if __name__ == "__main__":
    main()