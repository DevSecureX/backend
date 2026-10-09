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

def validate_essential_env_vars() -> bool:
    """Validate essential environment variables for production"""
    essential_vars = [
        'SECRET_KEY',
        'OPENAI_API_KEY', 
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
    
    # REDIS_URL is optional for graceful degradation
    if not os.getenv('REDIS_URL'):
        logger.warning("REDIS_URL not set - Redis caching will be disabled")
    
    logger.info("Essential environment variables validated")
    return True

async def verify_database_connection():
    """Verify database connectivity before starting server"""
    try:
        from core.database import test_connection
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

async def main():
    """Main production entrypoint"""
    logger.info("🚀 Starting DevSecureX Backend for production deployment...")
    
    # Configure production environment
    configure_production_environment()
    
    # Validate environment variables
    if not validate_essential_env_vars():
        sys.exit(1)
    
    # Verify database connection
    if not await verify_database_connection():
        logger.error("Database verification failed - exiting")
        sys.exit(1)
    
    # Import and run the FastAPI app
    import uvicorn
    from main import app
    
    # Get configuration from environment
    port = int(os.getenv('PORT', 8000))
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"Starting server on {host}:{port}")
    
    # Production-optimized uvicorn configuration
    uvicorn.run(
        app,
        host=host,
        port=port,
        workers=1,  # Single worker for memory efficiency on Cloud Run
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

if __name__ == "__main__":
    asyncio.run(main())