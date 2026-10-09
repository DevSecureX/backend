"""
Production-ready Redis configuration with cost controls
"""
import os
import logging
import redis.asyncio as redis
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Redis operation modes
REDIS_MODE_FULL = "full"  # All features enabled
REDIS_MODE_SCAN_ONLY = "scan_only"  # Only scanning operations
REDIS_MODE_DISABLED = "disabled"  # Completely disabled

def get_redis_mode() -> str:
    """Determine Redis operation mode"""
    # Allow environment variable to control Redis mode
    redis_mode = os.getenv("REDIS_MODE", REDIS_MODE_SCAN_ONLY).lower()
    
    # Force disabled if explicitly set
    if os.getenv("DISABLE_REDIS", "false").lower() == "true":
        return REDIS_MODE_DISABLED
    
    return redis_mode

def should_use_redis(operation_type: str = "general") -> bool:
    """Check if Redis should be used for a specific operation"""
    mode = get_redis_mode()
    
    if mode == REDIS_MODE_DISABLED:
        return False
    
    if mode == REDIS_MODE_FULL:
        return True
    
    if mode == REDIS_MODE_SCAN_ONLY:
        # Only allow scan-related operations
        allowed_operations = ["scan", "queue", "job", "progress"]
        return any(op in operation_type.lower() for op in allowed_operations)
    
    return False

def get_redis_url():
    """Get Redis URL based on environment"""
    # Production uses REDIS_URL, development uses LOCAL_REDIS_URL
    if os.getenv("APP_ENV") == "production":
        return os.getenv("REDIS_URL")
    else:
        return os.getenv("REDIS_URL") or os.getenv("LOCAL_REDIS_URL", "redis://localhost:6379")

def create_redis_client(operation_type: str = "general"):
    """Create Redis client with operation type checking"""
    # Check if this operation should use Redis
    if not should_use_redis(operation_type):
        logger.debug(f"Redis disabled for operation type: {operation_type}")
        return None
    
    redis_url = get_redis_url()
    
    if not redis_url:
        logger.error("No Redis URL configured")
        return None
    
    try:
        # For production Redis (rediss:// URLs), use proper SSL
        if redis_url.startswith('rediss://'):
            # Parse URL to get connection details
            parsed = urlparse(redis_url)
            
            # Create SSL-enabled client
            client = redis.Redis(
                host=parsed.hostname,
                port=parsed.port or 6380,
                password=parsed.password,
                username=parsed.username or 'default',
                ssl=True,
                ssl_cert_reqs=None,  # Upstash doesn't require cert verification
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                health_check_interval=0,  # Disable health checks
                retry_on_timeout=False,
                max_connections=10  # Limit connection pool
            )
        else:
            # Development Redis
            client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                health_check_interval=0,
                max_connections=10
            )
        
        logger.info(f"Redis client created for operation: {operation_type}")
        return client
        
    except Exception as e:
        logger.error(f"Failed to create Redis client: {e}")
        return None

# Singleton instance with lazy loading
_redis_clients = {}

def get_redis_client(operation_type: str = "general"):
    """Get or create Redis client for specific operation type"""
    if operation_type not in _redis_clients:
        _redis_clients[operation_type] = create_redis_client(operation_type)
    return _redis_clients[operation_type]

async def close_all_redis_clients():
    """Close all Redis connections"""
    for operation_type, client in _redis_clients.items():
        if client:
            try:
                await client.close()
                logger.info(f"Closed Redis client for {operation_type}")
            except:
                pass
    _redis_clients.clear()

# Export the controlled functions
__all__ = ['get_redis_client', 'should_use_redis', 'get_redis_mode', 'close_all_redis_clients']