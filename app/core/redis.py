import os
import logging
import asyncio
import time
import redis.asyncio as redis
from redis.exceptions import ConnectionError, TimeoutError

logger = logging.getLogger(__name__)

def get_redis_url():
    """Get Redis URL based on environment"""
    # Always return Redis URL, let individual components decide usage
    return os.getenv("REDIS_URL") or os.getenv("LOCAL_REDIS_URL", "redis://devsecurex-redis:6379")

def create_redis_client():
    """Create Redis client with production-grade settings"""
    redis_url = get_redis_url()
    
    if not redis_url:
        logger.error("No Redis URL configured")
        return None
    
    try:
        # PRODUCTION FIX: Enhanced connection settings for production stability
        base_config = {
            "decode_responses": True,
            "socket_connect_timeout": 60,  # Increased for production networks
            "socket_timeout": 120,  # Increased for long-running operations
            "socket_keepalive": True,
            "socket_keepalive_options": {},
            "retry_on_timeout": True,
            "retry_on_error": [ConnectionError, TimeoutError],
            "max_connections": 50,  # Increased pool size for production
            "health_check_interval": 0,  # Disable automatic health checks to prevent connection churn
        }
        
        # Production environment detection
        is_production = os.getenv("APP_ENV", "development").lower() == "production"
        
        if redis_url.startswith('rediss://'):
            # Production Redis with SSL
            if is_production:
                # Additional production SSL settings
                base_config.update({
                    "socket_connect_timeout": 90,  # Allow more time for SSL handshake
                    "connection_pool_kwargs": {
                        "ssl_check_hostname": False,  # For managed Redis services
                        "ssl_cert_reqs": None,
                    }
                })
            
            client = redis.from_url(redis_url, **base_config)
            
        else:
            # Development Redis without SSL
            if not is_production:
                # Development-specific optimizations
                base_config.update({
                    "socket_connect_timeout": 30,
                    "socket_timeout": 60,
                    "max_connections": 20
                })
            
            client = redis.from_url(redis_url, **base_config)
        
        logger.info(f"Redis client created (production: {is_production}, max_connections: {base_config['max_connections']})")
        return client
        
    except Exception as e:
        logger.error(f"Failed to create Redis client: {e}")
        return None

# Import optimized pool manager
try:
    from .redis_pool_manager import get_optimized_redis_client, close_redis_pool
    USE_POOL_MANAGER = True
except ImportError:
    logger.warning("Redis pool manager not available, using legacy implementation")
    USE_POOL_MANAGER = False

# CRITICAL FIX: Enhanced Redis client management with production-grade settings
_redis_client = None
_client_creation_time = None
_client_usage_count = 0
# PRODUCTION FIX: Increased client age for production stability
_max_client_age = 14400  # 4 hours max client age for production
_client_lock = asyncio.Lock()
_reconnection_attempts = 0
_max_reconnection_attempts = 5
_reconnection_backoff = 2  # seconds

async def get_redis_client():
    """Get the Redis client instance with connection health check and circuit breaker protection"""
    # Use optimized pool manager if available
    if USE_POOL_MANAGER:
        return await get_optimized_redis_client()
    
    # CRITICAL FIX: Use circuit breaker for Redis operations
    try:
        from core.circuit_breaker import get_circuit_breaker_enforcer
        enforcer = get_circuit_breaker_enforcer()
        
        async def _get_client_internal():
            return await _get_redis_client_internal()
        
        return await enforcer.enforce_redis_operation(_get_client_internal)
    except ImportError:
        # Fallback if circuit breaker not available
        logger.warning("Circuit breaker not available, using direct Redis connection")
        return await _get_redis_client_internal()
    except Exception as e:
        logger.warning(f"Redis client access failed through circuit breaker: {e}")
        return None

async def _get_redis_client_internal():
    """Internal Redis client management with production-grade connection tracking"""
    global _redis_client, _client_creation_time, _client_usage_count, _reconnection_attempts
    
    async with _client_lock:
        current_time = time.time()
        
        # Check if client needs recreation (age-based or missing)
        needs_recreation = (
            _redis_client is None or
            _client_creation_time is None or
            (current_time - _client_creation_time) > _max_client_age
        )
        
        if not needs_recreation:
            # PRODUCTION FIX: Enhanced health check with production timeouts
            try:
                # Use longer timeout for production networks
                is_production = os.getenv("APP_ENV", "development").lower() == "production"
                ping_timeout = 2.0 if is_production else 0.5
                
                await asyncio.wait_for(_redis_client.ping(), timeout=ping_timeout)
                _client_usage_count += 1
                _reconnection_attempts = 0  # Reset on successful connection
                
                # Log usage statistics for production monitoring
                if _client_usage_count % 500 == 0:  # Less frequent logging in production
                    age = current_time - _client_creation_time
                    logger.info(f"Redis client healthy - used {_client_usage_count} times (age: {age:.1f}s)")
                
                return _redis_client
                
            except (ConnectionError, TimeoutError, OSError) as e:
                logger.warning(f"Redis connection unhealthy, recreating: {e}")
                needs_recreation = True
                _reconnection_attempts += 1
                
            except AttributeError as e:
                # Handle parser attribute errors specifically
                if "_connected" in str(e) or "parser" in str(e).lower():
                    logger.error(f"Redis parser error detected, forcing reconnection: {e}")
                    needs_recreation = True
                    _reconnection_attempts += 1
                else:
                    logger.error(f"Unexpected attribute error: {e}")
                    raise
                    
            except Exception as e:
                logger.error(f"Unexpected Redis health check error: {e}")
                needs_recreation = True
                _reconnection_attempts += 1
        
        if needs_recreation:
            # PRODUCTION FIX: Circuit breaker for excessive reconnection attempts
            if _reconnection_attempts >= _max_reconnection_attempts:
                backoff_time = _reconnection_backoff * (2 ** min(_reconnection_attempts - _max_reconnection_attempts, 4))
                logger.error(f"Too many Redis reconnection attempts ({_reconnection_attempts}), backing off for {backoff_time}s")
                await asyncio.sleep(backoff_time)
                # Reset attempts after backoff to allow retry
                if _reconnection_attempts >= _max_reconnection_attempts + 3:
                    _reconnection_attempts = 0
                    logger.info("Resetting Redis reconnection attempts after extended backoff")
            
            # Close old connection safely
            if _redis_client:
                try:
                    # PRODUCTION FIX: Longer timeout for production cleanup
                    close_timeout = 5.0 if os.getenv("APP_ENV", "development").lower() == "production" else 2.0
                    await asyncio.wait_for(_redis_client.aclose(), timeout=close_timeout)
                    logger.debug("Old Redis client closed successfully")
                except asyncio.TimeoutError:
                    logger.warning("Timeout closing old Redis client")
                except Exception as close_error:
                    logger.warning(f"Error closing old Redis client: {close_error}")
            
            # Create new connection with backoff
            try:
                if _reconnection_attempts > 0:
                    backoff_delay = min(_reconnection_backoff * _reconnection_attempts, 30)  # Max 30s delay
                    logger.info(f"Waiting {backoff_delay}s before Redis reconnection attempt {_reconnection_attempts}")
                    await asyncio.sleep(backoff_delay)
                
                _redis_client = create_redis_client()
                _client_creation_time = current_time
                _client_usage_count = 0
                
                if _redis_client:
                    logger.info(f"New Redis client created successfully (attempt {_reconnection_attempts + 1})")
                    _reconnection_attempts = 0  # Reset on successful creation
                    return _redis_client
                else:
                    logger.error("Failed to create Redis client")
                    _reconnection_attempts += 1
                    return None
            except Exception as create_error:
                logger.error(f"Error creating new Redis client: {create_error}")
                _redis_client = None
                _client_creation_time = None
                _reconnection_attempts += 1
                return None
        
        return _redis_client

async def close_redis_client():
    """Close the Redis client connection with event loop protection"""
    # Use optimized pool manager if available
    if USE_POOL_MANAGER:
        await close_redis_pool()
        return
    
    # CRITICAL FIX: Enhanced client cleanup with connection tracking
    global _redis_client, _client_creation_time, _client_usage_count
    
    async with _client_lock:
        if _redis_client:
            try:
                # Log final usage statistics
                if _client_creation_time:
                    age = time.time() - _client_creation_time
                    logger.info(f"Closing Redis client (age: {age:.1f}s, usage: {_client_usage_count} times)")
                
                # Check if event loop is still available
                try:
                    loop = asyncio.get_running_loop()
                    if loop and not loop.is_closed():
                        await asyncio.wait_for(_redis_client.aclose(), timeout=5.0)
                        logger.debug("Redis client closed successfully")
                    else:
                        # Event loop is closed, skip async close
                        logger.info("Redis client close skipped - event loop closed")
                except RuntimeError:
                    # No event loop, skip async operations
                    logger.info("Redis client close skipped - no event loop")
            except asyncio.TimeoutError:
                logger.warning("Timeout closing Redis client")
            except Exception as e:
                logger.warning(f"Redis client close error: {e}")
            finally:
                _redis_client = None
                _client_creation_time = None
                _client_usage_count = 0

def get_redis_client_sync():
    """Create synchronous Redis client with production-grade settings"""
    import redis
    
    redis_url = get_redis_url()
    if not redis_url:
        logger.error("No Redis URL configured for sync client")
        return None
    
    try:
        # PRODUCTION FIX: Enhanced sync client settings
        is_production = os.getenv("APP_ENV", "development").lower() == "production"
        
        base_config = {
            "decode_responses": True,
            "socket_connect_timeout": 60 if is_production else 30,
            "socket_timeout": 120 if is_production else 60,
            "socket_keepalive": True,
            "retry_on_timeout": True,
            "max_connections": 30 if is_production else 20,
            "health_check_interval": 0  # Disable for sync client too
        }
        
        if redis_url.startswith('rediss://'):
            # Production Redis with SSL
            if is_production:
                base_config.update({
                    "socket_connect_timeout": 90,
                    "ssl_check_hostname": False,
                    "ssl_cert_reqs": None
                })
            
            client = redis.from_url(redis_url, **base_config)
        else:
            # Development Redis without SSL
            client = redis.from_url(redis_url, **base_config)
        
        logger.info(f"Synchronous Redis client created (production: {is_production})")
        return client
        
    except Exception as e:
        logger.error(f"Failed to create synchronous Redis client: {e}")
        return None

def get_redis_client_stats():
    """CRITICAL FIX: Get Redis client statistics for monitoring"""
    global _client_creation_time, _client_usage_count
    
    if _client_creation_time:
        age = time.time() - _client_creation_time
        return {
            "client_age_seconds": age,
            "usage_count": _client_usage_count,
            "max_age_seconds": _max_client_age,
            "client_exists": _redis_client is not None
        }
    else:
        return {
            "client_age_seconds": 0,
            "usage_count": 0,
            "max_age_seconds": _max_client_age,
            "client_exists": _redis_client is not None
        }
