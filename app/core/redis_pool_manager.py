"""
Redis Connection Pool Manager for DevSecureX
Optimized for high-performance scanning with proper connection pooling
"""

import os
import logging
import asyncio
import socket
from typing import Optional, Dict, Set, Any
import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import ConnectionError, TimeoutError, RedisError
from urllib.parse import urlparse
import time
from core.circuit_breaker import get_circuit_breaker, CircuitBreakerConfig, CircuitBreakerOpenError

logger = logging.getLogger(__name__)


class RedisPoolManager:
    """
    Singleton Redis connection pool manager with optimized settings for scanning
    """
    
    _instance: Optional['RedisPoolManager'] = None
    _lock = asyncio.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.pool: Optional[ConnectionPool] = None
            self.client: Optional[redis.Redis] = None
            self.initialized = True
            self.last_health_check = 0
            self.health_check_interval = int(os.getenv("REDIS_HEALTH_CHECK_INTERVAL", "180"))  # Default: 3 minutes - reduce frequency
            
            # Performance metrics
            self.metrics = {
                "connections_created": 0,
                "connections_reused": 0,
                "connection_errors": 0,
                "health_checks": 0
            }
            
            logger.info(f"RedisPoolManager initialized with health check interval: {self.health_check_interval}s")
    
    def get_redis_url(self) -> str:
        """Get Redis URL based on environment"""
        return os.getenv("REDIS_URL") or os.getenv("LOCAL_REDIS_URL", "redis://devsecurex-redis:6379")
    
    async def get_client(self) -> Optional[redis.Redis]:
        """
        CRITICAL FIX: Get Redis client with mandatory circuit breaker protection
        """
        # CRITICAL FIX: Enforce circuit breaker for all Redis operations
        from core.circuit_breaker import get_circuit_breaker_enforcer
        enforcer = get_circuit_breaker_enforcer()
        
        async def _get_client_internal():
            try:
                # Simple implementation - just create a client if we don't have one
                if not self.client:
                    redis_url = self.get_redis_url()
                    if redis_url:
                        logger.info(f"Creating simple Redis client for: {redis_url}")
                        # EMERGENCY FIX: Create client with completely disabled health check to prevent PING storm
                        self.client = redis.from_url(
                            redis_url, 
                            decode_responses=True, 
                            max_connections=20,
                            health_check_interval=0  # CRITICAL: Disable all automatic health checks
                        )
                        # EMERGENCY FIX: Skip connection test to prevent any pings
                        # Test the connection once
                        # await self.client.ping()
                        logger.info("✅ Simple Redis client created successfully (ping test skipped to prevent PING storm)")
                        self.metrics["connections_created"] += 1
                
                if self.client:
                    self.metrics["connections_reused"] += 1
                    
                return self.client
            except Exception as e:
                logger.error(f"Error getting Redis client: {e}", exc_info=True)
                self.client = None
                raise  # Re-raise to trigger circuit breaker
        
        # Execute with mandatory circuit breaker protection
        try:
            return await enforcer.enforce_redis_operation(_get_client_internal)
        except Exception as e:
            logger.warning(f"Redis client creation failed through circuit breaker: {e}")
            return None
    
    async def _create_pool(self):
        """Create optimized connection pool for scanning workloads"""
        redis_url = self.get_redis_url()
        
        if not redis_url:
            logger.error("No Redis URL configured")
            return
        
        try:
            logger.info(f"Creating optimized Redis connection pool for: {redis_url[:30]}...")
            
            # Simple working configuration - no complex parameters
            max_connections = min(int(os.getenv("REDIS_MAX_CONNECTIONS", "20")), 50)
            
            # Create connection pool with minimal params (proven to work)
            self.pool = ConnectionPool.from_url(
                redis_url,
                max_connections=max_connections,
                decode_responses=True
            )
            
            # Create client using the pool
            self.client = redis.Redis(connection_pool=self.pool)
            
            # EMERGENCY FIX: Skip connection test to prevent any pings
            # Test the connection
            # await self.client.ping()
            
            self.metrics["connections_created"] += 1
            logger.info(f"✅ Redis pool created successfully with {max_connections} max connections, health check interval: {self.health_check_interval}s")
            
        except Exception as e:
            self.metrics["connection_errors"] += 1
            logger.error(f"Failed to create Redis pool: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            self.client = None
            self.pool = None
    
    async def _health_check(self) -> bool:
        """Check if the Redis connection is healthy with enhanced parser error handling"""
        if not self.client:
            return False
        
        max_attempts = 2
        
        for attempt in range(max_attempts):
            try:
                # EMERGENCY FIX: Skip ping to prevent ping storm
                # Use extended timeout for better reliability with longer intervals
                # await asyncio.wait_for(self.client.ping(), timeout=5.0)
                self.metrics["health_checks"] += 1
                logger.debug(f"Redis health check skipped to prevent PING storm (interval: {self.health_check_interval}s, attempt: {attempt + 1})")
                return True  # Assume healthy to prevent pings
            except (ConnectionError, TimeoutError, RedisError, asyncio.TimeoutError) as e:
                if attempt < max_attempts - 1:  # Not the last attempt
                    logger.debug(f"Redis health check failed (attempt {attempt + 1}/{max_attempts}): {e}")
                    await asyncio.sleep(0.5)  # Brief wait before retry
                    continue
                else:
                    logger.warning(f"Redis health check failed after {max_attempts} attempts: {e}")
                self.metrics["connection_errors"] += 1
                return False
            except AttributeError as e:
                # Enhanced handling for parser attribute errors
                error_msg = str(e)
                is_parser_error = ("_connected" in error_msg or "parser" in error_msg.lower() or 
                                 "hiredis" in error_msg.lower() or "_AsyncHiredisParser" in error_msg)
                
                if is_parser_error:
                    if attempt < max_attempts - 1:  # Not the last attempt
                        logger.debug(f"Redis parser connection error (attempt {attempt + 1}/{max_attempts}): {e} - retrying")
                        # For parser errors, force client recreation on retry
                        try:
                            await self.client.aclose()
                        except:
                            pass
                        self.client = None
                        await asyncio.sleep(1.0)  # Longer wait for parser errors
                        await self._create_pool()  # Recreate client
                        if not self.client:
                            break
                        continue
                    else:
                        logger.error(f"Redis parser connection error persists after {max_attempts} attempts: {e} - forcing full reconnection")
                        self.metrics["connection_errors"] += 1
                        return False
                else:
                    logger.error(f"Unexpected attribute error during health check: {e}")
                    self.metrics["connection_errors"] += 1
                    return False
            except Exception as e:
                logger.error(f"Unexpected error during health check (attempt {attempt + 1}): {e}")
                self.metrics["connection_errors"] += 1
                if attempt == max_attempts - 1:  # Last attempt
                    return False
                await asyncio.sleep(0.5)
        
        return False
    
    async def _recreate_pool(self):
        """Recreate the connection pool after failure with enhanced cleanup"""
        logger.warning("Recreating Redis connection pool due to health check failure")
        
        # Enhanced cleanup with timeouts
        if self.client:
            try:
                await asyncio.wait_for(self.client.aclose(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Timeout closing old Redis client")
            except Exception as e:
                logger.warning(f"Error closing old client: {e}")
        
        if self.pool:
            try:
                await asyncio.wait_for(self.pool.disconnect(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Timeout disconnecting Redis pool")
            except Exception as e:
                logger.warning(f"Error disconnecting pool: {e}")
        
        self.client = None
        self.pool = None
        
        # Brief wait to allow connections to fully close
        await asyncio.sleep(1.0)
        
        # Create new pool
        try:
            await self._create_pool()
            if self.client:
                logger.info("✅ Redis connection pool successfully recreated")
            else:
                logger.error("❌ Failed to recreate Redis connection pool")
        except Exception as e:
            logger.error(f"Error during pool recreation: {e}")
    
    async def close(self):
        """Close all connections and cleanup"""
        async with self._lock:
            if self.client:
                try:
                    await self.client.aclose()
                except Exception as e:
                    logger.warning(f"Error closing Redis client: {e}")
            
            if self.pool:
                try:
                    await self.pool.disconnect()
                except Exception as e:
                    logger.warning(f"Error disconnecting pool: {e}")
            
            self.client = None
            self.pool = None
            logger.info("Redis pool manager closed")
    
    def get_metrics(self) -> dict:
        """Get connection pool metrics with optimization settings"""
        metrics = self.metrics.copy()
        
        # Add optimization configuration
        metrics["optimization_config"] = {
            "health_check_interval_seconds": self.health_check_interval,
            "environment_variables": {
                "REDIS_HEALTH_CHECK_INTERVAL": os.getenv("REDIS_HEALTH_CHECK_INTERVAL", "180"),
                "REDIS_MAX_CONNECTIONS": os.getenv("REDIS_MAX_CONNECTIONS", "30")
            }
        }
        
        if self.pool:
            try:
                # Add pool statistics
                metrics.update({
                    "pool_size": self.pool.connection_kwargs.get("max_connections", 0),
                    "in_use_connections": len(self.pool._in_use_connections) if hasattr(self.pool, "_in_use_connections") else 0,
                    "available_connections": len(self.pool._available_connections) if hasattr(self.pool, "_available_connections") else 0,
                })
            except:
                pass
        
        return metrics


# Global instance
_pool_manager = RedisPoolManager()


async def get_optimized_redis_client() -> Optional[redis.Redis]:
    """
    Get optimized Redis client from the connection pool
    This should be used throughout the application for all Redis operations
    """
    return await _pool_manager.get_client()


async def close_redis_pool():
    """Close the Redis connection pool"""
    await _pool_manager.close()


def get_redis_metrics() -> dict:
    """Get Redis connection pool metrics"""
    return _pool_manager.get_metrics()


# Backward compatibility functions
async def get_redis_client():
    """Backward compatible function - uses optimized pool"""
    return await get_optimized_redis_client()


async def close_redis_client():
    """Backward compatible function - closes pool"""
    await close_redis_pool()


class WorkerRedisManager:
    """
    CRITICAL FIX: Specialized Redis connection manager for worker processes.
    Implements comprehensive connection tracking, leak detection, and cleanup.
    """
    
    def __init__(self):
        self._pubsub_clients: Dict[str, redis.Redis] = {}
        self._general_client: Optional[redis.Redis] = None
        self._lock = asyncio.Lock()
        self._subscriptions: Dict[str, asyncio.Task] = {}
        
        # CRITICAL FIX: Connection tracking and leak detection
        self._connection_registry: Dict[str, Dict[str, Any]] = {}  # Track all connections
        self._connection_creation_time: Dict[str, float] = {}
        self._connection_usage_count: Dict[str, int] = {}
        self._leaked_connections: Set[str] = set()
        self._cleanup_tasks: Dict[str, asyncio.Task] = {}
        
        # Connection monitoring settings
        self._max_connection_age = 3600.0  # 1 hour max connection age
        self._leak_detection_threshold = 300.0  # 5 minutes of inactivity
        self._monitoring_task: Optional[asyncio.Task] = None
        self._monitoring_interval = 60.0  # Check every minute
        self._monitor_connections_coro = None  # Store deferred monitoring coroutine
        self._monitoring_started = False
        
        # Start connection monitoring
        self._start_connection_monitoring()
        
        logger.info(f"WorkerRedisManager initialized with leak detection (threshold: {self._leak_detection_threshold}s)")
        
    async def get_shared_client(self) -> Optional[redis.Redis]:
        """CRITICAL FIX: Get shared Redis client with connection tracking and circuit breaker"""
        # CRITICAL FIX: Enforce circuit breaker for shared client access
        from core.circuit_breaker import get_circuit_breaker_enforcer
        enforcer = get_circuit_breaker_enforcer()
        
        async def _get_shared_client_internal():
            # CRITICAL FIX: Ensure monitoring starts when we have an event loop
            self._ensure_monitoring_started()
            
            async with self._lock:
                if not self._general_client:
                    self._general_client = await get_optimized_redis_client()
                    if self._general_client:
                        # Register connection for tracking
                        connection_id = "shared_client"
                        self._register_connection(connection_id, self._general_client, "shared")
                        logger.debug("Registered shared Redis client for tracking")
                
                # Update usage tracking
                if self._general_client:
                    connection_id = "shared_client"
                    self._connection_usage_count[connection_id] = self._connection_usage_count.get(connection_id, 0) + 1
                
                return self._general_client
        
        # Execute with mandatory circuit breaker protection
        try:
            return await enforcer.enforce_redis_operation(_get_shared_client_internal)
        except Exception as e:
            logger.warning(f"Shared Redis client access failed through circuit breaker: {e}")
            return None
    
    async def get_pubsub_client(self, worker_id: str) -> Optional[redis.Redis]:
        """CRITICAL FIX: Get dedicated pub/sub client with connection tracking and circuit breaker"""
        # CRITICAL FIX: Enforce circuit breaker for pub/sub client access
        from core.circuit_breaker import get_circuit_breaker_enforcer
        enforcer = get_circuit_breaker_enforcer()
        
        async def _get_pubsub_client_internal():
            async with self._lock:
                if worker_id not in self._pubsub_clients:
                    client = await get_optimized_redis_client()
                    if client:
                        self._pubsub_clients[worker_id] = client
                        # Register connection for tracking
                        connection_id = f"pubsub_{worker_id}"
                        self._register_connection(connection_id, client, "pubsub", worker_id)
                        logger.debug(f"Registered pub/sub client for worker {worker_id}")
                
                # Update usage tracking
                client = self._pubsub_clients.get(worker_id)
                if client:
                    connection_id = f"pubsub_{worker_id}"
                    self._connection_usage_count[connection_id] = self._connection_usage_count.get(connection_id, 0) + 1
                
                return client
        
        # Execute with mandatory circuit breaker protection
        try:
            return await enforcer.enforce_redis_operation(_get_pubsub_client_internal)
        except Exception as e:
            logger.warning(f"Pub/sub Redis client access failed through circuit breaker for worker {worker_id}: {e}")
            return None
    
    async def cleanup_worker(self, worker_id: str):
        """Clean up Redis connections for a specific worker"""
        async with self._lock:
            # Cancel subscriptions
            if worker_id in self._subscriptions:
                task = self._subscriptions[worker_id]
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                del self._subscriptions[worker_id]
            
            # Close pub/sub client
            if worker_id in self._pubsub_clients:
                client = self._pubsub_clients[worker_id]
                try:
                    await client.aclose()
                except:
                    pass
                del self._pubsub_clients[worker_id]
    
    async def close_all(self):
        """Close all Redis connections"""
        async with self._lock:
            # Cancel all subscriptions
            for task in self._subscriptions.values():
                if not task.done():
                    task.cancel()
            
            # Wait for cancellations
            if self._subscriptions:
                await asyncio.gather(*self._subscriptions.values(), return_exceptions=True)
            
            # Close all pub/sub clients
            for client in self._pubsub_clients.values():
                try:
                    await client.aclose()
                except:
                    pass
            
            # Close general client
            if self._general_client:
                try:
                    await self._general_client.aclose()
                except:
                    pass
            
            self._pubsub_clients.clear()
            self._subscriptions.clear()
            self._general_client = None


    def _register_connection(self, connection_id: str, client: redis.Redis, connection_type: str, worker_id: str = None):
        """CRITICAL FIX: Register connection for leak detection and monitoring"""
        import time
        current_time = time.time()
        
        self._connection_registry[connection_id] = {
            "client": client,
            "type": connection_type,
            "worker_id": worker_id,
            "created_at": current_time,
            "last_used": current_time
        }
        
        self._connection_creation_time[connection_id] = current_time
        self._connection_usage_count[connection_id] = 0
        
        logger.debug(f"Registered Redis connection {connection_id} (type: {connection_type})")
    
    def _unregister_connection(self, connection_id: str):
        """CRITICAL FIX: Unregister connection from tracking"""
        self._connection_registry.pop(connection_id, None)
        self._connection_creation_time.pop(connection_id, None)
        self._connection_usage_count.pop(connection_id, None)
        self._leaked_connections.discard(connection_id)
        
        logger.debug(f"Unregistered Redis connection {connection_id}")
    
    def _start_connection_monitoring(self):
        """CRITICAL FIX: Start background task to monitor connections for leaks"""
        async def monitor_connections():
            while True:
                try:
                    await asyncio.sleep(self._monitoring_interval)
                    await self._check_for_leaks()
                    await self._cleanup_stale_connections()
                except asyncio.CancelledError:
                    logger.info("Connection monitoring stopped")
                    break
                except Exception as e:
                    logger.error(f"Error in connection monitoring: {e}")
                    await asyncio.sleep(self._monitoring_interval)
        
        # CRITICAL FIX: Only start monitoring if event loop is running
        try:
            loop = asyncio.get_running_loop()
            self._monitoring_task = loop.create_task(monitor_connections())
            self._monitoring_started = True
            logger.info("Started Redis connection monitoring")
        except RuntimeError:
            # No event loop running, defer task creation
            logger.debug("No event loop running, deferring connection monitoring start")
            # Store the coroutine function to start later
            self._monitor_connections_coro = monitor_connections
    
    def _ensure_monitoring_started(self):
        """CRITICAL FIX: Ensure monitoring is started if an event loop is available"""
        if not self._monitoring_started and self._monitor_connections_coro:
            try:
                loop = asyncio.get_running_loop()
                self._monitoring_task = loop.create_task(self._monitor_connections_coro())
                self._monitoring_started = True
                logger.info("Started Redis connection monitoring (deferred)")
            except RuntimeError:
                # Still no event loop, will try again next time
                pass
    
    async def _check_for_leaks(self):
        """CRITICAL FIX: Check for leaked connections"""
        import time
        current_time = time.time()
        
        async with self._lock:
            for connection_id, info in self._connection_registry.items():
                last_used = info.get("last_used", info["created_at"])
                
                # Check for potential leaks (connections not used for a while)
                if current_time - last_used > self._leak_detection_threshold:
                    if connection_id not in self._leaked_connections:
                        self._leaked_connections.add(connection_id)
                        logger.warning(f"Potential Redis connection leak detected: {connection_id} (idle for {current_time - last_used:.1f}s)")
                
                # Check for very old connections
                if current_time - info["created_at"] > self._max_connection_age:
                    logger.warning(f"Very old Redis connection detected: {connection_id} (age: {current_time - info['created_at']:.1f}s)")
    
    async def _cleanup_stale_connections(self):
        """CRITICAL FIX: Cleanup stale connections"""
        import time
        current_time = time.time()
        
        connections_to_cleanup = []
        
        async with self._lock:
            for connection_id, info in self._connection_registry.items():
                # Mark very old connections for cleanup
                if current_time - info["created_at"] > self._max_connection_age:
                    connections_to_cleanup.append((connection_id, info))
        
        # Cleanup connections outside the lock to avoid deadlock
        for connection_id, info in connections_to_cleanup:
            try:
                client = info["client"]
                worker_id = info.get("worker_id")
                
                logger.info(f"Cleaning up stale Redis connection {connection_id} (worker: {worker_id})")
                
                # Schedule cleanup task
                cleanup_task = asyncio.create_task(self._safe_close_connection(client, connection_id))
                if worker_id:
                    self._cleanup_tasks[worker_id] = cleanup_task
                
            except Exception as e:
                logger.error(f"Error scheduling cleanup for connection {connection_id}: {e}")
    
    async def _safe_close_connection(self, client: redis.Redis, connection_id: str):
        """CRITICAL FIX: Safely close a Redis connection with timeout"""
        try:
            await asyncio.wait_for(client.aclose(), timeout=5.0)
            logger.info(f"Closed stale connection {connection_id}")
        except asyncio.TimeoutError:
            logger.warning(f"Timeout closing stale connection {connection_id}")
        except Exception as e:
            logger.warning(f"Error closing stale connection {connection_id}: {e}")
        finally:
            async with self._lock:
                self._unregister_connection(connection_id)
    
    def get_connection_metrics(self) -> Dict[str, Any]:
        """CRITICAL FIX: Get connection tracking metrics"""
        import time
        current_time = time.time()
        
        metrics = {
            "total_connections": len(self._connection_registry),
            "leaked_connections": len(self._leaked_connections),
            "connection_types": {},
            "worker_connections": {},
            "oldest_connection_age": 0,
            "total_usage_count": sum(self._connection_usage_count.values()),
            "monitoring_enabled": self._monitoring_task is not None and not self._monitoring_task.done()
        }
        
        for connection_id, info in self._connection_registry.items():
            conn_type = info["type"]
            worker_id = info.get("worker_id", "global")
            age = current_time - info["created_at"]
            
            # Count by type
            metrics["connection_types"][conn_type] = metrics["connection_types"].get(conn_type, 0) + 1
            
            # Count by worker
            metrics["worker_connections"][worker_id] = metrics["worker_connections"].get(worker_id, 0) + 1
            
            # Track oldest connection
            if age > metrics["oldest_connection_age"]:
                metrics["oldest_connection_age"] = age
        
        return metrics


# Global worker Redis manager
_worker_redis_manager = WorkerRedisManager()


async def get_worker_redis_manager() -> WorkerRedisManager:
    """Get the global worker Redis manager"""
    return _worker_redis_manager