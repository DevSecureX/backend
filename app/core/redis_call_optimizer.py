"""
Redis Call Optimizer
Reduces Redis API calls through caching, batching, and smart operations

Configuration Environment Variables:
    REDIS_CACHE_DEFAULT_TTL: Default TTL for cache entries in seconds (default: 60)
    REDIS_QUEUE_STATS_TTL: TTL for queue statistics cache in seconds (default: 30)
    REDIS_KEY_COUNT_TTL: TTL for key count cache in seconds (default: 20)
    REDIS_BATCH_SIZE: Maximum batch size before auto-flush (default: 10)
    REDIS_BATCH_FLUSH_INTERVAL: Batch flush interval in seconds (default: 10)

Features:
    - Smart caching with configurable TTL
    - Batch operations to minimize round trips
    - Connection error resilience with fallback mechanisms
    - Background cache cleanup to prevent memory leaks
    - Comprehensive error handling and logging
    - Performance metrics tracking
"""

import asyncio
import json
import logging
import os
import time
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict
from redis.exceptions import ConnectionError, TimeoutError, RedisError

logger = logging.getLogger(__name__)

# Configuration constants with environment variable support
# These values can be overridden via environment variables for different environments

# Cache TTL settings - REDIS COST OPTIMIZED - balance between performance and data freshness
REDIS_CACHE_DEFAULT_TTL = int(os.getenv("REDIS_CACHE_DEFAULT_TTL", "900"))  # Extended cache TTL to 15 minutes
REDIS_QUEUE_STATS_TTL = int(os.getenv("REDIS_QUEUE_STATS_TTL", "300"))    # Queue stats cache TTL to 5 minutes
REDIS_KEY_COUNT_TTL = int(os.getenv("REDIS_KEY_COUNT_TTL", "180"))        # Key count cache TTL to 3 minutes

# Batch operation settings - REDIS COST OPTIMIZED - optimize for throughput vs latency
REDIS_BATCH_SIZE = int(os.getenv("REDIS_BATCH_SIZE", "50"))              # Increased batch size for efficiency  
REDIS_BATCH_FLUSH_INTERVAL = int(os.getenv("REDIS_BATCH_FLUSH_INTERVAL", "30"))  # Longer batch timeout (seconds)
REDIS_SCAN_COUNT = int(os.getenv("REDIS_SCAN_COUNT", "200"))             # Increase SCAN count to reduce round trips

@dataclass
class CacheEntry:
    """Cache entry with TTL"""
    value: Any
    expires_at: float
    created_at: float

class RedisCallOptimizer:
    """
    Production-ready Redis call optimizer with comprehensive error handling
    
    Optimizes Redis calls through:
    1. Smart caching with configurable TTL
    2. Operation batching to reduce round trips
    3. Lazy loading with fallback mechanisms
    4. Background cache maintenance
    5. Circuit breaker pattern for resilience
    
    Usage:
        optimizer = RedisCallOptimizer()
        await optimizer.start_background_cleanup()  # Optional: start background cleanup
        
        # Get cached queue stats
        stats = await optimizer.get_queue_stats_cached(redis_client, "queue", "processing", "failed")
        
        # Get value with fallback
        value = await optimizer.get_with_fallback(redis_client, "key", fallback_func=lambda: "default")
    """
    
    def __init__(self, default_ttl: int = None):
        self.default_ttl = default_ttl or REDIS_CACHE_DEFAULT_TTL
        self.cache: Dict[str, CacheEntry] = {}
        self.batch_operations: List[Tuple[str, str, Any]] = []
        self.last_batch_flush = time.time()
        self.batch_flush_interval = REDIS_BATCH_FLUSH_INTERVAL
        
        # Enhanced stats tracking with timing metrics
        self.stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "redis_calls_saved": 0,
            "batch_operations_saved": 0,
            "total_redis_calls": 0,
            "total_cache_operations": 0,
            "avg_cache_lookup_time": 0.0,
            "last_cleanup_count": 0,
            "background_cleanup_runs": 0
        }
        
        # Async cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._stop_cleanup = False
        
        logger.info("Redis Call Optimizer initialized")
    
    def _is_cache_valid(self, entry: CacheEntry) -> bool:
        """Check if cache entry is still valid"""
        return time.time() < entry.expires_at
    
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get value from cache if valid with performance tracking"""
        start_time = time.time()
        
        try:
            self.stats["total_cache_operations"] += 1
            
            if key in self.cache:
                entry = self.cache[key]
                if self._is_cache_valid(entry):
                    self.stats["cache_hits"] += 1
                    logger.debug(f"Cache HIT for key: {key}")
                    return entry.value
                else:
                    # Remove expired entry
                    del self.cache[key]
                    logger.debug(f"Cache EXPIRED for key: {key}")
            
            self.stats["cache_misses"] += 1
            logger.debug(f"Cache MISS for key: {key}")
            return None
            
        finally:
            # Update average lookup time
            lookup_time = time.time() - start_time
            total_ops = self.stats["total_cache_operations"]
            self.stats["avg_cache_lookup_time"] = (
                (self.stats["avg_cache_lookup_time"] * (total_ops - 1) + lookup_time) / total_ops
            )
    
    def _set_cache(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL"""
        ttl = ttl or self.default_ttl
        self.cache[key] = CacheEntry(
            value=value,
            expires_at=time.time() + ttl,
            created_at=time.time()
        )
    
    async def get_queue_stats_cached(self, redis_client, queue_key: str, processing_key: str, failed_key: str, ttl: int = None) -> Dict[str, int]:
        """Get queue stats with caching to avoid frequent Redis calls"""
        
        cache_key = f"queue_stats:{queue_key}"
        cached_stats = self._get_from_cache(cache_key)
        
        if cached_stats is not None:
            self.stats["redis_calls_saved"] += 3  # ZCARD, SCAN, LLEN calls saved
            return cached_stats
        
        # Cache miss - fetch from Redis
        try:
            logger.info(f"Fetching queue stats from Redis for queue: {queue_key}")
            self.stats["total_redis_calls"] += 3  # ZCARD, SCAN, LLEN
            
            stats = {
                "queued": await redis_client.zcard(queue_key),
                "processing": await self._count_keys_with_scan(redis_client, f"{processing_key}:*"),
                "failed": await redis_client.llen(failed_key)
            }
            
            logger.info(f"Queue stats retrieved - Queued: {stats['queued']}, Processing: {stats['processing']}, Failed: {stats['failed']}")
            
            # Cache the result
            self._set_cache(cache_key, stats, ttl or REDIS_QUEUE_STATS_TTL)
            return stats
            
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis connection issue while getting queue stats: {e}")
            return {"queued": 0, "processing": 0, "failed": 0}
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Data parsing issue in queue stats: {e}")
            return {"queued": 0, "processing": 0, "failed": 0}
        except Exception as e:
            logger.error(f"Unexpected error getting queue stats: {e}")
            return {"queued": 0, "processing": 0, "failed": 0}
    
    async def _count_keys_with_scan(self, redis_client, pattern: str) -> int:
        """Count keys using SCAN with caching"""
        
        cache_key = f"key_count:{pattern}"
        cached_count = self._get_from_cache(cache_key)
        
        if cached_count is not None:
            self.stats["redis_calls_saved"] += 1
            return cached_count
        
        try:
            logger.debug(f"Starting SCAN operation for pattern: {pattern}")
            keys = []
            cursor = 0
            scan_iterations = 0
            
            while True:
                cursor, partial_keys = await redis_client.scan(cursor=cursor, match=pattern, count=REDIS_SCAN_COUNT)
                keys.extend(partial_keys)
                scan_iterations += 1
                self.stats["total_redis_calls"] += 1  # Count each SCAN call
                
                if cursor == 0:
                    break
            
            count = len(keys)
            logger.debug(f"SCAN completed - Pattern: {pattern}, Keys found: {count}, Iterations: {scan_iterations}")
            self._set_cache(cache_key, count, ttl=REDIS_KEY_COUNT_TTL)
            return count
            
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis connection issue during SCAN operation: {e}")
            return 0
        except Exception as e:
            logger.error(f"Unexpected error during SCAN operation: {e}")
            return 0
    
    def add_batch_operation(self, operation: str, key: str, value: Any = None):
        """Add operation to batch queue"""
        self.batch_operations.append((operation, key, value))
        
        # Auto-flush if batch gets large or time threshold reached
        if (len(self.batch_operations) >= REDIS_BATCH_SIZE or 
            time.time() - self.last_batch_flush > self.batch_flush_interval):
            asyncio.create_task(self.flush_batch_operations())
    
    async def flush_batch_operations(self, redis_client=None):
        """Execute batched operations"""
        if not self.batch_operations or not redis_client:
            return
        
        try:
            # Group operations by type for efficiency
            operations_by_type = defaultdict(list)
            for op, key, value in self.batch_operations:
                operations_by_type[op].append((key, value))
            
            # Execute batched operations
            for op_type, ops in operations_by_type.items():
                if op_type == "SET":
                    # Batch SET operations using pipeline
                    async with redis_client.pipeline() as pipe:
                        for key, value in ops:
                            pipe.set(key, value)
                        await pipe.execute()
                
                elif op_type == "DEL":
                    # Batch DELETE operations
                    keys_to_delete = [key for key, _ in ops]
                    if keys_to_delete:
                        await redis_client.delete(*keys_to_delete)
            
            self.stats["batch_operations_saved"] += len(self.batch_operations) - len(operations_by_type)
            self.batch_operations.clear()
            self.last_batch_flush = time.time()
            
            logger.debug(f"Flushed {len(operations_by_type)} batched Redis operations")
            
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis connection issue during batch flush: {e}")
            # Don't clear operations on connection error - retry later
        except Exception as e:
            logger.error(f"Unexpected error during batch flush: {e}")
            # Clear operations to prevent infinite retry loops
            self.batch_operations.clear()
    
    async def get_with_fallback(self, redis_client, key: str, fallback_func=None, ttl: int = None) -> Any:
        """Get value with cache fallback and lazy loading"""
        
        # Try cache first
        cached_value = self._get_from_cache(key)
        if cached_value is not None:
            return cached_value
        
        try:
            # Try Redis
            value = await redis_client.get(key)
            if value is not None:
                try:
                    value = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    pass  # Keep as string
                
                self._set_cache(key, value, ttl or self.default_ttl)
                return value
            
            # Try fallback function if provided
            if fallback_func:
                fallback_value = await fallback_func() if asyncio.iscoroutinefunction(fallback_func) else fallback_func()
                self._set_cache(key, fallback_value, ttl or self.default_ttl)
                return fallback_value
            
            return None
            
        except (ConnectionError, TimeoutError, RedisError) as e:
            logger.warning(f"Redis connection issue getting {key}: {e}")
            
            # Return cached value even if expired as fallback
            if key in self.cache:
                logger.info(f"Using expired cache as fallback for {key}")
                return self.cache[key].value
            
            # Try fallback function as last resort
            if fallback_func:
                try:
                    fallback_value = await fallback_func() if asyncio.iscoroutinefunction(fallback_func) else fallback_func()
                    logger.info(f"Using fallback function result for {key}")
                    return fallback_value
                except Exception as fallback_error:
                    logger.error(f"Fallback function also failed for {key}: {fallback_error}")
            
            return None
            
        except (json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Data parsing issue for {key}: {e}")
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error getting {key}: {e}")
            return None
    
    async def cleanup_expired_cache(self):
        """Remove expired cache entries asynchronously"""
        current_time = time.time()
        expired_keys = []
        
        for key, entry in self.cache.items():
            if current_time >= entry.expires_at:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
            # Yield control to prevent blocking
            await asyncio.sleep(0)
        
        expired_count = len(expired_keys)
        if expired_count > 0:
            logger.info(f"Cache cleanup: removed {expired_count} expired entries, {len(self.cache)} entries remaining")
            self.stats["last_cleanup_count"] = expired_count
        
        return expired_count
    
    async def start_background_cleanup(self, cleanup_interval: int = 300):
        """Start background cleanup task (every 5 minutes by default)"""
        if self._cleanup_task and not self._cleanup_task.done():
            logger.warning("Background cleanup task already running")
            return
        
        self._stop_cleanup = False
        self._cleanup_task = asyncio.create_task(self._background_cleanup_loop(cleanup_interval))
        logger.info(f"Started background cache cleanup (interval: {cleanup_interval}s)")
    
    async def stop_background_cleanup(self):
        """Stop background cleanup task"""
        self._stop_cleanup = True
        
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped background cache cleanup")
    
    async def _background_cleanup_loop(self, interval: int):
        """Background cleanup loop"""
        while not self._stop_cleanup:
            try:
                self.stats["background_cleanup_runs"] += 1
                cleaned_count = await self.cleanup_expired_cache()
                
                if cleaned_count > 0:
                    logger.info(f"Background cleanup #{self.stats['background_cleanup_runs']} removed {cleaned_count} expired entries")
                
                # Log periodic health stats
                if self.stats["background_cleanup_runs"] % 12 == 0:  # Every hour if interval is 5 minutes
                    stats = self.get_health_stats()
                    logger.info(f"Redis Optimizer Health: {stats}")
                
                # Wait for next cleanup cycle
                await asyncio.sleep(interval)
                
            except asyncio.CancelledError:
                logger.debug("Background cleanup task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in background cleanup: {e}")
                await asyncio.sleep(60)  # Wait a minute before retrying
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive optimizer statistics"""
        total_requests = self.stats["cache_hits"] + self.stats["cache_misses"]
        cache_hit_rate = (self.stats["cache_hits"] / max(1, total_requests)) * 100
        total_redis_calls = self.stats["total_redis_calls"]
        redis_calls_saved = self.stats["redis_calls_saved"]
        optimization_rate = (redis_calls_saved / max(1, total_redis_calls + redis_calls_saved)) * 100
        
        return {
            "cache_entries": len(self.cache),
            "cache_hit_rate_percent": round(cache_hit_rate, 2),
            "redis_calls_saved": redis_calls_saved,
            "total_redis_calls": total_redis_calls,
            "optimization_rate_percent": round(optimization_rate, 2),
            "batch_operations_saved": self.stats["batch_operations_saved"],
            "total_operations_optimized": redis_calls_saved + self.stats["batch_operations_saved"],
            "avg_cache_lookup_ms": round(self.stats["avg_cache_lookup_time"] * 1000, 3),
            "background_cleanup_runs": self.stats["background_cleanup_runs"],
            "last_cleanup_count": self.stats["last_cleanup_count"]
        }
    
    def get_health_stats(self) -> Dict[str, Any]:
        """Get health monitoring statistics"""
        total_requests = self.stats["cache_hits"] + self.stats["cache_misses"]
        cache_hit_rate = (self.stats["cache_hits"] / max(1, total_requests)) * 100
        
        return {
            "status": "healthy" if cache_hit_rate > 50 else "degraded" if cache_hit_rate > 20 else "poor",
            "cache_entries": len(self.cache),
            "cache_hit_rate": round(cache_hit_rate, 1),
            "pending_batch_operations": len(self.batch_operations),
            "redis_calls_saved_total": self.stats["redis_calls_saved"],
            "cleanup_runs": self.stats["background_cleanup_runs"]
        }
    
    def reset_stats(self):
        """Reset statistics (preserves background cleanup count)"""
        cleanup_runs = self.stats["background_cleanup_runs"]  # Preserve this counter
        
        self.stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "redis_calls_saved": 0,
            "batch_operations_saved": 0,
            "total_redis_calls": 0,
            "total_cache_operations": 0,
            "avg_cache_lookup_time": 0.0,
            "last_cleanup_count": 0,
            "background_cleanup_runs": cleanup_runs
        }
        
        logger.info("Redis optimizer statistics reset")

# Global optimizer instance
_redis_optimizer: Optional[RedisCallOptimizer] = None

def get_redis_optimizer() -> RedisCallOptimizer:
    """Get or create the global Redis optimizer"""
    global _redis_optimizer
    
    if _redis_optimizer is None:
        _redis_optimizer = RedisCallOptimizer()
    
    return _redis_optimizer

async def cleanup_redis_optimizer():
    """Cleanup the global Redis optimizer"""
    global _redis_optimizer
    
    if _redis_optimizer:
        # Stop background cleanup first
        await _redis_optimizer.stop_background_cleanup()
        
        # Final cache cleanup
        await _redis_optimizer.cleanup_expired_cache()
        logger.info(f"Redis optimizer final stats: {_redis_optimizer.get_stats()}")
        _redis_optimizer = None
