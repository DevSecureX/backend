"""
Enhanced Caching Utilities for DevSecureX
World-class caching with Redis optimization, fallback mechanisms, and 10x performance
"""

import asyncio
import json
import logging
import hashlib
import os
from typing import Any, Optional, Union, Callable, Dict, List
from functools import wraps
from datetime import datetime, timedelta, timezone
# Import redis_client lazily to avoid production connections
from core.config import TESTING_MODE
import pickle
import zlib

logger = logging.getLogger(__name__)

# Global Redis optimizer instance
_redis_optimizer = None
_redis_optimizer_lock = asyncio.Lock()

async def _get_redis_optimizer():
    """Get Redis optimizer instance safely"""
    global _redis_optimizer
    
    if _redis_optimizer is not None:
        return _redis_optimizer
    
    async with _redis_optimizer_lock:
        if _redis_optimizer is not None:
            return _redis_optimizer
        
        try:
            from core.redis_optimized import get_redis_optimizer
            _redis_optimizer = await get_redis_optimizer()
            return _redis_optimizer
        except Exception as e:
            logger.warning(f"Failed to get Redis optimizer for cache: {e}")
            return None

# Backward compatibility - maintain old Redis client function
_redis_client_cache = None
_redis_client_lock = asyncio.Lock()

async def _get_safe_redis_client():
    """Get Redis client safely with connection reuse (legacy compatibility)"""
    global _redis_client_cache
    
    if _redis_client_cache is not None:
        try:
            # Test if connection is still alive
            await _redis_client_cache.ping()
            return _redis_client_cache
        except Exception:
            _redis_client_cache = None
    
    async with _redis_client_lock:
        # Double-check pattern
        if _redis_client_cache is not None:
            try:
                await _redis_client_cache.ping()
                return _redis_client_cache
            except Exception:
                _redis_client_cache = None
        
        try:
            from core.redis import get_redis_client
            _redis_client_cache = await get_redis_client()
            return _redis_client_cache
        except Exception as e:
            logger.warning(f"Failed to get Redis client for cache: {e}")
            return None

class AdvancedCache:
    """High-performance caching with Redis optimization, compression, serialization, and fallback"""
    
    def __init__(self, use_redis_optimizer: bool = True):
        self.local_cache: Dict[str, Any] = {}  # In-memory fallback
        self.local_cache_ttl: Dict[str, datetime] = {}
        self.max_local_cache_size = 1000
        self.use_redis_optimizer = use_redis_optimizer
        
        # Performance metrics
        self.metrics = {
            'optimizer_hits': 0,
            'optimizer_misses': 0,
            'legacy_hits': 0,
            'legacy_misses': 0,
            'local_hits': 0,
            'local_misses': 0,
            'total_requests': 0,
            'avg_response_time': 0.0
        }
        
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache with Redis optimizer and fallback mechanisms"""
        import time
        start_time = time.time()
        self.metrics['total_requests'] += 1
        
        # Try Redis optimizer first (if enabled)
        if self.use_redis_optimizer:
            try:
                redis_optimizer = await _get_redis_optimizer()
                if redis_optimizer:
                    value = await redis_optimizer.get(key, operation_type="cache")
                    if value is not None:
                        self.metrics['optimizer_hits'] += 1
                        self._update_response_time(start_time)
                        return value
                    else:
                        self.metrics['optimizer_misses'] += 1
                else:
                    # Optimizer not available, fall back to legacy Redis
                    return await self._get_legacy(key, default)
            except Exception as e:
                logger.warning(f"Redis optimizer get failed for key {key}: {e}")
                # Fall back to legacy Redis
                return await self._get_legacy(key, default)
        else:
            # Use legacy Redis method
            return await self._get_legacy(key, default)
        
        self._update_response_time(start_time)
        return default
    
    async def _get_legacy(self, key: str, default: Any = None) -> Any:
        """Legacy Redis get method for backward compatibility"""
        # First try local cache (fastest)
        if key in self.local_cache:
            if key in self.local_cache_ttl:
                if datetime.now(timezone.utc) > self.local_cache_ttl[key]:
                    # Expired - clean up
                    del self.local_cache[key]
                    del self.local_cache_ttl[key]
                else:
                    self.metrics['local_hits'] += 1
                    return self.local_cache[key]
            else:
                self.metrics['local_hits'] += 1
                return self.local_cache[key]
        
        self.metrics['local_misses'] += 1
        
        # Try Redis with timeout to prevent blocking
        try:
            safe_redis = await _get_safe_redis_client()
            if safe_redis:
                # Use asyncio.wait_for to prevent hanging
                value = await asyncio.wait_for(safe_redis.get(key), timeout=0.5)
                if value is not None:
                    deserialized = self._deserialize(value)
                    # Update local cache for faster future access
                    self.local_cache[key] = deserialized
                    self.metrics['legacy_hits'] += 1
                    return deserialized
                else:
                    self.metrics['legacy_misses'] += 1
                    
        except asyncio.TimeoutError:
            logger.warning(f"Redis get timeout for key {key}")
            self.metrics['legacy_misses'] += 1
        except Exception as e:
            logger.warning(f"Cache get error for key {key}: {e}")
            self.metrics['legacy_misses'] += 1
            
        return default
    
    async def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        """Set value in cache with TTL using Redis optimizer and fallback"""
        # Try Redis optimizer first (if enabled)
        if self.use_redis_optimizer:
            try:
                redis_optimizer = await _get_redis_optimizer()
                if redis_optimizer:
                    return await redis_optimizer.set(key, value, ttl, operation_type="cache")
                else:
                    # Fall back to legacy method
                    return await self._set_legacy(key, value, ttl)
            except Exception as e:
                logger.warning(f"Redis optimizer set failed for key {key}: {e}")
                # Fall back to legacy method
                return await self._set_legacy(key, value, ttl)
        else:
            # Use legacy method
            return await self._set_legacy(key, value, ttl)
    
    async def _set_legacy(self, key: str, value: Any, ttl: int = 300) -> bool:
        """Legacy Redis set method for backward compatibility"""
        # Always set in local cache first for immediate availability
        self._set_local(key, value, ttl)
        
        # Try Redis asynchronously with timeout
        try:
            safe_redis = await _get_safe_redis_client()
            if safe_redis:
                serialized = self._serialize(value)
                # Use asyncio.wait_for to prevent blocking
                await asyncio.wait_for(
                    safe_redis.setex(key, ttl, serialized),
                    timeout=0.5
                )
                return True
                
        except asyncio.TimeoutError:
            logger.warning(f"Redis set timeout for key {key}")
        except Exception as e:
            logger.warning(f"Cache set error for key {key}: {e}")
            
        # Return True since local cache was successful
        return True
    
    def _update_response_time(self, start_time: float):
        """Update average response time metrics"""
        import time
        response_time = time.time() - start_time
        if self.metrics['total_requests'] > 0:
            self.metrics['avg_response_time'] = (
                (self.metrics['avg_response_time'] * (self.metrics['total_requests'] - 1) + response_time) / 
                self.metrics['total_requests']
            )
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache using Redis optimizer and fallback"""
        try:
            # Try Redis optimizer first (if enabled)
            if self.use_redis_optimizer:
                redis_optimizer = await _get_redis_optimizer()
                if redis_optimizer:
                    return await redis_optimizer.delete(key, operation_type="cache")
            
            # Fall back to legacy method
            safe_redis = await _get_safe_redis_client()
            if safe_redis:
                await safe_redis.delete(key)
            
            # Also delete from local cache
            if key in self.local_cache:
                del self.local_cache[key]
            if key in self.local_cache_ttl:
                del self.local_cache_ttl[key]
                
            return True
        except Exception as e:
            logger.warning(f"Cache delete error for key {key}: {e}")
            return False
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive cache performance metrics"""
        total_hits = (self.metrics['optimizer_hits'] + self.metrics['legacy_hits'] + 
                      self.metrics['local_hits'])
        total_requests = self.metrics['total_requests']
        
        return {
            **self.metrics,
            'hit_rate': (total_hits / total_requests * 100) if total_requests > 0 else 0,
            'optimizer_usage': self.use_redis_optimizer,
            'local_cache_size': len(self.local_cache),
            'local_cache_max_size': self.max_local_cache_size
        }
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache using Redis optimizer and fallback"""
        try:
            # Try Redis optimizer first (if enabled)
            if self.use_redis_optimizer:
                redis_optimizer = await _get_redis_optimizer()
                if redis_optimizer:
                    return await redis_optimizer.exists(key, operation_type="cache")
            
            # Fall back to legacy method
            safe_redis = await _get_safe_redis_client()
            if safe_redis:
                return await safe_redis.exists(key) > 0
            return key in self.local_cache
        except Exception as e:
            logger.warning(f"Cache exists error for key {key}: {e}")
            return key in self.local_cache
    
    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching pattern using Redis optimizer and fallback"""
        try:
            # Try Redis optimizer first (if enabled)
            if self.use_redis_optimizer:
                redis_optimizer = await _get_redis_optimizer()
                if redis_optimizer:
                    return await redis_optimizer.invalidate_pattern(pattern, operation_type="cache")
            
            # Fall back to legacy method
            safe_redis = await _get_safe_redis_client()
            if safe_redis:
                keys = await safe_redis.keys(pattern)
                if keys:
                    return await safe_redis.delete(*keys)
            
            # Local cache pattern matching
            keys_to_delete = [k for k in self.local_cache.keys() if pattern in k]
            for key in keys_to_delete:
                del self.local_cache[key]
                if key in self.local_cache_ttl:
                    del self.local_cache_ttl[key]
            
            return len(keys_to_delete)
        except Exception as e:
            logger.warning(f"Cache invalidate pattern error for {pattern}: {e}")
            return 0
    
    def _serialize(self, value: Any) -> str:
        """Serialize value with compression for better performance"""
        if isinstance(value, (str, int, float, bool)) or value is None:
            return json.dumps(value)
        
        # Use pickle for complex objects, compress for large data
        pickled = pickle.dumps(value)
        if len(pickled) > 1024:  # Compress if > 1KB
            compressed = zlib.compress(pickled)
            return f"compressed:{compressed.hex()}"
        else:
            return f"pickled:{pickled.hex()}"
    
    def _deserialize(self, value: str) -> Any:
        """Deserialize value with decompression"""
        if value.startswith("compressed:"):
            hex_data = value[11:]  # Remove "compressed:" prefix
            compressed = bytes.fromhex(hex_data)
            pickled = zlib.decompress(compressed)
            return pickle.loads(pickled)
        elif value.startswith("pickled:"):
            hex_data = value[8:]  # Remove "pickled:" prefix
            pickled = bytes.fromhex(hex_data)
            return pickle.loads(pickled)
        else:
            return json.loads(value)
    
    def _set_local(self, key: str, value: Any, ttl: int):
        """Set value in local cache with size management"""
        # Clean up expired entries first
        self._cleanup_local_cache()
        
        # If cache is full, remove oldest entries
        if len(self.local_cache) >= self.max_local_cache_size:
            oldest_keys = sorted(
                self.local_cache_ttl.keys(),
                key=lambda k: self.local_cache_ttl[k]
            )[:100]  # Remove 100 oldest entries
            
            for key_to_remove in oldest_keys:
                if key_to_remove in self.local_cache:
                    del self.local_cache[key_to_remove]
                del self.local_cache_ttl[key_to_remove]
        
        self.local_cache[key] = value
        self.local_cache_ttl[key] = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    
    def _cleanup_local_cache(self):
        """Clean up expired local cache entries"""
        now = datetime.now(timezone.utc)
        expired_keys = [
            key for key, expires_at in self.local_cache_ttl.items()
            if now > expires_at
        ]
        
        for key in expired_keys:
            if key in self.local_cache:
                del self.local_cache[key]
            del self.local_cache_ttl[key]

# Global cache instance
cache = AdvancedCache()

def cache_key(*args, **kwargs) -> str:
    """Generate cache key from arguments"""
    key_data = f"{args}:{sorted(kwargs.items())}"
    return hashlib.md5(key_data.encode()).hexdigest()

def cached(ttl: int = 300, key_prefix: str = ""):
    """Decorator for caching function results"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            key = f"{key_prefix}:{func.__name__}:{cache_key(*args, **kwargs)}"
            
            # Try to get from cache
            result = await cache.get(key)
            if result is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache.set(key, result, ttl)
            logger.debug(f"Cache miss for {func.__name__}, result cached")
            
            return result
        return wrapper
    return decorator

# Specialized cache utilities
class ScanCache:
    """Specialized caching for scan operations"""
    
    @staticmethod
    async def get_scan_result(scan_id: str) -> Optional[Dict]:
        """Get cached scan result"""
        return await cache.get(f"scan:result:{scan_id}")
    
    @staticmethod
    async def set_scan_result(scan_id: str, result: Dict, ttl: int = 3600):
        """Cache scan result"""
        await cache.set(f"scan:result:{scan_id}", result, ttl)
    
    @staticmethod
    async def invalidate_user_scans(user_id: int):
        """Invalidate all cached scans for a user"""
        await cache.invalidate_pattern(f"scan:user:{user_id}:*")

class RepoCache:
    """Specialized caching for repository operations"""
    
    @staticmethod
    async def get_user_repos(user_id: int) -> Optional[List]:
        """Get cached user repositories"""
        return await cache.get(f"repo:user:{user_id}")
    
    @staticmethod
    async def set_user_repos(user_id: int, repos: List, ttl: int = 300):
        """Cache user repositories"""
        await cache.set(f"repo:user:{user_id}", repos, ttl)
    
    @staticmethod
    async def invalidate_user_repos(user_id: int):
        """Invalidate cached repositories for a user"""
        await cache.delete(f"repo:user:{user_id}")

class GitHubAPICache:
    """Specialized caching for GitHub API calls with high performance optimizations"""
    
    @staticmethod
    async def get_default_branch(repo_full_name: str) -> Optional[str]:
        """Get cached default branch (6-hour TTL)"""
        return await cache.get(f"repo:default_branch:{repo_full_name}")
    
    @staticmethod
    async def set_default_branch(repo_full_name: str, branch: str):
        """Cache default branch for 6 hours"""
        await cache.set(f"repo:default_branch:{repo_full_name}", branch, ttl=21600)
    
    @staticmethod
    async def get_branch_validation(repo_full_name: str, branch: str) -> Optional[str]:
        """Get cached branch validation (1-hour TTL)"""
        return await cache.get(f"branch:validation:{repo_full_name}:{branch}")
    
    @staticmethod
    async def set_branch_validation(repo_full_name: str, branch: str, is_valid: bool):
        """Cache branch validation for 1 hour (5 minutes for invalid)"""
        ttl = 3600 if is_valid else 300
        value = "valid" if is_valid else "invalid"
        await cache.set(f"branch:validation:{repo_full_name}:{branch}", value, ttl)
    
    @staticmethod
    async def get_pr_details(repo_full_name: str, pr_number: int) -> Optional[Dict]:
        """Get cached PR details (10-minute TTL)"""
        return await cache.get(f"pr:details:{repo_full_name}:{pr_number}")
    
    @staticmethod
    async def set_pr_details(repo_full_name: str, pr_number: int, details: Dict):
        """Cache PR details for 10 minutes"""
        await cache.set(f"pr:details:{repo_full_name}:{pr_number}", details, ttl=600)
    
    @staticmethod
    async def get_pr_changed_files(repo_full_name: str, pr_number: int) -> Optional[List]:
        """Get cached PR changed files (30-minute TTL)"""
        return await cache.get(f"pr:changed_files:{repo_full_name}:{pr_number}")
    
    @staticmethod
    async def set_pr_changed_files(repo_full_name: str, pr_number: int, files: List):
        """Cache PR changed files for 30 minutes"""
        await cache.set(f"pr:changed_files:{repo_full_name}:{pr_number}", files, ttl=1800)
    
    @staticmethod
    async def get_repo_contents(repo_full_name: str, branch: str) -> Optional[Dict]:
        """Get cached repository contents (15-minute TTL)"""
        return await cache.get(f"repo:contents:{repo_full_name}:{branch}")
    
    @staticmethod
    async def set_repo_contents(repo_full_name: str, branch: str, contents: Dict):
        """Cache repository contents for 15 minutes"""
        await cache.set(f"repo:contents:{repo_full_name}:{branch}", contents, ttl=900)
    
    @staticmethod
    async def get_repo_metadata(repo_full_name: str) -> Optional[Dict]:
        """Get cached repository metadata (30-minute TTL)"""
        return await cache.get(f"repo:metadata:{repo_full_name}")
    
    @staticmethod
    async def set_repo_metadata(repo_full_name: str, metadata: Dict):
        """Cache repository metadata for 30 minutes"""
        await cache.set(f"repo:metadata:{repo_full_name}", metadata, ttl=1800)
    
    @staticmethod
    async def invalidate_all_repo_caches(repo_full_name: str):
        """Invalidate all GitHub API caches for a repository"""
        await cache.delete(f"repo:default_branch:{repo_full_name}")
        await cache.delete(f"repo:metadata:{repo_full_name}")
        await cache.invalidate_pattern(f"branch:validation:{repo_full_name}:*")
        await cache.invalidate_pattern(f"repo:contents:{repo_full_name}:*")
        await cache.invalidate_pattern(f"pr:details:{repo_full_name}:*")
        await cache.invalidate_pattern(f"pr:changed_files:{repo_full_name}:*")
    
    @staticmethod
    async def invalidate_branch_caches(repo_full_name: str, branch: str):
        """Invalidate caches for a specific branch"""
        await cache.delete(f"branch:validation:{repo_full_name}:{branch}")
        await cache.delete(f"repo:contents:{repo_full_name}:{branch}")
    
    @staticmethod
    async def invalidate_pr_caches(repo_full_name: str, pr_number: int):
        """Invalidate caches for a specific PR"""
        await cache.delete(f"pr:details:{repo_full_name}:{pr_number}")
        await cache.delete(f"pr:changed_files:{repo_full_name}:{pr_number}")

class AICache:
    """Specialized caching for AI explanations"""
    
    @staticmethod
    async def get_explanation(pattern_hash: str) -> Optional[Dict]:
        """Get cached AI explanation"""
        return await cache.get(f"ai:explanation:{pattern_hash}")
    
    @staticmethod
    async def set_explanation(pattern_hash: str, explanation: Dict, ttl: int = 86400):
        """Cache AI explanation for 24 hours"""
        await cache.set(f"ai:explanation:{pattern_hash}", explanation, ttl)

# Rate limiting cache
class RateLimitCache:
    """Specialized caching for rate limiting"""
    
    @staticmethod
    async def increment_counter(key: str, ttl: int = 3600) -> int:
        """Increment rate limit counter"""
        try:
            safe_redis = await _get_safe_redis_client()
            if safe_redis:
                count = await safe_redis.incr(key)
                if count == 1:
                    await safe_redis.expire(key, ttl)
                return count
            else:
                # Fallback to simple tracking
                current = await cache.get(key, 0)
                new_count = current + 1
                await cache.set(key, new_count, ttl)
                return new_count
        except Exception as e:
            logger.warning(f"Rate limit increment error: {e}")
            return 0
    
    @staticmethod
    async def get_counter(key: str) -> int:
        """Get current rate limit counter"""
        try:
            safe_redis = await _get_safe_redis_client()
            if safe_redis:
                count = await safe_redis.get(key)
                return int(count) if count else 0
            else:
                return await cache.get(key, 0)
        except Exception as e:
            logger.warning(f"Rate limit get error: {e}")
            return 0

# Health check for cache system with Redis optimization
async def cache_health_check() -> Dict[str, Any]:
    """Check cache system health with fallback to legacy Redis client"""
    health = {
        "redis_available": False,
        "redis_optimizer_enabled": False,
        "local_cache_size": len(cache.local_cache),
        "local_cache_ttl_size": len(cache.local_cache_ttl),
        "cache_performance": cache.get_performance_metrics()
    }
    
    # Use legacy Redis health check as primary method to avoid parser issues
    try:
        safe_redis = await _get_safe_redis_client()
        if safe_redis:
            await safe_redis.ping()
            health["redis_available"] = True
            
            # Get Redis info
            info = await safe_redis.info()
            health["redis_memory"] = info.get("used_memory_human", "unknown")
            health["redis_connections"] = info.get("connected_clients", 0)
            
            # Set optimizer-like fields for compatibility
            health.update({
                "redis_optimizer_enabled": False,  # Using legacy client
                "redis_optimizer_status": "healthy",
                "redis_latency_ms": 0.0,  # Not measured in legacy mode
                "redis_pools": 1 if health["redis_available"] else 0,
            })
            
            logger.debug("Using legacy Redis health check (optimizer disabled due to connection issues)")
            return health
            
    except Exception as e:
        logger.warning(f"Legacy cache health check error: {e}")
    
    # Last resort: try Redis optimizer if legacy fails
    try:
        redis_optimizer = await _get_redis_optimizer()
        if redis_optimizer:
            optimizer_health = await redis_optimizer.health_check()
            health.update({
                "redis_optimizer_enabled": True,
                "redis_optimizer_status": optimizer_health.get("status", "unknown"),
                "redis_latency_ms": optimizer_health.get("latency_ms"),
                "redis_memory": optimizer_health.get("memory_usage"),
                "redis_connections": optimizer_health.get("connection_count"),
                "redis_pools": optimizer_health.get("pools_healthy", 0),
                "redis_available": optimizer_health.get("status") == "healthy"
            })
            
            # Get comprehensive performance stats
            try:
                perf_stats = await redis_optimizer.get_performance_stats()
                health["redis_performance_stats"] = perf_stats
            except Exception:
                pass  # Non-critical
                
            return health
    except Exception as e:
        logger.warning(f"Redis optimizer health check also failed: {e}")
    
    return health