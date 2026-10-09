"""
Advanced Rate Limiting Middleware
Implements sliding window rate limiting for custom rules endpoints with Redis support
"""

import os
import time
import logging
from typing import Dict, Optional
from dataclasses import dataclass
from collections import defaultdict, deque
from threading import RLock

from fastapi import Request, HTTPException, status
import redis.asyncio as redis

logger = logging.getLogger(__name__)

@dataclass
class RateLimit:
    """Rate limit configuration"""
    requests: int
    window_seconds: int
    burst_requests: Optional[int] = None
    burst_window_seconds: Optional[int] = None

@dataclass
class RateLimitResult:
    """Rate limit check result"""
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None

class SlidingWindowRateLimiter:
    """High-performance sliding window rate limiter with Redis support"""
    
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_client = None
        self.redis_url = redis_url
        
        # In-memory fallback for when Redis is not available
        self._memory_storage: Dict[str, deque] = defaultdict(deque)
        self._lock = RLock()
        
        # Rate limit configurations for different endpoints
        self.rate_limits = {
            # Custom rules endpoints
            'custom_rules_create': RateLimit(10, 3600, burst_requests=5, burst_window_seconds=60),  # 10/hour, burst 5/min
            'custom_rules_test': RateLimit(50, 3600, burst_requests=10, burst_window_seconds=60),   # 50/hour, burst 10/min
            'custom_rules_list': RateLimit(100, 3600, burst_requests=30, burst_window_seconds=60),  # 100/hour, burst 30/min
            'custom_rules_vote': RateLimit(50, 3600, burst_requests=20, burst_window_seconds=300),  # 50/hour, burst 20/5min
            'custom_rules_update': RateLimit(20, 3600, burst_requests=10, burst_window_seconds=300), # 20/hour, burst 10/5min
            'custom_rules_delete': RateLimit(10, 3600, burst_requests=5, burst_window_seconds=300),  # 10/hour, burst 5/5min
            
            # CLI endpoints
            'cli_scan': RateLimit(20, 3600, burst_requests=5, burst_window_seconds=300),  # 20/hour, burst 5/5min
            
            # General API endpoints
            'api_general': RateLimit(1000, 3600, burst_requests=100, burst_window_seconds=60),      # 1000/hour, burst 100/min
            'api_authenticated': RateLimit(2000, 3600, burst_requests=200, burst_window_seconds=60), # 2000/hour, burst 200/min
            
            # High-security endpoints
            'security_scan': RateLimit(20, 3600, burst_requests=5, burst_window_seconds=300),       # 20/hour, burst 5/5min
        }
        
        logger.info(f"Rate limiter initialized with Redis: {'Yes' if redis_url else 'No (memory fallback)'}")
    
    async def init_redis(self):
        """Initialize Redis connection"""
        if self.redis_url:
            try:
                self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
                await self.redis_client.ping()
                logger.info("Redis connection established for rate limiting")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis for rate limiting: {e}")
                self.redis_client = None
    
    def _get_client_key(self, request: Request, endpoint: str) -> str:
        """Generate unique key for rate limiting"""
        # Try to get user ID from request state
        try:
            user_id = getattr(request.state, 'user_id', None)
            if user_id:
                return f"rate_limit:user:{user_id}:{endpoint}"
        except AttributeError:
            pass
        
        # Fallback to IP address
        client_ip = "unknown"
        if request.client and request.client.host:
            client_ip = request.client.host
        
        # Check forwarded headers
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        
        return f"rate_limit:ip:{client_ip}:{endpoint}"
    
    async def _check_redis_rate_limit(self, key: str, rate_limit: RateLimit) -> RateLimitResult:
        """Check rate limit using Redis sliding window"""
        current_time = time.time()
        window_start = current_time - rate_limit.window_seconds
        
        pipe = self.redis_client.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count current requests in window
        pipe.zcard(key)
        
        # Add current request
        pipe.zadd(key, {str(current_time): current_time})
        
        # Set expiration
        pipe.expire(key, rate_limit.window_seconds + 60)
        
        results = await pipe.execute()
        current_count = results[1] + 1  # +1 for the request we just added
        
        # Check burst limits if configured
        if rate_limit.burst_requests and rate_limit.burst_window_seconds:
            burst_key = f"{key}:burst"
            burst_window_start = current_time - rate_limit.burst_window_seconds
            
            burst_pipe = self.redis_client.pipeline()
            burst_pipe.zremrangebyscore(burst_key, 0, burst_window_start)
            burst_pipe.zcard(burst_key)
            burst_pipe.zadd(burst_key, {str(current_time): current_time})
            burst_pipe.expire(burst_key, rate_limit.burst_window_seconds + 60)
            
            burst_results = await burst_pipe.execute()
            burst_count = burst_results[1] + 1
            
            if burst_count > rate_limit.burst_requests:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=current_time + rate_limit.burst_window_seconds,
                    retry_after=rate_limit.burst_window_seconds
                )
        
        # Check main rate limit
        allowed = current_count <= rate_limit.requests
        remaining = max(0, rate_limit.requests - current_count)
        reset_time = current_time + rate_limit.window_seconds
        
        if not allowed:
            # Remove the request we just added since it's rejected
            await self.redis_client.zrem(key, str(current_time))
        
        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time,
            retry_after=rate_limit.window_seconds if not allowed else None
        )
    
    def _check_memory_rate_limit(self, key: str, rate_limit: RateLimit) -> RateLimitResult:
        """Check rate limit using in-memory storage"""
        current_time = time.time()
        window_start = current_time - rate_limit.window_seconds
        
        with self._lock:
            # Clean old entries
            while self._memory_storage[key] and self._memory_storage[key][0] <= window_start:
                self._memory_storage[key].popleft()
            
            # Check burst limits if configured
            if rate_limit.burst_requests and rate_limit.burst_window_seconds:
                burst_key = f"{key}:burst"
                burst_window_start = current_time - rate_limit.burst_window_seconds
                
                # Clean old burst entries
                while self._memory_storage[burst_key] and self._memory_storage[burst_key][0] <= burst_window_start:
                    self._memory_storage[burst_key].popleft()
                
                if len(self._memory_storage[burst_key]) >= rate_limit.burst_requests:
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_time=current_time + rate_limit.burst_window_seconds,
                        retry_after=rate_limit.burst_window_seconds
                    )
                
                # Add to burst tracking
                self._memory_storage[burst_key].append(current_time)
            
            # Check main rate limit
            current_count = len(self._memory_storage[key])
            allowed = current_count < rate_limit.requests
            
            if allowed:
                self._memory_storage[key].append(current_time)
                remaining = rate_limit.requests - current_count - 1
            else:
                remaining = 0
            
            reset_time = current_time + rate_limit.window_seconds
            
            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=reset_time,
                retry_after=rate_limit.window_seconds if not allowed else None
            )
    
    async def check_rate_limit(self, request: Request, endpoint: str) -> RateLimitResult:
        """Check if request is within rate limits"""
        rate_limit = self.rate_limits.get(endpoint, self.rate_limits['api_general'])
        key = self._get_client_key(request, endpoint)
        
        try:
            if self.redis_client:
                return await self._check_redis_rate_limit(key, rate_limit)
            else:
                return self._check_memory_rate_limit(key, rate_limit)
        except Exception as e:
            logger.error(f"Rate limit check failed for {key}: {e}")
            # Allow request on error to avoid breaking the API
            return RateLimitResult(
                allowed=True,
                remaining=rate_limit.requests,
                reset_time=time.time() + rate_limit.window_seconds
            )
    
    async def increment_counter(self, request: Request, endpoint: str):
        """Manually increment counter for successful requests"""
        # This is handled automatically in check_rate_limit
        # Parameters kept for backward compatibility
        pass
    
    def get_rate_limit_info(self, endpoint: str) -> Dict:
        """Get rate limit configuration for an endpoint"""
        rate_limit = self.rate_limits.get(endpoint, self.rate_limits['api_general'])
        return {
            'requests_per_window': rate_limit.requests,
            'window_seconds': rate_limit.window_seconds,
            'burst_requests': rate_limit.burst_requests,
            'burst_window_seconds': rate_limit.burst_window_seconds,
        }
    
    async def get_usage_stats(self, request: Request, endpoint: str) -> Dict:
        """Get current usage statistics"""
        key = self._get_client_key(request, endpoint)
        rate_limit = self.rate_limits.get(endpoint, self.rate_limits['api_general'])
        
        try:
            if self.redis_client:
                current_time = time.time()
                window_start = current_time - rate_limit.window_seconds
                
                # Count requests in current window
                count = await self.redis_client.zcount(key, window_start, current_time)
                
                # Get burst count if applicable
                burst_count = 0
                if rate_limit.burst_requests and rate_limit.burst_window_seconds:
                    burst_key = f"{key}:burst"
                    burst_window_start = current_time - rate_limit.burst_window_seconds
                    burst_count = await self.redis_client.zcount(burst_key, burst_window_start, current_time)
                
                return {
                    'current_usage': count,
                    'limit': rate_limit.requests,
                    'window_seconds': rate_limit.window_seconds,
                    'burst_usage': burst_count,
                    'burst_limit': rate_limit.burst_requests,
                    'burst_window_seconds': rate_limit.burst_window_seconds,
                }
            else:
                with self._lock:
                    current_time = time.time()
                    window_start = current_time - rate_limit.window_seconds
                    
                    # Count valid entries
                    valid_entries = [t for t in self._memory_storage[key] if t > window_start]
                    
                    burst_count = 0
                    if rate_limit.burst_requests and rate_limit.burst_window_seconds:
                        burst_key = f"{key}:burst"
                        burst_window_start = current_time - rate_limit.burst_window_seconds
                        burst_entries = [t for t in self._memory_storage[burst_key] if t > burst_window_start]
                        burst_count = len(burst_entries)
                    
                    return {
                        'current_usage': len(valid_entries),
                        'limit': rate_limit.requests,
                        'window_seconds': rate_limit.window_seconds,
                        'burst_usage': burst_count,
                        'burst_limit': rate_limit.burst_requests,
                        'burst_window_seconds': rate_limit.burst_window_seconds,
                    }
        except Exception as e:
            logger.error(f"Failed to get usage stats for {key}: {e}")
            return {}

# Global rate limiter instance
_rate_limiter = None

def get_rate_limiter() -> SlidingWindowRateLimiter:
    """Get global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        # Try to get Redis URL from environment or config
        redis_url = os.getenv('REDIS_URL')
        _rate_limiter = SlidingWindowRateLimiter(redis_url)
    return _rate_limiter

async def init_rate_limiter():
    """Initialize rate limiter with Redis if available"""
    limiter = get_rate_limiter()
    await limiter.init_redis()

# Decorator for rate limiting - FIXED to preserve function signatures
def rate_limit(endpoint: str):
    """Decorator for applying rate limits to FastAPI endpoints"""
    def decorator(func):
        # Import functools here to avoid circular imports
        import functools
        
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                # Look in kwargs
                request = kwargs.get('request')
            
            if not request:
                # No request found, proceed without rate limiting
                logger.warning(f"No request object found for rate limiting on {func.__name__}")
                return await func(*args, **kwargs)
            
            # Check rate limit
            limiter = get_rate_limiter()
            result = await limiter.check_rate_limit(request, endpoint)
            
            if not result.allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        'error': 'Rate limit exceeded',
                        'endpoint': endpoint,
                        'retry_after': result.retry_after,
                        'reset_time': result.reset_time,
                    },
                    headers={
                        'Retry-After': str(result.retry_after) if result.retry_after else '60',
                        'X-RateLimit-Limit': str(limiter.rate_limits.get(endpoint, limiter.rate_limits['api_general']).requests),
                        'X-RateLimit-Remaining': str(result.remaining),
                        'X-RateLimit-Reset': str(int(result.reset_time)),
                    }
                )
            
            # Add rate limit headers to successful responses
            response = await func(*args, **kwargs)
            
            if hasattr(response, 'headers'):
                rate_limit_config = limiter.rate_limits.get(endpoint, limiter.rate_limits['api_general'])
                response.headers['X-RateLimit-Limit'] = str(rate_limit_config.requests)
                response.headers['X-RateLimit-Remaining'] = str(result.remaining)
                response.headers['X-RateLimit-Reset'] = str(int(result.reset_time))
            
            return response
        return wrapper
    return decorator