
# EMERGENCY Redis Configuration - Cost Optimized
# This configuration eliminates all automatic health checks

import os
import redis.asyncio as redis
from redis.asyncio.connection import ConnectionPool

REDIS_URL = os.getenv("REDIS_URL", "redis://devsecurex-redis:6379")

# CRITICAL: All health checks disabled
OPTIMAL_REDIS_CONFIG = {
    "health_check_interval": 0,  # DISABLED
    "socket_connect_timeout": 30,
    "socket_timeout": 60,
    "retry_on_timeout": True,
    "retry_on_error": [],
    "max_connections": 10,  # Reduced pool size
    "decode_responses": True
}

def create_cost_optimized_redis_client():
    """Create Redis client optimized for minimum cost"""
    return redis.from_url(REDIS_URL, **OPTIMAL_REDIS_CONFIG)

def create_cost_optimized_pool():
    """Create connection pool optimized for minimum cost"""
    return ConnectionPool.from_url(REDIS_URL, **OPTIMAL_REDIS_CONFIG)
