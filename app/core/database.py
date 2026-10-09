"""
Advanced database configuration for DevSecureX
Optimized connection pooling, intelligent health monitoring, and query retry mechanisms
"""
import os
import asyncio
import logging
import hashlib
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union, List, Tuple
from contextlib import asynccontextmanager
from collections import OrderedDict, defaultdict
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import text, event, Result
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DisconnectionError, TimeoutError, OperationalError, DBAPIError, InvalidRequestError
from sqlalchemy.exc import IntegrityError, StatementError
import uuid
from sqlalchemy.pool import QueuePool, Pool, StaticPool
from sqlalchemy.sql import Executable
from core.config import DATABASE_URL
import random
from enum import Enum

logger = logging.getLogger(__name__)

# Database operation types for load balancing
class DatabaseOperation(Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

# Database connection configuration
class DatabaseConnectionConfig:
    """Manage multiple database connections for load balancing"""
    
    def __init__(self):
        self.primary_url = DATABASE_URL
        self.read_replica_urls = self._parse_read_replicas()
        self.connection_weights = self._parse_connection_weights()
        self.failover_enabled = os.getenv("DB_FAILOVER_ENABLED", "true").lower() == "true"
        self.read_preference = os.getenv("DB_READ_PREFERENCE", "replica_preferred")  # replica_preferred, replica_only, primary_only
    
    def _parse_read_replicas(self) -> List[str]:
        """Parse read replica URLs from environment"""
        replicas_env = os.getenv("DATABASE_READ_REPLICAS", "")
        if not replicas_env:
            return []
        
        replicas = [url.strip() for url in replicas_env.split(",") if url.strip()]
        logger.info(f"Configured {len(replicas)} read replicas")
        return replicas
    
    def _parse_connection_weights(self) -> Dict[str, int]:
        """Parse connection weights for load balancing"""
        weights_env = os.getenv("DB_CONNECTION_WEIGHTS", "")
        if not weights_env:
            return {}
        
        weights = {}
        try:
            for weight_pair in weights_env.split(","):
                url, weight = weight_pair.split(":")
                weights[url.strip()] = int(weight.strip())
        except Exception as e:
            logger.warning(f"Failed to parse connection weights: {e}")
            return {}
        
        return weights
    
    def get_connection_url(self, operation: DatabaseOperation = DatabaseOperation.READ) -> str:
        """Get appropriate database URL based on operation type"""
        if operation == DatabaseOperation.WRITE or operation == DatabaseOperation.ADMIN:
            return self.primary_url
        
        # Read operation - check read preference
        if self.read_preference == "primary_only" or not self.read_replica_urls:
            return self.primary_url
        
        if self.read_preference == "replica_only" and self.read_replica_urls:
            return self._select_read_replica()
        
        # replica_preferred (default)
        if self.read_replica_urls:
            return self._select_read_replica()
        
        return self.primary_url
    
    def _select_read_replica(self) -> str:
        """Select read replica using weighted random selection"""
        if not self.read_replica_urls:
            return self.primary_url
        
        # If no weights configured, use simple random selection
        if not self.connection_weights:
            return random.choice(self.read_replica_urls)
        
        # Weighted selection
        weighted_urls = []
        for url in self.read_replica_urls:
            weight = self.connection_weights.get(url, 1)
            weighted_urls.extend([url] * weight)
        
        return random.choice(weighted_urls) if weighted_urls else self.read_replica_urls[0]
    
    def get_all_urls(self) -> List[Tuple[str, DatabaseOperation]]:
        """Get all database URLs with their preferred operations"""
        urls = [(self.primary_url, DatabaseOperation.WRITE)]
        for replica_url in self.read_replica_urls:
            urls.append((replica_url, DatabaseOperation.READ))
        return urls

# Global connection config
db_connection_config = DatabaseConnectionConfig()

# Validate primary DATABASE_URL
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not set")

if not (DATABASE_URL.startswith("postgresql+asyncpg://") or DATABASE_URL.startswith("sqlite+aiosqlite://")):
    raise ValueError("DATABASE_URL must use asyncpg driver (postgresql+asyncpg://) or sqlite+aiosqlite://")

# Advanced Database Configuration
class DatabaseConfig:
    """Advanced database configuration with environment-based optimization"""
    
    # Connection Pool Settings with intelligent sizing
    @staticmethod
    def get_optimal_pool_size() -> int:
        """Calculate optimal pool size based on environment and available resources"""
        base_size = int(os.getenv("DB_POOL_SIZE", "50"))  # CRITICAL FIX: Increased to 50 for better concurrency
        
        # CRITICAL FIX: Always respect the explicit DB_POOL_SIZE environment variable
        if os.getenv("DB_POOL_SIZE"):
            return min(base_size, 80)  # Respect env var but cap at 80 for safety
        
        # Adjust based on environment only if no explicit pool size set
        app_env = os.getenv("APP_ENV", "production").lower()
        if app_env in ["development", "local"]:
            return max(20, min(40, base_size))  # CRITICAL FIX: Increased minimum from 5 to 20 for local dev
        elif app_env == "testing":
            return max(10, min(20, base_size // 2))  # CRITICAL FIX: Increased testing pool from 2-5 to 10-20
        
        # Production: More conservative sizing to prevent exhaustion
        try:
            import psutil
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
            if available_memory_gb < 1:  # Less than 1GB available
                return max(20, min(30, base_size // 2))  # Increased minimums for better concurrency
            elif available_memory_gb < 2:  # Less than 2GB available
                return max(25, min(35, base_size // 1.5))  # Increased minimums for better concurrency
        except Exception:
            pass  # Fallback to base size if psutil fails
        
        # CRITICAL FIX: Cap maximum pool size to prevent resource exhaustion
        return min(base_size, 80)  # Allow up to 80 connections in pool for better concurrency
    
    @staticmethod
    def get_optimal_overflow(pool_size: Optional[int] = None) -> int:
        """Calculate optimal overflow based on pool size"""
        if pool_size is None:
            pool_size = DatabaseConfig.get_optimal_pool_size()
        base_overflow = int(os.getenv("DB_MAX_OVERFLOW", "80"))  # CRITICAL FIX: Increased to 80 for better overflow handling
        
        # CRITICAL FIX: More generous overflow calculation to prevent exhaustion
        optimal_overflow = max(base_overflow, int(pool_size * 1.5))  # Increased back to 1.5x for safety
        return min(optimal_overflow, 100)  # Cap at 100 overflow connections for better handling
    
    POOL_SIZE = get_optimal_pool_size()
    MAX_OVERFLOW = get_optimal_overflow(POOL_SIZE)
    POOL_TIMEOUT = int(os.getenv("DB_POOL_TIMEOUT", "60"))  # Increased from 30
    POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))  # 1 hour
    POOL_PRE_PING = os.getenv("DB_POOL_PRE_PING", "true").lower() == "true"
    POOL_PRE_WARM = os.getenv("DB_POOL_PRE_WARM", "true").lower() == "true"
    PRE_WARM_SIZE = int(os.getenv("DB_PRE_WARM_SIZE", str(max(2, POOL_SIZE // 4))))
    
    # Health Monitoring
    HEALTH_CHECK_INTERVAL = int(os.getenv("DB_HEALTH_CHECK_INTERVAL", "30"))  # seconds
    MAX_RETRIES = int(os.getenv("DB_MAX_RETRIES", "3"))
    RETRY_DELAY = float(os.getenv("DB_RETRY_DELAY", "0.5"))  # seconds
    
    # Query Optimization
    QUERY_TIMEOUT = int(os.getenv("DB_QUERY_TIMEOUT", "30"))  # seconds
    ENABLE_QUERY_CACHE = os.getenv("DB_ENABLE_QUERY_CACHE", "true").lower() == "true"
    
    # CRITICAL FIX: More conservative connection monitoring thresholds
    POOL_HIGH_USAGE_THRESHOLD = float(os.getenv("DB_POOL_HIGH_USAGE_THRESHOLD", "0.7"))  # 70% (reduced from 80%)
    POOL_CRITICAL_USAGE_THRESHOLD = float(os.getenv("DB_POOL_CRITICAL_USAGE_THRESHOLD", "0.85"))  # 85% (reduced from 95%)

# Advanced query cache with LRU eviction
class QueryCache:
    """Thread-safe LRU query cache with TTL support"""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache = OrderedDict()
        self.timestamps = {}
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
    
    def _generate_key(self, query: str, params: tuple = None) -> str:
        """Generate cache key from query and parameters"""
        key_data = query + str(params or ())
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _is_expired(self, key: str) -> bool:
        """Check if cache entry is expired"""
        if key not in self.timestamps:
            return True
        return (time.time() - self.timestamps[key]) > self.ttl_seconds
    
    def _evict_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = [
            key for key, timestamp in self.timestamps.items()
            if (current_time - timestamp) > self.ttl_seconds
        ]
        for key in expired_keys:
            self.cache.pop(key, None)
            self.timestamps.pop(key, None)
            self.evictions += 1
    
    def get(self, query: str, params: tuple = None) -> Optional[Any]:
        """Get cached result"""
        key = self._generate_key(query, params)
        
        with self.lock:
            self._evict_expired()
            
            if key in self.cache and not self._is_expired(key):
                # Move to end (most recently used)
                self.cache.move_to_end(key)
                self.hits += 1
                return self.cache[key]
            
            self.misses += 1
            return None
    
    def set(self, query: str, result: Any, params: tuple = None):
        """Cache query result"""
        key = self._generate_key(query, params)
        
        with self.lock:
            # Remove oldest entries if at max capacity
            while len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                self.cache.pop(oldest_key)
                self.timestamps.pop(oldest_key, None)
                self.evictions += 1
            
            self.cache[key] = result
            self.timestamps[key] = time.time()
    
    def clear(self):
        """Clear all cached entries"""
        with self.lock:
            self.cache.clear()
            self.timestamps.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate_percent": round(hit_rate, 2),
                "evictions": self.evictions,
                "ttl_seconds": self.ttl_seconds
            }

# Query performance monitoring
class QueryPerformanceMonitor:
    """Monitor query performance and detect slow queries"""
    
    def __init__(self):
        self.query_times = defaultdict(list)
        self.slow_queries = []
        self.slow_query_threshold = float(os.getenv("DB_SLOW_QUERY_THRESHOLD", "1.0"))  # seconds
        self.max_slow_queries = int(os.getenv("DB_MAX_SLOW_QUERIES_LOG", "100"))
        self.lock = threading.Lock()
    
    def record_query(self, query: str, duration: float, params: tuple = None):
        """Record query execution time"""
        with self.lock:
            # Normalize query for grouping (remove specific values)
            normalized_query = self._normalize_query(query)
            self.query_times[normalized_query].append(duration)
            
            # Keep only last 100 executions per query
            if len(self.query_times[normalized_query]) > 100:
                self.query_times[normalized_query] = self.query_times[normalized_query][-100:]
            
            # Log slow queries
            if duration > self.slow_query_threshold:
                slow_query_info = {
                    "query": query[:500],  # Truncate long queries
                    "duration": duration,
                    "params": str(params)[:200] if params else None,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                self.slow_queries.append(slow_query_info)
                # Keep only recent slow queries
                if len(self.slow_queries) > self.max_slow_queries:
                    self.slow_queries = self.slow_queries[-self.max_slow_queries:]
                
                logger.warning(f"Slow query detected ({duration:.3f}s): {query[:100]}...")
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query by removing specific values"""
        # Simple normalization - replace common patterns
        import re
        normalized = re.sub(r"'[^']*'", "?", query)  # Replace string literals
        normalized = re.sub(r"\b\d+\b", "?", normalized)  # Replace numbers
        return normalized
    
    def get_query_stats(self) -> Dict[str, Any]:
        """Get query performance statistics"""
        with self.lock:
            stats = {
                "total_query_types": len(self.query_times),
                "slow_queries_count": len(self.slow_queries),
                "slow_query_threshold": self.slow_query_threshold,
                "recent_slow_queries": self.slow_queries[-10:],  # Last 10 slow queries
                "query_performance": {}
            }
            
            # Calculate performance stats for each query type
            for query, times in self.query_times.items():
                if times:
                    stats["query_performance"][query[:100]] = {
                        "count": len(times),
                        "avg_duration": round(sum(times) / len(times), 4),
                        "max_duration": round(max(times), 4),
                        "min_duration": round(min(times), 4)
                    }
            
            return stats
    
    def clear_stats(self):
        """Clear all performance statistics"""
        with self.lock:
            self.query_times.clear()
            self.slow_queries.clear()

# Advanced transaction management
class TransactionManager:
    """Advanced transaction management with deadlock detection and retry logic"""
    
    def __init__(self):
        self.active_transactions = {}
        self.deadlock_events = 0
        self.transaction_retries = 0
        self.transaction_timeouts = 0
        self.lock = threading.Lock()
        self.max_retry_attempts = int(os.getenv("DB_TRANSACTION_MAX_RETRIES", "3"))
        self.deadlock_retry_delay = float(os.getenv("DB_DEADLOCK_RETRY_DELAY", "0.1"))
        self.transaction_timeout = int(os.getenv("DB_TRANSACTION_TIMEOUT", "30"))  # seconds
    
    def start_transaction(self, session_id: str = None) -> str:
        """Start tracking a new transaction"""
        if session_id is None:
            session_id = str(uuid.uuid4())
        
        with self.lock:
            self.active_transactions[session_id] = {
                "start_time": time.time(),
                "retry_count": 0,
                "operations": []
            }
        
        return session_id
    
    def end_transaction(self, session_id: str, success: bool = True):
        """End transaction tracking"""
        with self.lock:
            if session_id in self.active_transactions:
                transaction_info = self.active_transactions.pop(session_id)
                duration = time.time() - transaction_info["start_time"]
                
                if duration > self.transaction_timeout:
                    self.transaction_timeouts += 1
                    logger.warning(f"Long-running transaction detected: {duration:.2f}s (session: {session_id})")
    
    def record_deadlock(self, session_id: str, error: Exception):
        """Record deadlock event"""
        with self.lock:
            self.deadlock_events += 1
            
            if session_id in self.active_transactions:
                self.active_transactions[session_id]["retry_count"] += 1
        
        logger.warning(f"Deadlock detected in transaction {session_id}: {error}")
    
    def is_deadlock_error(self, error: Exception) -> bool:
        """Check if error is a deadlock"""
        error_str = str(error).lower()
        deadlock_indicators = [
            "deadlock detected",
            "deadlock found",
            "lock wait timeout",
            "could not serialize access",
            "serialization_failure"
        ]
        return any(indicator in error_str for indicator in deadlock_indicators)
    
    def should_retry_transaction(self, session_id: str, error: Exception) -> bool:
        """Determine if transaction should be retried"""
        if not self.is_deadlock_error(error):
            return False
        
        with self.lock:
            if session_id not in self.active_transactions:
                return False
            
            retry_count = self.active_transactions[session_id]["retry_count"]
            return retry_count < self.max_retry_attempts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get transaction management statistics"""
        with self.lock:
            return {
                "active_transactions": len(self.active_transactions),
                "deadlock_events": self.deadlock_events,
                "transaction_retries": self.transaction_retries,
                "transaction_timeouts": self.transaction_timeouts,
                "configuration": {
                    "max_retry_attempts": self.max_retry_attempts,
                    "deadlock_retry_delay": self.deadlock_retry_delay,
                    "transaction_timeout": self.transaction_timeout
                }
            }
    
    def get_long_running_transactions(self, threshold_seconds: int = None) -> List[Dict[str, Any]]:
        """Get list of long-running transactions"""
        if threshold_seconds is None:
            threshold_seconds = self.transaction_timeout // 2
        
        current_time = time.time()
        long_running = []
        
        with self.lock:
            for session_id, info in self.active_transactions.items():
                duration = current_time - info["start_time"]
                if duration > threshold_seconds:
                    long_running.append({
                        "session_id": session_id,
                        "duration_seconds": round(duration, 2),
                        "retry_count": info["retry_count"],
                        "operations_count": len(info["operations"])
                    })
        
        return long_running

# Global instances
query_cache = QueryCache(
    max_size=int(os.getenv("DB_CACHE_SIZE", "1000")),
    ttl_seconds=int(os.getenv("DB_CACHE_TTL", "300"))
)
query_monitor = QueryPerformanceMonitor()
transaction_manager = TransactionManager()

# Global metrics tracking
class DatabaseMetrics:
    """Track database connection pool and query metrics"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.total_connections = 0
        self.active_connections = 0
        self.pool_hits = 0
        self.pool_misses = 0
        self.query_count = 0
        self.failed_queries = 0
        self.retry_count = 0
        self.last_health_check = None
        self.connection_errors = []
    
    def record_connection_error(self, error: str):
        """Record connection error with timestamp"""
        self.connection_errors.append({
            "error": error,
            "timestamp": datetime.utcnow()
        })
        # Keep only last 10 errors
        self.connection_errors = self.connection_errors[-10:]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current database metrics with enhanced monitoring"""
        base_metrics = {
            "total_connections": self.total_connections,
            "active_connections": self.active_connections,
            "pool_hits": self.pool_hits,
            "pool_misses": self.pool_misses,
            "query_count": self.query_count,
            "failed_queries": self.failed_queries,
            "retry_count": self.retry_count,
            "last_health_check": self.last_health_check,
            "recent_errors": len(self.connection_errors),
            "pool_efficiency": (
                self.pool_hits / (self.pool_hits + self.pool_misses) * 100
                if (self.pool_hits + self.pool_misses) > 0 else 0
            )
        }
        
        # Add enhanced monitoring metrics
        base_metrics["query_cache"] = query_cache.get_stats()
        base_metrics["query_performance"] = query_monitor.get_query_stats()
        base_metrics["transaction_management"] = transaction_manager.get_stats()
        base_metrics["long_running_transactions"] = transaction_manager.get_long_running_transactions()
        
        return base_metrics

# Pool health monitoring
class ConnectionPoolMonitor:
    """Monitor connection pool health and performance"""
    
    def __init__(self):
        self.pool_usage_history = []
        self.last_warning_time = {}
        self.connection_creation_times = []
        self.pool_exhaustion_events = 0
        self.max_history_size = 100
        self.lock = threading.Lock()
    
    def record_pool_usage(self, pool_status: Dict[str, Any]):
        """Record current pool usage metrics"""
        with self.lock:
            usage_info = {
                "timestamp": time.time(),
                "checked_out": pool_status.get("checked_out", 0),
                "pool_size": pool_status.get("pool_size", 0),
                "overflow": pool_status.get("overflow", 0),
                "usage_percent": self._calculate_usage_percent(pool_status)
            }
            
            self.pool_usage_history.append(usage_info)
            
            # Keep only recent history
            if len(self.pool_usage_history) > self.max_history_size:
                self.pool_usage_history = self.pool_usage_history[-self.max_history_size:]
            
            # Check for pool exhaustion
            if usage_info["usage_percent"] > DatabaseConfig.POOL_CRITICAL_USAGE_THRESHOLD * 100:
                self.pool_exhaustion_events += 1
                self._log_pool_warning("critical", usage_info)
            elif usage_info["usage_percent"] > DatabaseConfig.POOL_HIGH_USAGE_THRESHOLD * 100:
                self._log_pool_warning("high", usage_info)
    
    def _calculate_usage_percent(self, pool_status: Dict[str, Any]) -> float:
        """Calculate pool usage percentage"""
        checked_out = pool_status.get("checked_out", 0)
        pool_size = pool_status.get("pool_size", 1)
        overflow = pool_status.get("overflow", 0)
        total_available = pool_size + overflow
        
        return (checked_out / total_available * 100) if total_available > 0 else 0
    
    def _log_pool_warning(self, level: str, usage_info: Dict[str, Any]):
        """Log pool usage warnings with throttling"""
        current_time = time.time()
        warning_key = f"{level}_usage"
        
        # Throttle warnings to once per minute
        if warning_key not in self.last_warning_time or \
           (current_time - self.last_warning_time[warning_key]) > 60:
            
            self.last_warning_time[warning_key] = current_time
            
            if level == "critical":
                logger.error(f"CRITICAL: Database pool usage at {usage_info['usage_percent']:.1f}% "
                           f"({usage_info['checked_out']} connections in use)")
            else:
                logger.warning(f"HIGH: Database pool usage at {usage_info['usage_percent']:.1f}% "
                             f"({usage_info['checked_out']} connections in use)")
    
    def get_pool_health_stats(self) -> Dict[str, Any]:
        """Get pool health statistics"""
        with self.lock:
            if not self.pool_usage_history:
                return {"status": "no_data"}
            
            recent_usage = self.pool_usage_history[-10:]  # Last 10 readings
            avg_usage = sum(reading["usage_percent"] for reading in recent_usage) / len(recent_usage)
            max_usage = max(reading["usage_percent"] for reading in recent_usage)
            
            status = "healthy"
            if max_usage > DatabaseConfig.POOL_CRITICAL_USAGE_THRESHOLD * 100:
                status = "critical"
            elif avg_usage > DatabaseConfig.POOL_HIGH_USAGE_THRESHOLD * 100:
                status = "warning"
            
            return {
                "status": status,
                "average_usage_percent": round(avg_usage, 2),
                "max_usage_percent": round(max_usage, 2),
                "pool_exhaustion_events": self.pool_exhaustion_events,
                "readings_count": len(self.pool_usage_history),
                "thresholds": {
                    "high_usage": DatabaseConfig.POOL_HIGH_USAGE_THRESHOLD * 100,
                    "critical_usage": DatabaseConfig.POOL_CRITICAL_USAGE_THRESHOLD * 100
                }
            }

# Global instances
db_metrics = DatabaseMetrics()
pool_monitor = ConnectionPoolMonitor()

# Advanced engine configuration
engine_kwargs = {
    "echo": os.getenv("SQL_DEBUG", "false").lower() == "true",
    "future": True,
    "pool_pre_ping": DatabaseConfig.POOL_PRE_PING,
    "pool_recycle": DatabaseConfig.POOL_RECYCLE,
}

# Configure pooling based on environment
if os.getenv("TESTING_MODE", "false").lower() == "true":
    from sqlalchemy.pool import NullPool
    engine_kwargs["poolclass"] = NullPool
    logger.info("Using NullPool for testing mode")
else:
    # Advanced production pooling - use default async-compatible pooling
    engine_kwargs.update({
        "pool_size": DatabaseConfig.POOL_SIZE,
        "max_overflow": DatabaseConfig.MAX_OVERFLOW,
        "pool_timeout": DatabaseConfig.POOL_TIMEOUT,
        "pool_reset_on_return": "commit",  # Reset connections on return
    })
    logger.info(f"Advanced async pooling configured: size={DatabaseConfig.POOL_SIZE}, "
                f"overflow={DatabaseConfig.MAX_OVERFLOW}, timeout={DatabaseConfig.POOL_TIMEOUT}s")

# Connection pool manager for multiple databases
class DatabaseEngineManager:
    """Manage multiple database engines for load balancing"""
    
    def __init__(self):
        self.engines = {}
        self.engine_health = {}
        self.connection_counts = defaultdict(int)
        self.last_health_check = {}
        self._create_engines()
    
    def _create_engines(self):
        """Create engines for primary and replica databases"""
        # Primary engine
        self.engines['primary'] = create_async_engine(DATABASE_URL, **engine_kwargs)
        self.engine_health['primary'] = True
        logger.info(f"Created primary database engine")
        
        # Replica engines
        for i, replica_url in enumerate(db_connection_config.read_replica_urls):
            engine_key = f'replica_{i}'
            try:
                # Validate replica URL format
                if not (replica_url.startswith("postgresql+asyncpg://") or replica_url.startswith("sqlite+aiosqlite://")):
                    logger.warning(f"Invalid replica URL format: {replica_url}")
                    continue
                
                self.engines[engine_key] = create_async_engine(replica_url, **engine_kwargs)
                self.engine_health[engine_key] = True
                logger.info(f"Created replica database engine: {engine_key}")
            except Exception as e:
                logger.error(f"Failed to create replica engine {engine_key}: {e}")
                self.engine_health[engine_key] = False
    
    def get_engine(self, operation: DatabaseOperation = DatabaseOperation.READ):
        """Get appropriate engine based on operation and health status"""
        if operation in [DatabaseOperation.WRITE, DatabaseOperation.ADMIN]:
            return self.engines['primary']
        
        # For read operations, try to use healthy replica
        healthy_replicas = [
            key for key, engine in self.engines.items() 
            if key.startswith('replica_') and self.engine_health.get(key, False)
        ]
        
        if healthy_replicas and db_connection_config.read_preference != 'primary_only':
            # Select replica with least connections (load balancing)
            selected_replica = min(healthy_replicas, key=lambda x: self.connection_counts[x])
            self.connection_counts[selected_replica] += 1
            return self.engines[selected_replica]
        
        # Fallback to primary
        self.connection_counts['primary'] += 1
        return self.engines['primary']
    
    async def check_engine_health(self, engine_key: str) -> bool:
        """Check health of a specific engine"""
        if engine_key not in self.engines:
            return False
        
        try:
            engine = self.engines[engine_key]
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            
            self.engine_health[engine_key] = True
            return True
            
        except Exception as e:
            logger.warning(f"Engine {engine_key} health check failed: {e}")
            self.engine_health[engine_key] = False
            return False
    
    async def check_all_engines_health(self) -> Dict[str, bool]:
        """Check health of all engines"""
        health_results = {}
        
        for engine_key in self.engines.keys():
            health_results[engine_key] = await self.check_engine_health(engine_key)
        
        return health_results
    
    def get_engine_stats(self) -> Dict[str, Any]:
        """Get statistics for all engines"""
        return {
            "engines": list(self.engines.keys()),
            "engine_health": self.engine_health.copy(),
            "connection_counts": dict(self.connection_counts),
            "total_engines": len(self.engines),
            "healthy_engines": sum(1 for health in self.engine_health.values() if health),
            "read_replicas_count": len([k for k in self.engines.keys() if k.startswith('replica_')]),
            "configuration": {
                "read_preference": db_connection_config.read_preference,
                "failover_enabled": db_connection_config.failover_enabled
            }
        }
    
    async def close_all_engines(self):
        """Close all database engines"""
        for engine_key, engine in self.engines.items():
            try:
                await engine.dispose()
                logger.info(f"Closed engine: {engine_key}")
            except Exception as e:
                logger.error(f"Error closing engine {engine_key}: {e}")

# Global engine manager
engine_manager = DatabaseEngineManager()

# Backward compatibility - primary engine
engine = engine_manager.engines['primary']

async def pre_warm_connection_pool():
    """Pre-warm the connection pool to improve initial performance"""
    if not DatabaseConfig.POOL_PRE_WARM:
        logger.info("Connection pool pre-warming disabled")
        return
    
    pre_warm_size = DatabaseConfig.PRE_WARM_SIZE
    logger.info(f"Pre-warming connection pool with {pre_warm_size} connections...")
    
    connections = []
    try:
        start_time = time.time()
        
        # Create initial connections
        for i in range(pre_warm_size):
            try:
                conn = await engine.connect()
                # Test the connection
                await conn.execute(text("SELECT 1"))
                connections.append(conn)
                logger.debug(f"Pre-warmed connection {i + 1}/{pre_warm_size}")
            except Exception as e:
                logger.warning(f"Failed to pre-warm connection {i + 1}: {e}")
        
        # Close connections to return them to pool
        for conn in connections:
            try:
                await conn.close()
            except Exception as e:
                logger.warning(f"Error closing pre-warmed connection: {e}")
        
        elapsed = time.time() - start_time
        logger.info(f"Connection pool pre-warming completed: {len(connections)}/{pre_warm_size} "
                   f"connections in {elapsed:.2f}s")
        
    except Exception as e:
        logger.error(f"Connection pool pre-warming failed: {e}")
        # Clean up any connections that were created
        for conn in connections:
            try:
                await conn.close()
            except Exception:
                pass

# Add connection pool event listeners for metrics tracking
@event.listens_for(engine.sync_engine, "connect")
def on_connect(dbapi_connection, connection_record):
    """Track new connections"""
    db_metrics.total_connections += 1
    logger.debug(f"New database connection created. Total: {db_metrics.total_connections}")

@event.listens_for(engine.sync_engine, "checkout")
def on_checkout(dbapi_connection, connection_record, connection_proxy):
    """Track connection checkout from pool"""
    db_metrics.active_connections += 1
    db_metrics.pool_hits += 1
    
    # Record pool usage for monitoring
    try:
        pool = engine.pool
        pool_status = {
            "pool_size": getattr(pool, 'size', lambda: 0)() if callable(getattr(pool, 'size', 0)) else getattr(pool, 'size', 0),
            "checked_out": getattr(pool, 'checkedout', lambda: 0)() if callable(getattr(pool, 'checkedout', 0)) else getattr(pool, 'checkedout', 0),
            "overflow": getattr(pool, 'overflow', lambda: 0)() if callable(getattr(pool, 'overflow', 0)) else getattr(pool, 'overflow', 0),
        }
        pool_monitor.record_pool_usage(pool_status)
    except Exception as e:
        logger.debug(f"Failed to record pool usage on checkout: {e}")

@event.listens_for(engine.sync_engine, "checkin")
def on_checkin(dbapi_connection, connection_record):
    """Track connection checkin to pool"""
    db_metrics.active_connections = max(0, db_metrics.active_connections - 1)

@event.listens_for(engine.sync_engine, "invalidate")
def on_invalidate(dbapi_connection, connection_record, exception):
    """Track connection invalidations"""
    if exception:
        error_msg = str(exception)
        db_metrics.record_connection_error(error_msg)
        logger.warning(f"Database connection invalidated: {error_msg}")

# Session factory with advanced configuration
async_session = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=True,  # Automatically flush before queries
    autocommit=False
)

class Base(AsyncAttrs, DeclarativeBase):
    pass

async def execute_with_cache_and_retry(session: AsyncSession, query: Union[str, Executable], 
                                       params: tuple = None, max_retries: int = None,
                                       use_cache: bool = True) -> Result:
    """Execute query with caching and intelligent retry logic"""
    if max_retries is None:
        max_retries = DatabaseConfig.MAX_RETRIES
    
    # Convert query to string for caching
    query_str = str(query) if not isinstance(query, str) else query
    
    # Try cache first (only for SELECT queries and if caching is enabled)
    if use_cache and DatabaseConfig.ENABLE_QUERY_CACHE and query_str.strip().upper().startswith('SELECT'):
        cached_result = query_cache.get(query_str, params)
        if cached_result is not None:
            logger.debug(f"Query cache hit: {query_str[:100]}...")
            return cached_result
    
    last_exception = None
    start_time = time.time()
    
    for attempt in range(max_retries + 1):
        try:
            db_metrics.query_count += 1
            
            # Execute query
            if isinstance(query, str):
                if params:
                    result = await session.execute(text(query), params)
                else:
                    result = await session.execute(text(query))
            else:
                result = await session.execute(query)
            
            # Record performance
            duration = time.time() - start_time
            query_monitor.record_query(query_str, duration, params)
            
            # Cache result for SELECT queries
            if (use_cache and DatabaseConfig.ENABLE_QUERY_CACHE and 
                query_str.strip().upper().startswith('SELECT')):
                query_cache.set(query_str, result, params)
            
            return result
            
        except (DisconnectionError, TimeoutError, OperationalError, DBAPIError) as e:
            last_exception = e
            db_metrics.failed_queries += 1
            
            # Record failed query performance
            duration = time.time() - start_time
            query_monitor.record_query(f"FAILED: {query_str}", duration, params)
            
            if attempt < max_retries:
                db_metrics.retry_count += 1
                retry_delay = DatabaseConfig.RETRY_DELAY * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Database query failed (attempt {attempt + 1}/{max_retries + 1}), "
                              f"retrying in {retry_delay}s: {str(e)}")
                await asyncio.sleep(retry_delay)
                
                # Try to rollback and refresh the session
                try:
                    await session.rollback()
                except Exception:
                    pass  # Ignore rollback errors during retry
                
                # Reset timer for retry
                start_time = time.time()
            else:
                logger.error(f"Database query failed after {max_retries + 1} attempts: {str(e)}")
                db_metrics.record_connection_error(str(e))
    
    raise last_exception

# Backward compatibility alias
execute_with_retry = execute_with_cache_and_retry

@asynccontextmanager
async def get_db_session(operation: DatabaseOperation = DatabaseOperation.READ):
    """Advanced database session context manager with transaction management and retry logic"""
    selected_engine = engine_manager.get_engine(operation)
    session_factory = sessionmaker(
        selected_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=True,
        autocommit=False
    )
    
    session_id = transaction_manager.start_transaction()
    max_retries = transaction_manager.max_retry_attempts
    
    for attempt in range(max_retries + 1):
        async with session_factory() as session:
            try:
                transaction_manager.active_transactions[session_id]["operations"].append(f"attempt_{attempt + 1}")
                
                yield session
                await session.commit()
                
                # Success - end transaction tracking
                transaction_manager.end_transaction(session_id, success=True)
                return
                
            except Exception as e:
                try:
                    await session.rollback()
                except Exception as rollback_error:
                    logger.error(f"Failed to rollback transaction: {rollback_error}")
                
                # Check if this is a deadlock that should be retried
                if transaction_manager.should_retry_transaction(session_id, e):
                    transaction_manager.record_deadlock(session_id, e)
                    transaction_manager.transaction_retries += 1
                    
                    if attempt < max_retries:
                        retry_delay = transaction_manager.deadlock_retry_delay * (2 ** attempt)
                        logger.warning(f"Retrying transaction {session_id} after deadlock "
                                     f"(attempt {attempt + 2}/{max_retries + 1}) in {retry_delay:.3f}s")
                        await asyncio.sleep(retry_delay)
                        continue
                
                # Not a retryable error or max retries reached
                transaction_manager.end_transaction(session_id, success=False)
                raise e
    
    # Should not reach here, but handle gracefully
    transaction_manager.end_transaction(session_id, success=False)
    raise Exception(f"Transaction {session_id} failed after {max_retries + 1} attempts")

@asynccontextmanager
async def get_db_transaction(operation: DatabaseOperation = DatabaseOperation.WRITE, 
                           isolation_level: str = None):
    """Advanced database transaction context manager with custom isolation levels"""
    selected_engine = engine_manager.get_engine(operation)
    session_factory = sessionmaker(
        selected_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=True,
        autocommit=False
    )
    
    session_id = transaction_manager.start_transaction()
    
    async with session_factory() as session:
        try:
            # Set isolation level if specified
            if isolation_level:
                await session.execute(text(f"SET TRANSACTION ISOLATION LEVEL {isolation_level}"))
                transaction_manager.active_transactions[session_id]["operations"].append(f"isolation_level_{isolation_level}")
            
            async with session.begin():
                yield session
                
            transaction_manager.end_transaction(session_id, success=True)
            
        except Exception as e:
            try:
                await session.rollback()
            except Exception as rollback_error:
                logger.error(f"Failed to rollback transaction: {rollback_error}")
            
            transaction_manager.end_transaction(session_id, success=False)
            
            # Record deadlock if applicable
            if transaction_manager.is_deadlock_error(e):
                transaction_manager.record_deadlock(session_id, e)
            
            raise e

async def get_db(operation: DatabaseOperation = DatabaseOperation.READ):
    """Advanced database session dependency with load balancing and health monitoring"""
    selected_engine = engine_manager.get_engine(operation)
    session_factory = sessionmaker(
        selected_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=True,
        autocommit=False
    )
    
    async with session_factory() as session:
        try:
            # Test connection health if needed
            if await _should_health_check():
                await _perform_health_check(session)
            
            yield session
            await session.commit()
        except Exception as e:
            try:
                await session.rollback()
            except Exception as rollback_error:
                logger.error(f"Failed to rollback transaction: {rollback_error}")
            
            # Record the error for monitoring
            db_metrics.failed_queries += 1
            db_metrics.record_connection_error(str(e))
            raise e

# Convenience functions for different operation types
async def get_db_read():
    """Get database session optimized for read operations"""
    async for session in get_db(DatabaseOperation.READ):
        yield session

async def get_db_write():
    """Get database session for write operations (always uses primary)"""
    async for session in get_db(DatabaseOperation.WRITE):
        yield session

async def _should_health_check() -> bool:
    """Determine if a health check is needed"""
    if not db_metrics.last_health_check:
        return True
    
    time_since_check = datetime.utcnow() - db_metrics.last_health_check
    return time_since_check.total_seconds() > DatabaseConfig.HEALTH_CHECK_INTERVAL

async def _perform_health_check(session: AsyncSession):
    """Perform intelligent health check"""
    try:
        await session.execute(text("SELECT 1"))
        db_metrics.last_health_check = datetime.utcnow()
        logger.debug("Database health check passed")
    except Exception as e:
        logger.warning(f"Database health check failed: {str(e)}")
        db_metrics.record_connection_error(f"Health check failed: {str(e)}")
        # Don't raise the exception - let the actual query handle retries

async def create_tables():
    """Create all database tables with connection pool pre-warming"""
    try:
        # Pre-warm connection pool first
        await pre_warm_connection_pool()
        
        # Use begin() transaction for DDL operations to ensure proper commit
        async with engine.begin() as conn:
            logger.info("Starting database table creation transaction...")
            await conn.run_sync(Base.metadata.create_all, checkfirst=True)
            logger.info("Database tables created successfully - transaction will commit")
            # Transaction is automatically committed when exiting the context manager
            
    except Exception as e:
        error_str = str(e).lower()
        # Ignore duplicate index/table errors - they're harmless
        if any(phrase in error_str for phrase in [
            "already exists", "duplicate", "constraint", "index"
        ]):
            logger.info(f"Tables/indexes already exist (harmless): {e}")
        else:
            # Re-raise other errors
            logger.error(f"Failed to create database tables: {e}")
            raise

async def test_connection():
    """Advanced database connection test with load balancing metrics"""
    try:
        start_time = datetime.utcnow()
        
        # Test primary connection
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Test all engine health
        engine_health = await engine_manager.check_all_engines_health()
        
        return {
            "status": "healthy",
            "response_time_ms": round(response_time * 1000, 2),
            "pool_size": DatabaseConfig.POOL_SIZE,
            "max_overflow": DatabaseConfig.MAX_OVERFLOW,
            "metrics": db_metrics.get_metrics(),
            "load_balancing": {
                "engine_health": engine_health,
                "engine_stats": engine_manager.get_engine_stats()
            }
        }
    except Exception as e:
        db_metrics.record_connection_error(str(e))
        engine_health = await engine_manager.check_all_engines_health()
        
        return {
            "status": "unhealthy",
            "error": str(e),
            "metrics": db_metrics.get_metrics(),
            "load_balancing": {
                "engine_health": engine_health,
                "engine_stats": engine_manager.get_engine_stats()
            }
        }

async def get_pool_status():
    """Get detailed connection pool status with enhanced monitoring"""
    try:
        pool = engine.pool
        pool_info = {
            "pool_size": getattr(pool, 'size', 'N/A'),
            "checked_in": getattr(pool, 'checkedin', 'N/A'),
            "checked_out": getattr(pool, 'checkedout', 'N/A'),
            "overflow": getattr(pool, 'overflow', 'N/A'),
            "invalid": getattr(pool, 'invalid', 'N/A'),
            "metrics": db_metrics.get_metrics(),
            "pool_health": pool_monitor.get_pool_health_stats(),
            "configuration": {
                "pool_size": DatabaseConfig.POOL_SIZE,
                "max_overflow": DatabaseConfig.MAX_OVERFLOW,
                "pre_warm_enabled": DatabaseConfig.POOL_PRE_WARM,
                "pre_warm_size": DatabaseConfig.PRE_WARM_SIZE,
                "high_usage_threshold": f"{DatabaseConfig.POOL_HIGH_USAGE_THRESHOLD * 100}%",
                "critical_usage_threshold": f"{DatabaseConfig.POOL_CRITICAL_USAGE_THRESHOLD * 100}%"
            }
        }
        
        # Calculate usage percentage
        if pool_info["pool_size"] != 'N/A' and pool_info["checked_out"] != 'N/A':
            total_available = pool_info["pool_size"] + (pool_info["overflow"] if pool_info["overflow"] != 'N/A' else 0)
            usage_percent = (pool_info["checked_out"] / total_available * 100) if total_available > 0 else 0
            pool_info["usage_percent"] = round(usage_percent, 2)
        
        return pool_info
        
    except Exception as e:
        logger.error(f"Failed to get pool status: {e}")
        return {"error": str(e), "metrics": db_metrics.get_metrics()}

async def reset_metrics():
    """Reset database metrics for monitoring"""
    db_metrics.reset()
    query_cache.clear()
    query_monitor.clear_stats()
    # Note: We don't reset transaction_manager stats as they may contain active transactions
    logger.info("Database metrics, cache, and performance stats reset")

async def get_transaction_stats() -> Dict[str, Any]:
    """Get detailed transaction statistics"""
    return {
        "transaction_stats": transaction_manager.get_stats(),
        "long_running_transactions": transaction_manager.get_long_running_transactions(),
        "deadlock_analysis": {
            "total_deadlocks": transaction_manager.deadlock_events,
            "retry_success_rate": (
                (transaction_manager.transaction_retries - transaction_manager.deadlock_events) / 
                transaction_manager.transaction_retries * 100
                if transaction_manager.transaction_retries > 0 else 0
            )
        }
    }

async def clear_query_cache():
    """Clear query cache manually"""
    query_cache.clear()
    logger.info("Query cache cleared")

async def get_query_performance_stats() -> Dict[str, Any]:
    """Get detailed query performance statistics"""
    return {
        "cache_stats": query_cache.get_stats(),
        "performance_stats": query_monitor.get_query_stats(),
        "configuration": {
            "cache_enabled": DatabaseConfig.ENABLE_QUERY_CACHE,
            "cache_size": query_cache.max_size,
            "cache_ttl": query_cache.ttl_seconds,
            "slow_query_threshold": query_monitor.slow_query_threshold
        }
    }

async def get_connection_health():
    """Comprehensive connection health check with advanced monitoring data"""
    health_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "pool_status": await get_pool_status(),
        "connection_test": await test_connection(),
        "query_performance": await get_query_performance_stats(),
        "transaction_stats": await get_transaction_stats(),
        "configuration": {
            "pool_size": DatabaseConfig.POOL_SIZE,
            "max_overflow": DatabaseConfig.MAX_OVERFLOW,
            "pool_timeout": DatabaseConfig.POOL_TIMEOUT,
            "pool_recycle": DatabaseConfig.POOL_RECYCLE,
            "health_check_interval": DatabaseConfig.HEALTH_CHECK_INTERVAL,
            "query_cache_enabled": DatabaseConfig.ENABLE_QUERY_CACHE,
            "slow_query_threshold": query_monitor.slow_query_threshold,
            "transaction_timeout": transaction_manager.transaction_timeout,
            "max_transaction_retries": transaction_manager.max_retry_attempts
        }
    }
    return health_data

@asynccontextmanager
async def get_async_session() -> AsyncSession:
    """
    CRITICAL FIX: Async context manager for database sessions
    Ensures proper session cleanup and connection pool management
    """
    async with get_db() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()

async def with_db_retry(operation, max_retries: int = 3, initial_delay: float = 1.0):
    """
    CRITICAL FIX: Database operation retry with exponential backoff
    Prevents connection failures from killing workers
    """
    last_exception = None
    
    for attempt in range(max_retries):
        try:
            if asyncio.iscoroutinefunction(operation):
                return await operation()
            else:
                return operation()
        except (DisconnectionError, TimeoutError, OperationalError) as e:
            last_exception = e
            if attempt == max_retries - 1:
                break
                
            # Exponential backoff with jitter
            delay = initial_delay * (2 ** attempt) + random.uniform(0, 1)
            logger.warning(f"Database operation failed (attempt {attempt + 1}/{max_retries}), retrying in {delay:.2f}s: {e}")
            await asyncio.sleep(delay)
        except Exception as e:
            # Non-retryable errors
            logger.error(f"Non-retryable database error: {e}")
            raise
    
    logger.error(f"Database operation failed after {max_retries} attempts")
    raise last_exception

async def get_db_connection_pool():
    """Get database connection pool for testing"""
    return engine_manager.get_primary_engine()

async def test_connection_resilience():
    """Test database connection resilience under stress"""
    try:
        async with get_async_session() as session:
            result = await session.execute(text("SELECT 1 as test"))
            row = result.fetchone()
            return {"status": "healthy", "test_result": row[0] if row else None}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def close_db():
    """Clean up all database connections with metrics logging"""
    try:
        logger.info("Closing database connections...")
        logger.info(f"Final metrics: {db_metrics.get_metrics()}")
        logger.info(f"Engine stats: {engine_manager.get_engine_stats()}")
        
        # Close all engines
        await engine_manager.close_all_engines()
        
        logger.info("All database connections closed successfully")
    except Exception as e:
        logger.error(f"Error closing database connections: {e}")
        raise