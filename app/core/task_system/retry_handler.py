"""
Advanced Retry Logic with Exponential Backoff and Dead Letter Queue

Features:
- Exponential backoff with jitter to prevent thundering herd
- Configurable retry policies per task type
- Dead letter queue for permanently failed tasks
- Circuit breaker pattern for failing services
- Comprehensive error categorization and tracking
- Smart retry decisions based on error types
"""

import asyncio
import json
import logging
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from dataclasses import dataclass, asdict

from core.redis import get_redis_client
from core.utils import utc_now_iso

logger = logging.getLogger(__name__)

class ErrorCategory(Enum):
    """Error categories for intelligent retry decisions"""
    TRANSIENT = "transient"          # Network timeouts, temporary unavailability
    RATE_LIMIT = "rate_limit"        # API rate limiting
    RESOURCE = "resource"            # Memory, disk space issues
    AUTH = "auth"                    # Authentication/authorization failures
    VALIDATION = "validation"        # Input validation errors
    BUSINESS = "business"            # Business logic errors
    FATAL = "fatal"                  # Unrecoverable errors
    UNKNOWN = "unknown"              # Uncategorized errors

class RetryPolicy(Enum):
    """Predefined retry policies"""
    NONE = "none"                    # No retries
    STANDARD = "standard"            # Standard exponential backoff
    AGGRESSIVE = "aggressive"        # More aggressive retries for critical tasks
    CONSERVATIVE = "conservative"    # Conservative retries to avoid resource exhaustion
    RATE_LIMITED = "rate_limited"    # Special handling for rate-limited services
    CUSTOM = "custom"               # Custom retry configuration

@dataclass
class RetryConfig:
    """Retry configuration settings"""
    max_retries: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 300.0
    exponential_base: float = 2.0
    jitter_factor: float = 0.1
    retry_on_errors: List[ErrorCategory] = None
    circuit_breaker_threshold: int = 5
    circuit_breaker_window_seconds: int = 300

    def __post_init__(self):
        if self.retry_on_errors is None:
            self.retry_on_errors = [
                ErrorCategory.TRANSIENT,
                ErrorCategory.RATE_LIMIT,
                ErrorCategory.RESOURCE
            ]

@dataclass 
class RetryAttempt:
    """Record of a retry attempt"""
    attempt_number: int
    attempted_at: str
    error_message: str
    error_category: ErrorCategory
    delay_seconds: float
    next_retry_at: Optional[str] = None

@dataclass
class RetryRecord:
    """Complete retry record for a task"""
    task_id: str
    attempts: List[RetryAttempt]
    total_attempts: int = 0
    last_error_category: Optional[ErrorCategory] = None
    is_permanently_failed: bool = False
    circuit_breaker_triggered: bool = False
    created_at: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = utc_now_iso()

class RetryHandler:
    """Advanced retry handler with exponential backoff and circuit breaker"""
    
    def __init__(self, redis_key_prefix: str = "retry_handler"):
        self.redis_key_prefix = redis_key_prefix
        self.retry_records_key = f"{redis_key_prefix}:records"
        self.circuit_breaker_key = f"{redis_key_prefix}:circuit_breaker"
        self.deadletter_key = f"{redis_key_prefix}:deadletter"
        self.metrics_key = f"{redis_key_prefix}:metrics"
        
        # Predefined retry policies
        self.retry_policies = {
            RetryPolicy.STANDARD: RetryConfig(
                max_retries=3,
                base_delay_seconds=1.0,
                max_delay_seconds=300.0,
                exponential_base=2.0,
                jitter_factor=0.1
            ),
            RetryPolicy.AGGRESSIVE: RetryConfig(
                max_retries=5,
                base_delay_seconds=0.5,
                max_delay_seconds=600.0,
                exponential_base=1.8,
                jitter_factor=0.15
            ),
            RetryPolicy.CONSERVATIVE: RetryConfig(
                max_retries=2,
                base_delay_seconds=5.0,
                max_delay_seconds=900.0,
                exponential_base=3.0,
                jitter_factor=0.2
            ),
            RetryPolicy.RATE_LIMITED: RetryConfig(
                max_retries=4,
                base_delay_seconds=60.0,
                max_delay_seconds=3600.0,
                exponential_base=2.0,
                jitter_factor=0.3,
                retry_on_errors=[ErrorCategory.RATE_LIMIT, ErrorCategory.TRANSIENT]
            ),
            RetryPolicy.NONE: RetryConfig(max_retries=0)
        }
        
        # Error classification patterns
        self.error_patterns = {
            ErrorCategory.TRANSIENT: [
                'connection timeout', 'connection reset', 'connection refused',
                'temporary failure', 'service unavailable', 'timeout',
                'network error', 'dns resolution failed', 'socket error'
            ],
            ErrorCategory.RATE_LIMIT: [
                'rate limit', 'too many requests', 'quota exceeded',
                'throttled', 'api limit', '429', 'rate exceeded'
            ],
            ErrorCategory.RESOURCE: [
                'out of memory', 'disk full', 'resource exhausted',
                'insufficient resources', 'memory allocation failed'
            ],
            ErrorCategory.AUTH: [
                'authentication failed', 'unauthorized', 'invalid token',
                'permission denied', 'access denied', '401', '403'
            ],
            ErrorCategory.VALIDATION: [
                'validation error', 'invalid input', 'bad request',
                'invalid format', 'schema validation', '400'
            ],
            ErrorCategory.FATAL: [
                'segmentation fault', 'fatal error', 'critical error',
                'unrecoverable', 'corrupted data', 'system failure'
            ]
        }
    
    def classify_error(self, error_message: str, exception_type: str = None) -> ErrorCategory:
        """Classify error into appropriate category for retry decisions"""
        
        error_lower = error_message.lower()
        
        # Check each category's patterns
        for category, patterns in self.error_patterns.items():
            if any(pattern in error_lower for pattern in patterns):
                return category
        
        # Exception type-based classification
        if exception_type:
            exception_lower = exception_type.lower()
            
            if any(name in exception_lower for name in ['timeout', 'connection', 'network']):
                return ErrorCategory.TRANSIENT
            elif any(name in exception_lower for name in ['auth', 'permission', 'unauthorized']):
                return ErrorCategory.AUTH
            elif any(name in exception_lower for name in ['validation', 'value', 'type']):
                return ErrorCategory.VALIDATION
        
        return ErrorCategory.UNKNOWN
    
    def get_retry_config(self, policy: RetryPolicy, custom_config: RetryConfig = None) -> RetryConfig:
        """Get retry configuration for the specified policy"""
        
        if policy == RetryPolicy.CUSTOM and custom_config:
            return custom_config
        
        return self.retry_policies.get(policy, self.retry_policies[RetryPolicy.STANDARD])
    
    async def should_retry(
        self,
        task_id: str,
        error_message: str,
        exception_type: str = None,
        retry_policy: RetryPolicy = RetryPolicy.STANDARD,
        custom_config: RetryConfig = None
    ) -> tuple[bool, Optional[float]]:
        """
        Determine if task should be retried and when
        
        Returns:
            (should_retry: bool, delay_seconds: Optional[float])
        """
        
        redis_client = await get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for retry decision")
            return False, None
        
        try:
            # Get or create retry record
            retry_record = await self._get_retry_record(task_id, redis_client)
            
            # Get retry configuration
            config = self.get_retry_config(retry_policy, custom_config)
            
            # Classify error
            error_category = self.classify_error(error_message, exception_type)
            
            # Check if error category is retryable
            if error_category not in config.retry_on_errors:
                logger.info(f"Task {task_id} error category {error_category.value} is not retryable")
                await self._mark_permanently_failed(task_id, error_message, error_category, redis_client)
                return False, None
            
            # Check circuit breaker
            if await self._is_circuit_breaker_open(error_category, redis_client):
                logger.warning(f"Circuit breaker open for {error_category.value}, not retrying task {task_id}")
                await self._mark_permanently_failed(task_id, "Circuit breaker open", error_category, redis_client)
                return False, None
            
            # Check retry limit
            if retry_record.total_attempts >= config.max_retries:
                logger.info(f"Task {task_id} exceeded max retries ({config.max_retries})")
                await self._mark_permanently_failed(task_id, f"Max retries exceeded: {error_message}", error_category, redis_client)
                return False, None
            
            # Calculate delay with exponential backoff and jitter
            delay_seconds = self._calculate_delay(retry_record.total_attempts, config)
            next_retry_at = (datetime.utcnow() + timedelta(seconds=delay_seconds)).isoformat()
            
            # Record retry attempt
            attempt = RetryAttempt(
                attempt_number=retry_record.total_attempts + 1,
                attempted_at=utc_now_iso(),
                error_message=error_message,
                error_category=error_category,
                delay_seconds=delay_seconds,
                next_retry_at=next_retry_at
            )
            
            retry_record.attempts.append(attempt)
            retry_record.total_attempts += 1
            retry_record.last_error_category = error_category
            
            # Update retry record
            await self._update_retry_record(retry_record, redis_client)
            
            # Update circuit breaker
            await self._update_circuit_breaker(error_category, redis_client)
            
            # Update metrics
            await self._update_metrics('retries_scheduled', redis_client)
            
            logger.info(f"Task {task_id} scheduled for retry {retry_record.total_attempts} in {delay_seconds:.1f} seconds")
            return True, delay_seconds
            
        except Exception as e:
            logger.error(f"Error in retry decision for task {task_id}: {e}", exc_info=True)
            return False, None
    
    def _calculate_delay(self, attempt_number: int, config: RetryConfig) -> float:
        """Calculate delay with exponential backoff and jitter"""
        
        # Exponential backoff: base_delay * (exponential_base ^ attempt)
        base_delay = config.base_delay_seconds * (config.exponential_base ** attempt_number)
        
        # Add jitter to prevent thundering herd
        jitter_range = base_delay * config.jitter_factor
        jitter = random.uniform(-jitter_range, jitter_range)
        
        # Calculate final delay
        delay = base_delay + jitter
        
        # Apply maximum delay limit
        delay = min(delay, config.max_delay_seconds)
        
        # Ensure minimum delay
        delay = max(delay, 0.1)
        
        return delay
    
    async def _get_retry_record(self, task_id: str, redis_client) -> RetryRecord:
        """Get or create retry record for task"""
        
        try:
            record_data = await redis_client.hget(self.retry_records_key, task_id)
            
            if record_data:
                record_dict = json.loads(record_data)
                # Convert attempt dictionaries back to RetryAttempt objects
                attempts = [RetryAttempt(**attempt) for attempt in record_dict['attempts']]
                record_dict['attempts'] = attempts
                
                # Handle enum deserialization
                if record_dict.get('last_error_category'):
                    record_dict['last_error_category'] = ErrorCategory(record_dict['last_error_category'])
                
                return RetryRecord(**record_dict)
            else:
                return RetryRecord(task_id=task_id, attempts=[])
                
        except Exception as e:
            logger.warning(f"Error loading retry record for {task_id}, creating new: {e}")
            return RetryRecord(task_id=task_id, attempts=[])
    
    async def _update_retry_record(self, record: RetryRecord, redis_client):
        """Update retry record in Redis"""
        
        try:
            # Convert to serializable format
            record_dict = asdict(record)
            
            # Convert enum to string
            if record_dict.get('last_error_category'):
                record_dict['last_error_category'] = record.last_error_category.value
            
            # Convert RetryAttempt objects to dictionaries
            record_dict['attempts'] = [
                {**asdict(attempt), 'error_category': attempt.error_category.value}
                for attempt in record.attempts
            ]
            
            await redis_client.hset(
                self.retry_records_key,
                record.task_id,
                json.dumps(record_dict)
            )
            
            # Set TTL to prevent indefinite storage
            await redis_client.expire(self.retry_records_key, 86400 * 7)  # 7 days
            
        except Exception as e:
            logger.error(f"Error updating retry record for {record.task_id}: {e}", exc_info=True)
    
    async def _mark_permanently_failed(
        self,
        task_id: str,
        final_error: str,
        error_category: ErrorCategory,
        redis_client
    ):
        """Mark task as permanently failed and move to dead letter queue"""
        
        try:
            # Get retry record
            retry_record = await self._get_retry_record(task_id, redis_client)
            retry_record.is_permanently_failed = True
            
            # Create dead letter entry
            dead_letter_entry = {
                'task_id': task_id,
                'final_error': final_error,
                'error_category': error_category.value,
                'retry_record': asdict(retry_record),
                'failed_at': utc_now_iso(),
                'total_retry_attempts': retry_record.total_attempts
            }
            
            # Add to dead letter queue
            await redis_client.lpush(
                self.deadletter_key,
                json.dumps(dead_letter_entry)
            )
            
            # Update retry record
            await self._update_retry_record(retry_record, redis_client)
            
            # Update metrics
            await self._update_metrics('permanent_failures', redis_client)
            
            logger.error(f"Task {task_id} permanently failed after {retry_record.total_attempts} attempts: {final_error}")
            
        except Exception as e:
            logger.error(f"Error marking task {task_id} as permanently failed: {e}", exc_info=True)
    
    async def _is_circuit_breaker_open(self, error_category: ErrorCategory, redis_client) -> bool:
        """Check if circuit breaker is open for error category"""
        
        try:
            breaker_key = f"{self.circuit_breaker_key}:{error_category.value}"
            
            # Get circuit breaker state
            breaker_data = await redis_client.hgetall(breaker_key)
            
            if not breaker_data:
                return False
            
            failure_count = int(breaker_data.get('failure_count', 0))
            last_failure_time = breaker_data.get('last_failure_time')
            threshold = int(breaker_data.get('threshold', 5))
            window_seconds = int(breaker_data.get('window_seconds', 300))
            
            if failure_count < threshold:
                return False
            
            # Check if we're still in the failure window
            if last_failure_time:
                last_failure = datetime.fromisoformat(last_failure_time)
                if (datetime.utcnow() - last_failure).total_seconds() > window_seconds:
                    # Reset circuit breaker after window expires
                    await redis_client.hset(breaker_key, 'failure_count', 0)
                    return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Error checking circuit breaker for {error_category.value}: {e}")
            return False
    
    async def _update_circuit_breaker(self, error_category: ErrorCategory, redis_client):
        """Update circuit breaker state after failure"""
        
        try:
            breaker_key = f"{self.circuit_breaker_key}:{error_category.value}"
            
            # Increment failure count
            await redis_client.hincrby(breaker_key, 'failure_count', 1)
            await redis_client.hset(breaker_key, 'last_failure_time', utc_now_iso())
            
            # Set default threshold and window if not exists
            if not await redis_client.hexists(breaker_key, 'threshold'):
                await redis_client.hset(breaker_key, 'threshold', 5)
                await redis_client.hset(breaker_key, 'window_seconds', 300)
            
            # Set TTL
            await redis_client.expire(breaker_key, 3600)  # 1 hour
            
        except Exception as e:
            logger.warning(f"Error updating circuit breaker for {error_category.value}: {e}")
    
    async def reset_circuit_breaker(self, error_category: ErrorCategory) -> bool:
        """Manually reset circuit breaker for error category"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return False
        
        try:
            breaker_key = f"{self.circuit_breaker_key}:{error_category.value}"
            await redis_client.hset(breaker_key, 'failure_count', 0)
            await redis_client.hset(breaker_key, 'last_reset_time', utc_now_iso())
            
            logger.info(f"Circuit breaker reset for {error_category.value}")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting circuit breaker for {error_category.value}: {e}")
            return False
    
    async def get_retry_stats(self) -> Dict[str, Any]:
        """Get comprehensive retry statistics"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return {'error': 'Redis unavailable'}
        
        try:
            stats = {}
            
            # Basic metrics
            metrics_data = await redis_client.hgetall(self.metrics_key)
            stats['metrics'] = {k: int(v) if v else 0 for k, v in metrics_data.items()}
            
            # Circuit breaker states
            cb_keys = await redis_client.keys(f"{self.circuit_breaker_key}:*")
            circuit_breakers = {}
            
            for cb_key in cb_keys:
                category = cb_key.split(':')[-1]
                cb_data = await redis_client.hgetall(cb_key)
                
                if cb_data:
                    failure_count = int(cb_data.get('failure_count', 0))
                    threshold = int(cb_data.get('threshold', 5))
                    
                    circuit_breakers[category] = {
                        'failure_count': failure_count,
                        'threshold': threshold,
                        'is_open': failure_count >= threshold,
                        'last_failure_time': cb_data.get('last_failure_time'),
                        'window_seconds': int(cb_data.get('window_seconds', 300))
                    }
            
            stats['circuit_breakers'] = circuit_breakers
            
            # Dead letter queue size
            stats['dead_letter_count'] = await redis_client.llen(self.deadletter_key)
            
            # Active retry records count
            stats['active_retry_records'] = await redis_client.hlen(self.retry_records_key)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting retry stats: {e}", exc_info=True)
            return {'error': str(e)}
    
    async def get_dead_letter_tasks(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get tasks from dead letter queue"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return []
        
        try:
            dead_tasks_json = await redis_client.lrange(self.deadletter_key, 0, limit - 1)
            dead_tasks = []
            
            for task_json in dead_tasks_json:
                try:
                    task_data = json.loads(task_json)
                    dead_tasks.append(task_data)
                except Exception as e:
                    logger.warning(f"Error parsing dead letter task: {e}")
            
            return dead_tasks
            
        except Exception as e:
            logger.error(f"Error getting dead letter tasks: {e}", exc_info=True)
            return []
    
    async def requeue_dead_letter_task(self, task_id: str) -> bool:
        """Requeue a task from dead letter queue (admin operation)"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return False
        
        try:
            # Get all dead letter tasks
            dead_tasks_json = await redis_client.lrange(self.deadletter_key, 0, -1)
            
            for i, task_json in enumerate(dead_tasks_json):
                try:
                    task_data = json.loads(task_json)
                    
                    if task_data.get('task_id') == task_id:
                        # Remove from dead letter queue
                        await redis_client.lrem(self.deadletter_key, 1, task_json)
                        
                        # Reset retry record
                        retry_record = RetryRecord(task_id=task_id, attempts=[])
                        await self._update_retry_record(retry_record, redis_client)
                        
                        logger.info(f"Requeued dead letter task {task_id}")
                        return True
                        
                except Exception as e:
                    logger.warning(f"Error processing dead letter task during requeue: {e}")
            
            logger.warning(f"Task {task_id} not found in dead letter queue")
            return False
            
        except Exception as e:
            logger.error(f"Error requeuing dead letter task {task_id}: {e}", exc_info=True)
            return False
    
    async def cleanup_old_records(self, days_old: int = 7) -> int:
        """Clean up old retry records and dead letter entries"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            return 0
        
        cleanup_count = 0
        cutoff_time = datetime.utcnow() - timedelta(days=days_old)
        
        try:
            # Clean old retry records
            all_records = await redis_client.hgetall(self.retry_records_key)
            
            for task_id, record_data in all_records.items():
                try:
                    record_dict = json.loads(record_data)
                    created_at = datetime.fromisoformat(record_dict.get('created_at', utc_now_iso()))
                    
                    if created_at < cutoff_time:
                        await redis_client.hdel(self.retry_records_key, task_id)
                        cleanup_count += 1
                        
                except Exception as e:
                    logger.warning(f"Error processing retry record {task_id} during cleanup: {e}")
            
            # Clean old dead letter entries
            dead_tasks_json = await redis_client.lrange(self.deadletter_key, 0, -1)
            
            for task_json in dead_tasks_json:
                try:
                    task_data = json.loads(task_json)
                    failed_at = datetime.fromisoformat(task_data.get('failed_at', utc_now_iso()))
                    
                    if failed_at < cutoff_time:
                        await redis_client.lrem(self.deadletter_key, 1, task_json)
                        cleanup_count += 1
                        
                except Exception as e:
                    logger.warning(f"Error processing dead letter entry during cleanup: {e}")
            
            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} old retry records and dead letter entries")
            
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Error during retry cleanup: {e}", exc_info=True)
            return 0
    
    async def _update_metrics(self, metric: str, redis_client):
        """Update retry metrics"""
        try:
            await redis_client.hincrby(self.metrics_key, metric, 1)
        except Exception as e:
            logger.warning(f"Failed to update retry metric {metric}: {e}")