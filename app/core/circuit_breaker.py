"""
Circuit Breaker and Retry Patterns for DevSecureX Performance Optimization
Implements circuit breaker pattern to prevent cascading failures and resource exhaustion
"""

import asyncio
import logging
import time
from typing import Any, Callable, Dict, Optional, Union, List
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import random

logger = logging.getLogger(__name__)


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, calls fail fast
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5          # Number of failures before opening
    success_threshold: int = 2          # Successes needed to close from half-open
    timeout: float = 60.0              # Seconds before moving to half-open
    max_timeout: float = 300.0         # Maximum timeout (5 minutes)
    backoff_multiplier: float = 2.0    # Exponential backoff multiplier
    jitter: bool = True                # Add random jitter to prevent thundering herd


@dataclass
class CircuitBreakerMetrics:
    """Circuit breaker metrics tracking"""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    timeout_calls: int = 0
    circuit_open_count: int = 0
    last_failure_time: Optional[float] = None
    failure_types: Dict[str, int] = field(default_factory=dict)


class CircuitBreaker:
    """
    Circuit breaker implementation to prevent cascading failures
    and resource exhaustion in background loops and polling operations
    """
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0
        self.metrics = CircuitBreakerMetrics()
        
        logger.info(f"Circuit breaker '{name}' initialized with config: {self.config}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        if not await self._can_execute():
            raise CircuitBreakerOpenError(
                f"Circuit breaker '{self.name}' is open. "
                f"Last failure: {self.metrics.last_failure_time}"
            )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if exc_type is None:
            await self._on_success()
        else:
            await self._on_failure(exc_type.__name__ if exc_type else "Unknown")
    
    async def _can_execute(self) -> bool:
        """Check if circuit breaker allows execution"""
        self.metrics.total_calls += 1
        
        if self.state == CircuitBreakerState.CLOSED:
            return True
        
        elif self.state == CircuitBreakerState.OPEN:
            current_time = time.time()
            timeout = min(
                self.config.timeout * (self.config.backoff_multiplier ** self.metrics.circuit_open_count),
                self.config.max_timeout
            )
            
            if self.config.jitter:
                # Add jitter to prevent thundering herd
                timeout *= (0.5 + random.random() * 0.5)
            
            if current_time - self.last_failure_time >= timeout:
                logger.info(f"Circuit breaker '{self.name}' moving to HALF_OPEN after {timeout:.1f}s")
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                return True
            else:
                return False
        
        elif self.state == CircuitBreakerState.HALF_OPEN:
            return True
        
        return False
    
    async def _on_success(self):
        """Handle successful execution"""
        self.metrics.successful_calls += 1
        
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                logger.info(f"Circuit breaker '{self.name}' moving to CLOSED after {self.success_count} successes")
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.success_count = 0
        
        elif self.state == CircuitBreakerState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0
    
    async def _on_failure(self, failure_type: str):
        """Handle failed execution"""
        self.metrics.failed_calls += 1
        self.metrics.last_failure_time = time.time()
        self.last_failure_time = self.metrics.last_failure_time
        
        # Track failure types
        self.metrics.failure_types[failure_type] = self.metrics.failure_types.get(failure_type, 0) + 1
        
        if self.state in [CircuitBreakerState.CLOSED, CircuitBreakerState.HALF_OPEN]:
            self.failure_count += 1
            
            if self.failure_count >= self.config.failure_threshold:
                logger.warning(
                    f"Circuit breaker '{self.name}' OPENING after {self.failure_count} failures. "
                    f"Last failure: {failure_type}"
                )
                self.state = CircuitBreakerState.OPEN
                self.metrics.circuit_open_count += 1
                self.success_count = 0
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout,
                "max_timeout": self.config.max_timeout,
            },
            "metrics": {
                "total_calls": self.metrics.total_calls,
                "successful_calls": self.metrics.successful_calls,
                "failed_calls": self.metrics.failed_calls,
                "timeout_calls": self.metrics.timeout_calls,
                "circuit_open_count": self.metrics.circuit_open_count,
                "success_rate": (
                    self.metrics.successful_calls / max(1, self.metrics.total_calls)
                ),
                "failure_types": self.metrics.failure_types.copy(),
                "last_failure_time": self.metrics.last_failure_time,
            }
        }


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open"""
    pass


class ExponentialBackoff:
    """
    Exponential backoff utility for retry operations
    with jitter to prevent thundering herd problems
    """
    
    def __init__(
        self,
        initial_delay: float = 1.0,
        max_delay: float = 300.0,  # 5 minutes max
        multiplier: float = 2.0,
        jitter: bool = True,
        max_retries: Optional[int] = None
    ):
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.multiplier = multiplier
        self.jitter = jitter
        self.max_retries = max_retries
        self.attempt = 0
    
    def get_delay(self) -> float:
        """Get next delay value"""
        if self.max_retries and self.attempt >= self.max_retries:
            raise MaxRetriesExceeded(f"Maximum retries ({self.max_retries}) exceeded")
        
        delay = min(self.initial_delay * (self.multiplier ** self.attempt), self.max_delay)
        
        if self.jitter:
            # Add random jitter (±25% of delay)
            jitter_amount = delay * 0.25 * (random.random() * 2 - 1)
            delay += jitter_amount
            delay = max(0.1, delay)  # Ensure minimum delay
        
        self.attempt += 1
        return delay
    
    def reset(self):
        """Reset backoff state"""
        self.attempt = 0


class MaxRetriesExceeded(Exception):
    """Exception raised when maximum retries are exceeded"""
    pass


async def with_circuit_breaker(
    breaker: CircuitBreaker,
    func: Callable,
    *args,
    **kwargs
) -> Any:
    """CRITICAL FIX: Execute function with mandatory circuit breaker protection"""
    if breaker is None:
        logger.critical("Circuit breaker is None - this indicates a bypass attempt!")
        raise CircuitBreakerOpenError("Circuit breaker bypass detected - operation blocked for safety")
    
    # CRITICAL FIX: Validate breaker is properly configured
    if not hasattr(breaker, 'state') or not hasattr(breaker, 'config'):
        logger.critical(f"Invalid circuit breaker object: {type(breaker)}")
        raise CircuitBreakerOpenError("Invalid circuit breaker - operation blocked for safety")
    
    async with breaker:
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return func(*args, **kwargs)


async def with_exponential_backoff(
    func: Callable,
    *args,
    backoff: ExponentialBackoff = None,
    exceptions: tuple = (Exception,),
    **kwargs
) -> Any:
    """
    Execute function with exponential backoff retry
    
    Args:
        func: Function to execute
        *args: Function arguments
        backoff: ExponentialBackoff instance
        exceptions: Tuple of exceptions to retry on
        **kwargs: Function keyword arguments
    
    Returns:
        Function result
    
    Raises:
        MaxRetriesExceeded: When max retries exceeded
        Exception: Last exception if all retries failed
    """
    if backoff is None:
        backoff = ExponentialBackoff()
    
    last_exception = None
    
    while True:
        try:
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
        
        except exceptions as e:
            last_exception = e
            logger.warning(f"Function {func.__name__} failed (attempt {backoff.attempt}): {e}")
            
            try:
                delay = backoff.get_delay()
                logger.info(f"Retrying {func.__name__} after {delay:.1f}s delay")
                await asyncio.sleep(delay)
            except MaxRetriesExceeded:
                logger.error(f"Max retries exceeded for {func.__name__}")
                raise last_exception from e


class PollingCircuitBreaker(CircuitBreaker):
    """
    Specialized circuit breaker for polling operations
    with additional safeguards against infinite loops
    """
    
    def __init__(
        self,
        name: str,
        max_iterations: int = 100,
        max_duration: float = 300.0,  # 5 minutes
        config: CircuitBreakerConfig = None
    ):
        super().__init__(name, config)
        self.max_iterations = max_iterations
        self.max_duration = max_duration
        self.start_time = None
        self.iterations = 0
    
    async def __aenter__(self):
        """Start polling session"""
        if self.start_time is None:
            self.start_time = time.time()
            self.iterations = 0
        
        # Check iteration and time limits
        if self.iterations >= self.max_iterations:
            raise PollingLimitExceeded(
                f"Maximum iterations ({self.max_iterations}) exceeded in polling '{self.name}'"
            )
        
        current_time = time.time()
        if self.start_time and (current_time - self.start_time) > self.max_duration:
            raise PollingLimitExceeded(
                f"Maximum duration ({self.max_duration}s) exceeded in polling '{self.name}'"
            )
        
        self.iterations += 1
        return await super().__aenter__()
    
    def reset_polling(self):
        """Reset polling counters for new session"""
        self.start_time = None
        self.iterations = 0


class PollingLimitExceeded(Exception):
    """Exception raised when polling limits are exceeded"""
    pass


# Global circuit breaker registry
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    name: str,
    config: CircuitBreakerConfig = None
) -> CircuitBreaker:
    """Get or create a circuit breaker by name"""
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name, config)
    return _circuit_breakers[name]


def get_polling_circuit_breaker(
    name: str,
    max_iterations: int = 100,
    max_duration: float = 300.0,
    config: CircuitBreakerConfig = None
) -> PollingCircuitBreaker:
    """Get or create a polling circuit breaker by name"""
    breaker_name = f"polling_{name}"
    if breaker_name not in _circuit_breakers:
        _circuit_breakers[breaker_name] = PollingCircuitBreaker(
            breaker_name, max_iterations, max_duration, config
        )
    return _circuit_breakers[breaker_name]


def get_all_circuit_breaker_metrics() -> Dict[str, Dict[str, Any]]:
    """Get metrics for all circuit breakers"""
    return {name: breaker.get_metrics() for name, breaker in _circuit_breakers.items()}


class CircuitBreakerEnforcer:
    """
    CRITICAL FIX: Circuit breaker enforcement to prevent bypassing safety mechanisms.
    This class ensures that all Redis operations go through circuit breaker validation.
    """
    
    def __init__(self):
        self._required_breakers: Dict[str, CircuitBreaker] = {}
        self._bypass_attempts: int = 0
        self._enforcement_enabled = True
        
        # Create mandatory circuit breakers for critical operations
        self._setup_mandatory_breakers()
        
        logger.info("Circuit breaker enforcer initialized with mandatory safety checks")
    
    def _setup_mandatory_breakers(self):
        """Setup mandatory circuit breakers that cannot be bypassed"""
        # Redis operations circuit breaker
        redis_config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=30.0,
            max_timeout=300.0
        )
        self._required_breakers["redis_operations"] = CircuitBreaker("redis_operations", redis_config)
        
        # Queue operations circuit breaker
        queue_config = CircuitBreakerConfig(
            failure_threshold=5,
            success_threshold=2,
            timeout=60.0,
            max_timeout=600.0
        )
        self._required_breakers["queue_operations"] = CircuitBreaker("queue_operations", queue_config)
        
        # Event system circuit breaker
        event_config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=1,
            timeout=30.0,
            max_timeout=180.0
        )
        self._required_breakers["event_system"] = CircuitBreaker("event_system", event_config)
        
        # Register all mandatory breakers in global registry
        for name, breaker in self._required_breakers.items():
            _circuit_breakers[name] = breaker
            logger.info(f"Registered mandatory circuit breaker: {name}")
    
    def get_redis_circuit_breaker(self) -> CircuitBreaker:
        """CRITICAL FIX: Get mandatory Redis circuit breaker - cannot be bypassed"""
        return self._required_breakers["redis_operations"]
    
    def get_queue_circuit_breaker(self) -> CircuitBreaker:
        """CRITICAL FIX: Get mandatory queue circuit breaker - cannot be bypassed"""
        return self._required_breakers["queue_operations"]
    
    def get_event_circuit_breaker(self) -> CircuitBreaker:
        """CRITICAL FIX: Get mandatory event system circuit breaker - cannot be bypassed"""
        return self._required_breakers["event_system"]
    
    async def enforce_redis_operation(self, operation_func, *args, **kwargs):
        """CRITICAL FIX: Enforce circuit breaker for Redis operations"""
        if not self._enforcement_enabled:
            self._bypass_attempts += 1
            logger.critical(f"Circuit breaker bypass attempted for Redis operation! (attempt #{self._bypass_attempts})")
            # Still enforce even if disabled to prevent bypassing
        
        breaker = self.get_redis_circuit_breaker()
        return await with_circuit_breaker(breaker, operation_func, *args, **kwargs)
    
    async def enforce_queue_operation(self, operation_func, *args, **kwargs):
        """CRITICAL FIX: Enforce circuit breaker for queue operations"""
        if not self._enforcement_enabled:
            self._bypass_attempts += 1
            logger.critical(f"Circuit breaker bypass attempted for queue operation! (attempt #{self._bypass_attempts})")
        
        breaker = self.get_queue_circuit_breaker()
        return await with_circuit_breaker(breaker, operation_func, *args, **kwargs)
    
    async def enforce_event_operation(self, operation_func, *args, **kwargs):
        """CRITICAL FIX: Enforce circuit breaker for event system operations"""
        if not self._enforcement_enabled:
            self._bypass_attempts += 1
            logger.critical(f"Circuit breaker bypass attempted for event operation! (attempt #{self._bypass_attempts})")
        
        breaker = self.get_event_circuit_breaker()
        return await with_circuit_breaker(breaker, operation_func, *args, **kwargs)
    
    def validate_circuit_breaker_compliance(self) -> Dict[str, Any]:
        """CRITICAL FIX: Validate that all mandatory circuit breakers are in place"""
        compliance_report = {
            "enforcement_enabled": self._enforcement_enabled,
            "bypass_attempts": self._bypass_attempts,
            "mandatory_breakers_status": {},
            "compliance_score": 0,
            "violations": []
        }
        
        total_breakers = len(self._required_breakers)
        compliant_breakers = 0
        
        for name, breaker in self._required_breakers.items():
            status = breaker.get_metrics()
            compliance_report["mandatory_breakers_status"][name] = {
                "state": status["state"],
                "total_calls": status["metrics"]["total_calls"],
                "success_rate": status["metrics"]["success_rate"]
            }
            
            # Check if breaker is functional
            if status["metrics"]["total_calls"] == 0:
                compliance_report["violations"].append(f"Circuit breaker '{name}' has never been used")
            else:
                compliant_breakers += 1
        
        compliance_report["compliance_score"] = (compliant_breakers / total_breakers) * 100
        
        if self._bypass_attempts > 0:
            compliance_report["violations"].append(f"{self._bypass_attempts} bypass attempts detected")
        
        return compliance_report
    
    def enable_enforcement(self):
        """Enable circuit breaker enforcement"""
        self._enforcement_enabled = True
        logger.info("Circuit breaker enforcement enabled")
    
    def disable_enforcement(self):
        """Disable enforcement - THIS SHOULD ONLY BE USED FOR TESTING"""
        logger.critical("Circuit breaker enforcement disabled - THIS IS DANGEROUS IN PRODUCTION!")
        self._enforcement_enabled = False


# Global circuit breaker enforcer
_circuit_breaker_enforcer = CircuitBreakerEnforcer()


def get_circuit_breaker_enforcer() -> CircuitBreakerEnforcer:
    """Get the global circuit breaker enforcer"""
    return _circuit_breaker_enforcer