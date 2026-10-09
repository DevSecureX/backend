"""
Timeout Monitoring and Alerting System for DevSecureX Backend
Provides comprehensive monitoring and alerting for timeout-related issues
"""

import logging
import time
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from collections import defaultdict, deque
import json

logger = logging.getLogger(__name__)

@dataclass
class TimeoutEvent:
    """Represents a timeout event for monitoring"""
    endpoint: str
    operation_type: str
    timeout_duration: int
    actual_duration: float
    timestamp: datetime
    request_id: str
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        return {
            "endpoint": self.endpoint,
            "operation_type": self.operation_type,
            "timeout_duration": self.timeout_duration,
            "actual_duration": self.actual_duration,
            "timestamp": self.timestamp.isoformat(),
            "request_id": self.request_id,
            "user_agent": self.user_agent,
            "ip_address": self.ip_address
        }

@dataclass 
class PerformanceMetrics:
    """Performance metrics for endpoints"""
    endpoint: str
    total_requests: int = 0
    timeout_count: int = 0
    avg_response_time: float = 0.0
    max_response_time: float = 0.0
    min_response_time: float = float('inf')
    success_rate: float = 100.0
    recent_timeouts: deque = field(default_factory=lambda: deque(maxlen=10))
    
    def update(self, duration: float, timed_out: bool = False):
        """Update metrics with new request data"""
        self.total_requests += 1
        
        if timed_out:
            self.timeout_count += 1
            self.recent_timeouts.append(datetime.now(timezone.utc))
        else:
            # Update response time stats only for successful requests
            self.avg_response_time = (
                (self.avg_response_time * (self.total_requests - 1) + duration) / 
                self.total_requests
            )
            self.max_response_time = max(self.max_response_time, duration)
            self.min_response_time = min(self.min_response_time, duration)
        
        # Calculate success rate
        self.success_rate = ((self.total_requests - self.timeout_count) / self.total_requests) * 100
    
    def get_recent_timeout_rate(self, minutes: int = 5) -> float:
        """Get timeout rate for recent time period"""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        recent_timeouts = sum(1 for timeout_time in self.recent_timeouts if timeout_time > cutoff)
        return (recent_timeouts / max(1, len(self.recent_timeouts))) * 100

class TimeoutMonitor:
    """Monitors timeout events and performance metrics"""
    
    def __init__(self, max_events: int = 1000):
        self.timeout_events: deque = deque(maxlen=max_events)
        self.performance_metrics: Dict[str, PerformanceMetrics] = defaultdict(
            lambda: PerformanceMetrics(endpoint="")
        )
        self.alert_thresholds = {
            "timeout_rate": float(os.getenv("ALERT_TIMEOUT_RATE", "10.0")),  # 10% timeout rate
            "avg_response_time": float(os.getenv("ALERT_AVG_RESPONSE_TIME", "60.0")),  # 60s avg
            "max_response_time": float(os.getenv("ALERT_MAX_RESPONSE_TIME", "300.0"))  # 5min max
        }
        
    def record_timeout(self, event: TimeoutEvent) -> None:
        """Record a timeout event"""
        self.timeout_events.append(event)
        
        # Update performance metrics
        metrics = self.performance_metrics[event.endpoint]
        metrics.endpoint = event.endpoint
        metrics.update(event.actual_duration, timed_out=True)
        
        # Log timeout event
        logger.error(
            f"PHASE 3: TIMEOUT EVENT: {event.endpoint} exceeded {event.timeout_duration}s "
            f"(actual: {event.actual_duration:.2f}s) [request_id: {event.request_id}]",
            extra={"timeout_event": event.to_dict()}
        )
        
        # PHASE 3: Publish timeout event via event-driven monitoring
        try:
            from monitoring.event_driven_monitoring import publish_timeout_event
            import asyncio
            
            # Use asyncio.create_task to avoid blocking
            asyncio.create_task(publish_timeout_event(
                endpoint=event.endpoint,
                duration=event.actual_duration,
                timeout_limit=event.timeout_duration
            ))
        except ImportError:
            # Event-driven monitoring not available
            pass
        except Exception as e:
            logger.debug(f"Failed to publish timeout event: {e}")
        
        # Check if alert thresholds are exceeded
        self._check_alert_thresholds(event.endpoint, metrics)
    
    def record_success(self, endpoint: str, duration: float) -> None:
        """Record a successful request"""
        metrics = self.performance_metrics[endpoint]
        metrics.endpoint = endpoint
        metrics.update(duration, timed_out=False)
        
        # Log slow successful requests
        if duration > self.alert_thresholds["avg_response_time"]:
            logger.warning(
                f"SLOW REQUEST: {endpoint} took {duration:.2f}s "
                f"(threshold: {self.alert_thresholds['avg_response_time']}s)"
            )
    
    def _check_alert_thresholds(self, endpoint: str, metrics: PerformanceMetrics) -> None:
        """Check if metrics exceed alert thresholds"""
        alerts = []
        
        # Check timeout rate
        recent_timeout_rate = metrics.get_recent_timeout_rate()
        if recent_timeout_rate > self.alert_thresholds["timeout_rate"]:
            alerts.append(f"High timeout rate: {recent_timeout_rate:.1f}%")
        
        # Check average response time
        if metrics.avg_response_time > self.alert_thresholds["avg_response_time"]:
            alerts.append(f"High avg response time: {metrics.avg_response_time:.1f}s")
        
        # Check maximum response time
        if metrics.max_response_time > self.alert_thresholds["max_response_time"]:
            alerts.append(f"High max response time: {metrics.max_response_time:.1f}s")
        
        if alerts:
            logger.critical(
                f"PERFORMANCE ALERT for {endpoint}: {', '.join(alerts)}",
                extra={
                    "performance_alert": {
                        "endpoint": endpoint,
                        "alerts": alerts,
                        "metrics": {
                            "timeout_rate": recent_timeout_rate,
                            "avg_response_time": metrics.avg_response_time,
                            "max_response_time": metrics.max_response_time,
                            "success_rate": metrics.success_rate
                        }
                    }
                }
            )
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        summary = {
            "total_timeout_events": len(self.timeout_events),
            "endpoints": {}
        }
        
        for endpoint, metrics in self.performance_metrics.items():
            if metrics.total_requests > 0:
                summary["endpoints"][endpoint] = {
                    "total_requests": metrics.total_requests,
                    "timeout_count": metrics.timeout_count,
                    "timeout_rate": (metrics.timeout_count / metrics.total_requests) * 100,
                    "success_rate": metrics.success_rate,
                    "avg_response_time": metrics.avg_response_time,
                    "max_response_time": metrics.max_response_time,
                    "min_response_time": metrics.min_response_time if metrics.min_response_time != float('inf') else 0,
                    "recent_timeout_rate": metrics.get_recent_timeout_rate()
                }
        
        return summary
    
    def get_recent_timeouts(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get timeout events from recent time period"""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        return [
            event.to_dict() 
            for event in self.timeout_events 
            if event.timestamp > cutoff
        ]
    
    def clear_old_data(self, days: int = 7) -> None:
        """Clear old timeout events and reset metrics"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Remove old timeout events
        old_events = [event for event in self.timeout_events if event.timestamp < cutoff]
        for _ in range(len(old_events)):
            if self.timeout_events and self.timeout_events[0].timestamp < cutoff:
                self.timeout_events.popleft()
        
        logger.info(f"Cleared {len(old_events)} timeout events older than {days} days")

# Singleton monitor instance
_monitor_instance: Optional[TimeoutMonitor] = None

def get_timeout_monitor() -> TimeoutMonitor:
    """Get singleton timeout monitor instance"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = TimeoutMonitor()
    return _monitor_instance

# Convenience functions
def record_timeout_event(
    endpoint: str,
    operation_type: str,
    timeout_duration: int,
    actual_duration: float,
    request_id: str,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None
) -> None:
    """Record a timeout event"""
    event = TimeoutEvent(
        endpoint=endpoint,
        operation_type=operation_type,
        timeout_duration=timeout_duration,
        actual_duration=actual_duration,
        timestamp=datetime.now(timezone.utc),
        request_id=request_id,
        user_agent=user_agent,
        ip_address=ip_address
    )
    get_timeout_monitor().record_timeout(event)

def record_success_event(endpoint: str, duration: float) -> None:
    """Record a successful request"""
    get_timeout_monitor().record_success(endpoint, duration)

def get_performance_summary() -> Dict[str, Any]:
    """Get performance metrics summary"""
    return get_timeout_monitor().get_metrics_summary()

# PHASE 3: Background cleanup task with extended intervals
async def cleanup_old_data():
    """Background task to cleanup old monitoring data (PHASE 3: Event-driven intervals)"""
    while True:
        try:
            get_timeout_monitor().clear_old_data()
            logger.info("🧹 PHASE 3: Timeout monitoring cleanup completed")
            await asyncio.sleep(86400)  # Keep daily cleanup (no change needed)
        except Exception as e:
            logger.error(f"Error in timeout monitoring cleanup: {e}")
            await asyncio.sleep(3600)  # Retry in 1 hour

# Import os for environment variables
import os