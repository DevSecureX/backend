"""
Performance Monitoring for Custom Rules Integration
Tracks performance metrics and provides optimization insights
"""

import time
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import asyncio
from functools import wraps
import json

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics for custom rules operations"""
    operation: str
    duration_ms: float
    user_id: int
    rule_count: int
    memory_usage_mb: Optional[float] = None
    cache_hits: int = 0
    cache_misses: int = 0
    errors: int = 0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

class CustomRulesPerformanceMonitor:
    """
    Performance monitoring system for custom rules integration
    Provides metrics, alerting, and optimization recommendations
    """
    
    def __init__(self):
        self.metrics_buffer: List[PerformanceMetrics] = []
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'total_requests': 0
        }
        self.slow_operations = []  # Track operations > 5 seconds
        
    def performance_timer(self, operation: str, user_id: int = 0, rule_count: int = 0):
        """Decorator to measure performance of operations"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                start_time = time.time()
                errors = 0
                
                try:
                    result = await func(*args, **kwargs)
                    
                    # Extract actual metrics from result if available
                    actual_rule_count = rule_count
                    if isinstance(result, dict):
                        actual_rule_count = result.get('total_rules', rule_count)
                    elif isinstance(result, list):
                        actual_rule_count = len(result)
                    
                    return result
                    
                except Exception as e:
                    errors = 1
                    raise
                    
                finally:
                    duration_ms = (time.time() - start_time) * 1000
                    
                    # Create metrics record
                    metrics = PerformanceMetrics(
                        operation=operation,
                        duration_ms=duration_ms,
                        user_id=user_id,
                        rule_count=actual_rule_count,
                        errors=errors
                    )
                    
                    # Record metrics
                    await self._record_metrics(metrics)
                    
                    # Alert on slow operations
                    if duration_ms > 5000:  # > 5 seconds
                        await self._alert_slow_operation(metrics)
            
            return wrapper
        return decorator
    
    async def _record_metrics(self, metrics: PerformanceMetrics):
        """Record performance metrics"""
        self.metrics_buffer.append(metrics)
        
        # Log significant operations
        if metrics.duration_ms > 1000:  # > 1 second
            logger.warning(
                f"Slow custom rules operation: {metrics.operation} "
                f"took {metrics.duration_ms:.2f}ms for {metrics.rule_count} rules (user: {metrics.user_id})"
            )
        
        # Periodically flush metrics buffer
        if len(self.metrics_buffer) > 100:
            await self._flush_metrics()
    
    async def _alert_slow_operation(self, metrics: PerformanceMetrics):
        """Alert on operations that are too slow"""
        self.slow_operations.append(metrics)
        
        logger.error(
            f"CRITICAL: Slow custom rules operation detected - "
            f"{metrics.operation} took {metrics.duration_ms:.2f}ms "
            f"for {metrics.rule_count} rules (user: {metrics.user_id})"
        )
        
        # TODO: Send alert to monitoring system (e.g., Datadog, New Relic)
    
    async def _flush_metrics(self):
        """Flush metrics buffer to storage/monitoring system"""
        if not self.metrics_buffer:
            return
        
        try:
            # Convert metrics to JSON for storage
            metrics_json = [asdict(metric) for metric in self.metrics_buffer]
            
            # TODO: Send to monitoring service
            logger.info(f"Flushed {len(self.metrics_buffer)} performance metrics")
            
            # Clear buffer
            self.metrics_buffer.clear()
            
        except Exception as e:
            logger.error(f"Error flushing performance metrics: {str(e)}")
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary statistics"""
        if not self.metrics_buffer:
            return {"status": "no_data"}
        
        # Calculate statistics
        durations = [m.duration_ms for m in self.metrics_buffer]
        rule_counts = [m.rule_count for m in self.metrics_buffer]
        
        return {
            "total_operations": len(self.metrics_buffer),
            "avg_duration_ms": sum(durations) / len(durations),
            "max_duration_ms": max(durations),
            "min_duration_ms": min(durations),
            "avg_rule_count": sum(rule_counts) / len(rule_counts) if rule_counts else 0,
            "max_rule_count": max(rule_counts) if rule_counts else 0,
            "slow_operations": len(self.slow_operations),
            "cache_hit_rate": self._calculate_cache_hit_rate(),
            "recommendations": self._generate_recommendations()
        }
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total_requests = self.cache_stats['total_requests']
        if total_requests == 0:
            return 0.0
        
        return self.cache_stats['hits'] / total_requests
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance optimization recommendations"""
        recommendations = []
        
        if not self.metrics_buffer:
            return recommendations
        
        # Check for slow operations
        slow_ops = [m for m in self.metrics_buffer if m.duration_ms > 2000]
        if slow_ops:
            recommendations.append(
                f"Found {len(slow_ops)} slow operations (>2s). Consider rule caching or pagination."
            )
        
        # Check for large rule sets
        large_rule_sets = [m for m in self.metrics_buffer if m.rule_count > 50]
        if large_rule_sets:
            recommendations.append(
                f"Found {len(large_rule_sets)} operations with >50 rules. Consider rule batching."
            )
        
        # Check cache performance
        hit_rate = self._calculate_cache_hit_rate()
        if hit_rate < 0.5:
            recommendations.append(
                f"Low cache hit rate ({hit_rate:.1%}). Consider improving caching strategy."
            )
        
        # Check error rates
        error_ops = [m for m in self.metrics_buffer if m.errors > 0]
        if error_ops:
            recommendations.append(
                f"Found {len(error_ops)} operations with errors. Review rule validation."
            )
        
        return recommendations
    
    async def monitor_memory_usage(self):
        """Monitor memory usage during rule processing"""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            
            if memory_mb > 500:  # Alert if > 500MB
                logger.warning(f"High memory usage in custom rules processing: {memory_mb:.1f}MB")
            
            return memory_mb
            
        except ImportError:
            logger.debug("psutil not available for memory monitoring")
            return None
    
    def record_cache_hit(self):
        """Record cache hit"""
        self.cache_stats['hits'] += 1
        self.cache_stats['total_requests'] += 1
    
    def record_cache_miss(self):
        """Record cache miss"""
        self.cache_stats['misses'] += 1
        self.cache_stats['total_requests'] += 1

# Global performance monitor instance
performance_monitor = CustomRulesPerformanceMonitor()

# Decorator for easy use
def monitor_performance(operation: str, user_id: int = 0, rule_count: int = 0):
    """Convenience decorator for performance monitoring"""
    return performance_monitor.performance_timer(operation, user_id, rule_count)