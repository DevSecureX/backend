"""
Performance monitoring and optimization utilities for the scanner
"""

import time
import psutil
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from functools import wraps
from contextlib import asynccontextmanager
import json

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    """Monitor and optimize scanner performance"""
    
    def __init__(self):
        self.metrics = {
            'tool_timings': {},
            'memory_usage': {},
            'file_processing': {},
            'bottlenecks': []
        }
        self.start_time = time.time()
        self.process = psutil.Process()
    
    @asynccontextmanager
    async def monitor_tool(self, tool_name: str):
        """Context manager to monitor tool execution"""
        start_time = time.time()
        start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        
        try:
            yield
        finally:
            end_time = time.time()
            end_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            
            duration = end_time - start_time
            memory_delta = end_memory - start_memory
            
            # Record metrics
            if tool_name not in self.metrics['tool_timings']:
                self.metrics['tool_timings'][tool_name] = []
            
            self.metrics['tool_timings'][tool_name].append({
                'duration': duration,
                'memory_delta': memory_delta,
                'timestamp': time.time()
            })
            
            # Log if slow
            if duration > 60:  # More than 1 minute
                logger.warning(f"Tool {tool_name} took {duration:.2f}s (memory: +{memory_delta:.1f}MB)")
                self.metrics['bottlenecks'].append({
                    'tool': tool_name,
                    'duration': duration,
                    'type': 'slow_execution'
                })
    
    def track_file_processing(self, file_path: str, issues_found: int, processing_time: float):
        """Track file processing metrics"""
        self.metrics['file_processing'][file_path] = {
            'issues_found': issues_found,
            'processing_time': processing_time,
            'issues_per_second': issues_found / processing_time if processing_time > 0 else 0
        }
    
    def get_optimization_suggestions(self) -> List[str]:
        """Generate optimization suggestions based on metrics"""
        suggestions = []
        
        # Analyze tool timings
        for tool, timings in self.metrics['tool_timings'].items():
            if not timings:
                continue
                
            avg_duration = sum(t['duration'] for t in timings) / len(timings)
            avg_memory = sum(t['memory_delta'] for t in timings) / len(timings)
            
            if avg_duration > 120:  # 2 minutes average
                suggestions.append(f"Consider optimizing {tool} - average runtime: {avg_duration:.1f}s")
            
            if avg_memory > 500:  # 500MB average
                suggestions.append(f"High memory usage in {tool} - average: {avg_memory:.1f}MB")
        
        # Check for bottlenecks
        if len(self.metrics['bottlenecks']) > 5:
            suggestions.append("Multiple performance bottlenecks detected - consider running in fast mode")
        
        # Memory usage suggestions
        current_memory = self.process.memory_info().rss / 1024 / 1024
        if current_memory > 2048:  # 2GB
            suggestions.append(f"High memory usage ({current_memory:.1f}MB) - consider reducing concurrency")
        
        return suggestions
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        total_time = time.time() - self.start_time
        
        # Calculate tool statistics
        tool_stats = {}
        for tool, timings in self.metrics['tool_timings'].items():
            if timings:
                tool_stats[tool] = {
                    'runs': len(timings),
                    'total_time': sum(t['duration'] for t in timings),
                    'avg_time': sum(t['duration'] for t in timings) / len(timings),
                    'max_time': max(t['duration'] for t in timings),
                    'total_memory': sum(t['memory_delta'] for t in timings)
                }
        
        # File processing statistics
        total_files = len(self.metrics['file_processing'])
        total_issues = sum(f['issues_found'] for f in self.metrics['file_processing'].values())
        
        return {
            'total_execution_time': total_time,
            'tool_statistics': tool_stats,
            'files_processed': total_files,
            'total_issues_found': total_issues,
            'bottlenecks': self.metrics['bottlenecks'],
            'optimization_suggestions': self.get_optimization_suggestions(),
            'memory_usage': {
                'current': self.process.memory_info().rss / 1024 / 1024,
                'peak': self.process.memory_info().rss / 1024 / 1024  # Would need tracking for real peak
            }
        }

class PerformanceOptimizer:
    """Optimize scanner performance based on system resources"""
    
    @staticmethod
    def get_optimal_concurrency() -> int:
        """Calculate optimal concurrency based on system resources"""
        cpu_count = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024 ** 3)
        
        # Base calculation: 50% of CPUs
        optimal = max(2, cpu_count // 2)
        
        # Adjust for memory (need at least 2GB per concurrent task)
        memory_limited = int(memory_gb / 2)
        optimal = min(optimal, memory_limited)
        
        # Cap at reasonable maximum
        optimal = min(optimal, 8)
        
        logger.info(f"Optimal concurrency: {optimal} (CPUs: {cpu_count}, Memory: {memory_gb:.1f}GB)")
        return optimal
    
    @staticmethod
    def should_skip_large_files(file_size: int, available_memory: int) -> bool:
        """Determine if a file is too large to process safely"""
        # Skip files larger than 10MB if low on memory
        if available_memory < 1024 * 1024 * 1024:  # Less than 1GB available
            return file_size > 10 * 1024 * 1024  # 10MB
        return file_size > 100 * 1024 * 1024  # 100MB normally
    
    @staticmethod
    async def run_with_timeout(coro: Callable, timeout: int, fallback_result: Any = None) -> Any:
        """Run coroutine with timeout and fallback"""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Operation timed out after {timeout}s")
            return fallback_result

def performance_tracked(func):
    """Decorator to track function performance"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        start_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            duration = time.time() - start_time
            end_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_delta = end_memory - start_memory
            
            if duration > 10:  # Log if takes more than 10 seconds
                logger.info(f"{func.__name__} completed in {duration:.2f}s (memory: +{memory_delta:.1f}MB)")
    
    return wrapper

class ScannerCache:
    """Simple in-memory cache for scanner operations"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        self.cache = {}
        self.max_size = max_size
        self.ttl = ttl
        self.access_times = {}
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key in self.cache:
            # Check TTL
            if time.time() - self.access_times[key] > self.ttl:
                del self.cache[key]
                del self.access_times[key]
                return None
            
            return self.cache[key]
        return None
    
    def set(self, key: str, value: Any):
        """Set value in cache"""
        # Evict oldest if at capacity
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.access_times, key=self.access_times.get)
            del self.cache[oldest_key]
            del self.access_times[oldest_key]
        
        self.cache[key] = value
        self.access_times[key] = time.time()
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
        self.access_times.clear()