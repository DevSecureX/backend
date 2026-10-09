"""
Prometheus Metrics Integration for DevSecureX Backend

Comprehensive metrics collection for all optimization phases:
- Database optimization metrics (Phase 1)
- Redis & caching performance (Phase 2) 
- Async operations & I/O (Phase 3)
- Background task processing (Phase 4)
- Security scanning operations
- Business metrics and SLA monitoring
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager

from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info,
    CollectorRegistry, multiprocess, generate_latest,
    CONTENT_TYPE_LATEST, push_to_gateway
)
from prometheus_client.multiprocess import MultiProcessCollector
from prometheus_client.exposition import MetricsHandler

from core.utils import utc_now_iso

logger = logging.getLogger(__name__)

class PrometheusMetrics:
    """Centralized Prometheus metrics management for DevSecureX"""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry()
        self._initialized = False
        
        # Performance tracking
        self.start_time = time.time()
        
        # Metrics containers
        self.counters: Dict[str, Counter] = {}
        self.histograms: Dict[str, Histogram] = {}
        self.gauges: Dict[str, Gauge] = {}
        self.summaries: Dict[str, Summary] = {}
        self.info_metrics: Dict[str, Info] = {}
        
        # Initialize all metrics
        self._init_metrics()
        
    def _init_metrics(self):
        """Initialize all Prometheus metrics"""
        
        # ===========================================
        # PHASE 1: DATABASE OPTIMIZATION METRICS
        # ===========================================
        
        # Connection Pool Metrics
        self.gauges['db_pool_size'] = Gauge(
            'db_pool_size_total',
            'Current database connection pool size',
            ['pool_type', 'status'],
            registry=self.registry
        )
        
        self.gauges['db_pool_checked_out'] = Gauge(
            'db_pool_checked_out_connections',
            'Currently checked out database connections',
            ['pool_name'],
            registry=self.registry
        )
        
        self.gauges['db_pool_overflow'] = Gauge(
            'db_pool_overflow_connections',
            'Current overflow database connections',
            ['pool_name'],
            registry=self.registry
        )
        
        self.counters['db_pool_checkouts'] = Counter(
            'db_pool_checkouts_total',
            'Total database connection checkouts',
            ['pool_name', 'status'],
            registry=self.registry
        )
        
        # Query Performance Metrics
        self.histograms['db_query_duration'] = Histogram(
            'db_query_duration_seconds',
            'Database query execution duration',
            ['query_type', 'table', 'status'],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0],
            registry=self.registry
        )
        
        self.counters['db_queries'] = Counter(
            'db_queries_total',
            'Total database queries executed',
            ['query_type', 'table', 'status'],
            registry=self.registry
        )
        
        self.gauges['db_active_queries'] = Gauge(
            'db_active_queries_current',
            'Currently active database queries',
            registry=self.registry
        )
        
        # Transaction Metrics
        self.counters['db_transactions'] = Counter(
            'db_transactions_total',
            'Database transactions',
            ['status', 'isolation_level'],
            registry=self.registry
        )
        
        self.histograms['db_transaction_duration'] = Histogram(
            'db_transaction_duration_seconds',
            'Database transaction duration',
            ['status'],
            registry=self.registry
        )
        
        # ===========================================
        # PHASE 2: REDIS & CACHING METRICS
        # ===========================================
        
        # Redis Connection Pool Metrics
        self.gauges['redis_pool_size'] = Gauge(
            'redis_pool_size_total',
            'Redis connection pool size',
            ['pool_name', 'pool_type'],
            registry=self.registry
        )
        
        self.counters['redis_pool_checkouts'] = Counter(
            'redis_pool_checkouts_total',
            'Redis connection pool checkouts',
            ['pool_name', 'status'],
            registry=self.registry
        )
        
        # Cache Performance Metrics
        self.counters['cache_operations'] = Counter(
            'cache_operations_total',
            'Cache operations by type and result',
            ['cache_type', 'operation', 'result'],
            registry=self.registry
        )
        
        self.histograms['cache_operation_duration'] = Histogram(
            'cache_operation_duration_seconds',
            'Cache operation duration',
            ['cache_type', 'operation'],
            buckets=[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
            registry=self.registry
        )
        
        self.gauges['cache_hit_rate'] = Gauge(
            'cache_hit_rate_percentage',
            'Cache hit rate percentage',
            ['cache_type'],
            registry=self.registry
        )
        
        self.gauges['cache_size'] = Gauge(
            'cache_size_bytes',
            'Cache size in bytes',
            ['cache_type', 'cache_name'],
            registry=self.registry
        )
        
        self.counters['cache_evictions'] = Counter(
            'cache_evictions_total',
            'Cache evictions by type',
            ['cache_type', 'reason'],
            registry=self.registry
        )
        
        # Multi-level Cache Metrics
        self.gauges['l1_cache_entries'] = Gauge(
            'l1_cache_entries_current',
            'Current L1 cache entries',
            ['cache_name'],
            registry=self.registry
        )
        
        self.gauges['l2_cache_entries'] = Gauge(
            'l2_cache_entries_current', 
            'Current L2 cache entries',
            ['cache_name'],
            registry=self.registry
        )
        
        # ===========================================
        # PHASE 3: ASYNC OPERATIONS & I/O METRICS
        # ===========================================
        
        # Async Operation Metrics
        self.counters['async_operations'] = Counter(
            'async_operations_total',
            'Async operations by type and status',
            ['operation_type', 'status'],
            registry=self.registry
        )
        
        self.histograms['async_operation_duration'] = Histogram(
            'async_operation_duration_seconds',
            'Async operation execution duration',
            ['operation_type'],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
            registry=self.registry
        )
        
        self.gauges['async_operations_active'] = Gauge(
            'async_operations_active_current',
            'Currently active async operations',
            ['operation_type'],
            registry=self.registry
        )
        
        # Concurrent Operations Tracking
        self.gauges['concurrent_operations'] = Gauge(
            'concurrent_operations_current',
            'Current concurrent operations',
            ['operation_category'],
            registry=self.registry
        )
        
        self.histograms['concurrent_batch_size'] = Histogram(
            'concurrent_batch_size',
            'Concurrent operation batch sizes',
            ['operation_type'],
            buckets=[1, 2, 5, 10, 20, 50, 100],
            registry=self.registry
        )
        
        # File I/O Metrics
        self.counters['file_operations'] = Counter(
            'file_operations_total',
            'File I/O operations',
            ['operation', 'file_type', 'status'],
            registry=self.registry
        )
        
        self.histograms['file_operation_duration'] = Histogram(
            'file_operation_duration_seconds',
            'File operation duration',
            ['operation', 'file_type'],
            registry=self.registry
        )
        
        self.histograms['file_size'] = Histogram(
            'file_size_bytes',
            'File sizes processed',
            ['operation', 'file_type'],
            buckets=[1024, 10240, 102400, 1048576, 10485760, 104857600],
            registry=self.registry
        )
        
        # Subprocess Metrics
        self.counters['subprocess_executions'] = Counter(
            'subprocess_executions_total',
            'Subprocess executions',
            ['command', 'status'],
            registry=self.registry
        )
        
        self.histograms['subprocess_duration'] = Histogram(
            'subprocess_duration_seconds',
            'Subprocess execution duration',
            ['command'],
            buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0],
            registry=self.registry
        )
        
        # ===========================================
        # PHASE 4: BACKGROUND TASK PROCESSING METRICS
        # ===========================================
        
        # Task Queue Metrics
        self.gauges['task_queue_size'] = Gauge(
            'task_queue_size_current',
            'Current task queue size',
            ['queue_name', 'priority'],
            registry=self.registry
        )
        
        self.counters['tasks_enqueued'] = Counter(
            'tasks_enqueued_total',
            'Total tasks enqueued',
            ['task_type', 'priority'],
            registry=self.registry
        )
        
        self.counters['tasks_processed'] = Counter(
            'tasks_processed_total',
            'Total tasks processed',
            ['task_type', 'status'],
            registry=self.registry
        )
        
        self.histograms['task_wait_time'] = Histogram(
            'task_wait_time_seconds',
            'Task wait time in queue',
            ['task_type', 'priority'],
            buckets=[1, 5, 10, 30, 60, 300, 600, 1800, 3600],
            registry=self.registry
        )
        
        self.histograms['task_execution_time'] = Histogram(
            'task_execution_time_seconds',
            'Task execution duration',
            ['task_type'],
            buckets=[1, 5, 10, 30, 60, 300, 600, 1800, 3600],
            registry=self.registry
        )
        
        # Worker Metrics
        self.gauges['workers_active'] = Gauge(
            'workers_active_current',
            'Currently active workers',
            ['worker_type'],
            registry=self.registry
        )
        
        self.gauges['worker_utilization'] = Gauge(
            'worker_utilization_percentage',
            'Worker utilization percentage',
            ['worker_id', 'worker_type'],
            registry=self.registry
        )
        
        self.counters['worker_scaling_events'] = Counter(
            'worker_scaling_events_total',
            'Worker scaling events',
            ['action', 'reason'],
            registry=self.registry
        )
        
        # Auto-scaling Metrics
        self.histograms['scaling_decision_time'] = Histogram(
            'scaling_decision_time_seconds',
            'Time taken to make scaling decisions',
            registry=self.registry
        )
        
        self.gauges['scaling_target_workers'] = Gauge(
            'scaling_target_workers',
            'Target number of workers from auto-scaling',
            registry=self.registry
        )
        
        # ===========================================
        # SECURITY SCANNING OPERATION METRICS
        # ===========================================
        
        # Scan Metrics
        self.counters['security_scans'] = Counter(
            'security_scans_total',
            'Security scans executed',
            ['scan_type', 'tool', 'status'],
            registry=self.registry
        )
        
        self.histograms['scan_duration'] = Histogram(
            'scan_duration_seconds',
            'Security scan duration',
            ['scan_type', 'tool'],
            buckets=[10, 30, 60, 300, 600, 1800, 3600, 7200],
            registry=self.registry
        )
        
        self.counters['vulnerabilities_found'] = Counter(
            'vulnerabilities_found_total',
            'Vulnerabilities found by scans',
            ['scan_type', 'tool', 'severity'],
            registry=self.registry
        )
        
        self.gauges['active_scans'] = Gauge(
            'active_scans_current',
            'Currently active security scans',
            ['scan_type'],
            registry=self.registry
        )
        
        # Repository Processing Metrics
        self.counters['repositories_processed'] = Counter(
            'repositories_processed_total',
            'Repositories processed',
            ['scan_type', 'status'],
            registry=self.registry
        )
        
        self.histograms['repository_size'] = Histogram(
            'repository_size_bytes',
            'Repository sizes processed',
            buckets=[1048576, 10485760, 104857600, 1073741824, 10737418240],
            registry=self.registry
        )
        
        self.counters['files_scanned'] = Counter(
            'files_scanned_total',
            'Files scanned by security tools',
            ['file_type', 'tool'],
            registry=self.registry
        )
        
        # ===========================================
        # BUSINESS METRICS & SLA MONITORING
        # ===========================================
        
        # API Performance Metrics
        self.counters['http_requests'] = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.histograms['http_request_duration'] = Histogram(
            'http_request_duration_seconds',
            'HTTP request duration',
            ['method', 'endpoint'],
            buckets=[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0],
            registry=self.registry
        )
        
        self.histograms['http_request_size'] = Histogram(
            'http_request_size_bytes',
            'HTTP request size',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        # SLA Compliance Metrics
        self.gauges['sla_compliance'] = Gauge(
            'sla_compliance_percentage',
            'SLA compliance percentage',
            ['service', 'sla_type'],
            registry=self.registry
        )
        
        self.counters['sla_violations'] = Counter(
            'sla_violations_total',
            'SLA violations',
            ['service', 'sla_type', 'severity'],
            registry=self.registry
        )
        
        # System Health Metrics
        self.gauges['system_health_score'] = Gauge(
            'system_health_score',
            'Overall system health score (0-100)',
            registry=self.registry
        )
        
        self.gauges['component_health'] = Gauge(
            'component_health_status',
            'Individual component health status',
            ['component', 'status'],
            registry=self.registry
        )
        
        # ===========================================
        # RESOURCE UTILIZATION METRICS
        # ===========================================
        
        # Memory Metrics
        self.gauges['memory_usage'] = Gauge(
            'memory_usage_bytes',
            'Memory usage by component',
            ['component'],
            registry=self.registry
        )
        
        self.gauges['memory_usage_percentage'] = Gauge(
            'memory_usage_percentage',
            'Memory usage percentage',
            ['component'],
            registry=self.registry
        )
        
        # CPU Metrics
        self.gauges['cpu_usage_percentage'] = Gauge(
            'cpu_usage_percentage',
            'CPU usage percentage',
            ['component'],
            registry=self.registry
        )
        
        # Application Info
        self.info_metrics['app_info'] = Info(
            'devsecurex_app_info',
            'DevSecureX application information',
            registry=self.registry
        )
        
        # Mark as initialized
        self._initialized = True
        logger.info("Prometheus metrics initialized successfully")
    
    # ===========================================
    # DATABASE METRICS METHODS
    # ===========================================
    
    def record_db_pool_status(self, pool_name: str, size: int, checked_out: int, overflow: int):
        """Record database pool status"""
        self.gauges['db_pool_size'].labels(pool_type=pool_name, status='total').set(size)
        self.gauges['db_pool_checked_out'].labels(pool_name=pool_name).set(checked_out)
        self.gauges['db_pool_overflow'].labels(pool_name=pool_name).set(overflow)
    
    def record_db_connection_checkout(self, pool_name: str, success: bool):
        """Record database connection checkout"""
        status = 'success' if success else 'failed'
        self.counters['db_pool_checkouts'].labels(pool_name=pool_name, status=status).inc()
    
    @contextmanager
    def time_db_query(self, query_type: str, table: str):
        """Context manager for timing database queries"""
        start_time = time.time()
        status = 'success'
        
        try:
            self.gauges['db_active_queries'].inc()
            yield
        except Exception as e:
            status = 'error'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['db_query_duration'].labels(
                query_type=query_type, table=table, status=status
            ).observe(duration)
            self.counters['db_queries'].labels(
                query_type=query_type, table=table, status=status
            ).inc()
            self.gauges['db_active_queries'].dec()
    
    @contextmanager
    def time_db_transaction(self, isolation_level: str = 'default'):
        """Context manager for timing database transactions"""
        start_time = time.time()
        status = 'success'
        
        try:
            yield
        except Exception as e:
            status = 'rollback'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['db_transaction_duration'].labels(status=status).observe(duration)
            self.counters['db_transactions'].labels(
                status=status, isolation_level=isolation_level
            ).inc()
    
    # ===========================================
    # REDIS & CACHING METRICS METHODS
    # ===========================================
    
    def record_redis_pool_status(self, pool_name: str, pool_type: str, size: int):
        """Record Redis pool status"""
        self.gauges['redis_pool_size'].labels(pool_name=pool_name, pool_type=pool_type).set(size)
    
    def record_redis_connection_checkout(self, pool_name: str, success: bool):
        """Record Redis connection checkout"""
        status = 'success' if success else 'failed'
        self.counters['redis_pool_checkouts'].labels(pool_name=pool_name, status=status).inc()
    
    @contextmanager
    def time_cache_operation(self, cache_type: str, operation: str):
        """Context manager for timing cache operations"""
        start_time = time.time()
        result = 'miss'  # Default
        
        try:
            yield lambda hit: setattr(self, '_cache_result', 'hit' if hit else 'miss')
            result = getattr(self, '_cache_result', 'miss')
        except Exception as e:
            result = 'error'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['cache_operation_duration'].labels(
                cache_type=cache_type, operation=operation
            ).observe(duration)
            self.counters['cache_operations'].labels(
                cache_type=cache_type, operation=operation, result=result
            ).inc()
    
    def record_cache_hit_rate(self, cache_type: str, hit_rate: float):
        """Record cache hit rate percentage"""
        self.gauges['cache_hit_rate'].labels(cache_type=cache_type).set(hit_rate)
    
    def record_cache_size(self, cache_type: str, cache_name: str, size_bytes: int):
        """Record cache size"""
        self.gauges['cache_size'].labels(cache_type=cache_type, cache_name=cache_name).set(size_bytes)
    
    def record_cache_eviction(self, cache_type: str, reason: str):
        """Record cache eviction"""
        self.counters['cache_evictions'].labels(cache_type=cache_type, reason=reason).inc()
    
    # ===========================================
    # ASYNC OPERATIONS METRICS METHODS
    # ===========================================
    
    @contextmanager
    def time_async_operation(self, operation_type: str):
        """Context manager for timing async operations"""
        start_time = time.time()
        status = 'success'
        
        self.gauges['async_operations_active'].labels(operation_type=operation_type).inc()
        
        try:
            yield
        except Exception as e:
            status = 'error'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['async_operation_duration'].labels(operation_type=operation_type).observe(duration)
            self.counters['async_operations'].labels(operation_type=operation_type, status=status).inc()
            self.gauges['async_operations_active'].labels(operation_type=operation_type).dec()
    
    def record_concurrent_operations(self, operation_category: str, count: int):
        """Record current concurrent operations count"""
        self.gauges['concurrent_operations'].labels(operation_category=operation_category).set(count)
    
    def record_concurrent_batch_size(self, operation_type: str, batch_size: int):
        """Record concurrent operation batch size"""
        self.histograms['concurrent_batch_size'].labels(operation_type=operation_type).observe(batch_size)
    
    @contextmanager
    def time_file_operation(self, operation: str, file_type: str, file_size: Optional[int] = None):
        """Context manager for timing file operations"""
        start_time = time.time()
        status = 'success'
        
        try:
            yield
        except Exception as e:
            status = 'error'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['file_operation_duration'].labels(
                operation=operation, file_type=file_type
            ).observe(duration)
            self.counters['file_operations'].labels(
                operation=operation, file_type=file_type, status=status
            ).inc()
            
            if file_size is not None:
                self.histograms['file_size'].labels(
                    operation=operation, file_type=file_type
                ).observe(file_size)
    
    @contextmanager
    def time_subprocess(self, command: str):
        """Context manager for timing subprocess execution"""
        start_time = time.time()
        status = 'success'
        
        try:
            yield
        except Exception as e:
            status = 'error'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['subprocess_duration'].labels(command=command).observe(duration)
            self.counters['subprocess_executions'].labels(command=command, status=status).inc()
    
    # ===========================================
    # TASK SYSTEM METRICS METHODS
    # ===========================================
    
    def record_task_enqueued(self, task_type: str, priority: str):
        """Record task enqueued"""
        self.counters['tasks_enqueued'].labels(task_type=task_type, priority=priority).inc()
    
    def record_task_processed(self, task_type: str, status: str, wait_time: float, execution_time: float):
        """Record task processing completion"""
        self.counters['tasks_processed'].labels(task_type=task_type, status=status).inc()
        self.histograms['task_wait_time'].labels(
            task_type=task_type, priority='normal'  # Default priority
        ).observe(wait_time)
        self.histograms['task_execution_time'].labels(task_type=task_type).observe(execution_time)
    
    def record_queue_size(self, queue_name: str, priority: str, size: int):
        """Record current queue size"""
        self.gauges['task_queue_size'].labels(queue_name=queue_name, priority=priority).set(size)
    
    def record_worker_status(self, worker_type: str, active_count: int):
        """Record worker status"""
        self.gauges['workers_active'].labels(worker_type=worker_type).set(active_count)
    
    def record_worker_utilization(self, worker_id: str, worker_type: str, utilization: float):
        """Record worker utilization percentage"""
        self.gauges['worker_utilization'].labels(
            worker_id=worker_id, worker_type=worker_type
        ).set(utilization)
    
    def record_scaling_event(self, action: str, reason: str, decision_time: float):
        """Record auto-scaling event"""
        self.counters['worker_scaling_events'].labels(action=action, reason=reason).inc()
        self.histograms['scaling_decision_time'].observe(decision_time)
    
    # ===========================================
    # SECURITY SCANNING METRICS METHODS
    # ===========================================
    
    @contextmanager
    def time_security_scan(self, scan_type: str, tool: str):
        """Context manager for timing security scans"""
        start_time = time.time()
        status = 'success'
        
        self.gauges['active_scans'].labels(scan_type=scan_type).inc()
        
        try:
            yield
        except Exception as e:
            status = 'error'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['scan_duration'].labels(scan_type=scan_type, tool=tool).observe(duration)
            self.counters['security_scans'].labels(scan_type=scan_type, tool=tool, status=status).inc()
            self.gauges['active_scans'].labels(scan_type=scan_type).dec()
    
    def record_vulnerabilities_found(self, scan_type: str, tool: str, severity: str, count: int):
        """Record vulnerabilities found"""
        for _ in range(count):
            self.counters['vulnerabilities_found'].labels(
                scan_type=scan_type, tool=tool, severity=severity
            ).inc()
    
    def record_repository_processed(self, scan_type: str, status: str, repo_size: int):
        """Record repository processing"""
        self.counters['repositories_processed'].labels(scan_type=scan_type, status=status).inc()
        self.histograms['repository_size'].observe(repo_size)
    
    def record_files_scanned(self, file_type: str, tool: str, count: int):
        """Record files scanned"""
        for _ in range(count):
            self.counters['files_scanned'].labels(file_type=file_type, tool=tool).inc()
    
    # ===========================================
    # HTTP & API METRICS METHODS
    # ===========================================
    
    @contextmanager
    def time_http_request(self, method: str, endpoint: str, request_size: Optional[int] = None):
        """Context manager for timing HTTP requests"""
        start_time = time.time()
        status_code = '500'  # Default error
        
        try:
            yield lambda code: setattr(self, '_status_code', str(code))
            status_code = getattr(self, '_status_code', '200')
        except Exception as e:
            status_code = '500'
            raise
        finally:
            duration = time.time() - start_time
            self.histograms['http_request_duration'].labels(
                method=method, endpoint=endpoint
            ).observe(duration)
            self.counters['http_requests'].labels(
                method=method, endpoint=endpoint, status_code=status_code
            ).inc()
            
            if request_size is not None:
                self.histograms['http_request_size'].labels(
                    method=method, endpoint=endpoint
                ).observe(request_size)
    
    # ===========================================
    # SLA & HEALTH METRICS METHODS
    # ===========================================
    
    def record_sla_compliance(self, service: str, sla_type: str, compliance_percentage: float):
        """Record SLA compliance percentage"""
        self.gauges['sla_compliance'].labels(service=service, sla_type=sla_type).set(compliance_percentage)
    
    def record_sla_violation(self, service: str, sla_type: str, severity: str):
        """Record SLA violation"""
        self.counters['sla_violations'].labels(
            service=service, sla_type=sla_type, severity=severity
        ).inc()
    
    def record_system_health_score(self, score: float):
        """Record overall system health score"""
        self.gauges['system_health_score'].set(score)
    
    def record_component_health(self, component: str, healthy: bool):
        """Record individual component health"""
        status = 'healthy' if healthy else 'unhealthy'
        self.gauges['component_health'].labels(component=component, status=status).set(1 if healthy else 0)
    
    # ===========================================
    # RESOURCE UTILIZATION METHODS
    # ===========================================
    
    def record_memory_usage(self, component: str, bytes_used: int, percentage: float):
        """Record memory usage"""
        self.gauges['memory_usage'].labels(component=component).set(bytes_used)
        self.gauges['memory_usage_percentage'].labels(component=component).set(percentage)
    
    def record_cpu_usage(self, component: str, percentage: float):
        """Record CPU usage"""
        self.gauges['cpu_usage_percentage'].labels(component=component).set(percentage)
    
    # ===========================================
    # UTILITY METHODS
    # ===========================================
    
    def set_app_info(self, version: str, environment: str, build_time: str):
        """Set application information"""
        self.info_metrics['app_info'].info({
            'version': version,
            'environment': environment,
            'build_time': build_time,
            'start_time': str(self.start_time)
        })
    
    def get_registry(self) -> CollectorRegistry:
        """Get the Prometheus registry"""
        return self.registry
    
    def generate_metrics(self) -> str:
        """Generate metrics in Prometheus format"""
        return generate_latest(self.registry)
    
    def get_content_type(self) -> str:
        """Get the content type for metrics"""
        return CONTENT_TYPE_LATEST
    
    async def push_to_gateway_async(self, gateway_url: str, job_name: str):
        """Push metrics to Prometheus push gateway"""
        try:
            push_to_gateway(gateway_url, job=job_name, registry=self.registry)
            logger.info(f"Metrics pushed to gateway: {gateway_url}")
        except Exception as e:
            logger.error(f"Failed to push metrics to gateway: {e}")
    
    def reset_metrics(self):
        """Reset all metrics (for testing)"""
        if not self._initialized:
            return
            
        # Clear all metrics
        for counter in self.counters.values():
            counter._value._value = 0
        
        for gauge in self.gauges.values():
            gauge._value._value = 0
        
        logger.info("All metrics reset")


# Global metrics instance
_metrics_instance: Optional[PrometheusMetrics] = None

def get_metrics() -> PrometheusMetrics:
    """Get the global Prometheus metrics instance"""
    global _metrics_instance
    
    if _metrics_instance is None:
        _metrics_instance = PrometheusMetrics()
    
    return _metrics_instance

def init_metrics(registry: Optional[CollectorRegistry] = None) -> PrometheusMetrics:
    """Initialize the global Prometheus metrics instance"""
    global _metrics_instance
    
    if _metrics_instance is None:
        _metrics_instance = PrometheusMetrics(registry)
        logger.info("Global Prometheus metrics initialized")
    
    return _metrics_instance

# Convenience decorators for common operations

def track_db_query(query_type: str, table: str):
    """Decorator to track database query metrics"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            metrics = get_metrics()
            with metrics.time_db_query(query_type, table):
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def track_async_operation(operation_type: str):
    """Decorator to track async operation metrics"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            metrics = get_metrics()
            with metrics.time_async_operation(operation_type):
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def track_security_scan(scan_type: str, tool: str):
    """Decorator to track security scan metrics"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            metrics = get_metrics()
            with metrics.time_security_scan(scan_type, tool):
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def track_http_request(method: str, endpoint: str):
    """Decorator to track HTTP request metrics"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            metrics = get_metrics()
            with metrics.time_http_request(method, endpoint) as set_status:
                try:
                    result = await func(*args, **kwargs)
                    set_status(200)  # Default success
                    return result
                except Exception as e:
                    set_status(500)  # Error status
                    raise
        return wrapper
    return decorator