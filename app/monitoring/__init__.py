"""
DevSecureX Monitoring and Observability Suite

Complete enterprise-grade monitoring system including:
- Prometheus metrics collection and exposure
- OpenTelemetry distributed tracing
- Structured logging with correlation IDs
- Comprehensive health checks
- SLA monitoring and performance analytics
- Grafana dashboards and alerting
- Real-time performance monitoring
"""

from .prometheus_metrics import (
    PrometheusMetrics,
    get_metrics,
    init_metrics,
    track_db_query,
    track_async_operation,
    track_security_scan,
    track_http_request
)

from .opentelemetry_tracing import (
    DevSecureXTracer,
    get_tracer,
    init_tracing,
    DatabaseTracing,
    CacheTracing,
    SecurityScanTracing,
    TaskSystemTracing,
    trace_async_function,
    trace_function,
    trace_database_operation,
    trace_cache_operation,
    trace_security_scan_operation,
    CorrelationManager
)

from .structured_logging import (
    DevSecureXLogger,
    get_logger,
    init_logging,
    log_async_function,
    log_function,
    log_security_operation,
    log_with_correlation,
    LogAggregator,
    get_log_aggregator,
    LogQuery
)

from .comprehensive_health import (
    HealthStatus,
    ComponentType,
    HealthCheckResult,
    SystemHealth,
    ComprehensiveHealthSystem,
    get_health_system,
    init_health_system
)

# Temporarily disabled due to numpy dependency
# from .sla_performance_analytics import (
#     SLAType,
#     SLASeverity,
#     BusinessImpact,
#     SLATarget,
#     SLAMeasurement,
#     SLAViolation,
#     PerformanceAnalytics,
#     SLAMonitor,
#     get_sla_monitor,
#     init_sla_monitoring
# )

from .grafana_dashboards import (
    GrafanaDashboardGenerator,
    get_dashboard_generator,
    generate_all_dashboards
)

from .monitoring_routes import router as monitoring_router

__all__ = [
    # Prometheus Metrics
    'PrometheusMetrics',
    'get_metrics',
    'init_metrics',
    'track_db_query',
    'track_async_operation',
    'track_security_scan',
    'track_http_request',
    
    # Distributed Tracing
    'DevSecureXTracer',
    'get_tracer',
    'init_tracing',
    'DatabaseTracing',
    'CacheTracing',
    'SecurityScanTracing',
    'TaskSystemTracing',
    'trace_async_function',
    'trace_function',
    'trace_database_operation',
    'trace_cache_operation',
    'trace_security_scan_operation',
    'CorrelationManager',
    
    # Structured Logging
    'DevSecureXLogger',
    'get_logger',
    'init_logging',
    'log_async_function',
    'log_function',
    'log_security_operation',
    'log_with_correlation',
    'LogAggregator',
    'get_log_aggregator',
    'LogQuery',
    
    # Health Monitoring
    'HealthStatus',
    'ComponentType',
    'HealthCheckResult',
    'SystemHealth',
    'ComprehensiveHealthSystem',
    'get_health_system',
    'init_health_system',
    
    # SLA & Performance Analytics
    'SLAType',
    'SLASeverity',
    'BusinessImpact',
    'SLATarget',
    'SLAMeasurement',
    'SLAViolation',
    'PerformanceAnalytics',
    'SLAMonitor',
    'get_sla_monitor',
    'init_sla_monitoring',
    
    # Grafana Dashboards
    'GrafanaDashboardGenerator',
    'get_dashboard_generator',
    'generate_all_dashboards',
    
    # FastAPI Routes
    'monitoring_router'
]