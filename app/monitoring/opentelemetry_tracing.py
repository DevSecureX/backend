"""
OpenTelemetry Distributed Tracing for DevSecureX Backend

Comprehensive distributed tracing implementation with:
- End-to-end request tracing across all services
- Automatic instrumentation for FastAPI, SQLAlchemy, Redis
- Custom spans for security scanning operations
- Trace correlation and context propagation
- Integration with Jaeger, Zipkin, and OTLP exporters
"""

import asyncio
import logging
import os
import time
import uuid
from typing import Dict, Any, Optional, List, Callable, Union
from contextlib import contextmanager, asynccontextmanager
from functools import wraps

from opentelemetry import trace, baggage, context
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource
try:
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
except ImportError:
    JaegerExporter = None

try:
    from opentelemetry.exporter.zipkin.json import ZipkinExporter
except ImportError:
    ZipkinExporter = None

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
except ImportError:
    OTLPSpanExporter = None
try:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
except ImportError:
    FastAPIInstrumentor = None

try:
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
except ImportError:
    SQLAlchemyInstrumentor = None

try:
    from opentelemetry.instrumentation.redis import RedisInstrumentor
except ImportError:
    RedisInstrumentor = None

try:
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
except ImportError:
    RequestsInstrumentor = None

try:
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
except ImportError:
    HTTPXClientInstrumentor = None
from opentelemetry.propagate import inject, extract
from opentelemetry.trace.status import Status, StatusCode
from opentelemetry.semconv.trace import SpanAttributes

from core.utils import utc_now_iso

logger = logging.getLogger(__name__)

class DevSecureXTracer:
    """Centralized tracing management for DevSecureX"""
    
    def __init__(self, service_name: str = "devsecurex-backend"):
        self.service_name = service_name
        self.tracer = None
        self._initialized = False
        
        # Tracing configuration
        self.config = {
            'enabled': os.getenv('TRACING_ENABLED', 'true').lower() == 'true',
            'service_name': service_name,
            'service_version': os.getenv('APP_VERSION', '1.0.0'),
            'environment': os.getenv('APP_ENV', 'development'),
            'sample_rate': float(os.getenv('TRACE_SAMPLE_RATE', '1.0')),
            
            # Exporters configuration
            'jaeger_endpoint': os.getenv('JAEGER_ENDPOINT'),
            'zipkin_endpoint': os.getenv('ZIPKIN_ENDPOINT'),
            'otlp_endpoint': os.getenv('OTLP_ENDPOINT'),
            'console_export': os.getenv('CONSOLE_TRACE_EXPORT', 'false').lower() == 'true'
        }
        
        # Performance tracking
        self.performance_stats = {
            'spans_created': 0,
            'spans_exported': 0,
            'export_errors': 0,
            'average_span_duration': 0.0
        }
    
    def initialize(self):
        """Initialize OpenTelemetry tracing"""
        if self._initialized or not self.config['enabled']:
            return
        
        try:
            # Create resource
            resource = Resource.create({
                "service.name": self.config['service_name'],
                "service.version": self.config['service_version'],
                "service.environment": self.config['environment'],
                "telemetry.sdk.name": "opentelemetry",
                "telemetry.sdk.language": "python"
            })
            
            # Set up tracer provider
            tracer_provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(tracer_provider)
            
            # Configure exporters
            self._setup_exporters(tracer_provider)
            
            # Get tracer
            self.tracer = trace.get_tracer(__name__)
            
            # Instrument libraries
            self._instrument_libraries()
            
            self._initialized = True
            logger.info(f"OpenTelemetry tracing initialized for service: {self.service_name}")
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry tracing: {e}", exc_info=True)
    
    def _setup_exporters(self, tracer_provider: TracerProvider):
        """Set up trace exporters based on configuration"""
        exporters = []
        
        # Console exporter for development
        if self.config['console_export']:
            console_exporter = ConsoleSpanExporter()
            console_processor = BatchSpanProcessor(console_exporter)
            tracer_provider.add_span_processor(console_processor)
            exporters.append('console')
        
        # Jaeger exporter
        if self.config['jaeger_endpoint'] and JaegerExporter:
            try:
                jaeger_exporter = JaegerExporter(
                    agent_host_name=self.config['jaeger_endpoint'].split(':')[0],
                    agent_port=int(self.config['jaeger_endpoint'].split(':')[1]) if ':' in self.config['jaeger_endpoint'] else 6831
                )
                jaeger_processor = BatchSpanProcessor(jaeger_exporter)
                tracer_provider.add_span_processor(jaeger_processor)
                exporters.append('jaeger')
            except Exception as e:
                logger.warning(f"Failed to configure Jaeger exporter: {e}")
        
        # Zipkin exporter
        if self.config['zipkin_endpoint'] and ZipkinExporter:
            try:
                zipkin_exporter = ZipkinExporter(endpoint=self.config['zipkin_endpoint'])
                zipkin_processor = BatchSpanProcessor(zipkin_exporter)
                tracer_provider.add_span_processor(zipkin_processor)
                exporters.append('zipkin')
            except Exception as e:
                logger.warning(f"Failed to configure Zipkin exporter: {e}")
        
        # OTLP exporter
        if self.config['otlp_endpoint'] and OTLPSpanExporter:
            try:
                otlp_exporter = OTLPSpanExporter(endpoint=self.config['otlp_endpoint'])
                otlp_processor = BatchSpanProcessor(otlp_exporter)
                tracer_provider.add_span_processor(otlp_processor)
                exporters.append('otlp')
            except Exception as e:
                logger.warning(f"Failed to configure OTLP exporter: {e}")
        
        if exporters:
            logger.info(f"Configured trace exporters: {', '.join(exporters)}")
        else:
            logger.warning("No trace exporters configured - traces will not be exported")
    
    def _instrument_libraries(self):
        """Automatically instrument common libraries"""
        try:
            instrumented = []
            
            # FastAPI instrumentation
            if FastAPIInstrumentor:
                FastAPIInstrumentor().instrument()
                instrumented.append("FastAPI")
            
            # SQLAlchemy instrumentation
            if SQLAlchemyInstrumentor:
                SQLAlchemyInstrumentor().instrument()
                instrumented.append("SQLAlchemy")
            
            # Redis instrumentation
            if RedisInstrumentor:
                RedisInstrumentor().instrument()
                instrumented.append("Redis")
            
            # HTTP client instrumentation
            if RequestsInstrumentor:
                RequestsInstrumentor().instrument()
                instrumented.append("Requests")
            
            if HTTPXClientInstrumentor:
                HTTPXClientInstrumentor().instrument()
                instrumented.append("HTTPX")
            
            if instrumented:
                logger.info(f"Auto-instrumentation configured for: {', '.join(instrumented)}")
            else:
                logger.warning("No instrumentation libraries available - traces will be limited")
            
        except Exception as e:
            logger.warning(f"Failed to configure auto-instrumentation: {e}")
    
    @contextmanager
    def start_span(
        self,
        name: str,
        kind: trace.SpanKind = trace.SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None,
        parent_context: Optional[context.Context] = None
    ):
        """Start a new span with comprehensive error handling"""
        if not self._initialized or not self.tracer:
            # Provide a no-op context manager when tracing is disabled
            yield None
            return
        
        start_time = time.time()
        
        try:
            # Create span
            span = self.tracer.start_span(
                name=name,
                kind=kind,
                context=parent_context
            )
            
            # Set attributes
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, str(value))
            
            # Set common attributes
            span.set_attribute("service.name", self.service_name)
            span.set_attribute("service.version", self.config['service_version'])
            span.set_attribute("environment", self.config['environment'])
            span.set_attribute("timestamp", utc_now_iso())
            
            self.performance_stats['spans_created'] += 1
            
            with trace.use_span(span, end_on_exit=True):
                try:
                    yield span
                    span.set_status(Status(StatusCode.OK))
                except Exception as e:
                    # Record exception in span
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
                finally:
                    # Update performance stats
                    duration = time.time() - start_time
                    self._update_performance_stats(duration)
                    
        except Exception as e:
            logger.error(f"Error in span creation: {e}", exc_info=True)
            yield None
    
    @asynccontextmanager
    async def start_async_span(
        self,
        name: str,
        kind: trace.SpanKind = trace.SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None,
        parent_context: Optional[context.Context] = None
    ):
        """Start an async span with comprehensive error handling"""
        if not self._initialized or not self.tracer:
            yield None
            return
        
        start_time = time.time()
        
        try:
            span = self.tracer.start_span(
                name=name,
                kind=kind,
                context=parent_context
            )
            
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, str(value))
            
            span.set_attribute("service.name", self.service_name)
            span.set_attribute("service.version", self.config['service_version'])
            span.set_attribute("environment", self.config['environment'])
            span.set_attribute("timestamp", utc_now_iso())
            span.set_attribute("async", True)
            
            self.performance_stats['spans_created'] += 1
            
            with trace.use_span(span, end_on_exit=True):
                try:
                    yield span
                    span.set_status(Status(StatusCode.OK))
                except Exception as e:
                    span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
                finally:
                    duration = time.time() - start_time
                    self._update_performance_stats(duration)
                    
        except Exception as e:
            logger.error(f"Error in async span creation: {e}", exc_info=True)
            yield None
    
    def _update_performance_stats(self, duration: float):
        """Update performance statistics"""
        # Simple moving average for span duration
        if self.performance_stats['spans_created'] == 1:
            self.performance_stats['average_span_duration'] = duration
        else:
            # Weighted average
            weight = 0.1
            self.performance_stats['average_span_duration'] = (
                (1 - weight) * self.performance_stats['average_span_duration'] +
                weight * duration
            )
    
    def add_span_attributes(self, span: trace.Span, attributes: Dict[str, Any]):
        """Add attributes to an existing span"""
        if not span or not attributes:
            return
        
        for key, value in attributes.items():
            try:
                span.set_attribute(key, str(value))
            except Exception as e:
                logger.warning(f"Failed to set span attribute {key}: {e}")
    
    def add_span_event(self, span: trace.Span, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Add an event to an existing span"""
        if not span:
            return
        
        try:
            span.add_event(name, attributes or {})
        except Exception as e:
            logger.warning(f"Failed to add span event {name}: {e}")
    
    def get_current_span(self) -> Optional[trace.Span]:
        """Get the current active span"""
        try:
            return trace.get_current_span()
        except Exception:
            return None
    
    def get_trace_id(self) -> Optional[str]:
        """Get the current trace ID"""
        try:
            current_span = self.get_current_span()
            if current_span and current_span.get_span_context().is_valid:
                return format(current_span.get_span_context().trace_id, '032x')
            return None
        except Exception:
            return None
    
    def get_span_id(self) -> Optional[str]:
        """Get the current span ID"""
        try:
            current_span = self.get_current_span()
            if current_span and current_span.get_span_context().is_valid:
                return format(current_span.get_span_context().span_id, '016x')
            return None
        except Exception:
            return None
    
    def inject_context(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Inject trace context into headers"""
        try:
            inject(headers)
            return headers
        except Exception as e:
            logger.warning(f"Failed to inject trace context: {e}")
            return headers
    
    def extract_context(self, headers: Dict[str, str]) -> Optional[context.Context]:
        """Extract trace context from headers"""
        try:
            return extract(headers)
        except Exception as e:
            logger.warning(f"Failed to extract trace context: {e}")
            return None
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get tracing performance statistics"""
        return {
            **self.performance_stats,
            'initialized': self._initialized,
            'enabled': self.config['enabled'],
            'service_name': self.service_name
        }

# Global tracer instance
_tracer_instance: Optional[DevSecureXTracer] = None

def get_tracer() -> DevSecureXTracer:
    """Get the global tracer instance"""
    global _tracer_instance
    
    if _tracer_instance is None:
        _tracer_instance = DevSecureXTracer()
        _tracer_instance.initialize()
    
    return _tracer_instance

def init_tracing(service_name: str = "devsecurex-backend") -> DevSecureXTracer:
    """Initialize global tracing"""
    global _tracer_instance
    
    if _tracer_instance is None:
        _tracer_instance = DevSecureXTracer(service_name)
        _tracer_instance.initialize()
        logger.info("Global OpenTelemetry tracing initialized")
    
    return _tracer_instance

# ===========================================
# SPECIALIZED TRACING CONTEXTS
# ===========================================

class DatabaseTracing:
    """Specialized tracing for database operations"""
    
    @staticmethod
    @contextmanager
    def trace_query(query_type: str, table: str, query: Optional[str] = None):
        """Trace database query execution"""
        tracer = get_tracer()
        
        attributes = {
            SpanAttributes.DB_OPERATION: query_type,
            SpanAttributes.DB_SQL_TABLE: table,
            "db.system": "postgresql"
        }
        
        if query:
            attributes[SpanAttributes.DB_STATEMENT] = query[:1000]  # Truncate long queries
        
        with tracer.start_span(
            f"db.{query_type}",
            kind=trace.SpanKind.CLIENT,
            attributes=attributes
        ) as span:
            yield span
    
    @staticmethod
    @contextmanager
    def trace_transaction(isolation_level: str = "default"):
        """Trace database transaction"""
        tracer = get_tracer()
        
        with tracer.start_span(
            "db.transaction",
            kind=trace.SpanKind.CLIENT,
            attributes={
                "db.system": "postgresql",
                "db.transaction.isolation_level": isolation_level
            }
        ) as span:
            yield span

class CacheTracing:
    """Specialized tracing for cache operations"""
    
    @staticmethod
    @contextmanager
    def trace_cache_operation(cache_type: str, operation: str, key: Optional[str] = None):
        """Trace cache operation"""
        tracer = get_tracer()
        
        attributes = {
            "cache.type": cache_type,
            "cache.operation": operation
        }
        
        if key:
            attributes["cache.key"] = key
        
        with tracer.start_span(
            f"cache.{operation}",
            kind=trace.SpanKind.CLIENT,
            attributes=attributes
        ) as span:
            yield span

class SecurityScanTracing:
    """Specialized tracing for security scanning operations"""
    
    @staticmethod
    @asynccontextmanager
    async def trace_security_scan(scan_type: str, tool: str, repository: Optional[str] = None):
        """Trace security scan execution"""
        tracer = get_tracer()
        
        attributes = {
            "scan.type": scan_type,
            "scan.tool": tool,
            "scan.category": "security"
        }
        
        if repository:
            attributes["scan.repository"] = repository
        
        async with tracer.start_async_span(
            f"scan.{scan_type}.{tool}",
            kind=trace.SpanKind.INTERNAL,
            attributes=attributes
        ) as span:
            yield span
    
    @staticmethod
    @asynccontextmanager
    async def trace_vulnerability_analysis(tool: str, file_count: int):
        """Trace vulnerability analysis"""
        tracer = get_tracer()
        
        async with tracer.start_async_span(
            f"analysis.vulnerability.{tool}",
            kind=trace.SpanKind.INTERNAL,
            attributes={
                "analysis.tool": tool,
                "analysis.file_count": file_count,
                "analysis.type": "vulnerability"
            }
        ) as span:
            yield span

class TaskSystemTracing:
    """Specialized tracing for task system operations"""
    
    @staticmethod
    @asynccontextmanager
    async def trace_task_execution(task_type: str, task_id: str, priority: str):
        """Trace task execution"""
        tracer = get_tracer()
        
        async with tracer.start_async_span(
            f"task.{task_type}",
            kind=trace.SpanKind.CONSUMER,
            attributes={
                "task.id": task_id,
                "task.type": task_type,
                "task.priority": priority,
                "messaging.operation": "process"
            }
        ) as span:
            yield span
    
    @staticmethod
    @contextmanager
    def trace_worker_scaling(action: str, worker_count: int):
        """Trace worker scaling operations"""
        tracer = get_tracer()
        
        with tracer.start_span(
            f"scaling.{action}",
            kind=trace.SpanKind.INTERNAL,
            attributes={
                "scaling.action": action,
                "scaling.worker_count": worker_count,
                "scaling.component": "auto_scaler"
            }
        ) as span:
            yield span

# ===========================================
# CONVENIENCE DECORATORS
# ===========================================

def trace_async_function(operation_name: Optional[str] = None, span_kind: trace.SpanKind = trace.SpanKind.INTERNAL):
    """Decorator for tracing async functions"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            name = operation_name or f"{func.__module__}.{func.__name__}"
            
            async with tracer.start_async_span(
                name,
                kind=span_kind,
                attributes={
                    "function.name": func.__name__,
                    "function.module": func.__module__
                }
            ) as span:
                # Add function arguments as attributes (be careful with sensitive data)
                if kwargs:
                    safe_kwargs = {k: str(v)[:100] for k, v in kwargs.items() 
                                 if not any(sensitive in k.lower() for sensitive in ['password', 'token', 'secret', 'key'])}
                    tracer.add_span_attributes(span, {"function.kwargs": str(safe_kwargs)})
                
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def trace_function(operation_name: Optional[str] = None, span_kind: trace.SpanKind = trace.SpanKind.INTERNAL):
    """Decorator for tracing synchronous functions"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            name = operation_name or f"{func.__module__}.{func.__name__}"
            
            with tracer.start_span(
                name,
                kind=span_kind,
                attributes={
                    "function.name": func.__name__,
                    "function.module": func.__module__
                }
            ) as span:
                if kwargs:
                    safe_kwargs = {k: str(v)[:100] for k, v in kwargs.items() 
                                 if not any(sensitive in k.lower() for sensitive in ['password', 'token', 'secret', 'key'])}
                    tracer.add_span_attributes(span, {"function.kwargs": str(safe_kwargs)})
                
                return func(*args, **kwargs)
        return wrapper
    return decorator

def trace_database_operation(query_type: str, table: str):
    """Decorator specifically for database operations"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            with DatabaseTracing.trace_query(query_type, table) as span:
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def trace_cache_operation(cache_type: str, operation: str):
    """Decorator specifically for cache operations"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            with CacheTracing.trace_cache_operation(cache_type, operation) as span:
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def trace_security_scan_operation(scan_type: str, tool: str):
    """Decorator specifically for security scan operations"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            async with SecurityScanTracing.trace_security_scan(scan_type, tool) as span:
                return await func(*args, **kwargs)
        return wrapper
    return decorator

# ===========================================
# CORRELATION ID MANAGEMENT
# ===========================================

class CorrelationManager:
    """Manage correlation IDs for request tracing"""
    
    @staticmethod
    def generate_correlation_id() -> str:
        """Generate a new correlation ID"""
        return str(uuid.uuid4())
    
    @staticmethod
    def get_correlation_id() -> Optional[str]:
        """Get correlation ID from current context"""
        try:
            # Try to get from trace context first
            tracer = get_tracer()
            trace_id = tracer.get_trace_id()
            if trace_id:
                return trace_id
            
            # Fallback to baggage
            return baggage.get_baggage("correlation_id")
        except Exception:
            return None
    
    @staticmethod
    def set_correlation_id(correlation_id: str):
        """Set correlation ID in current context"""
        try:
            # Set in baggage for propagation
            baggage.set_baggage("correlation_id", correlation_id)
            
            # Add to current span if available
            tracer = get_tracer()
            current_span = tracer.get_current_span()
            if current_span:
                current_span.set_attribute("correlation_id", correlation_id)
                
        except Exception as e:
            logger.warning(f"Failed to set correlation ID: {e}")
    
    @staticmethod
    def propagate_correlation_id(headers: Dict[str, str]) -> Dict[str, str]:
        """Propagate correlation ID in headers"""
        correlation_id = CorrelationManager.get_correlation_id()
        if correlation_id:
            headers["X-Correlation-ID"] = correlation_id
        return headers

# Initialize tracing on module import
if os.getenv('TRACING_ENABLED', 'true').lower() == 'true':
    try:
        init_tracing()
    except Exception as e:
        logger.warning(f"Failed to initialize tracing on import: {e}")