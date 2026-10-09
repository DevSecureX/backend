"""
Enhanced Structured Logging System for DevSecureX Backend

Features:
- JSON structured logging with correlation IDs
- Request tracing and context propagation  
- Performance metrics logging
- Security event logging
- Log aggregation and filtering
- Integration with OpenTelemetry tracing
- Real-time log streaming capabilities
- Centralized log configuration
"""

import asyncio
import json
import logging
import logging.config
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union, Callable
from contextlib import contextmanager
from functools import wraps

import structlog
from structlog.processors import JSONRenderer, TimeStamper, add_log_level, StackInfoRenderer
from structlog.contextvars import bind_contextvars, clear_contextvars, bound_contextvars

from monitoring.opentelemetry_tracing import get_tracer, CorrelationManager
from core.utils import utc_now_iso

# Global logger configuration
DEVSECUREX_LOGGER_NAME = "devsecurex"

class CorrelationProcessor:
    """Processor to add correlation ID and trace context to log records"""
    
    def __call__(self, logger, method_name, event_dict):
        # Add correlation ID
        correlation_id = CorrelationManager.get_correlation_id()
        if correlation_id:
            event_dict["correlation_id"] = correlation_id
        
        # Add trace context
        try:
            tracer = get_tracer()
            trace_id = tracer.get_trace_id()
            span_id = tracer.get_span_id()
            
            if trace_id:
                event_dict["trace_id"] = trace_id
            if span_id:
                event_dict["span_id"] = span_id
        except Exception:
            pass
        
        return event_dict

class PerformanceProcessor:
    """Processor to add performance context to log records"""
    
    def __call__(self, logger, method_name, event_dict):
        # Add performance timing if available
        if hasattr(structlog.get_context(), 'start_time'):
            start_time = structlog.get_context().get('start_time')
            if start_time:
                duration = time.time() - start_time
                event_dict["duration_ms"] = round(duration * 1000, 2)
        
        # Add memory usage if significant event
        if method_name in ['error', 'critical'] or event_dict.get('event_type') == 'performance':
            try:
                import psutil
                process = psutil.Process()
                event_dict["memory_mb"] = round(process.memory_info().rss / 1024 / 1024, 2)
                event_dict["cpu_percent"] = process.cpu_percent()
            except ImportError:
                pass
            except Exception:
                pass
        
        return event_dict

class SecurityEventProcessor:
    """Processor to enrich security-related log events"""
    
    def __call__(self, logger, method_name, event_dict):
        # Detect security events
        event_type = event_dict.get('event_type')
        if event_type in ['security_scan', 'vulnerability_found', 'auth_failure', 'access_denied']:
            event_dict["security_event"] = True
            event_dict["severity"] = self._determine_severity(event_type, event_dict)
        
        # Add security context
        if 'user_id' in event_dict:
            event_dict["user_context"] = True
        
        return event_dict
    
    def _determine_severity(self, event_type: str, event_dict: Dict[str, Any]) -> str:
        """Determine security event severity"""
        severity_map = {
            'vulnerability_found': event_dict.get('vulnerability_severity', 'medium'),
            'auth_failure': 'high',
            'access_denied': 'medium',
            'security_scan': 'low'
        }
        return severity_map.get(event_type, 'low')

class SanitizationProcessor:
    """Processor to sanitize sensitive information from logs"""
    
    SENSITIVE_KEYS = {
        'password', 'token', 'secret', 'key', 'api_key',
        'auth_token', 'access_token', 'refresh_token',
        'private_key', 'certificate', 'credential'
    }
    
    def __call__(self, logger, method_name, event_dict):
        return self._sanitize_dict(event_dict)
    
    def _sanitize_dict(self, data: Any) -> Any:
        """Recursively sanitize sensitive data"""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if isinstance(key, str) and any(sensitive in key.lower() for sensitive in self.SENSITIVE_KEYS):
                    sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = self._sanitize_dict(value)
            return sanitized
        elif isinstance(data, list):
            return [self._sanitize_dict(item) for item in data]
        elif isinstance(data, str) and len(data) > 100:
            # Truncate very long strings
            return data[:97] + "..."
        else:
            return data

class DevSecureXLogger:
    """Enhanced structured logger for DevSecureX"""
    
    def __init__(self, name: str = DEVSECUREX_LOGGER_NAME):
        self.name = name
        self.logger = None
        self._configured = False
        
        # Configuration
        self.config = {
            'level': os.getenv('LOG_LEVEL', 'INFO').upper(),
            'format': os.getenv('LOG_FORMAT', 'json'),  # json or console
            'output': os.getenv('LOG_OUTPUT', 'stdout'),  # stdout, file, or syslog
            'file_path': os.getenv('LOG_FILE_PATH', '/tmp/devsecurex.log'),
            'max_file_size': int(os.getenv('LOG_MAX_FILE_SIZE', '104857600')),  # 100MB
            'backup_count': int(os.getenv('LOG_BACKUP_COUNT', '5')),
            'enable_correlation': os.getenv('ENABLE_CORRELATION_LOGGING', 'true').lower() == 'true',
            'enable_performance': os.getenv('ENABLE_PERFORMANCE_LOGGING', 'true').lower() == 'true',
            'enable_security': os.getenv('ENABLE_SECURITY_LOGGING', 'true').lower() == 'true'
        }
        
        self.configure()
    
    def configure(self):
        """Configure structured logging"""
        if self._configured:
            return
        
        try:
            # Configure structlog
            processors = [
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                add_log_level,
                TimeStamper(fmt="iso"),
                StackInfoRenderer(),
            ]
            
            # Add custom processors based on configuration
            if self.config['enable_correlation']:
                processors.append(CorrelationProcessor())
            
            if self.config['enable_performance']:
                processors.append(PerformanceProcessor())
            
            if self.config['enable_security']:
                processors.append(SecurityEventProcessor())
            
            # Always add sanitization
            processors.append(SanitizationProcessor())
            
            # Add renderer based on format
            if self.config['format'] == 'json':
                processors.append(JSONRenderer(sort_keys=True))
            else:
                processors.append(structlog.dev.ConsoleRenderer(colors=True))
            
            structlog.configure(
                processors=processors,
                wrapper_class=structlog.stdlib.BoundLogger,
                logger_factory=structlog.stdlib.LoggerFactory(),
                cache_logger_on_first_use=True,
            )
            
            # Configure standard logging
            self._configure_standard_logging()
            
            # Get the structured logger
            self.logger = structlog.get_logger(self.name)
            
            self._configured = True
            self.logger.info("DevSecureX structured logging configured", 
                           config=self.config, logger_name=self.name)
            
        except Exception as e:
            print(f"Failed to configure logging: {e}", file=sys.stderr)
            # Fall back to basic logging
            logging.basicConfig(level=logging.INFO)
            self.logger = structlog.get_logger(self.name)
    
    def _configure_standard_logging(self):
        """Configure standard Python logging as the foundation"""
        # Create formatter
        if self.config['format'] == 'json':
            formatter = logging.Formatter(
                '%(message)s'  # structlog will handle the formatting
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        # Configure handler based on output type
        if self.config['output'] == 'file':
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler(
                self.config['file_path'],
                maxBytes=self.config['max_file_size'],
                backupCount=self.config['backup_count']
            )
        elif self.config['output'] == 'syslog':
            from logging.handlers import SysLogHandler
            handler = SysLogHandler(address='/dev/log')
        else:  # stdout
            handler = logging.StreamHandler(sys.stdout)
        
        handler.setFormatter(formatter)
        handler.setLevel(getattr(logging, self.config['level']))
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, self.config['level']))
        root_logger.addHandler(handler)
        
        # Configure our specific logger
        logger = logging.getLogger(self.name)
        logger.setLevel(getattr(logging, self.config['level']))
        logger.propagate = True
    
    @contextmanager
    def performance_context(self, operation: str, **kwargs):
        """Context manager for performance logging"""
        start_time = time.time()
        correlation_id = CorrelationManager.get_correlation_id() or str(uuid.uuid4())
        
        # Bind context variables
        with bound_contextvars(
            operation=operation,
            start_time=start_time,
            correlation_id=correlation_id,
            **kwargs
        ):
            try:
                yield
                # Log successful completion
                duration = time.time() - start_time
                self.logger.info(
                    "Operation completed successfully",
                    operation=operation,
                    duration_ms=round(duration * 1000, 2),
                    event_type="performance",
                    status="success"
                )
            except Exception as e:
                # Log error with performance context
                duration = time.time() - start_time
                self.logger.error(
                    "Operation failed",
                    operation=operation,
                    duration_ms=round(duration * 1000, 2),
                    event_type="performance",
                    status="error",
                    error=str(e),
                    error_type=type(e).__name__
                )
                raise
    
    @contextmanager
    def security_context(self, event_type: str, **kwargs):
        """Context manager for security event logging"""
        correlation_id = CorrelationManager.get_correlation_id() or str(uuid.uuid4())
        
        with bound_contextvars(
            event_type=event_type,
            correlation_id=correlation_id,
            **kwargs
        ):
            yield
    
    @contextmanager
    def user_context(self, user_id: str, **kwargs):
        """Context manager for user-specific logging"""
        with bound_contextvars(
            user_id=user_id,
            **kwargs
        ):
            yield
    
    def log_security_event(self, event_type: str, severity: str, message: str, **kwargs):
        """Log a security event"""
        log_method = getattr(self.logger, severity.lower(), self.logger.info)
        log_method(
            message,
            event_type=event_type,
            severity=severity,
            security_event=True,
            timestamp=utc_now_iso(),
            **kwargs
        )
    
    def log_vulnerability_found(self, tool: str, severity: str, vulnerability_type: str, 
                               file_path: str, line_number: Optional[int] = None, **kwargs):
        """Log vulnerability discovery"""
        self.logger.warning(
            "Vulnerability found during security scan",
            event_type="vulnerability_found",
            tool=tool,
            vulnerability_severity=severity,
            vulnerability_type=vulnerability_type,
            file_path=file_path,
            line_number=line_number,
            security_event=True,
            **kwargs
        )
    
    def log_scan_started(self, scan_type: str, tool: str, repository: str, **kwargs):
        """Log security scan start"""
        self.logger.info(
            "Security scan started",
            event_type="security_scan",
            scan_type=scan_type,
            tool=tool,
            repository=repository,
            status="started",
            **kwargs
        )
    
    def log_scan_completed(self, scan_type: str, tool: str, repository: str, 
                          duration_seconds: float, findings_count: int, **kwargs):
        """Log security scan completion"""
        self.logger.info(
            "Security scan completed",
            event_type="security_scan",
            scan_type=scan_type,
            tool=tool,
            repository=repository,
            status="completed",
            duration_seconds=duration_seconds,
            findings_count=findings_count,
            **kwargs
        )
    
    def log_task_event(self, task_type: str, task_id: str, status: str, **kwargs):
        """Log task system event"""
        log_level = 'info' if status in ['started', 'completed'] else 'error'
        log_method = getattr(self.logger, log_level)
        
        log_method(
            f"Task {status}",
            event_type="task_event",
            task_type=task_type,
            task_id=task_id,
            status=status,
            **kwargs
        )
    
    def log_api_request(self, method: str, endpoint: str, status_code: int, 
                       duration_ms: float, **kwargs):
        """Log API request"""
        log_level = 'info'
        if status_code >= 500:
            log_level = 'error'
        elif status_code >= 400:
            log_level = 'warning'
        
        log_method = getattr(self.logger, log_level)
        log_method(
            "API request processed",
            event_type="api_request",
            method=method,
            endpoint=endpoint,
            status_code=status_code,
            duration_ms=duration_ms,
            **kwargs
        )
    
    def log_database_operation(self, operation: str, table: str, duration_ms: float, 
                              status: str = "success", **kwargs):
        """Log database operation"""
        log_level = 'info' if status == 'success' else 'error'
        log_method = getattr(self.logger, log_level)
        
        log_method(
            f"Database {operation} operation",
            event_type="database_operation",
            operation=operation,
            table=table,
            duration_ms=duration_ms,
            status=status,
            **kwargs
        )
    
    def log_cache_operation(self, cache_type: str, operation: str, key: str, 
                           result: str, duration_ms: float, **kwargs):
        """Log cache operation"""
        self.logger.debug(
            f"Cache {operation} operation",
            event_type="cache_operation",
            cache_type=cache_type,
            operation=operation,
            key=key,
            result=result,
            duration_ms=duration_ms,
            **kwargs
        )
    
    def log_worker_scaling(self, action: str, worker_count: int, reason: str, **kwargs):
        """Log worker scaling event"""
        self.logger.info(
            f"Worker scaling: {action}",
            event_type="worker_scaling",
            action=action,
            worker_count=worker_count,
            reason=reason,
            **kwargs
        )
    
    def log_system_health(self, component: str, status: str, metrics: Dict[str, Any], **kwargs):
        """Log system health check"""
        log_level = 'info' if status == 'healthy' else 'warning'
        log_method = getattr(self.logger, log_level)
        
        log_method(
            f"Health check: {component} is {status}",
            event_type="health_check",
            component=component,
            status=status,
            metrics=metrics,
            **kwargs
        )
    
    def get_logger(self):
        """Get the underlying structlog logger"""
        return self.logger

# Global logger instance
_logger_instance: Optional[DevSecureXLogger] = None

def get_logger() -> DevSecureXLogger:
    """Get the global structured logger instance"""
    global _logger_instance
    
    if _logger_instance is None:
        _logger_instance = DevSecureXLogger()
    
    return _logger_instance

def init_logging(name: str = DEVSECUREX_LOGGER_NAME) -> DevSecureXLogger:
    """Initialize global structured logging"""
    global _logger_instance
    
    if _logger_instance is None:
        _logger_instance = DevSecureXLogger(name)
    
    return _logger_instance

# ===========================================
# CONVENIENCE DECORATORS
# ===========================================

def log_async_function(operation_name: Optional[str] = None, log_args: bool = False):
    """Decorator to log async function execution"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            logger = get_logger()
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            # Prepare context
            context = {"function": func.__name__, "module": func.__module__}
            if log_args and kwargs:
                # Only log safe arguments
                safe_kwargs = {k: str(v)[:100] for k, v in kwargs.items() 
                             if not any(sensitive in k.lower() for sensitive in 
                                      ['password', 'token', 'secret', 'key'])}
                context["arguments"] = safe_kwargs
            
            with logger.performance_context(op_name, **context):
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def log_function(operation_name: Optional[str] = None, log_args: bool = False):
    """Decorator to log synchronous function execution"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger()
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            
            context = {"function": func.__name__, "module": func.__module__}
            if log_args and kwargs:
                safe_kwargs = {k: str(v)[:100] for k, v in kwargs.items() 
                             if not any(sensitive in k.lower() for sensitive in 
                                      ['password', 'token', 'secret', 'key'])}
                context["arguments"] = safe_kwargs
            
            with logger.performance_context(op_name, **context):
                return func(*args, **kwargs)
        return wrapper
    return decorator

def log_security_operation(event_type: str):
    """Decorator to log security operations"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            logger = get_logger()
            
            with logger.security_context(event_type, function=func.__name__):
                return await func(*args, **kwargs)
        return wrapper
    return decorator

def log_with_correlation(func):
    """Decorator to ensure correlation ID is present"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Ensure correlation ID exists
        correlation_id = CorrelationManager.get_correlation_id()
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            CorrelationManager.set_correlation_id(correlation_id)
        
        return await func(*args, **kwargs)
    return wrapper

# ===========================================
# LOG AGGREGATION AND STREAMING
# ===========================================

class LogAggregator:
    """Aggregate and stream logs for real-time monitoring"""
    
    def __init__(self):
        self.listeners: List[Callable[[Dict[str, Any]], None]] = []
        self.buffer: List[Dict[str, Any]] = []
        self.buffer_size = int(os.getenv('LOG_BUFFER_SIZE', '1000'))
        
    def add_listener(self, callback: Callable[[Dict[str, Any]], None]):
        """Add a log event listener"""
        self.listeners.append(callback)
    
    def emit_log(self, log_record: Dict[str, Any]):
        """Emit a log record to all listeners"""
        self.buffer.append(log_record)
        
        # Maintain buffer size
        if len(self.buffer) > self.buffer_size:
            self.buffer = self.buffer[-self.buffer_size:]
        
        # Notify listeners
        for listener in self.listeners:
            try:
                listener(log_record)
            except Exception as e:
                print(f"Error in log listener: {e}", file=sys.stderr)
    
    def get_recent_logs(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get recent log records"""
        return self.buffer[-count:]
    
    def filter_logs(self, filter_func: Callable[[Dict[str, Any]], bool]) -> List[Dict[str, Any]]:
        """Filter logs based on criteria"""
        return [log for log in self.buffer if filter_func(log)]

# Global log aggregator
_log_aggregator = LogAggregator()

def get_log_aggregator() -> LogAggregator:
    """Get the global log aggregator"""
    return _log_aggregator

# ===========================================
# STRUCTURED LOG QUERIES
# ===========================================

class LogQuery:
    """Query interface for structured logs"""
    
    @staticmethod
    def get_security_events(hours: int = 24) -> List[Dict[str, Any]]:
        """Get security events from the last N hours"""
        aggregator = get_log_aggregator()
        cutoff_time = time.time() - (hours * 3600)
        
        return aggregator.filter_logs(
            lambda log: (
                log.get('security_event', False) and
                log.get('timestamp', 0) > cutoff_time
            )
        )
    
    @staticmethod
    def get_performance_issues(threshold_ms: float = 5000) -> List[Dict[str, Any]]:
        """Get performance issues above threshold"""
        aggregator = get_log_aggregator()
        
        return aggregator.filter_logs(
            lambda log: (
                log.get('event_type') == 'performance' and
                log.get('duration_ms', 0) > threshold_ms
            )
        )
    
    @staticmethod
    def get_error_logs(hours: int = 24) -> List[Dict[str, Any]]:
        """Get error logs from the last N hours"""
        aggregator = get_log_aggregator()
        cutoff_time = time.time() - (hours * 3600)
        
        return aggregator.filter_logs(
            lambda log: (
                log.get('level', '').lower() in ['error', 'critical'] and
                log.get('timestamp', 0) > cutoff_time
            )
        )
    
    @staticmethod
    def get_correlation_logs(correlation_id: str) -> List[Dict[str, Any]]:
        """Get all logs for a specific correlation ID"""
        aggregator = get_log_aggregator()
        
        return aggregator.filter_logs(
            lambda log: log.get('correlation_id') == correlation_id
        )

# Initialize logging on module import
try:
    init_logging()
except Exception as e:
    print(f"Failed to initialize logging on import: {e}", file=sys.stderr)