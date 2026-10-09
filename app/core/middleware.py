"""
Optimized Middleware for DevSecureX Backend
Focuses on performance, concurrency, and proper resource management
"""

import asyncio
import time
import logging
from typing import Callable
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from .timeout_config import get_endpoint_timeout, OperationType
from .timeout_monitoring import record_timeout_event, record_success_event

logger = logging.getLogger(__name__)

class PerformanceMiddleware(BaseHTTPMiddleware):
    """Lightweight performance monitoring middleware"""
    
    def __init__(self, app, slow_request_threshold: float = 5.0):
        super().__init__(app)
        self.slow_request_threshold = slow_request_threshold
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        
        # Add request ID for tracing
        request.state.request_id = f"req_{int(start_time * 1000)}"
        
        try:
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log slow requests with context
            if duration > self.slow_request_threshold:
                logger.warning(
                    f"Slow request detected: {request.method} {request.url.path} "
                    f"took {duration:.2f}s (threshold: {self.slow_request_threshold}s) "
                    f"[request_id: {request.state.request_id}]"
                )
            
            # Record successful request for monitoring
            record_success_event(str(request.url.path), duration)
            
            # Add performance headers for debugging
            response.headers["X-Process-Time"] = str(round(duration, 3))
            response.headers["X-Request-ID"] = request.state.request_id
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"Request failed: {request.method} {request.url.path} "
                f"after {duration:.2f}s with error: {str(e)} "
                f"[request_id: {request.state.request_id}]"
            )
            raise

class ConcurrencyLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to limit concurrent requests and prevent resource exhaustion"""
    
    def __init__(self, app, max_concurrent_requests: int = 100):
        super().__init__(app)
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.max_concurrent = max_concurrent_requests
        self.active_requests = 0
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check if we can acquire the semaphore immediately
        if self.semaphore.locked():
            logger.warning(
                f"Request queue full ({self.max_concurrent} concurrent requests). "
                f"Rejecting {request.method} {request.url.path}"
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Service temporarily unavailable",
                    "detail": "Too many concurrent requests. Please try again later.",
                    "retry_after": 5
                },
                headers={"Retry-After": "5"}
            )
        
        async with self.semaphore:
            self.active_requests += 1
            try:
                # Add concurrency info to request state
                request.state.active_requests = self.active_requests
                request.state.max_concurrent = self.max_concurrent
                
                response = await call_next(request)
                
                # Add concurrency headers
                response.headers["X-Active-Requests"] = str(self.active_requests)
                response.headers["X-Max-Concurrent"] = str(self.max_concurrent)
                
                return response
            finally:
                self.active_requests -= 1

class TimeoutMiddleware(BaseHTTPMiddleware):
    """Enhanced timeout middleware with centralized timeout configuration"""
    
    def __init__(self, app):
        super().__init__(app)
        logger.info("TimeoutMiddleware initialized with centralized timeout configuration")
    
    def get_timeout_for_path(self, path: str) -> int:
        """Get timeout based on request path using centralized configuration"""
        return get_endpoint_timeout(path)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        timeout = self.get_timeout_for_path(str(request.url.path))
        start_time = time.time()
        
        try:
            response = await asyncio.wait_for(call_next(request), timeout=timeout)
            return response
            
        except asyncio.TimeoutError:
            # Calculate accurate duration
            actual_duration = time.time() - start_time
            request_id = getattr(request.state, 'request_id', 'unknown')
            user_agent = request.headers.get('user-agent')
            ip_address = request.client.host if request.client else None
            
            # Determine operation type based on endpoint
            operation_type = "cli_scanning" if "/cli-scan" in str(request.url.path) else "http_request"
            
            record_timeout_event(
                endpoint=str(request.url.path),
                operation_type=operation_type,
                timeout_duration=timeout,
                actual_duration=actual_duration,
                request_id=request_id,
                user_agent=user_agent,
                ip_address=ip_address
            )
            
            logger.error(
                f"Request timeout: {request.method} {request.url.path} "
                f"exceeded {timeout}s timeout (actual: {actual_duration:.2f}s) [request_id: {request_id}]"
            )
            
            # Provide specific guidance for CLI scan timeouts
            detail_message = f"Operation exceeded {timeout} seconds timeout."
            if "/cli-scan" in str(request.url.path):
                detail_message += " Consider reducing file count, breaking into smaller batches, or increasing the TIMEOUT_CLI_SCANNING environment variable."
            else:
                detail_message += " For long-running operations, consider using background processing."
                
            return JSONResponse(
                status_code=408,
                content={
                    "error": "Request timeout",
                    "detail": detail_message,
                    "timeout": timeout,
                    "actual_duration": round(actual_duration, 2),
                    "endpoint": str(request.url.path),
                    "retry_after": 60,  # Suggest retry after 1 minute
                    "request_id": request_id
                },
                headers={"Retry-After": "60"}
            )

class ResourceCleanupMiddleware(BaseHTTPMiddleware):
    """Middleware to ensure proper resource cleanup after requests"""
    
    # Endpoints that should not have aggressive task cancellation
    PROTECTED_ENDPOINTS = {
        "/repos/disconnect", "/repos/connect", "/cli-scan/scan", 
        "/scans/trigger", "/scans/manual"
    }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            # Log the exception with context
            logger.error(
                f"Unhandled exception in {request.method} {request.url.path}: {str(e)}"
            )
            
            # Only perform aggressive cleanup for non-critical endpoints
            if not any(protected in str(request.url.path) for protected in self.PROTECTED_ENDPOINTS):
                try:
                    # Limited resource cleanup - only cancel obviously orphaned tasks
                    current_task = asyncio.current_task()
                    if current_task and not current_task.done():
                        # Only cancel tasks that have been running for more than 30 seconds
                        # and are not the current task
                        all_tasks = [t for t in asyncio.all_tasks() if not t.done()]
                        for task in all_tasks:
                            if (task != current_task and 
                                not task.done() and 
                                hasattr(task, '_created_at') and
                                time.time() - getattr(task, '_created_at', time.time()) > 30):
                                task.cancel()
                except Exception as cleanup_error:
                    logger.warning(f"Error during resource cleanup: {cleanup_error}")
            else:
                logger.info(f"Skipping aggressive cleanup for protected endpoint: {request.url.path}")
            
            # Re-raise the original exception
            raise

class HealthCheckBypassMiddleware(BaseHTTPMiddleware):
    """Middleware to bypass heavy processing for health checks"""
    
    HEALTH_ENDPOINTS = {"/health", "/live", "/ready"}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip heavy middleware for health check endpoints
        if request.url.path in self.HEALTH_ENDPOINTS:
            return await call_next(request)
        
        # For all other endpoints, continue with normal processing
        return await call_next(request)

def add_performance_middlewares(app):
    """Add all performance-related middlewares to the FastAPI app"""
    
    # Add middlewares in reverse order (they're applied in LIFO order)
    
    # 1. Resource cleanup (outermost)
    app.add_middleware(ResourceCleanupMiddleware)
    
    # 2. Concurrency limiting
    max_concurrent = int(os.getenv("MAX_CONCURRENT_REQUESTS", "100"))
    app.add_middleware(ConcurrencyLimitMiddleware, max_concurrent_requests=max_concurrent)
    
    # 3. Timeout handling
    app.add_middleware(TimeoutMiddleware)
    
    # 4. Performance monitoring
    slow_threshold = float(os.getenv("SLOW_REQUEST_THRESHOLD", "5.0"))
    app.add_middleware(PerformanceMiddleware, slow_request_threshold=slow_threshold)
    
    # 5. Health check bypass (innermost, closest to actual endpoints)
    app.add_middleware(HealthCheckBypassMiddleware)
    
    logger.info(f"Performance middlewares added with max_concurrent={max_concurrent}, slow_threshold={slow_threshold}s")

# Import os for environment variables
import os