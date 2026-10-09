"""
Enhanced Async Middleware for DevSecureX
Phase 3: High-performance async request processing and monitoring
"""

import asyncio
import time
import logging
import json
import uuid
from typing import Callable, Dict, Any, Optional, List
from datetime import datetime, timezone
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import psutil
import traceback

from core.async_file_io import AsyncFileIOManager, write_json_async

logger = logging.getLogger(__name__)

class AsyncPerformanceMiddleware(BaseHTTPMiddleware):
    """
    Advanced async performance monitoring middleware with comprehensive metrics
    
    Features:
    - Non-blocking request/response logging
    - Async performance metrics collection
    - Memory and CPU usage monitoring
    - Request tracing and correlation
    - Intelligent alerting for performance issues
    """
    
    def __init__(
        self, 
        app: ASGIApp,
        log_requests: bool = True,
        log_responses: bool = True,
        track_metrics: bool = True,
        alert_threshold_ms: float = 5000.0
    ):
        super().__init__(app)
        self.log_requests = log_requests
        self.log_responses = log_responses
        self.track_metrics = track_metrics
        self.alert_threshold_ms = alert_threshold_ms
        
        # Performance metrics
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_response_time": 0.0,
            "avg_response_time": 0.0,
            "min_response_time": float('inf'),
            "max_response_time": 0.0,
            "slow_requests": 0,
            "endpoints": {}
        }
        
        # File manager for async logging
        self.file_manager = AsyncFileIOManager()
        
        # Request tracking
        self.active_requests: Dict[str, Dict[str, Any]] = {}
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Dispatch requests with comprehensive async monitoring"""
        
        # Generate request ID for tracing
        request_id = str(uuid.uuid4())[:8]
        request.state.request_id = request_id
        
        # Capture request start time and system metrics
        start_time = time.time()
        start_cpu = psutil.cpu_percent()
        start_memory = psutil.virtual_memory().percent
        
        # Track active request
        request_info = {
            "request_id": request_id,
            "method": request.method,
            "url": str(request.url),
            "headers": dict(request.headers),
            "start_time": start_time,
            "start_cpu": start_cpu,
            "start_memory": start_memory
        }
        
        self.active_requests[request_id] = request_info
        
        # Log request asynchronously
        if self.log_requests:
            asyncio.create_task(self._log_request_async(request, request_id))
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate response time
            end_time = time.time()
            response_time_ms = (end_time - start_time) * 1000
            
            # Capture end system metrics
            end_cpu = psutil.cpu_percent()
            end_memory = psutil.virtual_memory().percent
            
            # Update metrics
            if self.track_metrics:
                await self._update_metrics_async(
                    request, response, response_time_ms, 
                    start_cpu, end_cpu, start_memory, end_memory
                )
            
            # Log response asynchronously
            if self.log_responses:
                asyncio.create_task(self._log_response_async(
                    request, response, response_time_ms, request_id
                ))
            
            # Alert on slow requests
            if response_time_ms > self.alert_threshold_ms:
                asyncio.create_task(self._alert_slow_request_async(
                    request, response_time_ms, request_id
                ))
            
            # Add performance headers
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{response_time_ms:.2f}ms"
            response.headers["X-Server-Timing"] = f"total;dur={response_time_ms:.2f}"
            
            return response
            
        except Exception as e:
            # Handle exceptions
            end_time = time.time()
            response_time_ms = (end_time - start_time) * 1000
            
            # Log error asynchronously
            asyncio.create_task(self._log_error_async(
                request, e, response_time_ms, request_id
            ))
            
            # Update error metrics
            if self.track_metrics:
                self.metrics["failed_requests"] += 1
                self.metrics["total_requests"] += 1
            
            # Return error response
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Internal server error",
                    "request_id": request_id,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                headers={
                    "X-Request-ID": request_id,
                    "X-Response-Time": f"{response_time_ms:.2f}ms"
                }
            )
            
        finally:
            # Clean up active request tracking
            self.active_requests.pop(request_id, None)
    
    async def _log_request_async(self, request: Request, request_id: str):
        """Log request details asynchronously"""
        try:
            # Extract request body if present and reasonable size
            request_body = None
            if hasattr(request, 'body') and request.headers.get('content-length'):
                content_length = int(request.headers.get('content-length', 0))
                if content_length > 0 and content_length < 10000:  # Max 10KB
                    try:
                        body_bytes = await request.body()
                        request_body = body_bytes.decode('utf-8')[:1000]  # First 1000 chars
                    except:
                        request_body = "<binary_or_invalid_utf8>"
            
            log_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "type": "request",
                "method": request.method,
                "url": str(request.url),
                "path": request.url.path,
                "query_params": dict(request.query_params),
                "headers": {k: v for k, v in request.headers.items() if k.lower() not in ['authorization', 'cookie']},
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "body_preview": request_body
            }
            
            logger.info(f"Request [{request_id}]: {request.method} {request.url.path}")
            
        except Exception as e:
            logger.error(f"Failed to log request async: {e}")
    
    async def _log_response_async(
        self, 
        request: Request, 
        response: Response, 
        response_time_ms: float,
        request_id: str
    ):
        """Log response details asynchronously"""
        try:
            log_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "type": "response",
                "status_code": response.status_code,
                "response_time_ms": response_time_ms,
                "headers": dict(response.headers),
                "method": request.method,
                "path": request.url.path
            }
            
            # Log level based on status code and response time
            if response.status_code >= 500:
                logger.error(f"Response [{request_id}]: {response.status_code} in {response_time_ms:.2f}ms")
            elif response.status_code >= 400:
                logger.warning(f"Response [{request_id}]: {response.status_code} in {response_time_ms:.2f}ms")
            elif response_time_ms > self.alert_threshold_ms:
                logger.warning(f"Slow Response [{request_id}]: {response.status_code} in {response_time_ms:.2f}ms")
            else:
                logger.info(f"Response [{request_id}]: {response.status_code} in {response_time_ms:.2f}ms")
                
        except Exception as e:
            logger.error(f"Failed to log response async: {e}")
    
    async def _log_error_async(
        self, 
        request: Request, 
        error: Exception, 
        response_time_ms: float,
        request_id: str
    ):
        """Log error details asynchronously"""
        try:
            log_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "type": "error",
                "error_type": type(error).__name__,
                "error_message": str(error),
                "traceback": traceback.format_exc(),
                "response_time_ms": response_time_ms,
                "method": request.method,
                "path": request.url.path,
                "url": str(request.url)
            }
            
            logger.error(f"Error [{request_id}]: {type(error).__name__}: {str(error)} in {response_time_ms:.2f}ms")
            
        except Exception as e:
            logger.error(f"Failed to log error async: {e}")
    
    async def _update_metrics_async(
        self,
        request: Request,
        response: Response,
        response_time_ms: float,
        start_cpu: float,
        end_cpu: float,
        start_memory: float,
        end_memory: float
    ):
        """Update performance metrics asynchronously"""
        try:
            # Update global metrics
            self.metrics["total_requests"] += 1
            
            if response.status_code < 400:
                self.metrics["successful_requests"] += 1
            else:
                self.metrics["failed_requests"] += 1
            
            # Update timing metrics
            self.metrics["total_response_time"] += response_time_ms
            self.metrics["avg_response_time"] = (
                self.metrics["total_response_time"] / self.metrics["total_requests"]
            )
            
            if response_time_ms < self.metrics["min_response_time"]:
                self.metrics["min_response_time"] = response_time_ms
            
            if response_time_ms > self.metrics["max_response_time"]:
                self.metrics["max_response_time"] = response_time_ms
            
            if response_time_ms > self.alert_threshold_ms:
                self.metrics["slow_requests"] += 1
            
            # Update endpoint-specific metrics
            endpoint = f"{request.method} {request.url.path}"
            if endpoint not in self.metrics["endpoints"]:
                self.metrics["endpoints"][endpoint] = {
                    "requests": 0,
                    "total_time": 0.0,
                    "avg_time": 0.0,
                    "min_time": float('inf'),
                    "max_time": 0.0,
                    "status_codes": {},
                    "cpu_usage": [],
                    "memory_usage": []
                }
            
            endpoint_metrics = self.metrics["endpoints"][endpoint]
            endpoint_metrics["requests"] += 1
            endpoint_metrics["total_time"] += response_time_ms
            endpoint_metrics["avg_time"] = endpoint_metrics["total_time"] / endpoint_metrics["requests"]
            
            if response_time_ms < endpoint_metrics["min_time"]:
                endpoint_metrics["min_time"] = response_time_ms
            
            if response_time_ms > endpoint_metrics["max_time"]:
                endpoint_metrics["max_time"] = response_time_ms
            
            # Track status codes
            status_code = str(response.status_code)
            endpoint_metrics["status_codes"][status_code] = (
                endpoint_metrics["status_codes"].get(status_code, 0) + 1
            )
            
            # Track system resource usage (keep last 100 measurements)
            cpu_delta = end_cpu - start_cpu
            memory_delta = end_memory - start_memory
            
            endpoint_metrics["cpu_usage"].append(cpu_delta)
            endpoint_metrics["memory_usage"].append(memory_delta)
            
            # Keep only last 100 measurements
            if len(endpoint_metrics["cpu_usage"]) > 100:
                endpoint_metrics["cpu_usage"] = endpoint_metrics["cpu_usage"][-100:]
            if len(endpoint_metrics["memory_usage"]) > 100:
                endpoint_metrics["memory_usage"] = endpoint_metrics["memory_usage"][-100:]
            
        except Exception as e:
            logger.error(f"Failed to update metrics async: {e}")
    
    async def _alert_slow_request_async(self, request: Request, response_time_ms: float, request_id: str):
        """Alert on slow requests asynchronously"""
        try:
            alert_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_type": "slow_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "url": str(request.url),
                "response_time_ms": response_time_ms,
                "threshold_ms": self.alert_threshold_ms,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "system_metrics": {
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent,
                    "active_requests": len(self.active_requests)
                }
            }
            
            logger.warning(
                f"SLOW REQUEST ALERT [{request_id}]: {request.method} {request.url.path} "
                f"took {response_time_ms:.2f}ms (threshold: {self.alert_threshold_ms}ms)"
            )
            
            # Could send to external monitoring system here
            
        except Exception as e:
            logger.error(f"Failed to send slow request alert: {e}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        metrics = self.metrics.copy()
        
        # Add current system metrics
        try:
            metrics["current_system"] = {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "active_requests": len(self.active_requests),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception:
            pass
        
        return metrics
    
    def reset_metrics(self):
        """Reset performance metrics"""
        self.metrics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "total_response_time": 0.0,
            "avg_response_time": 0.0,
            "min_response_time": float('inf'),
            "max_response_time": 0.0,
            "slow_requests": 0,
            "endpoints": {}
        }

class AsyncAuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Enhanced async authentication middleware with intelligent caching
    """
    
    def __init__(self, app: ASGIApp, excluded_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or ['/health', '/docs', '/openapi.json', '/ready', '/live']
        
        # Authentication cache to avoid redundant database lookups
        self.auth_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Dispatch with async authentication processing"""
        
        # Skip authentication for excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)
        
        # Extract authentication token asynchronously
        auth_result = await self._authenticate_async(request)
        
        if not auth_result["authenticated"]:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Authentication required",
                    "message": auth_result["message"],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
        
        # Add user info to request state
        request.state.user = auth_result["user"]
        request.state.authenticated = True
        
        return await call_next(request)
    
    async def _authenticate_async(self, request: Request) -> Dict[str, Any]:
        """Authenticate request asynchronously with caching"""
        try:
            # Extract authorization header
            auth_header = request.headers.get("authorization")
            if not auth_header:
                return {
                    "authenticated": False,
                    "message": "Authorization header missing"
                }
            
            # Parse bearer token
            if not auth_header.startswith("Bearer "):
                return {
                    "authenticated": False,
                    "message": "Invalid authorization format"
                }
            
            token = auth_header[7:]  # Remove "Bearer " prefix
            
            # Check cache first
            cached_result = await self._check_auth_cache_async(token)
            if cached_result:
                return cached_result
            
            # Authenticate with database (async operation)
            auth_result = await self._authenticate_with_database_async(token)
            
            # Cache successful authentication
            if auth_result["authenticated"]:
                await self._cache_auth_result_async(token, auth_result)
            
            return auth_result
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return {
                "authenticated": False,
                "message": "Authentication failed"
            }
    
    async def _check_auth_cache_async(self, token: str) -> Optional[Dict[str, Any]]:
        """Check authentication cache asynchronously"""
        try:
            cache_key = f"auth:{hash(token)}"  # Use hash for security
            
            if cache_key in self.auth_cache:
                cache_entry = self.auth_cache[cache_key]
                
                # Check if cache entry is still valid
                if time.time() - cache_entry["cached_at"] < self.cache_ttl:
                    return cache_entry["result"]
                else:
                    # Remove expired entry
                    del self.auth_cache[cache_key]
            
            return None
            
        except Exception as e:
            logger.debug(f"Auth cache check failed: {e}")
            return None
    
    async def _authenticate_with_database_async(self, token: str) -> Dict[str, Any]:
        """Authenticate with database asynchronously"""
        # This would be implemented based on your authentication system
        # For now, return a placeholder implementation
        
        try:
            # Simulate async database lookup
            await asyncio.sleep(0.01)  # Simulate small DB delay
            
            # This is where you'd integrate with your actual auth system
            # Example:
            # from auth.dependencies import verify_token_async
            # user = await verify_token_async(token)
            
            # Placeholder logic
            if token == "invalid_token":
                return {
                    "authenticated": False,
                    "message": "Invalid token"
                }
            
            return {
                "authenticated": True,
                "user": {
                    "id": 1,
                    "username": "authenticated_user",
                    "email": "user@example.com"
                }
            }
            
        except Exception as e:
            logger.error(f"Database authentication failed: {e}")
            return {
                "authenticated": False,
                "message": "Authentication service unavailable"
            }
    
    async def _cache_auth_result_async(self, token: str, auth_result: Dict[str, Any]):
        """Cache authentication result asynchronously"""
        try:
            cache_key = f"auth:{hash(token)}"
            
            self.auth_cache[cache_key] = {
                "result": auth_result,
                "cached_at": time.time()
            }
            
            # Clean up old cache entries (keep max 1000)
            if len(self.auth_cache) > 1000:
                # Remove oldest entries
                sorted_entries = sorted(
                    self.auth_cache.items(), 
                    key=lambda x: x[1]["cached_at"]
                )
                
                # Keep only the newest 800 entries
                entries_to_keep = sorted_entries[-800:]
                self.auth_cache = dict(entries_to_keep)
            
        except Exception as e:
            logger.debug(f"Auth cache update failed: {e}")

def add_async_middlewares(app):
    """Add all async middlewares to the FastAPI app"""
    
    # Add performance monitoring middleware
    app.add_middleware(AsyncPerformanceMiddleware)
    
    # Add authentication middleware (commented out - integrate with your auth system)
    # app.add_middleware(AsyncAuthenticationMiddleware)
    
    logger.info("Async middlewares added to FastAPI application")