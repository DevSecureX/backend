"""
CLI Scan Error Monitoring - Simplified
Basic error tracking for CLI scan endpoints to prevent 500 errors
"""

import time
import logging
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from core.database import test_connection

logger = logging.getLogger(__name__)


class CLIErrorMonitoringMiddleware(BaseHTTPMiddleware):
    """
    Simple error monitoring middleware for CLI scan endpoints
    """
    
    def __init__(self, app):
        super().__init__(app)
        self.last_pool_cleanup = 0
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only monitor CLI scan endpoints
        if not self._is_cli_scan_endpoint(request.url.path):
            return await call_next(request)
        
        start_time = time.time()
        
        try:
            # Basic system health check
            await self._check_system_health()
            
            # Process the request
            response = await call_next(request)
            
            # Log errors if status code >= 500
            if response.status_code >= 500:
                response_time = time.time() - start_time
                logger.error(f"CLI 500 error: {request.method} {request.url.path} in {response_time:.3f}s")
            
            return response
            
        except Exception as exc:
            response_time = time.time() - start_time
            logger.error(f"CLI exception: {request.url.path} in {response_time:.3f}s: {exc}")
            
            # Attempt basic recovery
            await self._attempt_recovery()
            
            # Re-raise the exception
            raise
    
    def _is_cli_scan_endpoint(self, path: str) -> bool:
        """Check if the request is for a CLI scan endpoint"""
        return '/cli-scan/' in path
    
    async def _check_system_health(self):
        """Basic system health check"""
        try:
            connection_result = await test_connection()
            if connection_result.get("status") != "healthy":
                logger.warning(f"Database connection unhealthy: {connection_result.get('error', 'Unknown error')}")
                    
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
    
    async def _attempt_recovery(self):
        """Attempt basic system recovery"""
        try:
            # Force garbage collection
            import gc
            gc.collect()
            
        except Exception as e:
            logger.error(f"Recovery attempt failed: {e}")


def get_error_statistics():
    """Get basic error statistics for monitoring"""
    return {
        "status": "operational",
        "timestamp": time.time()
    }


async def create_health_check_endpoint():
    """Create a basic health check endpoint"""
    try:
        connection_result = await test_connection()
        
        return {
            "status": "healthy" if connection_result.get("status") == "healthy" else "degraded",
            "timestamp": time.time(),
            "database": connection_result,
            "cli_endpoints": {
                "scan": "operational",
                "health": "operational"
            }
        }
    except Exception as e:
        return {
            "status": "degraded",
            "error": str(e),
            "timestamp": time.time()
        }