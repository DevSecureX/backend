"""
Signal Handlers for Graceful Worker Shutdown
Provides SIGTERM/SIGINT handlers for all worker processes to ensure clean shutdown
"""

import signal
import asyncio
import logging
import sys
import threading
from typing import Optional, Callable, Any
from functools import wraps

logger = logging.getLogger(__name__)


class GracefulShutdownHandler:
    """
    CRITICAL FIX: Graceful shutdown handler for worker processes
    Ensures workers shut down cleanly without losing data or leaving orphaned resources
    """
    
    def __init__(self, worker_name: str = "unknown"):
        self.worker_name = worker_name
        self.shutdown_event = asyncio.Event()
        self.cleanup_callbacks: list[Callable] = []
        self.shutdown_timeout = 30  # 30 seconds for graceful shutdown
        self.force_shutdown_timeout = 60  # 60 seconds before force kill
        self._shutdown_in_progress = False
        
        # Track original signal handlers to restore if needed
        self._original_handlers = {}
        
        logger.info(f"Graceful shutdown handler initialized for {worker_name}")
    
    def add_cleanup_callback(self, callback: Callable):
        """Add a cleanup callback to be called during shutdown"""
        self.cleanup_callbacks.append(callback)
        logger.debug(f"Added cleanup callback for {self.worker_name}")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        try:
            # Handle SIGTERM (Docker/systemd shutdown)
            self._original_handlers[signal.SIGTERM] = signal.signal(
                signal.SIGTERM, self._signal_handler
            )
            
            # Handle SIGINT (Ctrl+C)
            self._original_handlers[signal.SIGINT] = signal.signal(
                signal.SIGINT, self._signal_handler
            )
            
            # Handle SIGUSR1 for worker reload (if supported)
            if hasattr(signal, 'SIGUSR1'):
                self._original_handlers[signal.SIGUSR1] = signal.signal(
                    signal.SIGUSR1, self._reload_handler
                )
            
            logger.info(f"Signal handlers configured for {self.worker_name}")
            
        except ValueError as e:
            # This can happen if not in main thread
            logger.warning(f"Could not setup signal handlers for {self.worker_name}: {e}")
        except Exception as e:
            logger.error(f"Error setting up signal handlers for {self.worker_name}: {e}")
    
    def _signal_handler(self, signum: int, frame: Any):
        """Handle shutdown signals"""
        signal_name = signal.Signals(signum).name
        logger.info(f"Received {signal_name} signal for {self.worker_name} - initiating graceful shutdown")
        
        if self._shutdown_in_progress:
            logger.warning(f"Shutdown already in progress for {self.worker_name}")
            return
        
        self._shutdown_in_progress = True
        
        # Set the shutdown event
        try:
            # Get the current event loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(self.shutdown_event.set)
                # Schedule the graceful shutdown
                asyncio.create_task(self._graceful_shutdown())
            else:
                # No event loop, perform synchronous shutdown
                self._sync_shutdown()
        except RuntimeError:
            # No event loop available, perform synchronous shutdown
            self._sync_shutdown()
    
    def _reload_handler(self, signum: int, frame: Any):
        """Handle reload signals (SIGUSR1)"""
        logger.info(f"Received reload signal for {self.worker_name}")
        # This could trigger worker restart logic
        # For now, just log it
    
    async def _graceful_shutdown(self):
        """Perform graceful shutdown with timeout"""
        try:
            logger.info(f"Starting graceful shutdown for {self.worker_name}")
            
            # Run cleanup callbacks with timeout
            cleanup_tasks = []
            for callback in self.cleanup_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        cleanup_tasks.append(callback())
                    else:
                        # Run sync callbacks in thread pool
                        cleanup_tasks.append(
                            asyncio.get_event_loop().run_in_executor(None, callback)
                        )
                except Exception as e:
                    logger.error(f"Error preparing cleanup callback for {self.worker_name}: {e}")
            
            if cleanup_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*cleanup_tasks, return_exceptions=True),
                        timeout=self.shutdown_timeout
                    )
                    logger.info(f"Cleanup completed for {self.worker_name}")
                except asyncio.TimeoutError:
                    logger.warning(f"Cleanup timeout for {self.worker_name} - forcing shutdown")
                except Exception as e:
                    logger.error(f"Error during cleanup for {self.worker_name}: {e}")
            
            logger.info(f"Graceful shutdown completed for {self.worker_name}")
            
        except Exception as e:
            logger.error(f"Error during graceful shutdown for {self.worker_name}: {e}")
        finally:
            # Force exit after timeout
            asyncio.get_event_loop().call_later(
                self.force_shutdown_timeout - self.shutdown_timeout,
                self._force_exit
            )
    
    def _sync_shutdown(self):
        """Synchronous shutdown for cases where no event loop is available"""
        logger.info(f"Performing synchronous shutdown for {self.worker_name}")
        
        for callback in self.cleanup_callbacks:
            try:
                if not asyncio.iscoroutinefunction(callback):
                    callback()
                else:
                    logger.warning(f"Skipping async callback during sync shutdown: {callback}")
            except Exception as e:
                logger.error(f"Error in sync cleanup callback for {self.worker_name}: {e}")
        
        logger.info(f"Synchronous shutdown completed for {self.worker_name}")
        sys.exit(0)
    
    def _force_exit(self):
        """Force exit if graceful shutdown takes too long"""
        logger.error(f"Force exiting {self.worker_name} - graceful shutdown timeout exceeded")
        sys.exit(1)
    
    def is_shutdown_requested(self) -> bool:
        """Check if shutdown has been requested"""
        return self.shutdown_event.is_set()
    
    async def wait_for_shutdown(self):
        """Wait for shutdown signal"""
        await self.shutdown_event.wait()
    
    def restore_signal_handlers(self):
        """Restore original signal handlers"""
        for sig, handler in self._original_handlers.items():
            try:
                signal.signal(sig, handler)
            except Exception as e:
                logger.warning(f"Could not restore signal handler for {sig}: {e}")


def graceful_shutdown_wrapper(worker_name: str):
    """
    Decorator to add graceful shutdown support to worker functions
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            shutdown_handler = GracefulShutdownHandler(worker_name)
            shutdown_handler.setup_signal_handlers()
            
            try:
                # If the function accepts shutdown_handler, pass it
                import inspect
                sig = inspect.signature(func)
                if 'shutdown_handler' in sig.parameters:
                    kwargs['shutdown_handler'] = shutdown_handler
                
                return await func(*args, **kwargs)
            finally:
                shutdown_handler.restore_signal_handlers()
        
        return wrapper
    return decorator


# Global shutdown handlers for process-wide management
_global_shutdown_handlers = {}


def get_global_shutdown_handler(worker_name: str) -> GracefulShutdownHandler:
    """Get or create a global shutdown handler for a worker"""
    if worker_name not in _global_shutdown_handlers:
        _global_shutdown_handlers[worker_name] = GracefulShutdownHandler(worker_name)
        _global_shutdown_handlers[worker_name].setup_signal_handlers()
    
    return _global_shutdown_handlers[worker_name]


def cleanup_global_handlers():
    """Clean up all global shutdown handlers"""
    for handler in _global_shutdown_handlers.values():
        handler.restore_signal_handlers()
    _global_shutdown_handlers.clear()


# Production-ready signal handler for main processes
def setup_production_signal_handlers(app_name: str = "devsecurex"):
    """
    Setup production-grade signal handlers for the main application
    """
    def production_signal_handler(signum: int, frame: Any):
        signal_name = signal.Signals(signum).name
        logger.info(f"Production app {app_name} received {signal_name} - shutting down gracefully")
        
        # This will trigger the FastAPI lifespan shutdown
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Request graceful shutdown
                for task in asyncio.all_tasks(loop):
                    task.cancel()
            sys.exit(0)
        except Exception as e:
            logger.error(f"Error during production shutdown: {e}")
            sys.exit(1)
    
    try:
        signal.signal(signal.SIGTERM, production_signal_handler)
        signal.signal(signal.SIGINT, production_signal_handler)
        logger.info(f"Production signal handlers configured for {app_name}")
    except Exception as e:
        logger.warning(f"Could not setup production signal handlers: {e}")


# Worker health check integration
async def health_check_with_shutdown_support(
    health_check_func: Callable,
    shutdown_handler: GracefulShutdownHandler,
    check_interval: float = 30.0
):
    """
    Run health checks with shutdown support
    """
    while not shutdown_handler.is_shutdown_requested():
        try:
            await health_check_func()
            await asyncio.sleep(check_interval)
        except asyncio.CancelledError:
            logger.info("Health check cancelled - shutting down")
            break
        except Exception as e:
            logger.error(f"Health check error: {e}")
            await asyncio.sleep(check_interval)