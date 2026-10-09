"""
Fortress Worker Manager - Platform Integration Wrapper
Integrates the unified fortress worker system into the DevSecureX platform startup.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Global fortress worker manager instance
_fortress_worker_manager: Optional["FortressWorkerManager"] = None
_fortress_worker_lock = asyncio.Lock()

class FortressWorkerManager:
    """Platform integration wrapper for fortress worker system"""
    
    def __init__(self):
        self.worker_system = None
        self.is_initialized = False
        self.startup_time = None
        self.worker_tasks = []
        
    async def initialize(self) -> bool:
        """Initialize the fortress worker system"""
        try:
            logger.info("Initializing fortress worker management system...")
            
            # Import the unified fortress worker functions
            from scans.unified_queue import start_unified_worker
            
            self.start_unified_worker = start_unified_worker
            
            # Start the worker processes
            await self.start_workers()
            
            self.is_initialized = True
            self.startup_time = datetime.now(timezone.utc)
            
            logger.info("✅ Fortress worker management system initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize fortress worker manager: {e}")
            self.is_initialized = False
            return False
    
    async def start_workers(self):
        """Start fortress worker processes"""
        try:
            import os
            
            # Get configuration
            openai_api_key = os.getenv("OPENAI_API_KEY")
            if not openai_api_key:
                logger.warning("OPENAI_API_KEY not set - AI explanations will be disabled")
                openai_api_key = "dummy-key"
            
            # Support both SCAN_WORKERS (primary) and FORTRESS_WORKER_COUNT (fallback)
            # This ensures consistency with Docker environment variable mapping
            worker_count = int(os.getenv("SCAN_WORKERS", os.getenv("FORTRESS_WORKER_COUNT", "3")))
            
            logger.info(f"🔧 Starting {worker_count} fortress workers...")
            logger.info(f"🔧 Environment: SCAN_WORKERS={os.getenv('SCAN_WORKERS')}, FORTRESS_WORKER_COUNT={os.getenv('FORTRESS_WORKER_COUNT')}")
            
            successful_workers = 0
            # Start multiple workers
            for i in range(worker_count):
                worker_id = f"fortress-worker-{i+1}"
                try:
                    worker = await self.start_unified_worker(worker_id, openai_api_key)
                    logger.info(f"✅ Started fortress worker: {worker_id}")
                    successful_workers += 1
                except Exception as e:
                    logger.error(f"❌ Failed to start worker {worker_id}: {e}")
            
            if successful_workers > 0:
                logger.info(f"🎉 Fortress workers started: {successful_workers}/{worker_count} workers active")
            else:
                logger.error(f"❌ Failed to start any fortress workers: 0/{worker_count} workers active")
                raise Exception(f"Failed to start any fortress workers out of {worker_count} attempted")
            
        except Exception as e:
            logger.error(f"Failed to start fortress workers: {e}")
            raise
    
    async def get_worker_stats(self) -> Dict[str, Any]:
        """Get worker statistics"""
        if not self.is_initialized:
            return {
                "status": "not_initialized",
                "error": "Fortress worker manager not initialized",
                "workers_active": 0
            }
            
        try:
            # Get active workers from the unified system
            from scans.unified_queue.unified_worker import _active_workers
            
            worker_count = len(_active_workers)
            worker_ids = list(_active_workers.keys())
            
            stats = {
                "status": "active",
                "workers_active": worker_count,
                "worker_ids": worker_ids,
                "manager_startup_time": self.startup_time.isoformat() if self.startup_time else None,
                "system_type": "fortress"
            }
            return stats
        except Exception as e:
            return {
                "status": "error",
                "error": f"Failed to get worker stats: {str(e)}",
                "workers_active": 0,
                "system_type": "fortress"
            }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the fortress worker system"""
        if not self.is_initialized:
            return {
                "status": "unhealthy",
                "error": "Fortress worker manager not initialized"
            }
            
        try:
            # Get health status from workers
            from scans.unified_queue.unified_worker import _active_workers
            
            worker_count = len(_active_workers)
            healthy_workers = 0
            
            for worker_id, worker in _active_workers.items():
                if worker.running:
                    healthy_workers += 1
            
            health = {
                "status": "healthy" if healthy_workers > 0 else "unhealthy",
                "manager_status": "healthy",
                "system_type": "fortress",
                "workers_total": worker_count,
                "workers_healthy": healthy_workers,
                "workers_running": healthy_workers
            }
            
            if worker_count == 0:
                health["status"] = "unhealthy"
                health["error"] = "No workers active"
            
            return health
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": f"Health check failed: {str(e)}",
                "system_type": "fortress"
            }
    
    async def shutdown(self):
        """Shutdown the fortress worker system"""
        try:
            logger.info("Shutting down fortress worker management system...")
            
            # Stop all unified workers
            from scans.unified_queue import stop_all_unified_workers
            await stop_all_unified_workers()
                
            self.is_initialized = False
            self.start_unified_worker = None
            
            logger.info("✅ Fortress worker management system shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during fortress worker manager shutdown: {e}")


async def get_fortress_worker_manager() -> FortressWorkerManager:
    """Get or create the global fortress worker manager instance"""
    global _fortress_worker_manager
    
    async with _fortress_worker_lock:
        if _fortress_worker_manager is None:
            _fortress_worker_manager = FortressWorkerManager()
            await _fortress_worker_manager.initialize()
        
        return _fortress_worker_manager


async def shutdown_fortress_worker_manager():
    """Shutdown the global fortress worker manager"""
    global _fortress_worker_manager
    
    async with _fortress_worker_lock:
        if _fortress_worker_manager:
            await _fortress_worker_manager.shutdown()
            _fortress_worker_manager = None


# Health check function for platform integration
async def fortress_worker_health_check() -> Dict[str, Any]:
    """Platform health check for fortress worker system"""
    try:
        manager = await get_fortress_worker_manager()
        return await manager.health_check()
    except Exception as e:
        return {
            "status": "error",
            "error": f"Fortress worker health check failed: {str(e)}",
            "system_type": "fortress"
        }


# Worker stats function for monitoring
async def get_fortress_worker_stats() -> Dict[str, Any]:
    """Platform monitoring for fortress worker system"""
    try:
        manager = await get_fortress_worker_manager()
        return await manager.get_worker_stats()
    except Exception as e:
        return {
            "status": "error",
            "error": f"Failed to get fortress worker stats: {str(e)}",
            "system_type": "fortress"
        }