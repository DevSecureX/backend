"""
Fortress Queue Manager - Platform Integration Wrapper
Integrates the unified fortress queue system into the DevSecureX platform startup.
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Global fortress queue manager instance
_fortress_queue_manager: Optional["FortressQueueManager"] = None
_fortress_queue_lock = asyncio.Lock()

class FortressQueueManager:
    """Platform integration wrapper for fortress queue system"""
    
    def __init__(self):
        self.queue_system = None
        self.is_initialized = False
        self.startup_time = None
        
    async def initialize(self) -> bool:
        """Initialize the fortress queue system"""
        try:
            logger.info("Initializing fortress queue management system...")
            
            # Import and initialize the unified fortress system
            from ..unified_queue import get_unified_queue_manager
            
            self.queue_system = await get_unified_queue_manager()
            
            self.is_initialized = True
            self.startup_time = datetime.now(timezone.utc)
            
            logger.info("✅ Fortress queue management system initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize fortress queue manager: {e}")
            self.is_initialized = False
            return False
    
    async def submit_scan(self, scan_request: Dict[str, Any]) -> str:
        """Submit a scan to the fortress queue system"""
        if not self.is_initialized or not self.queue_system:
            raise RuntimeError("Fortress queue manager not initialized")
            
        logger.info(f"🔧 FORTRESS WRAPPER: submit_scan called with: {scan_request}")
        result = await self.queue_system.enqueue_scan(**scan_request)
        logger.info(f"🔧 FORTRESS WRAPPER: enqueue_scan returned: {result}")
        return result
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status from the fortress system"""
        if not self.is_initialized or not self.queue_system:
            raise RuntimeError("Fortress queue manager not initialized")
            
        return await self.queue_system.get_job_status(scan_id)
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        if not self.is_initialized or not self.queue_system:
            return {
                "status": "not_initialized",
                "error": "Fortress queue manager not initialized"
            }
            
        stats = await self.queue_system.get_stats()
        stats.update({
            "manager_startup_time": self.startup_time.isoformat() if self.startup_time else None,
            "system_type": "fortress"
        })
        return stats
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the fortress system"""
        if not self.is_initialized or not self.queue_system:
            return {
                "status": "unhealthy",
                "error": "Fortress queue manager not initialized"
            }
            
        try:
            # Simple health check based on queue system availability
            health = {
                "status": "healthy" if self.queue_system else "unhealthy",
                "manager_status": "healthy",
                "system_type": "fortress",
                "queue_system_available": bool(self.queue_system)
            }
            return health
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": f"Health check failed: {str(e)}",
                "system_type": "fortress"
            }
    
    async def shutdown(self):
        """Shutdown the fortress queue system"""
        try:
            logger.info("Shutting down fortress queue management system...")
            
            if self.queue_system:
                from ..unified_queue import shutdown_unified_queue_manager
                await shutdown_unified_queue_manager()
            
            self.is_initialized = False
            self.queue_system = None
            logger.info("✅ Fortress queue management system shut down successfully")
            
        except Exception as e:
            logger.error(f"Error shutting down fortress queue manager: {e}")


# Global singleton functions for platform integration
async def get_fortress_queue_manager() -> FortressQueueManager:
    """Get or create the global fortress queue manager instance"""
    global _fortress_queue_manager
    
    async with _fortress_queue_lock:
        if _fortress_queue_manager is None:
            _fortress_queue_manager = FortressQueueManager()
            
            # Initialize the manager
            success = await _fortress_queue_manager.initialize()
            if not success:
                _fortress_queue_manager = None
                raise RuntimeError("Failed to initialize fortress queue manager")
        
        return _fortress_queue_manager


async def shutdown_fortress_queue_manager():
    """Shutdown the global fortress queue manager"""
    global _fortress_queue_manager
    
    if _fortress_queue_manager:
        await _fortress_queue_manager.shutdown()
        _fortress_queue_manager = None


# Health check function for platform integration
async def fortress_queue_health_check() -> Dict[str, Any]:
    """Platform health check for fortress queue system"""
    try:
        manager = await get_fortress_queue_manager()
        return await manager.health_check()
    except Exception as e:
        return {
            "status": "error",
            "error": f"Fortress queue health check failed: {str(e)}",
            "system_type": "fortress"
        }


# Queue stats function for monitoring
async def get_fortress_queue_stats() -> Dict[str, Any]:
    """Platform monitoring for fortress queue system"""
    try:
        manager = await get_fortress_queue_manager()
        return await manager.get_queue_stats()
    except Exception as e:
        return {
            "status": "error",
            "error": f"Failed to get fortress queue stats: {str(e)}",
            "system_type": "fortress"
        }