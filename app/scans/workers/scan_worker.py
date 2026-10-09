import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException
from github import GithubException
from core.database import get_db
# Using unified fortress queue system for all scan operations
from ..scanner_engine import ScannerEngine
from ..ai.smart_explainer import SmartAIExplainer
from ..integrations.github_integration import GitHubIntegration
from ..models import Scan, ScanSummary
from auth.dependencies import decrypt_token

# Import all models to ensure proper SQLAlchemy relationship resolution
# This prevents "SupportQuery not found" errors when database sessions are created
import auth.models  # noqa: F401
import support.models  # noqa: F401
from core.issue_tracking import IssueTrackingService
from ..event_driven import event_system, WorkerEventType
from core.task_system.worker_coordinator import WorkerCoordinator, WorkerCapabilities

logger = logging.getLogger(__name__)

class ScanWorker:
    def __init__(self, worker_id: str, openai_api_key: str):
        self.worker_id = worker_id
        # Initialize fortress queue system for job distribution
        self.queue_manager = None  # Will be initialized in startup sequence with fortress queue
        self.scanner_engine = ScannerEngine()
        self.ai_explainer = SmartAIExplainer(openai_api_key)
        self.github_integration = GitHubIntegration()
        self.running = False
        self._stop_event = asyncio.Event()
        self._job_available_event = asyncio.Event()  # Event-driven job notification
        
        # CRITICAL FIX: Memory leak prevention tracking
        self._memory_tracking = {
            "jobs_processed": 0,
            "last_cleanup": time.time(),
            "cleanup_interval": 300,  # 5 minutes
            "max_jobs_before_cleanup": 50,
            "cached_objects": set(),
            "temp_files": set(),
            "active_connections": set()
        }
        
        # Check if we're in production environment
        self.is_production = os.getenv("APP_ENV", "development").lower() == "production"
        
        # Control AI analysis during scans (disabled by default for performance)
        # Set ENABLE_AI_DURING_SCAN=true to enable AI explanations during scanning
        # Note: AI explanations are always available on-demand via /scans/issues/explain API
        self.enable_ai_during_scan = os.getenv("ENABLE_AI_DURING_SCAN", "false").lower() == "true"
        
        # Event-driven configuration (NEW ARCHITECTURE) - OPTIMIZED FOR REDIS EFFICIENCY
        self.enable_event_driven = os.getenv("ENABLE_EVENT_DRIVEN_WORKERS", "true").lower() == "true"
        # CRITICAL FIX: Optimized fallback polling interval for responsiveness vs Redis efficiency 
        self.fallback_poll_interval = float(os.getenv("SCAN_WORKER_POLL_INTERVAL", "30"))  # 30 seconds for better responsiveness
        
        # CRITICAL FIX: Add adaptive polling to further reduce Redis calls
        self.adaptive_polling = True  # Enable adaptive polling behavior
        self.max_poll_interval = 1800  # Maximum 30 minutes between polls
        self.poll_backoff_multiplier = 1.5  # Gradually increase poll intervals when no jobs found
        
        # Subscription task for event-driven notifications
        self._subscription_task = None
        
        # CRITICAL FIX: Worker lifecycle management with proper state transitions
        self._worker_state = "starting"  # starting -> ready -> active -> stopping -> stopped
        self._state_lock = asyncio.Lock()
        self._readiness_checks = {
            "database": False,
            "redis": False,
            "queue_manager": False,
            "event_system": False
        }
        self._registration_timeout = 30.0  # 120 seconds max for registration (extended for complex startup)
        
        # Worker coordinator integration for proper lifecycle management
        self.coordinator = None
        self.capabilities = WorkerCapabilities(
            max_concurrent_tasks=2,
            supported_task_types=["security_scan", "general"],
            resource_limits={"cpu": 2.0, "memory": 1024},
            tags=["security", "scanner"]
        )
        
        # CRITICAL FIX: Enhanced resource cleanup tracking
        self._resource_cleanup_tasks = set()
        self._active_scans = {}
        self._scan_cleanup_registry = {}
        
        # CRITICAL FIX: Worker health monitoring integration
        self._health_monitor = None
        self._last_heartbeat = time.time()
        self._heartbeat_interval = 30  # 30 seconds
        self._heartbeat_task = None
        
        # Import time module for memory tracking
        import time
        
        logger.info(f"ScanWorker {worker_id} initialized (production: {self.is_production}, "
                   f"AI during scan: {self.enable_ai_during_scan}, "
                   f"event-driven: {self.enable_event_driven}, "
                   f"fallback poll: {self.fallback_poll_interval}s)")
        
    async def start(self):
        """Start the worker with proper startup sequence and readiness validation"""
        async with self._state_lock:
            if self._worker_state != "starting":
                logger.warning(f"Worker {self.worker_id} already in state {self._worker_state}, ignoring start()")
                return
        
        logger.info(f"Starting scan worker {self.worker_id} with readiness validation")
        
        # CRITICAL FIX: Implement proper startup sequence with readiness checks
        try:
            await asyncio.wait_for(
                self._perform_startup_sequence(),
                timeout=self._registration_timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Worker {self.worker_id} startup timed out after {self._registration_timeout}s")
            async with self._state_lock:
                self._worker_state = "failed"
            raise RuntimeError(f"Worker {self.worker_id} startup timed out")
        except Exception as e:
            logger.error(f"Worker {self.worker_id} startup failed: {e}")
            async with self._state_lock:
                self._worker_state = "failed"
            raise
    
    async def _perform_startup_sequence(self):
        """CRITICAL FIX: Perform complete startup sequence with readiness validation"""
        # Step 1: Validate database connectivity
        await self._validate_database_connectivity()
        
        # Step 2: Validate Redis connectivity  
        await self._validate_redis_connectivity()
        
        # Step 3: Validate queue manager
        await self._validate_queue_manager()
        
        # Step 4: Setup event system if enabled
        await self._setup_event_system()
        
        # Step 5: Transition to ready state
        async with self._state_lock:
            self._worker_state = "ready"
            logger.info(f"Worker {self.worker_id} is READY - all readiness checks passed")
        
        # Step 6: Register as active and start processing
        await self._register_as_active()
        
        # Step 7: Register with health monitor and start processing
        await self._register_with_health_monitor()
        
        self.running = True
        self.processing_task = asyncio.create_task(self._process_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info(f"🚀 Worker {self.worker_id} processing loop started as background task")
        
        # CRITICAL FIX: Immediately check for existing queued jobs on startup
        # This ensures stuck jobs don't wait for the fallback poll interval
        logger.info(f"Worker {self.worker_id} performing immediate startup queue check for existing jobs")
        await self._check_existing_queued_jobs()
        self._job_available_event.set()  # Trigger immediate job processing
    
    async def _validate_database_connectivity(self):
        """CRITICAL FIX: Validate database connectivity before marking worker as active"""
        logger.debug(f"Worker {self.worker_id}: Validating database connectivity")
        try:
            # Test database connection
            async for db_session in get_db():
                # Simple test query
                from sqlalchemy import text
                await db_session.execute(text("SELECT 1"))
                await db_session.close()
                break
            
            self._readiness_checks["database"] = True
            logger.info(f"✅ Worker {self.worker_id}: Database connectivity validated")
        except Exception as e:
            logger.error(f"❌ Worker {self.worker_id}: Database validation failed: {e}")
            raise RuntimeError(f"Database connectivity validation failed: {e}")
    
    async def _validate_redis_connectivity(self):
        """CRITICAL FIX: Validate Redis connectivity before marking worker as active"""
        logger.debug(f"Worker {self.worker_id}: Validating Redis connectivity")
        try:
            from core.redis_pool_manager import get_worker_redis_manager
            worker_manager = await get_worker_redis_manager()
            client = await worker_manager.get_shared_client()
            
            if not client:
                raise RuntimeError("Redis client unavailable")
            
            # Test Redis connection with timeout
            await asyncio.wait_for(client.ping(), timeout=5.0)
            
            self._readiness_checks["redis"] = True
            logger.info(f"✅ Worker {self.worker_id}: Redis connectivity validated")
        except Exception as e:
            logger.error(f"❌ Worker {self.worker_id}: Redis validation failed: {e}")
            raise RuntimeError(f"Redis connectivity validation failed: {e}")
    
    async def _validate_queue_manager(self):
        """CRITICAL FIX: Initialize and validate fortress queue manager (unified queue) before marking worker as active"""
        logger.debug(f"Worker {self.worker_id}: Initializing and validating fortress queue manager")
        try:
            # CRITICAL FIX: Initialize fortress queue manager (unified queue system)
            from scans.unified_queue import get_unified_queue_manager
            self.queue_manager = await get_unified_queue_manager()
            logger.info(f"✅ Worker {self.worker_id}: Fortress queue manager initialized")
            
            # Test queue manager connectivity
            test_stats = await self.queue_manager.get_queue_statistics()
            if test_stats is None:
                raise RuntimeError("Fortress queue manager returned None stats")
            
            logger.info(f"🏰 Worker {self.worker_id}: Fortress queue validated with {test_stats.get('total_queued', 0)} queued jobs")
            self._readiness_checks["queue_manager"] = True
            
        except Exception as e:
            logger.error(f"❌ Worker {self.worker_id}: Fortress queue manager initialization failed: {e}")
            # No fallback - fortress queue is the unified system
            raise RuntimeError(f"Fortress queue manager initialization failed: {e}")
    
    async def _setup_event_system(self):
        """CRITICAL FIX: Setup event system with proper error handling"""
        if not self.enable_event_driven:
            logger.info(f"Worker {self.worker_id}: Event-driven mode disabled, skipping event system setup")
            self._readiness_checks["event_system"] = True
            return
        
        logger.debug(f"Worker {self.worker_id}: Setting up event system")
        try:
            # Attempt to setup event subscription with timeout
            self._subscription_task = await asyncio.wait_for(
                event_system.subscribe_to_scan_jobs(
                    self.worker_id, 
                    self._on_job_notification
                ),
                timeout=10.0
            )
            
            if self._subscription_task:
                logger.info(f"✅ Worker {self.worker_id}: Event system subscription established")
                # Small delay to ensure subscription is fully active
                await asyncio.sleep(0.2)
            else:
                logger.warning(f"⚠️  Worker {self.worker_id}: Event system subscription failed, will use polling only")
            
            self._readiness_checks["event_system"] = True
        except asyncio.TimeoutError:
            logger.warning(f"⚠️  Worker {self.worker_id}: Event system setup timed out, falling back to polling")
            self._readiness_checks["event_system"] = True  # Don't fail startup for event system
        except Exception as e:
            logger.warning(f"⚠️  Worker {self.worker_id}: Event system setup failed: {e}, falling back to polling")
            self._readiness_checks["event_system"] = True  # Don't fail startup for event system
    
    async def _register_as_active(self):
        """CRITICAL FIX: Register worker as active only after all readiness checks pass"""
        # Verify all readiness checks passed
        failed_checks = [check for check, passed in self._readiness_checks.items() if not passed]
        if failed_checks:
            raise RuntimeError(f"Worker {self.worker_id} failed readiness checks: {failed_checks}")
        
        async with self._state_lock:
            self._worker_state = "active"
        
        # Register with coordinator if available
        if self.coordinator:
            try:
                await self.coordinator.register_worker(self.worker_id, self.capabilities)
                logger.info(f"✅ Worker {self.worker_id} registered with coordinator")
            except Exception as e:
                logger.warning(f"Failed to register with coordinator: {e}")
        
        logger.info(f"🚀 Worker {self.worker_id} is now ACTIVE and ready to process jobs")
    
    async def get_worker_state(self) -> str:
        """CRITICAL FIX: Get current worker state thread-safely"""
        async with self._state_lock:
            return self._worker_state
    
    async def _dequeue_job_unified(self) -> Optional[Dict[str, Any]]:
        """
        🏰 FORTRESS: Fortress queue job dequeue method using unified queue system.
        All jobs are processed through the fortress queue system.
        """
        try:
            # Use fortress queue (unified queue system) exclusively
            if hasattr(self.queue_manager, 'get_next_job'):
                logger.debug(f"Worker {self.worker_id}: Getting job from fortress queue")
                fortress_scan = await self.queue_manager.get_next_job(self.worker_id)
                
                if fortress_scan:
                    logger.info(f"🏰 Worker {self.worker_id}: Got job from fortress queue: {fortress_scan.scan_id}")
                    
                    # Convert fortress scan format to worker job format
                    job_data = {
                        'id': fortress_scan.scan_id,
                        'repo_full_name': fortress_scan.repo_full_name,
                        'scan_type': fortress_scan.scan_type,
                        'scan_data': fortress_scan.scan_config,
                        'priority': fortress_scan.priority.value if hasattr(fortress_scan.priority, 'value') else fortress_scan.priority,
                        'created_at': fortress_scan.queued_at.isoformat() if fortress_scan.queued_at else None,
                        'user_id': fortress_scan.user_id
                    }
                    
                    return job_data
            
            # No jobs available in fortress queue
            logger.debug(f"Worker {self.worker_id}: No jobs available in fortress queue")
            return None
            
        except Exception as e:
            logger.error(f"Error getting job from fortress queue for worker {self.worker_id}: {e}")
            return None
    
    async def _mark_job_completed_unified(self, job_id: str, db: AsyncSession = None):
        """
        🏰 FORTRESS: Mark job as completed in fortress queue system.
        """
        try:
            # Use fortress queue (unified queue system) exclusively
            if hasattr(self.queue_manager, 'mark_job_completed'):
                logger.debug(f"Worker {self.worker_id}: Marking job {job_id} as completed in fortress queue")
                await self.queue_manager.mark_job_completed(job_id, success=True)
                logger.info(f"🏰 Job {job_id} marked as completed in fortress queue")
                return
                
            logger.error(f"Fortress queue manager not available to mark job {job_id} as completed")
            
        except Exception as e:
            logger.error(f"Error marking job {job_id} as completed in fortress queue: {e}")
            # Don't fail the scan if completion marking fails
    
    async def _mark_job_failed_unified(self, job_id: str, error_message: str, retry: bool = True, db: AsyncSession = None):
        """
        🏰 FORTRESS: Mark job as failed in fortress queue system.
        """
        try:
            # Use fortress queue (unified queue system) exclusively
            if hasattr(self.queue_manager, 'mark_job_completed'):
                logger.debug(f"Worker {self.worker_id}: Marking job {job_id} as failed in fortress queue")
                await self.queue_manager.mark_job_completed(job_id, success=False, error=error_message)
                logger.info(f"🏰 Job {job_id} marked as failed in fortress queue")
                return
                
            logger.error(f"Fortress queue manager not available to mark job {job_id} as failed")
            
        except Exception as e:
            logger.error(f"Error marking job {job_id} as failed in fortress queue: {e}")
            # Don't fail the scan if error marking fails
    
    async def _update_job_scan_id_unified(self, job_id: str, scan_id: str, db: AsyncSession = None):
        """
        🏰 FORTRESS: Update job with scan_id in fortress queue system.
        """
        try:
            # Fortress queue handles scan_id updates through job metadata
            if hasattr(self.queue_manager, 'update_job_metadata'):
                logger.debug(f"Worker {self.worker_id}: Updating job {job_id} with scan_id {scan_id} in fortress queue")
                await self.queue_manager.update_job_metadata(job_id, {'scan_id': scan_id})
                logger.debug(f"🏰 Job {job_id} updated with scan_id {scan_id}")
                return
            
            # Fortress queue doesn't require scan_id updates - handled internally
            logger.debug(f"Job {job_id} scan_id update handled internally by fortress queue")
            
        except Exception as e:
            logger.error(f"Error updating job {job_id} with scan_id {scan_id}: {e}")
            # Don't fail the scan if scan_id update fails
    
    async def _update_job_status_unified(self, job_id: str, status: str, db: AsyncSession = None, error_message: str = None):
        """
        🏰 FORTRESS: Update job status in fortress queue system.
        """
        try:
            # Fortress queue handles status updates through job metadata
            if hasattr(self.queue_manager, 'update_job_status'):
                logger.debug(f"Worker {self.worker_id}: Updating job {job_id} status to {status} in fortress queue")
                await self.queue_manager.update_job_status(job_id, status, error_message=error_message)
                logger.debug(f"🏰 Job {job_id} status updated to {status}")
                return
            
            # Fortress queue handles status internally
            logger.debug(f"Job {job_id} status update handled internally by fortress queue")
            
        except Exception as e:
            logger.error(f"Error updating job {job_id} status to {status}: {e}")
            # Don't fail the scan if status update fails
    
    async def _check_existing_queued_jobs(self):
        """CRITICAL FIX: Check for existing queued jobs on worker startup and publish events"""
        try:
            from core.redis import get_redis_client
            import json
            
            redis_client = await get_redis_client()
            if not redis_client:
                logger.warning(f"Worker {self.worker_id}: Redis unavailable for startup queue check")
                return
            
            # Check if there are any queued scan jobs
            queue_items = await redis_client.zrange('scan_queue', 0, -1, withscores=True)
            
            if queue_items:
                logger.info(f"🔍 Worker {self.worker_id} found {len(queue_items)} existing jobs in queue on startup")
                
                # Publish events for existing jobs to wake up this and other workers
                try:
                    from ..event_driven import event_system
                    
                    for item, score in queue_items:
                        job_data = json.loads(item)
                        job_id = job_data['id']
                        repo_name = job_data.get('repo_full_name', 'unknown')
                        
                        logger.info(f"📢 Publishing startup event for existing job {job_id} ({repo_name})")
                        
                        # Publish event notification for existing job
                        await event_system.publish_scan_job_available(job_data)
                        
                except Exception as event_error:
                    logger.warning(f"Failed to publish events for existing jobs: {event_error}")
                    # Don't fail startup if event publishing fails
                
                logger.info(f"✅ Worker {self.worker_id} startup job check completed - published events for {len(queue_items)} existing jobs")
            else:
                logger.info(f"Worker {self.worker_id}: No existing jobs found in queue on startup")
                
        except Exception as e:
            logger.error(f"Error checking existing queued jobs on startup: {e}")
            # Don't fail startup if queue check fails
    
    async def stop(self):
        """Stop the worker gracefully with enhanced state management and cleanup"""
        async with self._state_lock:
            if self._worker_state in ["stopping", "stopped"]:
                logger.info(f"Worker {self.worker_id} already stopping/stopped")
                return
            
            logger.info(f"🛑 Stopping scan worker {self.worker_id} (current state: {self._worker_state})")
            self._worker_state = "stopping"
        
        self.running = False
        self._stop_event.set()
        
        # CRITICAL FIX: Enhanced event subscription cleanup
        if self._subscription_task:
            try:
                logger.info(f"Cancelling event subscription for worker {self.worker_id}")
                self._subscription_task.cancel()
                
                # Wait for cancellation with timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(self._subscription_task, return_exceptions=True),
                        timeout=10.0  # 10 second timeout for graceful shutdown
                    )
                    logger.info(f"✅ ScanWorker {self.worker_id} event subscription cancelled successfully")
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout cancelling event subscription for worker {self.worker_id}")
                except Exception as cancel_error:
                    logger.warning(f"Error during subscription cancellation for worker {self.worker_id}: {cancel_error}")
                    
            except Exception as e:
                logger.warning(f"Error unsubscribing from events for worker {self.worker_id}: {e}")
        
        # Cancel processing task if it exists
        if hasattr(self, 'processing_task') and self.processing_task:
            try:
                logger.info(f"Cancelling processing task for worker {self.worker_id}")
                self.processing_task.cancel()
                
                # Wait for cancellation with timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(self.processing_task, return_exceptions=True),
                        timeout=10.0  # 10 second timeout for graceful shutdown
                    )
                    logger.info(f"✅ ScanWorker {self.worker_id} processing task cancelled successfully")
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout cancelling processing task for worker {self.worker_id}")
                except Exception as cancel_error:
                    logger.warning(f"Error during processing task cancellation for worker {self.worker_id}: {cancel_error}")
                    
            except Exception as e:
                logger.warning(f"Error cancelling processing task for worker {self.worker_id}: {e}")
        
        # CRITICAL FIX: Clean up worker-specific Redis connections
        try:
            from core.redis_pool_manager import get_worker_redis_manager
            worker_manager = await get_worker_redis_manager()
            await worker_manager.cleanup_worker(self.worker_id)
            logger.info(f"✅ Worker {self.worker_id} Redis connections cleaned up successfully")
        except ImportError:
            logger.debug(f"Worker Redis manager not available for cleanup of {self.worker_id}")
        except Exception as cleanup_error:
            logger.warning(f"Worker Redis cleanup failed for {self.worker_id}: {cleanup_error}")
        
        # CRITICAL FIX: Final state transition to stopped
        async with self._state_lock:
            self._worker_state = "stopped"
        
        # CRITICAL FIX: Unregister from health monitor
        await self._unregister_from_health_monitor()
        
        # CRITICAL FIX: Stop heartbeat task
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # CRITICAL FIX: Final memory cleanup on worker stop
        await self._perform_final_cleanup()
        
        logger.info(f"✅ Scan worker {self.worker_id} stopped gracefully (final state: stopped)")
    
    async def _on_job_notification(self, event_data: dict):
        """Handle event-driven job notifications"""
        try:
            event_type = event_data.get("type")
            
            if event_type == WorkerEventType.SCAN_JOB_AVAILABLE.value:
                job_id = event_data.get("job_id")
                repo_name = event_data.get("repo_full_name")
                logger.info(f"🚀 ScanWorker {self.worker_id} received INSTANT job notification: {job_id} ({repo_name})")
                
                # CRITICAL FIX: Set the event to wake up the processing loop immediately
                if not self._job_available_event.is_set():
                    self._job_available_event.set()
                    logger.debug(f"Worker {self.worker_id} signaled processing loop for immediate job pickup")
                else:
                    logger.debug(f"Worker {self.worker_id} event already set, processing loop will handle")
                
            elif event_type == WorkerEventType.WORKER_SHUTDOWN.value:
                worker_type = event_data.get("worker_type")
                if worker_type == "scan" or worker_type == "all":
                    logger.info(f"ScanWorker {self.worker_id} received shutdown signal")
                    await self.stop()
            else:
                logger.debug(f"ScanWorker {self.worker_id} received unhandled event type: {event_type}")
            
        except Exception as e:
            logger.error(f"CRITICAL: Error handling job notification in worker {self.worker_id}: {e}", exc_info=True)
    
    async def _process_loop(self):
        """
        Hybrid event-driven + fallback polling architecture.
        
        NEW ARCHITECTURE:
        1. Primary: Event-driven notifications trigger immediate job processing
        2. Fallback: Minimal polling (2-5 minutes) for reliability
        3. Result: 99% reduction in Redis calls (from 80k+ to <1k per day)
        """
        logger.info(f"ScanWorker {self.worker_id} starting hybrid processing loop "
                   f"(event-driven: {self.enable_event_driven}, fallback poll: {self.fallback_poll_interval}s)")
        
        # CRITICAL FIX: Enhanced polling state with adaptive behavior
        last_fallback_poll = asyncio.get_event_loop().time()
        consecutive_failures = 0
        max_consecutive_failures = 3  # Reduced for faster failure detection
        
        # CRITICAL FIX: Adaptive polling variables to reduce Redis load
        consecutive_empty_polls = 0  # Track empty polls to increase interval
        current_poll_interval = self.fallback_poll_interval  # Start with base interval
        last_job_processed = asyncio.get_event_loop().time()  # Track when we last processed a job
        
        # CRITICAL FIX: Event rate limiting to prevent infinite loops
        last_event_time = 0
        event_rate_limit = 1.0  # Minimum 1 second between event notifications
        event_notifications_per_minute = 0
        last_minute_start = asyncio.get_event_loop().time()
        
        while self.running:
            # CRITICAL FIX: Process each job in its own session to prevent pool exhaustion
            try:
                await self._process_jobs_in_session_v2()
            except Exception as e:
                logger.error(f"Worker {self.worker_id} job processing error: {e}", exc_info=True)
                await asyncio.sleep(10)
                continue
    
    async def _get_db_session(self):
        """CRITICAL FIX: Proper database session context manager with retry logic"""
        from contextlib import asynccontextmanager
        from core.database import get_db_session, DatabaseOperation
        
        @asynccontextmanager
        async def session_manager():
            max_retries = 3
            last_error = None
            
            for attempt in range(max_retries):
                session = None
                try:
                    # CRITICAL FIX: Use proper session context
                    async with get_db_session(DatabaseOperation.WRITE) as db:
                        session = db
                        # Test the session
                        from sqlalchemy import text
                        await db.execute(text("SELECT 1"))
                        
                        yield db
                        
                        # CRITICAL FIX: Ensure session is committed on successful exit
                        await db.commit()
                        return
                        
                except Exception as e:
                    last_error = e
                    
                    # CRITICAL FIX: Ensure rollback on error
                    if session:
                        try:
                            await session.rollback()
                        except Exception as rollback_error:
                            logger.warning(f"Failed to rollback session: {rollback_error}")
                    
                    if attempt < max_retries - 1:
                        wait_time = (attempt + 1) * 2  # Exponential backoff
                        logger.warning(f"Database session failed for worker {self.worker_id} (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"Database session failed for worker {self.worker_id} after {max_retries} attempts: {e}")
                        raise last_error
        
        return session_manager()
    
    async def _process_jobs_in_session_v2(self):
        """CRITICAL FIX: Process jobs with proper session-per-job pattern to prevent pool exhaustion"""
        # Initialize adaptive polling variables
        last_fallback_poll = asyncio.get_event_loop().time()
        consecutive_failures = 0
        max_consecutive_failures = 3
        consecutive_empty_polls = 0
        current_poll_interval = self.fallback_poll_interval
        last_job_processed = asyncio.get_event_loop().time()
        last_event_time = 0
        event_rate_limit = 1.0
        event_notifications_per_minute = 0
        last_minute_start = asyncio.get_event_loop().time()
        
        while self.running:
            try:
                # CRITICAL FIX: HYBRID ARCHITECTURE with adaptive polling to minimize Redis calls
                current_time = asyncio.get_event_loop().time()
                should_fallback_poll = (current_time - last_fallback_poll) >= current_poll_interval
                
                if self.enable_event_driven and not should_fallback_poll:
                    # EVENT-DRIVEN MODE: Wait for job notification or adaptive timeout
                    try:
                        await asyncio.wait_for(
                            self._job_available_event.wait(), 
                            timeout=current_poll_interval  # Use adaptive interval
                        )
                        # CRITICAL FIX: Rate limit event notifications to prevent infinite loops
                        current_event_time = asyncio.get_event_loop().time()
                        
                        # Reset per-minute counter if needed
                        if current_event_time - last_minute_start > 60:
                            event_notifications_per_minute = 0
                            last_minute_start = current_event_time
                        
                        # Check rate limits
                        time_since_last_event = current_event_time - last_event_time
                        event_notifications_per_minute += 1
                        
                        if time_since_last_event < event_rate_limit:
                            logger.warning(f"⚠️  Worker {self.worker_id} rate limiting event notification (too fast: {time_since_last_event:.3f}s < {event_rate_limit}s)")
                            await asyncio.sleep(event_rate_limit - time_since_last_event)
                            
                        if event_notifications_per_minute > 30:  # Max 30 events per minute
                            logger.error(f"🚨 Worker {self.worker_id} EXCESSIVE event notifications ({event_notifications_per_minute}/min) - enforcing cooldown")
                            await asyncio.sleep(5)  # 5-second cooldown
                        
                        last_event_time = current_event_time
                        
                        # CRITICAL FIX: Clear the event IMMEDIATELY to prevent infinite loops
                        logger.info(f"⚡ Worker {self.worker_id} woken by EVENT NOTIFICATION - processing immediately")
                        
                        # CRITICAL FIX: Clear event BEFORE job processing to prevent infinite loop
                        if self._job_available_event.is_set():
                            self._job_available_event.clear()
                            logger.debug(f"Worker {self.worker_id} cleared job event after notification")
                        
                        # Reset adaptive polling on event-driven job
                        consecutive_empty_polls = 0
                        current_poll_interval = self.fallback_poll_interval
                        
                    except asyncio.TimeoutError:
                        # Timeout reached, will fallback poll below
                        should_fallback_poll = True
                        logger.debug(f"Worker {self.worker_id} event timeout after {current_poll_interval:.0f}s, performing adaptive fallback poll")
                        
                if should_fallback_poll:
                    # CRITICAL FIX: ADAPTIVE FALLBACK POLLING to minimize Redis operations
                    logger.debug(f"Worker {self.worker_id} performing adaptive fallback poll (interval: {current_poll_interval:.0f}s)")
                    last_fallback_poll = current_time
                    
                    # CRITICAL FIX: Only cleanup stale jobs occasionally to reduce Redis load
                    time_since_last_job = current_time - last_job_processed
                    should_cleanup = time_since_last_job > 600  # Only cleanup if no jobs for 10+ minutes
                    
                    if should_cleanup:
                        try:
                            # Use fortress queue manager for cleanup (fortress queue has its own cleanup)
                            if hasattr(self.queue_manager, 'cleanup_stale_jobs'):
                                await self.queue_manager.cleanup_stale_jobs()
                                logger.debug(f"Worker {self.worker_id} performed fortress queue stale job cleanup")
                        except Exception as cleanup_error:
                            logger.warning(f"Fortress queue stale job cleanup failed: {cleanup_error}")
                    else:
                        logger.debug(f"Worker {self.worker_id} skipped stale job cleanup (last job {time_since_last_job:.0f}s ago)")
                
                # Check for available jobs (triggered by event OR fallback poll)
                try:
                    # CRITICAL FIX: Use unified job dequeue method that works with both queue systems
                    job = await self._dequeue_job_unified()
                    consecutive_failures = 0  # Reset failure count on success
                    
                    if job:
                        job_id = job.get('id')
                        logger.info(f"🎯 Worker {self.worker_id} processing job: {job_id} (event-driven: {not should_fallback_poll})")
                        
                        # CRITICAL FIX: Reset adaptive polling on successful job
                        consecutive_empty_polls = 0
                        current_poll_interval = self.fallback_poll_interval
                        last_job_processed = current_time
                        
                        # CRITICAL FIX: Process job in its own session to prevent connection leaks
                        try:
                            await self._process_job_with_session(job)
                        except Exception as job_error:
                            logger.error(f"Failed to process job {job_id}: {job_error}", exc_info=True)
                            # Mark job as failed
                            try:
                                await self._mark_job_failed_unified(job_id, str(job_error), retry=True)
                            except Exception as mark_failed_error:
                                logger.error(f"Failed to mark job {job_id} as failed: {mark_failed_error}")
                        
                    elif should_fallback_poll:
                        # CRITICAL FIX: Implement adaptive polling - increase interval when no jobs found
                        consecutive_empty_polls += 1
                        
                        if self.adaptive_polling and consecutive_empty_polls > 2:  # After 2 empty polls, start backing off
                            # Gradually increase poll interval up to maximum
                            current_poll_interval = min(
                                current_poll_interval * self.poll_backoff_multiplier,
                                self.max_poll_interval
                            )
                            logger.debug(f"Worker {self.worker_id} adaptive polling: increased interval to {current_poll_interval:.0f}s after {consecutive_empty_polls} empty polls")
                        
                        # Only log occasionally to reduce noise
                        if consecutive_empty_polls <= 3 or consecutive_empty_polls % 10 == 0:
                            logger.debug(f"Worker {self.worker_id} no jobs available on fallback poll (empty polls: {consecutive_empty_polls}, next poll in {current_poll_interval:.0f}s)")
                        
                except Exception as dequeue_error:
                    consecutive_failures += 1
                    logger.error(f"Worker {self.worker_id} dequeue failed (attempt {consecutive_failures}): {dequeue_error}")
                    
                    if consecutive_failures >= max_consecutive_failures:
                        logger.error(f"Worker {self.worker_id} hit circuit breaker after {consecutive_failures} failures")
                        await asyncio.sleep(60)  # 1 minute backoff
                    else:
                        await asyncio.sleep(10)  # Short backoff
                    continue
                
                # Check for stop signal
                if self._stop_event.is_set():
                    break
                
                # CRITICAL FIX: Dynamic pause based on adaptive polling to prevent tight loops
                if not self.enable_event_driven:
                    # Polling-only mode: use adaptive delay
                    delay = min(5, max(1, current_poll_interval / 120))  # 1-5 second delay based on poll interval
                    await asyncio.sleep(delay)
                elif should_fallback_poll and consecutive_empty_polls > 5:
                    # Long delay after many empty polls to reduce CPU usage
                    await asyncio.sleep(2)
                elif should_fallback_poll:
                    # Standard brief delay for fallback polls
                    await asyncio.sleep(1)
                    
            except Exception as e:
                logger.error(f"Worker {self.worker_id} job processing error: {e}", exc_info=True)
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _process_job_with_session(self, job: dict):
        """CRITICAL FIX: Process job with its own database session to prevent pool exhaustion"""
        job_id = job["id"]
        
        # CRITICAL FIX: Each job gets its own database session that's properly closed
        async with get_db_session(DatabaseOperation.WRITE) as db:
            try:
                await self._process_job(job, db)
                # CRITICAL FIX: Explicit commit to ensure scan data is persisted
                await db.commit()
                logger.info(f"✅ CRITICAL FIX: Job {job_id} session committed successfully")
            except Exception as e:
                # Session auto-rollbacks on exception
                logger.error(f"Job {job_id} failed in session: {e}", exc_info=True)
                raise
    
    async def _process_job(self, job: dict, db: AsyncSession):
        """Process a single scan job with enhanced error handling and monitoring"""
        job_id = job["id"]
        scan_type = job["scan_type"]
        
        # CRITICAL FIX: Memory leak prevention for job processing
        self._memory_tracking["jobs_processed"] += 1
        self._active_scans[job_id] = {
            "start_time": time.time(),
            "scan_type": scan_type,
            "resources": set()
        }
        
        try:
            logger.info(f"Processing job {job_id} of type {scan_type}")
            
            # CRITICAL FIX: Periodic cleanup check
            await self._check_memory_cleanup()
            
            # Update job status in database
            await self.queue_manager._update_job_status(job_id, "processing", db)
            
            # CRITICAL FIX: Double-ensure job status is updated in database with retry
            max_status_retries = 3
            for attempt in range(max_status_retries):
                try:
                    await self._update_job_status_unified(job_id, "processing", db)
                    break
                except Exception as status_error:
                    if attempt == max_status_retries - 1:
                        logger.error(f"CRITICAL: Failed to update job {job_id} status after {max_status_retries} attempts: {status_error}")
                        # Don't fail the job, but log the issue
                    else:
                        logger.warning(f"Retry {attempt + 1}/{max_status_retries}: Failed to update job status: {status_error}")
                        await asyncio.sleep(1)  # Brief wait before retry
            
            # Process based on scan type (using fortress queue unified types)
            if scan_type == "pr_scan":
                await self._process_pr_scan(job, db)
            elif scan_type == "push_scan":
                await self._process_push_scan(job, db)
            elif scan_type in ["manual", "on_demand", "scheduled"]:
                await self._process_manual_scan(job, db)
            else:
                logger.warning(f"Unknown scan type '{scan_type}', defaulting to manual scan")
                await self._process_manual_scan(job, db)
            
            # CRITICAL FIX: Get scan_id from active scans tracking
            scan_id = self._active_scans.get(job_id, {}).get("scan_id")
            logger.info(f"CRITICAL DEBUG: Job {job_id} completion - scan_id: {scan_id}")
            
            # CRITICAL FIX: Ensure we have a valid scan_id before marking job complete
            if not scan_id:
                logger.error(f"❌ CRITICAL ERROR: Job {job_id} has no scan_id - scan creation likely failed!")
                # Don't fail the job - just mark it completed without scan_id
                logger.warning(f"⚠️ Job {job_id} will be marked completed without scan_id")
            else:
                logger.info(f"✅ Job {job_id} has valid scan_id: {scan_id}")
            
            # CRITICAL FIX: Flush database changes before marking job complete
            await db.flush()
            logger.info(f"✅ CRITICAL FIX: Database flushed for job {job_id}")
            
            # CRITICAL FIX: Mark job completed in the appropriate queue system with scan_id
            await self._mark_job_completed_unified(job_id, db)
            
            # Mark job as completed with scan_id link - session will be committed by context manager
            await self.queue_manager.mark_job_completed(job_id=job_id, scan_id=scan_id, db_session=db)
            logger.info(f"CRITICAL DEBUG: Job {job_id} mark_job_completed called with scan_id: {scan_id}")
            logger.info(f"✅ Job {job_id} completed successfully with scan_id: {scan_id}")
            
        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}", exc_info=True)
            try:
                # CRITICAL FIX: Report error to health monitor
                await self.report_error_to_health_monitor(f"Job {job_id} failed: {str(e)[:200]}")
                
                # CRITICAL FIX: Mark job failed in the appropriate queue system
                await self._mark_job_failed_unified(job_id, str(e), retry=True, db=db)
                
                await self.queue_manager.mark_job_failed(job_id, str(e), retry=True)
                # Note: Session rollback will be handled by context manager
                
            except Exception as rollback_error:
                logger.error(f"Failed to handle job failure for {job_id}: {rollback_error}", exc_info=True)
            
            # Re-raise the original exception to trigger session rollback
            raise
        finally:
            # CRITICAL FIX: Always cleanup job resources
            await self._cleanup_job_resources(job_id)
    
    async def _process_pr_scan(self, job: dict, db: AsyncSession):
        """Process PR scan job"""
        scan_data = job["scan_data"]
        repo_full_name = job["repo_full_name"]
        job_id = job["id"]
        
        # Extract PR scan parameters
        pr_number = scan_data["pr_number"]
        commit_sha = scan_data["commit_sha"]
        branch = scan_data["branch"]
        gh_token = scan_data["gh_token"]
        user_id = scan_data["user_id"]
        
        # Update progress: Starting
        await self._update_progress(job_id, 10, "Starting PR scan", "initializing")
        
        # Update GitHub status to pending
        await self.github_integration.update_check_run(
            repo_full_name, commit_sha, "pending", gh_token
        )
        
        # Update progress: Running scan
        await self._update_progress(job_id, 30, "Running security scan", "scanning")
        
        # Run focused scan (faster scope for PRs)
        scan_result = await self.scanner_engine.run_comprehensive_scan(
            repo_full_name=repo_full_name,
            branch=branch,
            scope=scan_data.get("scope", "code+deps"),  # User can specify scope for PRs too
            mode=scan_data.get("mode", "fast"),
            niche=scan_data.get("niche"),
            gh_token=gh_token,
            scan_type="pr",
            pr_number=pr_number,
            commit_sha=commit_sha,
            file_list=scan_data.get("file_list"),  # Pass changed files for focused scanning
            user_id=int(scan_data.get("user_id", 0)) if scan_data.get("user_id") else None,
            db_session=db,
            include_custom_rules=scan_data.get("include_custom_rules", False),
            include_community_rules=scan_data.get("include_community_rules", False),
            selected_custom_rule_ids=scan_data.get("selected_custom_rule_ids", []),
            selected_community_rule_ids=scan_data.get("selected_community_rule_ids", []),
            progress_callback=lambda p, s, t, *args: asyncio.create_task(
                self._update_progress(job_id, 30 + int(p * 0.4), s, t)  # 30-70% for scanning
            )
        )
        
        # Update progress: Processing results
        await self._update_progress(job_id, 70, "Processing scan results", "processing")
        
        # Store scan results
        try:
            # Ensure repository exists in database before storing scan
            await self._ensure_repository_exists(repo_full_name, user_id, db)
            
            logger.info(f"📀 CRITICAL DEBUG: About to store scan results for PR job {job_id}")
            scan_id = await self._store_scan_results(scan_result, user_id, repo_full_name, db, scan_data.get("niche"))
            logger.info(f"📀 CRITICAL DEBUG: Scan results stored successfully for PR job {job_id}, scan_id: {scan_id}")
            
            # CRITICAL FIX: Verify scan_id is valid
            if not scan_id:
                logger.error(f"❌ CRITICAL ERROR: _store_scan_results returned None/empty scan_id for PR job {job_id}")
                raise RuntimeError(f"Scan storage failed - no scan_id returned for job {job_id}")
            
            # CRITICAL FIX: Store scan_id for later use
            self._active_scans[job_id]["scan_id"] = scan_id
            logger.info(f"✅ Job {job_id} PR scan SUCCESSFULLY STORED and linked to scan_id {scan_id}")
        except Exception as e:
            logger.error(f"❌ Failed to store scan results for PR scan job {job_id}: {e}", exc_info=True)
            raise  # Re-raise to trigger job failure handling - rollback handled by context manager
        
        # AI analysis - controlled by environment variable
        if self.enable_ai_during_scan:
            # Update progress: AI analysis
            await self._update_progress(job_id, 80, "Generating AI explanations", "ai_analysis")
            
            # Generate AI explanations for critical/high issues
            critical_high_issues = [
                issue for issue in scan_result.get("issues", [])
                if issue.get("severity") in ["critical", "high"]
            ]
            
            if critical_high_issues:
                explanations = await self.ai_explainer.explain_issues_batch(
                    critical_high_issues, db, include_code_context=True
                )
            else:
                explanations = {}
        else:
            # Skip AI analysis - users can request explanations on-demand via API
            # This saves 60-90 seconds of processing time per scan
            # AI explanations are available at /scans/issues/explain endpoint
            explanations = {}
        
        # Update progress: GitHub integration (skipped AI, so jump from 70% to 90%)
        await self._update_progress(job_id, 90, "Updating GitHub status", "github_integration")
        
        # Update GitHub with results
        conclusion = self._determine_pr_conclusion(scan_result)
        await self.github_integration.update_check_run(
            repo_full_name, commit_sha, "completed", gh_token,
            conclusion=conclusion, scan_result=scan_result, scan_id=scan_id
        )
        
        # Update progress: Creating PR review
        await self._update_progress(job_id, 95, "Creating PR review", "pr_review")
        
        # Always create a PR review with our beautiful comments
        try:
            # Create comprehensive PR review with inline comments
            review_result = await self.github_integration.create_pr_review(
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                scan_result=scan_result,
                gh_token=gh_token,
                scan_id=scan_id
            )
            
            logger.info(f"Created PR review {review_result['review_id']} with {review_result['inline_comments_count']} inline comments")
            
            # Store review info in database for tracking
            # This will be implemented when we add the database models
            
        except Exception as e:
            logger.error(f"Failed to create PR review, falling back to comment: {e}")
            # Fallback to simple comment if review fails
            await self.github_integration.post_pr_comment_async(
                repo_full_name, pr_number, scan_result, gh_token, scan_id
            )
        
        # Update progress: Complete
        await self._update_progress(job_id, 100, "PR scan completed", "completed")
    
    async def _process_push_scan(self, job: dict, db: AsyncSession):
        """Process push scan job (full scan for main branches)"""
        scan_data = job["scan_data"]
        repo_full_name = job["repo_full_name"]
        
        # Run comprehensive scan for pushes to main branches
        scan_result = await self.scanner_engine.run_comprehensive_scan(
            repo_full_name=repo_full_name,
            branch=scan_data["branch"],
            scope="full",  # Full scope for main branch pushes
            mode="fast",
            niche=scan_data.get("niche"),
            gh_token=scan_data["gh_token"],
            scan_type="push",
            commit_sha=scan_data.get("commit_sha"),
            user_id=scan_data.get("user_id"),
            db_session=db,
            include_custom_rules=scan_data.get("include_custom_rules", False),
            include_community_rules=scan_data.get("include_community_rules", False),
            selected_custom_rule_ids=scan_data.get("selected_custom_rule_ids", []),
            selected_community_rule_ids=scan_data.get("selected_community_rule_ids", [])
        )
        
        # Store scan results
        try:
            # Ensure repository exists in database before storing scan
            await self._ensure_repository_exists(repo_full_name, scan_data["user_id"], db)
            
            logger.info(f"📀 CRITICAL DEBUG: About to store scan results for push job {job_id}")
            scan_id = await self._store_scan_results(scan_result, scan_data["user_id"], repo_full_name, db, scan_data.get("niche"))
            logger.info(f"📀 CRITICAL DEBUG: Scan results stored successfully for push job {job_id}, scan_id: {scan_id}")
            
            # CRITICAL FIX: Verify scan_id is valid
            if not scan_id:
                logger.error(f"❌ CRITICAL ERROR: _store_scan_results returned None/empty scan_id for push job {job_id}")
                raise RuntimeError(f"Scan storage failed - no scan_id returned for job {job_id}")
            
            # CRITICAL FIX: Store scan_id for later use
            self._active_scans[job_id]["scan_id"] = scan_id
            logger.info(f"✅ Job {job_id} push scan SUCCESSFULLY STORED and linked to scan_id {scan_id}")
        except Exception as e:
            logger.error(f"❌ Failed to store scan results for push scan job {job_id}: {e}", exc_info=True)
            raise  # Re-raise to trigger job failure handling - rollback handled by context manager
        
        # AI analysis for push scans - controlled by environment variable
        if self.enable_ai_during_scan:
            # Generate AI explanations for all issues above medium severity
            important_issues = [
                issue for issue in scan_result.get("issues", [])
                if issue.get("severity") in ["critical", "high", "medium"]
            ]
            
            if important_issues:
                await self.ai_explainer.explain_issues_batch(
                    important_issues, db, include_code_context=True
                )
        else:
            # Skip AI analysis for push scans - available on-demand via API
            # This significantly improves scan performance
            pass
    
    async def _process_manual_scan(self, job: dict, db: AsyncSession):
        """Process manual scan job with real-time progress tracking"""
        scan_data = job["scan_data"]
        job_id = job["id"]
        repo_full_name = job["repo_full_name"]
        
        logger.info(f"Starting manual scan for {repo_full_name} with data: {scan_data}")
        
        # Update progress: Starting scan
        await self._update_progress(job_id, 5, "Initializing security scan", "initializing")
        
        try:
            # Update progress: Beginning scan
            await self._update_progress(job_id, 10, "Starting comprehensive scan", "starting")
            
            # Run scan with user-specified parameters and progress tracking
            scan_result = await self.scanner_engine.run_comprehensive_scan(
                repo_full_name=repo_full_name,
                branch=scan_data["branch"],
                scope=scan_data.get("scope", "code+deps"),
                mode=scan_data.get("mode", "fast"),
                niche=scan_data.get("niche"),
                gh_token=scan_data["gh_token"],
                scan_type="manual",
                user_id=scan_data.get("user_id"),
                db_session=db,
                include_custom_rules=scan_data.get("include_custom_rules", False),
                include_community_rules=scan_data.get("include_community_rules", False),
                selected_custom_rule_ids=scan_data.get("selected_custom_rule_ids", []),
                selected_community_rule_ids=scan_data.get("selected_community_rule_ids", []),
                progress_callback=lambda p, s, t, *args: asyncio.create_task(
                    self._update_progress(job_id, 10 + int(p * 70), s, t)  # 10-80% for scanning
                )
            )
            logger.info(f"Scan completed with {len(scan_result.get('issues', []))} issues")
            logger.info(f"Scan scores: {scan_result.get('scores', {})}")
            
            # Update progress: Processing results
            await self._update_progress(job_id, 80, "Processing scan results", "processing")
            
        except Exception as e:
            logger.error(f"Scanner engine failed: {e}", exc_info=True)
            # Update progress: Scan failed
            await self._update_progress(job_id, 0, f"Scan failed: {str(e)}", "failed")
            # Create empty result to continue processing
            scan_result = {
                "issues": [],
                "total_score": 0,
                "duration": 0,
                "tools_used": [],
                "error": str(e)
            }
        
        # Store scan results
        logger.info(f"Storing scan results for repo: {repo_full_name}")
        
        # Update progress: Storing results
        await self._update_progress(job_id, 85, "Storing scan results", "storing")
        
        # Use performance-optimized database storage
        try:
            # Ensure repository exists in database before storing scan
            await self._ensure_repository_exists(repo_full_name, scan_data["user_id"], db)
            
            logger.info(f"📀 CRITICAL DEBUG: About to store scan results for manual job {job_id}")
            try:
                from ..performance_database_optimizer import store_scan_results_fast
                scan_id = await store_scan_results_fast(
                    scan_result, scan_data["user_id"], repo_full_name, db, scan_data.get("niche")
                )
                logger.info(f"📀 CRITICAL DEBUG: Scan record {scan_id} created (fast storage) for manual job {job_id}")
            except ImportError:
                logger.warning("Performance database optimizer not available, using standard storage")
                scan_id = await self._store_scan_results(scan_result, scan_data["user_id"], repo_full_name, db, scan_data.get("niche"))
                logger.info(f"📀 CRITICAL DEBUG: Scan record {scan_id} created (standard storage) for manual job {job_id}")
            
            # CRITICAL FIX: Verify scan_id is valid
            if not scan_id:
                logger.error(f"❌ CRITICAL ERROR: Scan storage returned None/empty scan_id for manual job {job_id}")
                raise RuntimeError(f"Scan storage failed - no scan_id returned for job {job_id}")
            
            # CRITICAL FIX: Store scan_id for later use
            self._active_scans[job_id]["scan_id"] = scan_id
            logger.info(f"✅ Job {job_id} manual scan SUCCESSFULLY STORED and linked to scan_id {scan_id}")
            
        except Exception as e:
            logger.error(f"❌ Failed to store scan results for manual scan job {job_id}: {e}", exc_info=True)
            raise  # Re-raise to trigger job failure handling - rollback handled by context manager
        
        # AI analysis for manual scans - controlled by environment variable
        if self.enable_ai_during_scan:
            # Update progress: AI analysis
            await self._update_progress(job_id, 90, "Generating AI explanations", "ai_analysis")
            
            # Generate AI explanations for all issues
            if scan_result.get("issues"):
                await self.ai_explainer.explain_issues_batch(
                    scan_result["issues"], db, include_code_context=True
                )
        else:
            # Skip AI analysis for manual scans - available on-demand via API
            # Users can request AI explanations for specific issues when needed
            # This reduces scan time from 90+ seconds to 15-20 seconds
            pass
        
        # Update progress: Complete
        await self._update_progress(job_id, 100, "Scan completed successfully", "completed")
    
    async def _store_scan_results(self, scan_result: dict, user_id: str, repo_full_name: str, db: AsyncSession, niche: str = "general") -> str:
        """Store scan results in database"""
        logger.info(f"_store_scan_results called with repo_full_name: {repo_full_name}")
        metadata = scan_result.get("metadata", {})
        scores = scan_result.get("scores", {})
        logger.info(f"Storing scores: {scores}")
        
        try:
            # Convert user_id to int safely
            user_id_int = int(user_id) if isinstance(user_id, str) and user_id.isdigit() else user_id
            
            # Create main scan record WITH user_id for composite foreign key
            scan_data = {
                "repo_full_name": repo_full_name,
                "user_id": user_id_int,  # Add user_id for composite FK
                "branch": metadata.get("branch") or "main",
                "mode": metadata.get("mode", "fast"),
                "scope": metadata.get("scope", "code+deps"),
                "scan_type": metadata.get("scan_type", "manual"),
                "niche": niche,
                "total_score": scores.get("total_score", 0),
                "code_score": scores.get("code_score"),
                "deps_score": scores.get("deps_score"),
                "secrets_score": scores.get("secrets_score"),
                "configs_score": scores.get("configs_score"),
                "commit_sha": metadata.get("commit_sha"),
                "pr_number": metadata.get("pr_number"),
                "scan_duration": int(metadata.get("scan_duration", 0)),
                "tools_used": metadata.get("tools_used", []),
                "status": "completed",
                "started_at": datetime.utcnow(),
                "completed_at": datetime.utcnow()
            }
            
            # Execute database operations without nested transaction management
            # The calling context manages transactions
            stmt = insert(Scan).values(**scan_data).returning(Scan.id)
            result = await db.execute(stmt)
            scan_id = result.scalar_one()
            
            # CRITICAL FIX: Flush immediately after scan creation to ensure it's persisted
            await db.flush()
            logger.info(f"✅ CRITICAL FIX: Scan {scan_id} inserted and flushed to database")
            
            # Create scan summaries by category and tool
            summaries = self._create_scan_summaries(scan_result.get("issues", []), scan_id)
            
            if summaries:
                stmt = insert(ScanSummary).values(summaries)
                await db.execute(stmt)
                # CRITICAL FIX: Flush summaries as well
                await db.flush()
                logger.info(f"✅ CRITICAL FIX: {len(summaries)} scan summaries inserted and flushed")
            
            # CRITICAL FIX: Track issues for resolution monitoring with proper session isolation
            try:
                # Use separate session for issue tracking to prevent connection pool exhaustion
                import asyncio
                asyncio.create_task(self._track_issues_async(scan_id, scan_result.get("issues", []), repo_full_name))
                logger.info(f"Issue tracking queued for scan {scan_id}")
            except Exception as e:
                logger.warning(f"Failed to queue issue tracking for scan {scan_id}: {e}")
                # Don't fail the entire scan storage if issue tracking fails
                
            logger.info(f"✅ CRITICAL FIX: Scan results stored with ID {scan_id} - ALL DATA FLUSHED")
            return scan_id
            
        except SQLAlchemyError as e:
            logger.error(f"Database error storing scan results: {e}")
            # Don't rollback here - let the calling context handle transaction management
            raise
        except Exception as e:
            logger.error(f"Error storing scan results: {e}")
            # Don't rollback here - let the calling context handle transaction management
            raise
    
    def _create_scan_summaries(self, issues: list, scan_id: str) -> list:
        """Create scan summaries grouped by category and tool"""
        logger.info(f"Creating scan summaries for {len(issues)} issues in scan {scan_id}")
        
        # ENHANCED: Debug log tool breakdown for diagnostic purposes
        tool_counts = {}
        for issue in issues:
            tool = issue.get("tool", "unknown")
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        logger.info(f"Issue breakdown by tool: {tool_counts}")
        
        summaries = {}
        
        for issue in issues:
            category = issue.get("category", "unknown")
            tool = issue.get("tool", "unknown")
            severity = issue.get("severity", "medium")
            
            key = f"{category}_{tool}"
            
            if key not in summaries:
                summaries[key] = {
                    "scan_id": scan_id,
                    "category": category,
                    "tool_name": tool,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "total_issues": 0,
                    "sample_issues": []
                }
            
            # Count by severity with enhanced Gosec tracking
            if severity == "critical":
                summaries[key]["critical_count"] += 1
                if tool == "gosec":
                    logger.info(f"🔍 CRITICAL GOSEC ISSUE: {issue.get('rule_id', 'unknown')} in {issue.get('file_path', 'unknown')}")
                else:
                    logger.info(f"CRITICAL ISSUE FOUND: {tool} - {issue.get('rule_id', 'unknown')} in {issue.get('file_path', 'unknown')}")
            elif severity == "high":
                summaries[key]["high_count"] += 1
                if tool == "gosec":
                    logger.info(f"🔍 HIGH GOSEC ISSUE: {issue.get('rule_id', 'unknown')} in {issue.get('file_path', 'unknown')}")
            elif severity == "medium":
                summaries[key]["medium_count"] += 1
                if tool == "gosec":
                    logger.debug(f"🔍 MEDIUM GOSEC ISSUE: {issue.get('rule_id', 'unknown')} in {issue.get('file_path', 'unknown')}")
            else:
                summaries[key]["low_count"] += 1
                if tool == "gosec":
                    logger.debug(f"🔍 LOW GOSEC ISSUE: {issue.get('rule_id', 'unknown')} in {issue.get('file_path', 'unknown')}")
            
            summaries[key]["total_issues"] += 1
            
            # Store ALL issues (no limit)
            sample_issue = {
                "message": issue.get("message"),
                "file_path": issue.get("file_path"),
                "line_start": issue.get("line_start"),
                "line_end": issue.get("line_end"),
                "severity": severity,
                "rule_id": issue.get("rule_id"),
                "confidence": issue.get("confidence"),
                "owasp_category": issue.get("owasp_category"),
                "cwe_id": issue.get("cwe_id"),
                "code_context": issue.get("code_context")  # Include code context!
            }
            summaries[key]["sample_issues"].append(sample_issue)
        
        # Log final issue summary for debugging
        total_critical = sum(s["critical_count"] for s in summaries.values())
        total_high = sum(s["high_count"] for s in summaries.values())
        total_medium = sum(s["medium_count"] for s in summaries.values())
        total_low = sum(s["low_count"] for s in summaries.values())
        total_all_issues = total_critical + total_high + total_medium + total_low
        
        logger.info(f"SCAN SUMMARY - Critical: {total_critical}, High: {total_high}, Medium: {total_medium}, Low: {total_low}")
        logger.info(f"TOTAL ISSUES IN SUMMARIES: {total_all_issues} (from {len(summaries)} tool/category combinations)")
        
        # ENHANCED: Log each summary for debugging
        for key, summary in summaries.items():
            logger.info(f"  Summary {key}: {summary['total_issues']} issues ({summary['critical_count']}C/{summary['high_count']}H/{summary['medium_count']}M/{summary['low_count']}L)")
        
        if total_critical == 0:
            logger.warning("NO CRITICAL ISSUES FOUND - Check if secret detection tools ran and found secrets")
        
        if len(issues) > 0 and total_all_issues == 0:
            logger.error(f"❌ CRITICAL: {len(issues)} issues provided but 0 issues in summaries - possible summary creation bug")
        elif len(issues) != total_all_issues:
            logger.warning(f"⚠️  Issue count mismatch: {len(issues)} input issues vs {total_all_issues} in summaries")
        
        summary_list = list(summaries.values())
        logger.info(f"Returning {len(summary_list)} scan summaries to be stored in database")
        return summary_list
    
    def _determine_pr_conclusion(self, scan_result: dict) -> str:
        """Determine GitHub check run conclusion based on scan results"""
        issues = scan_result.get("issues", [])
        scores = scan_result.get("scores", {})
        total_score = scores.get("total_score", 100)
        
        # Count critical and high severity issues
        critical_count = len([i for i in issues if i.get("severity") == "critical"])
        high_count = len([i for i in issues if i.get("severity") == "high"])
        
        if critical_count > 0:
            return "failure"
        elif high_count > 3:
            return "failure"
        elif total_score < 70:
            return "action_required"
        else:
            return "success"
    
    async def _update_progress(
        self, 
        job_id: str, 
        progress_percent: int, 
        stage: str, 
        current_tool: str = "",
        tools_completed: int = 0,
        total_tools: int = 0
    ):
        """Update scan progress in Redis for real-time tracking"""
        try:
            from core.redis import get_redis_client
            
            progress_data = {
                "progress": f"{progress_percent}%",
                "stage": stage,
                "current_tool": current_tool,
                "tools_completed": tools_completed,
                "total_tools": total_tools,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            redis_client = await get_redis_client()
            if redis_client:
                try:
                    # Store progress with 1 hour TTL
                    await redis_client.setex(
                        f"scan_progress:{job_id}",
                        3600,  # 1 hour TTL
                        json.dumps(progress_data)
                    )
                    logger.info(f"Progress update for job {job_id}: {progress_percent}% - {stage}")
                except Exception as redis_error:
                    logger.warning(f"Redis operation failed for job {job_id}: {redis_error}")
                    # Don't close connection on error - let health check handle it
            else:
                logger.debug(f"Redis not available, skipping progress update for job {job_id}")
            
        except Exception as e:
            logger.warning(f"Failed to update progress for job {job_id}: {e}")
            # Don't fail the scan if progress update fails
    
    async def _check_memory_cleanup(self):
        """CRITICAL FIX: Check if memory cleanup is needed"""
        current_time = time.time()
        
        # Check if cleanup is needed based on time or job count
        time_based_cleanup = (current_time - self._memory_tracking["last_cleanup"]) > self._memory_tracking["cleanup_interval"]
        job_based_cleanup = self._memory_tracking["jobs_processed"] % self._memory_tracking["max_jobs_before_cleanup"] == 0
        
        if time_based_cleanup or job_based_cleanup:
            await self._perform_memory_cleanup()
            self._memory_tracking["last_cleanup"] = current_time
    
    async def _perform_memory_cleanup(self):
        """CRITICAL FIX: Perform comprehensive memory cleanup"""
        logger.debug(f"Worker {self.worker_id} performing memory cleanup")
        
        try:
            # Clean up cached objects
            self._memory_tracking["cached_objects"].clear()
            
            # Clean up temporary files
            await self._cleanup_temp_files()
            
            # Clean up stale scan entries
            await self._cleanup_stale_scans()
            
            # Force garbage collection
            import gc
            collected = gc.collect()
            logger.debug(f"Worker {self.worker_id} garbage collection freed {collected} objects")
            
            # Clean up Redis connections if manager available
            try:
                from core.redis_pool_manager import get_worker_redis_manager
                worker_manager = await get_worker_redis_manager()
                metrics = worker_manager.get_connection_metrics()
                
                if metrics.get("leaked_connections", 0) > 0:
                    logger.warning(f"Worker {self.worker_id} detected {metrics['leaked_connections']} leaked Redis connections")
                    # The manager will handle cleanup automatically
                    
            except ImportError:
                logger.debug(f"Worker Redis manager not available for cleanup")
            
        except Exception as e:
            logger.warning(f"Error during memory cleanup for worker {self.worker_id}: {e}")
    
    async def _cleanup_temp_files(self):
        """CRITICAL FIX: Clean up temporary files created during scanning"""
        import os
        import tempfile
        
        temp_files_to_remove = list(self._memory_tracking["temp_files"])
        for temp_file in temp_files_to_remove:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    logger.debug(f"Removed temp file: {temp_file}")
                self._memory_tracking["temp_files"].discard(temp_file)
            except Exception as e:
                logger.warning(f"Failed to remove temp file {temp_file}: {e}")
        
        # Also clean up any files in system temp directory with our pattern
        try:
            temp_dir = tempfile.gettempdir()
            for filename in os.listdir(temp_dir):
                if f"devsecurex_{self.worker_id}" in filename:
                    temp_path = os.path.join(temp_dir, filename)
                    try:
                        os.remove(temp_path)
                        logger.debug(f"Removed orphaned temp file: {temp_path}")
                    except Exception:
                        pass  # Ignore errors for orphaned files
        except Exception as e:
            logger.debug(f"Error cleaning temp directory: {e}")
    
    async def _cleanup_stale_scans(self):
        """CRITICAL FIX: Clean up stale scan entries"""
        current_time = time.time()
        stale_threshold = 3600  # 1 hour
        
        stale_scans = []
        for scan_id, scan_info in self._active_scans.items():
            if (current_time - scan_info["start_time"]) > stale_threshold:
                stale_scans.append(scan_id)
        
        for scan_id in stale_scans:
            logger.warning(f"Cleaning up stale scan: {scan_id}")
            await self._cleanup_job_resources(scan_id)
    
    async def _cleanup_job_resources(self, job_id: str):
        """CRITICAL FIX: Clean up resources for a specific job"""
        try:
            # Remove from active scans
            scan_info = self._active_scans.pop(job_id, {})
            
            # Clean up any job-specific resources
            job_resources = scan_info.get("resources", set())
            for resource in job_resources:
                try:
                    if hasattr(resource, 'close'):
                        if asyncio.iscoroutinefunction(resource.close):
                            await resource.close()
                        else:
                            resource.close()
                    elif hasattr(resource, 'aclose'):
                        await resource.aclose()
                except Exception as cleanup_error:
                    logger.warning(f"Error cleaning up resource for job {job_id}: {cleanup_error}")
            
            # Remove from cleanup registry
            self._scan_cleanup_registry.pop(job_id, None)
            
            logger.debug(f"Cleaned up resources for job {job_id}")
            
        except Exception as e:
            logger.warning(f"Error during resource cleanup for job {job_id}: {e}")
    
    async def _perform_final_cleanup(self):
        """CRITICAL FIX: Perform final cleanup when worker stops"""
        logger.info(f"Worker {self.worker_id} performing final cleanup")
        
        try:
            # Clean up all active scans
            active_scan_ids = list(self._active_scans.keys())
            for scan_id in active_scan_ids:
                await self._cleanup_job_resources(scan_id)
            
            # Perform final memory cleanup
            await self._perform_memory_cleanup()
            
            # Cancel any remaining cleanup tasks
            if self._resource_cleanup_tasks:
                for task in list(self._resource_cleanup_tasks):
                    if not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                self._resource_cleanup_tasks.clear()
            
            logger.info(f"Worker {self.worker_id} final cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during final cleanup for worker {self.worker_id}: {e}")
    
    def get_memory_stats(self):
        """CRITICAL FIX: Get memory usage statistics for monitoring"""
        import psutil
        import os
        
        try:
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            
            return {
                "worker_id": self.worker_id,
                "jobs_processed": self._memory_tracking["jobs_processed"],
                "active_scans": len(self._active_scans),
                "cached_objects": len(self._memory_tracking["cached_objects"]),
                "temp_files": len(self._memory_tracking["temp_files"]),
                "memory_rss_mb": round(memory_info.rss / 1024 / 1024, 2),
                "memory_vms_mb": round(memory_info.vms / 1024 / 1024, 2),
                "cleanup_tasks": len(self._resource_cleanup_tasks),
                "last_cleanup": self._memory_tracking["last_cleanup"]
            }
        except ImportError:
            return {
                "worker_id": self.worker_id,
                "jobs_processed": self._memory_tracking["jobs_processed"],
                "active_scans": len(self._active_scans),
                "cached_objects": len(self._memory_tracking["cached_objects"]),
                "temp_files": len(self._memory_tracking["temp_files"]),
                "cleanup_tasks": len(self._resource_cleanup_tasks),
                "last_cleanup": self._memory_tracking["last_cleanup"],
                "note": "psutil not available for detailed memory stats"
            }
        except Exception as e:
            return {
                "worker_id": self.worker_id,
                "error": f"Failed to get memory stats: {e}"
            }
    
    async def _register_with_health_monitor(self):
        """Register worker with health monitoring system"""
        try:
            from core.worker_health_monitor import get_worker_health_monitor, WorkerState
            self._health_monitor = await get_worker_health_monitor()
            await self._health_monitor.register_worker(
                self.worker_id, 
                "scan_worker", 
                WorkerState.READY
            )
            logger.info(f"Worker {self.worker_id} registered with health monitor")
        except Exception as e:
            logger.warning(f"Failed to register with health monitor: {e}")
            self._health_monitor = None
    
    async def _unregister_from_health_monitor(self):
        """Unregister worker from health monitoring system"""
        if self._health_monitor:
            try:
                await self._health_monitor.unregister_worker(self.worker_id)
                logger.info(f"Worker {self.worker_id} unregistered from health monitor")
            except Exception as e:
                logger.warning(f"Failed to unregister from health monitor: {e}")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to health monitor"""
        while self.running:
            try:
                if self._health_monitor:
                    # Get current worker state
                    current_state = await self.get_worker_state()
                    
                    # Get job metrics
                    job_metrics = {
                        "jobs_processed": self._memory_tracking["jobs_processed"],
                        "jobs_failed": 0,  # Would need to track this separately
                        "last_job_timestamp": time.time() if self._active_scans else None
                    }
                    
                    # Get resource metrics
                    memory_stats = self.get_memory_stats()
                    resource_metrics = {
                        "memory_mb": memory_stats.get("memory_rss_mb", 0),
                        "cpu_percent": 0  # Would need psutil integration for CPU
                    }
                    
                    # Send heartbeat
                    from core.worker_health_monitor import WorkerState
                    state_map = {
                        "starting": WorkerState.STARTING,
                        "ready": WorkerState.READY,
                        "active": WorkerState.ACTIVE,
                        "stopping": WorkerState.STOPPING,
                        "stopped": WorkerState.STOPPED,
                        "failed": WorkerState.FAILED
                    }
                    
                    await self._health_monitor.update_worker_heartbeat(
                        self.worker_id,
                        state_map.get(current_state, WorkerState.ACTIVE),
                        job_metrics,
                        resource_metrics
                    )
                
                await asyncio.sleep(self._heartbeat_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Error in heartbeat loop for worker {self.worker_id}: {e}")
                await asyncio.sleep(self._heartbeat_interval)
    
    async def report_error_to_health_monitor(self, error_message: str):
        """Report error to health monitoring system"""
        if self._health_monitor:
            try:
                await self._health_monitor.report_worker_error(self.worker_id, error_message)
            except Exception as e:
                logger.warning(f"Failed to report error to health monitor: {e}")
        else:
            logger.debug(f"No health monitor available for worker {self.worker_id}")
    async def _track_issues_async(self, scan_id: str, issues: list, repo_full_name: str):
        """CRITICAL FIX: Track issues in separate session to prevent pool exhaustion"""
        try:
            from core.database import get_db_session, DatabaseOperation
            async with get_db_session(DatabaseOperation.WRITE) as issue_session:
                issue_service = IssueTrackingService()
                tracking_stats = await issue_service.track_scan_issues(
                    session=issue_session,
                    scan_id=scan_id,
                    issues=issues,
                    repo_full_name=repo_full_name
                )
                logger.info(f"Issue tracking completed for scan {scan_id}: {tracking_stats}")
        except Exception as e:
            logger.error(f"Async issue tracking failed for scan {scan_id}: {e}")
            # Don't raise - this is background task
    
    async def _ensure_repository_exists(self, repo_full_name: str, user_id: int, db: AsyncSession):
        """Ensure repository exists in database before storing scan results"""
        try:
            from sqlalchemy import select
            from repositories.models import Repository
            
            # Convert user_id to int safely  
            user_id_int = int(user_id) if isinstance(user_id, str) and user_id.isdigit() else user_id
            
            # Check if repository exists
            result = await db.execute(
                select(Repository).where(
                    Repository.full_name == repo_full_name,
                    Repository.user_id == user_id_int
                )
            )
            existing_repo = result.scalar_one_or_none()
            
            if existing_repo is None:
                logger.warning(f"Repository {repo_full_name} not found for user {user_id_int}, creating it")
                
                # Create repository record if it doesn't exist
                from sqlalchemy.dialects.postgresql import insert
                
                repo_data = {
                    "full_name": repo_full_name,
                    "user_id": user_id_int,
                    "name": repo_full_name.split('/')[-1] if '/' in repo_full_name else repo_full_name,
                    "private": True,  # Default to private
                    "default_branch": "main",  # Default branch
                    "description": f"Repository {repo_full_name}",
                    "language": "Unknown",
                    "is_active": True
                }
                
                stmt = insert(Repository).values(**repo_data)
                # Use on_conflict_do_nothing to handle race conditions
                stmt = stmt.on_conflict_do_nothing(index_elements=['full_name', 'user_id'])
                await db.execute(stmt)
                
                logger.info(f"Created repository record for {repo_full_name} (user {user_id_int})")
            else:
                logger.debug(f"Repository {repo_full_name} exists for user {user_id_int}")
                
        except Exception as e:
            logger.error(f"Failed to ensure repository exists: {e}", exc_info=True)
            # Don't raise here - let the scan proceed and fail on the actual FK constraint
            # This provides better error messaging
            pass
