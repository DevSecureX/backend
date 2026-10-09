"""
UNIFIED SCAN QUEUE MANAGER - THE FORTRESS

This is the ONE AND ONLY queue system that handles ALL scan operations.
No more fragmentation. No more fighting systems. Just one rock-solid solution.

Architecture:
- Single Redis-based queue with direct polling (no pub/sub complexity)
- Single job format for all scan types
- Direct job processing with immediate pickup
- No subscription failures, no channel mismatches
- Fortress-like reliability

SUCCESS CRITERIA:
- Scan creation → Processing in 1-2 seconds
- No "Waiting in queue" status ever
- No worker subscription failures
- One system handles everything
"""

import json
import uuid
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
from dataclasses import dataclass, asdict

from core.redis import get_redis_client
from core.utils import utc_now, utc_now_iso
from core.database import get_db_session, DatabaseOperation
from scans.models import ScanJob, Scan

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert

# Import all models to ensure proper SQLAlchemy relationship resolution
import auth.models  # noqa: F401
import support.models  # noqa: F401
import ai_assistant.models  # noqa: F401
import scans.models  # noqa: F401
import cli_scan.models  # noqa: F401

logger = logging.getLogger(__name__)


class UnifiedJobStatus(Enum):
    """Simple, clear job statuses"""
    QUEUED = "queued"
    PROCESSING = "processing" 
    COMPLETED = "completed"
    FAILED = "failed"


class UnifiedJobPriority(Enum):
    """Simple priority system"""
    URGENT = 0      # Critical security issues
    HIGH = 1        # PR scans
    NORMAL = 2      # Manual scans
    LOW = 3         # Background scans


@dataclass
class UnifiedScanJob:
    """Single job format for ALL scan types - no complexity"""
    id: str
    repo_full_name: str
    user_id: int
    scan_type: str  # "manual", "pr_scan", "push_scan", "scheduled"
    priority: UnifiedJobPriority
    scan_config: Dict[str, Any]
    
    # Status tracking
    status: UnifiedJobStatus = UnifiedJobStatus.QUEUED
    created_at: datetime = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    worker_id: Optional[str] = None
    
    # Error handling
    error_message: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


class UnifiedScanQueueManager:
    """
    THE FORTRESS: Single queue system that handles everything.
    
    No asyncio queues, no enterprise vs legacy separation, no pub/sub complexity.
    Just simple, reliable Redis operations with direct polling.
    """
    
    def __init__(self, redis_client=None):
        self.redis = redis_client
        
        # Single Redis keys for everything
        self.queue_key = "unified_scan_queue"
        self.processing_key = "unified_scan_processing"
        self.failed_key = "unified_scan_failed"
        self.stats_key = "unified_scan_stats"
        
        # Simple configuration
        self.job_timeout_seconds = 1800  # 30 minutes max per job
        self.cleanup_interval_seconds = 300  # 5 minutes between cleanups
        
        # Tracking
        self.active_jobs: Dict[str, UnifiedScanJob] = {}
        self._last_cleanup = 0
        
        logger.info("🏰 UnifiedScanQueueManager initialized - THE FORTRESS")
    
    async def enqueue_scan(
        self,
        repo_full_name: str,
        user_id: int,
        scan_type: str,
        scan_config: Dict[str, Any],
        priority: UnifiedJobPriority = UnifiedJobPriority.NORMAL
    ) -> str:
        """
        Single point of entry for ALL scan operations.
        Returns job_id immediately, job will be processed within 1-2 seconds.
        """
        logger.info(f"🔧 FORTRESS DEBUG: enqueue_scan called for {repo_full_name} by user {user_id}")
        
        # Create unified job
        job_id = str(uuid.uuid4())
        logger.info(f"🔧 FORTRESS DEBUG: Generated job_id: {job_id}")
        
        job = UnifiedScanJob(
            id=job_id,
            repo_full_name=repo_full_name,
            user_id=user_id,
            scan_type=scan_type,
            priority=priority,
            scan_config=scan_config
        )
        logger.info(f"🔧 FORTRESS DEBUG: Created UnifiedScanJob object for {job_id}")
        
        try:
            logger.info(f"🔧 FORTRESS DEBUG: Getting Redis client for {job_id}")
            redis_client = await get_redis_client()
            if not redis_client:
                raise RuntimeError("Redis client unavailable")
            logger.info(f"🔧 FORTRESS DEBUG: Redis client obtained for {job_id}")
            
            # CRITICAL: Create ScanJob entry in database when job is queued
            logger.info(f"🔧 FORTRESS DB: ABOUT TO CREATE ScanJob entry for {job_id}")
            try:
                await self._create_scan_job_in_database_direct(job)
                logger.info(f"✅ FORTRESS DB: ScanJob entry SUCCESSFULLY CREATED for {job_id}")
            except Exception as db_error:
                logger.error(f"💥 FORTRESS DB: CRITICAL ERROR creating ScanJob {job_id}: {db_error}")
                import traceback
                logger.error(f"💥 FORTRESS DB: Full traceback: {traceback.format_exc()}")
                # Continue with Redis queue even if database fails
            
            # Store job in Redis queue with priority score
            job_data = asdict(job)
            # Convert datetime objects to ISO strings
            for key, value in job_data.items():
                if isinstance(value, datetime):
                    job_data[key] = value.isoformat()
                elif isinstance(value, UnifiedJobStatus):
                    job_data[key] = value.value
                elif isinstance(value, UnifiedJobPriority):
                    job_data[key] = value.value
            
            # Add to priority queue (lower score = higher priority)
            await redis_client.zadd(
                self.queue_key,
                {json.dumps(job_data): priority.value}
            )
            
            # Update stats
            await self._increment_stat("jobs_queued")
            
            logger.info(f"🚀 FORTRESS: Job {job_id} queued for {repo_full_name} (priority: {priority.name})")
            return job_id
            
        except Exception as e:
            logger.error(f"❌ FORTRESS: Failed to enqueue job {job_id}: {e}")
            raise
    
    async def get_next_job(self, worker_id: str) -> Optional[UnifiedScanJob]:
        """
        Direct job pickup - no subscriptions, no complexity.
        Workers call this method directly via polling.
        """
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return None
            
            # Get highest priority job (lowest score)
            job_data = await redis_client.zpopmin(self.queue_key, count=1)
            
            if not job_data:
                return None  # No jobs available
            
            # Parse job
            job_json, _ = job_data[0]
            job_dict = json.loads(job_json)
            
            # Convert back to UnifiedScanJob
            job = self._dict_to_job(job_dict)
            
            # Mark as processing
            job.status = UnifiedJobStatus.PROCESSING
            job.worker_id = worker_id
            job.started_at = datetime.now(timezone.utc)
            
            # Store in processing set
            processing_data = asdict(job)
            for key, value in processing_data.items():
                if isinstance(value, datetime):
                    processing_data[key] = value.isoformat()
                elif isinstance(value, UnifiedJobStatus):
                    processing_data[key] = value.value
                elif isinstance(value, UnifiedJobPriority):
                    processing_data[key] = value.value
            
            await redis_client.setex(
                f"{self.processing_key}:{job.id}",
                self.job_timeout_seconds,
                json.dumps(processing_data)
            )
            
            # Track active job
            self.active_jobs[job.id] = job
            
            # CRITICAL: Update ScanJob status in database to "processing"
            logger.info(f"🔧 FORTRESS DB: Updating ScanJob {job.id} to processing status")
            await self._update_scan_job_in_database(job.id, {
                "status": "processing",
                "assigned_worker": worker_id,
                "started_at": job.started_at
            })
            logger.info(f"✅ FORTRESS DB: ScanJob {job.id} marked as processing")
            
            # Update stats
            await self._increment_stat("jobs_processing")
            
            logger.info(f"⚡ FORTRESS: Job {job.id} picked up by worker {worker_id}")
            return job
            
        except Exception as e:
            logger.error(f"❌ FORTRESS: Error getting next job for worker {worker_id}: {e}")
            return None
    
    async def mark_job_completed(self, job_id: str, result: Optional[Dict[str, Any]] = None, scan_id: Optional[str] = None, db_session: Optional[Any] = None):
        """Mark job as successfully completed"""
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return
            
            # Remove from processing
            await redis_client.delete(f"{self.processing_key}:{job_id}")
            
            # CRITICAL: Also remove progress tracking keys to clear "Processing" status
            await redis_client.delete(f"unified_scan_progress:{job_id}")
            await redis_client.delete(f"scan_progress:{job_id}")  # Legacy key cleanup
            logger.info(f"🧹 FORTRESS: Cleared processing and progress keys for job {job_id}")
            
            # Update active jobs tracking
            completion_time = datetime.now(timezone.utc)
            if job_id in self.active_jobs:
                job = self.active_jobs[job_id]
                job.status = UnifiedJobStatus.COMPLETED
                job.completed_at = completion_time
                del self.active_jobs[job_id]
            
            # CRITICAL: Update ScanJob status in database to "completed" with scan_id link
            logger.info(f"🔗 FORTRESS DB: Marking job {job_id} completed and linking to scan {scan_id}")
            await self._update_scan_job_in_database(job_id, {
                "status": "completed",
                "completed_at": completion_time,
                "scan_id": scan_id  # Critical: Link to the completed Scan record
            }, db_session=db_session)
            logger.info(f"✅ FORTRESS DB: Job {job_id} completed and linked to scan {scan_id}")
            
            # Update stats
            await self._increment_stat("jobs_completed")
            
            logger.info(f"✅ FORTRESS: Job {job_id} completed successfully")
            
        except Exception as e:
            logger.error(f"❌ FORTRESS: Error marking job {job_id} as completed: {e}")
    
    async def mark_job_failed(
        self, 
        job_id: str, 
        error_message: str, 
        retry: bool = True
    ):
        """Mark job as failed with optional retry"""
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return
            
            # Get job from processing
            processing_data = await redis_client.get(f"{self.processing_key}:{job_id}")
            if not processing_data:
                logger.warning(f"Job {job_id} not found in processing queue")
                return
            
            job_dict = json.loads(processing_data)
            job = self._dict_to_job(job_dict)
            
            # Remove from processing
            await redis_client.delete(f"{self.processing_key}:{job_id}")
            
            # Check retry logic
            if retry and job.retry_count < job.max_retries:
                # Retry with lower priority
                job.retry_count += 1
                job.error_message = error_message
                job.status = UnifiedJobStatus.QUEUED
                job.worker_id = None
                job.started_at = None
                
                # Re-queue with low priority
                job.priority = UnifiedJobPriority.LOW
                
                retry_data = asdict(job)
                for key, value in retry_data.items():
                    if isinstance(value, datetime):
                        retry_data[key] = value.isoformat()
                    elif isinstance(value, UnifiedJobStatus):
                        retry_data[key] = value.value
                    elif isinstance(value, UnifiedJobPriority):
                        retry_data[key] = value.value
                
                await redis_client.zadd(
                    self.queue_key,
                    {json.dumps(retry_data): UnifiedJobPriority.LOW.value}
                )
                
                logger.info(f"🔄 FORTRESS: Job {job_id} requeued for retry {job.retry_count}")
                
            else:
                # Permanent failure
                job.status = UnifiedJobStatus.FAILED
                job.error_message = error_message
                job.completed_at = datetime.now(timezone.utc)
                
                failed_data = asdict(job)
                for key, value in failed_data.items():
                    if isinstance(value, datetime):
                        failed_data[key] = value.isoformat()
                    elif isinstance(value, UnifiedJobStatus):
                        failed_data[key] = value.value
                    elif isinstance(value, UnifiedJobPriority):
                        failed_data[key] = value.value
                
                await redis_client.lpush(
                    self.failed_key,
                    json.dumps(failed_data)
                )
                
                # CRITICAL FIX: Update ScanJob status in database to "failed"
                await self._update_scan_job_in_database(job_id, {
                    "status": "failed",
                    "error_message": error_message,
                    "completed_at": job.completed_at,
                    "retry_count": job.retry_count
                })
                
                # Update stats
                await self._increment_stat("jobs_failed")
                
                logger.error(f"❌ FORTRESS: Job {job_id} failed permanently: {error_message}")
            
            # Clean up active jobs tracking
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]
            
        except Exception as e:
            logger.error(f"❌ FORTRESS: Error marking job {job_id} as failed: {e}")
    
    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a job with complete job information"""
        try:
            logger.info(f"🔍 FORTRESS DEBUG: Looking for job {job_id}")
            redis_client = await get_redis_client()
            if not redis_client:
                logger.warning(f"🔍 FORTRESS DEBUG: Redis client unavailable for job {job_id}")
                # CRITICAL FIX: Still check database even if Redis is unavailable
                job_status = await self._get_scan_job_from_database(job_id)
                if job_status:
                    logger.info(f"🔍 FORTRESS DEBUG: Found job {job_id} in database despite Redis unavailable")
                    return job_status
                logger.warning(f"🔍 FORTRESS DEBUG: Job {job_id} not found in database either")
                return None
            
            # Check processing queue first
            logger.info(f"🔍 FORTRESS DEBUG: Checking processing queue for job {job_id}")
            processing_data = await redis_client.get(f"{self.processing_key}:{job_id}")
            if processing_data:
                logger.info(f"🔍 FORTRESS DEBUG: Found job {job_id} in processing queue")
                job_dict = json.loads(processing_data)
                # Return complete job information for processing jobs
                return {
                    "job_id": job_id,
                    "status": job_dict.get("status", "processing"),
                    "repo_full_name": job_dict.get("repo_full_name"),
                    "user_id": job_dict.get("user_id"),
                    "scan_type": job_dict.get("scan_type"),
                    "created_at": job_dict.get("created_at"),
                    "started_at": job_dict.get("started_at"),
                    "worker_id": job_dict.get("worker_id"),
                    "priority": job_dict.get("priority"),
                    "scan_config": job_dict.get("scan_config", {}),
                    "progress": "Processing scan...",
                    "retry_count": job_dict.get("retry_count", 0)
                }
            
            # Check main queue
            queue_jobs = await redis_client.zrange(self.queue_key, 0, -1)
            for job_json in queue_jobs:
                job_dict = json.loads(job_json)
                if job_dict.get("id") == job_id:
                    # Return complete job information for queued jobs
                    return {
                        "job_id": job_id,
                        "status": "queued",
                        "repo_full_name": job_dict.get("repo_full_name"),
                        "user_id": job_dict.get("user_id"),
                        "scan_type": job_dict.get("scan_type"),
                        "created_at": job_dict.get("created_at"),
                        "priority": job_dict.get("priority"),
                        "scan_config": job_dict.get("scan_config", {}),
                        "progress": "Waiting in queue...",
                        "retry_count": job_dict.get("retry_count", 0)
                    }
            
            # Check failed queue
            failed_jobs = await redis_client.lrange(self.failed_key, 0, -1)
            for job_json in failed_jobs:
                job_dict = json.loads(job_json)
                if job_dict.get("id") == job_id:
                    # Return complete job information for failed jobs
                    return {
                        "job_id": job_id,
                        "status": "failed",
                        "repo_full_name": job_dict.get("repo_full_name"),
                        "user_id": job_dict.get("user_id"),
                        "scan_type": job_dict.get("scan_type"),
                        "created_at": job_dict.get("created_at"),
                        "started_at": job_dict.get("started_at"),
                        "completed_at": job_dict.get("completed_at"),
                        "error_message": job_dict.get("error_message"),
                        "priority": job_dict.get("priority"),
                        "scan_config": job_dict.get("scan_config", {}),
                        "retry_count": job_dict.get("retry_count", 0),
                        "progress": "Failed"
                    }
            
            # CRITICAL FIX: Check database for completed jobs
            # If not found in Redis, check the ScanJob database table
            logger.info(f"🔍 FORTRESS DEBUG: Job {job_id} not found in Redis, checking database")
            job_status = await self._get_scan_job_from_database(job_id)
            if job_status:
                logger.info(f"🔍 FORTRESS DEBUG: Found job {job_id} in database: {job_status}")
                return job_status
            
            logger.warning(f"🔍 FORTRESS DEBUG: Job {job_id} not found anywhere")
            return None  # Job not found
            
        except Exception as e:
            logger.error(f"❌ FORTRESS: Error getting job status {job_id}: {e}")
            return None
    
    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get comprehensive queue statistics"""
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return {"error": "Redis unavailable"}
            
            # Count items in each queue
            queued_count = await redis_client.zcard(self.queue_key)
            processing_keys = await redis_client.keys(f"{self.processing_key}:*")
            processing_count = len(processing_keys)
            failed_count = await redis_client.llen(self.failed_key)
            
            # Get historical stats
            stats_data = await redis_client.hgetall(self.stats_key)
            historical_stats = {k.decode(): int(v.decode()) for k, v in stats_data.items()} if stats_data else {}
            
            return {
                "queue_status": "healthy",
                "queued": queued_count,
                "processing": processing_count,
                "failed": failed_count,
                "total_active": queued_count + processing_count,
                "historical": historical_stats,
                "system": "unified_fortress",
                "last_cleanup": self._last_cleanup,
                "active_workers": len(set(job.worker_id for job in self.active_jobs.values() if job.worker_id))
            }
            
        except Exception as e:
            logger.error(f"❌ FORTRESS: Error getting queue stats: {e}")
            return {"error": str(e)}
    
    async def cleanup_stale_jobs(self):
        """Clean up jobs that have timed out"""
        current_time = asyncio.get_event_loop().time()
        if current_time - self._last_cleanup < self.cleanup_interval_seconds:
            return  # Too soon for cleanup
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return
            
            self._last_cleanup = current_time
            
            # Find stale processing jobs
            processing_keys = await redis_client.keys(f"{self.processing_key}:*")
            stale_count = 0
            
            for key in processing_keys:
                try:
                    job_data = await redis_client.get(key)
                    if job_data:
                        job_dict = json.loads(job_data)
                        started_at = job_dict.get("started_at")
                        
                        if started_at:
                            start_time = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
                            if datetime.now(timezone.utc) - start_time > timedelta(seconds=self.job_timeout_seconds):
                                # Job has timed out
                                job_id = job_dict.get("id")
                                await self.mark_job_failed(job_id, "Job timed out", retry=True)
                                stale_count += 1
                                
                except Exception as e:
                    logger.warning(f"Error checking job {key}: {e}")
            
            if stale_count > 0:
                logger.info(f"🧹 FORTRESS: Cleaned up {stale_count} stale jobs")
            
        except Exception as e:
            logger.error(f"❌ FORTRESS: Error during cleanup: {e}")
    
    def _dict_to_job(self, job_dict: Dict[str, Any]) -> UnifiedScanJob:
        """Convert dictionary to UnifiedScanJob object"""
        # Convert string values back to proper types
        if isinstance(job_dict.get("priority"), str):
            job_dict["priority"] = UnifiedJobPriority[job_dict["priority"]]
        elif isinstance(job_dict.get("priority"), int):
            job_dict["priority"] = UnifiedJobPriority(job_dict["priority"])
        
        if isinstance(job_dict.get("status"), str):
            job_dict["status"] = UnifiedJobStatus(job_dict["status"])
        
        # Convert datetime strings
        for field in ["created_at", "started_at", "completed_at"]:
            if job_dict.get(field):
                if isinstance(job_dict[field], str):
                    job_dict[field] = datetime.fromisoformat(job_dict[field].replace('Z', '+00:00'))
        
        return UnifiedScanJob(**job_dict)
    
    async def _increment_stat(self, stat_name: str):
        """Increment a statistic counter"""
        try:
            redis_client = await get_redis_client()
            if redis_client:
                await redis_client.hincrby(self.stats_key, stat_name, 1)
        except Exception:
            pass  # Don't fail operations due to stats
    
    async def _update_scan_job_in_database(self, job_id: str, updates: Dict[str, Any], db_session: Optional[Any] = None):
        """CRITICAL FIX: Update ScanJob status with proper session management to prevent pool exhaustion"""
        try:
            logger.info(f"🔧 FORTRESS DB: Updating ScanJob {job_id} with: {updates}")
            
            # CRITICAL FIX: Use provided session if available, otherwise create new one
            if db_session is not None:
                session = db_session
                should_commit = False  # External session handles commits
            else:
                # Use context manager for new session
                session_ctx = get_db_session(DatabaseOperation.WRITE)
                session = await session_ctx.__aenter__()
                should_commit = True
            
            try:
                # CRITICAL FIX: Skip scan existence check to avoid transaction isolation issues
                # The scan_id was just created in the same transaction, so we trust it exists
                # Update ScanJob record directly
                stmt = update(ScanJob).where(ScanJob.id == job_id).values(**updates)
                result = await session.execute(stmt)
                
                # CRITICAL FIX: Always flush changes to ensure they're visible
                await session.flush()
                
                # CRITICAL FIX: Only commit if we created the session
                if should_commit:
                    await session.commit()
                    logger.info(f"✅ FORTRESS DB: ScanJob {job_id} update COMMITTED to database")
                else:
                    logger.info(f"✅ FORTRESS DB: ScanJob {job_id} update FLUSHED (external session will commit)")
                
                if result.rowcount > 0:
                    logger.info(f"✅ FORTRESS DB: Updated ScanJob {job_id} in database: {updates}")
                else:
                    logger.warning(f"⚠️ FORTRESS DB: ScanJob {job_id} not found in database for update")
                    
            finally:
                # CRITICAL FIX: Clean up session context if we created it
                if should_commit and 'session_ctx' in locals():
                    await session_ctx.__aexit__(None, None, None)
                
        except Exception as e:
            # CRITICAL FIX: Handle all database errors gracefully but always attempt status update
            logger.error(f"❌ FORTRESS DB: Error updating ScanJob {job_id}: {e}")
            
            # Only retry if we're not already using an external session
            if db_session is None:
                # Always attempt a basic status update without scan_id to ensure job doesn't get stuck
                try:
                    basic_updates = {k: v for k, v in updates.items() if k != 'scan_id'}
                    if basic_updates:  # Only retry if there are non-scan_id updates
                        logger.info(f"🔄 FORTRESS DB: Retrying basic status update for {job_id}: {basic_updates}")
                        
                        async with get_db_session(DatabaseOperation.WRITE) as retry_session:
                            stmt = update(ScanJob).where(ScanJob.id == job_id).values(**basic_updates)
                            result = await retry_session.execute(stmt)
                            await retry_session.commit()
                            
                            if result.rowcount > 0:
                                logger.info(f"✅ FORTRESS DB: Basic status update succeeded for job {job_id}")
                            else:
                                logger.warning(f"⚠️ FORTRESS DB: Job {job_id} not found for basic update")
                                
                except Exception as retry_e:
                    logger.error(f"❌ FORTRESS DB: Basic status update also failed for job {job_id}: {retry_e}")
            
            # Don't raise - Redis queue should still work even if database fails
    
    
    async def _create_scan_job_in_database_direct(self, job: UnifiedScanJob):
        """CRITICAL FIX: Create ScanJob entry in database with proper session management"""
        logger.info(f"🔧 FORTRESS DB: Creating ScanJob entry for job {job.id}")
        
        max_retries = 3
        for attempt in range(max_retries):
            session_ctx = None
            try:
                session_ctx = get_db_session(DatabaseOperation.WRITE)
                session = await session_ctx.__aenter__()
                logger.info(f"🔧 FORTRESS DB: Attempt {attempt + 1}/{max_retries} - Creating ScanJob for {job.id}")
                
                # Create ScanJob database entry
                pr_number = None
                if job.scan_type == "pr_scan" and job.scan_config:
                    pr_number = job.scan_config.get("pr_number")
                
                scan_job = ScanJob(
                    id=job.id,
                    repo_full_name=job.repo_full_name,
                    user_id=job.user_id,
                    scan_type=job.scan_type,
                    priority=job.priority.value,
                    pr_number=pr_number,
                    job_data={
                        "user_id": job.user_id,
                        "scan_config": job.scan_config,
                        "created_at": job.created_at.isoformat(),
                        "priority": job.priority.name
                    },
                    status=job.status.value,
                    retry_count=job.retry_count,
                    max_retries=job.max_retries,
                    created_at=job.created_at
                )
                
                session.add(scan_job)
                await session.commit()  # CRITICAL FIX: Explicit commit
                
                # CRITICAL FIX: Ensure session is properly closed
                await session_ctx.__aexit__(None, None, None)
                session_ctx = None
                
                logger.info(f"✅ FORTRESS DB: ScanJob {job.id} successfully created in database")
                return  # Success - exit retry loop
                    
            except Exception as e:
                logger.error(f"❌ FORTRESS DB: Attempt {attempt + 1}/{max_retries} failed for job {job.id}: {e}")
                # CRITICAL FIX: Always ensure session context is cleaned up on error
                if session_ctx:
                    try:
                        await session_ctx.__aexit__(type(e), e, e.__traceback__)
                    except Exception:
                        pass  # Ignore cleanup errors
                    session_ctx = None
                    
                if attempt == max_retries - 1:
                    logger.error(f"💥 FORTRESS DB: All attempts failed for job {job.id}")
                    # Don't raise - allow job to proceed in Redis queue even if DB creation fails
                    return
                else:
                    import asyncio
                    await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
    
    async def _get_scan_job_from_database(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get ScanJob information from database (for completed jobs)"""
        session_ctx = None
        try:
            logger.info(f"🔍 FORTRESS DB: Querying database for job {job_id}")
            
            session_ctx = get_db_session(DatabaseOperation.READ)
            session = await session_ctx.__aenter__()
            
            # Query ScanJob record
            stmt = select(ScanJob).where(ScanJob.id == job_id)
            result = await session.execute(stmt)
            scan_job = result.scalar_one_or_none()
            
            logger.info(f"🔍 FORTRESS DB: Database query result for job {job_id}: {scan_job}")
            
            if scan_job:
                    logger.info(f"🔍 FORTRESS DB: Building response for job {job_id} - status: {scan_job.status}, scan_id: {scan_job.scan_id}")
                    
                    # Check Redis progress for processing jobs to detect completion discrepancies
                    actual_status = scan_job.status
                    actual_progress = self._get_progress_message(scan_job.status)
                    
                    if scan_job.status == "processing":
                        try:
                            # Check Redis progress data
                            redis_client = await get_redis_client()
                            if redis_client:
                                progress_data_str = await redis_client.get(f"unified_scan_progress:{job_id}")
                                if progress_data_str:
                                    import json
                                    progress_data = json.loads(progress_data_str)
                                    redis_progress = progress_data.get("progress", "0%")
                                    redis_stage = progress_data.get("stage", "")
                                    
                                    # If Redis shows 100% but database shows processing, mark as completed
                                    if redis_progress == "100%" or "completed" in redis_stage.lower():
                                        logger.warning(f"🔄 FORTRESS DB: Redis shows job {job_id} is 100% complete but database shows processing - correcting status")
                                        actual_status = "completed"
                                        actual_progress = "Completed successfully"
                                        
                                        # Attempt to fix the database status asynchronously
                                        asyncio.create_task(self._fix_stuck_job_status(job_id))
                                    else:
                                        actual_progress = f"{redis_progress} - {redis_stage}"
                        except Exception as e:
                            logger.warning(f"⚠️ FORTRESS DB: Could not check Redis progress for job {job_id}: {e}")
                    
                    # Return standardized job status format
                    return {
                        "job_id": scan_job.id,
                        "status": actual_status,
                        "repo_full_name": scan_job.repo_full_name,
                        "scan_type": scan_job.scan_type,
                        "priority": scan_job.priority,
                        "user_id": scan_job.job_data.get("user_id") if scan_job.job_data else None,
                        "scan_config": scan_job.job_data.get("scan_config", {}) if scan_job.job_data else {},
                        "created_at": scan_job.created_at.isoformat() if scan_job.created_at else None,
                        "started_at": scan_job.started_at.isoformat() if scan_job.started_at else None,
                        "completed_at": scan_job.completed_at.isoformat() if scan_job.completed_at else None,
                        "assigned_worker": scan_job.assigned_worker,
                        "error_message": scan_job.error_message,
                        "retry_count": scan_job.retry_count,
                        "scan_id": scan_job.scan_id,  # Link to completed Scan record
                        "progress": actual_progress
                    }
                
            logger.info(f"🔍 FORTRESS DB: Job {job_id} not found in database")
            return None
                
        except Exception as e:
            logger.error(f"❌ FORTRESS DB: Failed to get ScanJob {job_id} from database: {e}")
            import traceback
            logger.error(f"❌ FORTRESS DB: Traceback: {traceback.format_exc()}")
            return None
        finally:
            # CRITICAL FIX: Always clean up session context
            if session_ctx:
                try:
                    await session_ctx.__aexit__(None, None, None)
                except Exception:
                    pass  # Ignore cleanup errors
    
    def _get_progress_message(self, status: str) -> str:
        """Get human-readable progress message based on status"""
        progress_messages = {
            "queued": "Waiting in queue...",
            "processing": "Processing scan...",
            "completed": "Completed successfully",
            "failed": "Failed"
        }
        return progress_messages.get(status, "Unknown status")
    
    async def _fix_stuck_job_status(self, job_id: str):
        """Fix stuck job status by updating database to completed without scan_id reference"""
        try:
            logger.info(f"🔄 FORTRESS DB: Attempting to fix stuck job {job_id} status")
            
            from datetime import datetime, timezone
            completion_time = datetime.now(timezone.utc)
            
            # Update job to completed status without scan_id to avoid foreign key issues
            await self._update_scan_job_in_database(job_id, {
                "status": "completed",
                "completed_at": completion_time
                # Note: Not including scan_id to avoid foreign key constraint issues
            })
            
            logger.info(f"✅ FORTRESS DB: Successfully fixed stuck job {job_id} status")
            
        except Exception as e:
            logger.error(f"❌ FORTRESS DB: Failed to fix stuck job {job_id} status: {e}")


# Global singleton instance
_unified_queue_manager: Optional[UnifiedScanQueueManager] = None


async def get_unified_queue_manager() -> UnifiedScanQueueManager:
    """Get the single unified queue manager instance"""
    global _unified_queue_manager
    
    if _unified_queue_manager is None:
        try:
            redis_client = await get_redis_client()
        except Exception as e:
            logger.warning(f"Failed to get Redis client: {e}")
            redis_client = None
        
        _unified_queue_manager = UnifiedScanQueueManager(redis_client)
        logger.info("🏰 FORTRESS: Unified Queue Manager initialized")
    
    return _unified_queue_manager


async def shutdown_unified_queue_manager():
    """Shutdown the unified queue manager"""
    global _unified_queue_manager
    
    if _unified_queue_manager:
        # Perform any necessary cleanup
        logger.info("🏰 FORTRESS: Shutting down Unified Queue Manager")
        _unified_queue_manager = None