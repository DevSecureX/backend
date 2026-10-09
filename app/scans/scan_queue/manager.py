import json
import uuid
import logging
from datetime import timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.dialects.postgresql import insert
from core.redis import get_redis_client
from core.utils import utc_now, utc_now_iso, ensure_utc_datetime
from core.redis_call_optimizer import get_redis_optimizer
from ..models import ScanJob

logger = logging.getLogger(__name__)

class ScanPriority(Enum):
    URGENT = 0    # Critical security fixes
    HIGH = 1      # PR scans
    NORMAL = 2    # Manual scans
    LOW = 3       # Scheduled scans

class ScanType(Enum):
    MANUAL = "manual"
    PR_SCAN = "pr_scan"
    PUSH_SCAN = "push_scan"
    SCHEDULED = "scheduled"

class ScanQueueManager:
    def __init__(self):
        self.queue_key = "scan_queue"
        self.processing_key = "scan_processing"
        self.failed_key = "scan_failed"  
        self.max_retries = 3
        self.job_timeout = 2400  # CRITICAL FIX: Reduced from 1 hour to 40 minutes for faster cleanup
        
        # CRITICAL FIX: Add Redis operation throttling to prevent excessive calls
        self._last_cleanup = 0  # Track last cleanup time
        self._cleanup_interval = 900  # Minimum 15 minutes between cleanups
        self._redis_operation_timeout = 3.0  # Standard timeout for Redis operations
        
    async def enqueue_scan(
        self,
        repo_full_name: str,
        scan_type: ScanType,
        scan_data: Dict[str, Any],
        priority: ScanPriority = ScanPriority.NORMAL,
        db: AsyncSession = None
    ) -> str:
        """Enqueue a scan job"""
        job_id = str(uuid.uuid4())
        
        job_data = {
            "id": job_id,
            "repo_full_name": repo_full_name,
            "scan_type": scan_type.value,
            "priority": priority.value,
            "scan_data": scan_data,
            "created_at": utc_now_iso(),
            "retry_count": 0
        }
        
        try:
            # Store in database
            if db:
                await self._store_job_in_db(job_data, db)
            
            # Add to Redis queue with priority (fallback to database-only if Redis unavailable)
            redis_client = await get_redis_client()
            if redis_client is None:
                logger.warning("Redis client not available for enqueue - storing job in database only")
                # Still return the job_id even if Redis is unavailable
                # The job will be stored in database and can be processed later
                logger.info(f"Enqueued scan job {job_id} for {repo_full_name} in database (Redis unavailable)")
                return job_id
            else:
                await redis_client.zadd(
                    self.queue_key,
                    {json.dumps(job_data): priority.value}
                )
                logger.info(f"Enqueued scan job {job_id} for {repo_full_name} with priority {priority.name}")
                
                # EVENT-DRIVEN OPTIMIZATION: Immediately notify workers for instant processing
                try:
                    from ..event_driven import event_system
                    logger.debug(f"Publishing event notification for job {job_id}")
                    
                    # Publish event and check for active subscribers
                    event_published = await event_system.publish_scan_job_available(job_data)
                    
                    if event_published:
                        logger.info(f"✅ Event notification published for job {job_id} - workers will process instantly")
                    else:
                        logger.warning(f"⚠️  Event notification failed for job {job_id} - workers will use fallback polling")
                        
                except ImportError as e:
                    logger.warning(f"Event system not available: {e} - workers will use fallback polling")
                except Exception as event_error:
                    # Don't fail job enqueue if event notification fails
                    logger.warning(f"Failed to publish scan job event notification for {job_id}: {event_error}")
                    logger.warning("Workers will discover job via fallback polling")
            
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to enqueue scan job: {e}", exc_info=True)
            raise
    
    async def dequeue_job(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Dequeue highest priority job with enhanced connection pooling and circuit breaker protection"""
        
        try:
            # CRITICAL FIX: Use optimized Redis client with connection pooling
            try:
                from core.redis_pool_manager import get_worker_redis_manager
                worker_manager = await get_worker_redis_manager()
                redis_client = await worker_manager.get_shared_client()
            except ImportError:
                # Fallback to regular client if worker manager not available
                redis_client = await get_redis_client()
            
            if redis_client is None:
                logger.warning(f"Redis client not available for dequeue (worker: {worker_id})")
                return None
            
            # CRITICAL FIX: Get highest priority job with optimized timeout and better error handling
            try:
                # Use optimized timeout for queue operations
                job_data = await asyncio.wait_for(
                    redis_client.zpopmin(self.queue_key), 
                    timeout=self._redis_operation_timeout
                )
            except asyncio.TimeoutError:
                logger.debug(f"Redis zpopmin timeout for worker {worker_id} after {self._redis_operation_timeout}s")
                return None
            except Exception as e:
                logger.warning(f"Redis zpopmin failed for worker {worker_id}: {e}")
                return None
            
            if not job_data:
                logger.debug(f"No jobs available for worker {worker_id}")
                return None
            
            job_json = job_data[0][0]
            job = json.loads(job_json)
            
            # CRITICAL FIX: Move to processing queue with enhanced error handling and retries
            processing_data = {
                **job,
                "worker_id": worker_id,
                "started_at": utc_now_iso()
            }
            
            # Retry setex operation once if it fails
            for attempt in range(2):
                try:
                    await asyncio.wait_for(
                        redis_client.setex(
                            f"{self.processing_key}:{job['id']}",
                            self.job_timeout,
                            json.dumps(processing_data)
                        ),
                        timeout=self._redis_operation_timeout
                    )
                    
                    logger.info(f"✅ Dequeued job {job['id']} for worker {worker_id}")
                    return job
                    
                except asyncio.TimeoutError:
                    if attempt == 0:
                        logger.debug(f"Timeout setting job {job['id']} to processing, retrying...")
                        await asyncio.sleep(0.1)  # Brief delay before retry
                        continue
                    else:
                        logger.warning(f"Timeout setting job {job['id']} to processing after retry")
                        break
                        
                except Exception as e:
                    if attempt == 0:
                        logger.warning(f"Error setting job {job['id']} to processing, retrying: {e}")
                        await asyncio.sleep(0.1)  # Brief delay before retry
                        continue
                    else:
                        logger.error(f"Failed to move job {job['id']} to processing queue after retry: {e}")
                        break
            
            # CRITICAL FIX: Re-queue job with optimized timeout if processing queue failed
            logger.info(f"Re-queuing job {job['id']} due to processing queue failure")
            try:
                await asyncio.wait_for(
                    redis_client.zadd(self.queue_key, {job_json: job.get('priority', 2)}),
                    timeout=self._redis_operation_timeout
                )
                logger.info(f"♾️ Re-queued job {job['id']} successfully")
            except Exception as requeue_error:
                logger.error(f"CRITICAL: Failed to re-queue job {job['id']}: {requeue_error}")
            
            return None
                
        except Exception as e:
            logger.error(f"Unexpected error in dequeue_job for worker {worker_id}: {e}")
            return None
    
    async def mark_job_completed(self, job_id: str, db: AsyncSession = None):
        """Mark job as completed"""
        
        redis_client = await get_redis_client()
        if redis_client:
            await redis_client.delete(f"{self.processing_key}:{job_id}")
        
        if db:
            await self._update_job_status(job_id, "completed", db)
        
        logger.info(f"Marked job {job_id} as completed")
    
    async def mark_job_failed(
        self, 
        job_id: str, 
        error_message: str, 
        retry: bool = True,
        db: AsyncSession = None
    ):
        """Mark job as failed and optionally retry"""
        
        redis_client = await get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for mark_job_failed")
            return
            
        # Get job from processing queue
        processing_data = await redis_client.get(f"{self.processing_key}:{job_id}")
        
        if not processing_data:
            logger.warning(f"Job {job_id} not found in processing queue")
            return
        
        job = json.loads(processing_data)
        
        # Remove from processing
        await redis_client.delete(f"{self.processing_key}:{job_id}")
        
        # Check if should retry
        if retry and job.get("retry_count", 0) < self.max_retries:
            job["retry_count"] = job.get("retry_count", 0) + 1
            job["last_error"] = error_message
            job["retry_at"] = (utc_now() + timedelta(minutes=5 * job["retry_count"])).isoformat()
            
            # Re-queue with lower priority
            await redis_client.zadd(
                self.queue_key,
                {json.dumps(job): ScanPriority.LOW.value}
            )
            
            logger.info(f"Requeued job {job_id} for retry {job['retry_count']}")
        else:
            # Move to failed queue
            await redis_client.lpush(self.failed_key, json.dumps({
                **job,
                "failed_at": utc_now_iso(),
                "error_message": error_message
            }))
            
            logger.error(f"Job {job_id} failed permanently: {error_message}")
        
        if db:
            await self._update_job_status(job_id, "failed", db, error_message)
    
    async def get_queue_stats(self) -> Dict[str, int]:
        """Get queue statistics with caching to reduce Redis calls"""
        
        redis_client = await get_redis_client()
        if redis_client is None:
            # Return default stats if Redis is not available
            return {
                "queued": 0,
                "processing": 0,
                "failed": 0
            }
        
        try:
            # Use Redis call optimizer to cache frequent stats requests
            optimizer = get_redis_optimizer()
            stats = await optimizer.get_queue_stats_cached(
                redis_client, 
                self.queue_key, 
                self.processing_key, 
                self.failed_key,
                ttl=60  # Cache for 60 seconds
            )
            return stats
        except Exception as e:
            logger.error(f"Redis queue stats error: {e}")
            # Return default stats on Redis error
            return {
                "queued": 0,
                "processing": 0,
                "failed": 0
            }
    
    async def cleanup_stale_jobs(self):
        """Clean up stale processing jobs with optimized performance and throttling"""
        
        # CRITICAL FIX: Throttle cleanup operations to prevent excessive Redis calls
        current_time = asyncio.get_event_loop().time()
        if current_time - self._last_cleanup < self._cleanup_interval:
            logger.debug(f"Cleanup throttled - last cleanup {current_time - self._last_cleanup:.0f}s ago (min interval: {self._cleanup_interval}s)")
            return
        
        redis_client = await get_redis_client()
        if redis_client is None:
            logger.debug("Redis client not available for cleanup_stale_jobs")
            return
            
        try:
            logger.debug("Starting throttled stale job cleanup cycle")
            self._last_cleanup = current_time
            
            # CRITICAL FIX: Use faster scan with timeout and batch processing
            processing_keys = await asyncio.wait_for(
                self._scan_keys(redis_client, f"{self.processing_key}:*"),
                timeout=8.0  # Slightly longer timeout but still fast
            )
            
            if not processing_keys:
                logger.debug("No processing jobs to clean up")
                return
            
            # CRITICAL FIX: Process keys in smaller batches and limit per cycle
            cleanup_count = 0
            max_cleanup_per_cycle = 15  # Reduced limit to prevent Redis overload
            batch_size = 5  # Process in smaller batches
            
            for i in range(0, min(len(processing_keys), max_cleanup_per_cycle), batch_size):
                batch_keys = processing_keys[i:i + batch_size]
                
                for key in batch_keys:
                    try:
                        job_data = await asyncio.wait_for(
                            redis_client.get(key),
                            timeout=self._redis_operation_timeout
                        )
                        
                        if job_data:
                            job = json.loads(job_data)
                            started_at = ensure_utc_datetime(job.get("started_at"))
                            
                            # If job has been processing for more than timeout, mark as failed
                            if started_at and utc_now() - started_at > timedelta(seconds=self.job_timeout):
                                job_id = job.get("id")
                                await asyncio.wait_for(
                                    self.mark_job_failed(job_id, "Job timed out", retry=True),
                                    timeout=self._redis_operation_timeout
                                )
                                cleanup_count += 1
                                logger.warning(f"Cleaned up stale job {job_id}")
                                
                    except asyncio.TimeoutError:
                        logger.warning(f"Timeout during cleanup of key {key}")
                        continue
                    except Exception as key_error:
                        logger.warning(f"Error cleaning up key {key}: {key_error}")
                        continue
                
                # Small pause between batches to prevent Redis overload
                if i + batch_size < min(len(processing_keys), max_cleanup_per_cycle):
                    await asyncio.sleep(0.1)
                    
            if cleanup_count > 0:
                logger.info(f"Throttled cleanup cycle completed: {cleanup_count} stale jobs removed (processed {min(len(processing_keys), max_cleanup_per_cycle)}/{len(processing_keys)} keys)")
            else:
                logger.debug(f"No stale jobs found in cleanup cycle (checked {min(len(processing_keys), max_cleanup_per_cycle)}/{len(processing_keys)} keys)")
                
        except asyncio.TimeoutError:
            logger.warning("Stale job cleanup timed out - Redis may be under heavy load")
            # Don't reset cleanup timer on timeout - allow retry sooner
            self._last_cleanup = current_time - (self._cleanup_interval / 2)
        except Exception as e:
            logger.error(f"Error during stale job cleanup: {e}")
            # Don't reset cleanup timer on error - allow retry sooner
            self._last_cleanup = current_time - (self._cleanup_interval / 2)
    
    async def _store_job_in_db(self, job_data: Dict[str, Any], db: AsyncSession):
        """Store job in database for persistence"""
        try:
            db_job = {
                "id": job_data["id"],
                "repo_full_name": job_data["repo_full_name"],
                "scan_type": job_data["scan_type"],
                "priority": job_data["priority"],
                "job_data": job_data,
                "status": "queued"
            }
            
            stmt = insert(ScanJob).values(**db_job)
            await db.execute(stmt)
            # Don't commit here - let the calling context manage transactions
            logger.info(f"Stored job {job_data['id']} in database")
            
        except Exception as e:
            logger.error(f"Failed to store job in database: {e}", exc_info=True)
            # Don't rollback here - let the calling context handle it
            raise
    
    async def _update_job_status(
        self, 
        job_id: str, 
        status: str, 
        db: AsyncSession,
        error_message: str = None
    ):
        """Update job status in database"""
        try:
            update_data = {"status": status}
            
            if status == "completed":
                update_data["completed_at"] = utc_now()
            elif status == "failed" and error_message:
                update_data["error_message"] = error_message
                update_data["completed_at"] = utc_now()
            elif status == "processing":
                update_data["started_at"] = utc_now()
            
            await db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(**update_data)
            )
            # Don't commit here - let the calling context manage transactions
            logger.info(f"Updated job {job_id} status to {status}")
            
        except Exception as e:
            logger.error(f"Failed to update job status: {e}", exc_info=True)
            # Don't rollback here - let the calling context handle it
            raise
    
    async def _update_job_scan_id(self, job_id: str, scan_id: str, db: AsyncSession):
        """Update job with completed scan ID"""
        try:
            await db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(scan_id=scan_id)
            )
            # Don't commit here - let the calling context manage transactions
            logger.info(f"Updated job {job_id} with scan_id {scan_id}")
        except Exception as e:
            logger.error(f"Failed to update job scan_id: {e}", exc_info=True)
            # Don't rollback here - let the calling context handle it
            raise
    
    async def _scan_keys(self, redis_client, pattern: str) -> List[str]:
        """Use SCAN instead of KEYS to avoid blocking Redis"""
        try:
            keys = []
            cursor = 0
            while True:
                cursor, partial_keys = await redis_client.scan(cursor=cursor, match=pattern, count=100)
                keys.extend(partial_keys)
                if cursor == 0:
                    break
            return keys
        except Exception as e:
            logger.warning(f"SCAN operation failed, falling back to empty list: {e}")
            return []
    
    async def _count_keys_with_scan(self, redis_client, pattern: str) -> int:
        """Count keys using SCAN instead of expensive KEYS + len operations"""
        try:
            keys = await self._scan_keys(redis_client, pattern)
            return len(keys)
        except Exception as e:
            logger.warning(f"Key count via SCAN failed: {e}")
            return 0
