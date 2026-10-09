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
from ..models import ScanJob

logger = logging.getLogger(__name__)

class AutofixPriority(Enum):
    URGENT = 0    # Critical security fixes
    HIGH = 1      # User-initiated auto-fixes
    NORMAL = 2    # Scheduled auto-fixes
    LOW = 3       # Background maintenance

class AutofixJobStatus(Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class AutofixQueueManager:
    """Queue manager for auto-fix background jobs"""
    
    def __init__(self):
        self.queue_key = "autofix_queue"
        self.processing_key = "autofix_processing"
        self.progress_key = "autofix_progress"
        self.results_key = "autofix_results"
        self.failed_key = "autofix_failed"
        self.max_retries = 2
        self.job_timeout = 1800  # 30 minutes
        self._redis_client = None  # Cache Redis client to reduce connection overhead
        
        # Progress stages for UI feedback
        self.progress_stages = {
            0: "Initializing auto-fix job...",
            10: "Validating scan data...",
            20: "Analyzing security issues...",
            30: "Filtering issues by severity...",
            40: "Setting up workspace...",
            50: "Cloning repository...",
            60: "Applying security fixes...",
            70: "Generating security fixes...",
            85: "Creating pull request...",
            95: "Finalizing auto-fix...",
            100: "Auto-fix completed"
        }
    
    async def _get_redis_client(self):
        """Get Redis client with connection caching and health check"""
        if self._redis_client is None:
            self._redis_client = await get_redis_client()
        
        # Health check cached client
        if self._redis_client:
            try:
                await self._redis_client.ping()
                return self._redis_client
            except Exception as e:
                logger.warning(f"Cached Redis client failed health check: {e}")
                self._redis_client = await get_redis_client()
        
        return self._redis_client
        
    async def enqueue_autofix_job(
        self,
        scan_id: str,
        user_id: int,
        repo_full_name: str,
        autofix_data: Dict[str, Any],
        priority: AutofixPriority = AutofixPriority.HIGH,
        db: Optional[AsyncSession] = None
    ) -> str:
        """Enqueue an auto-fix job"""
        job_id = str(uuid.uuid4())
        
        job_data = {
            "id": job_id,
            "scan_id": scan_id,
            "user_id": user_id,
            "repo_full_name": repo_full_name,
            "priority": priority.value,
            "autofix_data": autofix_data,
            "created_at": utc_now_iso(),
            "retry_count": 0,
            "status": AutofixJobStatus.QUEUED.value
        }
        
        try:
            # Store job in database if available
            if db:
                await self._store_autofix_job_in_db(job_data, db)
            
            # Add to Redis queue with priority
            redis_client = await self._get_redis_client()
            if redis_client is None:
                logger.warning("Redis client not available for enqueue")
                if not db:
                    raise Exception("Neither Redis nor database available for job storage")
                return job_id
                
            await redis_client.zadd(
                self.queue_key,
                {json.dumps(job_data): priority.value}
            )
            
            # Initialize progress
            await self._update_progress(job_id, 0, self.progress_stages[0])
            
            logger.info(f"Enqueued auto-fix job {job_id} for scan {scan_id} with priority {priority.name}")
            return job_id
            
        except Exception as e:
            logger.error(f"Failed to enqueue auto-fix job: {e}", exc_info=True)
            raise
    
    async def dequeue_job(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Dequeue highest priority auto-fix job"""
        
        redis_client = await self._get_redis_client()
        if redis_client is None:
            logger.warning("Redis client not available for dequeue")
            return None
        
        # Get highest priority job (lowest score)
        job_data = await redis_client.zpopmin(self.queue_key)
        
        if not job_data:
            return None
        
        job_json = job_data[0][0]
        job = json.loads(job_json)
        
        # Move to processing queue with timeout
        processing_data = {
            **job,
            "worker_id": worker_id,
            "started_at": utc_now_iso(),
            "status": AutofixJobStatus.PROCESSING.value
        }
        
        await redis_client.setex(
            f"{self.processing_key}:{job['id']}",
            self.job_timeout,
            json.dumps(processing_data)
        )
        
        # Update progress
        await self._update_progress(job['id'], 10, self.progress_stages[10])
        
        logger.info(f"Dequeued auto-fix job {job['id']} for worker {worker_id}")
        return job
    
    async def mark_job_completed(
        self, 
        job_id: str, 
        result: Dict[str, Any],
        db: Optional[AsyncSession] = None
    ):
        """Mark auto-fix job as completed"""
        
        redis_client = await self._get_redis_client()
        if redis_client:
            # Remove from processing queue
            await redis_client.delete(f"{self.processing_key}:{job_id}")
            
            # Store results (include scan_id from processing data if available)
            processing_data = await redis_client.get(f"{self.processing_key}:{job_id}")
            scan_id = None
            if processing_data:
                job_info = json.loads(processing_data)
                scan_id = job_info.get("scan_id")
                
            await redis_client.setex(
                f"{self.results_key}:{job_id}",
                86400,  # 24 hours
                json.dumps({
                    "status": AutofixJobStatus.COMPLETED.value,
                    "scan_id": scan_id,
                    "result": result,
                    "completed_at": utc_now_iso()
                })
            )
            
            # CRITICAL FIX: Final progress update with complete result data
            final_result = result.copy() if isinstance(result, dict) else {}
            
            # Ensure all essential data is in the progress store for rich frontend display
            final_result.update({
                "scan_id": scan_id,
                "job_id": job_id,
                "status": "success" if result.get("success", True) else "failed",
                "progress": 100,
                "message": result.get("message", self.progress_stages[100])
            })
            
            await self._update_progress(job_id, 100, self.progress_stages[100], final_result)
        
        if db:
            await self._update_autofix_job_status(
                job_id, AutofixJobStatus.COMPLETED.value, db, result=result
            )
        
        logger.info(f"Marked auto-fix job {job_id} as completed")
    
    async def mark_job_failed(
        self, 
        job_id: str, 
        error_message: str, 
        retry: bool = True,
        db: Optional[AsyncSession] = None
    ):
        """Mark auto-fix job as failed and optionally retry"""
        
        redis_client = await self._get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for mark_job_failed")
            return
            
        # Get job from processing queue
        processing_data = await redis_client.get(f"{self.processing_key}:{job_id}")
        
        if not processing_data:
            logger.warning(f"Auto-fix job {job_id} not found in processing queue")
            return
        
        job = json.loads(processing_data)
        
        # Remove from processing
        await redis_client.delete(f"{self.processing_key}:{job_id}")
        
        # Check if should retry
        if retry and job.get("retry_count", 0) < self.max_retries:
            job["retry_count"] = job.get("retry_count", 0) + 1
            job["last_error"] = error_message
            job["retry_at"] = (utc_now() + timedelta(minutes=5 * job["retry_count"])).isoformat()
            job["status"] = AutofixJobStatus.QUEUED.value
            
            # Re-queue with lower priority
            await redis_client.zadd(
                self.queue_key,
                {json.dumps(job): AutofixPriority.LOW.value}
            )
            
            # Reset progress
            await self._update_progress(
                job_id, 0, 
                f"Retrying auto-fix (attempt {job['retry_count']})..."
            )
            
            logger.info(f"Requeued auto-fix job {job_id} for retry {job['retry_count']}")
        else:
            # Move to failed queue
            await redis_client.lpush(self.failed_key, json.dumps({
                **job,
                "failed_at": utc_now_iso(),
                "error_message": error_message,
                "status": AutofixJobStatus.FAILED.value
            }))
            
            # Store failed result (include scan_id from job data)
            scan_id = job.get("scan_id")
            await redis_client.setex(
                f"{self.results_key}:{job_id}",
                86400,  # 24 hours
                json.dumps({
                    "status": AutofixJobStatus.FAILED.value,
                    "scan_id": scan_id,
                    "error_message": error_message,
                    "failed_at": utc_now_iso()
                })
            )
            
            # Update progress to failed state
            await self._update_progress(
                job_id, -1, 
                f"Auto-fix failed: {error_message[:100]}...", 
                {"error": error_message}
            )
            
            logger.error(f"Auto-fix job {job_id} failed permanently: {error_message}")
        
        if db:
            status = AutofixJobStatus.QUEUED.value if retry and job.get("retry_count", 0) < self.max_retries else AutofixJobStatus.FAILED.value
            await self._update_autofix_job_status(
                job_id, status, db, error_message=error_message
            )
    
    async def cancel_job(self, job_id: str, db: Optional[AsyncSession] = None) -> bool:
        """Cancel an auto-fix job"""
        
        redis_client = await self._get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for cancel_job")
            return False
        
        cancelled = False
        
        # Try to remove from queue
        queue_jobs = await redis_client.zrange(self.queue_key, 0, -1, withscores=True)
        for job_json, score in queue_jobs:
            job = json.loads(job_json)
            if job.get("id") == job_id:
                await redis_client.zrem(self.queue_key, job_json)
                cancelled = True
                break
        
        # Try to cancel processing job (limited cancellation)
        processing_data = await redis_client.get(f"{self.processing_key}:{job_id}")
        if processing_data:
            # Mark as cancelled (worker should check this)
            job = json.loads(processing_data)
            job["status"] = AutofixJobStatus.CANCELLED.value
            job["cancelled_at"] = utc_now_iso()
            
            await redis_client.setex(
                f"{self.processing_key}:{job_id}",
                self.job_timeout,
                json.dumps(job)
            )
            
            # Store cancelled result (include scan_id from job data)
            scan_id = job.get("scan_id")
            await redis_client.setex(
                f"{self.results_key}:{job_id}",
                86400,
                json.dumps({
                    "status": AutofixJobStatus.CANCELLED.value,
                    "scan_id": scan_id,
                    "cancelled_at": utc_now_iso()
                })
            )
            
            # Update progress
            await self._update_progress(job_id, -1, "Auto-fix cancelled by user")
            
            cancelled = True
        
        if db:
            await self._update_autofix_job_status(
                job_id, AutofixJobStatus.CANCELLED.value, db
            )
        
        if cancelled:
            logger.info(f"Cancelled auto-fix job {job_id}")
        
        return cancelled
    
    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get auto-fix job status and progress"""
        
        redis_client = await self._get_redis_client()
        if not redis_client:
            logger.warning("Redis client not available for get_job_status")
            return None
        
        # Check progress
        progress_data = await redis_client.get(f"{self.progress_key}:{job_id}")
        if progress_data:
            progress = json.loads(progress_data)
        else:
            progress = {"progress": 0, "message": "Initializing...", "updated_at": utc_now_iso()}
        
        # Check if job is in processing
        processing_data = await redis_client.get(f"{self.processing_key}:{job_id}")
        if processing_data:
            job = json.loads(processing_data)
            return {
                "job_id": job_id,
                "scan_id": job.get("scan_id"),
                "status": job.get("status", AutofixJobStatus.PROCESSING.value),
                "progress": progress.get("progress", 0),
                "message": progress.get("message", "Processing..."),
                "created_at": job.get("created_at"),
                "started_at": job.get("started_at"),
                "worker_id": job.get("worker_id"),
                "updated_at": progress.get("updated_at")
            }
        
        # Check results
        result_data = await redis_client.get(f"{self.results_key}:{job_id}")
        if result_data:
            result = json.loads(result_data)
            
            # For completed jobs, use the rich progress data if available
            if result.get("status") == AutofixJobStatus.COMPLETED.value and progress.get("progress") == 100:
                # Use the comprehensive progress data for completed jobs
                enhanced_result = result.get("result", {})
                
                # Merge progress data into result for rich frontend display
                if progress.get("pr_url"):
                    enhanced_result["pr_url"] = progress.get("pr_url")
                if progress.get("fixed_count") is not None:
                    enhanced_result["fixed_count"] = progress.get("fixed_count")
                if progress.get("fixed_files"):
                    enhanced_result["fixed_files"] = progress.get("fixed_files")
                if progress.get("issues_found") is not None:
                    enhanced_result["issues_found"] = progress.get("issues_found")
                if progress.get("metrics"):
                    enhanced_result["metrics"] = progress.get("metrics")
                if progress.get("message"):
                    enhanced_result["message"] = progress.get("message")
                
                return {
                    "job_id": job_id,
                    "scan_id": result.get("scan_id") or progress.get("scan_id"),
                    "status": result.get("status"),
                    "progress": progress.get("progress", 100),
                    "message": progress.get("message", "Auto-fix completed successfully!"),
                    "result": enhanced_result,
                    "error_message": result.get("error_message"),
                    "completed_at": result.get("completed_at"),
                    "failed_at": result.get("failed_at"),
                    "cancelled_at": result.get("cancelled_at"),
                    "updated_at": progress.get("updated_at")
                }
            else:
                # Standard result handling for non-completed or incomplete jobs
                return {
                    "job_id": job_id,
                    "scan_id": result.get("scan_id"),  # May not be available in results
                    "status": result.get("status"),
                    "progress": 100 if result.get("status") == AutofixJobStatus.COMPLETED.value else -1,
                    "message": progress.get("message", "Completed"),
                    "result": result.get("result"),
                    "error_message": result.get("error_message"),
                    "completed_at": result.get("completed_at"),
                    "failed_at": result.get("failed_at"),
                    "cancelled_at": result.get("cancelled_at"),
                    "updated_at": progress.get("updated_at")
                }
        
        # Check if job is queued
        queue_jobs = await redis_client.zrange(self.queue_key, 0, -1, withscores=True)
        for job_json, score in queue_jobs:
            job = json.loads(job_json)
            if job.get("id") == job_id:
                return {
                    "job_id": job_id,
                    "scan_id": job.get("scan_id"),
                    "status": AutofixJobStatus.QUEUED.value,
                    "progress": 0,
                    "message": "Waiting in queue...",
                    "created_at": job.get("created_at"),
                    "priority": score,
                    "queue_position": await self._get_queue_position(job_id),
                    "updated_at": utc_now_iso()
                }
        
        return None
    
    async def get_user_jobs(self, user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """Get auto-fix jobs for a user"""
        
        redis_client = await self._get_redis_client()
        if not redis_client:
            return []
        
        jobs = []
        
        # Get queued jobs
        queue_jobs = await redis_client.zrange(self.queue_key, 0, -1, withscores=True)
        for job_json, score in queue_jobs:
            job = json.loads(job_json)
            if job.get("user_id") == user_id:
                jobs.append({
                    "job_id": job["id"],
                    "scan_id": job.get("scan_id"),
                    "repo_full_name": job.get("repo_full_name"),
                    "status": AutofixJobStatus.QUEUED.value,
                    "priority": score,
                    "created_at": job.get("created_at"),
                    "queue_position": await self._get_queue_position(job["id"])
                })
        
        # Get processing jobs
        processing_keys = await redis_client.keys(f"{self.processing_key}:*")
        for key in processing_keys:
            job_data = await redis_client.get(key)
            if job_data:
                job = json.loads(job_data)
                if job.get("user_id") == user_id:
                    progress_data = await redis_client.get(f"{self.progress_key}:{job['id']}")
                    progress = json.loads(progress_data) if progress_data else {"progress": 0, "message": "Processing..."}
                    
                    jobs.append({
                        "job_id": job["id"],
                        "scan_id": job.get("scan_id"),
                        "repo_full_name": job.get("repo_full_name"),
                        "status": job.get("status", AutofixJobStatus.PROCESSING.value),
                        "progress": progress.get("progress", 0),
                        "message": progress.get("message", "Processing..."),
                        "created_at": job.get("created_at"),
                        "started_at": job.get("started_at"),
                        "worker_id": job.get("worker_id")
                    })
        
        # Get completed/failed jobs (recent ones)
        result_keys = await redis_client.keys(f"{self.results_key}:*")
        for key in result_keys:
            result_data = await redis_client.get(key)
            if result_data:
                result = json.loads(result_data)
                # We need to get the original job data to check user_id
                # This is a limitation of storing only results
                # In a production system, you might want to include user_id in results
                job_id = key.split(":")[-1]
                
                jobs.append({
                    "job_id": job_id,
                    "status": result.get("status"),
                    "result": result.get("result"),
                    "error_message": result.get("error_message"),
                    "completed_at": result.get("completed_at"),
                    "failed_at": result.get("failed_at"),
                    "cancelled_at": result.get("cancelled_at")
                })
        
        # Sort by created_at and limit
        jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jobs[:limit]
    
    async def get_queue_stats(self) -> Dict[str, int]:
        """Get auto-fix queue statistics"""
        
        redis_client = await self._get_redis_client()
        if redis_client is None:
            return {
                "queued": 0,
                "processing": 0,
                "failed": 0,
                "completed_today": 0
            }
        
        try:
            stats = {
                "queued": await redis_client.zcard(self.queue_key),
                "processing": len(await redis_client.keys(f"{self.processing_key}:*")),
                "failed": await redis_client.llen(self.failed_key),
                "completed_today": 0  # This would need additional tracking
            }
            return stats
        except Exception as e:
            logger.error(f"Redis queue stats error: {e}")
            return {
                "queued": 0,
                "processing": 0,
                "failed": 0,
                "completed_today": 0
            }
    
    async def cleanup_stale_jobs(self):
        """Clean up stale processing jobs"""
        
        redis_client = await self._get_redis_client()
        if redis_client is None:
            logger.warning("Redis client not available for cleanup_stale_jobs")
            return
            
        try:
            processing_keys = await redis_client.keys(f"{self.processing_key}:*")
            
            for key in processing_keys:
                job_data = await redis_client.get(key)
                if job_data:
                    job = json.loads(job_data)
                    started_at = ensure_utc_datetime(job.get("started_at"))
                    
                    # If job has been processing for more than timeout, mark as failed
                    if started_at and utc_now() - started_at > timedelta(seconds=self.job_timeout):
                        job_id = job.get("id")
                        await self.mark_job_failed(
                            job_id, 
                            "Auto-fix job timed out", 
                            retry=True
                        )
                        logger.warning(f"Cleaned up stale auto-fix job {job_id}")
        except Exception as e:
            logger.error(f"Error during stale auto-fix job cleanup: {e}")
    
    async def _update_progress(
        self, 
        job_id: str, 
        progress: int, 
        message: str, 
        extra_data: Optional[Dict[str, Any]] = None
    ):
        """Update job progress in Redis"""
        
        redis_client = await self._get_redis_client()
        if not redis_client:
            return
        
        progress_data = {
            "progress": progress,
            "message": message,
            "updated_at": utc_now_iso()
        }
        
        if extra_data:
            progress_data.update(extra_data)
        
        await redis_client.setex(
            f"{self.progress_key}:{job_id}",
            86400,  # 24 hours
            json.dumps(progress_data)
        )
        
        logger.debug(f"Updated progress for job {job_id}: {progress}% - {message}")
    
    async def update_job_progress(
        self, 
        job_id: str, 
        progress: int, 
        message: Optional[str] = None
    ):
        """Public method to update job progress"""
        if message is None:
            message = self.progress_stages.get(progress, f"Progress: {progress}%")
        
        await self._update_progress(job_id, progress, message)
    
    async def _get_queue_position(self, job_id: str) -> int:
        """Get position of job in queue"""
        
        redis_client = await self._get_redis_client()
        if not redis_client:
            return 0
        
        queue_jobs = await redis_client.zrange(self.queue_key, 0, -1)
        for i, job_json in enumerate(queue_jobs):
            job = json.loads(job_json)
            if job.get("id") == job_id:
                return i + 1
        
        return 0
    
    async def _store_autofix_job_in_db(self, job_data: Dict[str, Any], db: AsyncSession):
        """Store auto-fix job in database for persistence"""
        try:
            # Reuse ScanJob table with autofix-specific data
            db_job = {
                "id": job_data["id"],
                "repo_full_name": job_data["repo_full_name"],
                "scan_type": "autofix",  # Use scan_type to distinguish auto-fix jobs
                "priority": job_data["priority"],
                "job_data": job_data,
                "status": job_data["status"]
            }
            
            stmt = insert(ScanJob).values(**db_job)
            await db.execute(stmt)
            await db.commit()
            
        except Exception as e:
            logger.error(f"Failed to store auto-fix job in database: {e}", exc_info=True)
            await db.rollback()
    
    async def _update_autofix_job_status(
        self, 
        job_id: str, 
        status: str, 
        db: AsyncSession,
        error_message: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None
    ):
        """Update auto-fix job status in database"""
        try:
            update_data = {"status": status}
            
            if status == AutofixJobStatus.COMPLETED.value:
                update_data["completed_at"] = utc_now()
                if result:
                    # Store result in job_data
                    current_job = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
                    job_record = current_job.scalar_one_or_none()
                    if job_record and job_record.job_data:
                        job_record.job_data["result"] = result
                        update_data["job_data"] = job_record.job_data
                        
            elif status == AutofixJobStatus.FAILED.value and error_message:
                update_data["error_message"] = error_message
                update_data["completed_at"] = utc_now()
                
            elif status == AutofixJobStatus.PROCESSING.value:
                update_data["started_at"] = utc_now()
                
            elif status == AutofixJobStatus.CANCELLED.value:
                update_data["completed_at"] = utc_now()
            
            await db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(**update_data)
            )
            await db.commit()
            
        except Exception as e:
            logger.error(f"Failed to update auto-fix job status: {e}", exc_info=True)
            await db.rollback()