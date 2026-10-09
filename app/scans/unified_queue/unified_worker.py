"""
UNIFIED SCAN WORKER - THE FORTRESS GUARD

This is the ONE AND ONLY worker system that processes ALL job types.
No subscriptions, no pub/sub, no complex event-driven architecture.
Just direct Redis polling with immediate job pickup.

Architecture:
- Direct Redis polling every 1-2 seconds
- Single worker handles all scan types (manual, PR, push, scheduled)
- No subscription failures or channel mismatches
- Immediate job processing (1-2 second pickup time)
- Rock-solid reliability

SUCCESS CRITERIA:
- Jobs processed within 1-2 seconds of being queued
- No worker subscription failures
- No "Waiting in queue" status
- Simple, reliable, fortress-like operation
"""

import asyncio
import json
import logging
import os
import time
import signal
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from fastapi import HTTPException
from github import GithubException

from core.database import get_db
from .unified_queue_manager import get_unified_queue_manager, UnifiedScanJob, UnifiedJobStatus
from scans.scanner_engine import ScannerEngine
from scans.ai.smart_explainer import SmartAIExplainer
from scans.integrations.github_integration import GitHubIntegration
from scans.models import Scan, ScanSummary
from auth.dependencies import decrypt_token

# Import all models to ensure proper SQLAlchemy relationship resolution
import auth.models  # noqa: F401
import support.models  # noqa: F401
import ai_assistant.models  # noqa: F401
import cli_scan.models  # noqa: F401
from core.issue_tracking import IssueTrackingService
from core.redis import get_redis_client

logger = logging.getLogger(__name__)


class UnifiedScanWorker:
    """
    THE FORTRESS GUARD: Single worker system that handles everything.
    
    No complex subscriptions, no event-driven complexity, no fragmentation.
    Just simple, direct polling with immediate job processing.
    """
    
    def __init__(self, worker_id: str, openai_api_key: str):
        self.worker_id = worker_id
        self.queue_manager = None  # Will be initialized in start()
        self.scanner_engine = ScannerEngine()
        self.ai_explainer = SmartAIExplainer(openai_api_key)
        self.github_integration = GitHubIntegration()
        
        # Simple configuration
        self.running = False
        self.poll_interval = float(os.getenv("UNIFIED_WORKER_POLL_INTERVAL", "1.5"))  # 1.5 seconds
        self.enable_ai_during_scan = os.getenv("ENABLE_AI_DURING_SCAN", "false").lower() == "true"
        
        # Worker state
        self._stop_event = asyncio.Event()
        self._processing_task = None
        
        # CRITICAL FIX: Health monitoring integration
        self._health_monitor = None
        self._last_heartbeat = time.time()
        self._heartbeat_interval = 30  # 30 seconds
        self._heartbeat_task = None
        self._jobs_processed_count = 0
        
        # CRITICAL FIX: Signal handler for graceful shutdown
        self._shutdown_handler = None
        
        # CRITICAL FIX: Memory management for long-running workers
        self._memory_manager = None
        
        logger.info(f"🏰 FORTRESS GUARD: Worker {worker_id} initialized (poll: {self.poll_interval}s)")
    
    async def start(self):
        """Start the fortress guard - simple and reliable"""
        if self.running:
            logger.warning(f"Worker {self.worker_id} already running")
            return
        
        logger.info(f"🚀 FORTRESS GUARD: Starting worker {self.worker_id}")
        
        try:
            # CRITICAL FIX: Setup signal handlers for graceful shutdown
            from core.signal_handlers import get_global_shutdown_handler
            self._shutdown_handler = get_global_shutdown_handler(f"unified_worker_{self.worker_id}")
            self._shutdown_handler.add_cleanup_callback(self._cleanup_on_shutdown)
            
            # CRITICAL FIX: Setup memory management for production stability
            from core.memory_management import get_memory_manager
            self._memory_manager = get_memory_manager(f"unified_worker_{self.worker_id}")
            self._memory_manager.add_cleanup_callback(self._memory_cleanup_callback)
            await self._memory_manager.start_monitoring()
            
            # Initialize queue manager
            self.queue_manager = await get_unified_queue_manager()
            
            # Start processing
            self.running = True
            self._processing_task = asyncio.create_task(self._processing_loop())
            
            # Register with health monitor
            await self._register_with_health_monitor()
            
            # Start heartbeat
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            logger.info(f"✅ FORTRESS GUARD: Worker {self.worker_id} started and ready to guard the fortress")
            
        except Exception as e:
            logger.error(f"❌ FORTRESS GUARD: Failed to start worker {self.worker_id}: {e}")
            self.running = False
            raise
    
    async def stop(self):
        """Stop the fortress guard gracefully"""
        if not self.running:
            return
        
        logger.info(f"🛑 FORTRESS GUARD: Stopping worker {self.worker_id}")
        
        self.running = False
        self._stop_event.set()
        
        # Cancel processing task
        if self._processing_task:
            self._processing_task.cancel()
            try:
                await self._processing_task
            except asyncio.CancelledError:
                pass
        
        # Stop heartbeat
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        # Unregister from health monitor
        await self._unregister_from_health_monitor()
        
        # CRITICAL FIX: Stop memory monitoring
        if self._memory_manager:
            try:
                await self._memory_manager.stop_monitoring()
                logger.info(f"🧹 FORTRESS GUARD: Memory monitoring stopped for worker {self.worker_id}")
            except Exception as e:
                logger.warning(f"Error stopping memory monitoring for worker {self.worker_id}: {e}")
        
        logger.info(f"✅ FORTRESS GUARD: Worker {self.worker_id} stopped")
    
    async def _processing_loop(self):
        """
        THE FORTRESS GUARD PATROL: Simple, direct polling.
        No subscriptions, no events, no complexity - just reliable job processing.
        """
        logger.info(f"🔄 FORTRESS GUARD: Worker {self.worker_id} starting patrol (poll every {self.poll_interval}s)")
        
        consecutive_no_jobs = 0
        max_no_jobs_before_backoff = 5
        backoff_multiplier = 1.2
        max_poll_interval = 10.0
        
        while self.running:
            try:
                # CRITICAL FIX: Check for shutdown signal
                if self._shutdown_handler and self._shutdown_handler.is_shutdown_requested():
                    logger.info(f"🛑 FORTRESS GUARD: Worker {self.worker_id} received shutdown signal")
                    break
                
                # Direct job polling - no subscriptions needed
                job = await self.queue_manager.get_next_job(self.worker_id)
                
                if job:
                    # Reset polling interval on job found
                    consecutive_no_jobs = 0
                    current_poll_interval = self.poll_interval
                    
                    logger.info(f"⚡ FORTRESS GUARD: Worker {self.worker_id} found job {job.id} - processing immediately")
                    
                    # Process job immediately
                    await self._process_job(job)
                    
                else:
                    # No job available - implement adaptive backoff
                    consecutive_no_jobs += 1
                    
                    if consecutive_no_jobs >= max_no_jobs_before_backoff:
                        # Gradually increase polling interval to reduce Redis load
                        current_poll_interval = min(
                            self.poll_interval * (backoff_multiplier ** (consecutive_no_jobs - max_no_jobs_before_backoff)),
                            max_poll_interval
                        )
                    else:
                        current_poll_interval = self.poll_interval
                    
                    # Only log occasionally to reduce noise
                    if consecutive_no_jobs <= 3 or consecutive_no_jobs % 10 == 0:
                        logger.debug(f"🔍 FORTRESS GUARD: Worker {self.worker_id} patrol complete - no jobs (sleeping {current_poll_interval:.1f}s)")
                    
                    # Sleep with current interval but check for shutdown periodically
                    sleep_time = min(current_poll_interval, 5.0)  # Check shutdown every 5 seconds max
                    await asyncio.sleep(sleep_time)
                
                # Check for stop signal
                if self._stop_event.is_set():
                    break
                    
            except Exception as e:
                logger.error(f"❌ FORTRESS GUARD: Worker {self.worker_id} patrol error: {e}")
                await asyncio.sleep(5)  # Brief error recovery delay
        
        logger.info(f"🏁 FORTRESS GUARD: Worker {self.worker_id} patrol ended")
    
    
    async def _process_job(self, job: UnifiedScanJob):
        """Process any job type - unified handling"""
        logger.info(f"🎯 FORTRESS GUARD: Processing {job.scan_type} job {job.id} for {job.repo_full_name}")
        
        # CRITICAL FIX: Use proper session context manager for automatic transaction management
        from core.database import get_db_session, DatabaseOperation
        
        try:
            async with get_db_session(DatabaseOperation.WRITE) as db:
                await self._process_job_with_db(job, db)
                # Session will be committed explicitly in _process_job_with_db
        except Exception as e:
            logger.error(f"❌ FORTRESS GUARD: Job {job.id} failed: {e}")
            await self.queue_manager.mark_job_failed(job.id, str(e), retry=True)
            raise
    
    async def _process_job_with_db(self, job: UnifiedScanJob, db: AsyncSession):
        """Process job with guaranteed database session"""        
        try:
            
            # Route to appropriate processor and capture scan_id
            scan_id = None
            if job.scan_type == "manual":
                scan_id = await self._process_manual_scan(job, db)
            elif job.scan_type == "pr_scan":
                scan_id = await self._process_pr_scan(job, db)
            elif job.scan_type == "push_scan":
                scan_id = await self._process_push_scan(job, db)
            elif job.scan_type == "scheduled":
                scan_id = await self._process_scheduled_scan(job, db)
            else:
                raise ValueError(f"Unknown scan type: {job.scan_type}")
            
            # CRITICAL FIX: Flush to ensure scan data is visible and commit in same session
            await db.flush()
            logger.info(f"🔄 FORTRESS GUARD: Scan {scan_id} flushed to database")
            
            # CRITICAL: Mark job as completed with scan_id link using the SAME session
            # This ensures atomicity and avoids transaction isolation issues
            logger.info(f"🔗 FORTRESS GUARD: Job {job.id} completed, linking to scan {scan_id}")
            await self.queue_manager.mark_job_completed(job.id, scan_id=scan_id, db_session=db)
            logger.info(f"✅ FORTRESS GUARD: Job {job.id} completed and linked to scan {scan_id} in database")
            
            # CRITICAL FIX: Commit the entire transaction (scan + job update) atomically
            await db.commit()
            logger.info(f"💾 FORTRESS GUARD: Transaction committed - Scan {scan_id} and Job {job.id} persisted")
            
        except Exception as e:
            # Error handling moved to _process_job method
            raise
    
    async def _process_manual_scan(self, job: UnifiedScanJob, db: AsyncSession):
        """Process manual scan with progress tracking"""
        scan_config = job.scan_config
        
        # Update progress
        await self._update_progress(job.id, 10, "Starting manual scan")
        
        # Run comprehensive scan
        scan_result = await self.scanner_engine.run_comprehensive_scan(
            repo_full_name=job.repo_full_name,
            branch=scan_config.get("branch", "main"),
            scope=scan_config.get("scope", "code+deps"),
            mode=scan_config.get("mode", "fast"),
            niche=scan_config.get("niche"),
            gh_token=scan_config.get("gh_token"),
            scan_type="manual",
            user_id=job.user_id,
            db_session=db,
            include_custom_rules=scan_config.get("include_custom_rules", False),
            include_community_rules=scan_config.get("include_community_rules", False),
            selected_custom_rule_ids=scan_config.get("selected_custom_rule_ids", []),
            selected_community_rule_ids=scan_config.get("selected_community_rule_ids", []),
            progress_callback=lambda p, s, t, *args: asyncio.create_task(
                self._update_progress(job.id, 10 + int(p * 70), s)
            )
        )
        
        # Update progress
        await self._update_progress(job.id, 80, "Storing scan results")
        
        # Store scan results
        scan_id = await self._store_scan_results(
            scan_result, job.user_id, job.repo_full_name, db, scan_config.get("niche", "general")
        )
        
        # AI analysis if enabled
        if self.enable_ai_during_scan and scan_result.get("issues"):
            await self._update_progress(job.id, 90, "AI analysis")
            await self.ai_explainer.explain_issues_batch(
                scan_result["issues"], db, include_code_context=True
            )
        
        # Complete
        await self._update_progress(job.id, 100, "Manual scan completed")
        
        # CRITICAL: Return scan_id for database linking
        logger.info(f"📋 FORTRESS GUARD: Scan completed with scan_id: {scan_id}")
        
        # CRITICAL FIX: Update job processing count for health monitoring
        self._jobs_processed_count += 1
        
        return scan_id
    
    async def _process_pr_scan(self, job: UnifiedScanJob, db: AsyncSession):
        """Process PR scan with GitHub integration"""
        scan_config = job.scan_config
        
        pr_number = scan_config["pr_number"]
        commit_sha = scan_config["commit_sha"]
        branch = scan_config["branch"]
        gh_token = scan_config["gh_token"]
        
        # Update progress
        await self._update_progress(job.id, 10, "Starting PR scan")
        
        # Update GitHub status
        await self.github_integration.update_check_run(
            job.repo_full_name, commit_sha, "pending", gh_token
        )
        
        # Run focused scan for PR
        scan_result = await self.scanner_engine.run_comprehensive_scan(
            repo_full_name=job.repo_full_name,
            branch=branch,
            scope=scan_config.get("scope", "code+deps"),
            mode=scan_config.get("mode", "fast"),
            niche=scan_config.get("niche"),
            gh_token=gh_token,
            scan_type="pr",
            pr_number=pr_number,
            commit_sha=commit_sha,
            file_list=scan_config.get("file_list"),
            user_id=job.user_id,
            db_session=db,
            include_custom_rules=scan_config.get("include_custom_rules", False),
            include_community_rules=scan_config.get("include_community_rules", False),
            selected_custom_rule_ids=scan_config.get("selected_custom_rule_ids", []),
            selected_community_rule_ids=scan_config.get("selected_community_rule_ids", []),
            progress_callback=lambda p, s, t, *args: asyncio.create_task(
                self._update_progress(job.id, 10 + int(p * 60), s)
            )
        )
        
        # Store results
        await self._update_progress(job.id, 70, "Storing results")
        scan_id = await self._store_scan_results(
            scan_result, job.user_id, job.repo_full_name, db, scan_config.get("niche", "general")
        )
        
        # Update GitHub with results
        await self._update_progress(job.id, 90, "Updating GitHub")
        conclusion = self._determine_pr_conclusion(scan_result)
        await self.github_integration.update_check_run(
            job.repo_full_name, commit_sha, "completed", gh_token,
            conclusion=conclusion, scan_result=scan_result, scan_id=scan_id
        )
        
        # Create PR review
        try:
            review_result = await self.github_integration.create_pr_review(
                repo_full_name=job.repo_full_name,
                pr_number=pr_number,
                scan_result=scan_result,
                gh_token=gh_token,
                scan_id=scan_id
            )
            logger.info(f"Created PR review with {review_result['inline_comments_count']} comments")
        except Exception as e:
            logger.error(f"Failed to create PR review: {e}")
            # Fallback to comment
            await self.github_integration.post_pr_comment_async(
                job.repo_full_name, pr_number, scan_result, gh_token, scan_id
            )
        
        await self._update_progress(job.id, 100, "PR scan completed")
        
        # CRITICAL: Return scan_id for database linking
        logger.info(f"📋 FORTRESS GUARD: Scan completed with scan_id: {scan_id}")
        return scan_id
    
    async def _process_push_scan(self, job: UnifiedScanJob, db: AsyncSession):
        """Process push scan for main branches"""
        scan_config = job.scan_config
        
        await self._update_progress(job.id, 10, "Starting push scan")
        
        # Run full scan for push
        scan_result = await self.scanner_engine.run_comprehensive_scan(
            repo_full_name=job.repo_full_name,
            branch=scan_config["branch"],
            scope="full",
            mode="fast",
            niche=scan_config.get("niche"),
            gh_token=scan_config["gh_token"],
            scan_type="push",
            commit_sha=scan_config.get("commit_sha"),
            user_id=job.user_id,
            db_session=db,
            include_custom_rules=scan_config.get("include_custom_rules", False),
            include_community_rules=scan_config.get("include_community_rules", False),
            selected_custom_rule_ids=scan_config.get("selected_custom_rule_ids", []),
            selected_community_rule_ids=scan_config.get("selected_community_rule_ids", []),
            progress_callback=lambda p, s, t, *args: asyncio.create_task(
                self._update_progress(job.id, 10 + int(p * 80), s)
            )
        )
        
        # Store results
        await self._update_progress(job.id, 90, "Storing results")
        scan_id = await self._store_scan_results(
            scan_result, job.user_id, job.repo_full_name, db, scan_config.get("niche", "general")
        )
        
        await self._update_progress(job.id, 100, "Push scan completed")
        
        # CRITICAL: Return scan_id for database linking
        logger.info(f"📋 FORTRESS GUARD: Scan completed with scan_id: {scan_id}")
        return scan_id
    
    async def _process_scheduled_scan(self, job: UnifiedScanJob, db: AsyncSession):
        """Process scheduled scan"""
        # Similar to manual scan but with scheduled context
        scan_id = await self._process_manual_scan(job, db)
        
        # CRITICAL: Return scan_id for database linking
        logger.info(f"📋 FORTRESS GUARD: Scan completed with scan_id: {scan_id}")
        return scan_id
    
    async def _store_scan_results(
        self, scan_result: dict, user_id: int, repo_full_name: str, 
        db: AsyncSession, niche: str = "general"
    ) -> str:
        """Store scan results in database"""
        metadata = scan_result.get("metadata", {})
        scores = scan_result.get("scores", {})
        
        try:
            # Create main scan record
            # Fix Python truthiness bug: Use 'is None' check instead of 'or' to avoid losing 0 values and empty lists
            scan_duration = scan_result.get("scan_duration")
            if scan_duration is None:
                scan_duration = metadata.get("scan_duration", 0)
            
            tools_used = scan_result.get("tools_used")
            if tools_used is None:
                tools_used = metadata.get("tools_used", [])
            
            scan_data = {
                "repo_full_name": repo_full_name,
                "user_id": user_id,
                "branch": metadata.get("branch", "main"),
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
                "scan_duration": int(scan_duration),
                "tools_used": tools_used,
                "status": "completed",
                "started_at": datetime.now(timezone.utc),
                "completed_at": datetime.now(timezone.utc)
            }
            
            # Insert scan
            stmt = insert(Scan).values(**scan_data).returning(Scan.id)
            result = await db.execute(stmt)
            scan_id = result.scalar_one()
            
            # Create scan summaries
            summaries = self._create_scan_summaries(scan_result.get("issues", []), scan_id)
            if summaries:
                stmt = insert(ScanSummary).values(summaries)
                await db.execute(stmt)
            
            # Transaction will be committed by the caller (_process_job_with_db)
            logger.info(f"💾 Scan results prepared with ID {scan_id} (pending commit)")
            
            # Temporarily disable issue tracking for PR scans to test scan persistence
            logger.info(f"🚧 Issue tracking temporarily disabled for scan {scan_id} to test scan persistence")
            
            return scan_id
            
        except Exception as e:
            logger.error(f"❌ Error storing scan results: {e}")
            # Don't rollback here - let the caller's context manager handle transaction management
            raise
    
    def _create_scan_summaries(self, issues: list, scan_id: str) -> list:
        """Create scan summaries grouped by category and tool"""
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
            
            # Count by severity
            if severity == "critical":
                summaries[key]["critical_count"] += 1
            elif severity == "high":
                summaries[key]["high_count"] += 1
            elif severity == "medium":
                summaries[key]["medium_count"] += 1
            else:
                summaries[key]["low_count"] += 1
            
            summaries[key]["total_issues"] += 1
            
            # Add sample issue
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
                "code_context": issue.get("code_context")
            }
            summaries[key]["sample_issues"].append(sample_issue)
        
        return list(summaries.values())
    
    def _determine_pr_conclusion(self, scan_result: dict) -> str:
        """Determine GitHub check conclusion"""
        issues = scan_result.get("issues", [])
        scores = scan_result.get("scores", {})
        total_score = scores.get("total_score", 100)
        
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
    
    async def _update_progress(self, job_id: str, progress_percent: int, stage: str):
        """Update job progress in Redis"""
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return
            
            progress_data = {
                "progress": f"{progress_percent}%",
                "stage": stage,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "worker_id": self.worker_id
            }
            
            await redis_client.setex(
                f"unified_scan_progress:{job_id}",
                3600,  # 1 hour TTL
                json.dumps(progress_data)
            )
            
            logger.info(f"📊 Progress {job_id}: {progress_percent}% - {stage}")
            
        except Exception as e:
            logger.warning(f"Failed to update progress for {job_id}: {e}")
    
    async def _register_with_health_monitor(self):
        """CRITICAL FIX: Register worker with health monitoring system"""
        try:
            from core.worker_health_monitor import get_worker_health_monitor, WorkerState
            self._health_monitor = await get_worker_health_monitor()
            await self._health_monitor.register_worker(
                self.worker_id, 
                "unified_worker", 
                WorkerState.ACTIVE
            )
            logger.info(f"Unified worker {self.worker_id} registered with health monitor")
        except Exception as e:
            logger.warning(f"Failed to register with health monitor: {e}")
            self._health_monitor = None
    
    async def _unregister_from_health_monitor(self):
        """CRITICAL FIX: Unregister worker from health monitoring system"""
        if self._health_monitor:
            try:
                await self._health_monitor.unregister_worker(self.worker_id)
                logger.info(f"Unified worker {self.worker_id} unregistered from health monitor")
            except Exception as e:
                logger.warning(f"Failed to unregister from health monitor: {e}")
    
    async def _heartbeat_loop(self):
        """CRITICAL FIX: Send periodic heartbeats to health monitor"""
        while self.running:
            try:
                if self._health_monitor:
                    # Get job metrics
                    job_metrics = {
                        "jobs_processed": self._jobs_processed_count,
                        "jobs_failed": 0,  # Would need to track failures separately
                        "last_job_timestamp": time.time() if self._jobs_processed_count > 0 else None
                    }
                    
                    # Get basic resource metrics
                    try:
                        import psutil
                        import os
                        process = psutil.Process(os.getpid())
                        memory_info = process.memory_info()
                        resource_metrics = {
                            "memory_mb": round(memory_info.rss / 1024 / 1024, 2),
                            "cpu_percent": process.cpu_percent()
                        }
                    except ImportError:
                        resource_metrics = {"memory_mb": 0, "cpu_percent": 0}
                    except Exception:
                        resource_metrics = {"memory_mb": 0, "cpu_percent": 0}
                    
                    # Send heartbeat
                    from core.worker_health_monitor import WorkerState
                    worker_state = WorkerState.ACTIVE if self.running else WorkerState.STOPPING
                    
                    await self._health_monitor.update_worker_heartbeat(
                        self.worker_id,
                        worker_state,
                        job_metrics,
                        resource_metrics
                    )
                
                await asyncio.sleep(self._heartbeat_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Error in heartbeat loop for unified worker {self.worker_id}: {e}")
                await asyncio.sleep(self._heartbeat_interval)
    
    async def report_error_to_health_monitor(self, error_message: str):
        """CRITICAL FIX: Report error to health monitoring system"""
        if self._health_monitor:
            try:
                await self._health_monitor.report_worker_error(self.worker_id, error_message)
            except Exception as e:
                logger.warning(f"Failed to report error to health monitor: {e}")
    
    async def _cleanup_on_shutdown(self):
        """CRITICAL FIX: Cleanup callback for graceful shutdown"""
        try:
            logger.info(f"🧹 FORTRESS GUARD: Starting cleanup for worker {self.worker_id}")
            
            # Stop the worker gracefully
            await self.stop()
            
            logger.info(f"✅ FORTRESS GUARD: Cleanup completed for worker {self.worker_id}")
            
        except Exception as e:
            logger.error(f"❌ FORTRESS GUARD: Error during cleanup for worker {self.worker_id}: {e}")
    
    async def _memory_cleanup_callback(self):
        """CRITICAL FIX: Memory cleanup callback for resource management"""
        try:
            logger.info(f"🧹 FORTRESS GUARD: Starting memory cleanup for worker {self.worker_id}")
            
            # Clear any cached scan results
            if hasattr(self, '_cached_results'):
                self._cached_results.clear()
            
            # Force garbage collection on scanner engine if available
            if hasattr(self.scanner_engine, 'cleanup'):
                await self.scanner_engine.cleanup()
            
            # Clear AI explainer cache
            if hasattr(self.ai_explainer, 'clear_cache'):
                await self.ai_explainer.clear_cache()
            
            # Clear GitHub integration cache
            if hasattr(self.github_integration, 'clear_cache'):
                self.github_integration.clear_cache()
            
            logger.info(f"✅ FORTRESS GUARD: Memory cleanup completed for worker {self.worker_id}")
            
        except Exception as e:
            logger.warning(f"Error during memory cleanup for worker {self.worker_id}: {e}")


# Global worker instance management
_active_workers = {}


async def start_unified_worker(worker_id: str, openai_api_key: str) -> UnifiedScanWorker:
    """Start a unified worker"""
    if worker_id in _active_workers:
        logger.warning(f"Worker {worker_id} already active")
        return _active_workers[worker_id]
    
    worker = UnifiedScanWorker(worker_id, openai_api_key)
    await worker.start()
    _active_workers[worker_id] = worker
    
    logger.info(f"🏰 FORTRESS: Started worker {worker_id}")
    return worker


async def stop_unified_worker(worker_id: str):
    """Stop a unified worker"""
    if worker_id in _active_workers:
        worker = _active_workers[worker_id]
        await worker.stop()
        del _active_workers[worker_id]
        logger.info(f"🏰 FORTRESS: Stopped worker {worker_id}")


async def stop_all_unified_workers():
    """Stop all unified workers"""
    worker_ids = list(_active_workers.keys())
    for worker_id in worker_ids:
        await stop_unified_worker(worker_id)
    logger.info("🏰 FORTRESS: All workers stopped")