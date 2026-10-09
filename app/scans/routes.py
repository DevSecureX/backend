from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, UploadFile, File
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, func, and_, text
from typing import List, Dict, Optional, Any, Literal
from enum import Enum
import uuid
import json
import logging
from datetime import datetime, timedelta, timezone
from core.utils import utc_now, utc_now_iso, format_datetime_response
from core.circuit_breaker import (
    get_polling_circuit_breaker, 
    CircuitBreakerConfig, 
    ExponentialBackoff, 
    with_exponential_backoff,
    PollingLimitExceeded,
    CircuitBreakerOpenError
)
import asyncio
import os
import tempfile
import zipfile
import shutil
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
import io

from core.database import get_db
# Import redis_client lazily to avoid production connections
from core.cache import cache, ScanCache, RepoCache, RateLimitCache, cached
from auth.dependencies import get_current_user, decrypt_token
from auth.models import User
from repos.models import Repo
from .models import Scan, ScanSummary, ScanJob, AIPatternCache, IssueFeedback, ComplianceMapping, PRSecurityComment, PRSecurityReview
# FORTRESS: Import the unified queue system - no more fragmentation!
from scans.unified_queue import get_unified_queue_manager, UnifiedJobPriority
from scans.ai.smart_explainer import SmartAIExplainer
from .webhooks.routes import webhooks_router
import os
from .pr_scanning.pr_fetcher import PRFetcher
from .pr_scanning.diff_analyzer import PRDiffAnalyzer

logger = logging.getLogger(__name__)

# Utility function for safe bulk deletion with progress tracking
async def safe_bulk_delete(db: AsyncSession, scan_ids: List[str], user_id: int) -> Dict[str, int]:
    """Safely delete multiple scans with proper FK handling and progress tracking"""
    
    if not scan_ids:
        return {"deleted_scans": 0, "deleted_summaries": 0, "deleted_dependencies": 0}
    
    logger.info(f"Starting bulk deletion of {len(scan_ids)} scans for user {user_id}")
    
    # Process in chunks to avoid overwhelming the database
    chunk_size = 50
    total_deleted = {"scans": 0, "summaries": 0, "dependencies": 0}
    
    for i in range(0, len(scan_ids), chunk_size):
        chunk = scan_ids[i:i + chunk_size]
        
        # Delete all scan-dependent records first  
        dep_result = await db.execute(delete(IssueFeedback).where(IssueFeedback.scan_id.in_(chunk)))
        total_deleted["dependencies"] += dep_result.rowcount
        
        dep_result = await db.execute(delete(ComplianceMapping).where(ComplianceMapping.scan_id.in_(chunk)))
        total_deleted["dependencies"] += dep_result.rowcount
        
        dep_result = await db.execute(delete(PRSecurityComment).where(PRSecurityComment.scan_id.in_(chunk)))
        total_deleted["dependencies"] += dep_result.rowcount
        
        dep_result = await db.execute(delete(PRSecurityReview).where(PRSecurityReview.scan_id.in_(chunk)))
        total_deleted["dependencies"] += dep_result.rowcount
        
        # Delete scan summaries
        summary_result = await db.execute(delete(ScanSummary).where(ScanSummary.scan_id.in_(chunk)))
        total_deleted["summaries"] += summary_result.rowcount
        
        # Set scan_id to NULL in ScanJob (follows FK constraint)
        await db.execute(
            update(ScanJob)
            .where(ScanJob.scan_id.in_(chunk))
            .values(scan_id=None, status="orphaned")
        )
        
        # Delete the scans themselves
        scan_result = await db.execute(delete(Scan).where(Scan.id.in_(chunk)))
        total_deleted["scans"] += scan_result.rowcount
        
        # Commit the changes for this chunk
        await db.commit()
        
        logger.info(f"Processed chunk {i//chunk_size + 1}/{(len(scan_ids) + chunk_size - 1)//chunk_size}")
    
    logger.info(f"Bulk deletion complete: {total_deleted}")
    return total_deleted

# Initialize components
scans_router = APIRouter(prefix="/scans", tags=["scans"])
# FORTRESS: Use only the unified queue system - no more fragmentation!
ai_explainer = SmartAIExplainer(os.getenv("OPENAI_API_KEY"))
pr_fetcher = PRFetcher()
diff_analyzer = PRDiffAnalyzer()

async def enqueue_scan_fortress(
    repo_full_name: str,
    scan_type: str,
    scan_config: Dict[str, Any],
    priority: str = "NORMAL",
    user_id: int = None,
    db: AsyncSession = None
) -> str:
    """
    🏰 FORTRESS: Single unified enqueue method - no more fragmentation!
    
    This is the ONE AND ONLY way to queue scans. No fallbacks, no complexity,
    no fighting systems. Just fortress-like reliability.
    """
    try:
        # Get the unified queue manager
        queue_manager = await get_unified_queue_manager()
        
        # Map priority to unified system
        priority_mapping = {
            "URGENT": UnifiedJobPriority.URGENT,
            "HIGH": UnifiedJobPriority.HIGH,
            "NORMAL": UnifiedJobPriority.NORMAL,
            "LOW": UnifiedJobPriority.LOW
        }
        
        unified_priority = priority_mapping.get(priority, UnifiedJobPriority.NORMAL)
        
        # Single enqueue call - no fallbacks, no complexity
        job_id = await queue_manager.enqueue_scan(
            repo_full_name=repo_full_name,
            user_id=user_id,
            scan_type=scan_type,
            scan_config=scan_config,
            priority=unified_priority
        )
        
        logger.info(f"🏰 FORTRESS: Scan {job_id} queued for {repo_full_name} (priority: {priority})")
        return job_id
        
    except Exception as e:
        logger.error(f"❌ FORTRESS: Failed to enqueue scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to queue scan: {str(e)}"
        )

# Include webhook routes
scans_router.include_router(webhooks_router)

# Include event-driven system monitoring routes
from .event_driven.routes import router as event_router
scans_router.include_router(event_router)

# Rate limiting constants
RATE_LIMIT_KEY_PREFIX = "rate:scans:"
RATE_LIMIT_MAX = 50  # 50 scans per hour per user
RATE_LIMIT_TTL = 3600
SCAN_CACHE_TTL = 3600

# Pydantic Models
class ScanMode(str, Enum):
    FAST = "fast"  # Note: Both modes now run all tools for maximum security coverage
    COMPREHENSIVE = "comprehensive"

class ScanScope(str, Enum):
    CODE_ONLY = "code-only"
    DEPS = "deps"
    CODE_DEPS = "code+deps"
    FULL = "full"

class ScanRequest(BaseModel):
    """Request model for triggering security scans
    
    MAXIMUM SECURITY COVERAGE: All scans now run with comprehensive mode and full scope
    to ensure complete A-to-Z security analysis with ALL available tools.
    
    Frontend parameters are accepted but internally overridden to guarantee maximum coverage:
    - mode: Always forced to 'comprehensive' 
    - scope: Always forced to 'full' (code + dependencies + infrastructure)
    """
    repo_full_name: str
    mode: Optional[ScanMode] = ScanMode.COMPREHENSIVE  # Frontend compatibility - always overridden to comprehensive
    scope: Optional[ScanScope] = ScanScope.FULL  # Frontend compatibility - always overridden to full
    branch: str = ""
    include_custom_rules: bool = False
    include_community_rules: bool = False
    selected_custom_rule_ids: Optional[List[str]] = []
    selected_community_rule_ids: Optional[List[str]] = []
    niche: str = "all"  # Security niche for rule filtering

class Issue(BaseModel):
    id: Optional[str] = None
    message: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    severity: str
    file_path: Optional[str] = None
    category: Optional[str] = None
    tool: Optional[str] = None
    rule_id: Optional[str] = None
    confidence: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    code_context: Optional[Dict[str, str]] = None  # Added for code snippets
    nist_id: Optional[str] = None  # Added for compliance
    pci_dss_id: Optional[str] = None
    hipaa_id: Optional[str] = None
    gdpr_article: Optional[str] = None
    iso_27001_id: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    total_score: int
    scores: Dict[str, Optional[float]]
    issues: List[Issue]
    branch: str
    mode: str
    scope: str
    scan_type: str
    metadata: Dict[str, Any]
    created_at: str
    custom_rules_metadata: Optional[Dict[str, Any]] = None  # Custom rules usage info

class ScanSummaryResponse(BaseModel):
    scan_id: str
    repo_full_name: str
    branch: str
    total_score: int
    status: str
    scan_type: str
    pr_number: Optional[int] = None  # Include PR number for PR scans
    issue_summary: Dict[str, int]
    created_at: str
    scan_duration: Optional[int] = None

class AIExplanationResponse(BaseModel):
    explanation: str
    fix_suggestion: Optional[str] = None
    testing_approach: Optional[str] = None
    business_impact: Optional[str] = None
    owasp_mapping: Optional[Dict[str, Any]] = None
    cached: bool = False

class QueueStatsResponse(BaseModel):
    queued: int
    processing: int
    failed: int
    total_scans_today: int
    average_scan_time: float

class PaginationMeta(BaseModel):
    page: int
    limit: int
    total: int
    total_pages: int

class PaginatedScanSummaryResponse(BaseModel):
    data: List[ScanSummaryResponse]
    pagination: PaginationMeta

class ScanStatsResponse(BaseModel):
    total_scans: int
    active_scans: int
    critical_issues: int
    completed_scans: int
    failed_scans: int
    by_status: Dict[str, int]
    by_repository: Dict[str, int]

class PRListResponse(BaseModel):
    number: int
    title: str
    state: str
    created_at: str
    updated_at: str
    author: Optional[str]
    head_sha: str
    additions: int
    deletions: int
    changed_files: int
    draft: bool
    labels: List[str]
    url: str

class PRScanRequest(BaseModel):
    """Request model for PR security scans
    
    Note: mode and scope are optional parameters for compatibility.
    """
    scope: Optional[str] = "code+deps"  # Optional: Defaults to 'code+deps'
    mode: Optional[str] = "comprehensive"  # Optional: Always comprehensive, kept for API compatibility
    include_custom_rules: bool = False
    include_community_rules: bool = False
    selected_custom_rule_ids: Optional[List[str]] = []
    selected_community_rule_ids: Optional[List[str]] = []
    niche: str = "all"

class BulkPRScanRequest(BaseModel):
    """Request model for bulk PR security scans
    
    Note: mode and scope are optional parameters for compatibility.
    """
    pr_numbers: Optional[List[int]] = None  # If None, scan all open PRs
    scope: Optional[str] = "code+deps"  # Optional: Defaults to 'code+deps'
    mode: Optional[str] = "comprehensive"  # Optional: Always comprehensive, kept for API compatibility
    max_concurrent: int = 5
    include_custom_rules: bool = False
    include_community_rules: bool = False
    selected_custom_rule_ids: Optional[List[str]] = []
    selected_community_rule_ids: Optional[List[str]] = []
    niche: str = "all"

class IssueFeedbackRequest(BaseModel):
    is_false_positive: bool
    feedback_reason: Optional[str] = None

@scans_router.post("/", response_model=dict)
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger a manual security scan"""
    
    logger.info(f"Manual scan request for {request.repo_full_name} by user {current_user.id}")
    
    # Rate limiting with cache fallback
    rate_key = f"{RATE_LIMIT_KEY_PREFIX}{current_user.id}"
    current_rate = await RateLimitCache.increment_counter(rate_key, RATE_LIMIT_TTL)
    if current_rate > RATE_LIMIT_MAX:
        logger.warning(f"Rate limit exceeded for user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    # Validate repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == request.repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        logger.warning(f"Unauthorized scan attempt for {request.repo_full_name} by user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized."
        )
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Validate branch if specified
    actual_branch = request.branch
    from core.cache import cache
    
    if not actual_branch:
        # Get default branch with caching (6-hour TTL)
        default_branch_cache_key = f"repo:default_branch:{repo.full_name}"
        cached_default_branch = await cache.get(default_branch_cache_key)
        
        if cached_default_branch is not None:
            actual_branch = cached_default_branch
            logger.info(f"Using cached default branch: {actual_branch}")
        else:
            from github import Github
            try:
                g = Github(gh_token)
                gh_repo = g.get_repo(repo.full_name)
                actual_branch = gh_repo.default_branch
                
                # Cache default branch for 6 hours
                await cache.set(default_branch_cache_key, actual_branch, ttl=21600)
                logger.info(f"Fetched and cached default branch: {actual_branch}")
            except Exception as e:
                logger.error(f"Failed to get default branch: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to access repository"
                )
    else:
        # Validate specified branch exists with caching (1-hour TTL)
        branch_validation_cache_key = f"branch:validation:{repo.full_name}:{actual_branch}"
        cached_validation = await cache.get(branch_validation_cache_key)
        
        if cached_validation is not None:
            if cached_validation == "valid":
                logger.info(f"Using cached validation for branch '{actual_branch}'")
            else:
                logger.warning(f"Cached validation shows branch '{actual_branch}' not found")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Branch '{actual_branch}' not found in repository"
                )
        else:
            from github import Github
            try:
                g = Github(gh_token)
                gh_repo = g.get_repo(repo.full_name)
                gh_repo.get_branch(actual_branch)
                
                # Cache valid branch for 1 hour
                await cache.set(branch_validation_cache_key, "valid", ttl=3600)
                logger.info(f"Validated and cached branch '{actual_branch}' exists")
            except Exception as e:
                # Cache invalid branch for shorter time (5 minutes)
                await cache.set(branch_validation_cache_key, "invalid", ttl=300)
                logger.warning(f"Branch '{actual_branch}' not found: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Branch '{actual_branch}' not found in repository"
                )
    
    # MAXIMUM SECURITY COVERAGE: Force comprehensive mode and full scope for ALL scans
    # This ensures every scan runs ALL available security tools with complete coverage
    scan_data = {
        "branch": actual_branch,
        "scope": ScanScope.FULL,  # ALWAYS full scope: code + dependencies + infrastructure
        "mode": ScanMode.COMPREHENSIVE,  # ALWAYS comprehensive mode: all tools enabled
        "gh_token": gh_token,
        "user_id": current_user.id,
        "niche": request.niche if request.niche != "all" else repo.niche,
        "include_custom_rules": request.include_custom_rules,
        "include_community_rules": request.include_community_rules,
        "selected_custom_rule_ids": request.selected_custom_rule_ids or [],
        "selected_community_rule_ids": request.selected_community_rule_ids or []
    }
    
    try:
        # 🏰 FORTRESS: Use unified fortress enqueue - no more fragmentation!
        job_id = await enqueue_scan_fortress(
            repo_full_name=request.repo_full_name,
            scan_type="manual",
            scan_config=scan_data,
            priority="NORMAL",
            user_id=current_user.id,
            db=db
        )
        
        logger.info(f"Queued manual scan job {job_id}")
        
        # MAXIMUM SECURITY COVERAGE: All scans now run comprehensive with full scope
        # Realistic estimate for complete A-to-Z security analysis with ALL tools
        estimated_time = "8-15 minutes"  # Full comprehensive scan: all tools + infrastructure + dependencies
            
        return {
            "job_id": job_id,
            "status": "queued",
            "message": "Scan has been queued for processing",
            "estimated_completion": estimated_time
        }
        
    except Exception as e:
        logger.error(f"Failed to queue scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to queue scan"
        )


@scans_router.post("/upload", response_model=dict)
async def trigger_local_scan(
    file: UploadFile = File(...),
    mode: str = "comprehensive",  # MAXIMUM COVERAGE: Always comprehensive (parameter kept for API compatibility)
    scope: str = "full",  # MAXIMUM COVERAGE: Always full scope (parameter kept for API compatibility)
    include_custom_rules: bool = False,
    include_community_rules: bool = False,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger a security scan on uploaded local files"""
    
    logger.info(f"Local file scan request by user {current_user.id}, file: {file.filename}")
    
    # Rate limiting
    rate_key = f"{RATE_LIMIT_KEY_PREFIX}{current_user.id}"
    current_rate = await RateLimitCache.increment_counter(rate_key, RATE_LIMIT_TTL)
    if current_rate > RATE_LIMIT_MAX:
        logger.warning(f"Rate limit exceeded for user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )
    
    # Validate file type (only accept zip files)
    if not file.filename.endswith('.zip'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only ZIP files are supported"
        )
    
    # Check file size (limit to 100MB)
    file_size = 0
    temp_file_path = None
    temp_extract_dir = None
    
    try:
        # Create temporary file to store upload
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            temp_file_path = temp_file.name
            
            # Read and save file content
            content = await file.read()
            file_size = len(content)
            
            # Check file size limit (100MB)
            if file_size > 100 * 1024 * 1024:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="File too large. Maximum size is 100MB"
                )
            
            temp_file.write(content)
        
        # Extract and validate ZIP file
        temp_extract_dir = tempfile.mkdtemp(prefix='scan_upload_')
        
        try:
            with zipfile.ZipFile(temp_file_path, 'r') as zip_ref:
                # Security check: prevent path traversal
                for file_info in zip_ref.infolist():
                    if '..' in file_info.filename or file_info.filename.startswith('/'):
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Invalid file paths in ZIP archive"
                        )
                
                zip_ref.extractall(temp_extract_dir)
        except zipfile.BadZipFile:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid ZIP file"
            )
        
        # Create a synthetic repository name for tracking
        repo_name = f"local-upload/{current_user.username}/{file.filename.replace('.zip', '')}"
        
        # Generate job ID
        job_id = str(uuid.uuid4())
        
        try:
            # 🏰 FORTRESS: Use unified fortress enqueue for local file scans
            scan_data = {
                "repo_full_name": repo_name,
                "mode": "comprehensive",  # MAXIMUM COVERAGE: Always comprehensive mode
                "scope": "full",  # MAXIMUM COVERAGE: Always full scope
                "branch": "uploaded",
                "include_custom_rules": include_custom_rules,
                "include_community_rules": include_community_rules,
                "niche": "all",
                "local_path": temp_extract_dir,  # Pass extracted directory path
                "is_local_scan": True,  # Flag to indicate local file scan
                "original_filename": file.filename,
                "file_size": file_size
            }
            
            job_id = await enqueue_scan_fortress(
                repo_full_name=repo_name,
                scan_type="local_upload",
                scan_config=scan_data,
                priority="NORMAL",
                user_id=current_user.id,
                db=db
            )
            
            logger.info(f"Local scan queued successfully: {job_id}")
            
            return {
                "job_id": job_id,
                "status": "queued",
                "message": "Local file scan has been queued for processing",
                "estimated_completion": "4-8 minutes",  # Comprehensive scan time
                "file_info": {
                    "filename": file.filename,
                    "size_mb": round(file_size / (1024 * 1024), 2)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to queue local scan: {str(e)}")
            # Cleanup on failure
            if temp_extract_dir and os.path.exists(temp_extract_dir):
                shutil.rmtree(temp_extract_dir, ignore_errors=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to queue local scan"
            )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in local scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
    finally:
        # Cleanup temporary file
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


@scans_router.get("/job/{job_id}/status")
async def get_job_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan job status from fortress queue system"""
    
    try:
        logger.info(f"🔍 DEBUG: Getting job status for {job_id}")
        
        # Get job status from the unified queue system
        logger.info(f"🔍 DEBUG: Initializing unified queue manager for job {job_id}")
        queue_manager = await get_unified_queue_manager()
        
        logger.info(f"🔍 DEBUG: Calling queue_manager.get_job_status for job {job_id}")
        job_status_info = await queue_manager.get_job_status(job_id)
        
        logger.info(f"🔍 DEBUG: Fortress queue returned for job {job_id}: {job_status_info}")
        
        if not job_status_info:
            logger.info(f"🔍 DEBUG: Job {job_id} not found in fortress queue, checking database fallback")
            # Fallback: check if job exists in database (ScanJob table)

            # First check the ScanJob table using the job_id
            logger.info(f"🔍 DEBUG: Querying ScanJob table for job {job_id}")
            job_result = await db.execute(
                select(ScanJob).where(ScanJob.id == job_id)
            )
            job = job_result.scalar_one_or_none()
            
            logger.info(f"🔍 DEBUG: ScanJob query result for {job_id}: {job}")
            
            if not job:
                logger.warning(f"🔍 DEBUG: Job {job_id} not found in ScanJob table either")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Job not found"
                )
            
            # Verify user owns this job by checking job_data
            job_data = job.job_data or {}
            scan_data = job_data.get("scan_data", {})
            job_user_id = scan_data.get("user_id")
            
            if not job_user_id or str(job_user_id) != str(current_user.id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Unauthorized access to job"
                )
            
            # Get real-time progress information
            progress_info = await _get_real_time_progress(job.id, job.status)
            
            # Base response
            response = {
                "job_id": job.id,
                "status": job.status,
                "repo_full_name": job.repo_full_name,
                "scan_type": job.scan_type,
                "created_at": format_datetime_response(job.created_at),
                "progress": progress_info["progress"],
                "stage": progress_info.get("stage", ""),
                "current_tool": progress_info.get("current_tool", ""),
                "tools_completed": progress_info.get("tools_completed", 0),
                "total_tools": progress_info.get("total_tools", 0)
            }
            
            # Add timestamps based on job status
            if job.started_at:
                response["started_at"] = format_datetime_response(job.started_at)
            if job.completed_at:
                response["completed_at"] = format_datetime_response(job.completed_at)
            
            # For completed jobs, get additional scan details
            if job.status == "completed" and job.scan_id:
                # Get the completed scan details
                scan_result = await db.execute(
                    select(Scan).where(Scan.id == job.scan_id)
                )
                scan = scan_result.scalar_one_or_none()
                
                if scan:
                    response.update({
                        "scan_id": scan.id,
                        "progress": "100%",
                        "total_score": scan.total_score,
                        "completed_at": format_datetime_response(scan.completed_at)
                    })
                else:
                    # Job marked as completed but scan not found
                    response["progress"] = "100%"
            elif job.status == "failed":
                response.update({
                    "error_message": job.error_message,
                    "progress": "0%"
                })
            
            return response
        
        # Extract job info from fortress queue status
        repo_full_name = job_status_info.get("repo_full_name", "")
        job_user_id = job_status_info.get("user_id")
        
        # Verify user owns this job
        if not job_user_id or int(job_user_id) != current_user.id:
            logger.warning(f"Unauthorized job access attempt: user {current_user.id} tried to access job {job_id} owned by {job_user_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized access to job"
            )
        
        # Additional check: Verify repository ownership if we have repo info
        if repo_full_name:
            repo_result = await db.execute(
                select(Repo).where(
                    and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
                )
            )
            if not repo_result.scalar_one_or_none():
                logger.warning(f"Repository ownership check failed for job {job_id}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Unauthorized access to job - repository not owned by user"
                )
        
        # Get additional progress information for processing jobs
        if job_status_info.get("status") == "processing":
            progress_info = await _get_real_time_progress(job_id, "processing")
            job_status_info.update({
                "stage": progress_info.get("stage", ""),
                "current_tool": progress_info.get("current_tool", ""),
                "tools_completed": progress_info.get("tools_completed", 0),
                "total_tools": progress_info.get("total_tools", 0)
            })
            
            # Override progress if we have more detailed info
            if progress_info.get("progress") != "Processing scan...":
                job_status_info["progress"] = progress_info["progress"]
        
        # Standardize the response format
        response = {
            "job_id": job_id,
            "status": job_status_info.get("status", "unknown"),
            "progress": job_status_info.get("progress", "Unknown"),
        }
        
        # Add additional fields based on what's available
        if "repo_full_name" in job_status_info:
            response["repo_full_name"] = job_status_info["repo_full_name"]
        if "scan_type" in job_status_info:
            response["scan_type"] = job_status_info["scan_type"]
        if "created_at" in job_status_info:
            response["created_at"] = job_status_info["created_at"]
        if "started_at" in job_status_info:
            response["started_at"] = job_status_info["started_at"]
        if "completed_at" in job_status_info:
            response["completed_at"] = job_status_info["completed_at"]
        if "worker_id" in job_status_info:
            response["worker_id"] = job_status_info["worker_id"]
        if "error_message" in job_status_info:
            response["error_message"] = job_status_info["error_message"]
        if "retry_count" in job_status_info:
            response["retry_count"] = job_status_info["retry_count"]
        
        # Add processing-specific fields
        if "stage" in job_status_info:
            response["stage"] = job_status_info["stage"]
        if "current_tool" in job_status_info:
            response["current_tool"] = job_status_info["current_tool"]
        if "tools_completed" in job_status_info:
            response["tools_completed"] = job_status_info["tools_completed"]
        if "total_tools" in job_status_info:
            response["total_tools"] = job_status_info["total_tools"]
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job status for {job_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get job status"
        )


@scans_router.post("/job/{job_id}/force-complete")
async def force_complete_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Force complete a stuck scan job - EMERGENCY USE ONLY"""
    
    try:
        logger.info(f"🚨 FORCE COMPLETE: Attempting to force complete job {job_id}")
        
        # Get job status to verify ownership first
        queue_manager = await get_unified_queue_manager()
        job_status_info = await queue_manager.get_job_status(job_id)
        
        if not job_status_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Job not found"
            )
        
        # Verify user owns this job
        job_user_id = job_status_info.get("user_id")
        if not job_user_id or int(job_user_id) != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized access to job"
            )
        
        # Only allow force completion on stuck processing jobs
        if job_status_info.get("status") != "processing":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Can only force complete jobs in 'processing' status. Current status: {job_status_info.get('status')}"
            )
        
        # Force complete the job using the private method
        await queue_manager._fix_stuck_job_status(job_id)
        
        logger.info(f"✅ FORCE COMPLETE: Successfully force completed job {job_id}")
        
        return {
            "message": "Job successfully force completed",
            "job_id": job_id,
            "previous_status": job_status_info.get("status"),
            "new_status": "completed"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ FORCE COMPLETE: Error force completing job {job_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to force complete job"
        )


async def _get_real_time_progress(job_id: str, job_status: str) -> Dict[str, Any]:
    """Get real-time progress information from Redis"""
    
    if job_status == "completed":
        return {"progress": "100%"}
    elif job_status == "failed":
        return {"progress": "0%"}
    elif job_status == "queued":
        return {"progress": "0%", "stage": "Waiting in queue"}
    elif job_status != "processing":
        return {"progress": "0%"}
    
    # Get progress from Redis for processing jobs
    try:
        from core.redis import get_redis_client
        redis_client = await get_redis_client()
        
        if redis_client:
            # 🏰 FORTRESS: Check both legacy and unified progress keys for compatibility
            progress_data = await redis_client.get(f"unified_scan_progress:{job_id}")
            if not progress_data:
                progress_data = await redis_client.get(f"scan_progress:{job_id}")
            
            if progress_data:
                import json
                progress_info = json.loads(progress_data)
                return progress_info
            else:
                # Fallback to generic processing status
                return {
                    "progress": "25%", 
                    "stage": "Initializing scan", 
                    "current_tool": "", 
                    "tools_completed": 0, 
                    "total_tools": 0
                }
        else:
            return {
                "progress": "25%", 
                "stage": "Processing", 
                "current_tool": "", 
                "tools_completed": 0, 
                "total_tools": 0
            }
    except Exception as e:
        logger.warning(f"Failed to get progress from Redis: {e}")
        return {
            "progress": "25%", 
            "stage": "Processing", 
            "current_tool": "", 
            "tools_completed": 0, 
            "total_tools": 0
        }


async def _poll_for_scan_completion(
    job_id: str,
    db: AsyncSession,
    current_user: User,
    max_wait_time: float = 300.0,  # 5 minutes max
    max_iterations: int = 60,      # Maximum 60 polls
    initial_delay: float = 2.0     # Start with 2 second delay
) -> Optional[str]:
    """
    Robust polling for scan completion with circuit breaker protection
    and exponential backoff to prevent infinite loops and resource exhaustion.
    
    Returns:
        scan_id if completed successfully
        
    Raises:
        HTTPException: On timeout, failure, or circuit breaker activation
    """
    
    # Create circuit breaker for this polling operation
    circuit_breaker = get_polling_circuit_breaker(
        name=f"scan_polling_{job_id}",
        max_iterations=max_iterations,
        max_duration=max_wait_time,
        config=CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            timeout=30.0  # 30 second circuit break
        )
    )
    
    # Create exponential backoff for retry delays
    backoff = ExponentialBackoff(
        initial_delay=initial_delay,
        max_delay=10.0,  # Max 10 second delay between polls
        multiplier=1.5,   # Gentle backoff increase
        jitter=True
    )
    
    logger.info(f"Starting robust polling for job {job_id}")
    
    try:
        while True:
            try:
                async with circuit_breaker:
                    # Get job status with exponential backoff on failures
                    job_status = await with_exponential_backoff(
                        get_job_status,
                        job_id, db, current_user,
                        backoff=ExponentialBackoff(initial_delay=0.5, max_delay=5.0, max_retries=3),
                        exceptions=(HTTPException, ConnectionError, TimeoutError)
                    )
                    
                    # Check completion states
                    if job_status["status"] == "completed":
                        scan_id = job_status.get("scan_id")
                        if scan_id:
                            logger.info(f"Scan job {job_id} completed successfully with scan_id: {scan_id}")
                            return scan_id
                        else:
                            logger.warning(f"Job {job_id} completed but no scan_id found")
                            raise HTTPException(
                                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Scan completed but no scan ID available"
                            )
                    
                    elif job_status["status"] == "failed":
                        error_msg = job_status.get("error_message", "Unknown error")
                        logger.error(f"Scan job {job_id} failed: {error_msg}")
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Security scan failed: {error_msg}"
                        )
                    
                    # Job still processing, apply backoff delay
                    delay = backoff.get_delay()
                    logger.debug(f"Job {job_id} status: {job_status['status']}, waiting {delay:.1f}s")
                    await asyncio.sleep(delay)
            
            except PollingLimitExceeded as e:
                logger.error(f"Polling limits exceeded for job {job_id}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail=f"Scan timeout after {max_wait_time}s or {max_iterations} attempts"
                )
            
            except CircuitBreakerOpenError as e:
                logger.error(f"Circuit breaker opened for job {job_id}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Scan service temporarily unavailable due to repeated failures"
                )
                
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Unexpected error while polling job {job_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error during scan polling"
        )
    finally:
        # Reset polling state for future use
        circuit_breaker.reset_polling()


async def _get_user_repositories(db: AsyncSession, user_id: int, limit: int = 1000) -> List[str]:
    """
    Get list of repository full names for a user with safety limit
    
    Args:
        db: Database session
        user_id: User ID
        limit: Maximum number of repositories to return (default 1000)
    
    Returns:
        List of repository full names
    """
    # Add limit to prevent memory issues with users who have many repositories
    repo_result = await db.execute(
        select(Repo.full_name)
        .where(Repo.user_id == user_id)
        .limit(limit)
        .order_by(Repo.created_at.desc())  # Get most recent repos first
    )
    
    repos = []
    for row in repo_result:
        repos.append(row[0])
        
    if len(repos) == limit:
        logger.warning(f"User {user_id} has {limit}+ repositories, results truncated")
        
    return repos

@scans_router.get("/stats", response_model=ScanStatsResponse)
async def get_scan_statistics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive scan statistics for the current user"""
    
    logger.info(f"Getting scan statistics for user {current_user.id}")
    
    # Get user's repositories
    user_repos = await _get_user_repositories(db, current_user.id)
    
    if not user_repos:
        return ScanStatsResponse(
            total_scans=0,
            active_scans=0,
            critical_issues=0,
            completed_scans=0,
            failed_scans=0,
            by_status={},
            by_repository={}
        )
    
    # Get all scans for user repos
    scans_query = select(Scan).where(Scan.repo_full_name.in_(user_repos))
    scans_result = await db.execute(scans_query)
    all_scans = scans_result.scalars().all()
    
    # Calculate statistics
    total_scans = len(all_scans)
    by_status = {}
    by_repository = {}
    critical_issues = 0
    completed_scans = 0
    failed_scans = 0
    
    for scan in all_scans:
        # Count by status
        status = scan.status
        by_status[status] = by_status.get(status, 0) + 1
        
        # Count by repository
        repo = scan.repo_full_name
        by_repository[repo] = by_repository.get(repo, 0) + 1
        
        # Count completed and failed
        if status == 'completed':
            completed_scans += 1
        elif status == 'failed':
            failed_scans += 1
        
        # Count critical issues from summaries
        if scan.status == 'completed':
            summaries_query = select(ScanSummary).where(ScanSummary.scan_id == scan.id)
            summaries_result = await db.execute(summaries_query)
            summaries = summaries_result.scalars().all()
            
            for summary in summaries:
                critical_issues += summary.critical_count
    
    # Get active scans from job queue (this could be enhanced with actual queue stats)
    active_scans = by_status.get('processing', 0) + by_status.get('queued', 0)
    
    return ScanStatsResponse(
        total_scans=total_scans,
        active_scans=active_scans,
        critical_issues=critical_issues,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        by_status=by_status,
        by_repository=by_repository
    )

@scans_router.get("/{scan_id}/export")
async def export_scan_report(
    scan_id: str,
    format: str = Query("pdf", description="Export format (pdf)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export scan details as a PDF report"""
    
    logger.info(f"Exporting scan report for {scan_id} by user {current_user.id}")
    
    # Validate format
    if format.lower() not in ["pdf"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported export format. Only 'pdf' is supported."
        )
    
    # Get scan details using the existing endpoint logic
    try:
        # Get scan from database (bypassing cache for consistent structure)
        # cached_result = await ScanCache.get_scan_result(scan_id)
        # if cached_result:
        #     scan_data = cached_result
        # else:
        
        # Fetch from database
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found"
            )
        
        # Verify user owns the repository
        result = await db.execute(
            select(Repo).where(
                and_(Repo.full_name == scan.repo_full_name, Repo.user_id == current_user.id)
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Unauthorized to access this scan"
            )
        
        # Parse scan data - map individual score columns to scores dict
        scan_data = {
            "scan_id": scan.id,
            "repo_full_name": scan.repo_full_name,
            "branch": scan.branch,
            "status": scan.status,
            "total_score": scan.total_score,
            "scores": {
                "code_score": scan.code_score,
                "deps_score": scan.deps_score,
                "secrets_score": scan.secrets_score,
                "configs_score": scan.configs_score
            },
            "issues": [],  # Issues will be fetched from ScanSummary table
            "mode": scan.mode,
            "scope": scan.scope,
            "scan_type": scan.scan_type,
            "metadata": {
                "scan_duration": scan.scan_duration,
                "tools_used": scan.tools_used or [],
                "commit_sha": scan.commit_sha,
                "pr_number": scan.pr_number,
                "sbom": scan.sbom
            },
            "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        }
        
        # Fetch issues from ScanSummary table
        try:
            summaries_result = await db.execute(
                select(ScanSummary).where(ScanSummary.scan_id == scan_id)
            )
            summaries = summaries_result.scalars().all()
            
            # Extract sample issues from summaries
            all_issues = []
            for summary in summaries:
                if summary.sample_issues:
                    issues = summary.sample_issues if isinstance(summary.sample_issues, list) else []
                    for issue in issues:
                        if isinstance(issue, dict):
                            issue['category'] = summary.category
                            issue['tool'] = summary.tool_name
                            all_issues.append(issue)
            
            scan_data["issues"] = all_issues[:50]  # Limit to 50 issues for PDF
        except Exception as e:
            logger.warning(f"Failed to fetch issues for scan {scan_id}: {e}")
            scan_data["issues"] = []
        
        # Set up Jinja2 template environment with custom filters
        template_dir = Path(__file__).parent / "templates"
        env = Environment(loader=FileSystemLoader(template_dir))
        
        template = env.get_template("scan_report.html")
        
        # Render HTML with scan data
        html_content = template.render(
            scan=scan_data,
            current_date=utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
        )
        
        # Generate PDF
        try:
            import weasyprint
            pdf_buffer = io.BytesIO()
            weasyprint.HTML(string=html_content).write_pdf(pdf_buffer)
            pdf_buffer.seek(0)
        except ImportError:
            raise HTTPException(
                status_code=500,
                detail="PDF export requires weasyprint. Please install: pip install weasyprint"
            )
        
        # Prepare filename
        repo_name = scan_data["repo_full_name"].replace("/", "_")
        filename = f"DevSecureX_Security_Report_{repo_name}_{scan_id[:8]}_{utc_now().strftime('%Y%m%d')}.pdf"
        
        # Return PDF as streaming response
        return StreamingResponse(
            io.BytesIO(pdf_buffer.read()),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/pdf"
            }
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        logger.error(f"Failed to export scan report for {scan_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate report. Please try again."
        )

@scans_router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_details(
    scan_id: str,
    include_issues: bool = Query(True, description="Include detailed issues in response"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed scan results"""
    
    logger.info(f"Fetching scan details for {scan_id} by user {current_user.id}")
    
    # Try cache first with new caching system
    if include_issues:
        cached_result = await ScanCache.get_scan_result(scan_id)
        if cached_result:
            try:
                logger.info(f"Scan {scan_id} served from cache")
                return ScanResponse(**cached_result)
            except Exception as e:
                logger.warning(f"Cache corruption for scan {scan_id}: {e}")
                await cache.delete(f"scan:result:{scan_id}")
    
    # Get scan from database
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Verify user owns the repository
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == scan.repo_full_name, Repo.user_id == current_user.id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access to scan"
        )
    
    # Get scan summaries and reconstruct issues
    issues = []
    if include_issues:
        issues = await _reconstruct_issues_from_summaries(scan_id, db)
    
    # Build response
    response_data = {
        "scan_id": scan.id,
        "status": scan.status,
        "total_score": scan.total_score,
        "scores": {
            "code_score": scan.code_score,
            "deps_score": scan.deps_score,
            "secrets_score": scan.secrets_score,
            "configs_score": scan.configs_score
        },
        "issues": issues,
        "branch": scan.branch,
        "mode": scan.mode,
        "scope": scan.scope,
        "scan_type": scan.scan_type,
        "metadata": {
            "scan_duration": scan.scan_duration,
            "tools_used": scan.tools_used or [],
            "commit_sha": scan.commit_sha,
            "pr_number": scan.pr_number,
            "sbom": scan.sbom
        },
        "created_at": format_datetime_response(scan.created_at)
    }
    
    # Cache the response with new caching system
    if include_issues:
        response_dict = response_data.copy()
        response_dict['issues'] = [issue.model_dump() if hasattr(issue, 'model_dump') else issue for issue in response_data['issues']]
        await ScanCache.set_scan_result(scan_id, response_dict, SCAN_CACHE_TTL)
    
    return ScanResponse(**response_data)

@scans_router.get("/repos/{repo_full_name:path}/scans", response_model=List[ScanSummaryResponse])
async def list_repo_scans(
    repo_full_name: str,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=200),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List scans for a specific repository"""
    
    logger.info(f"Listing scans for repo {repo_full_name} by user {current_user.id}")
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Build query
    query = select(Scan).where(Scan.repo_full_name == repo_full_name)
    
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    
    query = query.order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit)
    
    # Execute query
    result = await db.execute(query)
    scans = result.scalars().all()
    
    # Build response
    summaries = []
    for scan in scans:
        issue_summary = await _calculate_issue_summary(scan.id, db)
        
        summary = ScanSummaryResponse(
            scan_id=scan.id,
            repo_full_name=scan.repo_full_name,
            branch=scan.branch,
            total_score=scan.total_score,
            status=scan.status,
            scan_type=scan.scan_type,
            pr_number=scan.pr_number,  # Include PR number for PR scans
            issue_summary=issue_summary,
            created_at=format_datetime_response(scan.created_at),
            scan_duration=scan.scan_duration
        )
        summaries.append(summary)
    
    return summaries

async def _calculate_issue_summary(scan_id: str, db: AsyncSession) -> Dict[str, int]:
    """Calculate issue summary from scan summaries"""
    
    result = await db.execute(
        select(ScanSummary).where(ScanSummary.scan_id == scan_id)
    )
    summaries = result.scalars().all()
    
    total_summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "total": 0
    }
    
    for summary in summaries:
        total_summary["critical"] += summary.critical_count
        total_summary["high"] += summary.high_count
        total_summary["medium"] += summary.medium_count
        total_summary["low"] += summary.low_count
        total_summary["total"] += summary.total_issues
    
    return total_summary

@scans_router.get("/", response_model=PaginatedScanSummaryResponse)
async def list_user_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=200),
    scan_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    repository: Optional[str] = Query(None, description="Filter by repository full name"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all scans for the current user"""
    
    
    # Get user's repositories
    repo_result = await db.execute(
        select(Repo.full_name).where(Repo.user_id == current_user.id)
    )
    user_repos = [row[0] for row in repo_result.fetchall()]
    logger.info(f"User {current_user.id} owns repositories: {user_repos}")
    
    if not user_repos:
        return PaginatedScanSummaryResponse(
            data=[],
            pagination=PaginationMeta(
                page=page,
                limit=limit,
                total=0,
                total_pages=0
            )
        )
    
    # Build query
    query = select(Scan).where(Scan.repo_full_name.in_(user_repos))
    
    if scan_type:
        query = query.where(Scan.scan_type == scan_type)
    if status:
        query = query.where(Scan.status == status)
    if repository:
        logger.info(f"🔍 Repository filter applied: {repository}")
        
        # Ensure the repository belongs to the user for security
        if repository in user_repos:
            logger.info(f"✅ Repository {repository} belongs to user, applying filter")
            query = query.where(Scan.repo_full_name == repository)
        else:
            logger.warning(f"❌ Repository {repository} does not belong to user {current_user.id}, returning empty results")
            # Repository doesn't belong to user, return empty results
            return PaginatedScanSummaryResponse(
                data=[],
                pagination=PaginationMeta(
                    page=page,
                    limit=limit,
                    total=0,
                    total_pages=0
                )
            )
    
    query = query.order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit)
    
    # Debug: Log query execution
    logger.info(f"About to execute query with filters applied")
    
    # Execute query
    result = await db.execute(query)
    scans = result.scalars().all()
    
    logger.info(f"Query returned {len(scans)} scans")
    
    # Debug: Log the first few scan repo names to verify filtering
    if scans:
        scan_repos = [scan.repo_full_name for scan in scans[:5]]
        logger.info(f"First 5 scan repositories: {scan_repos}")
    
    # Build response
    summaries = []
    for scan in scans:
        issue_summary = await _calculate_issue_summary(scan.id, db)
        
        summary = ScanSummaryResponse(
            scan_id=scan.id,
            repo_full_name=scan.repo_full_name,
            branch=scan.branch,
            total_score=scan.total_score,
            status=scan.status,
            scan_type=scan.scan_type,
            pr_number=scan.pr_number,  # Include PR number for PR scans
            issue_summary=issue_summary,
            created_at=format_datetime_response(scan.created_at),
            scan_duration=scan.scan_duration
        )
        summaries.append(summary)
    
    # Get total count for pagination
    total_query = select(func.count(Scan.id)).where(Scan.repo_full_name.in_(user_repos))
    if scan_type:
        total_query = total_query.where(Scan.scan_type == scan_type)
    if status:
        total_query = total_query.where(Scan.status == status)
    if repository and repository in user_repos:
        total_query = total_query.where(Scan.repo_full_name == repository)
    
    total_result = await db.execute(total_query)
    total_count = total_result.scalar() or 0
    
    return PaginatedScanSummaryResponse(
        data=summaries,
        pagination=PaginationMeta(
            page=page,
            limit=limit,
            total=total_count,
            total_pages=(total_count + limit - 1) // limit
        )
    )

@scans_router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user)
):
    """Delete a scan and all associated data"""
    
    logger.info(f"Deleting scan {scan_id} by user {current_user.id}")
    
    # Create a new database session to avoid transaction conflicts
    from core.database import engine
    from sqlalchemy.ext.asyncio import AsyncSession
    
    # First, verify scan exists and user has permission using raw SQL
    async with engine.connect() as verify_conn:
        try:
            # Get scan and verify ownership with a single query
            result = await verify_conn.execute(
                text("""
                    SELECT s.id, s.repo_full_name 
                    FROM scans s 
                    INNER JOIN repos r ON s.repo_full_name = r.full_name 
                    WHERE s.id = :scan_id AND r.user_id = :user_id
                """),
                {"scan_id": scan_id, "user_id": current_user.id}
            )
            scan_row = result.fetchone()
            
            if not scan_row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Scan not found or unauthorized"
                )
                
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error verifying scan ownership {scan_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify scan ownership"
            )
    
    # Use direct connection to avoid session transaction conflicts
    async with engine.begin() as conn:
        try:
            # Delete related records first (foreign key constraints)
            await conn.execute(
                text("DELETE FROM issue_feedback WHERE scan_id = :scan_id"),
                {"scan_id": scan_id}
            )
            await conn.execute(
                text("DELETE FROM compliance_mappings WHERE scan_id = :scan_id"),
                {"scan_id": scan_id}
            )
            await conn.execute(
                text("DELETE FROM pr_security_comments WHERE scan_id = :scan_id"),
                {"scan_id": scan_id}
            )
            await conn.execute(
                text("DELETE FROM pr_security_reviews WHERE scan_id = :scan_id"),
                {"scan_id": scan_id}
            )
            await conn.execute(
                text("DELETE FROM scan_summaries WHERE scan_id = :scan_id"),
                {"scan_id": scan_id}
            )
            
            # Set scan_id to NULL in ScanJob (follows FK constraint)
            await conn.execute(
                text("UPDATE scan_jobs SET scan_id = NULL, status = 'orphaned' WHERE scan_id = :scan_id"),
                {"scan_id": scan_id}
            )
            
            # Delete main scan record
            scan_result = await conn.execute(
                text("DELETE FROM scans WHERE id = :scan_id"),
                {"scan_id": scan_id}
            )
            
            # Check if scan was actually deleted
            if scan_result.rowcount == 0:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Scan not found or already deleted"
                )
            
            logger.info(f"Successfully deleted scan {scan_id}")
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete scan {scan_id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to delete scan: {str(e)}"
            )
    
    # Clear cache after successful deletion
    try:
        await cache.delete(f"scan:result:{scan_id}")
        await ScanCache.invalidate_user_scans(current_user.id)
    except Exception as e:
        logger.warning(f"Failed to clear cache after deleting scan {scan_id}: {e}")
    
    return {"status": "deleted", "message": "Scan deleted successfully"}


@scans_router.get("/issues/explain", response_model=AIExplanationResponse)
async def get_ai_explanation(
    tool: str,
    rule_id: str,
    category: str,
    severity: str = "medium",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get AI explanation for a specific type of security issue"""
    
    logger.info(f"AI explanation request for {tool}:{rule_id} by user {current_user.id}")
    
    # Create a mock issue for explanation with appropriate file extension
    def get_file_extension_from_rule(tool: str, rule_id: str) -> str:
        """Determine appropriate file extension based on tool and rule_id"""
        # Language-specific patterns in rule IDs (JavaScript before Java to avoid substring conflicts)
        if "javascript" in rule_id.lower() or "js" in rule_id.lower() or tool.lower() in ["eslint", "semgrep-js"]:
            return "example.js"
        elif "java" in rule_id.lower() or tool.lower() in ["spotbugs", "semgrep-java"]:
            return "example.java"
        elif "typescript" in rule_id.lower() or "ts" in rule_id.lower():
            return "example.ts"
        elif "python" in rule_id.lower() or "py" in rule_id.lower() or tool.lower() in ["bandit", "semgrep-python"]:
            return "example.py"
        elif "go" in rule_id.lower() or tool.lower() in ["gosec", "semgrep-go"]:
            return "example.go"
        elif "rust" in rule_id.lower() or "rs" in rule_id.lower():
            return "example.rs"
        elif "cpp" in rule_id.lower() or "c++" in rule_id.lower() or tool.lower() in ["cppcheck"]:
            return "example.cpp"
        # DISABLED: Roslynator tool commented out - C#/.NET tool not installed
        # elif "csharp" in rule_id.lower() or "c#" in rule_id.lower() or tool.lower() in ["roslynator"]:
        #     return "example.cs"
        elif "php" in rule_id.lower():
            return "example.php"
        elif "ruby" in rule_id.lower() or "rb" in rule_id.lower():
            return "example.rb"
        elif "terraform" in rule_id.lower() or "tf" in rule_id.lower() or tool.lower() in ["checkov", "trivy"]:
            return "example.tf"
        elif "dockerfile" in rule_id.lower() or "docker" in rule_id.lower():
            return "Dockerfile"
        elif "yaml" in rule_id.lower() or "yml" in rule_id.lower():
            return "example.yaml"
        elif "json" in rule_id.lower():
            return "example.json"
        elif "xml" in rule_id.lower():
            return "example.xml"
        elif "html" in rule_id.lower():
            return "example.html"
        elif "css" in rule_id.lower():
            return "example.css"
        elif "shell" in rule_id.lower() or "bash" in rule_id.lower() or "sh" in rule_id.lower():
            return "example.sh"
        elif "sql" in rule_id.lower():
            return "example.sql"
        else:
            # Default based on tool
            if tool.lower() == "semgrep":
                return "example.py"  # Semgrep default
            elif tool.lower() == "bandit":
                return "example.py"
            elif tool.lower() == "eslint":
                return "example.js"
            elif tool.lower() == "gosec":
                return "example.go"
            elif tool.lower() == "spotbugs":
                return "example.java"
            elif tool.lower() == "cppcheck":
                return "example.cpp"
            elif tool.lower() == "checkov":
                return "example.tf"
            else:
                return "example.py"  # Final fallback
    
    file_path = get_file_extension_from_rule(tool, rule_id)
    
    mock_issue = {
        "tool": tool,
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "message": f"Security issue detected by {tool}",
        "file_path": file_path,
        "line_start": 1
    }
    
    try:
        explanations = await ai_explainer.explain_issues_batch([mock_issue], db)
        
        if explanations:
            issue_id = list(explanations.keys())[0]
            explanation = explanations[issue_id]
            
            return AIExplanationResponse(**explanation)
        else:
            # Return fallback explanation
            return AIExplanationResponse(
                explanation=f"This is a {severity} severity {category} issue detected by {tool}.",
                fix_suggestion="Review the code and apply security best practices.",
                cached=False
            )
            
    except Exception as e:
        logger.error(f"Failed to generate AI explanation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate explanation"
        )

@scans_router.post("/issues/{issue_id}/feedback", response_model=dict)
async def submit_issue_feedback(
    issue_id: str,
    request: IssueFeedbackRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Submit feedback for an issue (e.g., mark as false positive)"""
    
    logger.info(f"Submitting feedback for issue {issue_id} by user {current_user.id}")
    
    # Find the issue in scan summaries using parameterized JSON query
    from sqlalchemy import text
    # Sanitize issue_id to prevent SQL injection
    import re
    if not re.match(r'^[a-zA-Z0-9-]{8,36}$', issue_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid issue ID format"
        )
    
    result = await db.execute(
        select(ScanSummary).where(
            text("sample_issues @> :pattern").params(
                pattern=json.dumps([{"id": issue_id}])
            )
        )
    )
    summary = result.scalar_one_or_none()
    
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issue not found in scan summaries"
        )
    
    # Get the scan to verify ownership
    result = await db.execute(
        select(Scan).where(Scan.id == summary.scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Associated scan not found"
        )
    
    # Verify user owns the repository
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == scan.repo_full_name, Repo.user_id == current_user.id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized to provide feedback for this issue"
        )
    
    # Calculate issue hash (consistent with deduplication logic)
    from .utils.deduplicator import IssueDuplicator
    deduplicator = IssueDuplicator()
    issue_data = next((item for item in summary.sample_issues if item.get("id") == issue_id), None)
    if not issue_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issue data not found"
        )
    issue_hash = deduplicator.generate_issue_hash(issue_data)
    
    # Store feedback
    feedback = IssueFeedback(
        issue_hash=issue_hash,
        scan_id=summary.scan_id,
        is_false_positive=request.is_false_positive,
        user_id=str(current_user.id),
        feedback_reason=request.feedback_reason
    )
    
    try:
        db.add(feedback)
        await db.commit()
        logger.info(f"Feedback submitted for issue {issue_id}")
        return {"status": "success", "message": "Feedback submitted successfully"}
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to submit feedback for issue {issue_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit feedback"
        )

async def cleanup_stuck_scans(db: AsyncSession, user_repos: list, timeout_minutes: int = 30) -> int:
    """
    Detect and mark stuck scans as failed.

    A scan is considered stuck if:
    - Status is 'processing'
    - started_at is more than timeout_minutes ago
    - No recent activity

    Args:
        db: Database session
        user_repos: List of repository names for the current user
        timeout_minutes: Timeout in minutes (default: 30)

    Returns:
        int: Number of stuck scans cleaned up
    """
    from datetime import timedelta

    cutoff_time = utc_now() - timedelta(minutes=timeout_minutes)
    logger.info(f"Cleanup function called: timeout={timeout_minutes}min, cutoff_time={cutoff_time}, user_repos={len(user_repos)}")

    try:
        # Find stuck scans for this user's repositories
        stuck_scans_query = select(ScanJob).where(
            and_(
                ScanJob.status == "processing",
                ScanJob.repo_full_name.in_(user_repos),
                ScanJob.started_at.isnot(None),
                ScanJob.started_at < cutoff_time
            )
        )

        result = await db.execute(stuck_scans_query)
        stuck_scans = result.scalars().all()

        if not stuck_scans:
            return 0

        stuck_count = len(stuck_scans)

        # Update stuck scans to failed status
        for scan_job in stuck_scans:
            scan_job.status = "failed"
            scan_job.completed_at = utc_now()
            scan_job.error_message = f"Scan timed out after {timeout_minutes} minutes - marked as failed during queue cleanup"

            logger.warning(
                f"Marked stuck scan as failed: job_id={scan_job.id}, "
                f"repo={scan_job.repo_full_name}, "
                f"started_at={scan_job.started_at}, "
                f"duration={(utc_now() - scan_job.started_at).total_seconds() / 60:.1f} minutes"
            )

        # Commit the changes
        await db.commit()

        logger.info(f"Cleaned up {stuck_count} stuck scans for user repositories: {user_repos}")
        return stuck_count

    except Exception as e:
        logger.error(f"Error cleaning up stuck scans: {e}")
        await db.rollback()
        return 0


@scans_router.get("/queue/stats")
async def get_queue_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get scan queue statistics with stuck scan cleanup and aggressive caching to reduce Redis load"""

    print(f"DEBUG: Queue stats called for user {current_user.id}")
    logger.debug(f"Queue stats called for user {current_user.id}")

    # Cache key for user-specific queue stats
    cache_key = f"queue_stats:{current_user.id}"
    cache_ttl = 30  # Cache for 30 seconds to reduce Redis polling

    try:
        # Try to get cached stats first
        from core.cache import cache
        try:
            cached_stats = await cache.get(cache_key)
            if cached_stats is not None and isinstance(cached_stats, dict):
                cached_stats["cached"] = True
                cached_stats["timestamp"] = utc_now_iso()
                return cached_stats
        except Exception as cache_error:
            logger.warning(f"Cache retrieval failed for key {cache_key}: {cache_error}")
            # Clear the corrupted cache entry
            try:
                await cache.delete(cache_key)
            except:
                pass
        
        # Get user's repositories first
        repo_result = await db.execute(
            select(Repo.full_name).where(Repo.user_id == current_user.id)
        )
        user_repos = [row[0] for row in repo_result.fetchall()]
        
        # If user has no repositories, return cached zero stats
        if not user_repos:
            zero_stats = {
                "queued": 0,
                "processing": 0,
                "failed": 0,
                "total_scans_today": 0,
                "average_scan_time": 0.0,
                "stuck_scans_cleaned": 0,
                "cached": False,
                "timestamp": utc_now_iso(),
                "message": "No repositories connected"
            }
            # Cache zero stats for 60 seconds
            await cache.set(cache_key, zero_stats, ttl=60)
            return zero_stats
        
        # Skip Redis queue manager and use database-only approach

        # Clean up stuck scans before counting to ensure accurate statistics
        print(f"DEBUG: Starting cleanup for user {current_user.id} with {len(user_repos)} repositories")
        logger.info(f"Starting cleanup for user {current_user.id} with {len(user_repos)} repositories")
        stuck_count = await cleanup_stuck_scans(db, user_repos, timeout_minutes=30)
        print(f"DEBUG: Cleanup completed: {stuck_count} stuck scans processed for user {current_user.id}")
        logger.info(f"Cleanup completed: {stuck_count} stuck scans processed for user {current_user.id}")
        if stuck_count > 0:
            logger.info(f"Queue stats cleanup: marked {stuck_count} stuck scans as failed for user {current_user.id}")

        # Count jobs by status from database - filter by user's repositories
        queued_result = await db.execute(
            select(func.count(ScanJob.id)).where(
                and_(ScanJob.status == "queued", ScanJob.repo_full_name.in_(user_repos))
            )
        )
        processing_result = await db.execute(
            select(func.count(ScanJob.id)).where(
                and_(ScanJob.status == "processing", ScanJob.repo_full_name.in_(user_repos))
            )
        )
        failed_result = await db.execute(
            select(func.count(ScanJob.id)).where(
                and_(ScanJob.status == "failed", ScanJob.repo_full_name.in_(user_repos))
            )
        )
        
        queued = queued_result.scalar() or 0
        processing = processing_result.scalar() or 0
        failed = failed_result.scalar() or 0
        
        # Get today's scan statistics from database - filter by user's repositories
        today = utc_now().date()
        result = await db.execute(
            select(func.count(Scan.id), func.avg(Scan.scan_duration))
            .where(
                and_(
                    func.date(Scan.created_at) == today,
                    Scan.repo_full_name.in_(user_repos)
                )
            )
        )
        
        count_avg = result.first()
        total_today = count_avg[0] if count_avg else 0
        avg_duration = float(count_avg[1]) if count_avg and count_avg[1] else 0.0
        
        # Build response message
        base_message = f"User queue stats retrieved for {len(user_repos)} repositories"
        if stuck_count > 0:
            cleanup_message = f" (cleaned up {stuck_count} stuck scans)"
        else:
            cleanup_message = ""

        stats_response = {
            "queued": queued,
            "processing": processing,
            "failed": failed,
            "total_scans_today": total_today,
            "average_scan_time": avg_duration,
            "stuck_scans_cleaned": stuck_count,
            "cached": False,
            "timestamp": utc_now_iso(),
            "message": base_message + cleanup_message
        }
        
        # Cache the computed stats to reduce database load
        await cache.set(cache_key, stats_response, ttl=cache_ttl)
        return stats_response
        
    except Exception as e:
        logger.error(f"Queue stats endpoint error: {e}")
        # Return fallback stats
        return {
            "queued": 0,
            "processing": 0,
            "failed": 0,
            "total_scans_today": 0,
            "average_scan_time": 0.0,
            "stuck_scans_cleaned": 0,
            "cached": False,
            "timestamp": utc_now_iso(),
            "message": "Queue stats using fallback values"
        }

@scans_router.get("/repos/{repo_full_name:path}/prs", response_model=List[PRListResponse])
async def list_pull_requests(
    repo_full_name: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List open pull requests for a repository"""
    
    state = "open"  # Always fetch only open PRs
    logger.info(f"Listing open PRs for {repo_full_name}")
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Check cache first with new caching system  
    cache_key = f"prs:{repo_full_name}:open:{limit}"
    cached_prs = await cache.get(cache_key)
    if cached_prs:
        return cached_prs
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Fetch PRs with timeout handling
    try:
        # Add timeout to prevent hanging requests
        import asyncio
        prs = await asyncio.wait_for(
            pr_fetcher.get_prs(repo_full_name, gh_token, state, limit),
            timeout=90  # 90 seconds timeout for PR list
        )
        
        # Cache for 5 minutes with new caching system
        await cache.set(cache_key, prs, 300)
        
        return prs
        
    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching PRs for {repo_full_name}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Request timeout - GitHub API taking too long to respond. Please try again."
        )
    except Exception as e:
        logger.error(f"Failed to fetch PRs: {e}")
        # Provide more specific error messages
        if "rate limit" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="GitHub API rate limit exceeded. Please try again later."
            )
        elif "unauthorized" in str(e).lower() or "403" in str(e):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="GitHub authentication failed or insufficient permissions"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to fetch pull requests: {str(e)}"
            )

@scans_router.post("/repos/{repo_full_name:path}/prs/{pr_number}/scan")
async def scan_pull_request(
    repo_full_name: str,
    pr_number: int,
    request: PRScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger security scan for a specific pull request"""
    
    logger.info(f"PR scan request for {repo_full_name}#{pr_number}")
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Get PR details to validate it exists with caching (10-minute TTL)
    from core.cache import cache
    pr_details_cache_key = f"pr:details:{repo_full_name}:{pr_number}"
    cached_pr_details = await cache.get(pr_details_cache_key)
    
    if cached_pr_details is not None:
        pr_details = cached_pr_details
        logger.info(f"Using cached PR details for #{pr_number}")
    else:
        try:
            pr_details = await pr_fetcher.get_pr_details(repo_full_name, pr_number, gh_token)
            # Cache PR details for 10 minutes
            await cache.set(pr_details_cache_key, pr_details, ttl=600)
            logger.info(f"Fetched and cached PR details for #{pr_number}")
        except Exception as e:
            logger.error(f"Failed to fetch PR details: {e}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Pull request #{pr_number} not found"
            )
    
    # Get changed files for diff scanning with caching (30-minute TTL)
    pr_changed_files_cache_key = f"pr:changed_files:{repo_full_name}:{pr_number}"
    cached_changed_files = await cache.get(pr_changed_files_cache_key)
    
    if cached_changed_files is not None:
        changed_files = cached_changed_files
        logger.info(f"Using cached changed files for PR #{pr_number}")
    else:
        changed_files = await diff_analyzer.get_changed_files(repo_full_name, pr_number, gh_token)
        # Cache changed files for 30 minutes
        await cache.set(pr_changed_files_cache_key, changed_files, ttl=1800)
        logger.info(f"Fetched and cached changed files for PR #{pr_number}")
    
    file_list = [f["file_path"] for f in changed_files if f.get("file_path")]
    
    # Queue the scan
    scan_data = {
        "pr_number": pr_number,
        "commit_sha": pr_details["head"]["sha"],
        "branch": pr_details["head"]["ref"],
        "gh_token": gh_token,
        "user_id": str(current_user.id),
        "niche": request.niche if request.niche != "all" else repo.niche,
        "scope": "full",  # MAXIMUM COVERAGE: Always full scope
        "mode": "comprehensive",  # MAXIMUM COVERAGE: Always comprehensive mode
        "file_list": file_list,
        "include_custom_rules": request.include_custom_rules,
        "include_community_rules": request.include_community_rules,
        "selected_custom_rule_ids": request.selected_custom_rule_ids or [],
        "selected_community_rule_ids": request.selected_community_rule_ids or []
    }
    
    try:
        # 🏰 FORTRESS: Use unified fortress enqueue - no more fragmentation!
        job_id = await enqueue_scan_fortress(
            repo_full_name=repo_full_name,
            scan_type="pr_scan", 
            scan_config=scan_data,
            priority="HIGH",
            user_id=current_user.id,
            db=db
        )
        
        logger.info(f"Queued PR scan job {job_id} for {repo_full_name}#{pr_number}")
        
        # Calculate estimated completion time based on files changed (all scans are comprehensive)
        if len(file_list) <= 10:
            estimated_time = "2-4 minutes"   # Few files changed
        elif len(file_list) <= 30:
            estimated_time = "3-6 minutes"   # Moderate files changed
        elif len(file_list) <= 50:
            estimated_time = "4-8 minutes"   # Many files changed
        else:
            estimated_time = "5-10 minutes"  # Large PR changes
            
        return {
            "job_id": job_id,
            "status": "queued",
            "pr_number": pr_number,
            "message": f"Security scan queued for PR #{pr_number}",
            "changed_files": len(file_list),
            "estimated_completion": estimated_time
        }
        
    except Exception as e:
        logger.error(f"Failed to queue PR scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to queue scan"
        )
        
@scans_router.post("/repos/{repo_full_name:path}/prs/scan-all")
async def scan_all_pull_requests(
    repo_full_name: str,
    request: BulkPRScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Trigger security scans for multiple pull requests"""
    
    logger.info(f"Bulk PR scan request for {repo_full_name}")
    
    # Rate limiting for bulk operations with cache fallback
    rate_key = f"rate:bulk_scan:{current_user.id}"
    current_rate = await RateLimitCache.increment_counter(rate_key, 3600)
    if current_rate > 10:  # Max 10 bulk scans per hour
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Bulk scan rate limit exceeded"
        )
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Get PRs to scan
    if request.pr_numbers:
        # Validate specified PR numbers exist
        prs_to_scan = []
        for pr_num in request.pr_numbers[:50]:  # Limit to 50 PRs (increased from 20)
            try:
                pr = await pr_fetcher.get_pr_details(repo_full_name, pr_num, gh_token)
                prs_to_scan.append(pr)
            except:
                logger.warning(f"PR #{pr_num} not found, skipping")
    else:
        # Get all open PRs
        all_prs = await pr_fetcher.get_prs(repo_full_name, gh_token, "open", 50)
        prs_to_scan = all_prs[:request.max_concurrent]  # Limit number
    
    # Queue scans with rate limiting
    queued_jobs = []
    semaphore = asyncio.Semaphore(request.max_concurrent)
    
    async def queue_pr_scan(pr):
        async with semaphore:
            try:
                # Get changed files
                changed_files = await diff_analyzer.get_changed_files(
                    repo_full_name, 
                    pr["number"], 
                    gh_token
                )
                file_list = [f["file_path"] for f in changed_files if f.get("file_path")]
                
                scan_data = {
                    "pr_number": pr["number"],
                    "commit_sha": pr["head_sha"] if isinstance(pr, dict) else pr.head.sha,
                    "branch": pr["head_ref"] if isinstance(pr, dict) else pr.head.ref,
                    "gh_token": gh_token,
                    "user_id": str(current_user.id),
                    "niche": request.niche if request.niche != "all" else repo.niche,
                    "scope": "full",  # MAXIMUM COVERAGE: Always full scope
                    "mode": "comprehensive",  # MAXIMUM COVERAGE: Always comprehensive mode
                    "file_list": file_list,
                    "include_custom_rules": request.include_custom_rules,
                    "include_community_rules": request.include_community_rules,
                    "selected_custom_rule_ids": request.selected_custom_rule_ids or [],
                    "selected_community_rule_ids": request.selected_community_rule_ids or []
                }
                
                # 🏰 FORTRESS: Use unified fortress enqueue - no more fragmentation!
                job_id = await enqueue_scan_fortress(
                    repo_full_name=repo_full_name,
                    scan_type="pr_scan",
                    scan_config=scan_data,
                    priority="NORMAL",
                    user_id=current_user.id,
                    db=db
                )
                
                return {
                    "pr_number": pr["number"] if isinstance(pr, dict) else pr.number,
                    "job_id": job_id,
                    "status": "queued"
                }
            except Exception as e:
                logger.error(f"Failed to queue scan for PR: {e}")
                return {
                    "pr_number": pr["number"] if isinstance(pr, dict) else pr.number,
                    "error": str(e),
                    "status": "failed"
                }
    
    # Queue all scans
    tasks = [queue_pr_scan(pr) for pr in prs_to_scan]
    results = await asyncio.gather(*tasks)
    
    successful = [r for r in results if r.get("status") == "queued"]
    failed = [r for r in results if r.get("status") == "failed"]
    
    return {
        "total_prs": len(prs_to_scan),
        "queued": len(successful),
        "failed": len(failed),
        "results": results,
        "message": f"Queued {len(successful)} PR scans"
    }
    
@scans_router.get("/repos/{owner}/{repo_name}/prs/{pr_number}/scans", response_model=List[ScanSummaryResponse])
async def list_pr_scans(
    owner: str,
    repo_name: str,
    pr_number: int,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all scans for a specific pull request"""
    
    repo_full_name = f"{owner}/{repo_name}"
    logger.info(f"Listing scans for PR {repo_full_name}#{pr_number}")
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Query scans for this PR
    query = select(Scan).where(
        and_(
            Scan.repo_full_name == repo_full_name,
            Scan.pr_number == pr_number
        )
    ).order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit)
    
    result = await db.execute(query)
    scans = result.scalars().all()
    
    # Build response
    summaries = []
    for scan in scans:
        issue_summary = await _calculate_issue_summary(scan.id, db)
        
        summary = ScanSummaryResponse(
            scan_id=scan.id,
            repo_full_name=scan.repo_full_name,
            branch=scan.branch,
            total_score=scan.total_score,
            status=scan.status,
            scan_type=scan.scan_type,
            pr_number=scan.pr_number,  # Include PR number for PR scans
            issue_summary=issue_summary,
            created_at=format_datetime_response(scan.created_at),
            scan_duration=scan.scan_duration
        )
        summaries.append(summary)
    
    return summaries

@scans_router.post("/{scan_id}/post-pr-comment")
async def post_pr_security_comment(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Post scan results as a PR comment on GitHub"""
    
    logger.info(f"Manual PR comment request for scan {scan_id} by user {current_user.id}")
    
    # Get scan details
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Verify user owns the repository
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == scan.repo_full_name, Repo.user_id == current_user.id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access to scan"
        )
    
    # Check if scan is for a PR
    if not scan.pr_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This scan is not associated with a pull request"
        )
    
    # Get scan results
    scan_response = await get_scan_details(scan_id, True, db, current_user)
    scan_result = {
        "issues": [issue.model_dump() for issue in scan_response.issues],
        "scores": scan_response.scores,
        "metadata": scan_response.metadata
    }
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Post comment using GitHub integration
    from .integrations.github_integration import GitHubIntegration
    github_integration = GitHubIntegration()
    
    try:
        comment_url = await github_integration.post_pr_comment_async(
            repo_full_name=scan.repo_full_name,
            pr_number=scan.pr_number,
            scan_result=scan_result,
            gh_token=gh_token,
            scan_id=scan_id
        )
        
        # Store comment info in database
        from .models import PRSecurityComment
        pr_comment = PRSecurityComment(
            scan_id=scan_id,
            repo_full_name=scan.repo_full_name,
            pr_number=scan.pr_number,
            comment_type="comment",
            comment_url=comment_url
        )
        db.add(pr_comment)
        await db.commit()
        
        return {
            "status": "success",
            "comment_url": comment_url,
            "message": "Security analysis posted to PR"
        }
        
    except Exception as e:
        logger.error(f"Failed to post PR comment: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to post comment: {str(e)}"
        )

@scans_router.post("/repos/{repo_full_name:path}/prs/{pr_number}/security-review")
async def create_pr_security_review(
    repo_full_name: str,
    pr_number: int,
    review_action: str = Query("COMMENT", regex="^(COMMENT|APPROVE|REQUEST_CHANGES)$"),
    force_new_scan: bool = Query(False, description="Force a new scan before review"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a full PR review with inline security comments"""
    
    logger.info(f"PR security review request for {repo_full_name}#{pr_number}")
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Get or trigger scan for this PR
    if force_new_scan:
        # Trigger new scan
        scan_response = await scan_pull_request(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            request=PRScanRequest(),
            background_tasks=BackgroundTasks(),
            db=db,
            current_user=current_user
        )
        
        # Wait for scan to complete (with robust polling and circuit breaker)
        job_id = scan_response["job_id"]
        scan_id = await _poll_for_scan_completion(job_id, db, current_user)
    else:
        # Find most recent scan for this PR
        result = await db.execute(
            select(Scan)
            .where(
                and_(
                    Scan.repo_full_name == repo_full_name,
                    Scan.pr_number == pr_number,
                    Scan.status == "completed"
                )
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No completed scan found for this PR. Set force_new_scan=true to trigger one."
            )
        
        scan_id = scan.id
    
    # Get scan results
    scan_response = await get_scan_details(scan_id, True, db, current_user)
    scan_result = {
        "issues": [issue.model_dump() for issue in scan_response.issues],
        "scores": scan_response.scores,
        "metadata": scan_response.metadata
    }
    
    # Create PR review
    from .integrations.github_integration import GitHubIntegration
    github_integration = GitHubIntegration()
    
    try:
        review_result = await github_integration.create_pr_review(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            scan_result=scan_result,
            gh_token=gh_token,
            scan_id=scan_id,
            user_review_action=review_action
        )
        
        # Store review info in database
        from .models import PRSecurityReview
        issue_counts = github_integration._count_issues_by_severity(scan_result["issues"])
        
        pr_review = PRSecurityReview(
            scan_id=scan_id,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            review_id=str(review_result["review_id"]),
            review_action=review_result["review_action"],
            review_url=review_result["review_url"],
            security_score=scan_response.total_score,
            critical_count=issue_counts["critical"],
            high_count=issue_counts["high"],
            must_fix_count=issue_counts["critical"] + issue_counts["high"],
            inline_comments_count=review_result["inline_comments_count"]
        )
        db.add(pr_review)
        await db.commit()
        
        return {
            "status": "success",
            "review_url": review_result["review_url"],
            "review_action": review_result["review_action"],
            "inline_comments": review_result["inline_comments_count"],
            "message": f"Security review posted with action: {review_result['review_action']}"
        }
        
    except Exception as e:
        logger.error(f"Failed to create PR review: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create review: {str(e)}"
        )

@scans_router.get("/repos/{repo_full_name:path}/prs/{pr_number}/review-recommendation")
async def get_pr_review_recommendation(
    repo_full_name: str,
    pr_number: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get system recommendation for PR review action based on latest scan"""
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Find most recent scan for this PR
    result = await db.execute(
        select(Scan)
        .where(
            and_(
                Scan.repo_full_name == repo_full_name,
                Scan.pr_number == pr_number,
                Scan.status == "completed"
            )
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        return {
            "has_scan": False,
            "recommended_action": "COMMENT",
            "reason": "No scan data available"
        }
    
    # Get scan results to determine recommendation
    scan_response = await get_scan_details(scan.id, True, db, current_user)
    issues = [issue.model_dump() for issue in scan_response.issues]
    
    # Use GitHubIntegration's logic to determine recommendation
    from .integrations.github_integration import GitHubIntegration
    github_integration = GitHubIntegration()
    recommended_action = github_integration._determine_review_action(issues)
    
    # Count issues by severity for reason
    critical_count = sum(1 for i in issues if i.get("severity") == "critical")
    high_count = sum(1 for i in issues if i.get("severity") == "high")
    medium_count = sum(1 for i in issues if i.get("severity") == "medium")
    
    reason_parts = []
    if critical_count > 0:
        reason_parts.append(f"{critical_count} critical issue{'s' if critical_count != 1 else ''}")
    if high_count > 0:
        reason_parts.append(f"{high_count} high severity issue{'s' if high_count != 1 else ''}")
    if medium_count > 0:
        reason_parts.append(f"{medium_count} medium severity issue{'s' if medium_count != 1 else ''}")
    
    if not reason_parts:
        reason = "No significant security issues found"
    else:
        reason = f"Found: {', '.join(reason_parts)}"
    
    return {
        "has_scan": True,
        "recommended_action": recommended_action,
        "reason": reason,
        "issue_counts": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count
        },
        "scan_date": scan.created_at.isoformat()
    }

@scans_router.get("/repos/{repo_full_name:path}/prs/{pr_number}/security-reviews")
async def list_pr_security_reviews(
    repo_full_name: str,
    pr_number: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all security reviews for a PR"""
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Get reviews
    from .models import PRSecurityReview
    result = await db.execute(
        select(PRSecurityReview)
        .where(
            and_(
                PRSecurityReview.repo_full_name == repo_full_name,
                PRSecurityReview.pr_number == pr_number
            )
        )
        .order_by(PRSecurityReview.created_at.desc())
    )
    reviews = result.scalars().all()
    
    return [
        {
            "id": review.id,
            "scan_id": review.scan_id,
            "review_action": review.review_action,
            "security_score": review.security_score,
            "critical_count": review.critical_count,
            "high_count": review.high_count,
            "inline_comments_count": review.inline_comments_count,
            "review_url": review.review_url,
            "created_at": format_datetime_response(review.created_at)
        }
        for review in reviews
    ]

@scans_router.delete("/bulk/user-scans")
async def bulk_delete_user_scans(
    older_than_days: int = Query(30, ge=1, description="Delete scans older than this many days"),
    max_scans: int = Query(1000, ge=1, le=10000, description="Maximum number of scans to delete"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Bulk delete old scans for the current user with FK constraint handling"""
    
    logger.info(f"Bulk scan deletion request from user {current_user.id}: older than {older_than_days} days, max {max_scans}")
    
    try:
        # Get user's repositories
        repo_result = await db.execute(
            select(Repo.full_name).where(Repo.user_id == current_user.id)
        )
        user_repos = [row[0] for row in repo_result.fetchall()]
        
        if not user_repos:
            return {"message": "No repositories found", "deleted": 0}
        
        # Find old scans
        cutoff_date = utc_now() - timedelta(days=older_than_days)
        
        result = await db.execute(
            select(Scan.id)
            .where(
                and_(
                    Scan.repo_full_name.in_(user_repos),
                    Scan.created_at < cutoff_date
                )
            )
            .limit(max_scans)
        )
        
        scan_ids = [row[0] for row in result.fetchall()]
        
        if not scan_ids:
            return {
                "message": f"No scans older than {older_than_days} days found",
                "deleted": 0
            }
        
        # Use safe bulk deletion
        deletion_stats = await safe_bulk_delete(db, scan_ids, current_user.id)
        
        # Clear user's scan cache
        await ScanCache.invalidate_user_scans(current_user.id)
        
        return {
            "message": f"Successfully deleted {deletion_stats['scans']} old scans",
            "deleted_scans": deletion_stats["scans"],
            "deleted_summaries": deletion_stats["summaries"], 
            "deleted_dependencies": deletion_stats["dependencies"],
            "cutoff_date": format_datetime_response(cutoff_date)
        }
        
    except Exception as e:
        logger.error(f"Bulk scan deletion failed for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bulk deletion failed"
        )


@scans_router.get("/workers/status")
async def get_workers_status(
    current_user: User = Depends(get_current_user)
):
    """Get background workers status (admin only)"""
    import os
    from .workers.manager import get_worker_stats
    
    # Get environment info
    env_info = {
        "APP_ENV": os.getenv("APP_ENV", "development"),
        "ENABLE_BACKGROUND_WORKERS": os.getenv("ENABLE_BACKGROUND_WORKERS", "false"),
        "SCAN_WORKERS": os.getenv("SCAN_WORKERS", "2"),
        "REDIS_URL": "configured" if os.getenv("REDIS_URL") else "not configured"
    }
    
    # Get worker stats
    worker_stats = await get_worker_stats()
    
    return {
        "environment": env_info,
        "workers": worker_stats,
        "timestamp": utc_now_iso()
    }


# Enhanced PR scanning endpoints for world-class features
@scans_router.get("/repos/{repo_full_name:path}/prs/{pr_number}/insights")
async def get_pr_security_insights(
    repo_full_name: str,
    pr_number: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive security insights for a PR with historical analysis"""
    
    logger.info(f"PR insights request for {repo_full_name}#{pr_number}")
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Check cache first
    cache_key = f"pr_insights:{repo_full_name}:{pr_number}"
    cached_insights = await cache.get(cache_key)
    if cached_insights:
        return cached_insights
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Get comprehensive insights
    from .pr_enhancements import pr_enhancement_engine
    
    try:
        insights = await pr_enhancement_engine.get_pr_security_insights(
            repo_full_name, pr_number, gh_token, db
        )
        
        # Cache for 10 minutes
        await cache.set(cache_key, insights, 600)
        
        return insights
        
    except Exception as e:
        import traceback
        logger.error(f"Failed to get PR insights: {e}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate security insights"
        )


def _can_issue_be_auto_fixed(issue) -> bool:
    """Check if an issue can be automatically fixed based on rule patterns"""
    # Handle both Issue objects and dictionaries
    rule_id = (issue.rule_id if hasattr(issue, 'rule_id') else issue.get('rule_id', '')).lower()
    message = (issue.message if hasattr(issue, 'message') else issue.get('message', '')).lower()
    severity = issue.severity if hasattr(issue, 'severity') else issue.get('severity', '')
    category = issue.category if hasattr(issue, 'category') else issue.get('category', '')
    
    # Define fixable patterns based on common security issues
    fixable_patterns = [
        # SQL injection patterns
        ("sql", "injection"),
        ("execute", "raw"),
        ("cursor.execute", "parameterized"),
        
        # Code injection patterns  
        ("eval", "user"),
        ("exec", "input"),
        
        # Command injection
        ("os.popen", "user"),
        ("system", "call"),
        
        # Debug mode issues
        ("debug=true", "production"),
        ("app.run", "debug"),
        
        # Hardcoded secrets (basic cases)
        ("hardcoded", "secret"),
        ("api_key", "environment"),
        
        # Unsafe deserialization
        ("pickle.loads", "unsafe"),
        ("yaml.load", "unsafe"),
    ]
    
    # Check if the issue matches any fixable pattern
    for pattern1, pattern2 in fixable_patterns:
        if (pattern1 in rule_id or pattern1 in message) and (pattern2 in rule_id or pattern2 in message):
            return True
    
    # Additional checks based on severity and category
    if severity in ["high", "critical"] and category in ["injection", "security", "code-injection"]:
        return True
    
    return False


@scans_router.post("/repos/{repo_full_name:path}/prs/{pr_number}/auto-fix")
async def create_pr_auto_fix(
    repo_full_name: str,
    pr_number: int,
    create_pr: bool = Query(True, description="Create a new PR with fixes"),
    use_queue: bool = Query(True, description="Use async queue to avoid timeouts (recommended for production)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Enhanced auto-fix using security tools to scan PR changes and generate targeted fixes
    
    This endpoint has been optimized with:
    - Async queue support to avoid platform timeout limits (60s on Cloud Run/Render)
    - 5-minute timeout for direct execution (when use_queue=false)
    - Better error handling for GitHub API issues
    - Detailed error messages for debugging
    """
    
    logger.info(f"Enhanced auto-fix request for {repo_full_name}#{pr_number} (use_queue={use_queue})")
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # If use_queue is enabled, queue the job and return immediately to avoid platform timeouts
    if use_queue:
        logger.info(f"Using async queue for PR auto-fix {repo_full_name}#{pr_number} to avoid 60s platform timeout")
        
        try:
            # Import queue manager
            from .autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager, AutofixPriority
            queue_manager = await get_enterprise_autofix_queue_manager()
            
            # Generate a unique job ID
            job_id = str(uuid.uuid4())
            
            # Queue the PR auto-fix job with high priority
            await queue_manager.queue_job(
                job_id=job_id,
                repo_full_name=repo_full_name,
                scan_data={
                    "pr_number": pr_number,
                    "type": "pr_autofix",
                    "create_pr": create_pr,
                    "approach": "enhanced_security_tools_v2"
                },
                gh_token=gh_token,
                create_pr=create_pr,
                priority=AutofixPriority.HIGH,  # PR fixes get high priority
                user_id=current_user.id
            )
            
            logger.info(f"PR auto-fix job {job_id} queued successfully for {repo_full_name}#{pr_number}")
            
            # Return immediately with job ID for status tracking
            return {
                "status": "processing",
                "job_id": job_id,
                "message": f"Auto-fix for PR #{pr_number} is processing in the background",
                "pr_number": pr_number,
                "repository": repo_full_name,
                "approach": "enhanced_security_tools_v2_async",
                "estimated_time": "30-120 seconds",
                "check_status_url": f"/autofix/jobs/{job_id}/status"
            }
            
        except Exception as e:
            logger.error(f"Failed to queue PR auto-fix job: {e}")
            # If queueing fails and we're in production, return error instead of falling back
            if os.getenv("APP_ENV", "development") == "production":
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Auto-fix service is temporarily unavailable. Please try again in a few moments."
                )
            # In development, fall back to direct execution
            logger.warning(f"Falling back to direct execution for PR auto-fix {repo_full_name}#{pr_number}")
    
    # Direct execution (when use_queue=false or in development fallback)
    try:
        # Use the Enhanced Auto-Fixer V2 with improved capabilities
        from .integrations.enhanced_auto_fixer_v2 import EnhancedAutoFixerV2
        enhanced_fixer = EnhancedAutoFixerV2()
        
        logger.info(f"Using enhanced auto-fix V2 system with caching, test generation, and dependency updates for PR #{pr_number}")
        
        # Add timeout to prevent hanging auto-fix requests
        import asyncio
        fix_result = await asyncio.wait_for(
            enhanced_fixer.apply_enhanced_fixes(
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                gh_token=gh_token,
                create_pr=create_pr,
                enable_caching=True,        # NEW: Use caching for performance
                generate_tests=True,        # NEW: Generate tests for fixes
                update_dependencies=True    # NEW: Update vulnerable dependencies
            ),
            timeout=300  # 5 minutes timeout for auto-fix
        )
        
        # Track issues as fixed if successful
        if fix_result.get("fixed_count", 0) > 0:
            try:
                from core.issue_tracking import IssueTrackingService
                issue_service = IssueTrackingService()
                
                # Extract PR number from fix_pr_url or use the original PR number
                fix_pr_number = pr_number
                if fix_result.get("pr_url"):
                    import re
                    pr_match = re.search(r'/pull/(\d+)', fix_result["pr_url"])
                    if pr_match:
                        fix_pr_number = int(pr_match.group(1))
                
                # For enhanced fixes, track the files that were fixed
                for file_path in fix_result.get("fixed_files", []):
                    # Create a generic hash for tracking fixed files
                    issue_hash = issue_service.generate_issue_hash(
                        file_path=file_path,
                        line_number=0,  # Enhanced fixer works on file level
                        rule_id="enhanced-auto-fix",
                        description=f"Enhanced security fixes applied to {file_path}",
                        repo_full_name=repo_full_name
                    )
                    
                    await issue_service.mark_issue_fixed_by_autofix(
                        session=db,
                        issue_hash=issue_hash,
                        pr_number=fix_pr_number,
                        repo_full_name=repo_full_name,
                        fix_content=f"Enhanced auto-fix applied to {file_path}",
                        confidence_score=0.90  # Higher confidence for tool-based fixes
                    )
                
                logger.info(f"Tracked enhanced auto-fix for {len(fix_result.get('fixed_files', []))} files in PR #{fix_pr_number}")
                
            except Exception as e:
                logger.error(f"Failed to track enhanced auto-fix: {e}")
                # Don't fail the process if tracking fails
        
        # Add enhanced V2 metadata to the response
        response = {
            "status": "success" if fix_result.get("fixed_count", 0) > 0 else "no_fixes",
            "approach": "enhanced_security_tools_v2_with_optimizations",
            "fixed_count": fix_result.get("fixed_count", 0),
            "issues_found": fix_result.get("issues_found", 0),
            "fixed_files": fix_result.get("fixed_files", []),
            "verification": fix_result.get("verification", {}),
            "security_score": fix_result.get("security_score", {}),  # NEW: Security scoring
            "metrics": fix_result.get("metrics", {}),  # NEW: Performance metrics
            "tests_generated": fix_result.get("tests_generated", []),  # NEW: Generated tests
            "dependencies_updated": fix_result.get("dependencies_updated", []),  # NEW: Updated deps
            "cached_results_used": fix_result.get("cached_results_used", False),  # NEW: Cache usage
            "message": fix_result.get("message", "Enhanced auto-fix V2 completed with optimizations")
        }
        
        if create_pr and fix_result.get("pr_url"):
            response["fix_pr_url"] = fix_result["pr_url"]
        
        return response
        
    except asyncio.TimeoutError:
        logger.error(f"Auto-fix timeout for {repo_full_name}#{pr_number}")
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Auto-fix operation timed out. The process may be complex or GitHub API is slow. Please try again or use the async auto-fix queue."
        )
    except ImportError as e:
        logger.error(f"Enhanced auto-fixer not available: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enhanced auto-fix service is temporarily unavailable. Please try again later."
        )
    except Exception as e:
        logger.error(f"Enhanced auto-fix failed: {e}", exc_info=True)
        # Provide more helpful error messages
        error_msg = str(e)
        if "rate limit" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="GitHub API rate limit exceeded during auto-fix. Please try again later."
            )
        elif "unauthorized" in error_msg.lower() or "403" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="GitHub authentication failed during auto-fix. Please reconnect your GitHub account."
            )
        elif "not found" in error_msg.lower() or "404" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Pull request #{pr_number} not found in repository {repo_full_name}"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Auto-fix failed: {error_msg}"
            )

async def _reconstruct_issues_from_summaries(scan_id: str, db: AsyncSession) -> List[Issue]:
    """Reconstruct all issues from scan summaries with compliance mappings"""
    
    # Get scan summaries
    result = await db.execute(
        select(ScanSummary).where(ScanSummary.scan_id == scan_id)
    )
    summaries = result.scalars().all()
    
    # Get compliance mappings
    compliance_result = await db.execute(
        select(ComplianceMapping).where(ComplianceMapping.scan_id == scan_id)
    )
    compliance_mappings = compliance_result.scalars().all()
    compliance_dict = {f"{m.owasp_category}_{m.cwe_id}": m for m in compliance_mappings}
    
    issues = []
    
    for summary in summaries:
        if summary.sample_issues:
            for issue in summary.sample_issues:
                # Generate a unique issue ID
                issue_id = str(uuid.uuid4())
                
                # Look up compliance mapping
                compliance_key = f"{issue.get('owasp_category')}_{issue.get('cwe_id')}"
                compliance = compliance_dict.get(compliance_key)
                
                # Convert code_context to proper format
                code_context = issue.get("code_context")
                if code_context and isinstance(code_context, dict):
                    # Extract context_lines if it exists and convert to Dict[str, str]
                    if "context_lines" in code_context and isinstance(code_context["context_lines"], list):
                        formatted_context = {}
                        for line in code_context["context_lines"]:
                            if isinstance(line, dict) and "line_number" in line and "content" in line:
                                formatted_context[str(line["line_number"])] = line["content"]
                        code_context = formatted_context
                    # Otherwise, convert all values to strings
                    else:
                        code_context = {str(k): str(v) for k, v in code_context.items() if k not in ["line_start", "line_end", "context_start", "context_end", "total_file_lines"]}
                else:
                    code_context = None
                
                # Handle CWE ID that might be a list or string
                cwe_id = issue.get("cwe_id")
                if isinstance(cwe_id, list):
                    cwe_id = cwe_id[0] if cwe_id else None
                cwe_id = str(cwe_id) if cwe_id else None
                
                issue_obj = Issue(
                    id=issue_id,
                    message=issue.get("message", "Security issue"),
                    line_start=issue.get("line_start"),
                    line_end=issue.get("line_end"),
                    severity=issue.get("severity", "medium"),
                    file_path=issue.get("file_path"),
                    category=summary.category,
                    tool=summary.tool_name,
                    rule_id=issue.get("rule_id"),
                    confidence=issue.get("confidence", "medium"),
                    owasp_category=issue.get("owasp_category"),
                    cwe_id=cwe_id,
                    code_context=code_context,
                    nist_id=compliance.nist_id if compliance else None,
                    pci_dss_id=compliance.pci_dss_id if compliance else None,
                    hipaa_id=compliance.hipaa_id if compliance else None,
                    gdpr_article=compliance.gdpr_article if compliance else None,
                    iso_27001_id=compliance.iso_27001_id if compliance else None
                )
                issues.append(issue_obj)
    
    return issues


@scans_router.post("/{scan_id}/auto-fix")
async def auto_fix_scan_issues(
    scan_id: str,
    create_pr: bool = Query(True, description="Create a PR with fixes"),
    severity_filter: List[str] = Query(["critical", "high", "medium"], description="Severities to fix"),
    use_queue: bool = Query(True, description="Use background queue (recommended to avoid timeouts)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Auto-fix security issues from a completed scan (with queue system to prevent timeouts)"""
    
    # If queue is requested (default), redirect to the async endpoint
    if use_queue:
        logger.info(f"Redirecting scan auto-fix to queue system for scan {scan_id}")
        
        # Use the async auto-fix system by calling the other endpoint logic
        return await start_async_auto_fix(
            scan_id=scan_id,
            create_pr=create_pr,
            severity_filter=severity_filter,
            db=db,
            current_user=current_user
        )
    
    logger.info(f"Scan auto-fix request for scan {scan_id} by user {current_user.id} (synchronous mode)")
    
    # Get scan details
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Verify user owns the repository
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == scan.repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access to scan"
        )
    
    # Check scan status
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan must be completed to apply auto-fix. Current status: {scan.status}"
        )
    
    # Get scan issues
    issues = await _reconstruct_issues_from_summaries(scan_id, db)
    
    if not issues:
        return {
            "status": "success",
            "scan_id": scan_id,
            "fixed_count": 0,
            "message": "No issues found in scan to fix"
        }
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    try:
        # Use the scan-specific auto-fixer
        from .integrations.scan_auto_fixer import ScanAutoFixer
        scan_fixer = ScanAutoFixer()
        
        logger.info(f"Using scan auto-fix for {len(issues)} issues from scan {scan_id}")
        
        # Prepare scan data
        scan_data = {
            "repo_full_name": scan.repo_full_name,
            "branch": scan.branch,
            "issues": [issue.model_dump() if hasattr(issue, 'model_dump') else issue for issue in issues],
            "metadata": {
                "pr_number": scan.pr_number,
                "commit_sha": scan.commit_sha,
                "scan_duration": scan.scan_duration,
                "tools_used": scan.tools_used or []
            }
        }
        
        # Apply fixes
        fix_result = await scan_fixer.apply_scan_fixes(
            scan_id=scan_id,
            scan_data=scan_data,
            gh_token=gh_token,
            create_pr=create_pr,
            severity_filter=severity_filter,
            db_session=db
        )
        
        # Track fixes if successful
        if fix_result.get("fixed_count", 0) > 0:
            try:
                from core.issue_tracking import IssueTrackingService
                issue_service = IssueTrackingService()
                
                # Extract PR number from fix_pr_url if created
                fix_pr_number = None
                if fix_result.get("pr_url"):
                    import re
                    pr_match = re.search(r'/pull/(\d+)', fix_result["pr_url"])
                    if pr_match:
                        fix_pr_number = int(pr_match.group(1))
                
                # Track fixed files
                for file_path in fix_result.get("fixed_files", []):
                    issue_hash = issue_service.generate_issue_hash(
                        file_path=file_path,
                        line_number=0,
                        rule_id="scan-auto-fix",
                        description=f"Scan auto-fix applied to {file_path}",
                        repo_full_name=scan.repo_full_name
                    )
                    
                    await issue_service.mark_issue_fixed_by_autofix(
                        session=db,
                        issue_hash=issue_hash,
                        pr_number=fix_pr_number,
                        repo_full_name=scan.repo_full_name,
                        fix_content=f"Auto-fix from scan {scan_id}",
                        confidence_score=0.85
                    )
                
                logger.info(f"Tracked scan auto-fix for {len(fix_result.get('fixed_files', []))} files")
                
            except Exception as e:
                logger.error(f"Failed to track scan auto-fix: {e}")
                # Don't fail the process if tracking fails
        
        return fix_result
        
    except Exception as e:
        logger.error(f"Scan auto-fix failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Auto-fix failed: {str(e)}"
        )


# Auto-fix Queue System Endpoints

@scans_router.post("/{scan_id}/auto-fix-async")
async def start_async_auto_fix(
    scan_id: str,
    create_pr: bool = Query(True, description="Create a PR with fixes"),
    severity_filter: List[str] = Query(["critical", "high", "medium"], description="Severities to fix"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start an async auto-fix job for a completed scan"""
    
    logger.info(f"Async auto-fix request for scan {scan_id} by user {current_user.id}")
    
    # Get scan details
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Verify user access to the repository
    repo_result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == scan.repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = repo_result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found or access denied"
        )
    
    # Check scan status
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan must be completed to apply auto-fix. Current status: {scan.status}"
        )
    
    # Get scan issues
    issues = await _reconstruct_issues_from_summaries(scan_id, db)
    
    if not issues:
        return {
            "status": "no_issues",
            "message": "No security issues found in this scan to fix"
        }
    
    # Get user's GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    try:
        # CRITICAL FIX: Ensure autofix workers are available BEFORE queueing job
        logger.debug(f"Starting worker availability check for autofix job {scan_id}")
        from .autofix_queue.on_demand_manager import ensure_autofix_workers_available
        
        logger.debug(f"Calling ensure_autofix_workers_available for job {scan_id}")
        # Wait for workers to be ready before queueing the job
        # Use the critical context to force worker startup and wait for activation
        workers_ready = await ensure_autofix_workers_available("autofix_job")
        
        if not workers_ready:
            logger.debug(f"Autofix workers failed to start for job {scan_id}, proceeding anyway")
        else:
            logger.debug(f"Autofix workers confirmed ready for job {scan_id}")
        
        logger.debug(f"About to queue autofix job {scan_id} (workers_ready={workers_ready})")
        
        # CRITICAL FIX: Use enterprise autofix queue manager for consistency with workers
        from .autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager, AutofixPriority
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        # Prepare scan data for the job
        scan_data = {
            "repo_full_name": scan.repo_full_name,
            "branch": scan.branch,
            "issues": [
                {
                    "rule_id": issue.rule_id,
                    "severity": issue.severity,
                    "message": issue.message,
                    "file_path": issue.file_path,
                    "line_start": issue.line_start,
                    "line_end": issue.line_end,
                    "code_snippet": issue.code_context.get("snippet") if issue.code_context else None,
                    "tool": issue.tool
                } for issue in issues
            ],
            "metadata": {
                "commit_sha": scan.commit_sha,
                "pr_number": scan.pr_number
            }
        }
        
        # Prepare autofix job data
        autofix_data = {
            "scan_data": scan_data,
            "create_pr": create_pr,
            "severity_filter": severity_filter,
            "gh_token": gh_token
        }
        
        # Enqueue the job
        job_id = await queue_manager.enqueue_autofix_job(
            scan_id=scan_id,
            user_id=current_user.id,
            repo_full_name=scan.repo_full_name,
            autofix_data=autofix_data,
            priority=AutofixPriority.HIGH,
            db=db
        )
        
        return {
            "status": "queued",
            "job_id": job_id,
            "scan_id": scan_id,
            "issues_found": len(issues),
            "filtered_issues": len([
                issue for issue in issues 
                if issue.severity.lower() in [s.lower() for s in severity_filter]
            ]),
            "message": f"Auto-fix job queued successfully. Job ID: {job_id}",
            "estimated_duration": "5-30 minutes"
        }
        
    except Exception as e:
        logger.error(f"Failed to queue auto-fix job: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to queue auto-fix job: {str(e)}"
        )


@scans_router.post("/{scan_id}/autofix-job")
async def trigger_autofix_job(
    scan_id: str,
    create_pr: bool = Query(True, description="Create a PR with fixes"),
    severity_filter: List[str] = Query(["critical", "high", "medium"], description="Severities to fix"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Start an autofix job for a completed scan - restored prod-release UX"""
    
    logger.info(f"Autofix job request for scan {scan_id} by user {current_user.id}")
    
    # Get scan details
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Verify user access to the repository
    repo_result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == scan.repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = repo_result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository not found or access denied"
        )
    
    # Check scan status
    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan must be completed to apply auto-fix. Current status: {scan.status}"
        )
    
    # Get scan issues
    issues = await _reconstruct_issues_from_summaries(scan_id, db)
    
    if not issues:
        return {
            "success": True,
            "status": "no_issues",
            "message": "No security issues found in this scan to fix",
            "job_id": None,
            "scan_id": scan_id,
            "issues_found": 0,
            "filtered_issues": 0
        }
    
    # Get user's GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token for user {current_user.id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    try:
        # Ensure autofix workers are available
        logger.info(f"Starting worker availability check for autofix job {scan_id}")
        from .autofix_queue.on_demand_manager import ensure_autofix_workers_available
        
        # Wait for workers to be ready before queueing the job
        workers_ready = await ensure_autofix_workers_available("autofix_job")
        
        if not workers_ready:
            logger.error(f"Autofix workers failed to start for job {scan_id}, proceeding anyway")
        else:
            logger.info(f"Autofix workers confirmed ready for job {scan_id}")
        
        # CRITICAL FIX: Use enterprise autofix queue manager for consistency with workers
        from .autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager, AutofixPriority
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        # Prepare scan data for the job
        scan_data = {
            "repo_full_name": scan.repo_full_name,
            "branch": scan.branch,
            "issues": [
                {
                    "rule_id": issue.rule_id,
                    "severity": issue.severity,
                    "message": issue.message,
                    "file_path": issue.file_path,
                    "line_start": issue.line_start,
                    "line_end": issue.line_end,
                    "code_snippet": issue.code_context.get("snippet") if issue.code_context else None,
                    "tool": issue.tool
                } for issue in issues
            ],
            "metadata": {
                "commit_sha": scan.commit_sha,
                "pr_number": scan.pr_number
            }
        }
        
        # Prepare autofix job data
        autofix_data = {
            "scan_data": scan_data,
            "create_pr": create_pr,
            "severity_filter": severity_filter,
            "gh_token": gh_token
        }
        
        # Enqueue the job
        job_id = await queue_manager.enqueue_autofix_job(
            scan_id=scan_id,
            user_id=current_user.id,
            repo_full_name=scan.repo_full_name,
            autofix_data=autofix_data,
            priority=AutofixPriority.HIGH,
            db=db
        )
        
        # Return complete data structure expected by frontend
        return {
            "success": True,
            "status": "queued",
            "job_id": job_id,
            "scan_id": scan_id,
            "issues_found": len(issues),
            "filtered_issues": len([
                issue for issue in issues 
                if issue.severity.lower() in [s.lower() for s in severity_filter]
            ]),
            "message": f"Auto-fix job queued successfully. Job ID: {job_id}",
            "estimated_duration": "5-30 minutes",
            "queue_position": 1,
            "progress": {
                "percentage": 0,
                "stage": "Initializing auto-fix job...",
                "stage_number": 1,
                "total_stages": 11
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to queue auto-fix job: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to queue auto-fix job: {str(e)}"
        )


@scans_router.get("/autofix-jobs/{job_id}/status")
async def get_autofix_job_status(
    job_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get status and progress of an auto-fix job"""
    
    logger.info(f"🔍 ROUTE DEBUG: get_autofix_job_status called for job_id={job_id}, user={current_user.username}")
    
    try:
        # CRITICAL FIX: Use enterprise autofix queue manager - same as job creation and processing
        from .autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        job_status = await queue_manager.get_job_status(job_id)
        
        if not job_status:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Auto-fix job not found"
            )
        
        # Return the data directly from the queue manager (already properly formatted)
        return job_status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get auto-fix job status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get job status: {str(e)}"
        )


@scans_router.delete("/autofix-jobs/{job_id}")
async def cancel_autofix_job(
    job_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Cancel an auto-fix job"""
    
    try:
        from .autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        cancelled = await queue_manager.cancel_job(job_id, db)
        
        if not cancelled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Auto-fix job not found or cannot be cancelled"
            )
        
        return {
            "status": "cancelled",
            "job_id": job_id,
            "message": "Auto-fix job cancelled successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel auto-fix job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel job: {str(e)}"
        )


@scans_router.get("/autofix-jobs")
async def list_user_autofix_jobs(
    limit: int = Query(10, ge=1, le=50, description="Number of jobs to return"),
    current_user: User = Depends(get_current_user)
):
    """Get user's auto-fix jobs"""
    
    try:
        from .autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        jobs = await queue_manager.get_user_jobs(current_user.id, limit)
        
        return {
            "jobs": jobs,
            "total": len(jobs),
            "user_id": current_user.id
        }
        
    except Exception as e:
        logger.error(f"Failed to get user auto-fix jobs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get jobs: {str(e)}"
        )


@scans_router.get("/autofix-queue/stats")
async def get_autofix_queue_stats(
    current_user: User = Depends(get_current_user)
):
    """Get auto-fix queue statistics"""
    
    try:
        from .autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager
        queue_manager = await get_enterprise_autofix_queue_manager()
        
        stats = await queue_manager.get_queue_stats()
        
        return {
            "queue_stats": stats,
            "timestamp": utc_now_iso()
        }
        
    except Exception as e:
        logger.error(f"Failed to get auto-fix queue stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get queue stats: {str(e)}"
        )


# Auto-fix Worker Management Endpoints (On-Demand System)

@scans_router.post("/autofix-workers/start")
async def start_autofix_workers(
    current_user: User = Depends(get_current_user)
):
    """Manually start on-demand auto-fix workers"""
    
    try:
        from .autofix_queue.on_demand_manager import ensure_autofix_workers_available
        
        success = await ensure_autofix_workers_available("manual_start")
        
        if success:
            return {
                "status": "success",
                "message": "Auto-fix workers started successfully",
                "timestamp": utc_now_iso()
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to start auto-fix workers"
            )
        
    except Exception as e:
        logger.error(f"Failed to start auto-fix workers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start workers: {str(e)}"
        )


@scans_router.post("/autofix-workers/stop")
async def stop_autofix_workers(
    current_user: User = Depends(get_current_user)
):
    """Manually stop on-demand auto-fix workers (admin only)"""
    
    # Restrict to admin users for manual stops
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    try:
        from .autofix_queue.on_demand_manager import stop_autofix_workers_if_idle
        
        success = await stop_autofix_workers_if_idle("manual_stop")
        
        if success:
            return {
                "status": "success",
                "message": "Auto-fix workers stopped successfully",
                "timestamp": utc_now_iso()
            }
        else:
            return {
                "status": "info",
                "message": "Auto-fix workers were not running or already stopped",
                "timestamp": utc_now_iso()
            }
        
    except Exception as e:
        logger.error(f"Failed to stop auto-fix workers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop workers: {str(e)}"
        )


@scans_router.get("/autofix-workers/status")
async def get_autofix_workers_status(
    current_user: User = Depends(get_current_user)
):
    """Get status of on-demand auto-fix workers"""
    
    try:
        from .autofix_queue.on_demand_manager import get_autofix_workers_status
        
        worker_status = get_autofix_workers_status()
        return worker_status
        
    except Exception as e:
        logger.error(f"Failed to get auto-fix workers status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get workers status: {str(e)}"
        )


@scans_router.get("/autofix-workers/health")
async def get_autofix_workers_health(
    current_user: User = Depends(get_current_user)
):
    """Get health status of on-demand auto-fix workers"""
    
    try:
        from .autofix_queue.on_demand_manager import get_autofix_workers_health
        
        health = await get_autofix_workers_health()
        return health
        
    except Exception as e:
        logger.error(f"Failed to get auto-fix workers health: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get workers health: {str(e)}"
        )


@scans_router.post("/autofix-workers/restart")
async def restart_autofix_workers(
    current_user: User = Depends(get_current_user)
):
    """Restart on-demand auto-fix workers (admin only)"""
    
    # Restrict to admin users
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    try:
        from .autofix_queue.on_demand_manager import restart_autofix_workers
        
        success = await restart_autofix_workers("api_restart")
        
        if success:
            return {
                "status": "success",
                "message": "Auto-fix workers restarted successfully",
                "timestamp": utc_now_iso()
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to restart workers"
            )
        
    except Exception as e:
        logger.error(f"Failed to restart auto-fix workers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to restart workers: {str(e)}"
        )


@scans_router.post("/autofix-workers/scale")
async def scale_autofix_workers(
    worker_count: int = Query(..., ge=1, le=10, description="Number of workers to scale to"),
    current_user: User = Depends(get_current_user)
):
    """Scale auto-fix workers (admin only) - NOTE: On-demand system manages worker scaling automatically"""
    
    # Restrict to admin users
    if not getattr(current_user, 'is_admin', False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # For on-demand system, scaling is handled automatically
    # This endpoint is kept for compatibility but returns a message about the new system
    return {
        "status": "info",
        "message": "On-demand autofix system manages worker scaling automatically. Workers start when needed and stop when idle.",
        "requested_worker_count": worker_count,
        "system_type": "on_demand",
        "timestamp": utc_now_iso()
    }


@scans_router.get("/custom-rules/integration-status")
async def get_custom_rules_integration_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get custom rules integration status and capabilities"""
    
    try:
        # Import here to avoid circular imports
        from .services.custom_rules_integration import CustomRulesIntegration
        from .config.rules_config import RulesConfig
        
        integration_service = CustomRulesIntegration(db)
        
        # Get user's custom rules count
        user_rules_query = text("SELECT COUNT(*) FROM community_rules WHERE author_id = :user_id")
        result = await db.execute(user_rules_query, {"user_id": current_user.id})
        user_rules_count = result.scalar()
        
        # Get community rules count  
        community_rules_query = text("SELECT COUNT(*) FROM community_rules WHERE is_public = true AND upvotes >= 5")
        result = await db.execute(community_rules_query)
        community_rules_count = result.scalar()
        
        # Get supported tools
        supported_tools = RulesConfig.get_tools_supporting_custom_rules()
        
        return {
            "status": "operational",
            "integration_complete": True,
            "user_custom_rules_count": user_rules_count,
            "community_rules_count": community_rules_count,
            "supported_tools": list(supported_tools.keys()),
            "supported_niches": list(RulesConfig.NICHE_RULES_MAP.keys()),
            "features": {
                "scan_with_custom_rules": True,
                "scan_with_community_rules": True,
                "rule_validation": True,
                "rule_testing": True,
                "performance_optimized": True
            },
            "api_endpoints": {
                "trigger_scan_with_custom_rules": "POST /scans/",
                "pr_scan_with_custom_rules": "POST /scans/repos/{repo}/prs/{pr_number}/scan",
                "custom_rules_management": "GET/POST/PUT/DELETE /scans/rules/",
                "rule_testing": "POST /scans/rules/test"
            },
            "next_steps": [
                "Create custom rules via POST /scans/rules/",
                "Test rules using POST /scans/rules/test",
                "Include custom rules in scans using include_custom_rules=true parameter",
                "Monitor custom rules usage in scan metadata"
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting integration status: {str(e)}")
        return {
            "status": "error",
            "integration_complete": False,
            "error": str(e)
        }

@scans_router.get("/repos/{repo_full_name:path}/debug-scans")
async def debug_scan_data(
    repo_full_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Debug endpoint to inspect scan data"""
    
    # Get recent scans with all relevant fields
    debug_query = text("""
        SELECT id, repo_full_name, pr_number, scan_type, branch, created_at
        FROM scans 
        WHERE repo_full_name = :repo_name 
        ORDER BY created_at DESC 
        LIMIT 20
    """)
    result = await db.execute(debug_query, {"repo_name": repo_full_name})
    scans = [dict(row._mapping) for row in result]
    
    # Count PR scans by different criteria
    pr_by_number_query = text("SELECT COUNT(*) FROM scans WHERE repo_full_name = :repo_name AND pr_number IS NOT NULL")
    pr_by_type_query = text("SELECT COUNT(*) FROM scans WHERE repo_full_name = :repo_name AND scan_type = 'pr'")
    pr_by_either_query = text("SELECT COUNT(*) FROM scans WHERE repo_full_name = :repo_name AND (pr_number IS NOT NULL OR scan_type = 'pr')")
    
    pr_by_number = (await db.execute(pr_by_number_query, {"repo_name": repo_full_name})).scalar()
    pr_by_type = (await db.execute(pr_by_type_query, {"repo_name": repo_full_name})).scalar()
    pr_by_either = (await db.execute(pr_by_either_query, {"repo_name": repo_full_name})).scalar()
    
    return {
        "recent_scans": scans,
        "pr_count_by_number": pr_by_number,
        "pr_count_by_type": pr_by_type,
        "pr_count_by_either": pr_by_either
    }

@scans_router.get("/repos/{repo_full_name:path}/security-trends")
async def get_repository_security_trends(
    repo_full_name: str,
    days: int = Query(30, ge=7, le=90, description="Number of days to analyze"),
    branch: str = Query("main", description="Branch to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get security trend analysis for a repository"""
    
    # Verify repository access
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # DEBUG: Check actual PR scan data in database
    debug_query = text("""
        SELECT id, repo_full_name, pr_number, scan_type, created_at
        FROM scans 
        WHERE repo_full_name = :repo_name 
        ORDER BY created_at DESC 
        LIMIT 10
    """)
    debug_result = await db.execute(debug_query, {"repo_name": repo_full_name})
    debug_scans = [dict(row._mapping) for row in debug_result]
    logger.info(f"DEBUG - Recent scans for {repo_full_name}: {debug_scans}")
    
    # Simplified query for just the counts we need
    cutoff_date = utc_now() - timedelta(days=days)
    
    summary_query = text("""
        SELECT 
            COUNT(*) as total_scans,
            SUM(CASE WHEN (pr_number IS NOT NULL OR scan_type = 'pr') THEN 1 ELSE 0 END) as total_pr_scans
        FROM scans
        WHERE repo_full_name = :repo_name
            AND created_at > :cutoff_date
            AND (:branch = 'all' OR branch = :branch)
    """)
    
    result = await db.execute(summary_query, {
        "repo_name": repo_full_name,
        "cutoff_date": cutoff_date,
        "branch": branch
    })
    summary_row = result.fetchone()
    
    # Get top 3 issues only (most critical first)
    issue_query = text("""
        SELECT 
            ss.category,
            CASE 
                WHEN ss.critical_count > 0 THEN 'critical'
                WHEN ss.high_count > 0 THEN 'high'
                WHEN ss.medium_count > 0 THEN 'medium'
                ELSE 'low'
            END as severity,
            SUM(ss.total_issues) as count
        FROM scans s
        JOIN scan_summaries ss ON s.id = ss.scan_id
        WHERE s.repo_full_name = :repo_name
            AND s.created_at > :cutoff_date
            AND ss.total_issues > 0
        GROUP BY ss.category, 
            CASE 
                WHEN ss.critical_count > 0 THEN 'critical'
                WHEN ss.high_count > 0 THEN 'high'
                WHEN ss.medium_count > 0 THEN 'medium'
                ELSE 'low'
            END
        ORDER BY 
            CASE 
                WHEN (CASE 
                    WHEN ss.critical_count > 0 THEN 'critical'
                    WHEN ss.high_count > 0 THEN 'high'
                    WHEN ss.medium_count > 0 THEN 'medium'
                    ELSE 'low'
                END) = 'critical' THEN 1
                WHEN (CASE 
                    WHEN ss.critical_count > 0 THEN 'critical'
                    WHEN ss.high_count > 0 THEN 'high'
                    WHEN ss.medium_count > 0 THEN 'medium'
                    ELSE 'low'
                END) = 'high' THEN 2  
                WHEN (CASE 
                    WHEN ss.critical_count > 0 THEN 'critical'
                    WHEN ss.high_count > 0 THEN 'high'
                    WHEN ss.medium_count > 0 THEN 'medium'
                    ELSE 'low'
                END) = 'medium' THEN 3
                ELSE 4
            END, count DESC
        LIMIT 3
    """)
    
    issue_result = await db.execute(issue_query, {
        "repo_name": repo_full_name, 
        "cutoff_date": cutoff_date
    })
    
    top_issues = [
        {
            "category": row.category,
            "severity": row.severity,
            "count": row.count
        }
        for row in issue_result
    ]

    return {
        "repository": repo_full_name,
        "period_days": days,
        "trend_summary": {
            "total_scans": summary_row.total_scans or 0,
            "total_pr_scans": summary_row.total_pr_scans or 0,
        },
        "top_issues": top_issues
    }


# Removed broken GitHub Checks endpoint - using PR comments instead


@scans_router.post("/repos/{repo_full_name:path}/prs/{pr_number}/github-check")
async def create_pr_github_check(
    repo_full_name: str,
    pr_number: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create GitHub security analysis as PR comment"""
    
    logger.info(f"GitHub security analysis comment for {repo_full_name}#{pr_number}")
    
    # Verify repository access (same as checks endpoint)
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == repo_full_name, Repo.user_id == current_user.id)
        )
    )
    repo = result.scalar_one_or_none()
    
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Repository not connected or unauthorized"
        )
    
    # Get latest scan for this PR
    scan_result = await db.execute(
        select(Scan).where(
            and_(
                Scan.repo_full_name == repo_full_name,
                Scan.pr_number == pr_number,
                Scan.status == "completed"
            )
        ).order_by(Scan.created_at.desc()).limit(1)
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No completed scan found for this PR"
        )
    
    # Decrypt GitHub token
    try:
        gh_token = decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication error"
        )
    
    # Use PR comment instead of GitHub Checks
    from .integrations.github_integration import GitHubIntegration
    github_integration = GitHubIntegration()
    
    scan_details = await get_scan_details(scan.id, True, db, current_user)
    
    try:
        comment_url = await github_integration.post_pr_comment_async(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            scan_result={
                "total_score": scan_details.total_score,
                "issues": [issue.model_dump() for issue in scan_details.issues],
                "metadata": {"scan_duration": scan_details.metadata.get("scan_duration", 0)}
            },
            gh_token=gh_token,
            scan_id=scan.id
        )
        
        return {
            "status": "success",
            "type": "pr_comment",
            "comment_url": comment_url,
            "message": "Security analysis posted as PR comment"
        }
        
    except Exception as e:
        logger.error(f"Failed to create PR comment fallback: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create fallback comment: {str(e)}"
        )


