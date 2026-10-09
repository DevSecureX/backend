import hmac
import hashlib
import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from repos.models import Repo
from scans.unified_queue import get_unified_queue_manager, UnifiedJobPriority

logger = logging.getLogger(__name__)

webhooks_router = APIRouter(prefix="/webhook", tags=["webhooks"])

class WebhookSecurity:
    def __init__(self, webhook_secret: str):
        self.webhook_secret = webhook_secret.encode() if webhook_secret else None
    
    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verify GitHub webhook signature with timing attack protection"""
        if not self.webhook_secret:
            logger.error("Webhook secret not configured")
            return False
            
        if not signature or not isinstance(signature, str):
            logger.warning("Missing or invalid signature header")
            return False
            
        if not signature.startswith('sha256='):
            logger.warning("Invalid signature format - missing sha256= prefix")
            return False
            
        if len(signature) != 71:  # sha256= (7) + 64 hex chars
            logger.warning("Invalid signature length")
            return False
            
        try:
            expected_sig = hmac.new(
                self.webhook_secret,
                payload,
                hashlib.sha256
            ).hexdigest()
            
            received_sig = signature[7:]  # Remove 'sha256=' prefix
            
            # Use constant-time comparison to prevent timing attacks
            is_valid = hmac.compare_digest(expected_sig, received_sig)
            
            if not is_valid:
                logger.warning("Webhook signature verification failed")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Error during signature verification: {e}")
            return False

# Initialize webhook security
import os
webhook_security = WebhookSecurity(os.getenv("GITHUB_WEBHOOK_SECRET"))

@webhooks_router.post("/github")
async def handle_github_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Handle GitHub webhook events"""
    
    try:
        body = await request.body()
        signature = request.headers.get("X-Hub-Signature-256", "")
        event_type = request.headers.get("X-GitHub-Event", "")
        delivery_id = request.headers.get("X-GitHub-Delivery", "")
        
        logger.info(f"Received GitHub webhook: {event_type} (delivery: {delivery_id})")
        
        if not webhook_security.verify_signature(body, signature):
            logger.warning(f"Invalid webhook signature for delivery {delivery_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid webhook signature"
            )
        
        payload = json.loads(body.decode('utf-8'))
        
        if event_type == "pull_request":
            await handle_pull_request_event(payload, db)
        elif event_type == "push":
            await handle_push_event(payload, db)
        elif event_type == "ping":
            logger.info("Received GitHub ping event")
        else:
            logger.info(f"Ignoring unsupported event type: {event_type}")
        
        return {"status": "success", "event": event_type}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook processing failed"
        )

async def handle_pull_request_event(payload: dict, db: AsyncSession):
    """Handle pull request webhook events"""
    
    action = payload.get("action")
    
    if action not in ["opened", "synchronize", "reopened"]:
        logger.info(f"Ignoring PR action: {action}")
        return
    
    pr = payload.get("pull_request", {})
    repository = payload.get("repository", {})
    
    repo_full_name = repository.get("full_name")
    pr_number = pr.get("number")
    commit_sha = pr.get("head", {}).get("sha")
    branch = pr.get("head", {}).get("ref")
    
    if not all([repo_full_name, pr_number, commit_sha, branch]):
        logger.warning("Missing required PR data in webhook payload")
        return
    
    logger.info(f"Processing PR {action} for {repo_full_name}#{pr_number}")
    
    repo_data = await get_connected_repo(repo_full_name, db)
    if not repo_data:
        logger.info(f"Repository {repo_full_name} not connected, skipping scan")
        return
    
    # Check if auto_scan_prs is enabled
    result = await db.execute(
        select(Repo.auto_scan_prs).where(Repo.full_name == repo_full_name)
    )
    auto_scan_prs = result.scalar_one_or_none()
    if not auto_scan_prs:
        logger.info(f"Auto-scanning disabled for {repo_full_name}, skipping PR scan")
        return
    
    # Use unified queue manager for direct scan processing
    queue_manager = await get_unified_queue_manager()
    
    # MAXIMUM SECURITY COVERAGE: All webhook scans use comprehensive mode and full scope
    scan_config = {
        "action": "pr_scan",
        "repository": repo_full_name,
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "branch": branch,
        "mode": "comprehensive",  # ALWAYS comprehensive mode for webhook scans
        "scope": "full",  # ALWAYS full scope: code + dependencies + infrastructure
        "gh_token": repo_data["gh_token"],
        "niche": repo_data["niche"],
        "triggered_by": "github_webhook",
        "webhook_event": "pull_request"
    }
    
    # Directly enqueue scan using unified queue system
    job_id = await queue_manager.enqueue_scan(
        repo_full_name=repo_full_name,
        user_id=repo_data["user_id"],
        scan_type="pr_scan",
        scan_config=scan_config,
        priority=UnifiedJobPriority.HIGH
    )
    
    logger.info(f"Queued PR scan job {job_id} for {repo_full_name}#{pr_number}")

async def handle_push_event(payload: dict, db: AsyncSession):
    """Handle push webhook events"""
    
    repository = payload.get("repository", {})
    ref = payload.get("ref", "")
    commits = payload.get("commits", [])

    repo_full_name = repository.get("full_name")

    # Accept pushes to ALL branches (removed branch restriction)
    if not ref.startswith("refs/heads/"):
        logger.info(f"Ignoring non-branch ref: {ref}")
        return

    if not commits:
        logger.info("No commits in push event, skipping scan")
        return
    
    branch = ref.replace("refs/heads/", "")
    commit_sha = payload.get("after")
    
    logger.info(f"Processing push to {repo_full_name}:{branch}")
    
    repo_data = await get_connected_repo(repo_full_name, db)
    if not repo_data:
        logger.info(f"Repository {repo_full_name} not connected, skipping scan")
        return
    
    # Use unified queue manager for direct scan processing  
    queue_manager = await get_unified_queue_manager()
    
    # MAXIMUM SECURITY COVERAGE: All webhook scans use comprehensive mode and full scope
    scan_config = {
        "action": "push_scan",
        "repository": repo_full_name,
        "branch": branch,
        "commit_sha": commit_sha,
        "mode": "comprehensive",  # ALWAYS comprehensive mode for webhook scans
        "scope": "full",  # ALWAYS full scope: code + dependencies + infrastructure
        "gh_token": repo_data["gh_token"],
        "niche": repo_data["niche"],
        "commit_count": len(commits),
        "triggered_by": "github_webhook",
        "webhook_event": "push"
    }
    
    # Directly enqueue scan using unified queue system
    job_id = await queue_manager.enqueue_scan(
        repo_full_name=repo_full_name,
        user_id=repo_data["user_id"],
        scan_type="push_scan",
        scan_config=scan_config,
        priority=UnifiedJobPriority.NORMAL
    )
    
    logger.info(f"Queued push scan job {job_id} for {repo_full_name}:{branch}")

async def get_connected_repo(repo_full_name: str, db: AsyncSession) -> Optional[dict]:
    """Get connected repository data"""
    try:
        from auth.models import User
        from auth.dependencies import decrypt_token
        
        result = await db.execute(
            select(Repo, User)
            .join(User, Repo.user_id == User.id)
            .where(Repo.full_name == repo_full_name)
        )
        
        repo_user = result.first()
        if not repo_user:
            return None
        
        repo, user = repo_user
        
        try:
            gh_token = decrypt_token(user.github_access_token)
        except Exception as e:
            logger.error(f"Failed to decrypt GitHub token for user {user.id}: {e}")
            return None
        
        return {
            "user_id": user.id,
            "gh_token": gh_token,
            "niche": repo.niche,
            "repo_name": repo.full_name
        }
        
    except Exception as e:
        logger.error(f"Error getting connected repo data: {e}")
        return None