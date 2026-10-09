from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, validator, Field
from github import Github, GithubException, RateLimitExceededException, ContentFile, UnknownObjectException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, delete, update, and_, func
import json
import os
import logging
import re
from typing import List, Optional, Dict, Set, Union, Any
from datetime import datetime, timezone

from core.database import get_db
from core.utils import format_datetime_response, utc_now
# Import redis_client lazily to avoid production connections
from auth.dependencies import get_current_user, decrypt_token
from auth.models import User
from repos.models import Repo
from scans.models import Scan

logger = logging.getLogger(__name__)

repos_router = APIRouter(prefix="/repos", tags=["repos"])

# Configuration
USE_MOCK_WEBHOOKS = os.getenv("USE_MOCK_WEBHOOKS", "true").lower() == "true"
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "http://localhost:8010/webhook")
RATE_LIMIT_KEY_PREFIX = "rate:repos:"
RATE_LIMIT_MAX = int(os.getenv("REPOS_RATE_LIMIT_MAX", "10"))
RATE_LIMIT_TTL = int(os.getenv("REPOS_RATE_LIMIT_TTL", "3600"))
REPOS_CACHE_TTL = int(os.getenv("REPOS_CACHE_TTL", "300"))
MAX_SAMPLE_CONTENT_LENGTH = 500
ALLOWED_NICHES = {"all", "ai", "blockchain", "iot", "web3", "cloud", "api"}

# Enhanced validation patterns with security considerations
GITHUB_REPO_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,38}[a-zA-Z0-9])?/[a-zA-Z0-9]([a-zA-Z0-9._-]{0,98}[a-zA-Z0-9])?$')
BRANCH_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9._/-]{0,248}[a-zA-Z0-9])?$')

# Security: Reject dangerous patterns
DANGEROUS_PATTERNS = [
    r'\.\./',  # Path traversal
    r'/\.\.',  # Path traversal
    r'[\x00-\x1f\x7f]',  # Control characters
    r'[<>:"|?*]',  # Invalid filename characters
]
DANGEROUS_REGEX = re.compile('|'.join(DANGEROUS_PATTERNS))

class RepoConnectRequest(BaseModel):
    full_name: str = Field(..., min_length=3, max_length=255, description="GitHub repository full name")
    niche: str = Field(..., min_length=2, max_length=50, description="Repository niche")

    @validator("full_name")
    def validate_full_name(cls, v: str) -> str:
        v = v.strip()
        
        # Security: Check for dangerous patterns first
        if DANGEROUS_REGEX.search(v):
            raise ValueError("Repository name contains invalid or dangerous characters")
        
        if not GITHUB_REPO_PATTERN.match(v):
            raise ValueError("Invalid repository name format. Expected: owner/repo")
        if v.count('/') != 1:
            raise ValueError("Repository name must contain exactly one forward slash")
            
        owner, repo = v.split('/')
        if len(owner) < 1 or len(repo) < 1:
            raise ValueError("Owner and repository names cannot be empty")
        if len(owner) > 39 or len(repo) > 100:
            raise ValueError("Owner or repository name exceeds maximum length")
            
        # Additional security checks
        if owner.startswith('.') or repo.startswith('.'):
            raise ValueError("Owner and repository names cannot start with dots")
        if owner.endswith('.') or repo.endswith('.'):
            raise ValueError("Owner and repository names cannot end with dots")
            
        return v

    @validator("niche")
    def validate_niche(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in ALLOWED_NICHES:
            raise ValueError(f"Invalid niche. Must be one of: {', '.join(ALLOWED_NICHES)}")
        return v

class RepoResponse(BaseModel):
    id: int
    full_name: str
    niche: str
    settings: Dict
    webhook_id: Optional[int]
    default_branch: Optional[str]
    is_private: Optional[str]
    language: Optional[str]
    description: Optional[str]
    status: str
    created_at: str
    updated_at: str
    last_synced: Optional[str] = None

class RepoDisconnectRequest(BaseModel):
    full_name: str = Field(..., min_length=3, max_length=255)

    @validator("full_name")
    def validate_full_name(cls, v: str) -> str:
        v = v.strip()
        if not GITHUB_REPO_PATTERN.match(v):
            raise ValueError("Invalid repository name format")
        return v

class CodeAccessResponse(BaseModel):
    full_name: str
    branch: str
    sample_content: Dict[str, str]
    latest_commit: Dict[str, str]
    message: str
    accessed_at: str

class BranchesResponse(BaseModel):
    full_name: str
    branches: List[str]
    default_branch: str
    total_count: int

class RepositoryAttentionItem(BaseModel):
    repo_name: str
    critical_issues: int
    high_issues: int
    reason: str

class RepositoryStatsResponse(BaseModel):
    total_repositories: int
    active_repositories: int
    repositories_needing_attention: int
    repositories_needing_attention_details: List[RepositoryAttentionItem]
    total_issues_found: int
    repositories_by_status: Dict[str, int]
    repositories_by_language: Dict[str, int]
    repositories_by_niche: Dict[str, int]
    active_scans: int
    completed_scans: int
    critical_issues: int

async def check_rate_limit(user_id: int) -> None:
    """Check and enforce rate limiting for repository operations."""
    # Use RateLimitCache which has production protection built-in
    from core.cache import RateLimitCache
    rate_key = f"{RATE_LIMIT_KEY_PREFIX}{user_id}"
    try:
        current_rate = await RateLimitCache.increment_counter(rate_key, RATE_LIMIT_TTL)
        if current_rate > RATE_LIMIT_MAX:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {RATE_LIMIT_MAX} requests per hour."
            )
    except Exception as e:
        logger.error(f"Rate limit check failed for user {user_id}: {str(e)}")
        # Continue without rate limiting if cache fails

async def invalidate_user_cache(user_id: int, repo_full_name: str = None) -> None:
    """Invalidate user's repository cache including GitHub API caches."""
    # Use RepoCache which has production protection built-in
    from core.cache import RepoCache, cache
    try:
        # Invalidate connected repos cache
        await RepoCache.invalidate_user_repos(user_id)
        
        # Invalidate available repos cache
        available_repos_key = f"available_repos:user:{user_id}"
        await cache.delete(available_repos_key)
        logger.info(f"Invalidated available repos cache for user {user_id}")
        
        # Invalidate repo-specific caches if provided
        if repo_full_name:
            # Invalidate branches cache
            branches_cache_key = f"branches:repo:{repo_full_name}"
            await cache.delete(branches_cache_key)
            logger.info(f"Invalidated branches cache for repo {repo_full_name}")
            
            # Invalidate GitHub API caches for this repository
            await cache.invalidate_pattern(f"repo:default_branch:{repo_full_name}")
            await cache.invalidate_pattern(f"branch:validation:{repo_full_name}:*")
            await cache.invalidate_pattern(f"repo:contents:{repo_full_name}:*")
            await cache.invalidate_pattern(f"repo:metadata:{repo_full_name}")
            await cache.invalidate_pattern(f"pr:details:{repo_full_name}:*")
            await cache.invalidate_pattern(f"pr:changed_files:{repo_full_name}:*")
            logger.info(f"Invalidated GitHub API caches for repo {repo_full_name}")
        
    except Exception as e:
        logger.warning(f"Failed to invalidate cache for user {user_id}: {str(e)}")

async def invalidate_github_cache(repo_full_name: str, pr_number: int = None, branch: str = None) -> None:
    """Invalidate GitHub API caches for specific repository, PR, or branch."""
    from core.cache import cache
    try:
        logger.info(f"Invalidating GitHub caches for {repo_full_name}")
        
        # Always invalidate repository-level caches
        await cache.delete(f"repo:default_branch:{repo_full_name}")
        await cache.delete(f"repo:metadata:{repo_full_name}")
        
        # Invalidate branch-specific caches if branch provided
        if branch:
            await cache.delete(f"branch:validation:{repo_full_name}:{branch}")
            await cache.delete(f"repo:contents:{repo_full_name}:{branch}")
            logger.info(f"Invalidated branch caches for {repo_full_name}:{branch}")
        else:
            # Invalidate all branch-related caches
            await cache.invalidate_pattern(f"branch:validation:{repo_full_name}:*")
            await cache.invalidate_pattern(f"repo:contents:{repo_full_name}:*")
        
        # Invalidate PR-specific caches if PR number provided
        if pr_number:
            await cache.delete(f"pr:details:{repo_full_name}:{pr_number}")
            await cache.delete(f"pr:changed_files:{repo_full_name}:{pr_number}")
            logger.info(f"Invalidated PR caches for {repo_full_name}#{pr_number}")
        else:
            # Invalidate all PR-related caches
            await cache.invalidate_pattern(f"pr:details:{repo_full_name}:*")
            await cache.invalidate_pattern(f"pr:changed_files:{repo_full_name}:*")
            
        logger.info(f"Successfully invalidated GitHub caches for {repo_full_name}")
        
    except Exception as e:
        logger.warning(f"Failed to invalidate GitHub cache for {repo_full_name}: {str(e)}")

def validate_github_access(current_user: User) -> str:
    """Validate GitHub connection and return decrypted token."""
    if not current_user.is_github_connected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GitHub not connected. Please connect your GitHub account first."
        )
    
    if not current_user.github_access_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="GitHub access token not available. Please reconnect your GitHub account."
        )
    
    try:
        return decrypt_token(current_user.github_access_token)
    except Exception as e:
        logger.error(f"Failed to decrypt GitHub token for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid GitHub token. Please reconnect your GitHub account."
        )

def fetch_sample_content(gh_repo, branch: str) -> Dict[str, str]:
    """Fetch sample content from repository - FIXED isinstance issue."""
    sample_files = ["README.md", "README.rst", "README.txt", "package.json", "setup.py", "Cargo.toml"]
    
    for filename in sample_files:
        try:
            contents = gh_repo.get_contents(filename, ref=branch)
            # FIXED: Use hasattr and type checking instead of isinstance
            if hasattr(contents, 'decoded_content') and hasattr(contents, 'type') and contents.type == 'file':
                try:
                    decoded_content = contents.decoded_content.decode("utf-8")
                    snippet = decoded_content[:MAX_SAMPLE_CONTENT_LENGTH]
                    if len(decoded_content) > MAX_SAMPLE_CONTENT_LENGTH:
                        snippet += "..."
                    return {filename: snippet}
                except (UnicodeDecodeError, AttributeError) as e:
                    logger.warning(f"Failed to decode {filename}: {str(e)}")
                    continue
        except (UnknownObjectException, Exception) as e:
            logger.debug(f"File {filename} not found or accessible: {str(e)}")
            continue
    
    # Fallback to any readable file in root
    try:
        root_contents = gh_repo.get_contents("", ref=branch)
        # FIXED: Check if it's a list and handle properly
        if isinstance(root_contents, list):
            for content in root_contents[:5]:  # Check first 5 files
                # FIXED: Use hasattr instead of isinstance
                if (hasattr(content, 'type') and content.type == 'file' and 
                    hasattr(content, 'size') and content.size < 10000):  # Skip large files
                    try:
                        if hasattr(content, 'decoded_content'):
                            decoded_content = content.decoded_content.decode("utf-8")
                            snippet = decoded_content[:MAX_SAMPLE_CONTENT_LENGTH]
                            if len(decoded_content) > MAX_SAMPLE_CONTENT_LENGTH:
                                snippet += "..."
                            return {content.path: snippet}
                    except (UnicodeDecodeError, AttributeError, Exception) as e:
                        logger.debug(f"Failed to decode {content.path}: {str(e)}")
                        continue
    except Exception as e:
        logger.warning(f"Failed to fetch fallback content from {gh_repo.full_name}: {str(e)}")
    
    return {"message": "No readable content found in repository root"}

async def verify_repo_ownership(db: AsyncSession, full_name: str, user_id: int) -> Repo:
    """Verify that the repository is connected by the current user."""
    result = await db.execute(
        select(Repo).where(
            and_(Repo.full_name == full_name, Repo.user_id == user_id)
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository '{full_name}' not found or not connected by this user."
        )
    return repo

@repos_router.post("/connect", response_model=Dict[str, Any])
async def connect_repo(
    request: RepoConnectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Connect a GitHub repository to the platform."""
    await check_rate_limit(current_user.id)
    gh_token = validate_github_access(current_user)

    # Check cache for repository metadata (30-minute TTL)
    from core.cache import cache
    repo_metadata_cache_key = f"repo:metadata:{request.full_name}"
    cached_metadata = await cache.get(repo_metadata_cache_key)
    
    try:
        g = Github(gh_token)
        
        if cached_metadata is not None:
            logger.info(f"Using cached repository metadata for {request.full_name}")
            # Verify repository still accessible
            try:
                gh_repo = g.get_repo(request.full_name)
                # Use cached metadata but verify current permissions
                if not (gh_repo.permissions and gh_repo.permissions.push):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions. Push access required to connect repository."
                    )
                default_branch = cached_metadata["default_branch"]
            except Exception:
                # If repo access fails, clear cache and proceed normally
                await cache.delete(repo_metadata_cache_key)
                cached_metadata = None
        
        if cached_metadata is None:
            gh_repo = g.get_repo(request.full_name)
            
            # Verify repository permissions
            if not (gh_repo.permissions and gh_repo.permissions.push):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions. Push access required to connect repository."
                )
            
            default_branch = gh_repo.default_branch
            
            # Cache repository metadata for 30 minutes
            metadata = {
                "default_branch": default_branch,
                "permissions": {
                    "push": bool(gh_repo.permissions and gh_repo.permissions.push),
                    "admin": bool(gh_repo.permissions and gh_repo.permissions.admin)
                }
            }
            await cache.set(repo_metadata_cache_key, metadata, ttl=1800)
            logger.info(f"Fetched and cached repository metadata for {request.full_name}")
        
        logger.info(f"Connecting repo: {request.full_name}, default branch: {default_branch}")

        # Check if already connected by this user
        existing = await db.execute(
            select(Repo).where(
                and_(Repo.full_name == request.full_name, Repo.user_id == current_user.id)
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Repository already connected by this user."
            )

        webhook_id = None  # Use None for dummy webhook since it's nullable integer
        if not USE_MOCK_WEBHOOKS:
            logger.info(f"Creating real webhook for {request.full_name} to URL: {WEBHOOK_URL}")
            try:
                hook = gh_repo.create_hook(
                    "web",
                    {
                        "url": WEBHOOK_URL,
                        "content_type": "json",
                        "insecure_ssl": "0"  # Require SSL
                    },
                    ["push", "pull_request", "create", "delete"],
                    active=True
                )
                webhook_id = hook.id  # Keep as integer, not string
                logger.info(f"Created webhook {webhook_id} for {request.full_name}")
            except GithubException as e:
                logger.error(f"GitHub webhook creation error for {request.full_name}: status={e.status}, message={str(e)}")
                if e.status in [409, 422]:
                    error_data = str(e.data) if hasattr(e, 'data') else str(e)
                    error_message = str(e)
                    if ("Hook already exists" in error_data or 
                        "Webhook already exists" in error_message or
                        "hook already exists" in error_message.lower()):
                        # If webhook already exists, try to find existing webhook and use it
                        logger.info(f"Webhook already exists for {request.full_name}, attempting to find existing one")
                        try:
                            hooks = gh_repo.get_hooks()
                            for hook in hooks:
                                if hook.config and hook.config.get('url') == WEBHOOK_URL:
                                    webhook_id = hook.id  # Keep as integer
                                    logger.info(f"Found and using existing webhook {webhook_id} for {request.full_name}")
                                    break
                            else:
                                # No matching webhook found, use None for dummy
                                webhook_id = None
                                logger.warning(f"Webhook exists but couldn't find matching URL {WEBHOOK_URL} for {request.full_name}")
                        except Exception as hook_e:
                            logger.warning(f"Failed to retrieve existing webhooks for {request.full_name}: {str(hook_e)}")
                            webhook_id = None  # Use None for dummy webhook
                        # Continue with the flow instead of raising an error
                    else:
                        logger.error(f"Non-webhook error during creation for {request.full_name}: {str(e)}")
                        raise HTTPException(
                            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"Failed to create webhook: {str(e)}"
                        )
                else:
                    logger.error(f"Unexpected GitHub error status {e.status} for {request.full_name}: {str(e)}")
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Failed to create webhook: {str(e)}"
                    )

        # Get repository metadata safely
        settings = {
            "default_branch": gh_repo.default_branch,
            "is_private": str(gh_repo.private).lower() if gh_repo.private is not None else None,
            "language": gh_repo.language,
            "description": gh_repo.description
        }

        # Insert repository record
        await db.execute(
            insert(Repo).values(
                full_name=request.full_name,
                user_id=current_user.id,
                niche=request.niche,
                settings=settings,
                webhook_id=webhook_id,
                default_branch=gh_repo.default_branch,
                is_private=str(gh_repo.private).lower() if gh_repo.private is not None else None,
                language=gh_repo.language,
                description=gh_repo.description,
                status="active"
            )
        )
        await db.commit()

        # Invalidate cache
        await invalidate_user_cache(current_user.id, request.full_name)

        return {
            "status": "connected",
            "full_name": request.full_name,
            "webhook_id": webhook_id,
            "message": f"Repository {request.full_name} successfully connected."
        }

    except GithubException as e:
        await db.rollback()
        if e.status == 404:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found or access denied."
            )
        elif e.status == 403:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient GitHub permissions or API access denied."
            )
        elif e.status == 409:
            # Handle webhook already exists error by connecting anyway
            logger.info(f"409 error for {request.full_name}: {str(e)}")
            if "Webhook already exists" in str(e) or "hook already exists" in str(e).lower():
                logger.info(f"Webhook already exists for {request.full_name}, connecting with existing webhook")
                
                # Try to find existing webhook
                webhook_id = None  # Use None for dummy webhook
                try:
                    # Re-get the repo object since it might not be in scope
                    g = Github(gh_token)
                    gh_repo = g.get_repo(request.full_name)
                    hooks = gh_repo.get_hooks()
                    for hook in hooks:
                        if hook.config and hook.config.get('url') == WEBHOOK_URL:
                            webhook_id = hook.id  # Keep as integer
                            logger.info(f"Found existing webhook {webhook_id} for {request.full_name}")
                            break
                except Exception as hook_e:
                    logger.warning(f"Failed to find existing webhook for {request.full_name}: {str(hook_e)}")
                
                # Get repository metadata safely
                settings = {
                    "default_branch": gh_repo.default_branch,
                    "is_private": str(gh_repo.private).lower() if gh_repo.private is not None else None,
                    "language": gh_repo.language,
                    "description": gh_repo.description
                }

                # Insert repository record
                await db.execute(
                    insert(Repo).values(
                        full_name=request.full_name,
                        user_id=current_user.id,
                        niche=request.niche,
                        settings=settings,
                        webhook_id=webhook_id,
                        default_branch=gh_repo.default_branch,
                        is_private=str(gh_repo.private).lower() if gh_repo.private is not None else None,
                        language=gh_repo.language,
                        description=gh_repo.description,
                        status="active"
                    )
                )
                await db.commit()

                # Invalidate cache
                await invalidate_user_cache(current_user.id, request.full_name)

                return {
                    "status": "connected",
                    "full_name": request.full_name,
                    "webhook_id": webhook_id,
                    "message": f"Repository {request.full_name} successfully connected with existing webhook."
                }
            else:
                logger.error(f"409 error but not webhook related for {request.full_name}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"GitHub API conflict: {str(e)}"
                )
        elif isinstance(e, RateLimitExceededException):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="GitHub API rate limit exceeded. Please try again later."
            )
        else:
            logger.error(f"GitHub API error connecting {request.full_name}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to connect repository due to GitHub API error."
            )
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error connecting {request.full_name}: {str(e)}", exc_info=True)
        
        # Provide more specific error messages based on error type
        error_message = str(e)
        
        if "ModuleNotFoundError" in error_message or "ImportError" in error_message:
            logger.error(f"Import error during repository connection: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server configuration error. Please contact support."
            )
        elif "database" in error_message.lower() or "sqlalchemy" in error_message.lower():
            logger.error(f"Database error during repository connection: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Database connection error. Please try again later."
            )
        elif "redis" in error_message.lower() or "cache" in error_message.lower():
            logger.error(f"Cache error during repository connection: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Cache service error. Repository connection may succeed on retry."
            )
        elif "decrypt" in error_message.lower() or "token" in error_message.lower():
            logger.error(f"Token error during repository connection: {error_message}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="GitHub token error. Please reconnect your GitHub account."
            )
        else:
            # Generic error but with more context for debugging
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Repository connection failed: {error_message[:200]}{'...' if len(error_message) > 200 else ''}"
            )

@repos_router.get("/", response_model=List[RepoResponse])
async def list_connected_repos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all repositories connected by the current user."""
    # Use RepoCache which has production protection built-in
    from core.cache import RepoCache
    
    # Try cache first
    cached_repos = await RepoCache.get_user_repos(current_user.id)
    if cached_repos:
        logger.debug(f"Retrieved {len(cached_repos)} repos from cache for user {current_user.id}")
        return cached_repos

    # Query database
    try:
        result = await db.execute(
            select(Repo)
            .where(Repo.user_id == current_user.id)
            .order_by(Repo.created_at.desc())
        )
        repos_data = []
        for repo in result.scalars().all():
            repo_response = RepoResponse(
                id=repo.id,
                full_name=repo.full_name,
                niche=repo.niche,
                settings=repo.settings if repo.settings else {},
                webhook_id=repo.webhook_id,
                default_branch=repo.default_branch,
                is_private=repo.is_private,
                language=repo.language,
                description=repo.description,
                status=repo.status,
                created_at=format_datetime_response(repo.created_at),
                updated_at=format_datetime_response(repo.updated_at),
                last_synced=format_datetime_response(repo.last_synced)
            )
            repos_data.append(repo_response.dict())

        # Cache results using RepoCache
        await RepoCache.set_user_repos(current_user.id, repos_data, REPOS_CACHE_TTL)

        return repos_data

    except Exception as e:
        logger.error(f"Database error listing repos for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve connected repositories."
        )

@repos_router.post("/disconnect", response_model=Dict[str, str])
async def disconnect_repo(
    request: RepoDisconnectRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Disconnect a repository from the platform."""
    await check_rate_limit(current_user.id)
    gh_token = validate_github_access(current_user)

    logger.info(f"Disconnecting repo: {request.full_name} for user {current_user.id}")

    # Verify repository ownership
    repo = await verify_repo_ownership(db, request.full_name, current_user.id)

    try:
        g = Github(gh_token)
        gh_repo = g.get_repo(request.full_name)

        # Remove webhook if it exists
        if not USE_MOCK_WEBHOOKS and repo.webhook_id is not None:
            try:
                hook = gh_repo.get_hook(repo.webhook_id)  # webhook_id is already integer
                hook.delete()
                logger.info(f"Deleted webhook {repo.webhook_id} for {request.full_name}")
            except GithubException as e:
                if e.status == 404:
                    logger.warning(f"Webhook {repo.webhook_id} not found for {request.full_name}")
                elif e.status == 403:
                    logger.warning(f"Insufficient permissions to delete webhook {repo.webhook_id}")
                else:
                    logger.error(f"Failed to delete webhook {repo.webhook_id}: {str(e)}")

        # Remove from database to avoid FK constraint violations
        try:
            # First check how many scan records exist
            scan_count_result = await db.execute(
                select(func.count(Scan.id)).where(
                    and_(Scan.repo_full_name == request.full_name, Scan.user_id == current_user.id)
                )
            )
            scan_count = scan_count_result.scalar()
            logger.info(f"Found {scan_count} scan records for {request.full_name} to delete")
            
            if scan_count > 0:
                # Get all scan IDs for this repo to delete dependent records
                scan_ids_result = await db.execute(
                    select(Scan.id).where(
                        and_(Scan.repo_full_name == request.full_name, Scan.user_id == current_user.id)
                    )
                )
                scan_ids = [row[0] for row in scan_ids_result.fetchall()]
                
                if scan_ids:
                    # Delete all scan-dependent records first
                    from scans.models import ScanSummary, ComplianceMapping, IssueFeedback, PRSecurityComment, PRSecurityReview, ScanJob
                    
                    await db.execute(delete(IssueFeedback).where(IssueFeedback.scan_id.in_(scan_ids)))
                    await db.execute(delete(ComplianceMapping).where(ComplianceMapping.scan_id.in_(scan_ids)))
                    await db.execute(delete(PRSecurityComment).where(PRSecurityComment.scan_id.in_(scan_ids)))
                    await db.execute(delete(PRSecurityReview).where(PRSecurityReview.scan_id.in_(scan_ids)))
                    await db.execute(delete(ScanSummary).where(ScanSummary.scan_id.in_(scan_ids)))
                    
                    # Set scan_id to NULL in ScanJob (follows FK constraint)
                    await db.execute(
                        update(ScanJob)
                        .where(ScanJob.scan_id.in_(scan_ids))
                        .values(scan_id=None, status="orphaned")
                    )
                    
                    logger.info(f"Deleted dependent data for {len(scan_ids)} scans")
            
            # Delete associated scan records
            scan_delete_result = await db.execute(
                delete(Scan).where(
                    and_(Scan.repo_full_name == request.full_name, Scan.user_id == current_user.id)
                )
            )
            deleted_scans = scan_delete_result.rowcount
            logger.info(f"Deleted {deleted_scans} scan records for {request.full_name}")
            
            # Delete the repository record
            await db.execute(
                delete(Repo).where(
                    and_(Repo.full_name == request.full_name, Repo.user_id == current_user.id)
                )
            )
            
            # Commit the transaction
            await db.commit()
            
        except Exception as db_error:
            await db.rollback()
            logger.error(f"Database error during repo disconnect: {str(db_error)}")
            raise

        # Invalidate cache
        await invalidate_user_cache(current_user.id, request.full_name)

        return {
            "status": "disconnected",
            "full_name": request.full_name,
            "message": f"Repository {request.full_name} successfully disconnected."
        }

    except GithubException as e:
        await db.rollback()
        if e.status == 404:
            # Repository might have been deleted, still remove from our database
            async with db.begin():
                # Get scan IDs to delete dependent records
                scan_ids_result = await db.execute(
                    select(Scan.id).where(
                        and_(Scan.repo_full_name == request.full_name, Scan.user_id == current_user.id)
                    )
                )
                scan_ids = [row[0] for row in scan_ids_result.fetchall()]
                
                if scan_ids:
                    # Delete all scan-dependent records first
                    from scans.models import ScanSummary, ComplianceMapping, IssueFeedback, PRSecurityComment, PRSecurityReview, ScanJob
                    
                    await db.execute(delete(IssueFeedback).where(IssueFeedback.scan_id.in_(scan_ids)))
                    await db.execute(delete(ComplianceMapping).where(ComplianceMapping.scan_id.in_(scan_ids)))
                    await db.execute(delete(PRSecurityComment).where(PRSecurityComment.scan_id.in_(scan_ids)))
                    await db.execute(delete(PRSecurityReview).where(PRSecurityReview.scan_id.in_(scan_ids)))
                    await db.execute(delete(ScanSummary).where(ScanSummary.scan_id.in_(scan_ids)))
                    
                    # Set scan_id to NULL in ScanJob (follows FK constraint)
                    await db.execute(
                        update(ScanJob)
                        .where(ScanJob.scan_id.in_(scan_ids))
                        .values(scan_id=None, status="orphaned")
                    )
                
                # Delete associated scan records
                scan_delete_result = await db.execute(
                    delete(Scan).where(
                        and_(Scan.repo_full_name == request.full_name, Scan.user_id == current_user.id)
                    )
                )
                deleted_scans = scan_delete_result.rowcount
                logger.info(f"Deleted {deleted_scans} scan records for {request.full_name} (repo not found)")
                
                # Delete the repository record
                await db.execute(
                    delete(Repo).where(
                        and_(Repo.full_name == request.full_name, Repo.user_id == current_user.id)
                    )
                )
            
            await invalidate_user_cache(current_user.id, request.full_name)
            return {
                "status": "disconnected",
                "full_name": request.full_name,
                "message": f"Repository {request.full_name} disconnected (repository no longer accessible)."
            }
        elif isinstance(e, RateLimitExceededException):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="GitHub API rate limit exceeded. Please try again later."
            )
        else:
            logger.error(f"GitHub API error disconnecting {request.full_name}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to disconnect repository due to GitHub API error."
            )
    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error disconnecting {request.full_name}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while disconnecting the repository."
        )

@repos_router.get("/available", response_model=List[str])
async def list_available_github_repos(
    force_refresh: bool = Query(False, description="Force refresh from GitHub API bypassing cache"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List available GitHub repositories that can be connected.
    
    Parameters:
    - force_refresh: Set to true to bypass cache and get fresh data from GitHub API
    """
    logger.info(f"List available repos called for user {current_user.id}, github_connected: {current_user.is_github_connected}, force_refresh: {force_refresh}")
    gh_token = validate_github_access(current_user)

    # Check Redis cache first (unless force refresh)
    from core.cache import cache
    cache_key = f"available_repos:user:{current_user.id}"
    cache_ttl = 300  # 5 minutes cache
    
    try:
        # Try to get from cache unless force refresh is requested
        cached_repos = None if force_refresh else await cache.get(cache_key)
        if cached_repos is not None and not force_refresh:
            logger.info(f"Returning {len(cached_repos)} available repos from cache for user {current_user.id}")
            return cached_repos
        
        if force_refresh:
            logger.info(f"Force refresh requested, bypassing cache for user {current_user.id}")
            # Clear the cache to ensure fresh data
            await cache.delete(cache_key)
        else:
            logger.info(f"Cache miss for available repos, fetching from GitHub API for user {current_user.id}")
        
        g = Github(gh_token)
        user = g.get_user()
        
        # Get connected repositories
        result = await db.execute(
            select(Repo.full_name).where(Repo.user_id == current_user.id)
        )
        connected_repos: Set[str] = set(result.scalars().all())
        
        logger.info(f"User {current_user.id} has {len(connected_repos)} connected repos: {list(connected_repos)}")

        # Filter available repositories
        available_repos = []
        repo_count = 0
        
        logger.info(f"Starting repository enumeration for user {current_user.id} (GitHub user: {user.login})")
        
        # Enhanced repository enumeration to include both personal and organization repos
        all_repos = []
        
        # Get personal repositories (both public and private)
        logger.info(f"Fetching personal repositories for user {user.login}")
        try:
            personal_repos = list(user.get_repos(type="all"))
            all_repos.extend(personal_repos)
            logger.info(f"Found {len(personal_repos)} personal repositories")
        except Exception as e:
            logger.error(f"Failed to fetch personal repositories: {str(e)}")
        
        # Get organization repositories 
        try:
            logger.info(f"Fetching organization repositories for user {user.login}")
            orgs = list(user.get_orgs())
            logger.info(f"User is member of {len(orgs)} organizations")
            
            for org in orgs:
                try:
                    org_repos = list(org.get_repos(type="all"))
                    # Filter to only repos where user has push access
                    accessible_org_repos = []
                    for org_repo in org_repos:
                        if org_repo.permissions and org_repo.permissions.push:
                            accessible_org_repos.append(org_repo)
                    
                    all_repos.extend(accessible_org_repos)
                    logger.info(f"Found {len(accessible_org_repos)} accessible repositories in organization {org.login}")
                    
                except Exception as org_error:
                    logger.warning(f"Failed to fetch repos for org {org.login}: {str(org_error)}")
                    
        except Exception as org_error:
            logger.warning(f"Failed to fetch organizations: {str(org_error)}")
        
        logger.info(f"Total repositories found: {len(all_repos)}")
        repo_paginated_list = all_repos
        
        # Enhanced logging for repository discovery
        personal_count = len([r for r in all_repos if r.owner.login == user.login])
        org_count = len(all_repos) - personal_count
        private_count = len([r for r in all_repos if r.private])
        public_count = len(all_repos) - private_count
        
        logger.info(f"Repository breakdown - Personal: {personal_count}, Org: {org_count}, Private: {private_count}, Public: {public_count}")
        
        for repo in repo_paginated_list:
            repo_count += 1
            
            # Log details for first few repos when debugging
            if repo_count <= 5 or force_refresh:
                logger.info(f"Checking repo #{repo_count}: {repo.full_name} - private: {repo.private}, archived: {repo.archived}, push_access: {bool(repo.permissions and repo.permissions.push)}")
            
            if (repo.permissions and 
                repo.permissions.push and 
                not repo.archived and
                repo.full_name not in connected_repos):
                available_repos.append(repo.full_name)
                
                # Log when we include a repo
                if force_refresh or len(available_repos) <= 10:
                    logger.info(f"✓ Including repo: {repo.full_name}")
            else:
                # Log exclusion reasons for debugging
                exclusion_reasons = []
                if not repo.permissions or not repo.permissions.push:
                    exclusion_reasons.append("no_push_access")
                if repo.archived:
                    exclusion_reasons.append("archived")
                if repo.full_name in connected_repos:
                    exclusion_reasons.append("already_connected")
                
                if force_refresh or repo_count <= 10:
                    logger.info(f"✗ Excluding repo: {repo.full_name} - reasons: {exclusion_reasons}")
            
            # Fix 3: Increase limits to handle users with many repositories
            # Limit available repos to prevent memory issues but allow more than 100
            if len(available_repos) >= 500:
                logger.info(f"Reached 500 available repos limit for user {current_user.id}")
                break
                
            # Also limit total repos checked but allow checking more repositories
            if repo_count >= 1000:
                logger.info(f"Reached 1000 repo limit for user {current_user.id}, stopping enumeration")
                break

        # Sort and cache the results
        sorted_repos = sorted(available_repos)
        
        # Enhanced logging for debugging repository discovery issues
        logger.info(f"Repository enumeration complete for user {current_user.id}: checked {repo_count} repos, found {len(sorted_repos)} available")
        logger.info(f"Filtering results - Total: {repo_count}, Available: {len(sorted_repos)}, Already connected: {len([r for r in all_repos if r.full_name in connected_repos])}")
        logger.info(f"Exclusions - No push access: {repo_count - len([r for r in all_repos if r.permissions and r.permissions.push])}")
        logger.info(f"Exclusions - Archived: {len([r for r in all_repos if r.archived])}")
        
        if repo_count >= 1000:
            logger.warning(f"Repository enumeration stopped at limit - user may have more than 1000 repos")
        elif len(available_repos) >= 500:
            logger.warning(f"Available repository enumeration stopped at limit - user may have more than 500 eligible repos")
        
        # Log sample of available repositories for debugging
        if force_refresh and sorted_repos:
            logger.info(f"Sample available repos (first 10): {sorted_repos[:10]}")
        
        # Log private repositories specifically
        private_available = [r for r in all_repos if r.private and r.permissions and r.permissions.push and not r.archived and r.full_name not in connected_repos]
        logger.info(f"Private repositories available for connection: {len(private_available)}")
        if private_available and force_refresh:
            private_names = [r.full_name for r in private_available[:5]]
            logger.info(f"Sample private repos available: {private_names}")
        
        # Cache the results
        await cache.set(cache_key, sorted_repos, cache_ttl)
        logger.info(f"Cached {len(sorted_repos)} available repos for user {current_user.id} (TTL: {cache_ttl}s)")
        
        return sorted_repos

    except GithubException as e:
        if e.status in [401, 403]:
            logger.warning(f"Invalid GitHub token for user {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired GitHub token. Please reconnect your GitHub account."
            )
        elif isinstance(e, RateLimitExceededException):
            logger.warning(f"GitHub rate limit exceeded for user {current_user.id}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="GitHub API rate limit exceeded. Please try again later."
            )
        else:
            logger.error(f"GitHub API error listing available repos: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve available repositories."
            )
    except HTTPException:
        # Re-raise HTTPExceptions (like those from GithubException handling above)
        raise
    except Exception as e:
        logger.error(f"Unexpected error in list_available_github_repos for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while retrieving available repositories."
        )

@repos_router.get("/{full_name:path}/branches", response_model=BranchesResponse)
async def get_repo_branches(
    full_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all branches for a connected repository."""
    gh_token = validate_github_access(current_user)
    
    # Verify repository ownership
    await verify_repo_ownership(db, full_name, current_user.id)

    # Check Redis cache first
    from core.cache import cache
    cache_key = f"branches:repo:{full_name}"
    cache_ttl = 600  # 10 minutes cache (branches change less frequently)
    
    try:
        # Try to get from cache
        cached_branches = await cache.get(cache_key)
        if cached_branches is not None:
            logger.info(f"Returning {cached_branches['total_count']} branches from cache for repo {full_name}")
            return BranchesResponse(**cached_branches)
        
        logger.info(f"Cache miss for branches, fetching from GitHub API for repo {full_name}")
        
        g = Github(gh_token)
        gh_repo = g.get_repo(full_name)

        branches = []
        default_branch = gh_repo.default_branch or "main"
        
        for branch in gh_repo.get_branches():
            branches.append(branch.name)

        # Prepare response data
        response_data = {
            "full_name": full_name,
            "branches": sorted(branches),
            "default_branch": default_branch,
            "total_count": len(branches)
        }
        
        # Cache the results
        await cache.set(cache_key, response_data, cache_ttl)
        logger.info(f"Cached {len(branches)} branches for repo {full_name} (TTL: {cache_ttl}s)")

        return BranchesResponse(**response_data)

    except GithubException as e:
        if e.status == 404:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository not found or access denied."
            )
        elif e.status == 403:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient GitHub permissions."
            )
        elif isinstance(e, RateLimitExceededException):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="GitHub API rate limit exceeded."
            )
        else:
            logger.error(f"GitHub API error fetching branches for {full_name}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve repository branches."
            )

@repos_router.get("/{full_name:path}/contents", response_model=CodeAccessResponse)
async def get_repo_contents(
    full_name: str,
    branch: str = Query(..., description="Branch to fetch contents from"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get repository contents and confirm code access."""
    gh_token = validate_github_access(current_user)
    
    # Validate branch name
    if not BRANCH_NAME_PATTERN.match(branch):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid branch name format."
        )
    
    # Verify repository ownership
    await verify_repo_ownership(db, full_name, current_user.id)

    logger.info(f"Fetching contents for {full_name} on branch {branch}")

    try:
        g = Github(gh_token)
        gh_repo = g.get_repo(full_name)

        # Validate branch exists
        try:
            branch_obj = gh_repo.get_branch(branch)
        except GithubException as e:
            if e.status == 404:
                # Get available branches for error message
                available_branches = [b.name for b in gh_repo.get_branches()]
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Branch '{branch}' not found. Available branches: {', '.join(available_branches[:10])}"
                )
            raise

        # Fetch latest commit
        try:
            latest_commit = gh_repo.get_commit(sha=branch_obj.commit.sha)
            commit_details = {
                "sha": latest_commit.sha[:7],
                "message": (latest_commit.commit.message.split("\n")[0] 
                           if latest_commit.commit.message else "No commit message"),
                "author": (latest_commit.commit.author.name 
                          if latest_commit.commit.author else "Unknown"),
                "date": latest_commit.commit.author.date.isoformat() if latest_commit.commit.author else None
            }
        except Exception as e:
            logger.error(f"Failed to fetch commit for {full_name} on branch {branch}: {str(e)}")
            commit_details = {
                "sha": "N/A",
                "message": "Failed to fetch commit details",
                "author": "Unknown",
                "date": None
            }

        # Fetch sample content
        sample_content = fetch_sample_content(gh_repo, branch)

        return CodeAccessResponse(
            full_name=full_name,
            branch=branch,
            sample_content=sample_content,
            latest_commit=commit_details,
            message="Code access successfully confirmed. Sample content and commit details retrieved.",
            accessed_at=format_datetime_response(utc_now())
        )

    except GithubException as e:
        if e.status == 404:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Repository or branch not found."
            )
        elif e.status == 403:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient GitHub permissions."
            )
        elif isinstance(e, RateLimitExceededException):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="GitHub API rate limit exceeded."
            )
        else:
            logger.error(f"GitHub API error accessing {full_name}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to access repository contents."
            )
    except Exception as e:
        logger.error(f"Unexpected error accessing {full_name}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while accessing repository contents."
        )

@repos_router.post("/clear-cache", response_model=Dict[str, str])
async def clear_repository_cache(
    current_user: User = Depends(get_current_user)
):
    """
    Clear all repository-related cache for the current user.
    
    This is useful when repositories are not appearing in the available list
    due to stale Redis cache. This endpoint will clear:
    - Available repositories cache
    - Connected repositories cache  
    - Repository branches cache
    - GitHub API metadata cache
    """
    logger.info(f"Manual cache clear requested by user {current_user.id}")
    
    try:
        # Clear all user-related repository caches
        await invalidate_user_cache(current_user.id)
        
        # Additional specific cache clearing
        from core.cache import cache
        
        # Clear available repos cache (most critical for the issue)
        available_repos_key = f"available_repos:user:{current_user.id}"
        await cache.delete(available_repos_key)
        
        # Get Redis client for pattern-based clearing
        try:
            from core.redis import get_redis_client
            redis_client = await get_redis_client()
            
            if redis_client:
                # Clear any repository-related patterns for this user
                patterns_to_clear = [
                    f"*user:{current_user.id}*",
                    f"available_repos:user:{current_user.id}",
                    f"repo:user:{current_user.id}",
                    f"rate:repos:{current_user.id}"
                ]
                
                cleared_count = 0
                for pattern in patterns_to_clear:
                    keys = await redis_client.keys(pattern)
                    if keys:
                        deleted = await redis_client.delete(*keys)
                        cleared_count += deleted
                        logger.info(f"Cleared {deleted} keys matching pattern: {pattern}")
                
                logger.info(f"Total Redis keys cleared: {cleared_count}")
                
        except Exception as redis_error:
            logger.warning(f"Redis pattern clearing failed: {str(redis_error)}, using fallback")
        
        logger.info(f"Cache clearing completed for user {current_user.id}")
        
        return {
            "status": "success",
            "message": f"Repository cache cleared for user {current_user.id}. Next /repos/available call will fetch fresh data from GitHub."
        }
        
    except Exception as e:
        logger.error(f"Error clearing repository cache for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear repository cache"
        )

@repos_router.get("/debug/github-token", response_model=Dict[str, Any])
async def debug_github_token(
    current_user: User = Depends(get_current_user)
):
    """
    Debug endpoint to validate GitHub token scopes and permissions.
    
    This endpoint provides detailed information about:
    - GitHub token validation and scopes  
    - User GitHub profile information
    - Token permissions for private repositories
    - Rate limit information
    """
    logger.info(f"Debug GitHub token called for user {current_user.id}")
    gh_token = validate_github_access(current_user)
    
    debug_info = {
        "user_id": current_user.id,
        "github_connected": current_user.is_github_connected,
        "timestamp": format_datetime_response(utc_now()),
        "token_info": {},
        "github_user_info": {},
        "permissions_test": {},
        "rate_limit_info": {},
        "scope_analysis": {}
    }
    
    try:
        g = Github(gh_token)
        
        # Get GitHub user info
        user = g.get_user()
        debug_info["github_user_info"] = {
            "login": user.login,
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "public_repos": user.public_repos,
            "total_private_repos": user.total_private_repos,
            "owned_private_repos": user.owned_private_repos,
            "collaborators": user.collaborators if hasattr(user, 'collaborators') else 0,
            "created_at": user.created_at.isoformat() if user.created_at else None
        }
        
        # Get rate limit info
        rate_limit = g.get_rate_limit()
        debug_info["rate_limit_info"] = {
            "core_remaining": rate_limit.core.remaining,
            "core_limit": rate_limit.core.limit,
            "core_reset": rate_limit.core.reset.isoformat() if rate_limit.core.reset else None,
            "search_remaining": rate_limit.search.remaining,
            "search_limit": rate_limit.search.limit,
            "graphql_remaining": rate_limit.graphql.remaining if hasattr(rate_limit, 'graphql') else None
        }
        
        # Test private repository access
        debug_info["permissions_test"]["private_repos_accessible"] = False
        debug_info["permissions_test"]["sample_private_repos"] = []
        
        try:
            # Try to enumerate repositories and check for private ones
            repos_checked = 0
            private_repos_found = 0
            public_repos_found = 0
            
            for repo in user.get_repos(type="all"):
                repos_checked += 1
                
                if repo.private:
                    private_repos_found += 1
                    debug_info["permissions_test"]["private_repos_accessible"] = True
                    
                    # Add first few private repos as samples
                    if len(debug_info["permissions_test"]["sample_private_repos"]) < 5:
                        debug_info["permissions_test"]["sample_private_repos"].append({
                            "full_name": repo.full_name,
                            "private": repo.private,
                            "permissions": {
                                "admin": bool(repo.permissions.admin) if repo.permissions else False,
                                "push": bool(repo.permissions.push) if repo.permissions else False,
                                "pull": bool(repo.permissions.pull) if repo.permissions else False
                            },
                            "archived": repo.archived,
                            "created_at": repo.created_at.isoformat() if repo.created_at else None
                        })
                else:
                    public_repos_found += 1
                
                # Limit to first 100 repos for performance
                if repos_checked >= 100:
                    break
            
            debug_info["permissions_test"]["summary"] = {
                "total_repos_checked": repos_checked,
                "private_repos_found": private_repos_found,
                "public_repos_found": public_repos_found,
                "note": "Limited to first 100 repos for performance"
            }
            
        except Exception as perm_error:
            debug_info["permissions_test"]["error"] = str(perm_error)
        
        # Analyze token scopes by attempting various API calls
        scope_tests = {
            "can_read_public_repos": False,
            "can_read_private_repos": False, 
            "can_read_user_email": False,
            "can_read_orgs": False,
            "can_create_webhooks": False
        }
        
        try:
            # Test public repo access
            public_repo_test = list(user.get_repos(type="public"))[:1]
            scope_tests["can_read_public_repos"] = len(public_repo_test) > 0
        except:
            pass
            
        try:
            # Test private repo access
            private_repo_test = list(user.get_repos(type="private"))[:1] 
            scope_tests["can_read_private_repos"] = len(private_repo_test) > 0
        except:
            pass
            
        try:
            # Test user email access
            scope_tests["can_read_user_email"] = user.email is not None
        except:
            pass
            
        try:
            # Test org access
            orgs = list(user.get_orgs())[:1]
            scope_tests["can_read_orgs"] = len(orgs) > 0
        except:
            pass
        
        debug_info["scope_analysis"] = {
            "tests": scope_tests,
            "interpretation": {
                "likely_scopes": [],
                "missing_scopes": [],
                "recommendations": []
            }
        }
        
        # Interpret results
        interpretation = debug_info["scope_analysis"]["interpretation"]
        
        if scope_tests["can_read_public_repos"]:
            interpretation["likely_scopes"].append("public_repo (can read public repositories)")
        
        if scope_tests["can_read_private_repos"]:
            interpretation["likely_scopes"].append("repo (can read private repositories)")
        else:
            interpretation["missing_scopes"].append("repo (cannot access private repositories)")
            interpretation["recommendations"].append("Add 'repo' scope to access private repositories")
        
        if scope_tests["can_read_user_email"]:
            interpretation["likely_scopes"].append("user:email (can read user email)")
            
        if scope_tests["can_read_orgs"]:
            interpretation["likely_scopes"].append("read:org (can read organization info)")
        else:
            interpretation["missing_scopes"].append("read:org (cannot access organization repositories)")
            interpretation["recommendations"].append("Add 'read:org' scope to access organization repositories")
        
        return debug_info
        
    except GithubException as e:
        debug_info["error"] = {
            "type": "GithubException",
            "status": e.status,
            "message": str(e),
            "data": str(e.data) if hasattr(e, 'data') else None
        }
        
        if e.status in [401, 403]:
            debug_info["error"]["likely_cause"] = "Invalid or expired GitHub token, or insufficient token scopes"
        elif isinstance(e, RateLimitExceededException):
            debug_info["error"]["likely_cause"] = "GitHub API rate limit exceeded"
        
        return debug_info
        
    except Exception as e:
        debug_info["error"] = {
            "type": "UnexpectedError",
            "message": str(e),
            "likely_cause": "Internal server error or network issue"
        }
        return debug_info

@repos_router.get("/debug/available", response_model=Dict[str, Any])
async def debug_available_repositories(
    force_refresh: bool = Query(False, description="Force refresh from GitHub API bypassing cache"),
    include_all: bool = Query(False, description="Include all repos regardless of permissions/status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Debug endpoint to troubleshoot repository discovery issues.
    
    This endpoint provides detailed information about:
    - GitHub token validation and scopes
    - Cache status and contents
    - Repository enumeration with filtering details
    - Permission checks for each repository
    - Connected repositories status
    """
    logger.info(f"Debug available repos called for user {current_user.id}, force_refresh: {force_refresh}")
    gh_token = validate_github_access(current_user)
    
    debug_info = {
        "user_id": current_user.id,
        "github_connected": current_user.is_github_connected,
        "force_refresh": force_refresh,
        "include_all": include_all,
        "timestamp": format_datetime_response(utc_now()),
        "cache_info": {},
        "github_api_info": {},
        "repositories": [],
        "connected_repos": [],
        "filtering_stats": {
            "total_repos_checked": 0,
            "repos_with_push_access": 0,
            "archived_repos": 0,
            "private_repos": 0,
            "public_repos": 0,
            "already_connected": 0,
            "available_repos": 0
        }
    }
    
    try:
        from core.cache import cache
        cache_key = f"available_repos:user:{current_user.id}"
        
        # Check cache status
        cached_repos = None if force_refresh else await cache.get(cache_key)
        debug_info["cache_info"] = {
            "cache_key": cache_key,
            "cache_exists": cached_repos is not None,
            "cached_repos_count": len(cached_repos) if cached_repos else 0,
            "cached_repos": cached_repos[:10] if cached_repos else [],  # First 10 for debugging
            "force_refresh": force_refresh
        }
        
        # Initialize GitHub API client
        g = Github(gh_token)
        user = g.get_user()
        
        # Get GitHub API info
        try:
            rate_limit = g.get_rate_limit()
            debug_info["github_api_info"] = {
                "username": user.login,
                "user_id": user.id,
                "rate_limit_core_remaining": rate_limit.core.remaining,
                "rate_limit_core_limit": rate_limit.core.limit,
                "rate_limit_reset": rate_limit.core.reset.isoformat() if rate_limit.core.reset else None,
                "token_scopes": "Unable to determine scopes from PyGithub"  # GitHub API doesn't expose this directly
            }
        except Exception as e:
            debug_info["github_api_info"]["error"] = f"Failed to get GitHub API info: {str(e)}"
        
        # Get connected repositories from database with more details
        result = await db.execute(
            select(Repo).where(Repo.user_id == current_user.id)
        )
        connected_repos_data = result.scalars().all()
        connected_repos: Set[str] = set([repo.full_name for repo in connected_repos_data])
        
        debug_info["connected_repos"] = [{
            "full_name": repo.full_name,
            "status": repo.status,
            "is_private": repo.is_private,
            "language": repo.language,
            "niche": repo.niche,
            "created_at": format_datetime_response(repo.created_at)
        } for repo in connected_repos_data]
        
        # Check for dummy/test repositories in database
        dummy_repos = [repo for repo in connected_repos_data 
                      if 'test-repo' in repo.full_name.lower() or 
                         'another-repo' in repo.full_name.lower() or
                         'dummy' in repo.full_name.lower() or
                         'fake' in repo.full_name.lower()]
        
        if dummy_repos:
            debug_info["dummy_repos_found"] = [{
                "full_name": repo.full_name,
                "status": repo.status,
                "created_at": format_datetime_response(repo.created_at),
                "note": "This appears to be dummy/test data"
            } for repo in dummy_repos]
        else:
            debug_info["dummy_repos_found"] = []
        
        # If cached and not force refresh, return cache info
        if cached_repos and not force_refresh:
            debug_info["message"] = "Using cached data. Use force_refresh=true to bypass cache."
            debug_info["repositories"] = [{"full_name": repo, "source": "cache"} for repo in cached_repos[:20]]
            return debug_info
        
        # Fetch repositories from GitHub API with detailed logging
        available_repos = []
        repo_details = []
        stats = debug_info["filtering_stats"]
        
        logger.info(f"Starting repository enumeration for user {current_user.id}")
        
        # Apply same fixes as main endpoint: remove per_page parameter as it's not supported  
        # Add organization repositories to get complete picture
        all_repos = []
        
        # Get personal repositories
        logger.info(f"Fetching personal repositories for user {user.login}")
        personal_repos = list(user.get_repos(type="all"))
        all_repos.extend(personal_repos)
        
        # Get organization repositories
        try:
            orgs = user.get_orgs()
            for org in orgs:
                logger.info(f"Fetching repositories for organization {org.login}")
                try:
                    org_repos = list(org.get_repos(type="all"))
                    # Filter to only repos where user has push access
                    for org_repo in org_repos:
                        if org_repo.permissions and org_repo.permissions.push:
                            all_repos.append(org_repo)
                except Exception as org_error:
                    logger.warning(f"Failed to fetch repos for org {org.login}: {str(org_error)}")
        except Exception as org_error:
            logger.warning(f"Failed to fetch organizations: {str(org_error)}")
        
        logger.info(f"Total repositories found: {len(all_repos)} (personal: {len(personal_repos)}, org: {len(all_repos) - len(personal_repos)})")
        
        for repo in all_repos:
            stats["total_repos_checked"] += 1
            
            repo_info = {
                "full_name": repo.full_name,
                "private": repo.private,
                "archived": repo.archived,
                "permissions": {},
                "included": False,
                "exclusion_reasons": []
            }
            
            # Track private/public repos
            if repo.private:
                stats["private_repos"] += 1
            else:
                stats["public_repos"] += 1
            
            # Check permissions
            if repo.permissions:
                repo_info["permissions"] = {
                    "admin": bool(repo.permissions.admin),
                    "push": bool(repo.permissions.push),
                    "pull": bool(repo.permissions.pull)
                }
                
                if repo.permissions.push:
                    stats["repos_with_push_access"] += 1
                else:
                    repo_info["exclusion_reasons"].append("no_push_permission")
            else:
                repo_info["exclusion_reasons"].append("no_permissions_object")
            
            # Check archived status
            if repo.archived:
                stats["archived_repos"] += 1
                repo_info["exclusion_reasons"].append("archived")
            
            # Check if already connected
            if repo.full_name in connected_repos:
                stats["already_connected"] += 1
                repo_info["exclusion_reasons"].append("already_connected")
            
            # Apply filtering logic (same as main endpoint)
            if include_all:
                # Include all repos for debugging
                available_repos.append(repo.full_name)
                repo_info["included"] = True
                stats["available_repos"] += 1
            else:
                # Apply normal filtering
                if (repo.permissions and 
                    repo.permissions.push and 
                    not repo.archived and
                    repo.full_name not in connected_repos):
                    available_repos.append(repo.full_name)
                    repo_info["included"] = True
                    stats["available_repos"] += 1
                else:
                    repo_info["included"] = False
            
            repo_details.append(repo_info)
            
            # Limit to prevent excessive API calls (same as main endpoint)
            if len(available_repos) >= 500 and not include_all:
                repo_info["note"] = "Stopped at 500 available repos limit"
                break
                
            # Also limit total repos checked to prevent long API calls
            if stats["total_repos_checked"] >= 1000:
                repo_info["note"] = "Stopped at 1000 total repos checked limit"
                logger.info(f"Reached 1000 repo limit for user {current_user.id}, stopping enumeration")
                break
        
        # Sort available repos (same as main endpoint)
        sorted_repos = sorted(available_repos)
        
        # Update debug info
        debug_info["repositories"] = repo_details
        debug_info["available_repos_final"] = sorted_repos
        debug_info["message"] = f"Enumerated {stats['total_repos_checked']} repositories, found {len(sorted_repos)} available"
        
        # Add summary by repository type
        debug_info["repository_summary"] = {
            "total_found": len(all_repos),
            "personal_repos": len(personal_repos),
            "org_repos": len(all_repos) - len(personal_repos),
            "private_repos_accessible": stats["private_repos"] > 0,
            "private_repos_count": stats["private_repos"],
            "public_repos_count": stats["public_repos"]
        }
        
        # Cache the results if not in debug mode
        if not include_all:
            await cache.set(cache_key, sorted_repos, 300)  # 5 minutes cache
            debug_info["cache_info"]["updated_cache"] = True
        else:
            debug_info["cache_info"]["updated_cache"] = False
            debug_info["cache_info"]["cache_update_reason"] = "Skipped due to include_all=true"
        
        # Add recommendations based on findings
        recommendations = []
        
        if stats["private_repos"] == 0 and user.total_private_repos > 0:
            recommendations.append("No private repositories accessible - check GitHub token scopes (need 'repo' scope)")
        
        if len(debug_info["dummy_repos_found"]) > 0:
            recommendations.append(f"Found {len(debug_info['dummy_repos_found'])} dummy/test repositories in database - consider cleaning these up")
        
        if len(all_repos) < 50:  # User expects 50 repos
            recommendations.append(f"Only found {len(all_repos)} total repositories, expected ~50 - check organization access and token scopes")
        
        debug_info["recommendations"] = recommendations
        
        return debug_info
        
    except GithubException as e:
        debug_info["error"] = {
            "type": "GithubException",
            "status": e.status,
            "message": str(e),
            "data": str(e.data) if hasattr(e, 'data') else None
        }
        
        if e.status in [401, 403]:
            debug_info["error"]["likely_cause"] = "Invalid or expired GitHub token, or insufficient token scopes"
        elif isinstance(e, RateLimitExceededException):
            debug_info["error"]["likely_cause"] = "GitHub API rate limit exceeded"
        
        return debug_info
        
    except Exception as e:
        debug_info["error"] = {
            "type": "UnexpectedError",
            "message": str(e),
            "likely_cause": "Internal server error or network issue"
        }
        return debug_info

@repos_router.get("/stats", response_model=RepositoryStatsResponse)
async def get_repository_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get comprehensive repository statistics including scanning and issues data."""
    try:
        # Get user's repositories
        result = await db.execute(
            select(Repo).where(Repo.user_id == current_user.id)
        )
        repositories = result.scalars().all()
        
        if not repositories:
            return RepositoryStatsResponse(
                total_repositories=0,
                active_repositories=0,
                repositories_needing_attention=0,
                repositories_needing_attention_details=[],
                total_issues_found=0,
                repositories_by_status={},
                repositories_by_language={},
                repositories_by_niche={},
                active_scans=0,
                completed_scans=0,
                critical_issues=0
            )
        
        # Get repository full names
        repo_names = [repo.full_name for repo in repositories]
        
        # Count repositories by various categories
        total_repositories = len(repositories)
        active_repositories = len([r for r in repositories if r.status == 'active'])
        
        repositories_by_status = {}
        repositories_by_language = {}
        repositories_by_niche = {}
        
        for repo in repositories:
            # Count by status
            repositories_by_status[repo.status] = repositories_by_status.get(repo.status, 0) + 1
            
            # Count by language
            if repo.language:
                repositories_by_language[repo.language] = repositories_by_language.get(repo.language, 0) + 1
            
            # Count by niche
            repositories_by_niche[repo.niche] = repositories_by_niche.get(repo.niche, 0) + 1
        
        # Get scan statistics
        from scans.models import Scan, ScanSummary
        
        # Get all scans for user's repositories
        scans_result = await db.execute(
            select(Scan).where(Scan.repo_full_name.in_(repo_names))
        )
        scans = scans_result.scalars().all()
        
        # Calculate scan statistics
        active_scans = len([s for s in scans if s.status in ['processing', 'queued']])
        completed_scans = len([s for s in scans if s.status == 'completed'])
        
        # Get critical issues count and repositories needing attention
        critical_issues = 0
        total_issues_found = 0
        repos_with_high_priority_issues = {}  # Changed to dict to store details
        
        # Get scan summaries for completed scans
        completed_scan_ids = [s.id for s in scans if s.status == 'completed']
        if completed_scan_ids:
            summaries_result = await db.execute(
                select(ScanSummary).where(ScanSummary.scan_id.in_(completed_scan_ids))
            )
            summaries = summaries_result.scalars().all()
            
            # Create a mapping of scan_id to repo_full_name for efficient lookup
            scan_to_repo = {s.id: s.repo_full_name for s in scans}
            
            for summary in summaries:
                critical_count = summary.critical_count or 0
                high_count = summary.high_count or 0
                
                critical_issues += critical_count
                total_issues_found += critical_count + high_count + (summary.medium_count or 0) + (summary.low_count or 0)
                
                # Repository needs attention if it has critical issues or many high-priority issues
                if critical_count > 0 or high_count >= 3:
                    repo_name = scan_to_repo.get(summary.scan_id)
                    if repo_name:
                        # Accumulate issues for each repository
                        if repo_name not in repos_with_high_priority_issues:
                            repos_with_high_priority_issues[repo_name] = {
                                'critical': 0, 
                                'high': 0
                            }
                        
                        repos_with_high_priority_issues[repo_name]['critical'] += critical_count
                        repos_with_high_priority_issues[repo_name]['high'] += high_count
        
        # Count repositories needing attention and create detailed list
        repositories_needing_attention = len(repos_with_high_priority_issues)
        
        repositories_needing_attention_details = []
        for repo_name, issues in repos_with_high_priority_issues.items():
            critical_count = issues['critical']
            high_count = issues['high']
            
            # Determine the reason
            if critical_count > 0 and high_count >= 3:
                reason = f"{critical_count} critical, {high_count} high-priority issues"
            elif critical_count > 0:
                reason = f"{critical_count} critical issue{'s' if critical_count > 1 else ''}"
            else:
                reason = f"{high_count} high-priority issues"
            
            repositories_needing_attention_details.append(RepositoryAttentionItem(
                repo_name=repo_name,
                critical_issues=critical_count,
                high_issues=high_count,
                reason=reason
            ))
        
        return RepositoryStatsResponse(
            total_repositories=total_repositories,
            active_repositories=active_repositories,
            repositories_needing_attention=repositories_needing_attention,
            repositories_needing_attention_details=repositories_needing_attention_details,
            total_issues_found=total_issues_found,
            repositories_by_status=repositories_by_status,
            repositories_by_language=repositories_by_language,
            repositories_by_niche=repositories_by_niche,
            active_scans=active_scans,
            completed_scans=completed_scans,
            critical_issues=critical_issues
        )
        
    except Exception as e:
        logger.error(f"Error getting repository stats for user {current_user.id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve repository statistics"
        )