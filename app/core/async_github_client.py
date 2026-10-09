"""
Enhanced Async GitHub API Client for DevSecureX
Phase 3: Non-blocking GitHub operations with intelligent rate limiting and concurrency
"""

import asyncio
import aiohttp
import logging
import time
import json
from typing import Dict, List, Any, Optional, AsyncGenerator, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from urllib.parse import urljoin
import base64

logger = logging.getLogger(__name__)

@dataclass
class GitHubRateLimit:
    """GitHub API rate limit information"""
    limit: int
    remaining: int
    reset: int
    used: int
    
    @property
    def reset_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.reset, timezone.utc)
    
    @property
    def seconds_until_reset(self) -> int:
        return max(0, self.reset - int(time.time()))

@dataclass
class GitHubRepository:
    """GitHub repository information"""
    id: int
    name: str
    full_name: str
    private: bool
    default_branch: str
    clone_url: str
    ssh_url: str
    size: int
    language: Optional[str]
    languages_url: str
    created_at: str
    updated_at: str
    pushed_at: str

class AsyncGitHubClient:
    """
    World-class async GitHub API client with intelligent rate limiting and concurrency
    
    Features:
    - Non-blocking HTTP requests with aiohttp
    - Intelligent rate limit handling and backoff
    - Concurrent API operations with batching
    - Automatic retry logic with exponential backoff
    - Comprehensive error handling and recovery
    - Performance monitoring and metrics
    """
    
    def __init__(
        self, 
        token: str, 
        base_url: str = "https://api.github.com",
        max_concurrent_requests: int = 10,
        timeout: int = 30
    ):
        self.token = token
        self.base_url = base_url
        self.max_concurrent_requests = max_concurrent_requests
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        
        # Rate limiting
        self.rate_limit_semaphore = asyncio.Semaphore(max_concurrent_requests)
        self.rate_limit_info: Optional[GitHubRateLimit] = None
        self.rate_limit_lock = asyncio.Lock()
        
        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()
        
        # Performance metrics
        self.metrics = {
            "requests_made": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "rate_limited_requests": 0,
            "total_response_time": 0.0,
            "avg_response_time": 0.0,
            "bytes_transferred": 0
        }
        
        logger.info(f"AsyncGitHubClient initialized with {max_concurrent_requests} max concurrent requests")
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with proper headers"""
        if self._session is None or self._session.closed:
            async with self._session_lock:
                if self._session is None or self._session.closed:
                    headers = {
                        'Authorization': f'Bearer {self.token}',
                        'Accept': 'application/vnd.github.v3+json',
                        'User-Agent': 'DevSecureX-Scanner/1.0',
                        'X-GitHub-Api-Version': '2022-11-28'
                    }
                    
                    connector = aiohttp.TCPConnector(
                        limit=100,
                        limit_per_host=20,
                        keepalive_timeout=30
                    )
                    
                    self._session = aiohttp.ClientSession(
                        headers=headers,
                        timeout=self.timeout,
                        connector=connector
                    )
        
        return self._session
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        retry_count: int = 0,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        Make an async HTTP request with intelligent rate limiting and retry logic
        """
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        
        async with self.rate_limit_semaphore:
            # Check rate limit before making request
            await self._handle_rate_limit()
            
            session = await self._get_session()
            start_time = time.time()
            
            try:
                async with session.request(
                    method=method,
                    url=url,
                    params=params,
                    json=data if data else None
                ) as response:
                    
                    response_time = time.time() - start_time
                    self.metrics["requests_made"] += 1
                    self.metrics["total_response_time"] += response_time
                    self.metrics["avg_response_time"] = (
                        self.metrics["total_response_time"] / self.metrics["requests_made"]
                    )
                    
                    # Update rate limit info
                    await self._update_rate_limit_info(response)
                    
                    # Handle different response codes
                    if response.status == 200:
                        content = await response.text()
                        self.metrics["bytes_transferred"] += len(content.encode())
                        self.metrics["successful_requests"] += 1
                        
                        try:
                            return json.loads(content)
                        except json.JSONDecodeError:
                            return {"content": content}
                    
                    elif response.status == 403:
                        # Rate limit exceeded
                        self.metrics["rate_limited_requests"] += 1
                        
                        if retry_count < max_retries:
                            wait_time = await self._calculate_backoff_time(response)
                            logger.warning(f"Rate limited, waiting {wait_time}s before retry {retry_count + 1}/{max_retries}")
                            await asyncio.sleep(wait_time)
                            return await self._make_request(method, endpoint, params, data, retry_count + 1, max_retries)
                        else:
                            raise aiohttp.ClientError(f"Rate limit exceeded after {max_retries} retries")
                    
                    elif response.status == 404:
                        return {"error": "Not found", "status": 404}
                    
                    elif response.status >= 500:
                        # Server error - retry with exponential backoff
                        if retry_count < max_retries:
                            wait_time = (2 ** retry_count) + (asyncio.get_event_loop().time() % 1)  # Add jitter
                            logger.warning(f"Server error {response.status}, retrying in {wait_time:.2f}s")
                            await asyncio.sleep(wait_time)
                            return await self._make_request(method, endpoint, params, data, retry_count + 1, max_retries)
                        else:
                            raise aiohttp.ClientError(f"Server error {response.status} after {max_retries} retries")
                    
                    else:
                        error_text = await response.text()
                        raise aiohttp.ClientError(f"HTTP {response.status}: {error_text}")
                        
            except asyncio.TimeoutError:
                self.metrics["failed_requests"] += 1
                if retry_count < max_retries:
                    wait_time = (2 ** retry_count)
                    logger.warning(f"Request timeout, retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
                    return await self._make_request(method, endpoint, params, data, retry_count + 1, max_retries)
                else:
                    raise
            
            except Exception as e:
                self.metrics["failed_requests"] += 1
                logger.error(f"Request failed: {method} {url} - {str(e)}")
                raise
    
    async def _handle_rate_limit(self):
        """Handle rate limiting before making requests"""
        async with self.rate_limit_lock:
            if self.rate_limit_info and self.rate_limit_info.remaining <= 10:
                wait_time = self.rate_limit_info.seconds_until_reset + 1
                if wait_time > 0:
                    logger.warning(f"Approaching rate limit, waiting {wait_time}s")
                    await asyncio.sleep(wait_time)
    
    async def _update_rate_limit_info(self, response: aiohttp.ClientResponse):
        """Update rate limit information from response headers"""
        async with self.rate_limit_lock:
            try:
                self.rate_limit_info = GitHubRateLimit(
                    limit=int(response.headers.get('X-RateLimit-Limit', 5000)),
                    remaining=int(response.headers.get('X-RateLimit-Remaining', 5000)),
                    reset=int(response.headers.get('X-RateLimit-Reset', int(time.time()) + 3600)),
                    used=int(response.headers.get('X-RateLimit-Used', 0))
                )
            except (ValueError, TypeError):
                pass  # Invalid headers, keep existing rate limit info
    
    async def _calculate_backoff_time(self, response: aiohttp.ClientResponse) -> float:
        """Calculate backoff time for rate limited requests"""
        reset_time = response.headers.get('X-RateLimit-Reset')
        if reset_time:
            try:
                reset_timestamp = int(reset_time)
                wait_time = max(1.0, reset_timestamp - time.time())
                return min(wait_time, 3600)  # Max 1 hour wait
            except ValueError:
                pass
        
        return 60.0  # Default 1 minute backoff
    
    async def get_repository_async(self, owner: str, repo: str) -> Optional[GitHubRepository]:
        """Get repository information asynchronously"""
        try:
            data = await self._make_request('GET', f'/repos/{owner}/{repo}')
            
            if 'error' in data:
                logger.warning(f"Repository not found: {owner}/{repo}")
                return None
            
            return GitHubRepository(
                id=data.get('id'),
                name=data.get('name'),
                full_name=data.get('full_name'),
                private=data.get('private', False),
                default_branch=data.get('default_branch', 'main'),
                clone_url=data.get('clone_url'),
                ssh_url=data.get('ssh_url'),
                size=data.get('size', 0),
                language=data.get('language'),
                languages_url=data.get('languages_url'),
                created_at=data.get('created_at'),
                updated_at=data.get('updated_at'),
                pushed_at=data.get('pushed_at')
            )
            
        except Exception as e:
            logger.error(f"Failed to get repository {owner}/{repo}: {e}")
            return None
    
    async def get_repository_languages_async(self, owner: str, repo: str) -> Dict[str, int]:
        """Get repository languages asynchronously"""
        try:
            data = await self._make_request('GET', f'/repos/{owner}/{repo}/languages')
            return data if not isinstance(data, dict) or 'error' not in data else {}
        except Exception as e:
            logger.error(f"Failed to get languages for {owner}/{repo}: {e}")
            return {}
    
    async def get_repository_contents_async(
        self, 
        owner: str, 
        repo: str, 
        path: str = "", 
        ref: str = None
    ) -> List[Dict[str, Any]]:
        """Get repository contents asynchronously"""
        try:
            params = {"ref": ref} if ref else None
            data = await self._make_request('GET', f'/repos/{owner}/{repo}/contents/{path}', params=params)
            
            if 'error' in data:
                return []
            
            # Ensure we return a list
            return data if isinstance(data, list) else [data]
            
        except Exception as e:
            logger.error(f"Failed to get contents for {owner}/{repo}/{path}: {e}")
            return []
    
    async def get_file_content_async(
        self, 
        owner: str, 
        repo: str, 
        path: str, 
        ref: str = None
    ) -> Optional[str]:
        """Get file content asynchronously"""
        try:
            params = {"ref": ref} if ref else None
            data = await self._make_request('GET', f'/repos/{owner}/{repo}/contents/{path}', params=params)
            
            if 'error' in data or 'content' not in data:
                return None
            
            # Decode base64 content
            content_b64 = data['content'].replace('\n', '')
            content = base64.b64decode(content_b64).decode('utf-8')
            return content
            
        except Exception as e:
            logger.error(f"Failed to get file content {owner}/{repo}/{path}: {e}")
            return None
    
    async def get_repository_branches_async(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Get repository branches asynchronously"""
        try:
            data = await self._make_request('GET', f'/repos/{owner}/{repo}/branches')
            return data if not isinstance(data, dict) or 'error' not in data else []
        except Exception as e:
            logger.error(f"Failed to get branches for {owner}/{repo}: {e}")
            return []
    
    async def get_pull_request_async(self, owner: str, repo: str, pr_number: int) -> Optional[Dict[str, Any]]:
        """Get pull request information asynchronously"""
        try:
            data = await self._make_request('GET', f'/repos/{owner}/{repo}/pulls/{pr_number}')
            return data if 'error' not in data else None
        except Exception as e:
            logger.error(f"Failed to get pull request {owner}/{repo}/pulls/{pr_number}: {e}")
            return None
    
    async def get_pull_request_files_async(self, owner: str, repo: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get pull request changed files asynchronously"""
        try:
            data = await self._make_request('GET', f'/repos/{owner}/{repo}/pulls/{pr_number}/files')
            return data if not isinstance(data, dict) or 'error' not in data else []
        except Exception as e:
            logger.error(f"Failed to get PR files {owner}/{repo}/pulls/{pr_number}: {e}")
            return []
    
    async def create_issue_comment_async(
        self, 
        owner: str, 
        repo: str, 
        issue_number: int, 
        body: str
    ) -> Optional[Dict[str, Any]]:
        """Create an issue comment asynchronously"""
        try:
            data = {"body": body}
            result = await self._make_request('POST', f'/repos/{owner}/{repo}/issues/{issue_number}/comments', data=data)
            return result if 'error' not in result else None
        except Exception as e:
            logger.error(f"Failed to create issue comment {owner}/{repo}/{issue_number}: {e}")
            return None
    
    async def get_repositories_concurrent(self, repo_specs: List[Tuple[str, str]]) -> Dict[str, Optional[GitHubRepository]]:
        """Get multiple repositories concurrently"""
        async def get_single_repo(owner: str, repo: str) -> Tuple[str, Optional[GitHubRepository]]:
            result = await self.get_repository_async(owner, repo)
            return f"{owner}/{repo}", result
        
        tasks = [get_single_repo(owner, repo) for owner, repo in repo_specs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        repositories = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Repository fetch failed: {result}")
                continue
            repo_key, repo_data = result
            repositories[repo_key] = repo_data
        
        return repositories
    
    async def batch_language_detection(self, repo_specs: List[Tuple[str, str]]) -> Dict[str, Dict[str, int]]:
        """Batch language detection for multiple repositories"""
        async def get_languages(owner: str, repo: str) -> Tuple[str, Dict[str, int]]:
            languages = await self.get_repository_languages_async(owner, repo)
            return f"{owner}/{repo}", languages
        
        tasks = [get_languages(owner, repo) for owner, repo in repo_specs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_languages = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Language detection failed: {result}")
                continue
            repo_key, languages = result
            all_languages[repo_key] = languages
        
        return all_languages
    
    def get_rate_limit_info(self) -> Optional[GitHubRateLimit]:
        """Get current rate limit information"""
        return self.rate_limit_info
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        metrics = self.metrics.copy()
        
        # Add current rate limit info
        if self.rate_limit_info:
            metrics["rate_limit"] = asdict(self.rate_limit_info)
        
        # Add timestamp
        metrics["timestamp"] = datetime.now(timezone.utc).isoformat()
        
        return metrics
    
    def reset_metrics(self):
        """Reset performance metrics"""
        self.metrics = {
            "requests_made": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "rate_limited_requests": 0,
            "total_response_time": 0.0,
            "avg_response_time": 0.0,
            "bytes_transferred": 0
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on GitHub API connection"""
        try:
            start_time = time.time()
            await self._make_request('GET', '/rate_limit')
            response_time = time.time() - start_time
            
            return {
                "status": "healthy",
                "response_time": response_time,
                "rate_limit": asdict(self.rate_limit_info) if self.rate_limit_info else None,
                "metrics": self.get_performance_metrics()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "metrics": self.get_performance_metrics()
            }
    
    async def close(self):
        """Close the aiohttp session"""
        if self._session and not self._session.closed:
            await self._session.close()

# Factory function for creating GitHub clients
def create_async_github_client(
    token: str,
    max_concurrent: int = 10,
    timeout: int = 30
) -> AsyncGitHubClient:
    """Create an async GitHub client with optimal settings"""
    return AsyncGitHubClient(
        token=token,
        max_concurrent_requests=max_concurrent,
        timeout=timeout
    )