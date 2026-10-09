"""
Async GitHub Client for Non-Blocking API Calls
Replaces synchronous PyGithub with async httpx-based implementation
"""

import asyncio
import httpx
import logging
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
import json
import os
import sys

# Add the app directory to the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
from core.timeout_config import get_github_timeout

logger = logging.getLogger(__name__)

class AsyncGitHubClient:
    """Async GitHub API client for non-blocking operations"""
    
    def __init__(self, token: str, timeout: Optional[int] = None):
        self.token = token
        self.base_url = "https://api.github.com"
        # Use centralized timeout configuration or provided timeout
        self.timeout = timeout or get_github_timeout()
        logger.info(f"AsyncGitHubClient initialized with timeout: {self.timeout}s")
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "DevSecureX/1.0"
        }
    
    async def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make async HTTP request to GitHub API with configurable timeouts"""
        url = f"{self.base_url}{endpoint}"
        
        # Use httpx.Timeout object for more granular control
        timeout_config = httpx.Timeout(
            connect=30.0,   # Connection timeout
            read=self.timeout,  # Read timeout (can be long for large responses)
            write=30.0,     # Write timeout
            pool=10.0       # Pool timeout
        )
        
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    **kwargs
                )
                response.raise_for_status()
                return response.json()
            
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    raise ValueError(f"Resource not found: {endpoint}")
                elif e.response.status_code == 403:
                    raise ValueError(f"GitHub API rate limit or insufficient permissions: {e.response.text}")
                else:
                    raise ValueError(f"GitHub API error {e.response.status_code}: {e.response.text}")
            except httpx.TimeoutException:
                raise ValueError(f"GitHub API timeout for {endpoint}")
            except Exception as e:
                raise ValueError(f"GitHub API request failed: {str(e)}")
    
    async def get_repository(self, repo_full_name: str) -> Dict[str, Any]:
        """Get repository information"""
        return await self._make_request("GET", f"/repos/{repo_full_name}")
    
    async def get_pull_requests(
        self,
        repo_full_name: str,
        state: str = "all",
        sort: str = "updated",
        direction: str = "desc",
        per_page: int = 50,
        page: int = 1
    ) -> List[Dict[str, Any]]:
        """Get pull requests with pagination support"""
        
        params = {
            "state": state,
            "sort": sort,
            "direction": direction,
            "per_page": min(per_page, 100),  # GitHub API limit
            "page": page
        }
        
        data = await self._make_request(
            "GET",
            f"/repos/{repo_full_name}/pulls",
            params=params
        )
        
        # Process PR data to match expected format
        processed_prs = []
        for pr in data:
            processed_pr = {
                "number": pr["number"],
                "title": pr["title"],
                "body": pr.get("body", ""),
                "state": pr["state"],
                "created_at": pr["created_at"],
                "updated_at": pr["updated_at"],
                "merged_at": pr.get("merged_at"),
                "closed_at": pr.get("closed_at"),
                "merged": pr.get("merged", False),
                "author": {
                    "login": pr["user"]["login"] if pr["user"] else None,
                    "avatar_url": pr["user"]["avatar_url"] if pr["user"] else None,
                    "type": pr["user"]["type"] if pr["user"] else None
                },
                "head": {
                    "ref": pr["head"]["ref"] if pr["head"] else None,
                    "sha": pr["head"]["sha"] if pr["head"] else None,
                    "repo_name": pr["head"]["repo"]["full_name"] if pr["head"] and pr["head"]["repo"] else None
                },
                "base": {
                    "ref": pr["base"]["ref"] if pr["base"] else None,
                    "sha": pr["base"]["sha"] if pr["base"] else None,
                    "repo_name": pr["base"]["repo"]["full_name"] if pr["base"] and pr["base"]["repo"] else None
                },
                "mergeable": pr.get("mergeable"),
                "mergeable_state": pr.get("mergeable_state"),
                "draft": pr.get("draft", False),
                "additions": pr.get("additions", 0),
                "deletions": pr.get("deletions", 0),
                "changed_files": pr.get("changed_files", 0),
                "commits": pr.get("commits", 0),
                "labels": [{"name": label["name"], "color": label["color"]} for label in pr.get("labels", [])],
                "assignees": [{"login": a["login"], "avatar_url": a["avatar_url"]} for a in pr.get("assignees", [])],
                "requested_reviewers": [{"login": r["login"]} for r in pr.get("requested_reviewers", [])],
                "milestone": {
                    "title": pr["milestone"]["title"],
                    "state": pr["milestone"]["state"],
                    "due_on": pr["milestone"]["due_on"]
                } if pr.get("milestone") else None,
                "comments_count": pr.get("comments", 0),
                "review_comments_count": pr.get("review_comments", 0),
                "url": pr["html_url"]
            }
            processed_prs.append(processed_pr)
        
        return processed_prs
    
    async def get_pull_request(self, repo_full_name: str, pr_number: int) -> Dict[str, Any]:
        """Get detailed pull request information"""
        pr_data = await self._make_request("GET", f"/repos/{repo_full_name}/pulls/{pr_number}")
        
        # Process the data similar to get_pull_requests but for single PR
        return {
            "number": pr_data["number"],
            "title": pr_data["title"],
            "body": pr_data.get("body", ""),
            "state": pr_data["state"],
            "created_at": pr_data["created_at"],
            "updated_at": pr_data["updated_at"],
            "merged_at": pr_data.get("merged_at"),
            "closed_at": pr_data.get("closed_at"),
            "merged": pr_data.get("merged", False),
            "author": {
                "login": pr_data["user"]["login"] if pr_data["user"] else None,
                "avatar_url": pr_data["user"]["avatar_url"] if pr_data["user"] else None,
                "type": pr_data["user"]["type"] if pr_data["user"] else None
            },
            "head": {
                "ref": pr_data["head"]["ref"] if pr_data["head"] else None,
                "sha": pr_data["head"]["sha"] if pr_data["head"] else None,
                "repo_name": pr_data["head"]["repo"]["full_name"] if pr_data["head"] and pr_data["head"]["repo"] else None
            },
            "base": {
                "ref": pr_data["base"]["ref"] if pr_data["base"] else None,
                "sha": pr_data["base"]["sha"] if pr_data["base"] else None,
                "repo_name": pr_data["base"]["repo"]["full_name"] if pr_data["base"] and pr_data["base"]["repo"] else None
            },
            "mergeable": pr_data.get("mergeable"),
            "mergeable_state": pr_data.get("mergeable_state"),
            "draft": pr_data.get("draft", False),
            "additions": pr_data.get("additions", 0),
            "deletions": pr_data.get("deletions", 0),
            "changed_files": pr_data.get("changed_files", 0),
            "commits": pr_data.get("commits", 0),
            "labels": [{"name": label["name"], "color": label["color"]} for label in pr_data.get("labels", [])],
            "assignees": [{"login": a["login"], "avatar_url": a["avatar_url"]} for a in pr_data.get("assignees", [])],
            "requested_reviewers": [{"login": r["login"]} for r in pr_data.get("requested_reviewers", [])],
            "milestone": {
                "title": pr_data["milestone"]["title"],
                "state": pr_data["milestone"]["state"],
                "due_on": pr_data["milestone"]["due_on"]
            } if pr_data.get("milestone") else None,
            "comments_count": pr_data.get("comments", 0),
            "review_comments_count": pr_data.get("review_comments", 0),
            "url": pr_data["html_url"]
        }
    
    async def get_pull_request_files(self, repo_full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get files changed in a pull request"""
        logger.info(f"Fetching files for PR {repo_full_name}#{pr_number}")
        files_data = await self._make_request("GET", f"/repos/{repo_full_name}/pulls/{pr_number}/files")
        logger.info(f"PR {repo_full_name}#{pr_number}: GitHub returned {len(files_data)} files")
        
        processed_files = []
        for file in files_data:
            file_additions = file.get("additions", 0)
            file_deletions = file.get("deletions", 0)
            logger.debug(f"GitHub file {file.get('filename', 'unknown')}: +{file_additions}/-{file_deletions}")
            
            processed_file = {
                "filename": file["filename"],
                "status": file["status"],
                "additions": file_additions,
                "deletions": file_deletions,
                "changes": file["changes"],
                "patch": file.get("patch", ""),
                "previous_filename": file.get("previous_filename"),
                "blob_url": file["blob_url"],
                "raw_url": file["raw_url"]
            }
            processed_files.append(processed_file)
        
        return processed_files
    
    async def get_pull_request_reviews(self, repo_full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get pull request reviews"""
        reviews_data = await self._make_request("GET", f"/repos/{repo_full_name}/pulls/{pr_number}/reviews")
        
        processed_reviews = []
        for review in reviews_data:
            processed_review = {
                "id": review["id"],
                "user": review["user"]["login"] if review["user"] else None,
                "state": review["state"],
                "body": review.get("body", ""),
                "submitted_at": review.get("submitted_at")
            }
            processed_reviews.append(processed_review)
        
        return processed_reviews
    
    async def get_pull_request_commits(self, repo_full_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get commits from a pull request"""
        commits_data = await self._make_request("GET", f"/repos/{repo_full_name}/pulls/{pr_number}/commits")
        
        processed_commits = []
        for commit in commits_data:
            processed_commit = {
                "sha": commit["sha"],
                "message": commit["commit"]["message"],
                "author": {
                    "name": commit["commit"]["author"]["name"] if commit["commit"]["author"] else None,
                    "email": commit["commit"]["author"]["email"] if commit["commit"]["author"] else None,
                    "date": commit["commit"]["author"]["date"] if commit["commit"]["author"] else None
                },
                "committer": {
                    "name": commit["commit"]["committer"]["name"] if commit["commit"]["committer"] else None,
                    "email": commit["commit"]["committer"]["email"] if commit["commit"]["committer"] else None,
                    "date": commit["commit"]["committer"]["date"] if commit["commit"]["committer"] else None
                },
                "url": commit["html_url"],
                "additions": commit["stats"]["additions"] if "stats" in commit else 0,
                "deletions": commit["stats"]["deletions"] if "stats" in commit else 0,
                "total": commit["stats"]["total"] if "stats" in commit else 0
            }
            processed_commits.append(processed_commit)
        
        return processed_commits

    async def create_pull_request_review(
        self,
        repo_full_name: str,
        pr_number: int,
        body: str,
        event: str = "COMMENT",
        comments: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Create a pull request review"""
        data = {
            "body": body,
            "event": event
        }
        
        if comments:
            data["comments"] = comments
        
        return await self._make_request(
            "POST",
            f"/repos/{repo_full_name}/pulls/{pr_number}/reviews",
            json=data
        )
    
    async def create_issue_comment(
        self,
        repo_full_name: str,
        issue_number: int,
        body: str
    ) -> Dict[str, Any]:
        """Create a comment on an issue or pull request"""
        data = {"body": body}
        
        return await self._make_request(
            "POST",
            f"/repos/{repo_full_name}/issues/{issue_number}/comments",
            json=data
        )

# Utility functions for batching operations
async def batch_github_requests(client: AsyncGitHubClient, requests: List[callable], batch_size: int = 5) -> List[Any]:
    """Execute GitHub API requests in batches to respect rate limits"""
    results = []
    
    for i in range(0, len(requests), batch_size):
        batch = requests[i:i + batch_size]
        
        # Execute batch concurrently
        batch_results = await asyncio.gather(*[req() for req in batch], return_exceptions=True)
        
        # Process results and handle exceptions
        for result in batch_results:
            if isinstance(result, Exception):
                logger.error(f"Batch request failed: {result}")
                results.append(None)
            else:
                results.append(result)
        
        # Small delay between batches to be respectful to GitHub API
        if i + batch_size < len(requests):
            await asyncio.sleep(0.1)
    
    return results