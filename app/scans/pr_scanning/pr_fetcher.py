from typing import List, Dict, Optional, Any
from datetime import datetime
import logging
from .async_github_client import AsyncGitHubClient

logger = logging.getLogger(__name__)

class PRFetcher:
    def __init__(self):
        self.default_limit = 50
        
    async def get_prs(
        self,
        repo_full_name: str,
        gh_token: str,
        state: str = 'all',
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Fetch pull requests from repository using async GitHub client"""
        
        try:
            client = AsyncGitHubClient(gh_token, timeout=30)
            
            # Validate state parameter
            valid_states = ['open', 'closed', 'all']
            if state not in valid_states:
                state = 'all'
            
            # Calculate pages needed
            per_page = min(100, limit)  # GitHub API max is 100
            pages_needed = (limit + per_page - 1) // per_page
            
            all_prs = []
            
            # Fetch pages concurrently for better performance
            import asyncio
            page_requests = []
            for page in range(1, pages_needed + 1):
                page_requests.append(
                    client.get_pull_requests(
                        repo_full_name=repo_full_name,
                        state=state,
                        sort='updated',
                        direction='desc',
                        per_page=per_page,
                        page=page
                    )
                )
            
            # Execute all page requests concurrently
            page_results = await asyncio.gather(*page_requests, return_exceptions=True)
            
            # Process results and handle exceptions
            for page_result in page_results:
                if isinstance(page_result, Exception):
                    logger.warning(f"Failed to fetch PR page: {page_result}")
                    continue
                
                all_prs.extend(page_result)
                
                # Stop if we have enough PRs
                if len(all_prs) >= limit:
                    break
            
            # Limit to requested number
            pr_list = all_prs[:limit]
            
            # Convert to legacy format for compatibility and fetch detailed stats
            formatted_prs = []
            
            # OPTIMIZATION: Skip detailed file fetching for PR list to prevent timeouts
            # Use PR-level stats from GitHub API instead of detailed file analysis
            logger.info(f"Using PR-level statistics for {len(pr_list)} PRs (optimized for performance)")
            all_pr_files = []
            
            # Combine list data with PR-level statistics (much faster)
            for i, pr in enumerate(pr_list):
                # Use PR-level statistics directly from GitHub API (already available)
                total_additions = pr.get("additions", 0)
                total_deletions = pr.get("deletions", 0) 
                total_changed_files = pr.get("changed_files", 0)
                
                logger.debug(f"PR #{pr['number']} stats: +{total_additions}/-{total_deletions} ({total_changed_files} files)")
                
                formatted_pr = {
                    "number": pr["number"],
                    "title": pr["title"],
                    "state": pr["state"],
                    "created_at": pr["created_at"],
                    "updated_at": pr["updated_at"],
                    "merged_at": pr.get("merged_at"),
                    "closed_at": pr.get("closed_at"),
                    "author": pr["author"]["login"],
                    "author_avatar": pr["author"]["avatar_url"],
                    "head_ref": pr["head"]["ref"],
                    "head_sha": pr["head"]["sha"],
                    "base_ref": pr["base"]["ref"],
                    "base_sha": pr["base"]["sha"],
                    "mergeable": pr.get("mergeable"),
                    "draft": pr.get("draft", False),
                    # Use PR-level statistics for performance (no file-level fetching)
                    "additions": total_additions,
                    "deletions": total_deletions,
                    "changed_files": total_changed_files,
                    "labels": [label["name"] for label in pr.get("labels", [])],
                    "assignees": [assignee["login"] for assignee in pr.get("assignees", [])],
                    "reviewers": [],  # Will be populated if needed
                    "comments_count": pr.get("comments_count", 0),
                    "review_comments_count": pr.get("review_comments_count", 0),
                    "url": pr["url"]
                }
                
                # Skip review fetching in list view for performance - can be fetched on demand
                formatted_pr["reviewers"] = []
                
                formatted_prs.append(formatted_pr)
            
            logger.info(f"Fetched {len(formatted_prs)} PRs from {repo_full_name} with state={state}")
            return formatted_prs
            
        except Exception as e:
            logger.error(f"Error fetching PRs: {e}")
            raise
    
    async def get_pr_details(
        self,
        repo_full_name: str,
        pr_number: int,
        gh_token: str
    ) -> Dict[str, Any]:
        """Get detailed information about a specific PR using async client"""
        
        try:
            client = AsyncGitHubClient(gh_token, timeout=30)
            
            # Fetch PR details, files, and reviews concurrently
            import asyncio
            pr_task = client.get_pull_request(repo_full_name, pr_number)
            files_task = client.get_pull_request_files(repo_full_name, pr_number)
            reviews_task = client.get_pull_request_reviews(repo_full_name, pr_number)
            
            pr_data, files_data, reviews_data = await asyncio.gather(
                pr_task, files_task, reviews_task,
                return_exceptions=True
            )
            
            # Handle potential exceptions
            if isinstance(pr_data, Exception):
                logger.error(f"Failed to fetch PR data: {pr_data}")
                raise pr_data
            
            if isinstance(files_data, Exception):
                logger.warning(f"Failed to fetch PR files: {files_data}")
                files_data = []
            
            if isinstance(reviews_data, Exception):
                logger.warning(f"Failed to fetch PR reviews: {reviews_data}")
                reviews_data = []
            
            # Add files and reviews to PR data
            pr_data["files"] = files_data
            pr_data["reviews"] = reviews_data
            
            return pr_data
            
        except Exception as e:
            logger.error(f"Error fetching PR details: {e}")
            raise
    
    async def get_pr_commits(
        self,
        repo_full_name: str,
        pr_number: int,
        gh_token: str
    ) -> List[Dict[str, Any]]:
        """Get commits from a PR using async client"""
        
        try:
            client = AsyncGitHubClient(gh_token, timeout=30)
            commits = await client.get_pull_request_commits(repo_full_name, pr_number)
            return commits
            
        except Exception as e:
            logger.error(f"Error fetching PR commits: {e}")
            raise