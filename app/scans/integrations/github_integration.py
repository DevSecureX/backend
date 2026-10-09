import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from github import Github, GithubException
from fastapi import HTTPException
from .pr_comment_builder import PRCommentBuilder

logger = logging.getLogger(__name__)

class GitHubIntegration:
    def __init__(self):
        self.check_run_name = "Security Scan"
        self.comment_builder = PRCommentBuilder()
        
    async def update_check_run(
        self,
        repo_full_name: str,
        commit_sha: str,
        status: str,
        gh_token: str,
        conclusion: Optional[str] = None,
        scan_result: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None
    ):
        """Create or update GitHub check run"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            
            if status == "pending":
                check_run = repo.create_check_run(
                    name=self.check_run_name,
                    head_sha=commit_sha,
                    status="in_progress",
                    started_at=datetime.now(timezone.utc)
                )
                
                logger.info(f"Created pending check run for {repo_full_name}@{commit_sha}")
                
            elif status == "completed":
                if not scan_result:
                    raise ValueError("scan_result required for completed status")
                
                output = self._generate_check_run_output(scan_result, scan_id)
                
                # Try to find existing check run first
                existing_check_run = None
                try:
                    check_runs = repo.get_check_runs_for_ref(commit_sha, check_name=self.check_run_name)
                    if check_runs.totalCount > 0:
                        existing_check_run = check_runs[0]
                except:
                    pass
                
                if existing_check_run:
                    # Update existing check run
                    existing_check_run.edit(
                        status="completed",
                        conclusion=conclusion or "success",
                        completed_at=datetime.now(timezone.utc),
                        output=output
                    )
                    check_run = existing_check_run
                else:
                    # Create new check run
                    check_run = repo.create_check_run(
                        name=self.check_run_name,
                        head_sha=commit_sha,
                        status="completed",
                        conclusion=conclusion or "success",
                        completed_at=datetime.now(timezone.utc),
                        output=output
                    )
                
                logger.info(f"Updated check run for {repo_full_name}@{commit_sha} with conclusion {conclusion}")
                
        except GithubException as e:
            if e.status == 403:
                logger.error(f"No permission to create check runs for {repo_full_name}")
                # Don't fail the entire scan if check runs aren't available
                return
            elif e.status == 429:
                logger.error(f"GitHub API rate limit exceeded")
                raise HTTPException(status_code=429, detail="GitHub API rate limit exceeded")
            else:
                logger.error(f"GitHub API error updating check run: {e}")
                raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")
        except Exception as e:
            logger.error(f"Error updating check run: {e}")
            raise
    
    def _generate_check_run_output(self, scan_result: Dict[str, Any], scan_id: Optional[str]) -> Dict[str, Any]:
        """Generate check run output from scan results"""
        
        issues = scan_result.get("issues", [])
        scores = scan_result.get("scores", {})
        metadata = scan_result.get("metadata", {})
        
        total_score = scores.get("total_score", 0)
        issue_counts = self._count_issues_by_severity(issues)
        
        # Generate title
        title = f"Security Scan Results - Score: {total_score}/100"
        
        # Generate summary
        summary_parts = [
            f"**Overall Security Score:** {total_score}/100",
            f"**Total Issues Found:** {len(issues)}",
            ""
        ]
        
        if issue_counts["critical"] > 0:
            summary_parts.append(f"🚨 **Critical Issues:** {issue_counts['critical']}")
        if issue_counts["high"] > 0:
            summary_parts.append(f"⚠️ **High Severity:** {issue_counts['high']}")
        if issue_counts["medium"] > 0:
            summary_parts.append(f"⚡ **Medium Severity:** {issue_counts['medium']}")
        if issue_counts["low"] > 0:
            summary_parts.append(f"ℹ️ **Low Severity:** {issue_counts['low']}")
        
        summary_parts.extend([
            "",
            f"**Scan Duration:** {metadata.get('scan_duration', 0):.1f} seconds",
            f"**Tools Used:** {', '.join(metadata.get('tools_used', []))}"
        ])
        
        if scan_id:
            summary_parts.extend([
                "",
                f"[View Detailed Report](https://app.devsecurex.com/scans/{scan_id})"
            ])
        
        # Generate detailed text
        detailed_text = self._generate_detailed_report(issues, scores)
        
        return {
            "title": title,
            "summary": "\n".join(summary_parts),
            "text": detailed_text
        }
    
    def _count_issues_by_severity(self, issues: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count issues by severity level"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for issue in issues:
            severity = issue.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _generate_detailed_report(self, issues: List[Dict[str, Any]], scores: Dict[str, Any]) -> str:
        """Generate detailed markdown report"""
        
        if not issues:
            return "✅ No security issues found! Your code looks secure."
        
        # Group issues by category
        categories = {}
        for issue in issues:
            category = issue.get("category", "other")
            if category not in categories:
                categories[category] = []
            categories[category].append(issue)
        
        report_parts = ["## Detailed Findings\n"]
        
        for category, category_issues in categories.items():
            report_parts.append(f"### {category.title()} Issues ({len(category_issues)})\n")
            
            # Show top 5 issues per category
            for issue in category_issues[:5]:
                severity_emoji = self._get_severity_emoji(issue.get("severity", "medium"))
                
                report_parts.append(
                    f"{severity_emoji} **{issue.get('message', 'Security issue')}**\n"
                    f"- File: `{issue.get('file_path', 'unknown')}`"
                )
                
                if issue.get("line_start"):
                    report_parts[-1] += f" (Line {issue['line_start']})"
                
                report_parts[-1] += f"\n- Tool: {issue.get('tool', 'unknown')}"
                
                if issue.get("rule_id"):
                    report_parts[-1] += f" | Rule: `{issue['rule_id']}`"
                
                report_parts.append("")
            
            if len(category_issues) > 5:
                report_parts.append(f"*... and {len(category_issues) - 5} more {category} issues*\n")
        
        # Add category scores
        if scores:
            report_parts.extend([
                "## Category Scores\n",
                f"- **Code Quality:** {scores.get('code_score', 'N/A')}/100",
                f"- **Dependencies:** {scores.get('deps_score', 'N/A')}/100",
                f"- **Secrets:** {scores.get('secrets_score', 'N/A')}/100", 
                f"- **Configuration:** {scores.get('configs_score', 'N/A')}/100",
                ""
            ])
        
        return "\n".join(report_parts)
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emoji_map = {
            "critical": "🚨",
            "high": "⚠️", 
            "medium": "⚡",
            "low": "ℹ️"
        }
        return emoji_map.get(severity, "ℹ️")
    
    async def comment_on_pr(
        self,
        repo_full_name: str,
        pr_number: int,
        scan_result: Dict[str, Any],
        explanations: Dict[str, Dict[str, Any]],
        gh_token: str
    ):
        """Comment scan results on PR"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Generate PR comment
            comment = self._generate_pr_comment(scan_result, explanations)
            
            # Check if we already commented on this PR
            existing_comments = pr.get_issue_comments()
            security_scan_comment = None
            
            for comment_obj in existing_comments:
                if "Security Scan Results" in comment_obj.body:
                    security_scan_comment = comment_obj
                    break
            
            if security_scan_comment:
                # Update existing comment
                security_scan_comment.edit(comment)
                logger.info(f"Updated security comment on PR #{pr_number}")
            else:
                # Create new comment
                pr.create_issue_comment(comment)
                logger.info(f"Created security comment on PR #{pr_number}")
                
        except GithubException as e:
            logger.error(f"GitHub API error commenting on PR: {e}")
        except Exception as e:
            logger.error(f"Error commenting on PR: {e}")
    
    def _generate_pr_comment(
        self, 
        scan_result: Dict[str, Any], 
        explanations: Dict[str, Dict[str, Any]]
    ) -> str:
        """Generate PR comment with scan results"""
        
        issues = scan_result.get("issues", [])
        scores = scan_result.get("scores", {})
        total_score = scores.get("total_score", 0)
        
        # Filter for critical and high severity issues only
        critical_high_issues = [
            issue for issue in issues 
            if issue.get("severity") in ["critical", "high"]
        ]
        
        if not critical_high_issues:
            return (
                "## 🛡️ Security Scan Results\n\n"
                f"✅ **Great news!** No critical or high severity security issues found.\n\n"
                f"**Security Score:** {total_score}/100\n"
                f"**Total Issues:** {len(issues)} (all low/medium severity)\n\n"
                "*This comment is automatically generated by the security scanner.*"
            )
        
        comment_parts = [
            "## 🛡️ Security Scan Results\n",
            f"**Security Score:** {total_score}/100",
            f"**Critical/High Issues:** {len(critical_high_issues)}",
            f"**Total Issues:** {len(issues)}\n"
        ]
        
        if len(critical_high_issues) > 0:
            comment_parts.append("### 🚨 Issues Requiring Attention\n")
            
            for issue in critical_high_issues[:10]:  # Show top 10 (increased from 3)
                severity_emoji = self._get_severity_emoji(issue.get("severity"))
                
                comment_parts.extend([
                    f"#### {severity_emoji} {issue.get('message', 'Security Issue')}",
                    f"**File:** `{issue.get('file_path', 'unknown')}`"
                ])
                
                if issue.get("line_start"):
                    comment_parts[-1] += f" (Line {issue['line_start']})"
                
                comment_parts.append(f"**Tool:** {issue.get('tool', 'unknown')}")
                
                # Add AI explanation if available
                issue_id = self._generate_issue_id_for_comment(issue)
                if issue_id in explanations:
                    explanation = explanations[issue_id]
                    comment_parts.extend([
                        "**Explanation:**",
                        explanation.get("explanation", "No explanation available"),
                        "**Suggested Fix:**", 
                        explanation.get("fix_suggestion", "Review code and apply security best practices")
                    ])
                
                comment_parts.append("")  # Empty line between issues
            
            if len(critical_high_issues) > 3:
                comment_parts.append(f"*... and {len(critical_high_issues) - 3} more critical/high issues*\n")
        
        comment_parts.append("*This comment is automatically generated by the security scanner.*")
        
        return "\n".join(comment_parts)
    
    def _generate_issue_id_for_comment(self, issue: Dict[str, Any]) -> str:
        """Generate issue ID for looking up explanations"""
        import hashlib
        import json
        
        issue_data = {
            "tool": issue.get("tool"),
            "rule_id": issue.get("rule_id"),
            "file_path": issue.get("file_path"),
            "line_start": issue.get("line_start"),
            "message": issue.get("message")
        }
        
        issue_str = json.dumps(issue_data, sort_keys=True)
        return hashlib.md5(issue_str.encode()).hexdigest()
    
    async def create_pr_review(
        self,
        repo_full_name: str,
        pr_number: int,
        scan_result: Dict[str, Any],
        gh_token: str,
        scan_id: Optional[str] = None,
        user_review_action: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a comprehensive PR review with inline comments"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Check if PR is still open
            if pr.state != "open":
                logger.info(f"PR {pr_number} is {pr.state}, skipping review")
                return {
                    "review_id": None,
                    "review_action": "SKIPPED",
                    "inline_comments_count": 0,
                    "review_url": None
                }
            
            # Check for existing pending reviews from this user
            try:
                existing_reviews = list(pr.get_reviews())
                user_reviews = [r for r in existing_reviews if r.user and r.user.login == g.get_user().login]
                pending_reviews = [r for r in user_reviews if r.state == 'PENDING']
                
                if pending_reviews:
                    logger.warning(f"Found {len(pending_reviews)} pending review(s) from current user on PR #{pr_number}")
                    return {
                        "review_id": None,
                        "review_action": "PENDING_EXISTS",
                        "inline_comments_count": 0,
                        "review_url": None,
                        "message": f"{len(pending_reviews)} pending review(s) already exist. Please submit or dismiss them first."
                    }
                    
            except Exception as e:
                logger.warning(f"Could not check existing reviews: {e}")
                # Continue with creating review anyway
            
            # Get PR diff to map issues to diff lines
            pr_files = pr.get_files()
            file_diffs = {}
            for file in pr_files:
                file_diffs[file.filename] = {
                    "patch": file.patch,
                    "additions": file.additions,
                    "deletions": file.deletions
                }
            
            # Prepare issues and determine review action
            issues = scan_result.get("issues", [])
            
            # Use user's choice if provided, otherwise auto-determine
            if user_review_action and user_review_action in ['APPROVE', 'REQUEST_CHANGES', 'COMMENT']:
                review_action = user_review_action
                auto_recommended = self._determine_review_action(issues)
                logger.info(f"Using user-selected review action: {review_action} (system recommended: {auto_recommended})")
            else:
                review_action = self._determine_review_action(issues)
                logger.info(f"Auto-determined review action: {review_action}")
            
            # Build main review comment using our beautiful comment builder
            metadata = scan_result.get("metadata", {})
            metadata["scan_id"] = scan_id
            enhanced_result = {**scan_result, "metadata": metadata}
            review_body = self.comment_builder.build_security_comment(enhanced_result)
            
            # Build inline comments for issues in changed files
            inline_comments = []
            for issue in issues:
                if issue.get("severity") in ["critical", "high", "medium"]:
                    inline_comment = self._build_inline_review_comment(issue, file_diffs)
                    if inline_comment:
                        inline_comments.append(inline_comment)
            
            # Log the number of inline comments we're trying to create
            logger.info(f"Attempting to create review with {len(inline_comments)} inline comments")
            
            # Create the review - handle REQUEST_CHANGES specially to ensure it blocks
            try:
                if inline_comments:
                    # Try to create review with inline comments first
                    review = pr.create_review(
                        body=review_body,
                        event=review_action,
                        comments=inline_comments[:50]  # GitHub limits to 50 comments per review
                    )
                else:
                    # No inline comments - for REQUEST_CHANGES, ensure it's treated as blocking
                    if review_action == "REQUEST_CHANGES":
                        # GitHub needs specific conditions to create a blocking review
                        # Use a more explicit body that GitHub recognizes as requiring changes
                        blocking_review_body = f"""## 🚨 Security Review: Changes Required

{review_body}

### Action Required
This PR has been reviewed and **changes are required** before it can be merged. Please address the security issues listed above.

**Status: BLOCKED** - This PR cannot be merged until these issues are resolved."""
                        
                        review = pr.create_review(
                            body=blocking_review_body,
                            event=review_action
                        )
                    else:
                        # Regular comment review
                        review = pr.create_review(
                            body=review_body,
                            event=review_action
                        )
            except GithubException as inline_error:
                if inline_error.status == 422 and inline_comments:
                    # If inline comments caused 422, fallback with enhanced approach
                    logger.warning(f"Inline comments failed, using enhanced fallback for {review_action}: {inline_error}")
                    
                    if review_action == "REQUEST_CHANGES":
                        logger.info("Creating enhanced REQUEST_CHANGES review to ensure PR blocking behavior")
                        
                        # Try to create a general review comment that doesn't depend on diff positions
                        # This approach uses GitHub's "start a review" then "submit review" pattern
                        try:
                            # First, try the simple approach with enhanced messaging
                            blocking_body = f"""## 🚨 Security Review: Changes Required

{review_body}

### Required Actions:
- [ ] Address all critical and high severity security issues
- [ ] Review and fix medium severity issues  
- [ ] Request re-review after fixes are complete

**⚠️ This PR is blocked from merging until security issues are resolved.**

---
*This review was created by DevSecureX Security Scanner*"""
                            
                            review = pr.create_review(
                                body=blocking_body,
                                event="REQUEST_CHANGES"  # Explicitly use REQUEST_CHANGES
                            )
                            logger.info("Successfully created REQUEST_CHANGES review with enhanced blocking message")
                        except GithubException as fallback_error:
                            # If that still fails, log the issue but create a comment 
                            logger.error(f"Could not create REQUEST_CHANGES review, falling back to comment: {fallback_error}")
                            review = pr.create_review(
                                body=f"⚠️ **Note**: This should be a REQUEST_CHANGES review but GitHub API limitations forced a comment.\n\n{blocking_body}",
                                event="COMMENT"
                            )
                    else:
                        # For COMMENT reviews, use the original fallback
                        review = pr.create_review(
                            body=review_body,
                            event=review_action
                        )
                    
                    inline_comments = []  # Clear inline comments since they weren't used
                else:
                    raise inline_error
            
            logger.info(f"Created PR review for {repo_full_name}#{pr_number} with action: {review_action}")
            
            # Log basic review information
            logger.info(f"Created GitHub review - ID: {getattr(review, 'id', 'unknown')}, State: {getattr(review, 'state', 'unknown')}")
            
            return {
                "review_id": review.id,
                "review_action": review_action,
                "inline_comments_count": len(inline_comments),
                "review_url": review.html_url
            }
            
        except GithubException as e:
            # Log detailed error information
            error_data = getattr(e, 'data', {})
            logger.error(f"GitHub API error {e.status}: {e}")
            logger.error(f"Error details: {error_data}")
            
            if e.status == 403:
                logger.error(f"No permission to create PR reviews for {repo_full_name}")
                raise HTTPException(status_code=403, detail="Insufficient permissions for PR reviews")
            elif e.status == 422:
                # Check if the error is about pending reviews
                error_message = str(error_data.get('message', '')) if error_data else str(e)
                logger.error(f"Cannot create review: {error_message}")
                
                # Try to check for existing pending reviews
                try:
                    existing_reviews = list(pr.get_reviews())
                    pending_reviews = [r for r in existing_reviews if r.state == 'PENDING']
                    logger.info(f"Found {len(pending_reviews)} pending reviews on PR #{pr_number}")
                    
                    if pending_reviews:
                        # Cannot create review when pending reviews exist
                        logger.info("Found existing pending reviews, cannot create new review")
                        raise HTTPException(
                            status_code=422, 
                            detail=f"Cannot create review - {len(pending_reviews)} pending review(s) already exist. Please submit or dismiss existing reviews first."
                        )
                    else:
                        raise HTTPException(status_code=422, detail=f"Cannot create review: {error_message}")
                except Exception as review_check_error:
                    logger.error(f"Failed to check existing reviews: {review_check_error}")
                    raise HTTPException(status_code=422, detail="Cannot create review - check PR status and existing reviews")
                    
            elif e.status == 429:
                logger.error(f"GitHub API rate limit exceeded")
                raise HTTPException(status_code=429, detail="GitHub API rate limit exceeded")
            else:
                logger.error(f"GitHub API error creating PR review: {e}")
                raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")
        except Exception as e:
            logger.error(f"Error creating PR review: {e}")
            raise
    
    def _determine_review_action(self, issues: List[Dict[str, Any]]) -> str:
        """Determine review action based on issues found"""
        critical_count = sum(1 for i in issues if i.get("severity") == "critical")
        high_count = sum(1 for i in issues if i.get("severity") == "high")
        
        if critical_count > 0:
            return "REQUEST_CHANGES"
        elif high_count > 2:
            return "REQUEST_CHANGES"
        else:
            return "COMMENT"
    
    def _build_inline_review_comment(
        self, 
        issue: Dict[str, Any], 
        file_diffs: Dict[str, Dict]
    ) -> Optional[Dict[str, Any]]:
        """Build inline comment for PR review"""
        file_path = issue.get("file_path")
        line_number = issue.get("line_start")
        
        if not file_path or not line_number:
            return None
        
        # Check if file is in the PR diff
        if file_path not in file_diffs:
            return None
        
        # Try to find the line in the diff
        diff_info = file_diffs[file_path]
        if not diff_info.get("patch"):
            return None
        
        # Map line number to diff position
        diff_position = self._map_line_to_diff_position(
            diff_info["patch"], 
            line_number
        )
        
        if diff_position is None:
            return None
        
        # Build the inline comment
        comment_body = self.comment_builder.build_inline_comment(issue)
        
        return {
            "path": file_path,
            "position": diff_position,
            "body": comment_body
        }
    
    def _map_line_to_diff_position(self, patch: str, target_line: int) -> Optional[int]:
        """Map a file line number to diff position"""
        if not patch:
            return None
        
        lines = patch.split('\n')
        new_line_number = 0
        
        for i, line in enumerate(lines):
            if line.startswith('@@'):
                # Parse hunk header: @@ -old_start,old_lines +new_start,new_lines @@
                import re
                match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
                if match:
                    new_line_number = int(match.group(1)) - 1
            elif line.startswith('+++') or line.startswith('---'):
                # Skip file headers
                continue
            elif line.startswith('+'):
                # Added line
                new_line_number += 1
                if new_line_number == target_line:
                    # Return the position in the diff (1-indexed)
                    return i + 1
            elif line.startswith('-'):
                # Deleted line - don't increment new line number
                continue
            else:
                # Context line (no prefix or space prefix)
                new_line_number += 1
                if new_line_number == target_line:
                    # Return the position in the diff (1-indexed)
                    return i + 1
        
        # If we can't find the exact line, return None to skip inline comment
        return None
    
    async def post_pr_comment_async(
        self,
        repo_full_name: str,
        pr_number: int,
        scan_result: Dict[str, Any],
        gh_token: str,
        scan_id: Optional[str] = None
    ) -> str:
        """Post a regular PR comment (not a review) with scan results"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Build comment using our beautiful comment builder
            metadata = scan_result.get("metadata", {})
            metadata["scan_id"] = scan_id
            enhanced_result = {**scan_result, "metadata": metadata}
            comment_body = self.comment_builder.build_security_comment(enhanced_result)
            
            # Check if we already have a security comment
            existing_comments = pr.get_issue_comments()
            security_comment = None
            
            for comment in existing_comments:
                if "🔒 DevSecureX Security Analysis" in comment.body:
                    security_comment = comment
                    break
            
            if security_comment:
                # Update existing comment
                security_comment.edit(comment_body)
                logger.info(f"Updated security comment on PR #{pr_number}")
                return security_comment.html_url
            else:
                # Create new comment
                new_comment = pr.create_issue_comment(comment_body)
                logger.info(f"Created security comment on PR #{pr_number}")
                return new_comment.html_url
                
        except GithubException as e:
            logger.error(f"GitHub API error posting PR comment: {e}")
            raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")
        except Exception as e:
            logger.error(f"Error posting PR comment: {e}")
            raise