"""
Enhanced PR Review System - CodeRabbit-style code reviews with security focus
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from github import Github, GithubException
from ..pr_scanning.code_display import PRCodeDisplay
from ..ai.code_fixer import AICodeFixer
from .pr_comment_builder import PRCommentBuilder
import asyncio
import re

logger = logging.getLogger(__name__)

class EnhancedPRReview:
    """Create comprehensive PR reviews with inline code annotations"""
    
    def __init__(self, openai_api_key: Optional[str] = None):
        self.code_display = PRCodeDisplay()
        self.comment_builder = PRCommentBuilder()
        self.code_fixer = AICodeFixer(openai_api_key) if openai_api_key else None
        self.max_inline_comments = 30  # GitHub limit is 50, but we'll be conservative
        
    async def create_comprehensive_review(
        self,
        repo_full_name: str,
        pr_number: int,
        scan_result: Dict[str, Any],
        gh_token: str,
        scan_id: Optional[str] = None,
        enable_auto_fix: bool = True
    ) -> Dict[str, Any]:
        """Create a comprehensive PR review with code display and fixes"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Get all PR files and their content
            pr_files = list(pr.get_files())
            
            # Get issues grouped by file
            issues_by_file = self._group_issues_by_file(scan_result.get("issues", []))
            
            # Generate file tree overview
            file_tree = await self.code_display.get_pr_file_tree_with_issues(
                repo_full_name, pr_number, scan_result, gh_token
            )
            
            # Build main review comment with enhanced content
            review_body = await self._build_enhanced_review_body(
                scan_result, 
                file_tree,
                issues_by_file,
                pr_files,
                repo_full_name,
                pr_number,
                gh_token,
                scan_id
            )
            
            # Generate inline comments with code context
            inline_comments = await self._generate_enhanced_inline_comments(
                issues_by_file,
                pr_files,
                repo_full_name,
                pr_number,
                gh_token,
                enable_auto_fix
            )
            
            # Determine review action
            review_action = self._determine_review_action(scan_result.get("issues", []))
            
            # Create the review
            if inline_comments:
                # Prioritize inline comments (critical/high first)
                sorted_comments = sorted(
                    inline_comments,
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
                        x.get("severity", "low"), 3
                    )
                )
                
                review = pr.create_review(
                    body=review_body,
                    event=review_action,
                    comments=sorted_comments[:self.max_inline_comments]
                )
                
                # If there are more comments, post them separately
                if len(sorted_comments) > self.max_inline_comments:
                    remaining_comments = sorted_comments[self.max_inline_comments:]
                    await self._post_additional_comments(pr, remaining_comments)
                
            else:
                review = pr.create_review(
                    body=review_body,
                    event="COMMENT"
                )
            
            logger.info(f"Created enhanced PR review for {repo_full_name}#{pr_number}")
            
            return {
                "review_id": review.id,
                "review_url": review.html_url,
                "review_action": review_action,
                "inline_comments_count": len(inline_comments),
                "files_reviewed": len(issues_by_file),
                "total_issues": len(scan_result.get("issues", [])),
                "auto_fixes_suggested": sum(1 for c in inline_comments if c.get("has_fix"))
            }
            
        except Exception as e:
            logger.error(f"Error creating enhanced PR review: {e}")
            raise
    
    async def _build_enhanced_review_body(
        self,
        scan_result: Dict[str, Any],
        file_tree: Dict[str, Any],
        issues_by_file: Dict[str, List[Dict[str, Any]]],
        pr_files: List[Any],
        repo_full_name: str,
        pr_number: int,
        gh_token: str,
        scan_id: Optional[str] = None
    ) -> str:
        """Build enhanced review body with code snippets"""
        
        lines = []
        
        # Header
        scores = scan_result.get("scores", {})
        total_score = scores.get("total_score", 0)
        score_emoji = self._get_score_emoji(total_score)
        
        lines.extend([
            f"## 🔒 DevSecureX Security Review {score_emoji}",
            "",
            f"**Security Score: {total_score}/100**",
            ""
        ])
        
        # Summary statistics
        issues = scan_result.get("issues", [])
        issue_counts = self._count_issues_by_severity(issues)
        
        lines.extend([
            "### 📊 Summary",
            f"- **Files Changed:** {file_tree['total_files']}",
            f"- **Files with Issues:** {file_tree['files_with_issues']}",
            f"- **Total Issues:** {len(issues)}",
            ""
        ])
        
        if issue_counts["critical"] > 0:
            lines.append(f"🚨 **Critical:** {issue_counts['critical']}")
        if issue_counts["high"] > 0:
            lines.append(f"⚠️ **High:** {issue_counts['high']}")
        if issue_counts["medium"] > 0:
            lines.append(f"⚡ **Medium:** {issue_counts['medium']}")
        if issue_counts["low"] > 0:
            lines.append(f"ℹ️ **Low:** {issue_counts['low']}")
        
        lines.append("")
        
        # Most critical issues with code preview
        critical_high = [i for i in issues if i.get("severity") in ["critical", "high"]]
        
        if critical_high:
            lines.extend([
                "### 🔍 Critical Security Issues",
                ""
            ])
            
            # Show up to 10 critical issues with code context (increased from 3)
            for issue in critical_high[:10]:
                file_path = issue.get("file_path", "unknown")
                
                # Get code context for this issue
                try:
                    code_with_annotations = await self.code_display.get_file_content_with_annotations(
                        repo_full_name, pr_number, file_path, [issue], gh_token
                    )
                    
                    if not code_with_annotations.get("error"):
                        # Find the relevant code section
                        issue_sections = code_with_annotations["content"]["issue_sections"]
                        if issue_sections:
                            section = issue_sections[0]
                            code_preview = self.code_display.format_code_section_markdown(
                                section, file_path
                            )
                            lines.append(code_preview)
                    else:
                        # Fallback to simple issue display
                        lines.extend(self._format_simple_issue(issue))
                        
                except Exception as e:
                    logger.error(f"Error getting code context: {e}")
                    lines.extend(self._format_simple_issue(issue))
                
                lines.append("")
            
            if len(critical_high) > 3:
                lines.append(f"*... and {len(critical_high) - 3} more critical/high severity issues*")
                lines.append("")
        
        # File-by-file summary
        lines.extend([
            "### 📁 File Summary",
            ""
        ])
        
        # Sort files by issue count
        sorted_files = sorted(
            file_tree["files"].items(),
            key=lambda x: x[1]["total_issues"],
            reverse=True
        )
        
        for file_path, file_info in sorted_files[:10]:
            if file_info["total_issues"] > 0:
                status_icon = "🔴" if file_info["has_critical"] else "🟡" if file_info["has_high"] else "🟢"
                lines.append(
                    f"{status_icon} **{file_path}** - "
                    f"{file_info['total_issues']} issues "
                    f"(+{file_info['additions']}/-{file_info['deletions']})"
                )
        
        if len(sorted_files) > 10:
            lines.append(f"*... and {len(sorted_files) - 10} more files*")
        
        lines.append("")
        
        # Security recommendations
        recommendations = self._generate_recommendations(scan_result, file_tree)
        if recommendations:
            lines.extend([
                "### 💡 Recommendations",
                ""
            ])
            for rec in recommendations:
                lines.append(f"- {rec}")
            lines.append("")
        
        # Good practices found
        good_practices = self._identify_good_practices(scan_result)
        if good_practices:
            lines.extend([
                "### ✅ Good Security Practices",
                ""
            ])
            for practice in good_practices:
                lines.append(f"- ✅ {practice}")
            lines.append("")
        
        # Footer with links
        lines.extend([
            "---",
            ""
        ])
        
        if scan_id:
            lines.append(
                f"🤖 [View Full Report](https://app.devsecurex.com/scans/{scan_id}) | "
                f"[Configure Rules](https://app.devsecurex.com/settings/rules) | "
                f"[Documentation](https://docs.devsecurex.com)"
            )
        else:
            lines.append("🤖 Powered by [DevSecureX](https://devsecurex.com)")
        
        lines.append("")
        lines.append(f"<sub>💡 This review includes AI-powered fix suggestions where available</sub>")
        
        return "\n".join(lines)
    
    async def _generate_enhanced_inline_comments(
        self,
        issues_by_file: Dict[str, List[Dict[str, Any]]],
        pr_files: List[Any],
        repo_full_name: str,
        pr_number: int,
        gh_token: str,
        enable_auto_fix: bool
    ) -> List[Dict[str, Any]]:
        """Generate enhanced inline comments with code context and fixes"""
        
        inline_comments = []
        
        # Create a map of files in the PR
        pr_file_map = {f.filename: f for f in pr_files}
        
        for file_path, file_issues in issues_by_file.items():
            # Skip if file not in PR
            if file_path not in pr_file_map:
                continue
            
            pr_file = pr_file_map[file_path]
            
            # Skip if no patch available
            if not pr_file.patch:
                continue
            
            # Get file content and language
            try:
                g = Github(gh_token)
                repo = g.get_repo(repo_full_name)
                pr = repo.get_pull(pr_number)
                
                file_content = repo.get_contents(file_path, ref=pr.head.sha)
                content = file_content.decoded_content.decode('utf-8')
                language = self.code_display._detect_language(file_path)
                
            except Exception as e:
                logger.error(f"Error getting file content for {file_path}: {e}")
                continue
            
            # Generate fixes for issues if enabled
            fix_suggestions = {}
            if enable_auto_fix and self.code_fixer:
                try:
                    fix_suggestions = await self.code_fixer.generate_fix_suggestions_batch(
                        file_issues, content, language
                    )
                except Exception as e:
                    logger.error(f"Error generating fixes: {e}")
            
            # Create inline comments for each issue
            for issue in file_issues:
                # Skip low severity in inline comments to reduce noise
                if issue.get("severity") == "low":
                    continue
                
                line_number = issue.get("line_start")
                if not line_number:
                    continue
                
                # Map to diff position
                diff_position = self._map_line_to_diff_position(pr_file.patch, line_number)
                if diff_position is None:
                    continue
                
                # Build enhanced inline comment
                issue_id = issue.get("id", str(hash(str(issue))))
                fix = fix_suggestions.get(issue_id)
                
                comment_body = self._build_enhanced_inline_comment(issue, fix, language)
                
                inline_comments.append({
                    "path": file_path,
                    "position": diff_position,
                    "body": comment_body,
                    "severity": issue.get("severity", "medium"),
                    "has_fix": fix is not None
                })
        
        return inline_comments
    
    def _build_enhanced_inline_comment(
        self,
        issue: Dict[str, Any],
        fix: Optional[Dict[str, Any]],
        language: str
    ) -> str:
        """Build enhanced inline comment with fix suggestion"""
        
        severity = issue.get("severity", "medium")
        emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(severity, "ℹ️")
        
        lines = [
            f"{emoji} **{severity.upper()}: {issue.get('message', 'Security issue')}**",
            ""
        ]
        
        # Add explanation
        if issue.get("explanation"):
            lines.extend([
                f"**Why this matters:** {issue['explanation']}",
                ""
            ])
        
        # Add fix suggestion if available
        if fix:
            lines.extend([
                "**🔧 Suggested fix:**",
                f"```{language}",
                fix["fixed_code"],
                "```",
                ""
            ])
            
            if fix.get("explanation"):
                lines.extend([
                    f"**Fix explanation:** {fix['explanation']}",
                    ""
                ])
            
            confidence = fix.get("confidence", "medium")
            method = fix.get("method", "unknown")
            lines.append(f"<sub>Fix confidence: {confidence} | Method: {method}</sub>")
        
        # Add metadata
        lines.extend([
            "",
            f"*Tool: {issue.get('tool', 'unknown')} | Rule: {issue.get('rule_id', 'N/A')}*"
        ])
        
        # Add compliance info if available
        compliance_info = []
        if issue.get("owasp_category"):
            compliance_info.append(f"OWASP: {issue['owasp_category']}")
        if issue.get("cwe_id"):
            compliance_info.append(f"CWE-{issue['cwe_id']}")
        
        if compliance_info:
            lines.append(f"*Compliance: {' | '.join(compliance_info)}*")
        
        return "\n".join(lines)
    
    def _group_issues_by_file(self, issues: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group issues by file path"""
        issues_by_file = {}
        
        for issue in issues:
            file_path = issue.get("file_path", "unknown")
            if file_path not in issues_by_file:
                issues_by_file[file_path] = []
            issues_by_file[file_path].append(issue)
        
        return issues_by_file
    
    def _count_issues_by_severity(self, issues: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count issues by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for issue in issues:
            severity = issue.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _determine_review_action(self, issues: List[Dict[str, Any]]) -> str:
        """Determine review action based on issues"""
        critical_count = sum(1 for i in issues if i.get("severity") == "critical")
        high_count = sum(1 for i in issues if i.get("severity") == "high")
        
        if critical_count > 0:
            return "REQUEST_CHANGES"
        elif high_count > 3:
            return "REQUEST_CHANGES"
        elif high_count > 0:
            return "COMMENT"
        else:
            return "COMMENT"
    
    def _get_score_emoji(self, score: int) -> str:
        """Get emoji for score"""
        if score >= 90:
            return "✅"
        elif score >= 80:
            return "🟡"
        elif score >= 70:
            return "🟠"
        else:
            return "🔴"
    
    def _format_simple_issue(self, issue: Dict[str, Any]) -> List[str]:
        """Format issue without code context"""
        severity = issue.get("severity", "medium")
        emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(severity, "ℹ️")
        
        return [
            f"#### {emoji} {issue.get('message', 'Security Issue')}",
            f"**File:** `{issue.get('file_path', 'unknown')}:{issue.get('line_start', '?')}`",
            f"**Tool:** {issue.get('tool', 'unknown')} | **Rule:** {issue.get('rule_id', 'N/A')}"
        ]
    
    def _generate_recommendations(
        self,
        scan_result: Dict[str, Any],
        file_tree: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        issues = scan_result.get("issues", [])
        issue_counts = self._count_issues_by_severity(issues)
        
        if issue_counts["critical"] > 0:
            recommendations.append(
                f"🚨 Fix {issue_counts['critical']} critical security issues before merging"
            )
        
        if issue_counts["high"] > 0:
            recommendations.append(
                f"⚠️ Address {issue_counts['high']} high severity issues"
            )
        
        # Check for common vulnerability patterns
        has_sql_injection = any(
            "sql" in i.get("rule_id", "").lower() or "injection" in i.get("message", "").lower()
            for i in issues
        )
        if has_sql_injection:
            recommendations.append("🔍 Review database queries and use parameterized statements")
        
        has_xss = any(
            "xss" in i.get("rule_id", "").lower() or "cross-site" in i.get("message", "").lower()
            for i in issues
        )
        if has_xss:
            recommendations.append("🔍 Sanitize all user inputs and escape output properly")
        
        has_secrets = any(
            i.get("tool") == "trufflehog" or "secret" in i.get("message", "").lower()
            for i in issues
        )
        if has_secrets:
            recommendations.append("🔑 Remove hardcoded secrets and use environment variables")
        
        return recommendations
    
    def _identify_good_practices(self, scan_result: Dict[str, Any]) -> List[str]:
        """Identify good security practices"""
        practices = []
        
        scores = scan_result.get("scores", {})
        
        if scores.get("secrets_score", 0) == 100:
            practices.append("No hardcoded secrets detected")
        
        if scores.get("deps_score", 0) >= 95:
            practices.append("Dependencies are well-maintained with minimal vulnerabilities")
        
        if scores.get("code_score", 0) >= 90:
            practices.append("Code follows security best practices")
        
        return practices
    
    def _map_line_to_diff_position(self, patch: str, target_line: int) -> Optional[int]:
        """Map file line number to diff position"""
        if not patch:
            return None
        
        lines = patch.split('\n')
        current_line = 0
        diff_position = 0
        
        for i, line in enumerate(lines):
            if line.startswith('@@'):
                match = re.match(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
                if match:
                    current_line = int(match.group(1)) - 1
            elif line.startswith('+') and not line.startswith('+++'):
                current_line += 1
                diff_position = i + 1
                if current_line == target_line:
                    return diff_position
            elif not line.startswith('-') and not line.startswith('---'):
                current_line += 1
        
        return None
    
    async def _post_additional_comments(self, pr: Any, comments: List[Dict[str, Any]]):
        """Post additional comments that didn't fit in the review"""
        
        for comment in comments:
            try:
                pr.create_issue_comment(
                    f"**Additional security issue found:**\n\n{comment['body']}"
                )
            except Exception as e:
                logger.error(f"Error posting additional comment: {e}")