import logging
import html
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class PRCommentBuilder:
    """Build beautiful, actionable PR comments for security scan results"""
    
    def __init__(self):
        self.severity_emojis = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "⚡",
            "low": "ℹ️"
        }
        self.severity_colors = {
            "critical": "#d73a49",
            "high": "#cb2431", 
            "medium": "#e36209",
            "low": "#0366d6"
        }
    
    def build_security_comment(self, scan_result: Dict[str, Any]) -> str:
        """Build the main security scan comment for a PR"""
        issues = scan_result.get("issues", [])
        scores = scan_result.get("scores", {})
        metadata = scan_result.get("metadata", {})
        
        total_score = scores.get("total_score", 0)
        scan_id = metadata.get("scan_id")
        
        # Count issues by severity
        issue_counts = self._count_issues_by_severity(issues)
        
        # Filter critical/high issues for detailed display
        critical_high_issues = [
            issue for issue in issues 
            if issue.get("severity") in ["critical", "high"]
        ]
        
        # Build comment parts
        comment_parts = [
            self._build_header(total_score),
            self._build_score_section(scores),
            self._build_issue_summary(issue_counts, total_score),
        ]
        
        # Add critical issues section if any
        if critical_high_issues:
            comment_parts.append(self._build_critical_issues_section(critical_high_issues[:5]))
        
        # Add recommendations for other issues
        medium_low_issues = [
            issue for issue in issues
            if issue.get("severity") in ["medium", "low"]
        ]
        if medium_low_issues:
            comment_parts.append(self._build_recommendations_section(medium_low_issues))
        
        # Add good practices if found
        good_practices = self._identify_good_practices(scan_result)
        if good_practices:
            comment_parts.append(self._build_good_practices_section(good_practices))
        
        # Add footer
        comment_parts.append(self._build_footer(scan_id, metadata))
        
        return "\n\n".join(filter(None, comment_parts))
    
    def _build_header(self, total_score: int) -> str:
        """Build the comment header with score"""
        score_emoji = self._get_score_emoji(total_score)
        status_text = self._get_status_text(total_score)
        
        return f"""## 🔒 DevSecureX Security Analysis

**Overall Security Score: {total_score}/100** {score_emoji} {status_text}"""
    
    def _build_score_section(self, scores: Dict[str, Any]) -> str:
        """Build the detailed scores section"""
        score_lines = []
        
        if scores.get("code_score") is not None:
            score_lines.append(f"**Code Quality:** {scores['code_score']}/100")
        if scores.get("deps_score") is not None:
            score_lines.append(f"**Dependencies:** {scores['deps_score']}/100")
        if scores.get("secrets_score") is not None:
            score_lines.append(f"**Secrets:** {scores['secrets_score']}/100")
        if scores.get("configs_score") is not None:
            score_lines.append(f"**Configuration:** {scores['configs_score']}/100")
        
        if score_lines:
            return "### 📊 Category Scores\n" + "\n".join(f"- {line}" for line in score_lines)
        return ""
    
    def _build_issue_summary(self, issue_counts: Dict[str, int], total_score: int) -> str:
        """Build issue summary section"""
        total_issues = sum(issue_counts.values())
        must_fix = issue_counts.get("critical", 0) + issue_counts.get("high", 0)
        
        lines = []
        
        if must_fix > 0:
            lines.append(f"### 🚨 Must Fix Before Merge ({must_fix} issues)")
        
        if issue_counts.get("critical", 0) > 0:
            lines.append(f"- {self.severity_emojis['critical']} **Critical Issues:** {issue_counts['critical']}")
        if issue_counts.get("high", 0) > 0:
            lines.append(f"- {self.severity_emojis['high']} **High Severity:** {issue_counts['high']}")
        if issue_counts.get("medium", 0) > 0:
            lines.append(f"- {self.severity_emojis['medium']} **Medium Severity:** {issue_counts['medium']}")
        if issue_counts.get("low", 0) > 0:
            lines.append(f"- {self.severity_emojis['low']} **Low Severity:** {issue_counts['low']}")
        
        lines.append(f"\n**Total Issues Found:** {total_issues}")
        
        return "\n".join(lines)
    
    def _build_critical_issues_section(self, issues: List[Dict[str, Any]]) -> str:
        """Build detailed critical issues section with code snippets"""
        if not issues:
            return ""
        
        section = ["### 🔍 Critical Security Issues\n"]
        
        for i, issue in enumerate(issues, 1):
            issue_block = self._build_issue_block(issue, i)
            section.append(issue_block)
        
        if len(issues) > 5:
            section.append(f"\n*... and {len(issues) - 5} more critical/high severity issues*")
        
        return "\n".join(section)
    
    def _build_issue_block(self, issue: Dict[str, Any], index: int) -> str:
        """Build a single issue block with code context"""
        severity = issue.get("severity", "medium")
        emoji = self.severity_emojis.get(severity, "ℹ️")
        
        # Build issue header (escape HTML to prevent XSS)
        message = html.escape(issue.get('message', 'Security Issue'))
        file_path = html.escape(issue.get('file_path', 'unknown'))
        
        lines = [
            f"<details>",
            f"<summary><strong>{emoji} {severity.upper()}: {message}</strong> in <code>{file_path}:{issue.get('line_start', '?')}</code></summary>",
            ""
        ]
        
        # Add vulnerable code if available
        code_context = issue.get("code_context", {})
        if code_context and code_context.get("vulnerable_code"):
            lines.extend([
                "**Vulnerable Code:**",
                "```" + code_context.get("language", ""),
                code_context["vulnerable_code"],
                "```",
                ""
            ])
        
        # Add fix suggestion if available
        if code_context and code_context.get("suggested_fix"):
            lines.extend([
                "**Suggested Fix:**", 
                "```" + code_context.get("language", ""),
                code_context["suggested_fix"],
                "```",
                ""
            ])
        
        # Add explanation
        lines.extend([
            f"**Tool:** {issue.get('tool', 'Unknown')} | **Rule:** {issue.get('rule_id', 'N/A')}",
            ""
        ])
        
        # Add compliance mappings if available
        compliance_info = []
        if issue.get("owasp_category"):
            compliance_info.append(f"OWASP: {issue['owasp_category']}")
        if issue.get("cwe_id"):
            compliance_info.append(f"CWE-{issue['cwe_id']}")
        
        if compliance_info:
            lines.append(f"**Compliance:** {' | '.join(compliance_info)}")
            lines.append("")
        
        # Add why this matters
        if severity in ["critical", "high"]:
            lines.append(f"**Why this matters:** {self._get_impact_description(issue)}")
            lines.append("")
        
        lines.append("</details>")
        
        return "\n".join(lines)
    
    def _build_recommendations_section(self, issues: List[Dict[str, Any]]) -> str:
        """Build recommendations for medium/low issues"""
        if not issues:
            return ""
        
        # Group by category
        by_category = {}
        for issue in issues:
            category = issue.get("category", "other")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(issue)
        
        lines = ["### ⚠️ Additional Recommendations"]
        
        for category, category_issues in by_category.items():
            lines.append(f"\n**{category.title()} ({len(category_issues)} issues)**")
            # Show first 10 issues per category (increased from 3)
            for issue in category_issues[:10]:
                severity = issue.get("severity", "medium")
                emoji = self.severity_emojis.get(severity, "ℹ️")
                file_info = f"`{issue.get('file_path', 'unknown')}:{issue.get('line_start', '?')}`"
                lines.append(f"- {emoji} {issue.get('message', 'Issue')} in {file_info}")
            
            if len(category_issues) > 3:
                lines.append(f"- *... and {len(category_issues) - 3} more {category} issues*")
        
        return "\n".join(lines)
    
    def _build_good_practices_section(self, practices: List[str]) -> str:
        """Build section highlighting good security practices"""
        if not practices:
            return ""
        
        lines = ["### ✅ Good Security Practices Found"]
        for practice in practices:
            lines.append(f"- ✅ {practice}")
        
        return "\n".join(lines)
    
    def _build_footer(self, scan_id: Optional[str], metadata: Dict[str, Any]) -> str:
        """Build comment footer with links and metadata"""
        lines = ["---"]
        
        if scan_id:
            lines.append(f"🤖 Posted by [DevSecureX](https://devsecurex.com) | [View Full Report](https://devsecurex.com/scans/{scan_id}) | [Configure](https://devsecurex.com/settings)")
        else:
            lines.append(f"🤖 Posted by [DevSecureX](https://devsecurex.com)")
        
        # Add scan metadata
        scan_time = metadata.get("scan_duration", 0)
        if scan_time:
            lines.append(f"\n<sub>Scan completed in {scan_time:.1f} seconds</sub>")
        
        return "\n".join(lines)
    
    def build_inline_comment(self, issue: Dict[str, Any]) -> str:
        """Build an inline comment for a specific issue"""
        severity = issue.get("severity", "medium")
        emoji = self.severity_emojis.get(severity, "ℹ️")
        
        message = html.escape(issue.get('message', 'Security issue detected'))
        lines = [
            f"{emoji} **{severity.upper()} Security Issue**: {message}"
        ]
        
        # Add code fix if available
        code_context = issue.get("code_context", {})
        if code_context and code_context.get("suggested_fix"):
            lines.extend([
                "",
                "**Suggested fix:**",
                "```" + code_context.get("language", ""),
                code_context["suggested_fix"],
                "```"
            ])
        
        # Add tool info
        lines.extend([
            "",
            f"*Tool: {issue.get('tool', 'Unknown')} | Rule: {issue.get('rule_id', 'N/A')}*"
        ])
        
        return "\n".join(lines)
    
    def _count_issues_by_severity(self, issues: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count issues by severity level"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for issue in issues:
            severity = issue.get("severity", "medium")
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _get_score_emoji(self, score: int) -> str:
        """Get emoji based on score"""
        if score >= 90:
            return "🟢"
        elif score >= 80:
            return "🟡"
        elif score >= 70:
            return "🟠"
        else:
            return "🔴"
    
    def _get_status_text(self, score: int) -> str:
        """Get status text based on score"""
        if score >= 90:
            return "(Excellent)"
        elif score >= 80:
            return "(Good)"
        elif score >= 70:
            return "(Needs Improvement)"
        else:
            return "(Critical Issues Found)"
    
    def _get_impact_description(self, issue: Dict[str, Any]) -> str:
        """Get impact description for an issue"""
        severity = issue.get("severity", "medium")
        category = issue.get("category", "").lower()
        
        impact_map = {
            ("critical", "injection"): "This vulnerability could allow attackers to execute arbitrary code or access your entire database.",
            ("critical", "authentication"): "This could allow unauthorized access to user accounts and sensitive data.",
            ("critical", "secrets"): "Exposed credentials could grant attackers full access to your systems.",
            ("high", "xss"): "This could allow attackers to steal user sessions or inject malicious scripts.",
            ("high", "sql"): "This could lead to data breaches or unauthorized data manipulation.",
        }
        
        # Try to find specific impact
        for (sev, cat), impact in impact_map.items():
            if severity == sev and cat in category:
                return impact
        
        # Default impacts
        if severity == "critical":
            return "This vulnerability poses an immediate risk to your application's security."
        elif severity == "high":
            return "This issue could be exploited to compromise user data or system integrity."
        else:
            return "This issue should be addressed to improve your security posture."
    
    def _identify_good_practices(self, scan_result: Dict[str, Any]) -> List[str]:
        """Identify good security practices from scan results"""
        practices = []
        scores = scan_result.get("scores", {})
        
        if scores.get("secrets_score", 0) == 100:
            practices.append("No hardcoded secrets or credentials detected")
        
        if scores.get("deps_score", 0) >= 95:
            practices.append("Dependencies are up-to-date with minimal vulnerabilities")
        
        # Check for security headers, auth, etc. based on scan results
        # This would need more sophisticated analysis of the actual issues
        
        return practices