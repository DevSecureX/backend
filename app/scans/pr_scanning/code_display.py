"""
Enhanced PR Code Display Module with inline security annotations
Provides CodeRabbit-like code viewing with security issue highlighting
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from github import Github
import re
import html

logger = logging.getLogger(__name__)

class PRCodeDisplay:
    """Display PR code changes with inline security annotations"""
    
    def __init__(self):
        self.context_lines = 5  # Lines of context around issues
        self.max_file_size = 100000  # 100KB max file size to display
        
    async def get_file_content_with_annotations(
        self,
        repo_full_name: str,
        pr_number: int,
        file_path: str,
        issues: List[Dict[str, Any]],
        gh_token: str
    ) -> Dict[str, Any]:
        """Get file content with security annotations"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Get file content from PR head
            try:
                file_content = repo.get_contents(file_path, ref=pr.head.sha)
                
                if file_content.size > self.max_file_size:
                    return {
                        "error": "File too large to display",
                        "file_path": file_path,
                        "size": file_content.size
                    }
                
                content = file_content.decoded_content.decode('utf-8')
                
            except Exception as e:
                logger.error(f"Error getting file content: {e}")
                return {
                    "error": f"Could not retrieve file: {str(e)}",
                    "file_path": file_path
                }
            
            # Get file diff
            file_diff = None
            for file in pr.get_files():
                if file.filename == file_path:
                    file_diff = file
                    break
            
            # Process content with annotations
            annotated_content = self._annotate_content(
                content=content,
                issues=issues,
                file_diff=file_diff
            )
            
            return {
                "file_path": file_path,
                "language": self._detect_language(file_path),
                "content": annotated_content,
                "total_lines": len(content.split('\n')),
                "issues_count": len(issues),
                "additions": file_diff.additions if file_diff else 0,
                "deletions": file_diff.deletions if file_diff else 0
            }
            
        except Exception as e:
            logger.error(f"Error displaying PR code: {e}")
            return {
                "error": str(e),
                "file_path": file_path
            }
    
    def _annotate_content(
        self,
        content: str,
        issues: List[Dict[str, Any]],
        file_diff: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Annotate content with security issues"""
        
        lines = content.split('\n')
        
        # Parse diff to identify changed lines
        changed_lines = self._parse_diff_lines(file_diff) if file_diff else {}
        
        # Group issues by line
        issues_by_line = {}
        for issue in issues:
            line_start = issue.get('line_start', 0)
            if line_start > 0:
                if line_start not in issues_by_line:
                    issues_by_line[line_start] = []
                issues_by_line[line_start].append(issue)
        
        # Build annotated lines
        annotated_lines = []
        for i, line in enumerate(lines, 1):
            line_data = {
                "line_number": i,
                "content": line,
                "is_changed": i in changed_lines.get('added', []),
                "is_removed": i in changed_lines.get('removed', []),
                "issues": []
            }
            
            # Add issues for this line
            if i in issues_by_line:
                for issue in issues_by_line[i]:
                    line_data["issues"].append({
                        "severity": issue.get("severity", "medium"),
                        "message": issue.get("message", "Security issue"),
                        "tool": issue.get("tool", "unknown"),
                        "rule_id": issue.get("rule_id"),
                        "suggestion": issue.get("code_context", {}).get("suggested_fix")
                    })
            
            annotated_lines.append(line_data)
        
        # Find sections with issues
        issue_sections = self._identify_issue_sections(annotated_lines, issues_by_line)
        
        return {
            "lines": annotated_lines,
            "issue_sections": issue_sections,
            "changed_lines": changed_lines
        }
    
    def _parse_diff_lines(self, file_diff: Any) -> Dict[str, List[int]]:
        """Parse diff to find changed line numbers"""
        
        if not file_diff or not file_diff.patch:
            return {"added": [], "removed": []}
        
        added_lines = []
        removed_lines = []
        
        current_line_old = 0
        current_line_new = 0
        
        for line in file_diff.patch.split('\n'):
            # Parse hunk header
            hunk_match = re.match(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
            if hunk_match:
                current_line_old = int(hunk_match.group(1))
                current_line_new = int(hunk_match.group(2))
                continue
            
            # Track line changes
            if line.startswith('-') and not line.startswith('---'):
                removed_lines.append(current_line_old)
                current_line_old += 1
            elif line.startswith('+') and not line.startswith('+++'):
                added_lines.append(current_line_new)
                current_line_new += 1
            elif not line.startswith('\\'):  # Context line
                current_line_old += 1
                current_line_new += 1
        
        return {"added": added_lines, "removed": removed_lines}
    
    def _identify_issue_sections(
        self,
        annotated_lines: List[Dict[str, Any]],
        issues_by_line: Dict[int, List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Identify code sections containing issues"""
        
        sections = []
        
        for line_num, issues in issues_by_line.items():
            # Calculate section bounds
            start_line = max(1, line_num - self.context_lines)
            end_line = min(len(annotated_lines), line_num + self.context_lines)
            
            # Extract section
            section_lines = annotated_lines[start_line-1:end_line]
            
            # Find the most severe issue
            severities = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            most_severe = max(issues, key=lambda x: severities.get(x.get("severity", "low"), 0))
            
            sections.append({
                "start_line": start_line,
                "end_line": end_line,
                "issue_line": line_num,
                "severity": most_severe.get("severity", "medium"),
                "issue_count": len(issues),
                "primary_issue": most_severe,
                "all_issues": issues,
                "lines": section_lines
            })
        
        # Sort by severity and line number
        sections.sort(key=lambda x: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x["severity"], 0),
            x["start_line"]
        ))
        
        return sections
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension"""
        
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx',
            '.java': 'java',
            '.go': 'go',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.c': 'c',
            '.rs': 'rust',
            '.kt': 'kotlin',
            '.swift': 'swift',
            '.scala': 'scala',
            '.r': 'r',
            '.sh': 'bash',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.json': 'json',
            '.xml': 'xml',
            '.sql': 'sql',
            '.tf': 'hcl',
            'Dockerfile': 'dockerfile'
        }
        
        for ext, lang in ext_map.items():
            if file_path.endswith(ext) or file_path.split('/')[-1] == ext:
                return lang
        
        return 'text'
    
    def format_code_section_html(self, section: Dict[str, Any]) -> str:
        """Format code section as HTML for PR comments"""
        
        lines = []
        language = self._detect_language(section.get("file_path", ""))
        
        # Add header
        primary_issue = section["primary_issue"]
        severity = primary_issue.get("severity", "medium")
        severity_emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(severity, "ℹ️")
        
        lines.append(f'<div class="code-section">')
        lines.append(f'<h4>{severity_emoji} {html.escape(primary_issue.get("message", "Security Issue"))}</h4>')
        
        # Add code block
        lines.append(f'<pre><code class="language-{language}">')
        
        for line_data in section["lines"]:
            line_num = line_data["line_number"]
            content = html.escape(line_data["content"])
            
            # Highlight issue line
            if line_num == section["issue_line"]:
                lines.append(f'<span class="issue-line">{line_num:4d} | {content}</span>')
            elif line_data.get("is_changed"):
                lines.append(f'<span class="added-line">{line_num:4d} | + {content}</span>')
            else:
                lines.append(f'{line_num:4d} |   {content}')
        
        lines.append('</code></pre>')
        
        # Add issue details
        if len(section["all_issues"]) > 1:
            lines.append(f'<p><strong>{len(section["all_issues"])} issues on this line:</strong></p>')
        
        lines.append('<ul>')
        for issue in section["all_issues"]:
            tool = issue.get("tool", "unknown")
            rule = issue.get("rule_id", "N/A")
            lines.append(f'<li>{html.escape(issue.get("message", ""))} <em>({tool}: {rule})</em></li>')
        lines.append('</ul>')
        
        # Add suggestion if available
        suggestion = primary_issue.get("code_context", {}).get("suggested_fix")
        if suggestion:
            lines.append('<p><strong>Suggested fix:</strong></p>')
            lines.append(f'<pre><code class="language-{language}">{html.escape(suggestion)}</code></pre>')
        
        lines.append('</div>')
        
        return '\n'.join(lines)
    
    def format_code_section_markdown(self, section: Dict[str, Any], file_path: str) -> str:
        """Format code section as Markdown for PR comments with enhanced precision"""
        
        lines = []
        language = self._detect_language(file_path)
        
        # Add header with enhanced context
        primary_issue = section["primary_issue"]
        severity = primary_issue.get("severity", "medium")
        severity_emoji = {"critical": "🚨", "high": "⚠️", "medium": "⚡", "low": "ℹ️"}.get(severity, "ℹ️")
        
        lines.append(f'#### {severity_emoji} {primary_issue.get("message", "Security Issue")}')
        lines.append(f'**File:** `{file_path}` | **Line:** {section["issue_line"]} | **Severity:** {severity.upper()}')
        
        # Add OWASP/CWE info if available
        compliance_info = []
        if primary_issue.get("owasp_category"):
            compliance_info.append(f"OWASP: {primary_issue['owasp_category']}")
        if primary_issue.get("cwe_id"):
            compliance_info.append(f"CWE-{primary_issue['cwe_id']}")
        
        if compliance_info:
            lines.append(f'**Compliance:** {" | ".join(compliance_info)}')
        
        lines.append('')
        
        # Add code block with enhanced highlighting and line numbers
        lines.append(f'```{language}')
        
        for line_data in section["lines"]:
            line_num = line_data["line_number"]
            content = line_data["content"]
            is_issue_line = line_num == section["issue_line"]
            is_changed = line_data.get("is_changed", False)
            
            # Format line with indicators
            prefix = ""
            suffix = ""
            
            if is_issue_line:
                suffix = "  // ⚠️ SECURITY ISSUE"
            elif is_changed:
                prefix = "+ "  # Show as added line
            
            # Add line number and content
            lines.append(f'{line_num:4d} | {prefix}{content}{suffix}')
        
        lines.append('```')
        lines.append('')
        
        # Add detailed issue analysis
        if len(section["all_issues"]) > 1:
            lines.append(f'**🔍 {len(section["all_issues"])} security issues found on line {section["issue_line"]}:**')
        else:
            lines.append('**🔍 Issue Analysis:**')
        lines.append('')
        
        for i, issue in enumerate(section["all_issues"], 1):
            tool = issue.get("tool", "unknown")
            rule = issue.get("rule_id", "N/A")
            severity = issue.get("severity", "medium")
            confidence = issue.get("confidence", "medium")
            
            lines.append(f'{i}. **{severity.upper()}** ({confidence} confidence): {issue.get("message", "")}')
            lines.append(f'   *Detected by {tool} (Rule: {rule})*')
            
            # Add specific explanation if available
            if issue.get("explanation"):
                lines.append(f'   📝 {issue["explanation"]}')
        
        lines.append('')
        
        # Add AI-powered fix suggestion if available
        suggestion = primary_issue.get("code_context", {}).get("suggested_fix")
        if suggestion:
            lines.append('**🤖 AI-Powered Fix Suggestion:**')
            lines.append(f'```{language}')
            lines.append(suggestion)
            lines.append('```')
            
            # Add fix explanation if available
            if primary_issue.get("fix_explanation"):
                lines.append(f'**Fix Explanation:** {primary_issue["fix_explanation"]}')
            
            lines.append('')
        
        # Add security impact
        if primary_issue.get("security_impact"):
            lines.append(f'**🛡️ Security Impact:** {primary_issue["security_impact"]}')
            lines.append('')
        
        # Add testing recommendations
        if primary_issue.get("testing_notes"):
            lines.append(f'**🧪 Testing Recommendations:** {primary_issue["testing_notes"]}')
            lines.append('')
        
        # Add remediation guidance
        remediation_tips = self._get_remediation_tips(primary_issue, language)
        if remediation_tips:
            lines.append('**🔧 Remediation Guidance:**')
            for tip in remediation_tips:
                lines.append(f'- {tip}')
            lines.append('')
        
        return '\n'.join(lines)
    
    def _get_remediation_tips(self, issue: Dict[str, Any], language: str) -> List[str]:
        """Get language-specific remediation tips"""
        
        tips = []
        rule_id = issue.get("rule_id", "").lower()
        message = issue.get("message", "").lower()
        
        # SQL Injection tips
        if "sql" in rule_id or "injection" in message:
            if language == "python":
                tips.append("Use parameterized queries with `cursor.execute(query, params)`")
                tips.append("Consider using an ORM like SQLAlchemy for safer database operations")
            elif language in ["javascript", "typescript"]:
                tips.append("Use parameterized queries with prepared statements")
                tips.append("Sanitize inputs with libraries like `validator` or `escape-html`")
            elif language == "java":
                tips.append("Use `PreparedStatement` instead of `Statement`")
                tips.append("Never concatenate user input directly into SQL queries")
        
        # XSS tips
        elif "xss" in rule_id or "cross-site" in message:
            if language in ["javascript", "typescript"]:
                tips.append("Use `DOMPurify.sanitize()` for HTML sanitization")
                tips.append("Avoid `innerHTML` with user data, use `textContent` instead")
            elif language == "python":
                tips.append("Use template engines with auto-escaping (e.g., Jinja2)")
                tips.append("Sanitize output with `html.escape()` or similar functions")
        
        # Hardcoded secrets tips
        elif "secret" in message or "key" in message or "password" in message:
            tips.append("Move secrets to environment variables")
            tips.append("Use a secrets management service (AWS Secrets Manager, HashiCorp Vault)")
            tips.append("Never commit secrets to version control")
            tips.append("Rotate any exposed credentials immediately")
        
        # Path traversal tips
        elif "path" in rule_id or "traversal" in message:
            if language == "python":
                tips.append("Use `os.path.basename()` to strip directory components")
                tips.append("Validate paths with `os.path.commonpath()` checks")
            tips.append("Use a whitelist of allowed file extensions")
            tips.append("Implement proper access controls for file operations")
        
        # Generic security tips if no specific ones match
        if not tips:
            tips.append("Review the security implications of this code")
            tips.append("Consider input validation and output encoding")
            tips.append("Implement proper error handling")
            tips.append("Follow secure coding guidelines for " + language)
        
        return tips
    
    async def get_pr_file_tree_with_issues(
        self,
        repo_full_name: str,
        pr_number: int,
        scan_results: Dict[str, Any],
        gh_token: str
    ) -> Dict[str, Any]:
        """Get PR file tree with issue counts"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            # Group issues by file
            issues_by_file = {}
            for issue in scan_results.get("issues", []):
                file_path = issue.get("file_path", "unknown")
                if file_path not in issues_by_file:
                    issues_by_file[file_path] = []
                issues_by_file[file_path].append(issue)
            
            # Build file tree
            file_tree = {}
            
            for file in pr.get_files():
                file_path = file.filename
                file_issues = issues_by_file.get(file_path, [])
                
                # Count by severity
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for issue in file_issues:
                    severity = issue.get("severity", "medium")
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                file_tree[file_path] = {
                    "status": file.status,
                    "additions": file.additions,
                    "deletions": file.deletions,
                    "total_issues": len(file_issues),
                    "severity_counts": severity_counts,
                    "has_critical": severity_counts["critical"] > 0,
                    "has_high": severity_counts["high"] > 0
                }
            
            return {
                "total_files": len(file_tree),
                "files_with_issues": sum(1 for f in file_tree.values() if f["total_issues"] > 0),
                "files": file_tree
            }
            
        except Exception as e:
            logger.error(f"Error building file tree: {e}")
            raise