from typing import List, Dict, Optional, Any
from github import Github, GithubException
import logging
import re

logger = logging.getLogger(__name__)

class PRDiffAnalyzer:
    def __init__(self):
        self.security_patterns = self._load_security_patterns()
        
    async def get_changed_files(
        self,
        repo_full_name: str,
        pr_number: int,
        gh_token: str
    ) -> List[Dict[str, Any]]:
        """Get list of changed files in PR with security-relevant filtering"""
        
        try:
            g = Github(gh_token)
            repo = g.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            
            changed_files = []
            
            for file in pr.get_files():
                # Skip non-scannable files
                if not self._is_scannable_file(file.filename):
                    continue
                
                file_data = {
                    "file_path": file.filename,
                    "status": file.status,  # 'added', 'modified', 'removed'
                    "additions": file.additions,
                    "deletions": file.deletions,
                    "changes": file.changes,
                    "patch": file.patch,
                    "previous_filename": file.previous_filename,
                    "sha": file.sha,
                    "blob_url": file.blob_url,
                    "raw_url": file.raw_url,
                    "security_relevant": self._is_security_relevant(file),
                    "risk_score": self._calculate_file_risk_score(file)
                }
                
                # Extract changed line numbers from patch
                if file.patch:
                    file_data["changed_lines"] = self._extract_changed_lines(file.patch)
                
                changed_files.append(file_data)
            
            # Sort by risk score (highest first)
            changed_files.sort(key=lambda x: x["risk_score"], reverse=True)
            
            logger.info(f"Found {len(changed_files)} changed files in PR #{pr_number}")
            return changed_files
            
        except GithubException as e:
            logger.error(f"GitHub API error getting PR files: {e}")
            raise
        except Exception as e:
            logger.error(f"Error analyzing PR diff: {e}")
            raise
    
    def _is_scannable_file(self, filename: str) -> bool:
        """Check if file should be scanned"""
        
        # Skip common non-code files
        skip_patterns = [
            r'\.md$', r'\.txt$', r'\.rst$', r'\.pdf$', r'\.png$', r'\.jpg$', 
            r'\.jpeg$', r'\.gif$', r'\.svg$', r'\.ico$', r'\.zip$', r'\.tar$',
            r'\.gz$', r'\.lock$', r'\.sum$', r'\.mod$', r'\.min\.js$', r'\.min\.css$',
            r'node_modules/', r'vendor/', r'\.git/', r'__pycache__/', r'\.pytest_cache/',
            r'\.idea/', r'\.vscode/', r'dist/', r'build/', r'target/'
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return False
        
        # Include known code file extensions
        code_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
            '.cs', '.cpp', '.c', '.h', '.hpp', '.cc', '.cxx', '.rs', '.kt',
            '.swift', '.scala', '.r', '.m', '.mm', '.pl', '.sh', '.bash',
            '.yml', '.yaml', '.json', '.xml', '.sql', '.tf', '.hcl',
            'Dockerfile', 'Makefile', '.env', '.config'
        }
        
        # Check if file has code extension or is a known config file
        for ext in code_extensions:
            if filename.endswith(ext) or filename == ext:
                return True
        
        # Check for files without extension that might be scripts
        if '.' not in filename.split('/')[-1]:
            return True
        
        return False
    
    def _is_security_relevant(self, file) -> bool:
        """Determine if a file change is security-relevant"""
        
        filename = file.filename.lower()
        
        # High priority security files
        security_files = [
            'auth', 'login', 'password', 'token', 'secret', 'key', 'cert',
            'security', 'permission', 'access', 'role', 'policy', 'cors',
            'csrf', 'xss', 'sql', 'inject', 'escape', 'sanitize', 'validate',
            'encrypt', 'decrypt', 'hash', 'salt', 'sign', 'verify',
            '.env', 'config', 'settings', 'dockerfile', 'docker-compose',
            'requirements', 'package.json', 'gemfile', 'pom.xml', 'build.gradle'
        ]
        
        # Check filename
        for keyword in security_files:
            if keyword in filename:
                return True
        
        # Check patch content for security patterns
        if file.patch:
            return self._patch_contains_security_patterns(file.patch)
        
        return False
    
    def _patch_contains_security_patterns(self, patch: str) -> bool:
        """Check if patch contains security-relevant patterns"""
        
        if not patch:
            return False
        
        # Security-relevant patterns to look for in patches
        patterns = [
            r'password\s*[=:]',
            r'api[_-]?key\s*[=:]',
            r'secret\s*[=:]',
            r'token\s*[=:]',
            r'private[_-]?key',
            r'BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'os\.system',
            r'subprocess\.',
            r'shell\s*=\s*True',
            r'innerHTML\s*=',
            r'dangerouslySetInnerHTML',
            r'document\.write',
            r'\.raw\s*\(',
            r'SELECT.*FROM.*WHERE',
            r'INSERT.*INTO.*VALUES',
            r'UPDATE.*SET.*WHERE',
            r'DELETE.*FROM',
            r'md5\s*\(',
            r'sha1\s*\(',
            r'Math\.random\s*\(',
            r'rand\s*\(',
            r'pickle\.loads',
            r'unserialize\s*\(',
            r'yaml\.load\s*\('
        ]
        
        patch_lower = patch.lower()
        for pattern in patterns:
            if re.search(pattern, patch_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _calculate_file_risk_score(self, file) -> int:
        """Calculate risk score for a changed file"""
        
        score = 0
        filename = file.filename.lower()
        
        # File type risk
        high_risk_files = {
            'auth': 30, 'login': 30, 'password': 40, 'token': 35,
            'secret': 40, 'key': 35, 'security': 25, '.env': 50,
            'dockerfile': 20, 'requirements': 15, 'package.json': 15
        }
        
        for keyword, points in high_risk_files.items():
            if keyword in filename:
                score += points
        
        # Change size risk
        if file.additions > 100:
            score += 20
        elif file.additions > 50:
            score += 10
        elif file.additions > 20:
            score += 5
        
        # Deletion risk (removing security controls?)
        if file.deletions > 50:
            score += 15
        
        # New file risk
        if file.status == 'added':
            score += 10
        
        # Security patterns in patch
        if file.patch and self._patch_contains_security_patterns(file.patch):
            score += 25
        
        return min(score, 100)  # Cap at 100
    
    def _extract_changed_lines(self, patch: str) -> Dict[str, List[int]]:
        """Extract line numbers that were added/removed from patch"""
        
        added_lines = []
        removed_lines = []
        
        if not patch:
            return {"added": added_lines, "removed": removed_lines}
        
        current_line_old = 0
        current_line_new = 0
        
        for line in patch.split('\n'):
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
            else:
                # Context line (no change)
                if not line.startswith('\\'):  # Skip "No newline at end of file"
                    current_line_old += 1
                    current_line_new += 1
        
        return {
            "added": added_lines,
            "removed": removed_lines
        }
    
    def _load_security_patterns(self) -> List[Dict[str, Any]]:
        """Load security patterns for enhanced detection"""
        
        return [
            {
                "name": "hardcoded_secret",
                "pattern": r'(password|secret|key|token)\s*=\s*["\'][^"\']+["\']',
                "severity": "high",
                "message": "Potential hardcoded credential"
            },
            {
                "name": "sql_injection",
                "pattern": r'(SELECT|INSERT|UPDATE|DELETE).*\+.*(%s|format|f["\'])',
                "severity": "critical",
                "message": "Potential SQL injection vulnerability"
            },
            {
                "name": "command_injection",
                "pattern": r'(os\.system|subprocess\.|exec|eval)\s*\([^)]*\+',
                "severity": "critical",
                "message": "Potential command injection vulnerability"
            },
            {
                "name": "xss",
                "pattern": r'(innerHTML|document\.write|dangerouslySetInnerHTML)\s*=.*\+',
                "severity": "high",
                "message": "Potential XSS vulnerability"
            },
            {
                "name": "weak_crypto",
                "pattern": r'(md5|sha1|Math\.random|rand)\s*\(',
                "severity": "medium",
                "message": "Use of weak cryptographic function"
            }
        ]
    
    async def analyze_security_impact(
        self,
        changed_files: List[Dict[str, Any]],
        scan_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze security impact of PR changes"""
        
        impact_analysis = {
            "total_files_changed": len(changed_files),
            "security_relevant_files": sum(1 for f in changed_files if f["security_relevant"]),
            "high_risk_files": sum(1 for f in changed_files if f["risk_score"] >= 50),
            "new_vulnerabilities": [],
            "fixed_vulnerabilities": [],
            "security_score_change": 0,
            "recommendations": []
        }
        
        # Analyze which vulnerabilities are in changed lines
        for issue in scan_results.get("issues", []):
            file_path = issue.get("file_path")
            line_start = issue.get("line_start")
            
            # Find corresponding changed file
            changed_file = next((f for f in changed_files if f["file_path"] == file_path), None)
            
            if changed_file and line_start:
                changed_lines = changed_file.get("changed_lines", {})
                
                # Check if vulnerability is in added lines (new vulnerability)
                if line_start in changed_lines.get("added", []):
                    impact_analysis["new_vulnerabilities"].append({
                        "file": file_path,
                        "line": line_start,
                        "severity": issue.get("severity"),
                        "message": issue.get("message")
                    })
        
        # Generate recommendations
        if impact_analysis["new_vulnerabilities"]:
            impact_analysis["recommendations"].append(
                f"Fix {len(impact_analysis['new_vulnerabilities'])} new security issues before merging"
            )
        
        if impact_analysis["high_risk_files"] > 0:
            impact_analysis["recommendations"].append(
                f"Carefully review {impact_analysis['high_risk_files']} high-risk file changes"
            )
        
        return impact_analysis