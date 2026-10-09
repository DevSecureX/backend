"""
Auto-fix integration for security issues.
Generates and applies fixes for common security vulnerabilities.
"""

import logging
import base64
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

class AutoFixer:
    """Automatically fix security issues in code using AI-powered fixes"""
    
    def __init__(self):
        self.github_api_base = "https://api.github.com"
        # Initialize AI explainer for generating actual code fixes
        from ..ai.smart_explainer import SmartAIExplainer
        openai_api_key = os.getenv('OPENAI_API_KEY', '')
        self.ai_explainer = SmartAIExplainer(openai_api_key) if openai_api_key else None
        
    async def apply_fixes(
        self,
        repo_full_name: str,
        pr_number: int,
        issues: List[Dict[str, Any]],
        gh_token: str,
        create_pr: bool = True,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """Apply auto-fixes for security issues"""
        
        # Stage 1: Initialize and parse repository information
        if progress_callback:
            await progress_callback(9, "Stage 1 of 11: Initializing autofix process...")
        
        owner, repo = repo_full_name.split("/")
        
        # Stage 2: Fetch repository and PR details  
        if progress_callback:
            await progress_callback(18, "Stage 2 of 11: Fetching repository details...")
        
        # Get PR details
        pr_details = await self._get_pr_details(owner, repo, pr_number, gh_token)
        base_branch = pr_details["head"]["ref"]
        base_sha = pr_details["head"]["sha"]
        
        # Stage 3: Create fix branch
        if progress_callback:
            await progress_callback(27, "Stage 3 of 11: Creating autofix branch...")
        
        # Create fix branch
        fix_branch = f"devsecurex-auto-fix-pr-{pr_number}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        await self._create_branch(owner, repo, fix_branch, base_sha, gh_token)
        
        # Stage 4: Analyze and categorize security issues
        if progress_callback:
            await progress_callback(36, "Stage 4 of 11: Analyzing security issues...")
        
        # Group issues by file for better processing
        files_to_fix = {}
        for issue in issues:
            file_path = issue.get("file_path")
            if file_path:
                if file_path not in files_to_fix:
                    files_to_fix[file_path] = []
                files_to_fix[file_path].append(issue)
        
        # Stage 5: Preparing fix generation system
        if progress_callback:
            await progress_callback(45, "Stage 5 of 11: Initializing AI-powered fix generation...")
        
        fixed_files = {}
        total_fixes_applied = 0
        
        # Stage 6: Processing and applying fixes to vulnerable files
        if progress_callback:
            await progress_callback(54, f"Stage 6 of 11: Applying fixes to {len(files_to_fix)} files...")
        
        # Process each file
        file_count = 0
        for file_path, file_issues in files_to_fix.items():
            file_count += 1
            # Progress within Stage 6: 54% + (file_progress * 18% / total_files)
            file_progress = (file_count / len(files_to_fix)) * 18
            if progress_callback:
                await progress_callback(54 + file_progress, f"Stage 6 of 11: Processing file {file_count}/{len(files_to_fix)}: {file_path}...")
            # Get original file content
            content = await self._get_file_content(owner, repo, file_path, base_branch, gh_token)
            if not content:
                continue
            
            # Apply all fixes to this file with a clean summary comment
            fixed_content, fixes_applied = await self._apply_all_fixes_to_file(content, file_issues, file_path)
            
            if fixes_applied > 0:
                fixed_files[file_path] = fixed_content
                total_fixes_applied += fixes_applied
                logger.info(f"Applied {fixes_applied} fixes to {file_path}")
        
        # Stage 7: Committing fixes to repository
        if progress_callback:
            await progress_callback(72, "Stage 7 of 11: Committing security fixes...")
        
        # Commit fixes
        if fixed_files:
            commit_message = f"🔧 Auto-fix {total_fixes_applied} security issues from PR #{pr_number}\n\nFixed by DevSecureX"
            
            # Stage 8: Uploading file changes
            if progress_callback:
                await progress_callback(81, "Stage 8 of 11: Uploading fixed files...")
            
            for file_path, content in fixed_files.items():
                await self._update_file(
                    owner, repo, file_path, content,
                    commit_message, fix_branch, gh_token
                )
            
            # Stage 9: Generating PR documentation and metadata
            if progress_callback:
                await progress_callback(90, "Stage 9 of 11: Preparing pull request...")
            
            # Create PR if requested
            pr_url = None
            if create_pr:
                # Create PR against the feature branch (head) not the base branch (main)
                # This way users can see exactly what we fixed in their feature
                pr_data = {
                    "title": f"🔒 Security fixes for PR #{pr_number}",
                    "body": self._generate_fix_pr_body(issues, total_fixes_applied),
                    "head": fix_branch,
                    "base": pr_details["head"]["ref"]  # Use feature branch instead of main
                }
                
                # Stage 10: Creating pull request
                if progress_callback:
                    await progress_callback(95, "Stage 10 of 11: Creating pull request...")
                
                pr_response = await self._create_pull_request(
                    owner, repo, pr_data, gh_token
                )
                pr_url = pr_response.get("html_url")
            
            # Stage 11: Finalizing and packaging results
            if progress_callback:
                await progress_callback(100, "Stage 11 of 11: Finalizing autofix results...")
            
            return {
                "fixed_count": total_fixes_applied,
                "branch_name": fix_branch,
                "pr_url": pr_url,
                "fixed_files": list(fixed_files.keys())
            }
        
        return {
            "fixed_count": 0,
            "message": "No fixes could be applied"
        }
    
    async def _get_pr_details(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        gh_token: str
    ) -> Dict[str, Any]:
        """Get PR details from GitHub"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/pulls/{pr_number}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                return await response.json()
    
    async def _create_branch(
        self,
        owner: str,
        repo: str,
        branch_name: str,
        base_sha: str,
        gh_token: str
    ) -> None:
        """Create a new branch"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/git/refs"
        
        data = {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=data,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status != 201:
                    raise Exception(f"Failed to create branch: {await response.text()}")
    
    async def _get_file_content(
        self,
        owner: str,
        repo: str,
        file_path: str,
        branch: str,
        gh_token: str
    ) -> Optional[str]:
        """Get file content from GitHub"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/contents/{file_path}?ref={branch}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    content = base64.b64decode(data["content"]).decode("utf-8")
                    return content
                return None
    
    async def _update_file(
        self,
        owner: str,
        repo: str,
        file_path: str,
        content: str,
        commit_message: str,
        branch: str,
        gh_token: str
    ) -> None:
        """Update file content on GitHub"""
        # First get the file SHA
        url = f"{self.github_api_base}/repos/{owner}/{repo}/contents/{file_path}?ref={branch}"
        
        async with aiohttp.ClientSession() as session:
            # Get current file info
            async with session.get(
                url,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status == 200:
                    file_data = await response.json()
                    file_sha = file_data["sha"]
                else:
                    file_sha = None
            
            # Update file
            data = {
                "message": commit_message,
                "content": base64.b64encode(content.encode()).decode(),
                "branch": branch
            }
            
            if file_sha:
                data["sha"] = file_sha
            
            async with session.put(
                url,
                json=data,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status not in [200, 201]:
                    raise Exception(f"Failed to update file: {await response.text()}")
    
    async def _create_pull_request(
        self,
        owner: str,
        repo: str,
        pr_data: Dict[str, Any],
        gh_token: str
    ) -> Dict[str, Any]:
        """Create a pull request"""
        url = f"{self.github_api_base}/repos/{owner}/{repo}/pulls"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=pr_data,
                headers={"Authorization": f"token {gh_token}"}
            ) as response:
                if response.status == 201:
                    return await response.json()
                else:
                    raise Exception(f"Failed to create PR: {await response.text()}")
    
    def _apply_fix_to_content(
        self,
        content: str,
        issue: Dict[str, Any]
    ) -> str:
        """Apply a fix to file content"""
        lines = content.split("\n")
        line_start_raw = issue.get("line_start", 1)
        line_start = (line_start_raw - 1) if line_start_raw is not None else 0  # Convert to 0-based
        line_end_raw = issue.get("line_end", line_start_raw)
        line_end = (line_end_raw - 1) if line_end_raw is not None else line_start
        
        code_context = issue.get("code_context", {})
        vulnerable_code = code_context.get("vulnerable_code", "")
        suggested_fix = code_context.get("suggested_fix", "")
        
        if not vulnerable_code or not suggested_fix:
            return content
        
        # Simple replacement within the affected lines
        for i in range(line_start, min(line_end + 1, len(lines))):
            if vulnerable_code.strip() in lines[i]:
                # Replace the vulnerable pattern with the fix
                lines[i] = lines[i].replace(vulnerable_code.strip(), suggested_fix.strip())
                break
        
        return "\n".join(lines)
    
    def _apply_generated_fix_to_content(
        self,
        content: str,
        issue: Dict[str, Any],
        generated_fix: Dict[str, str]
    ) -> str:
        """Apply a generated fix to file content with precise line-based replacement"""
        lines = content.split("\n")
        line_start_raw = issue.get("line_start", 1)
        line_start = (line_start_raw - 1) if line_start_raw is not None else 0  # Convert to 0-based
        line_end_raw = issue.get("line_end", line_start_raw)
        line_end = (line_end_raw - 1) if line_end_raw is not None else line_start
        
        old_code = generated_fix["old_code"].strip()
        new_code = generated_fix["new_code"].strip()
        description = generated_fix.get("description", "Security fix applied")
        
        # Ensure we don't go out of bounds
        if line_start >= len(lines):
            logger.warning(f"Line {line_start_raw} is beyond file length ({len(lines)} lines)")
            return content
        
        # Strategy 1: Replace specific vulnerable patterns with proper fixes
        
        # Fix eval() injection
        if "eval(" in old_code and line_start < len(lines):
            original_line = lines[line_start]
            if "eval(" in original_line:
                logger.info(f"Fixing eval() injection at line {line_start+1}")
                # Preserve original indentation
                original_indent = len(original_line) - len(original_line.lstrip())
                indent = " " * original_indent
                
                comment = f"{indent}# FIXED: {description}"
                if "return str(eval(" in original_line:
                    # Replace the entire eval call with safe alternative
                    fixed_line = f"{indent}# Security fix: eval() disabled to prevent code injection\n{indent}return \"Error: eval() disabled for security\""
                else:
                    fixed_line = f"{indent}# Security fix: eval() disabled to prevent code injection\n{indent}# Original: {original_line.strip()}\n{indent}pass  # TODO: Implement safe alternative"
                
                lines[line_start] = f"{comment}\n{fixed_line}"
                return "\n".join(lines)
        
        # Fix os.popen command injection
        if "os.popen" in old_code and line_start < len(lines):
            original_line = lines[line_start]
            if "os.popen(" in original_line:
                logger.info(f"Fixing command injection at line {line_start+1}")
                # Preserve original indentation
                original_indent = len(original_line) - len(original_line.lstrip())
                indent = " " * original_indent
                
                comment = f"{indent}# FIXED: {description}"
                fixed_line = f"""{indent}# Security fix: Using subprocess.run() with input validation
{indent}import subprocess
{indent}import re
{indent}if re.match(r'^[a-zA-Z0-9.-]+$', target):
{indent}    result = subprocess.run(['ping', '-c', '1', target], capture_output=True, text=True, timeout=5)
{indent}    return result.stdout
{indent}else:
{indent}    return \"Invalid target specified\""""
                
                lines[line_start] = f"{comment}\n{fixed_line}"
                return "\n".join(lines)
        
        # Fix SQL injection
        if "sql" in old_code.lower() and ("query" in old_code or "execute" in old_code):
            if line_start < len(lines):
                original_line = lines[line_start]
                logger.info(f"Fixing SQL injection at line {line_start+1}")
                
                # Preserve original indentation
                original_indent = len(original_line) - len(original_line.lstrip())
                indent = " " * original_indent
                
                if "query = f\"" in original_line:
                    # Fix parameterized query
                    comment = f"{indent}# FIXED: {description}"
                    fixed_line = f"{indent}# Security fix: Using parameterized queries\n{indent}query = \"SELECT * FROM users WHERE username = ? AND password = ?\""
                    lines[line_start] = f"{comment}\n{fixed_line}"
                elif "cursor.execute(query)" in original_line:
                    comment = f"{indent}# FIXED: {description}"
                    fixed_line = f"{indent}# Security fix: Using parameterized queries\n{indent}cursor.execute(query, (username, password))"
                    lines[line_start] = f"{comment}\n{fixed_line}"
                
                return "\n".join(lines)
        
        # Fix debug mode
        if "debug=True" in old_code and line_start < len(lines):
            original_line = lines[line_start]
            if "debug=True" in original_line:
                logger.info(f"Fixing debug mode at line {line_start+1}")
                # Preserve original indentation
                original_indent = len(original_line) - len(original_line.lstrip())
                indent = " " * original_indent
                
                comment = f"{indent}# FIXED: {description}"
                fixed_line = original_line.replace("debug=True", "debug=False")
                lines[line_start] = f"{comment}\n{fixed_line}"
                return "\n".join(lines)
        
        # Fix pickle.loads
        if "pickle.loads" in old_code and line_start < len(lines):
            original_line = lines[line_start]
            if "pickle.loads(" in original_line:
                logger.info(f"Fixing pickle deserialization at line {line_start+1}")
                # Preserve original indentation
                original_indent = len(original_line) - len(original_line.lstrip())
                indent = " " * original_indent
                
                comment = f"{indent}# FIXED: {description}"
                fixed_line = f"""{indent}# Security fix: Using JSON instead of pickle for safer deserialization
{indent}import json
{indent}try:
{indent}    obj = json.loads(data.decode('utf-8'))
{indent}except (json.JSONDecodeError, UnicodeDecodeError):
{indent}    obj = None  # Handle invalid data safely"""
                
                lines[line_start] = f"{comment}\n{fixed_line}"
                return "\n".join(lines)
        
        # Strategy 2: Add security comment for unhandled cases
        if line_start < len(lines):
            logger.info(f"Adding security warning at line {line_start+1}")
            # Preserve original indentation
            original_line = lines[line_start]
            original_indent = len(original_line) - len(original_line.lstrip())
            indent = " " * original_indent
            
            comment = f"{indent}# SECURITY WARNING: {description}"
            # Don't modify the original line, just add a comment above it
            lines.insert(line_start, comment)
            return "\n".join(lines)
        
        logger.warning(f"Could not apply fix for issue at line {line_start_raw}")
        return content
    
    async def _apply_all_fixes_to_file(self, content: str, issues: List[Dict[str, Any]], file_path: str = "") -> tuple[str, int]:
        """Apply AI-powered fixes to a single file with a summary comment at the top"""
        lines = content.split("\n")
        fixes_applied = 0
        fix_summaries = []
        
        # Sort issues by line number (descending) to avoid line number shifting
        sorted_issues = sorted(issues, key=lambda x: x.get("line_start", 0), reverse=True)
        
        for issue in sorted_issues:
            line_start_raw = issue.get("line_start", 1)
            line_start = (line_start_raw - 1) if line_start_raw is not None else 0
            
            if line_start >= len(lines):
                continue
            
            # Get the original line to preserve indentation
            original_line = lines[line_start]
            original_indent = len(original_line) - len(original_line.lstrip())
            
            # Generate AI-powered fix for this specific issue
            ai_fix = await self._generate_ai_code_fix(issue, original_line)
            
            if ai_fix and ai_fix.get("fixed_code"):
                # Ensure the fix preserves the original indentation
                fixed_code = ai_fix["fixed_code"]
                
                # If the fixed code doesn't have proper indentation, add it
                fixed_lines = fixed_code.split('\n')
                properly_indented_lines = []
                
                for i, line in enumerate(fixed_lines):
                    if line.strip():  # Only process non-empty lines
                        # If line has no indentation or less than original, add proper indentation
                        line_indent = len(line) - len(line.lstrip())
                        if i == 0 and line_indent < original_indent:
                            # First line should match original indentation
                            properly_indented_lines.append(' ' * original_indent + line.lstrip())
                        elif i > 0 and line_indent == 0 and line.strip():
                            # Subsequent lines need at least the original indentation
                            properly_indented_lines.append(' ' * original_indent + line)
                        else:
                            properly_indented_lines.append(line)
                    else:
                        properly_indented_lines.append(line)
                
                # Apply the properly indented fix - CRITICAL INDENTATION FIX
                fixed_content_with_indent = '\n'.join(properly_indented_lines)
                
                # EMERGENCY FIX: Ensure ALL lines have proper indentation
                emergency_fixed_lines = []
                for line in fixed_content_with_indent.split('\n'):
                    if line.strip():  # Non-empty line
                        current_indent = len(line) - len(line.lstrip())
                        if current_indent == 0:  # No indentation
                            emergency_fixed_lines.append(' ' * original_indent + line)
                            logger.warning(f"EMERGENCY: Fixed zero indentation line: '{line}' -> '{' ' * original_indent + line}'")
                        else:
                            emergency_fixed_lines.append(line)
                    else:
                        emergency_fixed_lines.append(line)
                
                lines[line_start] = '\n'.join(emergency_fixed_lines)
                fix_summaries.append(f"Line {line_start_raw}: {ai_fix['description']}")
                fixes_applied += 1
                logger.info(f"Applied AI-generated fix at line {line_start_raw}: {ai_fix['description']}")
        
        # Add summary comment at the top if any fixes were applied
        if fixes_applied > 0:
            summary_comment = self._generate_file_summary_comment(fix_summaries, fixes_applied, file_path)
            lines.insert(0, summary_comment)
        
        return "\n".join(lines), fixes_applied
    
    async def _generate_ai_code_fix(self, issue: Dict[str, Any], original_line: str) -> Optional[Dict[str, str]]:
        """Generate actual code fix using OpenAI with language awareness"""
        if not self.ai_explainer or not self.ai_explainer.client:
            # Fallback to template-based fixes if AI not available
            return self._generate_template_fix(issue, original_line)
        
        try:
            # Detect language from file path
            file_path = issue.get('file_path', '')
            language_info = self._detect_language(file_path)
            
            # Build context-rich prompt for AI
            vulnerability = issue.get('message', 'Security issue')
            original_indent = len(original_line) - len(original_line.lstrip())
            
            prompt = f"""Fix this {language_info['name']} security vulnerability:

VULNERABLE LINE: {original_line}
ISSUE: {vulnerability}

Requirements:
- Return ONLY the clean {language_info['name']} code replacement
- PRESERVE THE EXACT INDENTATION as shown in the vulnerable line ({original_indent} {language_info['indent_type']})
- The fixed line must start with the same indentation as the vulnerable line
- NO markdown formatting (no ```{language_info['markdown_name']}``` blocks)
- NO explanations or comments unless adding a security comment
- Make MINIMAL changes - only fix the security issue, don't rewrite the entire line
- Just the raw {language_info['name']} code that replaces the vulnerable line

Example (preserving indentation):
Input: "{language_info['example_input']}"
Output: "{language_info['example_output']}"

IMPORTANT: Your response must start with exactly {original_indent} spaces to match the original indentation.

Your fix:"""

            response = await asyncio.to_thread(
                self.ai_explainer.client.chat.completions.create,
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": f"You are a security engineer fixing {language_info['name']} code. Return ONLY the secure replacement line that fixes the vulnerability. CRITICAL: You must preserve the exact indentation from the original line - start your response with exactly {original_indent} spaces. Make minimal changes to fix only the security issue. No markdown, no explanations, no extra comments - just the secure code with the original indentation preserved."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=150
            )
            
            fixed_code = response.choices[0].message.content.strip()
            
            # DEBUG: Log what AI actually returned
            logger.info(f"AI returned for line {issue.get('line_start', '?')}: '{fixed_code}' (original: '{original_line}')")
            
            # Aggressively clean up any markdown artifacts for any language
            # Remove any ```language or ``` blocks
            markdown_patterns = ['```python', '```javascript', '```js', '```typescript', '```ts', 
                               '```go', '```java', '```csharp', '```c#', '```php', '```ruby', 
                               '```cpp', '```c++', '```c', '```sql', '```yaml', '```json', '```']
            for pattern in markdown_patterns:
                fixed_code = fixed_code.replace(pattern + '\n', '').replace(pattern, '')
            fixed_code = fixed_code.replace('\n```', '').replace('```', '')
            
            # Remove any explanation text that might precede the code
            lines = fixed_code.split('\n')
            code_lines = []
            
            for line in lines:
                line = line.strip()
                # Skip empty lines or lines that look like explanations
                if not line:
                    continue
                if any(line.lower().startswith(x) for x in ["here", "the", "to fix", "this", "you", "we", "i", "fixed", "secure"]):
                    continue
                if line.startswith('#') and len(line) > 50:  # Skip long comment lines
                    continue
                code_lines.append(line)
            
            # Take only the actual code lines and restore proper indentation
            if code_lines:
                # Get the original indentation based on language
                if language_info['indent_type'] == 'tabs':
                    indent_str = '\t' * (original_indent // 4)  # Assume 4 spaces = 1 tab
                else:
                    indent_str = ' ' * original_indent
                
                # Process each line to ensure proper indentation
                indented_lines = []
                for i, line in enumerate(code_lines):
                    if line:  # Non-empty line
                        # Check if line already has proper indentation
                        current_indent = len(line) - len(line.lstrip())
                        
                        # If line has no indentation or less than needed, add proper indentation
                        if current_indent < original_indent:
                            # For the first line, always use original indentation
                            if i == 0:
                                indented_lines.append(indent_str + line.lstrip())
                            else:
                                # For subsequent lines, preserve relative indentation if present
                                if current_indent > 0:
                                    # Line has some indentation, preserve the relative difference
                                    extra_indent = ' ' * current_indent
                                    indented_lines.append(indent_str + extra_indent + line.lstrip())
                                else:
                                    # No indentation, use base indentation
                                    indented_lines.append(indent_str + line.lstrip())
                        else:
                            # Line already has sufficient indentation, keep as is
                            indented_lines.append(line)
                    else:
                        # Empty line
                        indented_lines.append(line)
                
                # Join lines without stripping to preserve indentation
                fixed_code = '\n'.join(indented_lines)
            
            # Final validation - ensure we got clean code
            if fixed_code and not any(fixed_code.lower().startswith(x) for x in ["here", "the", "to fix", "```", "this", "you"]):
                # CRITICAL: Ensure the fixed code maintains original indentation
                fixed_lines = fixed_code.split('\n')
                properly_indented_fixed_lines = []
                
                for i, line in enumerate(fixed_lines):
                    if line.strip():  # Non-empty line
                        current_indent = len(line) - len(line.lstrip())
                        if current_indent < original_indent:
                            # AI didn't preserve indentation - fix it
                            logger.warning(f"AI didn't preserve indentation (got {current_indent}, expected {original_indent}), fixing...")
                            logger.info(f"  Original line: '{line}'")
                            corrected_line = (' ' * original_indent) + line.lstrip()
                            logger.info(f"  Corrected to: '{corrected_line}'")
                            properly_indented_fixed_lines.append(corrected_line)
                        else:
                            # Indentation looks correct
                            properly_indented_fixed_lines.append(line)
                    else:
                        # Empty line
                        properly_indented_fixed_lines.append(line)
                
                fixed_code = '\n'.join(properly_indented_fixed_lines)
                
                return {
                    "fixed_code": fixed_code,
                    "description": f"Fixed {vulnerability[:60]}{'...' if len(vulnerability) > 60 else ''}"
                }
        
        except Exception as e:
            logger.warning(f"AI fix generation failed: {e}")
        
        # Fallback to template-based fix
        return self._generate_template_fix(issue, original_line)
    
    def _generate_template_fix(self, issue: Dict[str, Any], original_line: str) -> Optional[Dict[str, str]]:
        """Fallback template-based fixes when AI is not available"""
        message = issue.get("message", "").lower()
        indentation = len(original_line) - len(original_line.lstrip())
        indent = " " * indentation
        
        # Ensure we always preserve the original indentation exactly
        
        # Clean template fixes for common issues
        if "eval(" in original_line:
            # Simple one-line fix that preserves indentation
            return {
                "fixed_code": f"{indent}return \"Error: eval() disabled for security reasons\"",
                "description": "Disabled eval() to prevent code injection"
            }
        elif "os.popen(" in original_line and "ping" in original_line:
            # Multi-line fix with preserved indentation
            return {
                "fixed_code": f"{indent}import subprocess\n{indent}result = subprocess.run(['ping', '-c', '1', target], capture_output=True, text=True, timeout=5)\n{indent}return result.stdout if result.returncode == 0 else \"Ping failed\"",
                "description": "Replaced os.popen() with secure subprocess.run()"
            }
        elif "query = f\"" in original_line and ("username" in original_line or "password" in original_line):
            return {
                "fixed_code": f'{indent}query = "SELECT * FROM users WHERE username = ? AND password = ?"',
                "description": "Fixed SQL injection using parameterized query"
            }
        elif "cursor.execute(query)" in original_line:
            return {
                "fixed_code": f"{indent}cursor.execute(query, (username, password))",
                "description": "Fixed SQL injection using parameterized query"
            }
        elif "debug=True" in original_line:
            # Preserve the entire line structure including indentation
            fixed_line = original_line.replace("debug=True", "debug=False")
            return {
                "fixed_code": fixed_line,
                "description": "Disabled debug mode for production security"
            }
        elif "pickle.loads(" in original_line:
            # Multi-line fix with proper indentation for nested try-except
            return {
                "fixed_code": f"{indent}import json\n{indent}try:\n{indent}    obj = json.loads(data.decode('utf-8'))\n{indent}except (json.JSONDecodeError, UnicodeDecodeError):\n{indent}    obj = None  # Handle invalid data safely",
                "description": "Replaced pickle with safer JSON deserialization"
            }
        
        return None
    
    def _generate_file_summary_comment(self, fix_summaries: List[str], fixes_applied: int, file_path: str = "") -> str:
        """Generate a minimal summary comment for the top of the file using correct comment style"""
        language_info = self._detect_language(file_path)
        comment_prefix = language_info['comment_prefix']
        return f"{comment_prefix} DevSecureX Auto-Fix: {fixes_applied} security issues fixed - please review before merging"
    
    def _generate_fix_pr_body(
        self,
        issues: List[Dict[str, Any]],
        fixed_count: int
    ) -> str:
        """Generate PR body for fixes"""
        body = f"""## 🔒 Security Auto-Fix

This PR automatically fixes **{fixed_count}** security issues detected by DevSecureX.

### Fixed Issues:

"""
        
        # Group by severity
        by_severity = {}
        for issue in issues:
            if issue.get("code_context", {}).get("suggested_fix"):
                severity = issue.get("severity", "medium")
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(issue)
        
        severity_emojis = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "⚡",
            "low": "ℹ️"
        }
        
        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                body += f"\n#### {severity_emojis.get(severity, '📌')} {severity.title()} Severity\n\n"
                for issue in by_severity[severity][:5]:  # Show max 5 per severity
                    body += f"- **{issue.get('message', 'Security issue')}** in `{issue.get('file_path', 'unknown')}:{issue.get('line_start', '?')}`\n"
                
                if len(by_severity[severity]) > 5:
                    body += f"- *... and {len(by_severity[severity]) - 5} more {severity} issues*\n"
        
        body += """

### Review Guidelines:

1. ✅ Review each fix carefully to ensure it doesn't break functionality
2. ✅ Run your test suite to verify no regressions
3. ✅ Consider if additional security measures are needed
4. ✅ Update any affected documentation

---
🤖 Generated by [DevSecureX](https://devsecurex.com) | [View Security Report](https://devsecurex.com)
"""
        
        return body
    
    def _generate_fix_for_issue(self, issue: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Generate actual code replacement for common security issues"""
        rule_id = issue.get("rule_id", "").lower()
        message = issue.get("message", "").lower()
        file_path = issue.get("file_path", "")
        code_context = issue.get("code_context", {})
        vulnerable_code = code_context.get("vulnerable_code", "")
        
        # Return format: {"old_code": "...", "new_code": "...", "description": "..."}
        
        # Code injection fixes - eval()
        if "eval" in rule_id or "eval" in vulnerable_code:
            if "eval(code)" in vulnerable_code:
                return {
                    "old_code": "eval(code)",
                    "new_code": "# SECURITY FIX: eval() removed - use ast.literal_eval() for safe data parsing\n    # return ast.literal_eval(code) if needed",
                    "description": "Removed dangerous eval() call to prevent code injection"
                }
            elif "return str(eval(" in vulnerable_code:
                return {
                    "old_code": vulnerable_code.strip(),
                    "new_code": "    # SECURITY FIX: eval() removed to prevent code injection\n    # TODO: Implement safe alternative based on your use case\n    return \"Error: eval() has been disabled for security\"",
                    "description": "Replaced eval() with safe error message"
                }
        
        # Command injection fixes
        if "os.popen" in vulnerable_code:
            if "os.popen(f\"ping -c 1 {target}\")" in vulnerable_code:
                return {
                    "old_code": "os.popen(f\"ping -c 1 {target}\").read()",
                    "new_code": "# SECURITY FIX: Using subprocess.run() with input validation\n    import subprocess\n    import re\n    # Validate target to prevent command injection\n    if re.match(r'^[a-zA-Z0-9.-]+$', target):\n        result = subprocess.run(['ping', '-c', '1', target], \n                              capture_output=True, text=True, timeout=5)\n        return result.stdout\n    else:\n        return \"Invalid target specified\"",
                    "description": "Replaced os.popen() with subprocess.run() and input validation"
                }
        
        # SQL injection fixes
        if ("sql" in rule_id or "sql" in message) and "injection" in message:
            if "cursor.execute(query)" in vulnerable_code:
                return {
                    "old_code": "query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n    cursor.execute(query)",
                    "new_code": "# SECURITY FIX: Using parameterized queries to prevent SQL injection\n    query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n    cursor.execute(query, (username, password))",
                    "description": "Replaced string formatting with parameterized queries"
                }
        
        # Debug mode fixes
        if "debug=true" in vulnerable_code or (rule_id == "b201" and "app.run" in vulnerable_code):
            if "app.run(debug=True)" in vulnerable_code:
                return {
                    "old_code": "app.run(debug=True)",
                    "new_code": "# SECURITY FIX: Debug mode disabled in production\n    app.run(debug=False)",
                    "description": "Disabled debug mode for production security"
                }
        
        # Pickle deserialization fixes
        if "pickle.loads" in vulnerable_code:
            return {
                "old_code": "obj = pickle.loads(data)",
                "new_code": "# SECURITY FIX: Pickle replaced with JSON for safer deserialization\n    import json\n    try:\n        obj = json.loads(data.decode('utf-8'))\n    except (json.JSONDecodeError, UnicodeDecodeError):\n        obj = None  # Handle invalid data safely",
                "description": "Replaced pickle.loads() with safer JSON deserialization"
            }
        
        # For other high-severity issues, add security comments
        if issue.get("severity") in ["critical", "high"]:
            return {
                "old_code": vulnerable_code.strip(),
                "new_code": f"# SECURITY WARNING: {message[:100]}\n    # TODO: Review and fix this security issue\n    {vulnerable_code.strip()}",
                "description": f"Added security warning comment for manual review"
            }
        
        return None
    
    def _detect_language(self, file_path: str) -> Dict[str, str]:
        """Detect programming language from file extension"""
        if not file_path:
            return self._get_default_language_info()
        
        ext = file_path.split('.')[-1].lower() if '.' in file_path else ''
        
        language_map = {
            # Python
            'py': {
                'name': 'Python',
                'markdown_name': 'python',
                'indent_type': 'spaces',
                'comment_prefix': '#',
                'example_input': '    result = eval(user_input)',
                'example_output': '    result = ast.literal_eval(user_input)'
            },
            # JavaScript/TypeScript
            'js': {
                'name': 'JavaScript',
                'markdown_name': 'javascript',
                'indent_type': 'spaces',
                'comment_prefix': '//',
                'example_input': '    result = eval(userInput);',
                'example_output': '    result = JSON.parse(userInput);'
            },
            'ts': {
                'name': 'TypeScript',
                'markdown_name': 'typescript',
                'indent_type': 'spaces',
                'comment_prefix': '//',
                'example_input': '    result = eval(userInput);',
                'example_output': '    result = JSON.parse(userInput);'
            },
            # Go
            'go': {
                'name': 'Go',
                'markdown_name': 'go',
                'indent_type': 'tabs',
                'comment_prefix': '//',
                'example_input': '\tresult := exec.Command("ping", target)',
                'example_output': '\tresult := exec.Command("ping", "-c", "1", target)'
            },
            # Java
            'java': {
                'name': 'Java',
                'markdown_name': 'java',
                'indent_type': 'spaces',
                'comment_prefix': '//',
                'example_input': '    String result = Runtime.getRuntime().exec(cmd);',
                'example_output': '    ProcessBuilder pb = new ProcessBuilder(cmd);'
            },
            # C#
            'cs': {
                'name': 'C#',
                'markdown_name': 'csharp',
                'indent_type': 'spaces',
                'comment_prefix': '//',
                'example_input': '    var result = Process.Start(cmd);',
                'example_output': '    var psi = new ProcessStartInfo { FileName = cmd };'
            },
            # PHP
            'php': {
                'name': 'PHP',
                'markdown_name': 'php',
                'indent_type': 'spaces',
                'comment_prefix': '//',
                'example_input': '    $result = eval($userInput);',
                'example_output': '    $result = json_decode($userInput);'
            },
            # Ruby
            'rb': {
                'name': 'Ruby',
                'markdown_name': 'ruby',
                'indent_type': 'spaces',
                'comment_prefix': '#',
                'example_input': '    result = eval(user_input)',
                'example_output': '    result = JSON.parse(user_input)'
            },
            # C/C++
            'c': {
                'name': 'C',
                'markdown_name': 'c',
                'indent_type': 'spaces',
                'comment_prefix': '//',
                'example_input': '    system(command);',
                'example_output': '    execvp(argv[0], argv);'
            },
            'cpp': {
                'name': 'C++',
                'markdown_name': 'cpp',
                'indent_type': 'spaces',
                'comment_prefix': '//',
                'example_input': '    system(command.c_str());',
                'example_output': '    std::system(command.c_str());'
            }
        }
        
        return language_map.get(ext, self._get_default_language_info())
    
    def _get_default_language_info(self) -> Dict[str, str]:
        """Get default language info for unknown file types"""
        return {
            'name': 'code',
            'markdown_name': 'text',
            'indent_type': 'spaces',
            'comment_prefix': '#',
            'example_input': '    vulnerable_function(user_input)',
            'example_output': '    safe_function(sanitized_input)'
        }