"""
AI-powered Code Fixer Module
Generates automatic security fixes for detected vulnerabilities
"""

import logging
from openai import AsyncOpenAI
from typing import Dict, List, Any, Optional, Tuple
import re
import ast
import json
import asyncio

logger = logging.getLogger(__name__)

class AICodeFixer:
    """Generate automatic security fixes using AI"""
    
    def __init__(self, openai_api_key: str):
        self.client = AsyncOpenAI(api_key=openai_api_key)
        self.model = "gpt-4o-mini"  # Cost-optimized model
        self.fix_patterns = self._load_fix_patterns()
        self.max_concurrent_fixes = 5
        
    async def generate_fix(
        self,
        issue: Dict[str, Any],
        code_context: Dict[str, Any],
        language: str
    ) -> Optional[Dict[str, Any]]:
        """Generate automatic fix for a security issue"""
        
        try:
            # Try pattern-based fix first (faster and more reliable)
            pattern_fix = self._try_pattern_fix(issue, code_context, language)
            if pattern_fix:
                return pattern_fix
            
            # Use AI for complex fixes
            ai_fix = await self._generate_ai_fix(issue, code_context, language)
            return ai_fix
            
        except Exception as e:
            logger.error(f"Error generating fix: {e}")
            return None
    
    def _try_pattern_fix(
        self,
        issue: Dict[str, Any],
        code_context: Dict[str, Any],
        language: str
    ) -> Optional[Dict[str, Any]]:
        """Try to fix using predefined patterns"""
        
        rule_id = issue.get("rule_id", "")
        tool = issue.get("tool", "")
        vulnerable_code = code_context.get("vulnerable_code", "")
        
        # Find matching pattern
        for pattern in self.fix_patterns:
            if (pattern["tool"] == tool and 
                pattern["rule_id"] == rule_id and 
                pattern["language"] == language):
                
                fix = self._apply_pattern(
                    pattern["fix_pattern"],
                    vulnerable_code,
                    code_context
                )
                
                if fix:
                    return {
                        "fixed_code": fix,
                        "explanation": pattern["explanation"],
                        "confidence": "high",
                        "method": "pattern"
                    }
        
        return None
    
    async def _generate_ai_fix(
        self,
        issue: Dict[str, Any],
        code_context: Dict[str, Any],
        language: str
    ) -> Optional[Dict[str, Any]]:
        """Generate fix using AI"""
        
        try:
            prompt = self._build_enhanced_fix_prompt(issue, code_context, language)
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are an expert security engineer specializing in automated vulnerability remediation. 
Your role is to provide precise, minimal security fixes that:
1. Eliminate the security vulnerability completely
2. Maintain all existing functionality 
3. Follow language-specific best practices
4. Are production-ready without additional changes
5. Include clear explanations for developers

Focus on providing the most secure and maintainable solution."""
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Lower for more consistent results
                max_tokens=800,
                response_format={"type": "json_object"}
            )
            
            fix_data = self._parse_enhanced_ai_response(response.choices[0].message.content)
            
            if fix_data and self._validate_fix(fix_data["fixed_code"], code_context, language):
                return {
                    "fixed_code": fix_data["fixed_code"],
                    "explanation": fix_data.get("explanation", "AI-generated security fix"),
                    "confidence": fix_data.get("confidence", "medium"),
                    "method": "ai",
                    "security_impact": fix_data.get("security_impact", ""),
                    "testing_notes": fix_data.get("testing_notes", "")
                }
            
        except Exception as e:
            logger.error(f"AI fix generation failed: {e}")
        
        return None
    
    def _build_enhanced_fix_prompt(
        self,
        issue: Dict[str, Any],
        code_context: Dict[str, Any],
        language: str
    ) -> str:
        """Build enhanced prompt for AI fix generation"""
        
        owasp_info = ""
        if issue.get('owasp_category'):
            owasp_info = f"\nOWASP Category: {issue['owasp_category']}"
        
        cwe_info = ""
        if issue.get('cwe_id'):
            cwe_info = f"\nCWE-{issue['cwe_id']}"
        
        return f"""You must respond with valid JSON only. Analyze and fix this {language} security vulnerability:

**Vulnerability Details:**
- Issue: {issue.get('message', 'Security issue')} 
- Severity: {issue.get('severity', 'medium')}
- Tool: {issue.get('tool', 'unknown')}
- Rule ID: {issue.get('rule_id', 'unknown')}{owasp_info}{cwe_info}

**Vulnerable Code:**
```{language}
{code_context.get('vulnerable_code', '')}
```

**Context (lines before):**
```{language}
{code_context.get('context_before', '')}
```

**Context (lines after):**
```{language}
{code_context.get('context_after', '')}
```

**Requirements:**
1. Eliminate the security vulnerability completely
2. Preserve all existing functionality
3. Follow {language} security best practices
4. Make it production-ready
5. Minimize code changes

Respond with JSON in this exact format:
{{
  "fixed_code": "the corrected code here",
  "explanation": "clear explanation of what was fixed and why",
  "confidence": "high|medium|low",
  "security_impact": "brief description of security improvement",
  "testing_notes": "suggestions for testing the fix"
}}"""

    def _build_fix_prompt(
        self,
        issue: Dict[str, Any],
        code_context: Dict[str, Any],
        language: str
    ) -> str:
        """Build prompt for AI fix generation (legacy method)"""
        
        return f"""Fix this {language} security vulnerability:

Issue: {issue.get('message', 'Security issue')}
Severity: {issue.get('severity', 'medium')}
Tool/Rule: {issue.get('tool', 'unknown')}/{issue.get('rule_id', 'unknown')}

Vulnerable Code:
```{language}
{code_context.get('vulnerable_code', '')}
```

Context (lines before):
```{language}
{code_context.get('context_before', '')}
```

Context (lines after):
```{language}
{code_context.get('context_after', '')}
```

Provide a minimal, secure fix that:
1. Fixes the security issue
2. Maintains the original functionality
3. Follows {language} best practices
4. Is production-ready

Response format:
FIXED_CODE:
```{language}
[your fixed code here]
```
EXPLANATION:
[brief explanation of the fix]
"""
    
    def _parse_enhanced_ai_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse enhanced AI response (JSON format)"""
        
        try:
            response_data = json.loads(response)
            
            # Validate required fields
            if not response_data.get("fixed_code") or not response_data.get("explanation"):
                return None
            
            return {
                "fixed_code": response_data["fixed_code"].strip(),
                "explanation": response_data["explanation"].strip(),
                "confidence": response_data.get("confidence", "medium"),
                "security_impact": response_data.get("security_impact", ""),
                "testing_notes": response_data.get("testing_notes", "")
            }
            
        except json.JSONDecodeError:
            logger.error("AI response is not valid JSON")
            # Fallback to legacy parsing
            return self._parse_ai_response(response)
        except Exception as e:
            logger.error(f"Error parsing enhanced AI response: {e}")
            return None

    def _parse_ai_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse AI response to extract fix (legacy method)"""
        
        try:
            # Extract fixed code
            code_match = re.search(r'FIXED_CODE:\s*```\w*\n(.*?)```', response, re.DOTALL)
            if not code_match:
                return None
            
            fixed_code = code_match.group(1).strip()
            
            # Extract explanation
            explanation_match = re.search(r'EXPLANATION:\s*(.+)', response, re.DOTALL)
            explanation = explanation_match.group(1).strip() if explanation_match else ""
            
            return {
                "fixed_code": fixed_code,
                "explanation": explanation
            }
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            return None
    
    def _validate_fix(self, fixed_code: str, code_context: Dict[str, Any], language: str) -> bool:
        """Validate that the fix is safe and syntactically correct"""
        
        try:
            # Basic validation
            if not fixed_code or len(fixed_code) > 10000:
                return False
            
            # Language-specific validation
            if language == "python":
                return self._validate_python_code(fixed_code)
            elif language in ["javascript", "typescript"]:
                return self._validate_javascript_code(fixed_code)
            elif language == "java":
                return self._validate_java_code(fixed_code)
            
            # Default: basic checks
            return True
            
        except Exception:
            return False
    
    def _validate_python_code(self, code: str) -> bool:
        """Validate Python code syntax"""
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False
    
    def _validate_javascript_code(self, code: str) -> bool:
        """Basic JavaScript validation"""
        # Check for common syntax errors
        if code.count('(') != code.count(')'):
            return False
        if code.count('{') != code.count('}'):
            return False
        if code.count('[') != code.count(']'):
            return False
        return True
    
    def _validate_java_code(self, code: str) -> bool:
        """Basic Java validation"""
        # Check for balanced braces and semicolons
        if code.count('{') != code.count('}'):
            return False
        if not code.strip().endswith(';') and not code.strip().endswith('}'):
            return False
        return True
    
    def _apply_pattern(
        self,
        pattern: Dict[str, Any],
        vulnerable_code: str,
        code_context: Dict[str, Any]
    ) -> Optional[str]:
        """Apply a fix pattern to vulnerable code"""
        
        try:
            if pattern["type"] == "regex_replace":
                return re.sub(
                    pattern["search"],
                    pattern["replace"],
                    vulnerable_code,
                    flags=re.MULTILINE
                )
            elif pattern["type"] == "template":
                return pattern["template"].format(
                    code=vulnerable_code,
                    **code_context
                )
            elif pattern["type"] == "function":
                return self._apply_function_pattern(pattern, vulnerable_code, code_context)
            
        except Exception as e:
            logger.error(f"Error applying pattern: {e}")
        
        return None
    
    def _apply_function_pattern(
        self,
        pattern: Dict[str, Any],
        vulnerable_code: str,
        code_context: Dict[str, Any]
    ) -> Optional[str]:
        """Apply function-based patterns"""
        
        func_name = pattern["function"]
        
        if func_name == "escape_sql":
            return self._escape_sql(vulnerable_code)
        elif func_name == "sanitize_input":
            return self._sanitize_input(vulnerable_code, pattern["language"])
        elif func_name == "use_parameterized_query":
            return self._convert_to_parameterized_query(vulnerable_code, pattern["language"])
        elif func_name == "add_validation":
            return self._add_input_validation(vulnerable_code, pattern["language"])
        
        return None
    
    def _escape_sql(self, code: str) -> str:
        """Add SQL escaping"""
        # Example implementation
        if "execute(" in code:
            return code.replace("execute(", "execute_safe(")
        return code
    
    def _sanitize_input(self, code: str, language: str) -> str:
        """Add input sanitization"""
        if language == "python":
            return f"sanitize_input({code})"
        elif language == "javascript":
            return f"DOMPurify.sanitize({code})"
        return code
    
    def _convert_to_parameterized_query(self, code: str, language: str) -> str:
        """Convert to parameterized query"""
        if language == "python":
            # Convert string formatting to parameterized
            if "%" in code and "SELECT" in code:
                return re.sub(r'%\s*\((.*?)\)', r'%s', code) + " # Use parameterized query"
        return code
    
    def _add_input_validation(self, code: str, language: str) -> str:
        """Add input validation"""
        if language == "python":
            return f"if validate_input({code}):\n    {code}"
        elif language == "javascript":
            return f"if (validateInput({code})) {{\n    {code}\n}}"
        return code
    
    def _load_fix_patterns(self) -> List[Dict[str, Any]]:
        """Load predefined fix patterns"""
        
        return [
            # SQL Injection fixes
            {
                "tool": "semgrep",
                "rule_id": "sql-injection",
                "language": "python",
                "type": "regex_replace",
                "search": r'execute\s*\(\s*["\'].*?%.*?["\'].*?%',
                "replace": "execute(?, ",
                "fix_pattern": {"type": "function", "function": "use_parameterized_query"},
                "explanation": "Use parameterized queries to prevent SQL injection"
            },
            # XSS fixes
            {
                "tool": "semgrep",
                "rule_id": "xss",
                "language": "javascript",
                "type": "template",
                "template": "DOMPurify.sanitize({code})",
                "fix_pattern": {"type": "function", "function": "sanitize_input"},
                "explanation": "Sanitize user input to prevent XSS"
            },
            # Hardcoded secrets
            {
                "tool": "trufflehog",
                "rule_id": "hardcoded-secret",
                "language": "python",
                "type": "regex_replace",
                "search": r'(password|secret|key)\s*=\s*["\']([^"\']+)["\']',
                "replace": r'\1 = os.environ.get("\1".upper())',
                "fix_pattern": {"type": "regex_replace"},
                "explanation": "Move secrets to environment variables"
            },
            # Path traversal
            {
                "tool": "semgrep",
                "rule_id": "path-traversal",
                "language": "python",
                "type": "template",
                "template": "os.path.join(BASE_DIR, os.path.basename({code}))",
                "fix_pattern": {"type": "template"},
                "explanation": "Sanitize file paths to prevent directory traversal"
            },
            # Weak crypto
            {
                "tool": "bandit",
                "rule_id": "B303",
                "language": "python",
                "type": "regex_replace",
                "search": r'md5\s*\(',
                "replace": "hashlib.sha256(",
                "fix_pattern": {"type": "regex_replace"},
                "explanation": "Replace MD5 with SHA256 for better security"
            }
        ]
    
    async def generate_fix_suggestions_batch(
        self,
        issues: List[Dict[str, Any]],
        file_content: str,
        language: str
    ) -> Dict[str, Dict[str, Any]]:
        """Generate fixes for multiple issues in batch with concurrency control"""
        
        fix_suggestions = {}
        
        # Group similar issues
        issue_groups = self._group_similar_issues(issues)
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent_fixes)
        
        async def generate_group_fix(group_id: str, group_issues: List[Dict[str, Any]]):
            async with semaphore:
                try:
                    # Generate fix for the group representative
                    representative_issue = group_issues[0]
                    code_context = self._extract_code_context(
                        representative_issue,
                        file_content
                    )
                    
                    fix = await self.generate_fix(
                        representative_issue,
                        code_context,
                        language
                    )
                    
                    if fix:
                        # Apply fix to all issues in group
                        group_fixes = {}
                        for issue in group_issues:
                            issue_id = issue.get("id", str(hash(str(issue))))
                            group_fixes[issue_id] = fix
                        return group_fixes
                    
                except Exception as e:
                    logger.error(f"Error generating fix for group {group_id}: {e}")
                
                return {}
        
        # Run fixes in parallel with controlled concurrency
        tasks = [
            generate_group_fix(group_id, group_issues)
            for group_id, group_issues in issue_groups.items()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine results
        for result in results:
            if isinstance(result, dict):
                fix_suggestions.update(result)
            elif isinstance(result, Exception):
                logger.error(f"Batch fix generation error: {result}")
        
        logger.info(f"Generated {len(fix_suggestions)} fix suggestions for {len(issues)} issues")
        return fix_suggestions
    
    def _group_similar_issues(self, issues: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group similar issues that can be fixed together"""
        
        groups = {}
        
        for issue in issues:
            # Create group key based on tool, rule, and general location
            group_key = f"{issue.get('tool')}_{issue.get('rule_id')}_{issue.get('category')}"
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(issue)
        
        return groups
    
    def _extract_code_context(
        self,
        issue: Dict[str, Any],
        file_content: str
    ) -> Dict[str, Any]:
        """Extract code context for an issue"""
        
        lines = file_content.split('\n')
        line_start = issue.get('line_start', 1) - 1
        line_end = issue.get('line_end', line_start + 1)
        
        # Extract vulnerable code
        vulnerable_code = '\n'.join(lines[line_start:line_end])
        
        # Extract context
        context_start = max(0, line_start - 3)
        context_end = min(len(lines), line_end + 3)
        
        return {
            "vulnerable_code": vulnerable_code,
            "context_before": '\n'.join(lines[context_start:line_start]),
            "context_after": '\n'.join(lines[line_end:context_end]),
            "full_context": '\n'.join(lines[context_start:context_end])
        }