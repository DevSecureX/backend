import hashlib
import json
import logging
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import asyncio

import openai
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_
from sqlalchemy.dialects.postgresql import insert
# Import redis_client only when needed to avoid production connections
from ..models import AIPatternCache

logger = logging.getLogger(__name__)

class SmartAIExplainer:
    def __init__(self, openai_api_key: str):
        self.client = openai.OpenAI(api_key=openai_api_key) if openai_api_key else None
        self.model = "gpt-4o-mini"
        self.cache_ttl = 86400 * 7  # 7 days
        
    async def explain_issues_batch(
        self, 
        issues: List[Dict[str, Any]], 
        db: AsyncSession,
        include_code_context: bool = True
    ) -> Dict[str, Dict[str, Any]]:
        """Explain multiple issues efficiently using caching and batching"""
        
        if not self.client:
            logger.error("OpenAI client not initialized")
            return {}
        
        explanations = {}
        
        # Group issues by pattern for batch processing
        issue_groups = self._group_issues_by_pattern(issues)
        
        for pattern_hash, issue_group in issue_groups.items():
            try:
                # Check cache first
                cached_explanation = await self._get_cached_explanation(pattern_hash, db)
                
                if cached_explanation:
                    # Use cached explanation for all issues in this pattern
                    for issue in issue_group:
                        issue_id = self._generate_issue_id(issue)
                        explanations[issue_id] = {
                            "explanation": cached_explanation.explanation,
                            "fix_suggestion": cached_explanation.fix_suggestion,
                            "testing_approach": cached_explanation.testing_approach,
                            "owasp_mapping": cached_explanation.owasp_mapping,
                            "cached": True
                        }
                        
                        # Update usage count
                        await self._update_usage_count(pattern_hash, db)
                else:
                    # Generate new explanation
                    batch_explanation = await self._generate_batch_explanation(issue_group, include_code_context)
                    
                    if batch_explanation:
                        # Cache the explanation
                        await self._cache_explanation(pattern_hash, issue_group[0], batch_explanation, db)
                        
                        # Apply to all issues in this pattern
                        for issue in issue_group:
                            issue_id = self._generate_issue_id(issue)
                            explanations[issue_id] = {**batch_explanation, "cached": False}
                            
            except Exception as e:
                logger.error(f"Failed to explain pattern {pattern_hash}: {e}")
                # Add fallback explanations for this group
                for issue in issue_group:
                    issue_id = self._generate_issue_id(issue)
                    explanations[issue_id] = self._generate_fallback_explanation(issue)
        
        return explanations
    
    def _group_issues_by_pattern(self, issues: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group similar issues together for batch processing"""
        groups = {}
        
        for issue in issues:
            pattern_hash = self._calculate_pattern_hash(issue)
            if pattern_hash not in groups:
                groups[pattern_hash] = []
            groups[pattern_hash].append(issue)
        
        return groups
    
    def _calculate_pattern_hash(self, issue: Dict[str, Any]) -> str:
        """Calculate hash for issue pattern to enable caching"""
        # Extract file extension to ensure language-specific caching
        file_path = issue.get("file_path", "")
        if not file_path:
            file_extension = "py"  # Default fallback
        elif file_path.lower() in ["dockerfile", "dockerfile.prod", "dockerfile.dev"]:
            file_extension = "dockerfile"  # Special case for Dockerfiles
        elif "." in file_path:
            file_extension = file_path.split(".")[-1].lower()
        else:
            file_extension = "py"  # Fallback for files without extensions
        
        pattern_data = {
            "rule_id": issue.get("rule_id"),
            "tool": issue.get("tool"),
            "category": issue.get("category"),
            "severity": issue.get("severity"),
            "owasp_category": issue.get("owasp_category"),
            "cwe_id": issue.get("cwe_id"),
            "file_extension": file_extension  # Include language context in cache key
        }
        
        pattern_str = json.dumps(pattern_data, sort_keys=True)
        return hashlib.sha256(pattern_str.encode()).hexdigest()
    
    def _generate_issue_id(self, issue: Dict[str, Any]) -> str:
        """Generate unique ID for an issue"""
        issue_data = {
            "tool": issue.get("tool"),
            "rule_id": issue.get("rule_id"),
            "file_path": issue.get("file_path"),
            "line_start": issue.get("line_start"),
            "message": issue.get("message")
        }
        
        issue_str = json.dumps(issue_data, sort_keys=True)
        return hashlib.md5(issue_str.encode()).hexdigest()
    
    async def _get_cached_explanation(self, pattern_hash: str, db: AsyncSession) -> Optional[AIPatternCache]:
        """Get cached explanation from database"""
        try:
            result = await db.execute(
                select(AIPatternCache).where(AIPatternCache.pattern_hash == pattern_hash)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logger.warning(f"Failed to get cached explanation: {e}")
            return None
    
    async def _generate_batch_explanation(
        self, 
        issues: List[Dict[str, Any]], 
        include_code_context: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Generate AI explanation for a batch of similar issues"""
        
        representative_issue = issues[0]  # Use first issue as representative
        
        # Build comprehensive prompt
        prompt = self._build_comprehensive_prompt(representative_issue, len(issues), include_code_context)
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=[
                    {
                        "role": "system", 
                        "content": """You are a senior security engineer explaining code vulnerabilities. 
                        Provide clear, actionable explanations that help developers understand and fix security issues.
                        Always include specific fix suggestions and testing approaches."""
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=1500
            )
            
            content = response.choices[0].message.content.strip()
            return self._parse_ai_response(content, representative_issue)
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            return None
    
    def _build_comprehensive_prompt(
        self, 
        issue: Dict[str, Any], 
        issue_count: int,
        include_code_context: bool = True
    ) -> str:
        """Build comprehensive prompt for AI explanation"""
        
        prompt_parts = [
            f"Security Issue Analysis (Found in {issue_count} location{'s' if issue_count > 1 else ''}):",
            "",
            f"Tool: {issue.get('tool', 'Unknown')}",
            f"Rule ID: {issue.get('rule_id', 'Unknown')}",
            f"Category: {issue.get('category', 'Unknown')}",
            f"Severity: {issue.get('severity', 'Unknown')}",
            f"Message: {issue.get('message', 'No description')}",
            ""
        ]
        
        if issue.get('file_path'):
            prompt_parts.extend([
                f"File: {issue['file_path']}",
                f"Line: {issue.get('line_start', 'Unknown')}",
                ""
            ])
        
        if issue.get('owasp_category'):
            prompt_parts.append(f"OWASP Category: {issue['owasp_category']}")
        
        if issue.get('cwe_id'):
            prompt_parts.append(f"CWE ID: {issue['cwe_id']}")
        
        prompt_parts.extend([
            "",
            "Please provide:",
            "1. EXPLANATION: Clear explanation of what this vulnerability is and why it's dangerous",
            "2. FIX_SUGGESTION: Specific code changes or configuration fixes",
            "3. TESTING_APPROACH: How to verify the fix works and prevent regression",
            "4. BUSINESS_IMPACT: Potential business consequences if exploited",
            "",
            "Format your response with clear sections using the headers above."
        ])
        
        return "\n".join(prompt_parts)
    
    def _parse_ai_response(self, content: str, issue: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AI response into structured format"""
        
        sections = {
            "explanation": "",
            "fix_suggestion": "",
            "testing_approach": "",
            "business_impact": ""
        }
        
        # Split by ### headers (the AI is using ### for headers)
        parts = content.split('###')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            # Check which section this is
            if part.upper().startswith('EXPLANATION'):
                sections['explanation'] = part.split(':', 1)[1].strip() if ':' in part else part
            elif 'FIX' in part.upper() and 'SUGGESTION' in part.upper():
                sections['fix_suggestion'] = part.split(':', 1)[1].strip() if ':' in part else part
            elif 'TESTING' in part.upper():
                sections['testing_approach'] = part.split(':', 1)[1].strip() if ':' in part else part
            elif 'BUSINESS' in part.upper() and 'IMPACT' in part.upper():
                sections['business_impact'] = part.split(':', 1)[1].strip() if ':' in part else part
        
        # If parsing failed, put everything in explanation
        if not sections['fix_suggestion'] and not sections['testing_approach']:
            # The AI included everything in the explanation, so we keep it as is
            sections['explanation'] = content
        
        # Add OWASP mapping
        owasp_mapping = None
        if issue.get('owasp_category'):
            owasp_mapping = {
                "category": issue['owasp_category'],
                "cwe_id": issue.get('cwe_id'),
                "severity_justification": f"Classified as {issue.get('severity', 'medium')} severity"
            }
        
        return {
            "explanation": sections['explanation'].strip(),
            "fix_suggestion": sections['fix_suggestion'].strip(),
            "testing_approach": sections['testing_approach'].strip(),
            "business_impact": sections['business_impact'].strip(),
            "owasp_mapping": owasp_mapping
        }
    
    async def _cache_explanation(
        self, 
        pattern_hash: str, 
        representative_issue: Dict[str, Any], 
        explanation: Dict[str, Any], 
        db: AsyncSession
    ):
        """Cache explanation in database"""
        try:
            cache_entry = {
                "pattern_hash": pattern_hash,
                "rule_id": representative_issue.get("rule_id"),
                "tool": representative_issue.get("tool"),
                "category": representative_issue.get("category"),
                "explanation": explanation.get("explanation"),
                "fix_suggestion": explanation.get("fix_suggestion"),
                "testing_approach": explanation.get("testing_approach"),
                "owasp_mapping": explanation.get("owasp_mapping"),
                "confidence_score": 0.8,
                "prompt_version": "v1.0"
            }
            
            stmt = insert(AIPatternCache).values(**cache_entry)
            stmt = stmt.on_conflict_do_nothing(index_elements=['pattern_hash'])
            
            await db.execute(stmt)
            await db.commit()
            
            logger.info(f"Cached AI explanation for pattern {pattern_hash}")
            
        except Exception as e:
            logger.error(f"Failed to cache explanation: {e}")
            await db.rollback()
    
    async def _update_usage_count(self, pattern_hash: str, db: AsyncSession):
        """Update usage count for cached explanation"""
        try:
            await db.execute(
                update(AIPatternCache)
                .where(AIPatternCache.pattern_hash == pattern_hash)
                .values(usage_count=AIPatternCache.usage_count + 1)
            )
            await db.commit()
        except Exception as e:
            logger.warning(f"Failed to update usage count: {e}")
            await db.rollback()
    
    def _generate_fallback_explanation(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        """Generate basic fallback explanation when AI fails"""
        return {
            "explanation": f"Security issue detected by {issue.get('tool', 'security scanner')}: {issue.get('message', 'No description available')}",
            "fix_suggestion": "Review the flagged code and consult security best practices for your programming language.",
            "testing_approach": "Add unit tests to verify the fix and include security testing in your CI/CD pipeline.",
            "business_impact": f"This {issue.get('severity', 'medium')} severity issue could potentially impact application security.",
            "cached": False,
            "fallback": True
        }
        
# Add these methods to your existing SmartAIExplainer class

    async def _build_optimized_prompt(
        self, 
        issue: Dict[str, Any], 
        issue_count: int,
        language: str = None,
        niche: str = None,
        include_code_context: bool = True
    ) -> str:
        """Build optimized prompt with language and niche context"""
        
        # Detect language from file extension if not provided
        if not language and issue.get('file_path'):
            ext = os.path.splitext(issue['file_path'])[1].lstrip('.')
            language = self._map_extension_to_language(ext)
        
        # Build context-aware prompt
        prompt_parts = [
            f"Security Issue Analysis for {language or 'code'}" + (f" in {niche} application" if niche else ""),
            f"(Found in {issue_count} location{'s' if issue_count > 1 else ''})",
            "",
            f"Tool: {issue.get('tool', 'Unknown')}",
            f"Rule: {issue.get('rule_id', 'Unknown')}",
            f"Category: {issue.get('category', 'Unknown')}",
            f"Severity: {issue.get('severity', 'Unknown')}",
            f"Message: {issue.get('message', 'No description')}",
        ]
        
        if issue.get('file_path'):
            prompt_parts.extend([
                f"File: {issue['file_path']}",
                f"Line: {issue.get('line_start', 'Unknown')}",
            ])
        
        # Add code context if available
        if include_code_context and issue.get('code_context'):
            context = issue['code_context']
            prompt_parts.extend([
                "",
                "Code Context:",
                "```" + context.get('file_extension', ''),
                context.get('code_snippet', ''),
                "```"
            ])
        
        # Add specific instructions based on language and niche
        if language:
            prompt_parts.extend([
                "",
                f"Consider {language}-specific security patterns and best practices."
            ])
        
        if niche:
            niche_considerations = {
                'ai': "Consider AI/ML specific risks like model poisoning, data leakage, and API key exposure.",
                'blockchain': "Consider blockchain risks like private key exposure, smart contract vulnerabilities, and consensus attacks.",
                'iot': "Consider IoT risks like device authentication, firmware vulnerabilities, and insecure communication.",
                'fintech': "Consider financial risks like transaction integrity, PCI compliance, and monetary calculations.",
                'healthcare': "Consider HIPAA compliance, PHI protection, and medical device security."
            }
            if niche in niche_considerations:
                prompt_parts.append(niche_considerations[niche])
        
        prompt_parts.extend([
            "",
            "Provide:",
            "1. EXPLANATION: Clear explanation of the vulnerability and why it's dangerous",
            "2. FIX_SUGGESTION: Specific code fix" + (f" for {language}" if language else ""),
            "3. FIXED_CODE: The secure version of the vulnerable code",
            "4. TESTING_APPROACH: How to test the fix",
            "5. BUSINESS_IMPACT: Consequences if exploited" + (f" in a {niche} context" if niche else ""),
            "",
            "Format with clear section headers. Keep explanations concise but comprehensive."
        ])
        
        return "\n".join(prompt_parts)

    def _map_extension_to_language(self, ext: str) -> str:
        """Map file extension to programming language"""
        ext_map = {
            'py': 'Python',
            'js': 'JavaScript',
            'ts': 'TypeScript',
            'go': 'Go',
            'java': 'Java',
            'cs': 'C#',
            'php': 'PHP',
            'rb': 'Ruby',
            'cpp': 'C++',
            'c': 'C',
            'rs': 'Rust',
            'kt': 'Kotlin',
            'swift': 'Swift',
            'scala': 'Scala',
            'r': 'R',
            'sh': 'Shell',
            'sql': 'SQL'
        }
        return ext_map.get(ext, None)

    async def cleanup_stale_cache(self, db: AsyncSession, days: int = 7, min_usage: int = 5):
        """Clean up stale AI explanation cache entries"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Delete entries older than cutoff with low usage
            result = await db.execute(
                delete(AIPatternCache).where(
                    and_(
                        AIPatternCache.created_at < cutoff_date,
                        AIPatternCache.usage_count < min_usage
                    )
                ).returning(AIPatternCache.id)
            )
            
            deleted_ids = [row[0] for row in result.fetchall()]
            await db.commit()
            
            logger.info(f"Cleaned up {len(deleted_ids)} stale AI cache entries")
            return len(deleted_ids)
            
        except Exception as e:
            logger.error(f"Failed to cleanup AI cache: {e}")
            await db.rollback()
            return 0

    async def generate_architectural_fix(
        self,
        issues: List[Dict[str, Any]],
        db: AsyncSession,
        repo_context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Generate architectural-level fixes for systemic issues"""
        
        if not self.client:
            logger.error("OpenAI client not initialized")
            return {}
        
        # Group issues by category and severity
        issue_patterns = {}
        for issue in issues:
            key = f"{issue.get('category')}:{issue.get('severity')}"
            if key not in issue_patterns:
                issue_patterns[key] = []
            issue_patterns[key].append(issue)
        
        # Build architectural analysis prompt
        prompt = self._build_architectural_prompt(issue_patterns, repo_context)
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model="gpt-4",  # Use GPT-4 for architectural recommendations
                messages=[
                    {
                        "role": "system",
                        "content": """You are a senior security architect. Analyze security patterns 
                        and provide architectural-level recommendations to prevent systemic vulnerabilities."""
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            content = response.choices[0].message.content.strip()
            
            # Parse and structure the response
            architectural_fix = self._parse_architectural_response(content)
            
            # Cache the architectural recommendation
            if architectural_fix:
                pattern_hash = hashlib.sha256(json.dumps(issue_patterns, sort_keys=True).encode()).hexdigest()
                await self._cache_architectural_fix(pattern_hash, architectural_fix, db)
            
            return architectural_fix
            
        except Exception as e:
            logger.error(f"Failed to generate architectural fix: {e}")
            return self._generate_fallback_architectural_fix(issue_patterns)

    def _build_architectural_prompt(self, issue_patterns: Dict[str, List[Dict]], repo_context: Dict[str, Any]) -> str:
        """Build prompt for architectural recommendations"""
        
        prompt_parts = ["Security Architecture Analysis", ""]
        
        # Add repository context if available
        if repo_context:
            prompt_parts.extend([
                f"Repository: {repo_context.get('name', 'Unknown')}",
                f"Languages: {', '.join(repo_context.get('languages', []))}",
                f"Niche: {repo_context.get('niche', 'general')}",
                ""
            ])
        
        # Summarize issues by pattern
        prompt_parts.append("Issue Patterns Detected:")
        for pattern, issues in issue_patterns.items():
            category, severity = pattern.split(':')
            prompt_parts.append(f"- {len(issues)} {severity} {category} issues")
        
        # Add specific examples
        prompt_parts.extend(["", "Top Issues:"])
        example_count = 0
        for pattern, issues in sorted(issue_patterns.items(), key=lambda x: len(x[1]), reverse=True):
            if example_count >= 5:
                break
            for issue in issues[:2]:  # Show up to 2 examples per pattern
                prompt_parts.append(f"- {issue.get('tool')}: {issue.get('message')}")
                example_count += 1
        
        prompt_parts.extend([
            "",
            "Provide architectural recommendations:",
            "1. DESIGN_PATTERNS: Security design patterns to implement",
            "2. INFRASTRUCTURE: Infrastructure-level security controls",
            "3. DEVELOPMENT_PROCESS: Process improvements (CI/CD, code review)",
            "4. SECURITY_FRAMEWORKS: Applicable security frameworks and standards",
            "5. TOOLING: Additional security tools and automation",
            "6. TRAINING: Specific security training recommendations",
            "",
            "Focus on systemic improvements that address root causes."
        ])
        
        return "\n".join(prompt_parts)

    def _parse_architectural_response(self, content: str) -> Dict[str, Any]:
        """Parse architectural recommendations from AI response"""
        
        sections = {
            "design_patterns": [],
            "infrastructure": [],
            "development_process": [],
            "security_frameworks": [],
            "tooling": [],
            "training": []
        }
        
        current_section = None
        current_items = []
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Check for section headers
            if 'DESIGN_PATTERNS' in line.upper():
                if current_section and current_items:
                    sections[current_section] = current_items
                current_section = 'design_patterns'
                current_items = []
            elif 'INFRASTRUCTURE' in line.upper():
                if current_section and current_items:
                    sections[current_section] = current_items
                current_section = 'infrastructure'
                current_items = []
            elif 'DEVELOPMENT_PROCESS' in line.upper():
                if current_section and current_items:
                    sections[current_section] = current_items
                current_section = 'development_process'
                current_items = []
            elif 'SECURITY_FRAMEWORKS' in line.upper():
                if current_section and current_items:
                    sections[current_section] = current_items
                current_section = 'security_frameworks'
                current_items = []
            elif 'TOOLING' in line.upper():
                if current_section and current_items:
                    sections[current_section] = current_items
                current_section = 'tooling'
                current_items = []
            elif 'TRAINING' in line.upper():
                if current_section and current_items:
                    sections[current_section] = current_items
                current_section = 'training'
                current_items = []
            elif line and current_section:
                # Extract bullet points or numbered items
                if line.startswith(('-', '*', '•')) or (len(line) > 2 and line[0].isdigit() and line[1] in '.)'):
                    item_text = line.lstrip('-*•0123456789.) ').strip()
                    if item_text:
                        current_items.append(item_text)
        
        # Save last section
        if current_section and current_items:
            sections[current_section] = current_items
        
        # Create structured response
        return {
            "design_patterns": sections['design_patterns'],
            "infrastructure": sections['infrastructure'],
            "development_process": sections['development_process'],
            "security_frameworks": sections['security_frameworks'],
            "tooling": sections['tooling'],  
            "training": sections['training'],
            "generated_at": datetime.utcnow().isoformat()
        }

    async def _cache_architectural_fix(self, pattern_hash: str, fix: Dict[str, Any], db: AsyncSession):
        """Cache architectural recommendations"""
        try:
            cache_entry = {
                "pattern_hash": pattern_hash,
                "rule_id": "ARCH-" + pattern_hash[:8],
                "tool": "architectural-analysis",
                "category": "architecture",
                "explanation": "Architectural security recommendations",
                "architectural_fix": json.dumps(fix),
                "confidence_score": 0.9,
                "prompt_version": "v1.0"
            }
            
            stmt = insert(AIPatternCache).values(**cache_entry)
            stmt = stmt.on_conflict_do_update(
                index_elements=['pattern_hash'],
                set_={"architectural_fix": json.dumps(fix), "usage_count": AIPatternCache.usage_count + 1}
            )
            
            await db.execute(stmt)
            await db.commit()
            
        except Exception as e:
            logger.error(f"Failed to cache architectural fix: {e}")
            await db.rollback()

    def _generate_fallback_architectural_fix(self, issue_patterns: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Generate fallback architectural recommendations"""
        
        # Count total issues
        total_issues = sum(len(issues) for issues in issue_patterns.values())
        
        # Basic recommendations based on issue patterns
        recommendations = {
            "design_patterns": [
                "Implement input validation layer at API boundaries",
                "Use parameterized queries for all database operations",
                "Apply principle of least privilege across all services"
            ],
            "infrastructure": [
                "Enable security scanning in CI/CD pipeline",
                "Implement Web Application Firewall (WAF)",
                "Use secrets management service for credentials"
            ],
            "development_process": [
                "Mandatory security code reviews for all changes",
                "Automated security testing in pull requests",
                "Regular dependency updates and scanning"
            ],
            "security_frameworks": [
                "Implement OWASP Top 10 controls",
                "Follow NIST Cybersecurity Framework",
                "Apply Zero Trust principles"
            ],
            "tooling": [
                "Integrate SAST tools into IDE",
                "Deploy runtime application security (RASP)",
                "Implement security observability and monitoring"
            ],
            "training": [
                "OWASP secure coding practices training",
                "Language-specific security workshops",
                "Security champion program"
            ],
            "generated_at": datetime.utcnow().isoformat(),
            "fallback": True
        }
        
        return recommendations

    async def get_ai_explanation(
        self,
        tool: str,
        rule_id: str,
        category: str,
        severity: str,
        message: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Get AI explanation for a specific security issue or analysis"""
        
        if not self.client:
            logger.error("OpenAI client not initialized")
            return {
                "explanation": f"AI analysis unavailable: {message}",
                "confidence": 0.0,
                "fallback": True
            }
        
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security expert providing clear explanations of security issues and recommendations."
                    },
                    {
                        "role": "user",
                        "content": message
                    }
                ],
                temperature=0.3,
                max_tokens=800
            )
            
            content = response.choices[0].message.content.strip()
            
            return {
                "explanation": content,
                "confidence": 0.8,
                "tool": tool,
                "rule_id": rule_id,
                "category": category,
                "severity": severity
            }
            
        except Exception as e:
            logger.error(f"Failed to get AI explanation: {e}")
            return {
                "explanation": f"Analysis: {message}. Please review manually for security implications.",
                "confidence": 0.0,
                "fallback": True
            }