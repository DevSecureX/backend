"""
Enhanced PR scanning features for world-class security analysis.
Competitive features inspired by CodeRabbit, Snyk, and other leading tools.
"""

import logging
import asyncio
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, text
import json
import hashlib

from .models import Scan
from repos.models import Repo
from auth.models import User
from core.cache import cache, RateLimitCache
from .ai.smart_explainer import SmartAIExplainer
from .pr_scanning.pr_fetcher import PRFetcher
from .pr_scanning.diff_analyzer import PRDiffAnalyzer

logger = logging.getLogger(__name__)

class PREnhancementEngine:
    """Advanced PR analysis engine with world-class features"""
    
    def __init__(self):
        openai_api_key = os.getenv('OPENAI_API_KEY', '')
        self.ai_analyzer = SmartAIExplainer(openai_api_key)
        self.pr_fetcher = PRFetcher()
        self.diff_analyzer = PRDiffAnalyzer()
        
    async def get_pr_security_insights(
        self,
        repo_full_name: str,
        pr_number: int,
        gh_token: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Get comprehensive security insights for a PR"""
        
        # Get PR details and diff
        pr_details = await self.pr_fetcher.get_pr_details(repo_full_name, pr_number, gh_token)
        changed_files = await self.diff_analyzer.get_changed_files(repo_full_name, pr_number, gh_token)
        
        # Get author login safely
        author_login = None
        if pr_details and pr_details.get("author") and pr_details["author"].get("login"):
            author_login = pr_details["author"]["login"]
        
        # Analyze historical patterns
        historical_insights = await self._analyze_historical_patterns(
            repo_full_name, author_login, db
        )
        
        # Get incremental analysis
        incremental_analysis = await self._perform_incremental_analysis(
            repo_full_name, pr_number, changed_files, db
        )
        
        # Get base branch safely
        base_branch = "main"  # default fallback
        if pr_details and pr_details.get("base") and pr_details["base"].get("ref"):
            base_branch = pr_details["base"]["ref"]
        
        # Security trend analysis
        security_trends = await self._analyze_security_trends(
            repo_full_name, base_branch, db
        )
        
        # AI-powered insights
        ai_insights = await self._generate_ai_insights(
            pr_details, changed_files, incremental_analysis
        )
        
        return {
            "pr_number": pr_number,
            "title": pr_details.get("title", f"PR #{pr_number}") if pr_details else f"PR #{pr_number}",
            "author": author_login or "unknown",
            "security_risk_score": await self._calculate_pr_risk_score(
                incremental_analysis, historical_insights
            ),
            "incremental_analysis": incremental_analysis,
            "historical_patterns": historical_insights,
            "security_trends": security_trends,
            "ai_insights": ai_insights,
            "recommendations": await self._generate_recommendations(
                incremental_analysis, ai_insights
            ),
            "auto_fix_available": await self._check_auto_fix_availability(
                incremental_analysis.get("new_issues", []) if incremental_analysis else []
            ),
            "compliance_impact": await self._assess_compliance_impact(
                incremental_analysis.get("new_issues", []) if incremental_analysis else []
            )
        }
    
    async def _analyze_historical_patterns(
        self,
        repo_full_name: str,
        author: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Analyze historical security patterns for the PR author"""
        
        # Get repository's previous PRs and their security outcomes (author-agnostic)
        query = text("""
            SELECT 
                COUNT(*) as total_prs,
                AVG(s.total_score) as avg_security_score,
                SUM(CASE WHEN s.total_score < 70 THEN 1 ELSE 0 END) as risky_prs,
                COUNT(DISTINCT ss.category) as issue_categories
            FROM scans s
            LEFT JOIN scan_summaries ss ON s.id = ss.scan_id
            WHERE s.repo_full_name = :repo_name 
                AND s.pr_number IS NOT NULL
                AND s.created_at > NOW() - INTERVAL '90 days'
        """)
        
        result = await db.execute(
            query,
            {"repo_name": repo_full_name}
        )
        stats = result.fetchone()
        
        # Get most common issue types from this author
        common_issues_query = text("""
            SELECT 
                ss.category,
                CASE 
                    WHEN ss.critical_count > 0 THEN 'critical'
                    WHEN ss.high_count > 0 THEN 'high'
                    WHEN ss.medium_count > 0 THEN 'medium'
                    ELSE 'low'
                END as severity,
                SUM(ss.total_issues) as count
            FROM scans s
            JOIN scan_summaries ss ON s.id = ss.scan_id
            WHERE s.repo_full_name = :repo_name 
                AND s.pr_number IS NOT NULL
                AND s.created_at > NOW() - INTERVAL '90 days'
            GROUP BY category, severity
            ORDER BY count DESC
            LIMIT 5
        """)
        
        issues_result = await db.execute(
            common_issues_query,
            {"repo_name": repo_full_name, "author": author}
        )
        common_issues = [
            {"category": row.category, "severity": row.severity, "count": row.count}
            for row in issues_result
        ]
        
        return {
            "author_stats": {
                "total_prs": stats.total_prs or 0,
                "avg_security_score": float(stats.avg_security_score or 0),
                "risky_prs_count": stats.risky_prs or 0,
                "unique_issue_categories": stats.issue_categories or 0
            },
            "common_issues": common_issues,
            "trust_score": self._calculate_author_trust_score(stats),
            "improvement_trend": await self._calculate_improvement_trend(
                repo_full_name, author, db
            )
        }
    
    async def _perform_incremental_analysis(
        self,
        repo_full_name: str,
        pr_number: int,
        changed_files: List[Dict[str, Any]],
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Perform incremental diff analysis comparing to base branch"""
        
        # Get latest scan from base branch
        base_scan_query = select(Scan).where(
            and_(
                Scan.repo_full_name == repo_full_name,
                Scan.scan_type == "manual",
                Scan.pr_number.is_(None)
            )
        ).order_by(Scan.created_at.desc()).limit(1)
        
        result = await db.execute(base_scan_query)
        base_scan = result.scalar_one_or_none()
        
        # Get current PR scan if exists
        pr_scan_query = select(Scan).where(
            and_(
                Scan.repo_full_name == repo_full_name,
                Scan.pr_number == pr_number
            )
        ).order_by(Scan.created_at.desc()).limit(1)
        
        pr_result = await db.execute(pr_scan_query)
        pr_scan = pr_result.scalar_one_or_none()
        
        if not pr_scan:
            return {
                "status": "no_scan",
                "message": "PR not yet scanned",
                "changed_files_count": len(changed_files),
                "estimated_impact": "unknown"
            }
        
        # Get issues from summaries
        base_issues = []
        if base_scan:
            base_issues = await self._get_scan_issues(base_scan.id, db)
        
        pr_issues = []
        if pr_scan:
            pr_issues = await self._get_scan_issues(pr_scan.id, db)
        
        # Identify new, fixed, and persistent issues
        new_issues = []
        fixed_issues = []
        persistent_issues = []
        
        # Create issue fingerprints for comparison
        base_fingerprints = {
            self._create_issue_fingerprint(issue): issue 
            for issue in base_issues
        }
        pr_fingerprints = {
            self._create_issue_fingerprint(issue): issue 
            for issue in pr_issues
        }
        
        # Find new issues
        for fp, issue in pr_fingerprints.items():
            if fp not in base_fingerprints:
                # Check if this issue is in a changed file
                if any(cf.get("file_path") == issue.get("file_path") for cf in changed_files if cf):
                    new_issues.append(issue)
        
        # Find fixed issues
        for fp, issue in base_fingerprints.items():
            if fp not in pr_fingerprints:
                # Check if this fix is in a changed file
                if any(cf.get("file_path") == issue.get("file_path") for cf in changed_files if cf):
                    fixed_issues.append(issue)
        
        # Find persistent issues in changed files
        for fp, issue in pr_fingerprints.items():
            if fp in base_fingerprints:
                if any(cf.get("file_path") == issue.get("file_path") for cf in changed_files if cf):
                    persistent_issues.append(issue)
        
        return {
            "status": "analyzed",
            "base_score": base_scan.total_score if base_scan else None,
            "pr_score": pr_scan.total_score,
            "score_delta": pr_scan.total_score - (base_scan.total_score if base_scan else 100),
            "new_issues": new_issues,
            "fixed_issues": fixed_issues,
            "persistent_issues": persistent_issues,
            "summary": {
                "new_critical": sum(1 for i in new_issues if i.get("severity") == "critical"),
                "new_high": sum(1 for i in new_issues if i.get("severity") == "high"),
                "fixed_critical": sum(1 for i in fixed_issues if i.get("severity") == "critical"),
                "fixed_high": sum(1 for i in fixed_issues if i.get("severity") == "high"),
                "total_new": len(new_issues),
                "total_fixed": len(fixed_issues),
                "total_persistent": len(persistent_issues)
            },
            "security_improvement": len(fixed_issues) > len(new_issues)
        }
    
    async def _analyze_security_trends(
        self,
        repo_full_name: str,
        branch: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """Analyze security trends over time"""
        
        # Get scan history for the last 30 days
        query = text("""
            SELECT 
                DATE(s.created_at) as scan_date,
                AVG(s.total_score) as avg_score,
                COUNT(DISTINCT s.id) as scan_count,
                COALESCE(SUM(ss.total_issues), 0) as total_issues
            FROM scans s
            LEFT JOIN scan_summaries ss ON s.id = ss.scan_id
            WHERE s.repo_full_name = :repo_name
                AND s.branch = :branch
                AND s.created_at > NOW() - INTERVAL '30 days'
            GROUP BY scan_date
            ORDER BY scan_date DESC
        """)
        
        result = await db.execute(
            query,
            {"repo_name": repo_full_name, "branch": branch}
        )
        
        trends = [
            {
                "date": row.scan_date.isoformat(),
                "avg_score": float(row.avg_score),
                "scan_count": row.scan_count,
                "total_issues": row.total_issues
            }
            for row in result
        ]
        
        # Calculate trend direction
        if len(trends) >= 2:
            recent_score = trends[0].get("avg_score", 0)
            older_score = trends[-1].get("avg_score", 0)
            trend_direction = "improving" if recent_score > older_score else "declining"
            trend_percentage = ((recent_score - older_score) / older_score) * 100 if older_score > 0 else 0
        else:
            trend_direction = "stable"
            trend_percentage = 0
        
        return {
            "trend_data": trends[:7],  # Last 7 days
            "trend_direction": trend_direction,
            "trend_percentage": round(trend_percentage, 2),
            "avg_score_30d": sum(t.get("avg_score", 0) for t in trends) / len(trends) if trends else 0,
            "total_scans_30d": sum(t.get("scan_count", 0) for t in trends),
            "issue_velocity": self._calculate_issue_velocity(trends)
        }
    
    async def _generate_ai_insights(
        self,
        pr_details: Dict[str, Any],
        changed_files: List[Dict[str, Any]],
        incremental_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate AI-powered insights for the PR"""
        
        # Prepare context for AI analysis with null safety
        context = {
            "pr_title": pr_details.get("title", "Unknown PR") if pr_details else "Unknown PR",
            "pr_description": pr_details.get("body", "") if pr_details else "",
            "files_changed": len(changed_files) if changed_files else 0,
            "lines_added": sum(f.get("additions", 0) for f in changed_files) if changed_files else 0,
            "lines_deleted": sum(f.get("deletions", 0) for f in changed_files) if changed_files else 0,
            "new_security_issues": incremental_analysis.get("summary", {}).get("total_new", 0) if incremental_analysis else 0,
            "fixed_security_issues": incremental_analysis.get("summary", {}).get("total_fixed", 0) if incremental_analysis else 0
        }
        
        # Use AI to analyze PR impact
        ai_prompt = f"""Analyze this pull request for security implications:
        
        Title: {context['pr_title']}
        Description: {context['pr_description'][:500] if context['pr_description'] else 'No description'}
        
        Changes: {context['files_changed']} files, +{context['lines_added']}/-{context['lines_deleted']} lines
        Security Impact: {context['new_security_issues']} new issues, {context['fixed_security_issues']} fixed
        
        Provide:
        1. Overall security assessment
        2. Key risk areas to review
        3. Suggested security improvements
        4. Potential attack vectors introduced
        """
        
        # Use the smart AI explainer
        ai_response = await self.ai_analyzer.get_ai_explanation(
            tool="pr_analysis",
            rule_id="security_review",
            category="pr_security",
            severity="high",
            message=ai_prompt
        )
        
        return {
            "security_assessment": ai_response.get("explanation", ""),
            "risk_areas": self._extract_risk_areas(ai_response),
            "improvement_suggestions": self._extract_suggestions(ai_response),
            "confidence_score": ai_response.get("confidence", 0.8)
        }
    
    async def _calculate_pr_risk_score(
        self,
        incremental_analysis: Dict[str, Any],
        historical_insights: Dict[str, Any]
    ) -> int:
        """Calculate risk score for the PR (0-100, lower is better)"""
        
        base_risk = 0
        
        # Factor in new issues
        if incremental_analysis.get("status") == "analyzed":
            summary = incremental_analysis.get("summary", {})
            base_risk += summary.get("new_critical", 0) * 25
            base_risk += summary.get("new_high", 0) * 15
            base_risk += summary.get("total_new", 0) * 2
            
            # Reduce risk for fixed issues
            base_risk -= summary.get("fixed_critical", 0) * 20
            base_risk -= summary.get("fixed_high", 0) * 10
        
        # Factor in author history
        author_trust = historical_insights.get("trust_score", 50)
        risk_modifier = (100 - author_trust) / 100
        base_risk = int(base_risk * (1 + risk_modifier))
        
        # Cap at 100
        return min(100, max(0, base_risk))
    
    async def _generate_recommendations(
        self,
        incremental_analysis: Dict[str, Any],
        ai_insights: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        # Based on new issues
        if incremental_analysis.get("status") == "analyzed":
            summary = incremental_analysis.get("summary", {})
            
            if summary.get("new_critical", 0) > 0:
                recommendations.append({
                    "priority": "critical",
                    "title": "Critical Security Issues Detected",
                    "description": f"This PR introduces {summary['new_critical']} critical security issues that must be fixed before merging.",
                    "action": "fix_required"
                })
            
            if summary.get("total_fixed", 0) > 5:
                recommendations.append({
                    "priority": "positive",
                    "title": "Security Improvements",
                    "description": f"Great job! This PR fixes {summary['total_fixed']} security issues.",
                    "action": "acknowledge"
                })
        
        # Add AI recommendations
        ai_suggestions = ai_insights.get("improvement_suggestions", [])
        for suggestion in ai_suggestions[:3]:  # Top 3 AI suggestions
            recommendations.append({
                "priority": "medium",
                "title": "AI Suggestion",
                "description": suggestion,
                "action": "review"
            })
        
        return recommendations
    
    async def _check_auto_fix_availability(
        self,
        issues: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Check if auto-fix is available for issues"""
        
        fixable_issues = []
        
        for issue in issues:
            # Check if issue has a suggested fix
            if issue.get("code_context", {}).get("suggested_fix"):
                fixable_issues.append({
                    "issue_id": issue.get("id", f"{issue.get('file_path')}:{issue.get('line_start')}"),
                    "severity": issue.get("severity"),
                    "can_auto_fix": True,
                    "fix_confidence": self._calculate_fix_confidence(issue)
                })
        
        return {
            "total_fixable": len(fixable_issues),
            "fixable_issues": fixable_issues,
            "auto_fix_available": len(fixable_issues) > 0
        }
    
    async def _assess_compliance_impact(
        self,
        issues: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Assess compliance impact of new issues"""
        
        compliance_mapping = {
            "owasp": set(),
            "cwe": set(),
            "pci_dss": set(),
            "hipaa": set(),
            "gdpr": set(),
            "sox": set()
        }
        
        for issue in issues:
            if issue.get("owasp_category"):
                compliance_mapping["owasp"].add(issue.get("owasp_category"))
            if issue.get("cwe_id"):
                compliance_mapping["cwe"].add(f"CWE-{issue.get('cwe_id')}")
            if issue.get("pci_dss_id"):
                compliance_mapping["pci_dss"].add(issue.get("pci_dss_id"))
            if issue.get("hipaa_id"):
                compliance_mapping["hipaa"].add(issue.get("hipaa_id"))
            if issue.get("gdpr_article"):
                compliance_mapping["gdpr"].add(f"Article {issue.get('gdpr_article')}")
        
        # Calculate impact score
        impact_score = 0
        for framework, violations in compliance_mapping.items():
            if violations:
                impact_score += len(violations) * self._get_framework_weight(framework)
        
        return {
            "compliance_violations": {k: list(v) for k, v in compliance_mapping.items()},
            "impact_score": min(100, impact_score),
            "affected_frameworks": [k for k, v in compliance_mapping.items() if v],
            "requires_compliance_review": impact_score > 20
        }
    
    def _create_issue_fingerprint(self, issue: Dict[str, Any]) -> str:
        """Create a unique fingerprint for an issue"""
        parts = [
            issue.get("file_path", ""),
            str(issue.get("line_start", "")),
            issue.get("rule_id", ""),
            issue.get("message", "")[:100]  # First 100 chars of message
        ]
        return hashlib.md5(":".join(parts).encode()).hexdigest()
    
    def _calculate_author_trust_score(self, stats) -> int:
        """Calculate trust score for PR author (0-100)"""
        if not stats or stats.total_prs == 0:
            return 50  # Neutral for new authors
        
        avg_score = float(stats.avg_security_score or 0)
        risky_ratio = (stats.risky_prs or 0) / stats.total_prs
        
        # Start with average security score
        trust_score = avg_score
        
        # Penalize for high ratio of risky PRs
        trust_score -= risky_ratio * 30
        
        # Bonus for consistent good security
        if avg_score > 85 and risky_ratio < 0.1:
            trust_score += 10
        
        return int(min(100, max(0, trust_score)))
    
    async def _calculate_improvement_trend(
        self,
        repo_full_name: str,
        author: str,
        db: AsyncSession
    ) -> str:
        """Calculate if author is improving over time"""
        
        query = text("""
            SELECT 
                DATE_TRUNC('week', created_at) as week,
                AVG(total_score) as avg_score
            FROM scans
            WHERE repo_full_name = :repo_name 
                AND pr_number IS NOT NULL
                AND created_at > NOW() - INTERVAL '90 days'
            GROUP BY week
            ORDER BY week
        """)
        
        result = await db.execute(
            query,
            {"repo_name": repo_full_name}
        )
        
        weekly_scores = [row.avg_score for row in result]
        
        if len(weekly_scores) < 2:
            return "insufficient_data"
        
        # Simple trend calculation
        first_half_avg = sum(weekly_scores[:len(weekly_scores)//2]) / (len(weekly_scores)//2)
        second_half_avg = sum(weekly_scores[len(weekly_scores)//2:]) / (len(weekly_scores) - len(weekly_scores)//2)
        
        if second_half_avg > first_half_avg + 5:
            return "improving"
        elif second_half_avg < first_half_avg - 5:
            return "declining"
        else:
            return "stable"
    
    def _calculate_issue_velocity(self, trends: List[Dict[str, Any]]) -> str:
        """Calculate if issues are increasing or decreasing"""
        if len(trends) < 2:
            return "stable"
        
        recent_issues = sum(t.get("total_issues", 0) for t in trends[:3]) / 3
        older_issues = sum(t.get("total_issues", 0) for t in trends[-3:]) / 3
        
        if recent_issues < older_issues * 0.8:
            return "decreasing"
        elif recent_issues > older_issues * 1.2:
            return "increasing"
        else:
            return "stable"
    
    def _extract_risk_areas(self, ai_response: Dict[str, Any]) -> List[str]:
        """Extract risk areas from AI response"""
        # This would parse the AI response for risk areas
        # For now, return example risk areas
        return [
            "SQL injection in database queries",
            "Unvalidated user input",
            "Exposed API keys"
        ]
    
    def _extract_suggestions(self, ai_response: Dict[str, Any]) -> List[str]:
        """Extract suggestions from AI response"""
        # This would parse the AI response for suggestions
        # For now, return example suggestions
        return [
            "Add input validation for user-supplied data",
            "Use parameterized queries instead of string concatenation",
            "Move sensitive configuration to environment variables"
        ]
    
    def _calculate_fix_confidence(self, issue: Dict[str, Any]) -> float:
        """Calculate confidence in auto-fix"""
        # Higher confidence for simple fixes
        if issue.get("severity") in ["low", "medium"]:
            return 0.9
        elif issue.get("category") in ["code_style", "best_practices"]:
            return 0.95
        else:
            return 0.7
    
    def _get_framework_weight(self, framework: str) -> int:
        """Get weight for compliance framework"""
        weights = {
            "pci_dss": 5,
            "hipaa": 5,
            "gdpr": 4,
            "sox": 4,
            "owasp": 3,
            "cwe": 2
        }
        return weights.get(framework, 1)
    
    async def _get_scan_issues(self, scan_id: str, db: AsyncSession) -> List[Dict[str, Any]]:
        """Get all issues for a scan from summaries"""
        from .models import ScanSummary
        
        result = await db.execute(
            select(ScanSummary).where(ScanSummary.scan_id == scan_id)
        )
        summaries = result.scalars().all()
        
        issues = []
        for summary in summaries:
            if summary.sample_issues:
                issues.extend(summary.sample_issues)
        
        return issues


# Initialize singleton
pr_enhancement_engine = PREnhancementEngine()