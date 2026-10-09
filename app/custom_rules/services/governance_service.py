"""
Rule Governance Service
Handles rule approval workflows, quality control, and administrative features
"""

import uuid
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func, desc, case
from fastapi import HTTPException, status

from ..models import CommunityRules
from scans.models import RuleComments, RuleFeedback
from .rules_service import CustomRulesService

import logging
logger = logging.getLogger(__name__)


class RuleGovernanceService:
    """Service for rule governance, approval workflows, and quality control"""
    
    # Quality thresholds for automatic approval
    QUALITY_THRESHOLDS = {
        'auto_approve': {
            'min_effectiveness_score': 80.0,
            'max_false_positive_rate': 0.1,
            'min_test_success_rate': 0.9,
            'min_upvotes': 5,
            'max_downvotes': 1
        },
        'review_required': {
            'min_effectiveness_score': 60.0,
            'max_false_positive_rate': 0.3,
            'min_test_success_rate': 0.7
        },
        'auto_reject': {
            'max_effectiveness_score': 40.0,
            'min_false_positive_rate': 0.5,
            'max_test_success_rate': 0.5,
            'min_downvotes': 10
        }
    }
    
    # Approval workflow states
    APPROVAL_STATES = {
        'pending': 'Pending Review',
        'under_review': 'Under Review',
        'approved': 'Approved',
        'rejected': 'Rejected',
        'needs_changes': 'Needs Changes',
        'auto_approved': 'Automatically Approved'
    }
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.base_service = CustomRulesService(db)
    
    async def submit_rule_for_approval(
        self,
        rule_id: str,
        user_id: int,
        submission_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Submit a rule for community approval"""
        
        # Get rule and verify ownership
        rule = await self.base_service.get_rule_by_id(rule_id, user_id)
        if rule['author_id'] != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Can only submit your own rules for approval"
            )
        
        # Check if rule is already public
        if rule['is_public']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Rule is already public"
            )
        
        # Check if already pending approval
        existing_submission = await self._get_pending_submission(rule_id)
        if existing_submission:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Rule is already pending approval"
            )
        
        # Evaluate rule quality
        quality_assessment = await self._assess_rule_quality(rule_id)
        
        # Determine approval path
        approval_decision = self._determine_approval_path(quality_assessment)
        
        if approval_decision['action'] == 'auto_approve':
            # Automatically approve high-quality rules
            await self._auto_approve_rule(rule_id, quality_assessment)
            return {
                'rule_id': rule_id,
                'status': 'auto_approved',
                'decision': approval_decision,
                'quality_assessment': quality_assessment
            }
        
        elif approval_decision['action'] == 'auto_reject':
            # Automatically reject low-quality rules
            await self._auto_reject_rule(rule_id, quality_assessment, approval_decision['reasons'])
            return {
                'rule_id': rule_id,
                'status': 'auto_rejected',
                'decision': approval_decision,
                'quality_assessment': quality_assessment
            }
        
        else:
            # Queue for manual review
            submission_record = await self._create_approval_submission(
                rule_id, user_id, quality_assessment, submission_notes
            )
            
            return {
                'rule_id': rule_id,
                'status': 'pending_review',
                'submission_id': submission_record['id'],
                'estimated_review_time': '2-5 business days',
                'quality_assessment': quality_assessment
            }
    
    async def review_rule_submission(
        self,
        submission_id: str,
        reviewer_id: int,
        review_decision: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Review a rule submission (admin/moderator function)"""
        
        # This would typically check if reviewer has admin/moderator privileges
        # For now, we'll assume proper authorization is handled at the API level
        
        submission = await self._get_submission_by_id(submission_id)
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        
        decision = review_decision.get('decision')  # 'approve', 'reject', 'needs_changes'
        reviewer_notes = review_decision.get('notes', '')
        required_changes = review_decision.get('required_changes', [])
        
        if decision == 'approve':
            await self._approve_rule_submission(submission, reviewer_id, reviewer_notes)
            status = 'approved'
        elif decision == 'reject':
            await self._reject_rule_submission(submission, reviewer_id, reviewer_notes)
            status = 'rejected'
        elif decision == 'needs_changes':
            await self._request_changes(submission, reviewer_id, reviewer_notes, required_changes)
            status = 'needs_changes'
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid review decision"
            )
        
        return {
            'submission_id': submission_id,
            'rule_id': submission['rule_id'],
            'decision': decision,
            'status': status,
            'reviewed_by': reviewer_id,
            'reviewer_notes': reviewer_notes,
            'reviewed_at': datetime.now(timezone.utc).isoformat()
        }
    
    async def get_pending_submissions(
        self,
        limit: int = 50,
        priority_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get pending rule submissions for review"""
        
        # This would query a submissions table (which we'd need to create)
        # For now, return a placeholder structure
        
        return [
            {
                'submission_id': str(uuid.uuid4()),
                'rule_id': str(uuid.uuid4()),
                'rule_name': 'Example Rule',
                'author_id': 123,
                'submitted_at': (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                'priority': 'medium',
                'quality_score': 75.5,
                'estimated_review_time': '1-2 days',
                'submission_notes': 'Please review for community use'
            }
        ]
    
    async def get_rule_quality_metrics(
        self,
        rule_id: str,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get comprehensive quality metrics for a rule"""
        
        rule = await self.base_service.get_rule_by_id(rule_id, user_id)
        quality_assessment = await self._assess_rule_quality(rule_id)
        
        return {
            'rule_id': rule_id,
            'rule_name': rule['rule_name'],
            'quality_assessment': quality_assessment,
            'approval_eligibility': self._determine_approval_path(quality_assessment),
            'improvement_suggestions': await self._generate_quality_improvements(quality_assessment),
            'assessed_at': datetime.now(timezone.utc).isoformat()
        }
    
    async def bulk_quality_assessment(
        self,
        rule_ids: List[str],
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Perform quality assessment on multiple rules"""
        
        results = {
            'assessed': [],
            'failed': [],
            'summary': {
                'total_processed': len(rule_ids),
                'high_quality': 0,
                'medium_quality': 0,
                'low_quality': 0
            }
        }
        
        for rule_id in rule_ids:
            try:
                metrics = await self.get_rule_quality_metrics(rule_id, user_id)
                quality_score = metrics['quality_assessment']['overall_quality_score']
                
                if quality_score >= 80:
                    results['summary']['high_quality'] += 1
                elif quality_score >= 60:
                    results['summary']['medium_quality'] += 1
                else:
                    results['summary']['low_quality'] += 1
                
                results['assessed'].append({
                    'rule_id': rule_id,
                    'quality_score': quality_score,
                    'quality_tier': 'high' if quality_score >= 80 else 'medium' if quality_score >= 60 else 'low'
                })
                
            except Exception as e:
                results['failed'].append({
                    'rule_id': rule_id,
                    'error': str(e)
                })
        
        return results
    
    async def get_community_moderation_stats(
        self,
        timeframe: str = '30d'
    ) -> Dict[str, Any]:
        """Get community moderation statistics"""
        
        # Calculate date range
        now = datetime.now(timezone.utc)
        if timeframe == '7d':
            start_date = now - timedelta(days=7)
        elif timeframe == '30d':
            start_date = now - timedelta(days=30)
        elif timeframe == '90d':
            start_date = now - timedelta(days=90)
        else:
            start_date = datetime.min.replace(tzinfo=timezone.utc)
        
        # Query various moderation metrics
        total_submissions_query = select(func.count(CommunityRules.id)).where(
            and_(
                CommunityRules.created_at >= start_date,
                CommunityRules.is_public == True
            )
        )
        
        total_submissions = (await self.db.execute(total_submissions_query)).scalar() or 0
        
        return {
            'timeframe': timeframe,
            'total_submissions': total_submissions,
            'approval_metrics': {
                'auto_approved': int(total_submissions * 0.3),  # Estimated
                'manually_approved': int(total_submissions * 0.5),  # Estimated
                'rejected': int(total_submissions * 0.15),  # Estimated
                'pending': int(total_submissions * 0.05)  # Estimated
            },
            'quality_distribution': {
                'high': int(total_submissions * 0.2),
                'medium': int(total_submissions * 0.6),
                'low': int(total_submissions * 0.2)
            },
            'average_review_time_hours': 48,  # Estimated
            'generated_at': now.isoformat()
        }
    
    # Private helper methods
    
    async def _assess_rule_quality(self, rule_id: str) -> Dict[str, Any]:
        """Comprehensive quality assessment of a rule"""
        
        try:
            from .analytics_service import RuleAnalyticsService
            analytics_service = RuleAnalyticsService(self.db)
            
            # Get effectiveness score
            effectiveness_data = await analytics_service.calculate_rule_effectiveness_score(rule_id)
            effectiveness_score = effectiveness_data.get('effectiveness_score', 0)
            
            # Get performance metrics
            performance_metrics = await analytics_service.get_rule_performance_metrics(rule_id)
            
            false_positive_rate = performance_metrics['accuracy_metrics']['false_positive_rate']
            avg_execution_time = performance_metrics['performance_metrics']['avg_execution_time_ms']
            
        except Exception:
            # Fallback values if analytics fail
            effectiveness_score = 50.0
            false_positive_rate = 0.2
            avg_execution_time = 1000.0
        
        # Get rule details
        rule = await self.base_service.get_rule_by_id(rule_id)
        
        # Calculate component scores
        pattern_quality_score = self._assess_pattern_quality(rule['pattern'])
        documentation_score = self._assess_documentation_quality(
            rule.get('description', ''),
            rule.get('rule_name', '')
        )
        community_score = self._assess_community_engagement(
            rule.get('upvotes', 0),
            rule.get('downvotes', 0),
            rule.get('usage_count', 0)
        )
        
        # Technical quality score
        technical_score = (
            effectiveness_score * 0.4 +
            max(0, 100 - (false_positive_rate * 200)) * 0.3 +  # Lower FP rate = higher score
            max(0, 100 - (avg_execution_time / 50)) * 0.3  # Faster execution = higher score
        )
        
        # Overall quality score
        overall_quality_score = (
            technical_score * 0.5 +
            pattern_quality_score * 0.2 +
            documentation_score * 0.2 +
            community_score * 0.1
        )
        
        return {
            'overall_quality_score': round(overall_quality_score, 1),
            'component_scores': {
                'technical': round(technical_score, 1),
                'pattern_quality': round(pattern_quality_score, 1),
                'documentation': round(documentation_score, 1),
                'community_engagement': round(community_score, 1)
            },
            'metrics': {
                'effectiveness_score': effectiveness_score,
                'false_positive_rate': false_positive_rate,
                'avg_execution_time_ms': avg_execution_time,
                'upvotes': rule.get('upvotes', 0),
                'usage_count': rule.get('usage_count', 0)
            },
            'quality_tier': self._determine_quality_tier(overall_quality_score)
        }
    
    def _determine_approval_path(self, quality_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Determine the appropriate approval path for a rule"""
        
        overall_score = quality_assessment['overall_quality_score']
        metrics = quality_assessment['metrics']
        
        # Check for auto-approval
        auto_approve_thresholds = self.QUALITY_THRESHOLDS['auto_approve']
        if (
            overall_score >= auto_approve_thresholds['min_effectiveness_score'] and
            metrics['false_positive_rate'] <= auto_approve_thresholds['max_false_positive_rate'] and
            metrics['upvotes'] >= auto_approve_thresholds['min_upvotes']
        ):
            return {
                'action': 'auto_approve',
                'confidence': 'high',
                'reasons': ['High overall quality score', 'Low false positive rate', 'Community approval']
            }
        
        # Check for auto-rejection
        auto_reject_thresholds = self.QUALITY_THRESHOLDS['auto_reject']
        if overall_score <= auto_reject_thresholds['max_effectiveness_score']:
            return {
                'action': 'auto_reject',
                'confidence': 'high',
                'reasons': ['Very low quality score', 'Does not meet minimum standards']
            }
        
        # Manual review required
        return {
            'action': 'manual_review',
            'confidence': 'medium',
            'priority': 'high' if overall_score >= 70 else 'medium' if overall_score >= 50 else 'low',
            'reasons': ['Requires human judgment', 'Quality score within review range']
        }
    
    def _assess_pattern_quality(self, pattern: str) -> float:
        """Assess the quality of a rule pattern"""
        
        if not pattern or len(pattern.strip()) < 10:
            return 0.0
        
        score = 50.0  # Base score
        
        # Length appropriateness
        if 50 <= len(pattern) <= 2000:
            score += 20.0
        elif len(pattern) < 50 or len(pattern) > 5000:
            score -= 20.0
        
        # Pattern complexity (heuristic)
        if pattern.count('{') + pattern.count('[') > 0:
            score += 10.0  # Has structure
        
        if 'pattern:' in pattern or 'patterns:' in pattern:
            score += 15.0  # Valid Semgrep structure
        
        # Avoid overly complex patterns
        if pattern.count('*') + pattern.count('+') + pattern.count('?') > 10:
            score -= 15.0  # Too many wildcards
        
        return min(100.0, max(0.0, score))
    
    def _assess_documentation_quality(
        self,
        description: str,
        rule_name: str
    ) -> float:
        """Assess the quality of rule documentation"""
        
        score = 0.0
        
        # Rule name quality
        if rule_name and len(rule_name.strip()) >= 10:
            score += 25.0
        elif rule_name and len(rule_name.strip()) >= 5:
            score += 15.0
        
        # Description quality
        if description:
            desc_len = len(description.strip())
            if desc_len >= 100:
                score += 50.0
            elif desc_len >= 50:
                score += 35.0
            elif desc_len >= 20:
                score += 20.0
            else:
                score += 10.0
        
        # Check for key documentation elements
        desc_lower = description.lower() if description else ''
        
        if any(keyword in desc_lower for keyword in ['vulnerability', 'security', 'issue', 'problem']):
            score += 10.0  # Describes the issue
        
        if any(keyword in desc_lower for keyword in ['detect', 'find', 'identify', 'catch']):
            score += 10.0  # Explains what it does
        
        if any(keyword in desc_lower for keyword in ['example', 'such as', 'like', 'including']):
            score += 5.0  # Provides examples
        
        return min(100.0, score)
    
    def _assess_community_engagement(
        self,
        upvotes: int,
        downvotes: int,
        usage_count: int
    ) -> float:
        """Assess community engagement with the rule"""
        
        if upvotes == 0 and downvotes == 0 and usage_count == 0:
            return 50.0  # Neutral score for new rules
        
        # Calculate engagement score
        net_votes = upvotes - downvotes
        engagement_score = (
            min(net_votes * 10, 50) +  # Up to 50 points for net positive votes
            min(usage_count * 2, 40) +  # Up to 40 points for usage
            10  # Base score
        )
        
        # Penalty for high downvote ratio
        total_votes = upvotes + downvotes
        if total_votes > 0:
            downvote_ratio = downvotes / total_votes
            if downvote_ratio > 0.3:
                engagement_score -= (downvote_ratio - 0.3) * 100
        
        return min(100.0, max(0.0, engagement_score))
    
    def _determine_quality_tier(self, overall_score: float) -> str:
        """Determine quality tier based on overall score"""
        
        if overall_score >= 85:
            return 'excellent'
        elif overall_score >= 70:
            return 'good'
        elif overall_score >= 55:
            return 'fair'
        else:
            return 'poor'
    
    async def _generate_quality_improvements(
        self,
        quality_assessment: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Generate specific improvement suggestions"""
        
        suggestions = []
        component_scores = quality_assessment['component_scores']
        
        if component_scores['documentation'] < 70:
            suggestions.append({
                'category': 'documentation',
                'suggestion': 'Improve rule description with more details about the security issue',
                'priority': 'high'
            })
        
        if component_scores['pattern_quality'] < 70:
            suggestions.append({
                'category': 'pattern',
                'suggestion': 'Refine the rule pattern for better accuracy and performance',
                'priority': 'high'
            })
        
        if component_scores['technical'] < 60:
            suggestions.append({
                'category': 'technical',
                'suggestion': 'Test the rule more thoroughly to improve effectiveness',
                'priority': 'medium'
            })
        
        if component_scores['community_engagement'] < 30:
            suggestions.append({
                'category': 'community',
                'suggestion': 'Share the rule with the community for feedback and testing',
                'priority': 'low'
            })
        
        return suggestions
    
    async def _get_pending_submission(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Check if rule has a pending submission"""
        # This would query a submissions table - placeholder for now
        return None
    
    async def _create_approval_submission(
        self,
        rule_id: str,
        user_id: int,
        quality_assessment: Dict[str, Any],
        submission_notes: Optional[str]
    ) -> Dict[str, Any]:
        """Create a new approval submission record"""
        # This would create a record in a submissions table - placeholder for now
        return {
            'id': str(uuid.uuid4()),
            'rule_id': rule_id,
            'user_id': user_id,
            'status': 'pending',
            'quality_score': quality_assessment['overall_quality_score'],
            'submitted_at': datetime.now(timezone.utc).isoformat()
        }
    
    async def _auto_approve_rule(self, rule_id: str, quality_assessment: Dict[str, Any]) -> None:
        """Automatically approve a high-quality rule"""
        await self.db.execute(
            update(CommunityRules)
            .where(CommunityRules.id == rule_id)
            .values(
                is_public=True,
                is_verified=True,
                verification_notes=f"Auto-approved based on quality score: {quality_assessment['overall_quality_score']}"
            )
        )
        await self.db.commit()
    
    async def _auto_reject_rule(self, rule_id: str, quality_assessment: Dict[str, Any], reasons: List[str]) -> None:
        """Automatically reject a low-quality rule"""
        # This would create a rejection record - for now, just log
        logger.info(f"Auto-rejected rule {rule_id}: {reasons}")
    
    async def _get_submission_by_id(self, submission_id: str) -> Optional[Dict[str, Any]]:
        """Get submission by ID"""
        # Placeholder - would query submissions table
        return None
    
    async def _approve_rule_submission(self, submission: Dict, reviewer_id: int, notes: str) -> None:
        """Approve a rule submission"""
        # Placeholder implementation
        pass
    
    async def _reject_rule_submission(self, submission: Dict, reviewer_id: int, notes: str) -> None:
        """Reject a rule submission"""
        # Placeholder implementation
        pass
    
    async def _request_changes(self, submission: Dict, reviewer_id: int, notes: str, changes: List[str]) -> None:
        """Request changes to a rule submission"""
        # Placeholder implementation
        pass