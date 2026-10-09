"""
Rule Collaboration Service
Handles community collaboration features for custom security rules
"""

import uuid
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func, desc, case
from fastapi import HTTPException, status

from ..models import CommunityRules, CommunityRuleVotes
from scans.models import RuleComments, RuleCollections, RuleCollectionItems, RuleFeedback
from .rules_service import CustomRulesService

import logging
logger = logging.getLogger(__name__)


class RuleCollaborationService:
    """Service for managing rule collaboration and community features"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.base_service = CustomRulesService(db)
    
    async def create_rule_collection(
        self,
        user_id: int,
        collection_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a new rule collection"""
        
        collection = RuleCollections(
            id=str(uuid.uuid4()),
            name=collection_data['name'],
            description=collection_data.get('description', ''),
            user_id=user_id,
            is_public=collection_data.get('is_public', False)
        )
        
        self.db.add(collection)
        await self.db.commit()
        await self.db.refresh(collection)
        
        logger.info(f"User {user_id} created rule collection {collection.id}")
        
        return {
            'id': collection.id,
            'name': collection.name,
            'description': collection.description,
            'user_id': collection.user_id,
            'is_public': collection.is_public,
            'created_at': collection.created_at.isoformat()
        }
    
    async def add_rule_to_collection(
        self,
        collection_id: str,
        rule_id: str,
        user_id: int,
        order_index: Optional[int] = None
    ) -> Dict[str, Any]:
        """Add a rule to a collection"""
        
        # Verify collection ownership
        collection_query = select(RuleCollections).where(RuleCollections.id == collection_id)
        collection_result = await self.db.execute(collection_query)
        collection = collection_result.scalar_one_or_none()
        
        if not collection:
            raise HTTPException(status_code=404, detail="Collection not found")
        
        if collection.user_id != user_id:
            raise HTTPException(status_code=403, detail="Only collection owner can add rules")
        
        # Verify rule exists and is accessible
        await self.base_service.get_rule_by_id(rule_id, user_id)
        
        # Check if rule already in collection
        existing_query = select(RuleCollectionItems).where(
            and_(
                RuleCollectionItems.collection_id == collection_id,
                RuleCollectionItems.rule_id == rule_id
            )
        )
        existing_result = await self.db.execute(existing_query)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Rule already in collection")
        
        # Add rule to collection
        collection_item = RuleCollectionItems(
            id=str(uuid.uuid4()),
            collection_id=collection_id,
            rule_id=rule_id
        )
        
        self.db.add(collection_item)
        await self.db.commit()
        
        return {
            'collection_id': collection_id,
            'rule_id': rule_id,
            'added_at': collection_item.added_at.isoformat()
        }
    
    async def create_rule_comment(
        self,
        rule_id: str,
        user_id: int,
        comment_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a comment or discussion on a rule"""
        
        # Verify rule exists and is accessible
        rule = await self.base_service.get_rule_by_id(rule_id, user_id)
        
        # Only allow comments on public rules or own rules
        if not rule['is_public'] and rule['author_id'] != user_id:
            raise HTTPException(status_code=403, detail="Cannot comment on private rules")
        
        comment = RuleComments(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            parent_comment_id=comment_data.get('parent_comment_id'),
            user_id=user_id,
            comment=comment_data['content']
        )
        
        self.db.add(comment)
        await self.db.commit()
        await self.db.refresh(comment)
        
        logger.info(f"User {user_id} commented on rule {rule_id}")
        
        return {
            'id': comment.id,
            'rule_id': rule_id,
            'parent_comment_id': comment.parent_comment_id,
            'user_id': user_id,
            'content': comment.comment,
            'created_at': comment.created_at.isoformat()
        }
    
    async def get_rule_comments(
        self,
        rule_id: str,
        user_id: Optional[int] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get comments for a rule"""
        
        # Verify access to rule
        await self.base_service.get_rule_by_id(rule_id, user_id)
        
        query = (
            select(RuleComments)
            .where(RuleComments.rule_id == rule_id)
            .order_by(desc(RuleComments.created_at))
            .limit(limit)
        )
        
        result = await self.db.execute(query)
        comments = result.scalars().all()
        
        comment_list = []
        for comment in comments:
            comment_list.append({
                'id': comment.id,
                'parent_comment_id': comment.parent_comment_id,
                'user_id': comment.user_id,
                'content': comment.comment,
                'created_at': comment.created_at.isoformat(),
                'updated_at': comment.updated_at.isoformat()
            })
        
        return comment_list
    
    async def submit_rule_feedback(
        self,
        rule_id: str,
        user_id: int,
        scan_id: str,
        feedback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Submit feedback on rule effectiveness"""
        
        # Verify rule exists
        await self.base_service.get_rule_by_id(rule_id, user_id)
        
        # Check if user already provided this type of feedback
        existing_query = select(RuleFeedback).where(
            and_(
                RuleFeedback.rule_id == rule_id,
                RuleFeedback.user_id == user_id,
                RuleFeedback.feedback_type == feedback_data['feedback_type']
            )
        )
        existing_result = await self.db.execute(existing_query)
        if existing_result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Feedback already provided for this type")
        
        feedback = RuleFeedback(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            user_id=user_id,
            feedback_type=feedback_data['feedback_type'],
            rating=feedback_data.get('rating'),
            comment=feedback_data.get('comment')
        )
        
        self.db.add(feedback)
        await self.db.commit()
        
        # Update rule effectiveness metrics
        await self._update_rule_effectiveness_metrics(rule_id)
        
        logger.info(f"User {user_id} provided feedback on rule {rule_id}")
        
        return {
            'feedback_id': feedback.id,
            'rule_id': rule_id,
            'feedback_type': feedback.feedback_type,
            'rating': feedback.rating,
            'created_at': feedback.created_at.isoformat()
        }
    
    async def get_community_leaderboard(
        self,
        timeframe: str = '30d',  # 7d, 30d, 90d, all
        category: str = 'all',
        limit: int = 20
    ) -> Dict[str, Any]:
        """Get community leaderboard based on contributions"""
        
        # Calculate date range
        now = datetime.now(timezone.utc)
        if timeframe == '7d':
            start_date = now - timedelta(days=7)
        elif timeframe == '30d':
            start_date = now - timedelta(days=30)
        elif timeframe == '90d':
            start_date = now - timedelta(days=90)
        else:  # all
            start_date = datetime.min.replace(tzinfo=timezone.utc)
        
        # Build base query
        query = (
            select(
                CommunityRules.author_id,
                func.count(CommunityRules.id).label('rule_count'),
                func.sum(CommunityRules.upvotes).label('total_upvotes'),
                func.sum(CommunityRules.usage_count).label('total_usage')
            )
            .where(
                and_(
                    CommunityRules.is_public == True,
                    CommunityRules.created_at >= start_date
                )
            )
            .group_by(CommunityRules.author_id)
        )
        
        query = query.order_by(desc('total_upvotes')).limit(limit)
        
        result = await self.db.execute(query)
        leaderboard_data = result.all()
        
        leaderboard = []
        for rank, row in enumerate(leaderboard_data, 1):
            # Calculate contribution score
            contribution_score = (
                (row.total_upvotes or 0) * 2 +
                (row.total_usage or 0) * 0.1 +
                (row.rule_count or 0) * 5
            )
            
            leaderboard.append({
                'rank': rank,
                'author_id': row.author_id,
                'rule_count': row.rule_count or 0,
                'total_upvotes': row.total_upvotes or 0,
                'total_usage': row.total_usage or 0,
                'contribution_score': round(contribution_score, 2)
            })
        
        return {
            'leaderboard': leaderboard,
            'timeframe': timeframe,
            'category': category,
            'generated_at': now.isoformat()
        }
    
    async def get_trending_rules(
        self,
        timeframe: str = '7d',
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get trending rules based on recent activity"""
        
        # Calculate date range
        now = datetime.now(timezone.utc)
        if timeframe == '7d':
            start_date = now - timedelta(days=7)
        elif timeframe == '30d':
            start_date = now - timedelta(days=30)
        else:
            start_date = now - timedelta(days=7)  # Default to 7 days
        
        # Query for rules with recent activity
        query = (
            select(CommunityRules)
            .where(
                and_(
                    CommunityRules.is_public == True,
                    CommunityRules.updated_at >= start_date
                )
            )
            .order_by(
                desc(CommunityRules.upvotes),
                desc(CommunityRules.usage_count),
                desc(CommunityRules.updated_at)
            )
            .limit(limit)
        )
        
        result = await self.db.execute(query)
        trending_rules = result.scalars().all()
        
        trending_list = []
        for rule in trending_rules:
            # Calculate trending score
            days_since_update = (now - rule.updated_at).days + 1
            trending_score = (
                (rule.upvotes * 2) +
                (rule.usage_count * 0.5) +
                (100 / days_since_update)  # Recency bonus
            )
            
            trending_list.append({
                'id': rule.id,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language,
                'description': rule.description,
                'author_id': rule.author_id,
                'upvotes': rule.upvotes,
                'usage_count': rule.usage_count,
                'trending_score': round(trending_score, 2),
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat()
            })
        
        # Sort by trending score
        trending_list.sort(key=lambda x: x['trending_score'], reverse=True)
        
        return trending_list
    
    async def get_rule_recommendations_for_user(
        self,
        user_id: int,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get personalized rule recommendations for a user"""
        
        # Get user's rule preferences (tools, languages they use)
        user_preferences_query = (
            select(
                CommunityRules.tool,
                CommunityRules.language,
                func.count().label('count')
            )
            .where(CommunityRules.author_id == user_id)
            .group_by(CommunityRules.tool, CommunityRules.language)
            .order_by(desc('count'))
        )
        
        preferences_result = await self.db.execute(user_preferences_query)
        user_preferences = preferences_result.all()
        
        if not user_preferences:
            # If no preferences, return top-rated public rules
            return await self._get_top_rated_rules(limit)
        
        # Get rules matching user preferences that they haven't created
        preferred_tools = [pref.tool for pref in user_preferences[:3]]  # Top 3 tools
        preferred_languages = [pref.language for pref in user_preferences[:3] if pref.language]
        
        query = (
            select(CommunityRules)
            .where(
                and_(
                    CommunityRules.is_public == True,
                    CommunityRules.author_id != user_id,
                    or_(
                        CommunityRules.tool.in_(preferred_tools),
                        CommunityRules.language.in_(preferred_languages) if preferred_languages else False
                    )
                )
            )
            .order_by(
                desc(CommunityRules.upvotes)
            )
            .limit(limit)
        )
        
        result = await self.db.execute(query)
        recommendations = result.scalars().all()
        
        recommendation_list = []
        for rule in recommendations:
            recommendation_list.append({
                'id': rule.id,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language,
                'description': rule.description,
                'author_id': rule.author_id,
                'upvotes': rule.upvotes,
                'usage_count': rule.usage_count,
                'recommendation_reason': self._get_recommendation_reason(rule, preferred_tools, preferred_languages)
            })
        
        return recommendation_list
    
    async def create_rule_improvement_proposal(
        self,
        rule_id: str,
        user_id: int,
        proposal_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create an improvement proposal for a rule"""
        
        # Verify rule exists
        rule = await self.base_service.get_rule_by_id(rule_id, user_id)
        
        if not rule['is_public']:
            raise HTTPException(status_code=403, detail="Can only propose improvements to public rules")
        
        # Create improvement proposal as a special comment
        proposal_content = {
            'type': 'improvement_proposal',
            'title': proposal_data['title'],
            'description': proposal_data['description'],
            'proposed_changes': proposal_data.get('proposed_changes', {}),
            'expected_benefits': proposal_data.get('expected_benefits', []),
            'test_cases': proposal_data.get('test_cases', [])
        }
        
        proposal = RuleComments(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            user_id=user_id,
            comment=json.dumps(proposal_content)
        )
        
        self.db.add(proposal)
        await self.db.commit()
        await self.db.refresh(proposal)
        
        logger.info(f"User {user_id} created improvement proposal for rule {rule_id}")
        
        return {
            'proposal_id': proposal.id,
            'rule_id': rule_id,
            'title': proposal_data['title'],
            'description': proposal_data['description'],
            'status': 'pending_review',
            'created_at': proposal.created_at.isoformat()
        }
    
    # Private helper methods
    
    async def _update_rule_effectiveness_metrics(self, rule_id: str) -> None:
        """Update effectiveness metrics for a rule based on feedback"""
        
        # Calculate feedback-based metrics
        feedback_query = (
            select(
                func.count().label('total_feedback'),
                func.count().filter(RuleFeedback.feedback_type == 'false_positive').label('false_positives'),
                func.count().filter(RuleFeedback.feedback_type == 'true_positive').label('true_positives'),
                func.avg(RuleFeedback.rating).label('avg_rating')
            )
            .where(RuleFeedback.rule_id == rule_id)
        )
        
        feedback_result = await self.db.execute(feedback_query)
        metrics = feedback_result.first()
        
        if metrics and metrics.total_feedback > 0:
            false_positive_rate = metrics.false_positives / metrics.total_feedback
            effectiveness_score = (
                ((metrics.true_positives / metrics.total_feedback) * 0.6) +
                ((1 - false_positive_rate) * 0.3) +
                ((metrics.avg_rating or 0) / 5.0 * 0.1)
            ) * 100
            
            # Update rule with calculated metrics
            await self.db.execute(
                update(CommunityRules)
                .where(CommunityRules.id == rule_id)
                .values(
                    false_positive_rate=false_positive_rate,
                    effectiveness_score=effectiveness_score
                )
            )
            await self.db.commit()
    
    async def _get_top_rated_rules(self, limit: int) -> List[Dict[str, Any]]:
        """Get top-rated public rules as fallback recommendations"""
        
        query = (
            select(CommunityRules)
            .where(
                and_(
                    CommunityRules.is_public == True
                )
            )
            .order_by(
                desc(CommunityRules.upvotes)
            )
            .limit(limit)
        )
        
        result = await self.db.execute(query)
        rules = result.scalars().all()
        
        rule_list = []
        for rule in rules:
            rule_list.append({
                'id': rule.id,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language,
                'description': rule.description,
                'author_id': rule.author_id,
                'upvotes': rule.upvotes,
                'usage_count': rule.usage_count,
                'recommendation_reason': 'Top rated community rule'
            })
        
        return rule_list
    
    def _get_recommendation_reason(self, rule, preferred_tools: List[str], preferred_languages: List[str]) -> str:
        """Get reason why this rule is recommended"""
        
        reasons = []
        
        if rule.tool in preferred_tools:
            reasons.append(f"matches your {rule.tool} usage")
        
        if rule.language and rule.language in preferred_languages:
            reasons.append(f"targets {rule.language} which you use")
        
        if rule.upvotes > 10:
            reasons.append("popular in community")
        
        return "; ".join(reasons) if reasons else "recommended for you"