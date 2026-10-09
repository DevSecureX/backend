"""
Custom Rules Dependencies

Dependency injection setup for custom rules functionality.
Provides common dependencies and configurations for the rules system.
"""

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from core.database import get_db
from auth.dependencies import get_current_user
from auth.models import User
from .services.rules_service import CustomRulesService
from .config.rules_config import RulesConfig


async def get_rules_service(
    db: AsyncSession = Depends(get_db)
) -> CustomRulesService:
    """Get the rules service instance"""
    return CustomRulesService(db)


async def get_rules_config() -> RulesConfig:
    """Get the rules configuration"""
    return RulesConfig


async def validate_rule_author(
    rule_id: str,
    current_user: User = Depends(get_current_user),
    rules_service: CustomRulesService = Depends(get_rules_service)
):
    """Validate that the current user is the author of the rule"""
    try:
        rule = await rules_service.get_rule_by_id(rule_id, current_user.id)
        if rule['author_id'] != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only modify your own rules"
            )
        return rule
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )


async def validate_rule_access(
    rule_id: str,
    current_user: Optional[User] = Depends(get_current_user),
    rules_service: CustomRulesService = Depends(get_rules_service)
):
    """Validate that the user can access the rule (public rules or own rules)"""
    try:
        user_id = current_user.id if current_user else None
        rule = await rules_service.get_rule_by_id(rule_id, user_id)
        
        # Public rules can be accessed by anyone
        if rule['is_public']:
            return rule
            
        # Private rules can only be accessed by the author
        if current_user and rule['author_id'] == current_user.id:
            return rule
            
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to access this rule"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found"
        )


def get_supported_tools() -> dict:
    """Get supported tools for custom rules"""
    return RulesConfig.get_tools_supporting_custom_rules()


def get_tool_config(tool: str) -> dict:
    """Get configuration for a specific tool"""
    config = RulesConfig.get_tool_custom_rule_config(tool)
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool}' is not supported"
        )
    return config