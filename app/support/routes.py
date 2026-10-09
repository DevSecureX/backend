from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, and_
from typing import List, Optional
from datetime import datetime
import logging

from core.database import get_db
from auth.dependencies import get_current_user
from auth.models import User
from .models import SupportQuery, SupportResponse
from pydantic import BaseModel, validator

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/support", tags=["support"])

# Pydantic models for request/response
class SupportQueryCreate(BaseModel):
    subject: str
    category: str  # general, technical, billing, feature_request
    priority: str = "medium"  # low, medium, high, urgent
    message: str
    
    @validator('subject')
    def subject_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError('Subject cannot be empty')
        return v.strip()
    
    @validator('category')
    def validate_category(cls, v):
        allowed_categories = ['general', 'technical', 'billing', 'feature_request']
        if v not in allowed_categories:
            raise ValueError(f'Category must be one of: {", ".join(allowed_categories)}')
        return v
    
    @validator('priority')
    def validate_priority(cls, v):
        allowed_priorities = ['low', 'medium', 'high', 'urgent']
        if v not in allowed_priorities:
            raise ValueError(f'Priority must be one of: {", ".join(allowed_priorities)}')
        return v
    
    @validator('message')
    def message_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError('Message cannot be empty')
        return v.strip()

class SupportResponseCreate(BaseModel):
    message: str
    
    @validator('message')
    def message_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError('Response message cannot be empty')
        return v.strip()

class SupportResponseOut(BaseModel):
    id: int
    message: str
    is_admin_response: bool
    created_at: datetime
    responder_id: Optional[int]
    
    class Config:
        from_attributes = True

class SupportQueryOut(BaseModel):
    id: int
    subject: str
    category: str
    priority: str
    message: str
    status: str
    created_at: datetime
    updated_at: Optional[datetime]
    resolved_at: Optional[datetime]
    responses: List[SupportResponseOut] = []
    
    class Config:
        from_attributes = True

class SupportQueryUpdate(BaseModel):
    status: Optional[str] = None
    
    @validator('status')
    def validate_status(cls, v):
        if v is not None:
            allowed_statuses = ['open', 'in_progress', 'resolved', 'closed']
            if v not in allowed_statuses:
                raise ValueError(f'Status must be one of: {", ".join(allowed_statuses)}')
        return v

@router.post("/queries", response_model=SupportQueryOut)
async def create_support_query(
    query_data: SupportQueryCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new support query"""
    try:
        # Create new support query
        support_query = SupportQuery(
            user_id=current_user.id,
            subject=query_data.subject,
            category=query_data.category,
            priority=query_data.priority,
            message=query_data.message,
            status="open"
        )
        
        db.add(support_query)
        await db.commit()
        await db.refresh(support_query)
        
        logger.info(f"Support query created by user {current_user.id}: {support_query.id}")
        
        return support_query
        
    except Exception as e:
        logger.error(f"Error creating support query: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create support query")

@router.get("/queries", response_model=List[SupportQueryOut])
async def get_user_support_queries(
    status: Optional[str] = Query(None, description="Filter by status"),
    category: Optional[str] = Query(None, description="Filter by category"),
    limit: int = Query(50, le=100, description="Number of queries to return"),
    offset: int = Query(0, description="Number of queries to skip"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's support queries with optional filtering"""
    try:
        # Build query
        query = select(SupportQuery).where(SupportQuery.user_id == current_user.id)
        
        # Apply filters
        if status:
            query = query.where(SupportQuery.status == status)
        if category:
            query = query.where(SupportQuery.category == category)
        
        # Order by creation date (newest first)
        query = query.order_by(desc(SupportQuery.created_at))
        
        # Apply pagination
        query = query.offset(offset).limit(limit)
        
        result = await db.execute(query)
        support_queries = result.scalars().all()
        
        return support_queries
        
    except Exception as e:
        logger.error(f"Error fetching support queries: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch support queries")

@router.get("/queries/{query_id}", response_model=SupportQueryOut)
async def get_support_query(
    query_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific support query with all responses"""
    try:
        # Get query with responses
        query = select(SupportQuery).where(
            and_(
                SupportQuery.id == query_id,
                SupportQuery.user_id == current_user.id
            )
        )
        
        result = await db.execute(query)
        support_query = result.scalar_one_or_none()
        
        if not support_query:
            raise HTTPException(status_code=404, detail="Support query not found")
        
        return support_query
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching support query {query_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch support query")

@router.post("/queries/{query_id}/responses", response_model=SupportResponseOut)
async def add_response_to_query(
    query_id: int,
    response_data: SupportResponseCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Add a response/follow-up to an existing support query"""
    try:
        # Verify query exists and belongs to user
        query = select(SupportQuery).where(
            and_(
                SupportQuery.id == query_id,
                SupportQuery.user_id == current_user.id
            )
        )
        
        result = await db.execute(query)
        support_query = result.scalar_one_or_none()
        
        if not support_query:
            raise HTTPException(status_code=404, detail="Support query not found")
        
        # Create response
        response = SupportResponse(
            query_id=query_id,
            responder_id=current_user.id,
            message=response_data.message,
            is_admin_response=False
        )
        
        db.add(response)
        
        # Update query status if it was closed/resolved
        if support_query.status in ['resolved', 'closed']:
            support_query.status = 'open'
            support_query.resolved_at = None
        
        await db.commit()
        await db.refresh(response)
        
        logger.info(f"Response added to support query {query_id} by user {current_user.id}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding response to query {query_id}: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to add response")

@router.put("/queries/{query_id}", response_model=SupportQueryOut)
async def update_support_query(
    query_id: int,
    update_data: SupportQueryUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update a support query (mainly for changing status)"""
    try:
        # Get query
        query = select(SupportQuery).where(
            and_(
                SupportQuery.id == query_id,
                SupportQuery.user_id == current_user.id
            )
        )
        
        result = await db.execute(query)
        support_query = result.scalar_one_or_none()
        
        if not support_query:
            raise HTTPException(status_code=404, detail="Support query not found")
        
        # Update fields
        if update_data.status:
            support_query.status = update_data.status
            if update_data.status in ['resolved', 'closed']:
                support_query.resolved_at = datetime.utcnow()
            else:
                support_query.resolved_at = None
        
        await db.commit()
        await db.refresh(support_query)
        
        logger.info(f"Support query {query_id} updated by user {current_user.id}")
        
        return support_query
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating support query {query_id}: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update support query")


# Admin endpoints (for future use)
@router.get("/admin/queries", response_model=List[SupportQueryOut])
async def get_all_support_queries_admin(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    limit: int = Query(50, le=100),
    offset: int = Query(0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Admin endpoint to get all support queries"""
    # TODO: Add admin role check when role system is implemented
    # For now, this endpoint is available to all users but could be restricted
    
    try:
        query = select(SupportQuery)
        
        # Apply filters
        if status:
            query = query.where(SupportQuery.status == status)
        if priority:
            query = query.where(SupportQuery.priority == priority)
        if category:
            query = query.where(SupportQuery.category == category)
        
        # Order by priority and creation date
        query = query.order_by(
            SupportQuery.priority.desc(),
            desc(SupportQuery.created_at)
        ).offset(offset).limit(limit)
        
        result = await db.execute(query)
        support_queries = result.scalars().all()
        
        return support_queries
        
    except Exception as e:
        logger.error(f"Error fetching all support queries: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch support queries")