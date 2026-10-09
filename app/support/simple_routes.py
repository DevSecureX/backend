from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, text
from typing import List, Optional
from datetime import datetime
import logging

from core.database import get_db
from auth.dependencies import get_current_user
from auth.models import User
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/support", tags=["support"])

# Simple Pydantic models
class SupportQueryCreate(BaseModel):
    subject: str
    category: str = "general"
    priority: str = "medium"
    message: str

class SupportQueryOut(BaseModel):
    id: int
    subject: str
    category: str
    priority: str
    message: str
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

@router.get("/queries", response_model=List[dict])
async def get_user_support_queries(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's support queries with simple SQL"""
    try:
        query = text("""
            SELECT id, subject, category, priority, message, status, created_at
            FROM support_queries 
            WHERE user_id = :user_id 
            ORDER BY created_at DESC 
            LIMIT 50
        """)
        
        result = await db.execute(query, {"user_id": current_user.id})
        queries = result.fetchall()
        
        # Convert to list of dicts
        query_list = []
        for row in queries:
            query_list.append({
                "id": row[0],
                "subject": row[1],
                "category": row[2],
                "priority": row[3],
                "message": row[4],
                "status": row[5],
                "created_at": row[6].isoformat() if row[6] else None
            })
        
        return query_list
        
    except Exception as e:
        logger.error(f"Error fetching support queries: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch support queries")

@router.post("/queries", response_model=dict)
async def create_support_query(
    query_data: SupportQueryCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new support query with simple SQL"""
    try:
        query = text("""
            INSERT INTO support_queries (user_id, subject, category, priority, message, status, created_at)
            VALUES (:user_id, :subject, :category, :priority, :message, 'open', NOW())
            RETURNING id, subject, category, priority, message, status, created_at
        """)
        
        result = await db.execute(query, {
            "user_id": current_user.id,
            "subject": query_data.subject.strip(),
            "category": query_data.category,
            "priority": query_data.priority,
            "message": query_data.message.strip()
        })
        
        await db.commit()
        row = result.fetchone()
        
        if row:
            return {
                "id": row[0],
                "subject": row[1],
                "category": row[2],
                "priority": row[3],
                "message": row[4],
                "status": row[5],
                "created_at": row[6].isoformat() if row[6] else None
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create support query")
        
    except Exception as e:
        logger.error(f"Error creating support query: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create support query")

@router.get("/test")
async def test_support_endpoint():
    """Test endpoint without authentication"""
    return {"status": "support module is working", "timestamp": datetime.now().isoformat()}

