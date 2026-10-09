"""
Simplified FastAPI routes for AI assistant
Essential HTTP endpoints for chat management
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from core.database import get_db
from auth.dependencies import get_current_user
from auth.models import User
from .chat_manager import chat_manager

# Pydantic models for request/response
class CreateSessionRequest(BaseModel):
    session_type: str = "general"
    title: Optional[str] = None

class SessionResponse(BaseModel):
    session_id: str
    title: Optional[str]
    session_type: str
    created_at: str
    message_count: int

class MessageResponse(BaseModel):
    message_id: str
    role: str
    content: str
    message_type: str
    timestamp: str
    msg_meta: Dict[str, Any]

# Create router
ai_router = APIRouter(prefix="/ai-assistant", tags=["AI Assistant"])

@ai_router.post("/sessions", response_model=SessionResponse)
async def create_chat_session(
    request: CreateSessionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new chat session"""
    try:
        session_data = await chat_manager.create_chat_session(
            user_id=current_user.id,
            session_type=request.session_type,
            title=request.title,
            db=db
        )
        return SessionResponse(**session_data)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create session: {str(e)}"
        )

@ai_router.get("/sessions", response_model=List[SessionResponse])
async def get_chat_sessions(
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's chat sessions"""
    try:
        sessions = await chat_manager.get_user_chat_sessions(
            user_id=current_user.id,
            limit=limit,
            db=db
        )
        return [SessionResponse(**session) for session in sessions]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get sessions: {str(e)}"
        )

@ai_router.get("/sessions/{session_id}", response_model=Dict[str, Any])
async def get_chat_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get chat session details with message history"""
    try:
        # Get session details
        session_data = await chat_manager.get_chat_session(
            session_id=session_id,
            user_id=current_user.id,
            db=db
        )
        
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        # Get message history
        history = await chat_manager.get_chat_history(
            session_id=session_id,
            user_id=current_user.id,
            db=db
        )
        
        return {
            "session": session_data,
            "messages": history
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get session: {str(e)}"
        )

@ai_router.get("/sessions/{session_id}/messages", response_model=List[MessageResponse])
async def get_session_messages(
    session_id: str,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get messages from chat session"""
    try:
        # Verify session exists
        session_data = await chat_manager.get_chat_session(
            session_id=session_id,
            user_id=current_user.id,
            db=db
        )
        
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        # Get message history
        messages = await chat_manager.get_chat_history(
            session_id=session_id,
            user_id=current_user.id,
            limit=limit,
            db=db
        )
        
        return [MessageResponse(**msg) for msg in messages]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get messages: {str(e)}"
        )

@ai_router.delete("/sessions/{session_id}")
async def delete_chat_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete (deactivate) chat session"""
    try:
        success = await chat_manager.deactivate_session(
            session_id=session_id,
            user_id=current_user.id,
            db=db
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        return {"message": "Session deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete session: {str(e)}"
        )

@ai_router.post("/sessions/cleanup")
async def cleanup_empty_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Clean up empty sessions (no messages) for current user"""
    try:
        from sqlalchemy import select, update, func
        from .models import ChatSession, ChatMessage
        
        # Find sessions with no messages
        empty_sessions_query = select(ChatSession.id).where(
            ChatSession.user_id == current_user.id,
            ChatSession.is_active == True
        ).outerjoin(ChatMessage, ChatSession.id == ChatMessage.session_id).group_by(
            ChatSession.id
        ).having(func.count(ChatMessage.id) == 0)
        
        result = await db.execute(empty_sessions_query)
        empty_session_ids = [row[0] for row in result.all()]
        
        if empty_session_ids:
            # Deactivate empty sessions
            await db.execute(
                update(ChatSession)
                .where(ChatSession.id.in_(empty_session_ids))
                .values(is_active=False)
            )
            await db.commit()
            
            return {
                "message": f"Cleaned up {len(empty_session_ids)} empty sessions",
                "cleaned_sessions": len(empty_session_ids)
            }
        else:
            return {"message": "No empty sessions found", "cleaned_sessions": 0}
            
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cleanup sessions: {str(e)}"
        )

@ai_router.get("/health")
async def ai_health_check():
    """Health check for AI assistant service"""
    try:
        from datetime import datetime
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "ai-assistant",
            "version": "1.0.0",
            "features": ["socket_chat", "session_management", "real_time_responses"]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )