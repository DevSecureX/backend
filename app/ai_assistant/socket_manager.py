"""
Socket.IO manager for real-time AI chat
Handles WebSocket connections and real-time messaging
"""

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

import socketio
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException

from core.database import get_db
from auth.models import User
from auth.dependencies import get_current_user_from_token
from .chat_manager import chat_manager
from .openai_client import security_ai_client

logger = logging.getLogger(__name__)

class AISocketManager:
    """Manages Socket.IO connections for AI chat"""
    
    def __init__(self):
        # Create Socket.IO server with CORS settings
        self.sio = socketio.AsyncServer(
            cors_allowed_origins="*",
            async_mode="asgi",
            logger=False,  # Disable socketio logging to reduce noise
            engineio_logger=False
        )
        
        # Track active connections
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Setup event handlers
        self._setup_event_handlers()
    
    def _setup_event_handlers(self):
        """Setup Socket.IO event handlers"""
        
        @self.sio.event
        async def connect(sid, environ, auth):
            """Handle client connection"""
            try:
                logger.info(f"Client {sid} attempting to connect")
                
                # Verify JWT token from auth data
                if not auth or 'token' not in auth:
                    logger.warning(f"Client {sid} missing auth token")
                    await self.sio.disconnect(sid)
                    return False
                
                # Verify token and get user
                token = auth['token']
                user = await get_current_user_from_token(token)
                
                if not user:
                    logger.warning(f"Client {sid} invalid token")
                    await self.sio.disconnect(sid)
                    return False
                
                # Store session info
                self.active_sessions[sid] = {
                    "user_id": user.id,
                    "email": user.email,
                    "connected_at": datetime.now(timezone.utc),
                    "current_session": None
                }
                
                logger.info(f"Client {sid} connected as user {user.id}")
                
                # Send connection confirmation
                await self.sio.emit('connected', {
                    'status': 'connected',
                    'user_id': user.id,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }, room=sid)
                
                return True
                
            except Exception as e:
                logger.error(f"Connection error for {sid}: {e}")
                await self.sio.disconnect(sid)
                return False
        
        @self.sio.event
        async def disconnect(sid):
            """Handle client disconnection"""
            try:
                if sid in self.active_sessions:
                    user_id = self.active_sessions[sid]["user_id"]
                    logger.info(f"Client {sid} (user {user_id}) disconnected")
                    del self.active_sessions[sid]
                else:
                    logger.info(f"Unknown client {sid} disconnected")
                    
            except Exception as e:
                logger.error(f"Disconnect error for {sid}: {e}")
        
        @self.sio.event
        async def create_session(sid, data):
            """Create new chat session"""
            try:
                if sid not in self.active_sessions:
                    await self.sio.emit('error', {'message': 'Not authenticated'}, room=sid)
                    return
                
                user_id = self.active_sessions[sid]["user_id"]
                session_type = data.get('session_type', 'general')
                title = data.get('title')
                
                # Get database session using proper async context manager
                db = None
                try:
                    async for db in get_db():
                        # Create chat session
                        session_data = await chat_manager.create_chat_session(
                            user_id=user_id,
                            session_type=session_type,
                            title=title,
                            db=db
                        )
                        
                        # Update active session
                        self.active_sessions[sid]["current_session"] = session_data["session_id"]
                        
                        # Send session created event
                        await self.sio.emit('session_created', session_data, room=sid)
                        
                        logger.info(f"Created session {session_data['session_id']} for user {user_id}")
                        break
                        
                except Exception as db_error:
                    logger.error(f"Database error in create_session: {db_error}")
                    raise db_error
                
            except Exception as e:
                logger.error(f"Session creation error: {e}")
                await self.sio.emit('error', {'message': 'Failed to create session'}, room=sid)
        
        @self.sio.event
        async def join_session(sid, data):
            """Join existing chat session"""
            try:
                if sid not in self.active_sessions:
                    await self.sio.emit('error', {'message': 'Not authenticated'}, room=sid)
                    return
                
                user_id = self.active_sessions[sid]["user_id"]
                session_id = data.get('session_id')
                
                if not session_id:
                    await self.sio.emit('error', {'message': 'Session ID required'}, room=sid)
                    return
                
                # Get database session using proper async context manager
                try:
                    async for db in get_db():
                        # Verify session belongs to user
                        session_data = await chat_manager.get_chat_session(
                            session_id=session_id,
                            user_id=user_id,
                            db=db
                        )
                        
                        if not session_data:
                            await self.sio.emit('error', {'message': 'Session not found'}, room=sid)
                            return
                        
                        # Update active session
                        self.active_sessions[sid]["current_session"] = session_id
                        
                        # Get chat history
                        history = await chat_manager.get_chat_history(
                            session_id=session_id,
                            user_id=user_id,
                            db=db
                        )
                        
                        # Send session joined event with history
                        await self.sio.emit('session_joined', {
                            'session': session_data,
                            'history': history
                        }, room=sid)
                        
                        logger.info(f"User {user_id} joined session {session_id}")
                        break
                        
                except Exception as db_error:
                    logger.error(f"Database error in join_session: {db_error}")
                    raise db_error
                
            except Exception as e:
                logger.error(f"Session join error: {e}")
                await self.sio.emit('error', {'message': 'Failed to join session'}, room=sid)
        
        @self.sio.event
        async def send_message(sid, data):
            """Handle incoming chat message"""
            try:
                if sid not in self.active_sessions:
                    await self.sio.emit('error', {'message': 'Not authenticated'}, room=sid)
                    return
                
                user_id = self.active_sessions[sid]["user_id"]
                session_id = self.active_sessions[sid].get("current_session")
                
                message = data.get('message', '').strip()
                if not message:
                    await self.sio.emit('error', {'message': 'Message cannot be empty'}, room=sid)
                    return
                
                # Get database session using proper async context manager
                try:
                    async for db in get_db():
                        # Auto-create session if none exists (lazy session creation)
                        if not session_id:
                            logger.info(f"No active session for user {user_id}, creating one for first message")
                            try:
                                # Create session with temporary title (will be updated after first message)
                                session_data = await chat_manager.create_chat_session(
                                    user_id=user_id,
                                    session_type="general",
                                    title="New Chat",  # Temporary title
                                    db=db
                                )
                                session_id = session_data["session_id"]
                                
                                # Update active session
                                self.active_sessions[sid]["current_session"] = session_id
                                
                                # Notify frontend of session creation
                                await self.sio.emit('session_created', session_data, room=sid)
                                
                                logger.info(f"Auto-created session {session_id} for user {user_id}")
                                
                            except Exception as create_error:
                                logger.error(f"Failed to auto-create session: {create_error}")
                                await self.sio.emit('error', {'message': 'Failed to create chat session'}, room=sid)
                                return
                        # Save user message
                        user_msg = await chat_manager.add_message(
                            session_id=session_id,
                            user_id=user_id,
                            role="user",
                            content=message,
                            message_type="text",
                            db=db
                        )
                        
                        # Send user message confirmation
                        await self.sio.emit('message_received', user_msg, room=sid)
                        
                        # Get conversation context (this will include the user message we just added)
                        context = await chat_manager.get_conversation_context(
                            session_id=session_id,
                            user_id=user_id,
                            db=db
                        )
                        
                        # Check if this is the first message (context should have 1 item - the user message we just added)
                        is_first_message = len(context) == 1 and context[0]["role"] == "user"
                        logger.info(f"Context length: {len(context)}, is_first_message: {is_first_message}")
                        
                        # Generate AI response with streaming
                        await self._generate_ai_response(
                            sid=sid,
                            session_id=session_id,
                            user_id=user_id,
                            user_message=message,
                            context=context,
                            is_first_message=is_first_message,
                            db=db
                        )
                        break
                        
                except Exception as db_error:
                    logger.error(f"Database error in send_message: {db_error}")
                    raise db_error
                
            except Exception as e:
                logger.error(f"Message handling error: {e}")
                await self.sio.emit('error', {'message': 'Failed to process message'}, room=sid)
        
        @self.sio.event
        async def get_sessions(sid, data):
            """Get user's chat sessions"""
            try:
                if sid not in self.active_sessions:
                    await self.sio.emit('error', {'message': 'Not authenticated'}, room=sid)
                    return
                
                user_id = self.active_sessions[sid]["user_id"]
                limit = data.get('limit', 20)
                
                # Get database session using proper async context manager
                try:
                    async for db in get_db():
                        sessions = await chat_manager.get_user_chat_sessions(
                            user_id=user_id,
                            limit=limit,
                            db=db
                        )
                        
                        await self.sio.emit('sessions_list', {'sessions': sessions}, room=sid)
                        break
                        
                except Exception as db_error:
                    logger.error(f"Database error in get_sessions: {db_error}")
                    raise db_error
                
            except Exception as e:
                logger.error(f"Sessions list error: {e}")
                await self.sio.emit('error', {'message': 'Failed to get sessions'}, room=sid)
    
    async def _generate_ai_response(
        self,
        sid: str,
        session_id: str,
        user_id: int,
        user_message: str,
        context: list,
        is_first_message: bool,
        db: AsyncSession
    ):
        """Generate streaming AI response"""
        try:
            # Prepare messages for AI
            messages = context + [{"role": "user", "content": user_message}]
            
            # Stream AI response
            ai_content = ""
            
            # Send typing indicator
            await self.sio.emit('ai_typing', {'typing': True}, room=sid)
            
            async for chunk in security_ai_client.chat_completion_stream(
                messages=messages,
                user_id=user_id,
                session_id=session_id,
                db=db
            ):
                if chunk["type"] == "chunk":
                    ai_content += chunk["content"]
                    
                    # Send streaming chunk
                    await self.sio.emit('ai_chunk', {
                        'content': chunk["content"],
                        'session_id': session_id
                    }, room=sid)
                
                elif chunk["type"] == "complete":
                    # Save AI message
                    ai_msg = await chat_manager.add_message(
                        session_id=session_id,
                        user_id=user_id,
                        role="assistant",
                        content=ai_content,
                        message_type="text",
                        msg_meta={
                            "model_used": chunk["metadata"]["model_used"],
                            "processing_time": chunk["metadata"]["processing_time"]
                        },
                        db=db
                    )
                    
                    # Send completion
                    await self.sio.emit('ai_complete', {
                        'message': ai_msg,
                        'metadata': chunk["metadata"]
                    }, room=sid)
                    
                    # Auto-generate title for first message
                    if is_first_message:  # First user message
                        logger.info(f"Generating title for first message in session {session_id}")
                        logger.info(f"User message: {user_message[:100]}...")
                        logger.info(f"AI response: {ai_content[:100]}...")
                        
                        generated_title = await chat_manager.auto_generate_title(
                            session_id=session_id,
                            user_id=user_id,
                            first_message=user_message,
                            ai_response=ai_content,
                            db=db
                        )
                        
                        if generated_title:
                            logger.info(f"Successfully generated title: '{generated_title}' for session {session_id}")
                        else:
                            logger.warning(f"Failed to generate title for session {session_id}")
                
                elif chunk["type"] == "error":
                    await self.sio.emit('ai_error', {
                        'error': chunk["error"],
                        'session_id': session_id
                    }, room=sid)
            
            # Stop typing indicator
            await self.sio.emit('ai_typing', {'typing': False}, room=sid)
            
        except Exception as e:
            logger.error(f"AI response generation error: {e}")
            await self.sio.emit('ai_error', {
                'error': 'Failed to generate response',
                'session_id': session_id
            }, room=sid)
            await self.sio.emit('ai_typing', {'typing': False}, room=sid)
    
    def get_asgi_app(self):
        """Get ASGI application for Socket.IO"""
        return socketio.ASGIApp(self.sio)
    
    async def get_active_sessions_count(self) -> int:
        """Get count of active connections"""
        return len(self.active_sessions)
    
    async def broadcast_maintenance(self, message: str):
        """Broadcast maintenance message to all connected clients"""
        await self.sio.emit('maintenance', {'message': message})

# Global instance
ai_socket_manager = AISocketManager()