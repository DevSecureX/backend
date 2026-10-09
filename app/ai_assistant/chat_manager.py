"""
Chat session management for AI assistant
Handles chat sessions, message history, and context
"""

import uuid
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, update, desc
from sqlalchemy.orm import selectinload

from .models import ChatSession, ChatMessage
from .openai_client import security_ai_client
import logging

logger = logging.getLogger(__name__)

class ChatManager:
    """Manages chat sessions and messages for AI assistant"""
    
    def __init__(self):
        self.max_history_length = 10  # Keep last 10 messages for context
        self.session_timeout_hours = 24
    
    async def create_chat_session(
        self,
        user_id: int,
        session_type: str = "general",
        title: Optional[str] = None,
        db: AsyncSession = None
    ) -> Dict[str, Any]:
        """Create a new chat session with proper error handling"""
        
        try:
            session_id = str(uuid.uuid4())
            now = datetime.utcnow()
            
            # Create session with proper datetime handling
            session_data = {
                "id": session_id,
                "user_id": user_id,
                "title": title,
                "session_type": session_type,
                "is_active": True,
                "created_at": now,
                "updated_at": now,
                "session_meta": {
                    "created_via": "api",
                    "created_at": now.isoformat()
                }
            }
            
            # Execute insert with proper error handling
            await db.execute(
                insert(ChatSession).values(**session_data)
            )
            await db.commit()
            
            logger.info(f"Successfully created chat session {session_id} for user {user_id}")
            
            return {
                "session_id": session_id,
                "title": title or "New Chat",
                "session_type": session_type,
                "created_at": now.isoformat(),
                "message_count": 0
            }
            
        except Exception as e:
            logger.error(f"Error creating chat session for user {user_id}: {e}", exc_info=True)
            try:
                await db.rollback()
            except Exception as rollback_error:
                logger.error(f"Rollback failed: {rollback_error}")
            raise Exception(f"Failed to create chat session: {str(e)}")
    
    async def get_chat_session(
        self,
        session_id: str,
        user_id: int,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        """Get chat session details"""
        
        try:
            result = await db.execute(
                select(ChatSession)
                .options(selectinload(ChatSession.messages))
                .where(
                    ChatSession.id == session_id,
                    ChatSession.user_id == user_id,
                    ChatSession.is_active == True
                )
            )
            session = result.scalar_one_or_none()
            
            if not session:
                return None
            
            # Get message count
            message_count = len(session.messages) if session.messages else 0
            
            return {
                "session_id": session.id,
                "title": session.title,
                "session_type": session.session_type,
                "created_at": session.created_at.isoformat() if session.created_at else datetime.utcnow().isoformat(),
                "updated_at": session.updated_at.isoformat() if session.updated_at else datetime.utcnow().isoformat(),
                "message_count": message_count,
                "session_meta": session.session_meta or {}
            }
            
        except Exception as e:
            logger.error(f"Error getting chat session {session_id}: {e}")
            return None
    
    async def get_user_chat_sessions(
        self,
        user_id: int,
        limit: int = 20,
        db: AsyncSession = None
    ) -> List[Dict[str, Any]]:
        """Get user's chat sessions with optimized message count query and automatic cleanup"""
        
        try:
            from sqlalchemy import func
            
            # First, automatically cleanup empty sessions
            await self.cleanup_empty_sessions(user_id, db)
            
            # Optimized query with message count in single query
            result = await db.execute(
                select(
                    ChatSession,
                    func.count(ChatMessage.id).label('message_count')
                )
                .outerjoin(ChatMessage, ChatSession.id == ChatMessage.session_id)
                .where(
                    ChatSession.user_id == user_id,
                    ChatSession.is_active == True
                )
                .group_by(ChatSession.id)
                .order_by(desc(ChatSession.updated_at))
                .limit(limit)
            )
            
            session_data = result.all()
            
            session_list = []
            for session, message_count in session_data:
                # Only include sessions with at least 1 message (filter out empty sessions)
                if message_count and int(message_count) > 0:
                    session_list.append({
                        "session_id": session.id,
                        "title": session.title or "Untitled Chat",
                        "session_type": session.session_type,
                        "created_at": session.created_at.isoformat() if session.created_at else datetime.utcnow().isoformat(),
                        "updated_at": session.updated_at.isoformat() if session.updated_at else datetime.utcnow().isoformat(),
                        "message_count": int(message_count)
                    })
            
            logger.info(f"Retrieved {len(session_list)} sessions for user {user_id}")
            return session_list
            
        except Exception as e:
            logger.error(f"Error getting user chat sessions: {e}", exc_info=True)
            return []
    
    async def add_message(
        self,
        session_id: str,
        user_id: int,
        role: str,
        content: str,
        message_type: str = "text",
        msg_meta: Optional[Dict[str, Any]] = None,
        db: AsyncSession = None
    ) -> Dict[str, Any]:
        """Add message to chat session with proper validation and error handling"""
        
        # Validate inputs
        if not session_id or not content.strip():
            raise ValueError("Session ID and content are required")
        
        if role not in ["user", "assistant", "system"]:
            raise ValueError(f"Invalid role: {role}. Must be 'user', 'assistant', or 'system'")
        
        try:
            message_id = str(uuid.uuid4())
            now = datetime.utcnow()
            
            # Prepare message data with all required fields
            message_data = {
                "id": message_id,
                "session_id": session_id,
                "user_id": user_id,
                "role": role,
                "content": content.strip(),
                "message_type": message_type,
                "msg_meta": msg_meta or {},
                "timestamp": now
            }
            
            # Add optional fields from msg_meta if provided
            if msg_meta:
                message_data.update({
                    "model_used": msg_meta.get("model_used"),
                    "tokens_used": msg_meta.get("tokens_used"),
                    "processing_time": msg_meta.get("processing_time"),
                    "confidence_score": msg_meta.get("confidence_score")
                })
            
            # Insert message
            await db.execute(
                insert(ChatMessage).values(**message_data)
            )
            
            # Update session timestamp to keep it fresh
            await db.execute(
                update(ChatSession)
                .where(ChatSession.id == session_id, ChatSession.user_id == user_id)
                .values(updated_at=now)
            )
            
            await db.commit()
            
            logger.info(f"Added {role} message to session {session_id}")
            
            return {
                "message_id": message_id,
                "role": role,
                "content": content.strip(),
                "message_type": message_type,
                "timestamp": now.isoformat(),
                "msg_meta": msg_meta or {}
            }
            
        except Exception as e:
            logger.error(f"Error adding message to session {session_id}: {e}", exc_info=True)
            try:
                await db.rollback()
            except Exception as rollback_error:
                logger.error(f"Message rollback failed: {rollback_error}")
            raise Exception(f"Failed to add message: {str(e)}")
    
    async def get_chat_history(
        self,
        session_id: str,
        user_id: int,
        limit: int = 50,
        db: AsyncSession = None
    ) -> List[Dict[str, Any]]:
        """Get chat message history"""
        
        try:
            result = await db.execute(
                select(ChatMessage)
                .where(
                    ChatMessage.session_id == session_id,
                    ChatMessage.user_id == user_id
                )
                .order_by(ChatMessage.timestamp)
                .limit(limit)
            )
            messages = result.scalars().all()
            
            history = []
            for msg in messages:
                history.append({
                    "message_id": msg.id,
                    "role": msg.role,
                    "content": msg.content,
                    "message_type": msg.message_type,
                    "timestamp": msg.timestamp.isoformat(),
                    "msg_meta": msg.msg_meta or {},
                    "model_used": msg.model_used,
                    "tokens_used": msg.tokens_used,
                    "processing_time": msg.processing_time
                })
            
            return history
            
        except Exception as e:
            logger.error(f"Error getting chat history for session {session_id}: {e}")
            return []
    
    async def get_conversation_context(
        self,
        session_id: str,
        user_id: int,
        db: AsyncSession
    ) -> List[Dict[str, str]]:
        """Get recent conversation context for AI"""
        
        try:
            result = await db.execute(
                select(ChatMessage)
                .where(
                    ChatMessage.session_id == session_id,
                    ChatMessage.user_id == user_id
                )
                .order_by(desc(ChatMessage.timestamp))
                .limit(self.max_history_length)
            )
            messages = result.scalars().all()
            
            # Reverse to get chronological order
            context = []
            for msg in reversed(messages):
                context.append({
                    "role": msg.role,
                    "content": msg.content
                })
            
            return context
            
        except Exception as e:
            logger.error(f"Error getting conversation context: {e}")
            return []
    
    async def update_session_title(
        self,
        session_id: str,
        user_id: int,
        title: str,
        db: AsyncSession
    ) -> bool:
        """Update chat session title"""
        
        try:
            await db.execute(
                update(ChatSession)
                .where(
                    ChatSession.id == session_id,
                    ChatSession.user_id == user_id
                )
                .values(title=title, updated_at=datetime.utcnow())
            )
            await db.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error updating session title: {e}")
            await db.rollback()
            return False
    
    async def auto_generate_title(
        self,
        session_id: str,
        user_id: int,
        first_message: str,
        db: AsyncSession,
        ai_response: Optional[str] = None
    ) -> Optional[str]:
        """Auto-generate meaningful title from first message and AI response"""
        
        try:
            # Smart title generation based on content
            title = None
            
            # Analyze both user message and AI response for better titles
            combined_text = f"{first_message.lower()} {ai_response.lower() if ai_response else ''}"
            
            logger.info(f"Title generation for: '{first_message[:50]}...'")
            logger.info(f"Combined text (first 100 chars): '{combined_text[:100]}...'")
            
            # Security-specific topics with more specific patterns (ordered by specificity - most specific first)
            security_topics = {
                # Very specific vulnerability patterns first
                ('sql injection attack', 'sqli attack', 'sql injection vulnerability'): 'SQL Injection Discussion',
                ('cross-site scripting attack', 'xss attack', 'script injection attack'): 'XSS Security Help',
                ('cross-site request forgery', 'csrf attack', 'csrf vulnerability'): 'CSRF Protection',
                ('code injection', 'command injection', 'ldap injection'): 'Injection Vulnerability Help',
                
                # Specific security mechanisms
                ('jwt token', 'json web token', 'bearer token security'): 'JWT Security',
                ('password hashing', 'bcrypt', 'password encryption'): 'Password Security',
                ('oauth authentication', 'oauth security', 'oauth implementation'): 'OAuth Implementation',
                ('two factor authentication', '2fa', 'multi factor auth'): 'Multi-Factor Authentication',
                
                # Specific security practices
                ('security scan results', 'vulnerability scan report', 'scan findings'): 'Vulnerability Analysis',
                ('penetration test', 'pentest report', 'security testing'): 'Penetration Testing',
                ('code security review', 'secure code analysis', 'code audit'): 'Code Security Review',
                ('security compliance', 'gdpr compliance', 'hipaa compliance', 'pci compliance'): 'Compliance Help',
                
                # Broader patterns (less specific, checked later)
                ('api security', 'rest api security', 'api endpoint security'): 'API Security',
                ('owasp top 10', 'owasp guidelines', 'owasp standards'): 'OWASP Guidelines',
                ('security best practices', 'secure development', 'security recommendations'): 'Security Best Practices',
                ('incident response', 'security breach', 'security incident'): 'Incident Response',
                ('threat modeling', 'attack vector', 'security risk assessment'): 'Threat Analysis',
                
                # Authentication and authorization (more specific first)
                ('authentication implementation', 'login security', 'signin security'): 'Authentication Help',
                ('authorization setup', 'access control implementation', 'permission system'): 'Authorization Setup',
                ('encryption implementation', 'decrypt data', 'cryptography help'): 'Encryption Discussion',
                
                # Very general patterns (only if nothing else matches)
                ('security policy', 'security standard', 'security framework'): 'Security Policy Help',
            }
            
            # Find matching topics - only match if pattern is contextually appropriate
            matched_titles = []
            for patterns, topic_title in security_topics.items():
                for pattern in patterns:
                    if pattern in combined_text:
                        # Additional validation: ensure it's not a false positive
                        pattern_words = pattern.split()
                        text_words = combined_text.split()
                        
                        # For single word patterns, be more strict
                        if len(pattern_words) == 1:
                            # Single word must appear with related context words
                            if any(context_word in text_words for context_word in ['help', 'how', 'what', 'explain', 'about']):
                                matched_titles.append((pattern, topic_title, len(pattern_words)))
                        else:
                            # Multi-word patterns are generally more specific
                            matched_titles.append((pattern, topic_title, len(pattern_words)))
                        break
            
            # Choose the most specific match (highest word count)
            if matched_titles:
                # Sort by specificity (word count) descending, then by pattern length
                matched_titles.sort(key=lambda x: (x[2], len(x[0])), reverse=True)
                best_match = matched_titles[0]
                logger.info(f"Matched pattern: '{best_match[0]}' (specificity: {best_match[2]}) -> Title: '{best_match[1]}'")
                logger.info(f"All matches found: {[(m[0], m[1]) for m in matched_titles[:3]]}")
                title = best_match[1]
            
            # Fallback to smart message analysis with better extraction
            if not title:
                logger.info(f"No specific security pattern matched, using smart fallback analysis")
                message_lower = first_message.lower()
                
                # Check for question patterns and create contextual titles
                if any(q in message_lower for q in ['how to', 'how do', 'how can', 'how should']):
                    # Extract the main topic after "how to"
                    key_words = []
                    words = first_message.split()
                    for i, word in enumerate(words):
                        if word.lower() in ['how', 'to', 'do', 'can', 'should']:
                            # Take next 3-4 meaningful words
                            key_words = [w for w in words[i+1:i+5] if len(w) > 2 and w.lower() not in ['the', 'a', 'an', 'in', 'on', 'at', 'for', 'with']]
                            break
                    if key_words:
                        title = f"How to {' '.join(key_words[:3]).title()}"
                        logger.info(f"Generated 'how-to' title: {title}")
                    else:
                        title = 'How-to Security Guide'
                        
                elif any(q in message_lower for q in ['what is', 'what are', 'what does', 'explain', 'define']):
                    # Extract what they're asking about
                    key_words = []
                    words = first_message.split()
                    for i, word in enumerate(words):
                        if word.lower() in ['what', 'explain', 'define']:
                            # Take next 2-3 meaningful words
                            key_words = [w for w in words[i+1:i+4] if len(w) > 2 and w.lower() not in ['is', 'are', 'does', 'the', 'a', 'an']]
                            break
                    if key_words:
                        title = f"About {' '.join(key_words[:2]).title()}"
                        logger.info(f"Generated 'about' title: {title}")
                    else:
                        title = 'Security Explanation'
                        
                elif any(q in message_lower for q in ['help', 'issue', 'problem', 'error', 'fix']):
                    # Extract the main problem area
                    key_words = []
                    problem_words = ['help', 'issue', 'problem', 'error', 'fix', 'trouble', 'bug']
                    words = first_message.split()
                    for i, word in enumerate(words):
                        if word.lower() in problem_words:
                            # Take surrounding context words
                            start = max(0, i-2)
                            end = min(len(words), i+4)
                            key_words = [w for w in words[start:end] if len(w) > 2 and w.lower() not in problem_words + ['with', 'the', 'a', 'an', 'my', 'our']]
                            break
                    if key_words:
                        title = f"{' '.join(key_words[:2]).title()} Help"
                        logger.info(f"Generated 'help' title: {title}")
                    else:
                        title = 'Security Problem Solving'
                        
                elif 'security' in message_lower:
                    # Generic security question - extract key terms
                    words = first_message.split()
                    security_related = []
                    stop_words = {'the', 'a', 'an', 'i', 'you', 'we', 'they', 'it', 'this', 'that', 'is', 'are', 'was', 'were', 'can', 'could', 'would', 'should', 'will', 'to', 'and', 'or', 'but'}
                    
                    for word in words:
                        clean_word = word.lower().strip('.,!?;:')
                        if len(clean_word) > 3 and clean_word not in stop_words:
                            security_related.append(word)
                        if len(security_related) >= 3:
                            break
                    
                    if security_related:
                        title = f"{' '.join(security_related[:2]).title()} Security"
                        logger.info(f"Generated security-focused title: {title}")
                    else:
                        title = "Security Discussion"
                else:
                    # Extract meaningful words from the beginning, avoiding common words
                    words = first_message.split()
                    meaningful_words = []
                    stop_words = {'the', 'a', 'an', 'i', 'you', 'we', 'they', 'it', 'this', 'that', 'is', 'are', 'was', 'were', 'can', 'could', 'would', 'should', 'will'}
                    
                    for word in words:
                        clean_word = word.lower().strip('.,!?;:')
                        if len(clean_word) > 2 and clean_word not in stop_words:
                            meaningful_words.append(word)
                        if len(meaningful_words) >= 4:
                            break
                    
                    if meaningful_words:
                        title = " ".join(meaningful_words)
                        if len(title) > 45:
                            title = title[:42] + "..."
                        logger.info(f"Generated general title: {title}")
                    else:
                        title = "Security Chat"
            
            # Ensure title isn't too long
            if title and len(title) > 50:
                title = title[:47] + "..."
            
            # Update session with generated title
            if title and await self.update_session_title(session_id, user_id, title, db):
                logger.info(f"Generated smart title for session {session_id}: {title}")
                return title
            
            return None
            
        except Exception as e:
            logger.error(f"Error auto-generating title: {e}")
            return None
    
    async def cleanup_empty_sessions(
        self,
        user_id: int,
        db: AsyncSession
    ) -> int:
        """Automatically cleanup empty sessions for a user"""
        
        try:
            from sqlalchemy import func, update
            
            # Find sessions with no messages
            empty_sessions_query = select(ChatSession.id).where(
                ChatSession.user_id == user_id,
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
                logger.info(f"Auto-cleaned up {len(empty_session_ids)} empty sessions for user {user_id}")
                return len(empty_session_ids)
            
            return 0
            
        except Exception as e:
            logger.error(f"Error in automatic cleanup: {e}")
            return 0

    async def deactivate_session(
        self,
        session_id: str,
        user_id: int,
        db: AsyncSession
    ) -> bool:
        """Deactivate a chat session"""
        
        try:
            await db.execute(
                update(ChatSession)
                .where(
                    ChatSession.id == session_id,
                    ChatSession.user_id == user_id
                )
                .values(is_active=False, updated_at=datetime.utcnow())
            )
            await db.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error deactivating session: {e}")
            await db.rollback()
            return False

# Global instance
chat_manager = ChatManager()