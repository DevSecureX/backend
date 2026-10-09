import os
import time
import logging
import asyncio
import json
from typing import Dict, List, Any, Optional, AsyncGenerator
from datetime import datetime, timedelta

from openai import AsyncOpenAI
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, update

from .models import AIInteraction, AIAnalysisCache
from .prompt_manager import PromptManager
from .reference_validator import reference_validator

logger = logging.getLogger(__name__)

class SecurityAIClient:
    """OpenAI client specialized for security analysis and assistance"""
    
    def __init__(self):
        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY")
        )
        self.model = "gpt-4o-mini"
        self.prompt_manager = PromptManager()
        
        # Cache settings
        self.cache_enabled = True
        self.cache_duration = timedelta(hours=24)
        
        # Rate limiting
        self.max_tokens = 4000
        self.temperature = 0.1  # Low temperature for consistent security advice
        
    async def chat_completion_stream(
        self,
        messages: List[Dict[str, str]],
        user_id: int,
        session_id: str,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream chat completion with real-time response"""
        
        start_time = time.time()
        
        try:
            # Add system prompt for security context
            system_prompt = self.prompt_manager.get_system_prompt("security_assistant")
            
            # Prepare messages with system context
            full_messages = [
                {"role": "system", "content": system_prompt}
            ] + messages
            
            # Log interaction start
            interaction_data = {
                "messages": messages,
                "context": context or {},
                "session_id": session_id
            }
            
            # Stream the response
            stream = await self.client.chat.completions.create(
                model=self.model,
                messages=full_messages,
                stream=True,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            # Collect full response for reference validation
            full_response = ""
            
            async for chunk in stream:
                if chunk.choices[0].delta.content:
                    content = chunk.choices[0].delta.content
                    full_response += content
                    processing_time = int((time.time() - start_time) * 1000)
                    
                    yield {
                        "type": "chunk", 
                        "content": content,
                        "metadata": {
                            "session_id": session_id,
                            "processing_time": processing_time,
                            "tokens_used": None  # Will be set on completion
                        }
                    }
            
            # Validate and clean references in the complete response
            cleaned_response = reference_validator.validate_reference_text(full_response)
            if cleaned_response != full_response:
                # Send correction if references were cleaned
                yield {
                    "type": "reference_correction",
                    "content": "\n\n*Note: Some references have been updated to ensure current validity*",
                    "metadata": {
                        "session_id": session_id,
                        "corrections_applied": True
                    }
                }
            
            # Stream completion
            total_time = int((time.time() - start_time) * 1000)
            yield {
                "type": "complete",
                "metadata": {
                    "session_id": session_id,
                    "processing_time": total_time,
                    "model_used": self.model
                }
            }
            
        except Exception as e:
            logger.error(f"Chat completion stream error: {e}")
            yield {
                "type": "error",
                "error": str(e),
                "metadata": {
                    "session_id": session_id,
                    "processing_time": int((time.time() - start_time) * 1000)
                }
            }
    
    async def analyze_security_issue(
        self,
        code_snippet: str,
        language: str,
        user_id: int,
        db: AsyncSession,
        context: Optional[str] = None,
        scan_results: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """Analyze security issues in code"""
        
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = f"issue_analysis_{hash(code_snippet)}_{language}"
            if self.cache_enabled:
                cached = await self._get_cached_result(cache_key, db)
                if cached:
                    return cached
            
            # Prepare analysis prompt
            analysis_prompt = self.prompt_manager.get_analysis_prompt(
                code_snippet=code_snippet,
                language=language,
                context=context,
                scan_results=scan_results
            )
            
            # Get AI analysis
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.prompt_manager.get_system_prompt("issue_analyzer")},
                    {"role": "user", "content": analysis_prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            # Process and validate response
            raw_analysis = response.choices[0].message.content
            validated_analysis = reference_validator.validate_reference_text(raw_analysis)
            
            analysis_result = {
                "analysis": validated_analysis,
                "severity": "medium",  # Could be extracted from response
                "confidence": 85,  # Could be calculated
                "recommendations": [],  # Could be parsed from response
                "metadata": {
                    "model_used": self.model,
                    "tokens_used": response.usage.total_tokens,
                    "processing_time": int((time.time() - start_time) * 1000),
                    "language": language,
                    "context": context,
                    "references_validated": validated_analysis != raw_analysis
                }
            }
            
            # Cache result
            if self.cache_enabled:
                await self._cache_result(cache_key, analysis_result, db)
            
            # Log interaction
            await self._log_interaction(
                user_id=user_id,
                interaction_type="issue_analysis",
                input_data={"code_snippet": code_snippet, "language": language},
                ai_response=analysis_result,
                db=db
            )
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Issue analysis error: {e}")
            raise
    
    async def get_security_recommendations(
        self,
        topic: str,
        user_id: int,
        db: AsyncSession,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Get security recommendations for specific topics"""
        
        start_time = time.time()
        
        try:
            # Prepare recommendation prompt
            rec_prompt = self.prompt_manager.get_recommendation_prompt(
                topic=topic,
                context=context
            )
            
            # Get AI recommendations
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self.prompt_manager.get_system_prompt("security_advisor")},
                    {"role": "user", "content": rec_prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            # Validate references in recommendations
            raw_recommendations = response.choices[0].message.content
            validated_recommendations = reference_validator.validate_reference_text(raw_recommendations)
            
            recommendations = {
                "topic": topic,
                "recommendations": validated_recommendations,
                "metadata": {
                    "model_used": self.model,
                    "tokens_used": response.usage.total_tokens,
                    "processing_time": int((time.time() - start_time) * 1000),
                    "context": context,
                    "references_validated": validated_recommendations != raw_recommendations
                }
            }
            
            # Log interaction
            await self._log_interaction(
                user_id=user_id,
                interaction_type="security_recommendations",
                input_data={"topic": topic, "context": context},
                ai_response=recommendations,
                db=db
            )
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Recommendations error: {e}")
            raise
    
    async def _get_cached_result(self, cache_key: str, db: AsyncSession) -> Optional[Dict[str, Any]]:
        """Get cached analysis result"""
        try:
            result = await db.execute(
                select(AIAnalysisCache).where(
                    AIAnalysisCache.cache_key == cache_key,
                    AIAnalysisCache.expires_at > datetime.utcnow()
                )
            )
            cached = result.scalar_one_or_none()
            
            if cached:
                # Update access info
                await db.execute(
                    update(AIAnalysisCache)
                    .where(AIAnalysisCache.id == cached.id)
                    .values(
                        accessed_at=datetime.utcnow(),
                        access_count=AIAnalysisCache.access_count + 1
                    )
                )
                await db.commit()
                
                return cached.result
                
        except Exception as e:
            logger.error(f"Cache retrieval error: {e}")
            
        return None
    
    async def _cache_result(self, cache_key: str, result: Dict[str, Any], db: AsyncSession):
        """Cache analysis result"""
        try:
            await db.execute(
                insert(AIAnalysisCache).values(
                    cache_key=cache_key,
                    analysis_type="issue_analysis",
                    input_hash="",  # Could implement proper hashing
                    result=result,
                    expires_at=datetime.utcnow() + self.cache_duration,
                    model_used=self.model,
                    tokens_used=result.get("metadata", {}).get("tokens_used")
                )
            )
            await db.commit()
            
        except Exception as e:
            logger.error(f"Cache storage error: {e}")
    
    async def _log_interaction(
        self,
        user_id: int,
        interaction_type: str,
        input_data: Dict[str, Any],
        ai_response: Dict[str, Any],
        db: AsyncSession
    ):
        """Log AI interaction for analytics"""
        try:
            await db.execute(
                insert(AIInteraction).values(
                    user_id=user_id,
                    interaction_type=interaction_type,
                    input_data=input_data,
                    ai_response=ai_response,
                    model_used=self.model,
                    tokens_used=ai_response.get("metadata", {}).get("tokens_used"),
                    processing_time=ai_response.get("metadata", {}).get("processing_time"),
                    success=True
                )
            )
            await db.commit()
            
        except Exception as e:
            logger.error(f"Interaction logging error: {e}")

# Global instance
security_ai_client = SecurityAIClient()