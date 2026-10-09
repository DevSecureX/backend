"""
Data Retention and Cleanup Utilities for DevSecureX

Implements enterprise-grade data retention policies with automated cleanup
mechanisms for logs, temporary data, and expired records.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text, and_, or_
import logging

from app.ai_assistant.models import (
    ChatMessage, ChatSession, AIInteraction, AIAnalysisCache
)
from app.cli_scan.models import (
    CLIActivityLog, CLIUsageStats, CLIScanSession, CLIScanResult
)
from app.auth.models import BlacklistedToken, LoginAttempt
from app.support.models import SupportQuery, SupportResponse

logger = logging.getLogger(__name__)


class DataRetentionManager:
    """
    Manages data retention policies and automated cleanup operations
    """
    
    # Retention periods in days
    RETENTION_POLICIES = {
        # Chat and AI data
        'chat_messages': 365,  # 1 year
        'chat_sessions_inactive': 90,  # 90 days for inactive sessions
        'ai_interactions': 180,  # 6 months
        'ai_analysis_cache': 30,  # 30 days
        
        # CLI and activity logs
        'cli_activity_logs': 90,  # 3 months
        'cli_scan_results': 365,  # 1 year
        'cli_usage_stats': 730,  # 2 years (for trend analysis)
        'cli_scan_sessions_expired': 7,  # 1 week for expired sessions
        
        # Security and authentication
        'blacklisted_tokens': 30,  # 30 days after expiry
        'login_attempts': 30,  # 30 days
        
        # Support data
        'support_queries_resolved': 365,  # 1 year for resolved queries
        'support_responses': 365,  # 1 year
        
        # User data (soft delete)
        'deleted_users': 30,  # 30 days retention after deletion
    }
    
    def __init__(self, db: Session):
        self.db = db
    
    def cleanup_expired_tokens(self) -> Dict[str, int]:
        """Clean up expired blacklisted tokens"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=self.RETENTION_POLICIES['blacklisted_tokens']
            )
            
            result = self.db.execute(
                text("""
                    DELETE FROM blacklisted_tokens 
                    WHERE expires_at < :cutoff_date
                """),
                {"cutoff_date": cutoff_date}
            )
            
            deleted_count = result.rowcount
            self.db.commit()
            
            logger.info(f"Cleaned up {deleted_count} expired blacklisted tokens")
            return {"blacklisted_tokens": deleted_count}
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up expired tokens: {e}")
            return {"blacklisted_tokens": 0}
    
    def cleanup_old_login_attempts(self) -> Dict[str, int]:
        """Clean up old login attempts"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=self.RETENTION_POLICIES['login_attempts']
            )
            
            result = self.db.execute(
                text("""
                    DELETE FROM login_attempts 
                    WHERE created_at < :cutoff_date
                """),
                {"cutoff_date": cutoff_date}
            )
            
            deleted_count = result.rowcount
            self.db.commit()
            
            logger.info(f"Cleaned up {deleted_count} old login attempts")
            return {"login_attempts": deleted_count}
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up login attempts: {e}")
            return {"login_attempts": 0}
    
    def cleanup_inactive_chat_sessions(self) -> Dict[str, int]:
        """Clean up inactive chat sessions and related messages"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=self.RETENTION_POLICIES['chat_sessions_inactive']
            )
            
            # Delete messages first (due to FK constraint)
            message_result = self.db.execute(
                text("""
                    DELETE FROM chat_messages 
                    WHERE session_id IN (
                        SELECT id FROM chat_sessions 
                        WHERE updated_at < :cutoff_date AND is_active = false
                    )
                """),
                {"cutoff_date": cutoff_date}
            )
            
            # Then delete sessions
            session_result = self.db.execute(
                text("""
                    DELETE FROM chat_sessions 
                    WHERE updated_at < :cutoff_date AND is_active = false
                """),
                {"cutoff_date": cutoff_date}
            )
            
            self.db.commit()
            
            logger.info(f"Cleaned up {session_result.rowcount} inactive chat sessions and {message_result.rowcount} messages")
            return {
                "chat_sessions": session_result.rowcount,
                "chat_messages": message_result.rowcount
            }
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up inactive chat sessions: {e}")
            return {"chat_sessions": 0, "chat_messages": 0}
    
    def cleanup_expired_ai_cache(self) -> Dict[str, int]:
        """Clean up expired AI analysis cache entries"""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Clean up expired entries
            expired_result = self.db.execute(
                text("""
                    DELETE FROM ai_analysis_cache 
                    WHERE expires_at IS NOT NULL AND expires_at < :current_time
                """),
                {"current_time": current_time}
            )
            
            # Clean up old entries without expiration
            old_cutoff = current_time - timedelta(
                days=self.RETENTION_POLICIES['ai_analysis_cache']
            )
            
            old_result = self.db.execute(
                text("""
                    DELETE FROM ai_analysis_cache 
                    WHERE expires_at IS NULL AND created_at < :cutoff_date
                """),
                {"cutoff_date": old_cutoff}
            )
            
            self.db.commit()
            
            total_deleted = expired_result.rowcount + old_result.rowcount
            logger.info(f"Cleaned up {total_deleted} expired AI cache entries")
            return {"ai_analysis_cache": total_deleted}
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up AI cache: {e}")
            return {"ai_analysis_cache": 0}
    
    def cleanup_old_cli_activity_logs(self) -> Dict[str, int]:
        """Clean up old CLI activity logs"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=self.RETENTION_POLICIES['cli_activity_logs']
            )
            
            result = self.db.execute(
                text("""
                    DELETE FROM cli_activity_logs 
                    WHERE created_at < :cutoff_date
                """),
                {"cutoff_date": cutoff_date}
            )
            
            deleted_count = result.rowcount
            self.db.commit()
            
            logger.info(f"Cleaned up {deleted_count} old CLI activity logs")
            return {"cli_activity_logs": deleted_count}
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up CLI activity logs: {e}")
            return {"cli_activity_logs": 0}
    
    def cleanup_expired_cli_sessions(self) -> Dict[str, int]:
        """Clean up expired CLI scan sessions"""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Clean up expired sessions
            result = self.db.execute(
                text("""
                    DELETE FROM cli_scan_sessions 
                    WHERE expires_at < :current_time
                """),
                {"current_time": current_time}
            )
            
            deleted_count = result.rowcount
            self.db.commit()
            
            logger.info(f"Cleaned up {deleted_count} expired CLI scan sessions")
            return {"cli_scan_sessions": deleted_count}
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up CLI scan sessions: {e}")
            return {"cli_scan_sessions": 0}
    
    def cleanup_old_ai_interactions(self) -> Dict[str, int]:
        """Clean up old AI interactions"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=self.RETENTION_POLICIES['ai_interactions']
            )
            
            result = self.db.execute(
                text("""
                    DELETE FROM ai_interactions 
                    WHERE created_at < :cutoff_date
                """),
                {"cutoff_date": cutoff_date}
            )
            
            deleted_count = result.rowcount
            self.db.commit()
            
            logger.info(f"Cleaned up {deleted_count} old AI interactions")
            return {"ai_interactions": deleted_count}
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up AI interactions: {e}")
            return {"ai_interactions": 0}
    
    def cleanup_soft_deleted_users(self) -> Dict[str, int]:
        """Permanently delete users after soft delete retention period"""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=self.RETENTION_POLICIES['deleted_users']
            )
            
            # First, get the user IDs to be permanently deleted
            user_ids_result = self.db.execute(
                text("""
                    SELECT id FROM users 
                    WHERE is_deleted = true AND deleted_at < :cutoff_date
                """),
                {"cutoff_date": cutoff_date}
            )
            
            user_ids = [row[0] for row in user_ids_result.fetchall()]
            
            if not user_ids:
                return {"deleted_users": 0}
            
            # Permanently delete users (CASCADE will handle related records)
            result = self.db.execute(
                text("""
                    DELETE FROM users 
                    WHERE is_deleted = true AND deleted_at < :cutoff_date
                """),
                {"cutoff_date": cutoff_date}
            )
            
            deleted_count = result.rowcount
            self.db.commit()
            
            logger.info(f"Permanently deleted {deleted_count} users after retention period")
            return {"deleted_users": deleted_count}
            
        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up soft-deleted users: {e}")
            return {"deleted_users": 0}
    
    def run_full_cleanup(self) -> Dict[str, Any]:
        """
        Run complete data retention cleanup across all tables
        
        Returns:
            Dictionary with cleanup statistics and any errors
        """
        cleanup_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "success": True,
            "deleted_counts": {},
            "errors": []
        }
        
        cleanup_operations = [
            ("expired_tokens", self.cleanup_expired_tokens),
            ("login_attempts", self.cleanup_old_login_attempts),
            ("chat_sessions", self.cleanup_inactive_chat_sessions),
            ("ai_cache", self.cleanup_expired_ai_cache),
            ("cli_logs", self.cleanup_old_cli_activity_logs),
            ("cli_sessions", self.cleanup_expired_cli_sessions),
            ("ai_interactions", self.cleanup_old_ai_interactions),
            ("deleted_users", self.cleanup_soft_deleted_users),
        ]
        
        for operation_name, operation_func in cleanup_operations:
            try:
                result = operation_func()
                cleanup_results["deleted_counts"].update(result)
                logger.info(f"Completed cleanup operation: {operation_name}")
            except Exception as e:
                error_msg = f"Failed cleanup operation {operation_name}: {str(e)}"
                cleanup_results["errors"].append(error_msg)
                cleanup_results["success"] = False
                logger.error(error_msg)
        
        # Calculate total deletions
        total_deleted = sum(
            count for count in cleanup_results["deleted_counts"].values()
            if isinstance(count, int)
        )
        cleanup_results["total_deleted"] = total_deleted
        
        logger.info(f"Data retention cleanup completed. Total records deleted: {total_deleted}")
        
        return cleanup_results
    
    def get_retention_summary(self) -> Dict[str, Any]:
        """
        Get summary of current data retention status
        
        Returns:
            Dictionary with table sizes and retention estimates
        """
        try:
            summary = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "table_stats": {},
                "retention_policies": self.RETENTION_POLICIES
            }
            
            # Get table statistics
            table_queries = {
                "chat_messages": "SELECT COUNT(*) as count, MIN(timestamp) as oldest, MAX(timestamp) as newest FROM chat_messages",
                "chat_sessions": "SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(updated_at) as newest FROM chat_sessions",
                "ai_interactions": "SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(created_at) as newest FROM ai_interactions",
                "ai_analysis_cache": "SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(accessed_at) as newest FROM ai_analysis_cache",
                "cli_activity_logs": "SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(created_at) as newest FROM cli_activity_logs",
                "cli_scan_results": "SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(created_at) as newest FROM cli_scan_results",
                "blacklisted_tokens": "SELECT COUNT(*) as count, MIN(created_at) as oldest, MAX(expires_at) as newest FROM blacklisted_tokens",
            }
            
            for table_name, query in table_queries.items():
                try:
                    result = self.db.execute(text(query)).fetchone()
                    summary["table_stats"][table_name] = {
                        "count": result[0] if result[0] else 0,
                        "oldest_record": result[1].isoformat() if result[1] else None,
                        "newest_record": result[2].isoformat() if result[2] else None
                    }
                except Exception as e:
                    logger.warning(f"Could not get stats for table {table_name}: {e}")
                    summary["table_stats"][table_name] = {"error": str(e)}
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating retention summary: {e}")
            return {"error": str(e)}


def create_cleanup_job():
    """
    Factory function to create a data retention cleanup job
    Can be used with task schedulers like Celery or APScheduler
    """
    from core.database import get_db
    
    def cleanup_job():
        db = next(get_db())
        try:
            manager = DataRetentionManager(db)
            results = manager.run_full_cleanup()
            logger.info(f"Scheduled cleanup completed: {results}")
            return results
        finally:
            db.close()
    
    return cleanup_job