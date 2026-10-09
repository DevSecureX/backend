"""
DevSecureX Cleanup Service

This service handles automated cleanup tasks including:
- Permanent deletion of soft-deleted users after 30-day retention period
- Cleanup of expired blacklisted tokens
- Cleanup of old login attempts and audit logs
- General database maintenance tasks

Security Features:
- Audit logging for all permanent deletions
- Rate limiting and safety checks
- Configurable retention periods
- Comprehensive error handling and monitoring
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, and_, func, text
from sqlalchemy.exc import SQLAlchemyError

from core.database import get_db
from auth.models import User, BlacklistedToken, LoginAttempt
from auth.dependencies import cleanup_expired_blacklisted_tokens

logger = logging.getLogger(__name__)

class CleanupService:
    """
    Service responsible for automated cleanup tasks in DevSecureX
    """
    
    def __init__(self):
        self.retention_days = 30  # Default 30-day retention for soft-deleted users
        self.max_deletions_per_run = 100  # Safety limit to prevent accidental mass deletion
        self.cleanup_batch_size = 50  # Process deletions in batches for performance
    
    async def cleanup_soft_deleted_users(self, db: AsyncSession, dry_run: bool = False) -> Dict[str, int]:
        """
        Permanently delete users that have been soft-deleted for more than retention_days
        
        Args:
            db: Database session
            dry_run: If True, only count users that would be deleted without actually deleting
            
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
            
            logger.info(f"Starting soft-deleted users cleanup (retention: {self.retention_days} days)")
            logger.info(f"Cutoff date: {cutoff_date}")
            
            # Find users eligible for permanent deletion
            result = await db.execute(
                select(User).where(
                    and_(
                        User.is_deleted == True,
                        User.deleted_at <= cutoff_date
                    )
                ).limit(self.max_deletions_per_run)
            )
            
            users_to_delete = result.scalars().all()
            total_found = len(users_to_delete)
            
            if total_found == 0:
                logger.info("No soft-deleted users found for permanent deletion")
                return {"found": 0, "deleted": 0, "errors": 0}
            
            logger.info(f"Found {total_found} users eligible for permanent deletion")
            
            if dry_run:
                # Just return counts without deleting
                user_info = []
                for user in users_to_delete:
                    days_deleted = (datetime.now(timezone.utc) - user.deleted_at).days
                    user_info.append({
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "deleted_at": user.deleted_at,
                        "days_deleted": days_deleted,
                        "deletion_reason": user.deletion_reason
                    })
                
                logger.info(f"DRY RUN: Would delete {total_found} users")
                for info in user_info[:5]:  # Show first 5 users
                    logger.info(f"  - {info['username']} ({info['email']}) - deleted {info['days_deleted']} days ago")
                
                return {
                    "found": total_found,
                    "deleted": 0,
                    "errors": 0,
                    "dry_run": True,
                    "users": user_info
                }
            
            # Process deletions in batches
            deleted_count = 0
            error_count = 0
            
            for i in range(0, total_found, self.cleanup_batch_size):
                batch = users_to_delete[i:i + self.cleanup_batch_size]
                
                try:
                    # Log deletion attempt for audit purposes
                    batch_info = []
                    for user in batch:
                        days_deleted = (datetime.now(timezone.utc) - user.deleted_at).days
                        batch_info.append({
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "deleted_at": user.deleted_at,
                            "days_deleted": days_deleted,
                            "deletion_reason": user.deletion_reason
                        })
                        
                        # Detailed audit log for each user
                        logger.info(
                            f"Permanently deleting user {user.id} ({user.username}, {user.email}) "
                            f"- soft deleted {days_deleted} days ago, reason: {user.deletion_reason}"
                        )
                    
                    # Delete the batch of users
                    user_ids = [user.id for user in batch]
                    await db.execute(
                        delete(User).where(User.id.in_(user_ids))
                    )
                    
                    await db.commit()
                    deleted_count += len(batch)
                    
                    logger.info(f"Successfully deleted batch of {len(batch)} users")
                    
                except Exception as e:
                    logger.error(f"Error deleting batch: {str(e)}")
                    error_count += len(batch)
                    await db.rollback()
                    continue
            
            logger.info(f"Cleanup completed: {deleted_count} users permanently deleted, {error_count} errors")
            
            return {
                "found": total_found,
                "deleted": deleted_count,
                "errors": error_count
            }
            
        except Exception as e:
            logger.error(f"Error in cleanup_soft_deleted_users: {str(e)}")
            await db.rollback()
            raise
    
    async def cleanup_old_login_attempts(self, db: AsyncSession, days_to_keep: int = 90) -> Dict[str, int]:
        """
        Remove old login attempts to prevent table growth
        
        Args:
            db: Database session
            days_to_keep: Number of days of login attempts to keep
            
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            
            logger.info(f"Cleaning up login attempts older than {days_to_keep} days")
            
            # Count records to be deleted
            count_result = await db.execute(
                select(func.count(LoginAttempt.id)).where(
                    LoginAttempt.created_at < cutoff_date
                )
            )
            
            records_to_delete = count_result.scalar()
            
            if records_to_delete == 0:
                logger.info("No old login attempts found for cleanup")
                return {"found": 0, "deleted": 0}
            
            # Delete old login attempts
            result = await db.execute(
                delete(LoginAttempt).where(
                    LoginAttempt.created_at < cutoff_date
                )
            )
            
            deleted_count = result.rowcount
            await db.commit()
            
            logger.info(f"Cleaned up {deleted_count} old login attempts")
            
            return {
                "found": records_to_delete,
                "deleted": deleted_count
            }
            
        except Exception as e:
            logger.error(f"Error in cleanup_old_login_attempts: {str(e)}")
            await db.rollback()
            raise
    
    async def cleanup_expired_tokens(self, db: AsyncSession) -> Dict[str, int]:
        """
        Clean up expired blacklisted tokens
        
        Args:
            db: Database session
            
        Returns:
            Dictionary with cleanup statistics
        """
        try:
            logger.info("Cleaning up expired blacklisted tokens")
            
            # Use existing cleanup function
            await cleanup_expired_blacklisted_tokens(db)
            
            # Count remaining tokens for reporting
            result = await db.execute(select(func.count(BlacklistedToken.id)))
            remaining_tokens = result.scalar()
            
            logger.info(f"Token cleanup completed. {remaining_tokens} tokens remaining")
            
            return {"remaining_tokens": remaining_tokens}
            
        except Exception as e:
            logger.error(f"Error in cleanup_expired_tokens: {str(e)}")
            raise
    
    async def run_full_cleanup(self, dry_run: bool = False) -> Dict[str, Dict]:
        """
        Run all cleanup tasks
        
        Args:
            dry_run: If True, perform read-only operations to show what would be cleaned
            
        Returns:
            Dictionary with results from all cleanup tasks
        """
        logger.info(f"Starting full cleanup cycle (dry_run: {dry_run})")
        
        results = {}
        
        async for db in get_db():
            try:
                # Cleanup soft-deleted users
                logger.info("Running soft-deleted users cleanup...")
                results['soft_deleted_users'] = await self.cleanup_soft_deleted_users(db, dry_run)
                
                if not dry_run:
                    # Cleanup expired tokens
                    logger.info("Running expired tokens cleanup...")
                    results['expired_tokens'] = await self.cleanup_expired_tokens(db)
                    
                    # Cleanup old login attempts
                    logger.info("Running old login attempts cleanup...")
                    results['login_attempts'] = await self.cleanup_old_login_attempts(db)
                
                break  # Exit the async generator after first iteration
                
            except Exception as e:
                logger.error(f"Error during full cleanup: {str(e)}")
                results['error'] = str(e)
                raise
            
            finally:
                await db.close()
        
        # Log summary
        if dry_run:
            logger.info("=== DRY RUN CLEANUP SUMMARY ===")
            if 'soft_deleted_users' in results:
                logger.info(f"Soft-deleted users that would be permanently deleted: {results['soft_deleted_users']['found']}")
        else:
            logger.info("=== CLEANUP SUMMARY ===")
            if 'soft_deleted_users' in results:
                logger.info(f"Users permanently deleted: {results['soft_deleted_users']['deleted']}")
            if 'login_attempts' in results:
                logger.info(f"Old login attempts cleaned: {results['login_attempts']['deleted']}")
            if 'expired_tokens' in results:
                logger.info(f"Remaining blacklisted tokens: {results['expired_tokens']['remaining_tokens']}")
        
        return results

# Global cleanup service instance
cleanup_service = CleanupService()

async def run_cleanup_job(dry_run: bool = False):
    """
    Standalone function to run cleanup job
    Can be called from cron jobs, scheduled tasks, or management commands
    """
    try:
        results = await cleanup_service.run_full_cleanup(dry_run=dry_run)
        return results
    except Exception as e:
        logger.error(f"Cleanup job failed: {str(e)}")
        raise

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX Cleanup Service")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Show what would be cleaned without actually deleting")
    parser.add_argument("--users-only", action="store_true", 
                       help="Only cleanup soft-deleted users")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if args.users_only:
        async def users_cleanup():
            async for db in get_db():
                try:
                    results = await cleanup_service.cleanup_soft_deleted_users(db, dry_run=args.dry_run)
                    print(f"Users cleanup results: {results}")
                    break
                finally:
                    await db.close()
        
        asyncio.run(users_cleanup())
    else:
        results = asyncio.run(run_cleanup_job(dry_run=args.dry_run))
        print(f"Full cleanup results: {results}")