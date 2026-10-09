#!/usr/bin/env python3
"""
Database Migration: Add Performance Indexes for Custom Rules

This migration adds critical database indexes to optimize query performance
for the custom rules system, especially for frequent operations like:
- Fetching user's custom rules by niche
- Finding popular community rules
- Rule search and filtering
- Vote tracking and analytics

Run: python app/migrations/004_add_custom_rules_indexes.py --action migrate
Rollback: python app/migrations/004_add_custom_rules_indexes.py --action rollback
"""

import asyncio
import logging
import sys
import argparse
from datetime import datetime
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from core.config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CustomRulesIndexMigration:
    """Migration to add performance indexes for custom rules queries"""
    
    def __init__(self):
        self.settings = get_settings()
        self.engine = None
        
    async def connect(self):
        """Create database connection"""
        try:
            # For SQLite, use different connection string
            if 'sqlite' in self.settings.database_url.lower():
                # SQLite requires aiosqlite
                db_url = self.settings.database_url.replace('sqlite:///', 'sqlite+aiosqlite:///')
            else:
                # PostgreSQL
                db_url = self.settings.database_url.replace('postgresql://', 'postgresql+asyncpg://')
                
            self.engine = create_async_engine(db_url, echo=False)
            logger.info("Database connection established")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
            
    async def disconnect(self):
        """Close database connection"""
        if self.engine:
            await self.engine.dispose()
            logger.info("Database connection closed")
            
    async def migrate(self):
        """Apply migration - add indexes"""
        logger.info("Starting migration: Adding custom rules performance indexes...")
        
        async with self.engine.begin() as conn:
            try:
                # Check if we're using PostgreSQL or SQLite
                is_postgres = 'postgresql' in self.settings.database_url.lower()
                
                # 1. Index for fetching user's custom rules by niche (most frequent operation)
                logger.info("Creating index for user rules by niche...")
                if is_postgres:
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_community_rules_user_niche_tool 
                        ON community_rules(author_id, tool, language) 
                        WHERE is_public = FALSE
                    """))
                else:
                    # SQLite doesn't support partial indexes in the same way
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_community_rules_user_niche_tool 
                        ON community_rules(author_id, tool, language, is_public)
                    """))
                
                # 2. Index for finding popular community rules (sorted by votes and usage)
                logger.info("Creating index for popular community rules...")
                if is_postgres:
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_community_rules_popularity 
                        ON community_rules(
                            ((upvotes - downvotes) + (usage_count * 0.1)) DESC,
                            created_at DESC
                        ) 
                        WHERE is_public = TRUE
                    """))
                else:
                    # SQLite: simpler index
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_community_rules_popularity 
                        ON community_rules(upvotes, downvotes, usage_count, created_at)
                    """))
                
                # 3. Index for rule search by name and description (text search)
                logger.info("Creating index for rule text search...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_community_rules_text_search 
                    ON community_rules(rule_name, severity, is_verified)
                """))
                
                # 4. Index for fetching rules by specific IDs (for selected_custom_rule_ids)
                logger.info("Creating index for rule ID lookups...")
                # Primary key already provides this, but add for compound queries
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_community_rules_id_public 
                    ON community_rules(id, is_public, author_id)
                """))
                
                # 5. Index for vote tracking (prevent duplicate votes efficiently)
                logger.info("Creating index for vote tracking...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_rule_votes_rule_user 
                    ON community_rule_votes(rule_id, user_id)
                """))
                
                # 6. Index for user's vote history
                logger.info("Creating index for user vote history...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_rule_votes_user_created 
                    ON community_rule_votes(user_id, created_at DESC)
                """))
                
                # 7. Index for rule comments (nested comments support)
                logger.info("Creating index for rule comments...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_rule_comments_rule_created 
                    ON rule_comments(rule_id, created_at DESC)
                """))
                
                # 8. Index for rule collections
                logger.info("Creating index for rule collections...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_rule_collections_user_public 
                    ON rule_collections(user_id, is_public, created_at DESC)
                """))
                
                # 9. Composite index for rule collection items
                logger.info("Creating index for collection items...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_collection_items_collection_rule 
                    ON rule_collection_items(collection_id, rule_id)
                """))
                
                # 10. Index for rule feedback aggregation
                logger.info("Creating index for rule feedback...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_rule_feedback_rule_type 
                    ON rule_feedback(rule_id, feedback_type, rating)
                """))
                
                # 11. Performance index for filtering by language and severity
                logger.info("Creating composite index for language and severity filters...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_community_rules_lang_severity 
                    ON community_rules(language, severity, is_public, is_verified)
                """))
                
                # 12. Index for trending rules (recent + popular)
                logger.info("Creating index for trending rules...")
                if is_postgres:
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_community_rules_trending 
                        ON community_rules(created_at DESC, upvotes DESC) 
                        WHERE is_public = TRUE AND created_at > CURRENT_DATE - INTERVAL '30 days'
                    """))
                else:
                    # SQLite version
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_community_rules_trending 
                        ON community_rules(created_at, upvotes, is_public)
                    """))
                
                # 13. Index for analytics - rules by tool and niche
                logger.info("Creating analytics index...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_community_rules_analytics 
                    ON community_rules(tool, language, severity, is_verified, created_at)
                """))
                
                # 14. Index for soft delete operations (if implemented)
                logger.info("Creating soft delete index...")
                await conn.execute(text("""
                    CREATE INDEX IF NOT EXISTS idx_community_rules_deleted 
                    ON community_rules(is_verified, is_public) 
                """))
                
                # 15. Performance stats collection
                logger.info("Analyzing tables for query optimization...")
                if is_postgres:
                    # PostgreSQL ANALYZE command
                    await conn.execute(text("ANALYZE community_rules"))
                    await conn.execute(text("ANALYZE community_rule_votes"))
                    await conn.execute(text("ANALYZE rule_comments"))
                    await conn.execute(text("ANALYZE rule_collections"))
                    await conn.execute(text("ANALYZE rule_collection_items"))
                    await conn.execute(text("ANALYZE rule_feedback"))
                else:
                    # SQLite ANALYZE command
                    await conn.execute(text("ANALYZE"))
                
                # Log migration completion
                await conn.execute(text("""
                    INSERT INTO migration_history (migration_name, applied_at, status)
                    VALUES (:name, :applied_at, :status)
                """), {
                    "name": "004_add_custom_rules_indexes",
                    "applied_at": datetime.utcnow(),
                    "status": "completed"
                })
                
                logger.info("✅ Migration completed successfully! All indexes created.")
                
            except Exception as e:
                logger.error(f"Migration failed: {e}")
                raise
                
    async def rollback(self):
        """Rollback migration - remove indexes"""
        logger.info("Starting rollback: Removing custom rules performance indexes...")
        
        async with self.engine.begin() as conn:
            try:
                # Drop all indexes created by this migration
                indexes_to_drop = [
                    "idx_community_rules_user_niche_tool",
                    "idx_community_rules_popularity",
                    "idx_community_rules_text_search",
                    "idx_community_rules_id_public",
                    "idx_rule_votes_rule_user",
                    "idx_rule_votes_user_created",
                    "idx_rule_comments_rule_created",
                    "idx_rule_collections_user_public",
                    "idx_collection_items_collection_rule",
                    "idx_rule_feedback_rule_type",
                    "idx_community_rules_lang_severity",
                    "idx_community_rules_trending",
                    "idx_community_rules_analytics",
                    "idx_community_rules_deleted"
                ]
                
                for index_name in indexes_to_drop:
                    try:
                        logger.info(f"Dropping index: {index_name}")
                        await conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
                    except Exception as e:
                        logger.warning(f"Could not drop index {index_name}: {e}")
                
                # Log rollback completion
                await conn.execute(text("""
                    UPDATE migration_history 
                    SET status = 'rolled_back', rolled_back_at = :rolled_back_at
                    WHERE migration_name = :name
                """), {
                    "name": "004_add_custom_rules_indexes",
                    "rolled_back_at": datetime.utcnow()
                })
                
                logger.info("✅ Rollback completed successfully! All indexes removed.")
                
            except Exception as e:
                logger.error(f"Rollback failed: {e}")
                raise
                
    async def check_indexes(self):
        """Check which indexes currently exist"""
        logger.info("Checking existing indexes...")
        
        async with self.engine.begin() as conn:
            try:
                is_postgres = 'postgresql' in self.settings.database_url.lower()
                
                if is_postgres:
                    # PostgreSQL query
                    result = await conn.execute(text("""
                        SELECT indexname, tablename, indexdef
                        FROM pg_indexes
                        WHERE tablename IN (
                            'community_rules', 
                            'community_rule_votes',
                            'rule_comments',
                            'rule_collections',
                            'rule_collection_items',
                            'rule_feedback'
                        )
                        ORDER BY tablename, indexname
                    """))
                else:
                    # SQLite query
                    result = await conn.execute(text("""
                        SELECT name, tbl_name, sql
                        FROM sqlite_master
                        WHERE type = 'index'
                        AND tbl_name IN (
                            'community_rules', 
                            'community_rule_votes',
                            'rule_comments',
                            'rule_collections',
                            'rule_collection_items',
                            'rule_feedback'
                        )
                        ORDER BY tbl_name, name
                    """))
                
                indexes = result.fetchall()
                
                logger.info(f"\nFound {len(indexes)} indexes:")
                for idx in indexes:
                    logger.info(f"  - {idx[0]} on {idx[1]}")
                    
                return indexes
                
            except Exception as e:
                logger.error(f"Failed to check indexes: {e}")
                raise

async def main():
    """Main migration runner"""
    parser = argparse.ArgumentParser(description='Custom Rules Index Migration')
    parser.add_argument(
        '--action',
        choices=['migrate', 'rollback', 'check'],
        required=True,
        help='Migration action to perform'
    )
    
    args = parser.parse_args()
    
    migration = CustomRulesIndexMigration()
    
    try:
        await migration.connect()
        
        if args.action == 'migrate':
            await migration.migrate()
        elif args.action == 'rollback':
            await migration.rollback()
        elif args.action == 'check':
            await migration.check_indexes()
            
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        sys.exit(1)
    finally:
        await migration.disconnect()

if __name__ == "__main__":
    asyncio.run(main())