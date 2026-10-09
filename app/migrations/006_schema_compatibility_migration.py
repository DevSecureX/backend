"""
Schema Compatibility Migration
Migration ID: 006_schema_compatibility_migration

This migration handles schema compatibility issues when restoring database backups
from older Docker images. It ensures that the database schema matches the current
codebase expectations.

Key changes:
1. Validates and creates missing tables if needed
2. Handles table name variations (e.g., compliance_mappings vs compliance_mapping)
3. Ensures all required indexes exist
4. Adds missing columns that might be required by current code
"""

import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, List
from core.database import engine

logger = logging.getLogger(__name__)

MIGRATION_ID = "006_schema_compatibility_migration"
MIGRATION_DESCRIPTION = "Schema compatibility fixes for restored database backups"


async def get_existing_tables(db: AsyncSession) -> set:
    """Get list of existing tables."""
    result = await db.execute(text("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_type = 'BASE TABLE'
    """))
    return {row[0] for row in result.fetchall()}


async def get_existing_columns(db: AsyncSession, table_name: str) -> set:
    """Get list of existing columns for a table."""
    result = await db.execute(text("""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND table_name = :table_name
    """), {"table_name": table_name})
    return {row[0] for row in result.fetchall()}


async def create_missing_indexes(db: AsyncSession) -> None:
    """Create missing indexes that are critical for performance."""
    indexes_to_create = [
        # Critical indexes for repository operations
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_repos_user_full_name ON repos(user_id, full_name)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scans_repo_user ON scans(repo_full_name, user_id)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scans_status_created ON scans(status, created_at)",
        
        # Indexes for cleanup operations
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_summaries_scan_id ON scan_summaries(scan_id)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_issue_feedback_scan_id ON issue_feedback(scan_id)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_compliance_mappings_scan_id ON compliance_mappings(scan_id)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pr_security_comments_scan_id ON pr_security_comments(scan_id)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pr_security_reviews_scan_id ON pr_security_reviews(scan_id)",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_jobs_scan_id ON scan_jobs(scan_id)"
    ]
    
    for index_sql in indexes_to_create:
        try:
            await db.execute(text(index_sql))
            logger.info(f"Created index: {index_sql.split()[-1]}")
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.debug(f"Index already exists, skipping: {index_sql.split()[-1]}")
            else:
                logger.warning(f"Failed to create index: {str(e)}")


async def ensure_table_compatibility(db: AsyncSession) -> None:
    """Ensure table structures are compatible with current code."""
    existing_tables = await get_existing_tables(db)
    
    # Handle compliance_mapping vs compliance_mappings table name issue
    if 'compliance_mapping' in existing_tables and 'compliance_mappings' not in existing_tables:
        logger.info("Renaming compliance_mapping to compliance_mappings for consistency")
        try:
            await db.execute(text("ALTER TABLE compliance_mapping RENAME TO compliance_mappings"))
            logger.info("Successfully renamed compliance_mapping to compliance_mappings")
        except Exception as e:
            logger.error(f"Failed to rename compliance_mapping table: {str(e)}")
    
    # Ensure repos table has all required columns
    if 'repos' in existing_tables:
        existing_columns = await get_existing_columns(db, 'repos')
        required_columns = {
            'id', 'full_name', 'user_id', 'niche', 'settings',
            'webhook_id', 'default_branch', 'is_private', 'language',
            'description', 'created_at', 'updated_at', 'last_synced',
            'status', 'sync_error'
        }
        
        missing_columns = required_columns - existing_columns
        if missing_columns:
            logger.warning(f"Repos table missing columns: {missing_columns}")
            
            # Add missing columns with appropriate defaults
            column_additions = {
                'status': "ALTER TABLE repos ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active'",
                'sync_error': "ALTER TABLE repos ADD COLUMN IF NOT EXISTS sync_error TEXT",
                'last_synced': "ALTER TABLE repos ADD COLUMN IF NOT EXISTS last_synced TIMESTAMP WITH TIME ZONE"
            }
            
            for col, sql in column_additions.items():
                if col in missing_columns:
                    try:
                        await db.execute(text(sql))
                        logger.info(f"Added missing column {col} to repos table")
                    except Exception as e:
                        logger.error(f"Failed to add column {col}: {str(e)}")


async def fix_foreign_key_constraints(db: AsyncSession) -> None:
    """Fix foreign key constraints that might be missing or incorrect."""
    try:
        # Ensure scans table has proper composite foreign key to repos
        await db.execute(text("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 
                    FROM information_schema.table_constraints 
                    WHERE constraint_name = 'scans_repo_full_name_user_id_fkey'
                    AND table_name = 'scans'
                ) THEN
                    ALTER TABLE scans 
                    ADD CONSTRAINT scans_repo_full_name_user_id_fkey 
                    FOREIGN KEY (repo_full_name, user_id) 
                    REFERENCES repos(full_name, user_id) 
                    ON DELETE CASCADE;
                END IF;
            END $$;
        """))
        logger.info("Ensured scans->repos foreign key constraint exists")
        
    except Exception as e:
        logger.warning(f"Foreign key constraint fix failed: {str(e)}")


async def validate_migration_success(db: AsyncSession) -> bool:
    """Validate that the migration completed successfully."""
    try:
        existing_tables = await get_existing_tables(db)
        
        # Check that all critical tables exist
        required_tables = {
            'repos', 'scans', 'scan_summaries', 'scan_jobs',
            'issue_feedback', 'compliance_mappings',
            'pr_security_comments', 'pr_security_reviews'
        }
        
        missing_tables = required_tables - existing_tables
        if missing_tables:
            logger.error(f"Migration validation failed: missing tables {missing_tables}")
            return False
        
        # Check that repos table has required columns
        if 'repos' in existing_tables:
            repos_columns = await get_existing_columns(db, 'repos')
            required_repo_columns = {'id', 'full_name', 'user_id', 'status'}
            if not required_repo_columns.issubset(repos_columns):
                logger.error("Migration validation failed: repos table missing required columns")
                return False
        
        logger.info("Migration validation successful")
        return True
        
    except Exception as e:
        logger.error(f"Migration validation error: {str(e)}")
        return False


async def record_migration_history(db: AsyncSession) -> None:
    """Record migration in migration history table."""
    try:
        # Ensure migration_history table exists
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS migration_history (
                id SERIAL PRIMARY KEY,
                migration_id VARCHAR(100) UNIQUE NOT NULL,
                description TEXT,
                applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                success BOOLEAN NOT NULL DEFAULT TRUE
            )
        """))
        
        # Record this migration
        await db.execute(text("""
            INSERT INTO migration_history (migration_id, description, success)
            VALUES (:migration_id, :description, TRUE)
            ON CONFLICT (migration_id) DO NOTHING
        """), {
            "migration_id": MIGRATION_ID,
            "description": MIGRATION_DESCRIPTION
        })
        
        logger.info(f"Recorded migration {MIGRATION_ID} in history")
        
    except Exception as e:
        logger.error(f"Failed to record migration history: {str(e)}")


async def run_migration() -> bool:
    """
    Run the schema compatibility migration.
    
    Returns:
        bool: True if migration completed successfully
    """
    logger.info(f"Starting migration: {MIGRATION_ID}")
    
    try:
        from core.database import async_session
        
        async with async_session() as db:
            # Check if migration was already applied
            try:
                result = await db.execute(text("""
                    SELECT 1 FROM migration_history 
                    WHERE migration_id = :migration_id AND success = TRUE
                """), {"migration_id": MIGRATION_ID})
                
                if result.fetchone():
                    logger.info(f"Migration {MIGRATION_ID} already applied, skipping")
                    return True
                    
            except Exception:
                # Migration history table might not exist yet
                pass
            
            # Run migration steps
            logger.info("Step 1: Ensuring table compatibility")
            await ensure_table_compatibility(db)
            
            logger.info("Step 2: Creating missing indexes")
            await create_missing_indexes(db)
            
            logger.info("Step 3: Fixing foreign key constraints")
            await fix_foreign_key_constraints(db)
            
            # Commit changes
            await db.commit()
            
            # Validate migration success
            logger.info("Step 4: Validating migration success")
            if not await validate_migration_success(db):
                logger.error("Migration validation failed")
                await db.rollback()
                return False
            
            # Record migration history
            logger.info("Step 5: Recording migration history")
            await record_migration_history(db)
            await db.commit()
            
            logger.info(f"Migration {MIGRATION_ID} completed successfully")
            return True
            
    except Exception as e:
        logger.error(f"Migration {MIGRATION_ID} failed: {str(e)}")
        return False


if __name__ == "__main__":
    import asyncio
    
    async def main():
        success = await run_migration()
        if success:
            print(f"✅ Migration {MIGRATION_ID} completed successfully")
        else:
            print(f"❌ Migration {MIGRATION_ID} failed")
            exit(1)
    
    asyncio.run(main())