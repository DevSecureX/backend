#!/usr/bin/env python3
"""
Migration 007: Fix schema compatibility after database backup restoration

This migration addresses the schema differences between the restored database backup
and the current application schema, specifically for the repos table.

Issues Fixed:
1. Missing 'is_connected' column (backup uses 'status' instead) 
2. Missing 'branch' column (backup uses 'default_branch' instead)
3. Missing 'archived' and 'disabled' columns
4. Convert old status values to boolean is_connected values

Created: 2025-08-29
"""

import asyncio
import sys
import os
import argparse
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text, MetaData, inspect
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add app directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.config import get_database_url

class BackupSchemaCompatibilityMigration:
    def __init__(self):
        self.database_url = get_database_url()
        self.engine = create_async_engine(self.database_url)
    
    async def check_table_structure(self):
        """Check current repos table structure"""
        logger.info("Checking current repos table structure...")
        
        async with self.engine.begin() as conn:
            # Check what columns exist
            result = await conn.execute(text("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_name = 'repos' 
                ORDER BY ordinal_position;
            """))
            
            columns = {}
            for row in result.fetchall():
                columns[row[0]] = {
                    'type': row[1],
                    'nullable': row[2],
                    'default': row[3]
                }
            
            logger.info(f"Found {len(columns)} columns in repos table")
            
            # Check for specific columns we need
            missing_columns = []
            if 'is_connected' not in columns:
                missing_columns.append('is_connected')
            if 'branch' not in columns:
                missing_columns.append('branch')
            if 'archived' not in columns:
                missing_columns.append('archived')
            if 'disabled' not in columns:
                missing_columns.append('disabled')
                
            has_status = 'status' in columns
            has_default_branch = 'default_branch' in columns
            
            return {
                'columns': columns,
                'missing_columns': missing_columns,
                'has_status': has_status,
                'has_default_branch': has_default_branch
            }
    
    async def migrate_up(self):
        """Apply the schema compatibility migration"""
        logger.info("🚀 Starting backup schema compatibility migration...")
        
        try:
            # Check current structure
            structure = await self.check_table_structure()
            
            if not structure['missing_columns']:
                logger.info("✅ Schema is already compatible, no migration needed")
                return True
                
            async with self.engine.begin() as conn:
                logger.info("📝 Applying schema compatibility fixes...")
                
                # Step 1: Add missing columns if they don't exist
                if 'is_connected' in structure['missing_columns']:
                    logger.info("Adding is_connected column...")
                    await conn.execute(text("""
                        ALTER TABLE repos 
                        ADD COLUMN is_connected BOOLEAN DEFAULT TRUE;
                    """))
                
                if 'branch' in structure['missing_columns']:
                    logger.info("Adding branch column...")
                    await conn.execute(text("""
                        ALTER TABLE repos 
                        ADD COLUMN branch VARCHAR(255);
                    """))
                
                if 'archived' in structure['missing_columns']:
                    logger.info("Adding archived column...")
                    await conn.execute(text("""
                        ALTER TABLE repos 
                        ADD COLUMN archived BOOLEAN DEFAULT FALSE;
                    """))
                
                if 'disabled' in structure['missing_columns']:
                    logger.info("Adding disabled column...")
                    await conn.execute(text("""
                        ALTER TABLE repos 
                        ADD COLUMN disabled BOOLEAN DEFAULT FALSE;
                    """))
                
                # Step 2: Migrate data from old columns to new columns
                if structure['has_status'] and 'is_connected' in structure['missing_columns']:
                    logger.info("Converting status values to is_connected boolean...")
                    # Convert status to is_connected: 'active' -> true, others -> false
                    await conn.execute(text("""
                        UPDATE repos 
                        SET is_connected = CASE 
                            WHEN status = 'active' THEN TRUE 
                            ELSE FALSE 
                        END;
                    """))
                
                if structure['has_default_branch'] and 'branch' in structure['missing_columns']:
                    logger.info("Copying default_branch to branch column...")
                    await conn.execute(text("""
                        UPDATE repos 
                        SET branch = default_branch 
                        WHERE default_branch IS NOT NULL;
                    """))
                
                # Step 3: Set reasonable defaults for missing data
                logger.info("Setting reasonable defaults...")
                await conn.execute(text("""
                    UPDATE repos 
                    SET branch = 'main' 
                    WHERE branch IS NULL;
                """))
                
                # Step 4: Create indexes for performance
                logger.info("Creating performance indexes...")
                try:
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_repos_is_connected 
                        ON repos(is_connected);
                    """))
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_repos_user_connected 
                        ON repos(user_id, is_connected);
                    """))
                    await conn.execute(text("""
                        CREATE INDEX IF NOT EXISTS idx_repos_archived_disabled 
                        ON repos(archived, disabled) WHERE archived = FALSE AND disabled = FALSE;
                    """))
                except Exception as e:
                    logger.warning(f"Index creation warning: {e}")
                
                logger.info("✅ Schema compatibility migration completed successfully!")
                
                # Step 5: Verify the changes
                await self.verify_migration()
                return True
                
        except Exception as e:
            logger.error(f"❌ Migration failed: {str(e)}")
            raise
    
    async def verify_migration(self):
        """Verify the migration worked correctly"""
        logger.info("🔍 Verifying migration results...")
        
        async with self.engine.begin() as conn:
            # Check column existence
            result = await conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'repos' 
                AND column_name IN ('is_connected', 'branch', 'archived', 'disabled')
                ORDER BY column_name;
            """))
            
            found_columns = [row[0] for row in result.fetchall()]
            expected_columns = ['archived', 'branch', 'disabled', 'is_connected']
            
            if set(found_columns) == set(expected_columns):
                logger.info("✅ All required columns are present")
            else:
                missing = set(expected_columns) - set(found_columns)
                logger.warning(f"⚠️ Missing columns: {missing}")
            
            # Check data conversion
            result = await conn.execute(text("""
                SELECT 
                    COUNT(*) as total_repos,
                    COUNT(*) FILTER (WHERE is_connected = TRUE) as connected_repos,
                    COUNT(*) FILTER (WHERE branch IS NOT NULL) as repos_with_branch,
                    COUNT(*) FILTER (WHERE archived = FALSE) as non_archived_repos
                FROM repos;
            """))
            
            stats = result.fetchone()
            logger.info(f"📊 Migration stats:")
            logger.info(f"   Total repositories: {stats[0]}")
            logger.info(f"   Connected repositories: {stats[1]}")
            logger.info(f"   Repositories with branch: {stats[2]}")
            logger.info(f"   Non-archived repositories: {stats[3]}")
    
    async def migrate_down(self):
        """Rollback the migration (for testing purposes)"""
        logger.info("⏪ Rolling back schema compatibility migration...")
        
        try:
            async with self.engine.begin() as conn:
                # Remove the columns we added (be careful in production!)
                logger.warning("This will remove is_connected, branch, archived, disabled columns")
                
                await conn.execute(text("DROP INDEX IF EXISTS idx_repos_is_connected;"))
                await conn.execute(text("DROP INDEX IF EXISTS idx_repos_user_connected;"))
                await conn.execute(text("DROP INDEX IF EXISTS idx_repos_archived_disabled;"))
                
                await conn.execute(text("ALTER TABLE repos DROP COLUMN IF EXISTS is_connected;"))
                await conn.execute(text("ALTER TABLE repos DROP COLUMN IF EXISTS branch;"))
                await conn.execute(text("ALTER TABLE repos DROP COLUMN IF EXISTS archived;"))
                await conn.execute(text("ALTER TABLE repos DROP COLUMN IF EXISTS disabled;"))
                
                logger.info("✅ Migration rollback completed")
                return True
                
        except Exception as e:
            logger.error(f"❌ Rollback failed: {str(e)}")
            raise
    
    async def close(self):
        """Close database connection"""
        if self.engine:
            await self.engine.dispose()

async def main():
    parser = argparse.ArgumentParser(description='Backup Schema Compatibility Migration')
    parser.add_argument('--action', choices=['migrate', 'rollback', 'check'], 
                       default='migrate', help='Action to perform')
    args = parser.parse_args()
    
    migration = BackupSchemaCompatibilityMigration()
    
    try:
        if args.action == 'check':
            structure = await migration.check_table_structure()
            print(f"Missing columns: {structure['missing_columns']}")
            print(f"Has status column: {structure['has_status']}")
            print(f"Has default_branch column: {structure['has_default_branch']}")
            
        elif args.action == 'migrate':
            success = await migration.migrate_up()
            if success:
                print("✅ Schema compatibility migration completed successfully!")
            else:
                print("❌ Migration failed")
                sys.exit(1)
                
        elif args.action == 'rollback':
            success = await migration.migrate_down()
            if success:
                print("✅ Migration rollback completed")
            else:
                print("❌ Rollback failed")
                sys.exit(1)
                
    except Exception as e:
        logger.error(f"Migration error: {str(e)}")
        sys.exit(1)
    finally:
        await migration.close()

if __name__ == "__main__":
    asyncio.run(main())