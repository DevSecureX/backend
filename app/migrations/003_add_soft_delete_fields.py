#!/usr/bin/env python3
"""
Migration: Add Soft Delete Fields to Users Table
Version: 003
Date: 2025-08-10

This migration adds soft delete functionality to the users table with
30-day retention policy for security and compliance purposes.

Changes:
- Add is_deleted, deleted_at, deletion_reason columns to users table
- Add performance indexes for cleanup operations
- Preserve data for 30 days after deletion for analysis

Run this script with: python run_migration.py --migration 003 --action migrate
"""

import asyncio
import logging
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import os
import sys

# Add the parent directory to the Python path to import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import DATABASE_URL

logger = logging.getLogger(__name__)

# SQL statements for adding soft delete fields to users table
ADD_SOFT_DELETE_FIELDS = """
-- Add soft delete fields to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS deletion_reason VARCHAR(255);
"""

# Add indexes for soft delete performance
CREATE_SOFT_DELETE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_user_active ON users(is_deleted, deleted_at);",
    "CREATE INDEX IF NOT EXISTS idx_user_cleanup ON users(is_deleted, deleted_at) WHERE is_deleted = TRUE;",
    "CREATE INDEX IF NOT EXISTS idx_user_is_deleted ON users(is_deleted);",
]

# Table comments for documentation
ADD_COLUMN_COMMENTS = [
    "COMMENT ON COLUMN users.is_deleted IS 'Soft delete flag - TRUE when user account is deleted but preserved for retention period';",
    "COMMENT ON COLUMN users.deleted_at IS 'Timestamp when user account was soft deleted';",
    "COMMENT ON COLUMN users.deletion_reason IS 'Reason for account deletion (user requested, admin action, etc.)';",
]

async def run_migration():
    """Run the migration to add soft delete fields"""
    
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable not set")
    
    # Create async engine
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    try:
        async with engine.begin() as conn:
            print("Starting migration: Add Soft Delete Fields to Users Table...")
            
            # Add soft delete columns
            print("Adding soft delete columns to users table...")
            await conn.execute(text(ADD_SOFT_DELETE_FIELDS))
            
            # Create indexes for performance
            print("Creating indexes for soft delete operations...")
            for index_sql in CREATE_SOFT_DELETE_INDEXES:
                await conn.execute(text(index_sql))
            
            # Add column comments
            print("Adding column documentation...")
            for comment_sql in ADD_COLUMN_COMMENTS:
                await conn.execute(text(comment_sql))
            
            print("Migration completed successfully!")
            print("Users table now supports soft delete with 30-day retention policy")
            
    except Exception as e:
        print(f"Migration failed: {e}")
        raise
    
    finally:
        await engine.dispose()

async def verify_migration():
    """Verify that the migration was successful"""
    engine = create_async_engine(DATABASE_URL, echo=False)
    
    try:
        async with engine.begin() as conn:
            # Check if columns exist
            result = await conn.execute(text("""
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns 
                WHERE table_schema = 'public' 
                AND table_name = 'users'
                AND column_name IN ('is_deleted', 'deleted_at', 'deletion_reason')
                ORDER BY column_name;
            """))
            
            columns = {row[0]: row for row in result}
            expected_columns = ['is_deleted', 'deleted_at', 'deletion_reason']
            
            for expected_column in expected_columns:
                if expected_column not in columns:
                    raise Exception(f"{expected_column} column not found in users table")
            
            # Verify is_deleted column properties
            is_deleted_info = columns['is_deleted']
            if is_deleted_info[2] != 'NO':  # is_nullable
                raise Exception("is_deleted column should be NOT NULL")
            if 'false' not in str(is_deleted_info[3]).lower():  # column_default
                raise Exception("is_deleted column should have DEFAULT FALSE")
            
            # Check if indexes exist
            result = await conn.execute(text("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'users'
                AND indexname IN (
                    'idx_user_active', 'idx_user_cleanup', 'idx_user_is_deleted'
                );
            """))
            
            indexes = [row[0] for row in result]
            expected_indexes = ['idx_user_active', 'idx_user_cleanup', 'idx_user_is_deleted']
            
            for expected_index in expected_indexes:
                if expected_index not in indexes:
                    raise Exception(f"{expected_index} index not found")
            
            print("Migration verification successful!")
            print(f"Added columns: {', '.join(columns.keys())}")
            print(f"Created indexes: {', '.join(indexes)}")
            
            # Test basic operations
            print("\nTesting soft delete operations...")
            
            # Check current user count
            result = await conn.execute(text("SELECT COUNT(*) FROM users WHERE is_deleted = FALSE;"))
            active_users = result.scalar()
            
            result = await conn.execute(text("SELECT COUNT(*) FROM users WHERE is_deleted = TRUE;"))
            deleted_users = result.scalar()
            
            print(f"✓ Active users: {active_users}")
            print(f"✓ Soft-deleted users: {deleted_users}")
            
            # Test index performance
            result = await conn.execute(text("""
                EXPLAIN (FORMAT JSON) 
                SELECT * FROM users WHERE is_deleted = FALSE AND deleted_at IS NULL;
            """))
            
            execution_plan = result.scalar()
            print(f"✓ Query optimization check completed")
            
    finally:
        await engine.dispose()

async def rollback_migration():
    """Rollback the migration by removing soft delete fields"""
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    try:
        async with engine.begin() as conn:
            print("Rolling back soft delete fields migration...")
            
            # Drop indexes first
            print("Dropping soft delete indexes...")
            await conn.execute(text("DROP INDEX IF EXISTS idx_user_active;"))
            await conn.execute(text("DROP INDEX IF EXISTS idx_user_cleanup;"))
            await conn.execute(text("DROP INDEX IF EXISTS idx_user_is_deleted;"))
            
            # Remove columns
            print("Removing soft delete columns...")
            await conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS is_deleted;"))
            await conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS deleted_at;"))
            await conn.execute(text("ALTER TABLE users DROP COLUMN IF EXISTS deletion_reason;"))
            
            print("Migration rollback completed!")
            
    finally:
        await engine.dispose()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX Soft Delete Migration")
    parser.add_argument("--action", choices=["migrate", "verify", "rollback"], 
                       default="migrate", help="Action to perform")
    
    args = parser.parse_args()
    
    if args.action == "migrate":
        asyncio.run(run_migration())
    elif args.action == "verify":
        asyncio.run(verify_migration())
    elif args.action == "rollback":
        response = input("Are you sure you want to rollback the soft delete migration? This will remove soft delete functionality. (yes/no): ")
        if response.lower() == "yes":
            asyncio.run(rollback_migration())
        else:
            print("Rollback cancelled.")