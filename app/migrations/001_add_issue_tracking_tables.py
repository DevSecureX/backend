#!/usr/bin/env python3
"""
Migration: Add Issue Tracking Tables
Version: 001
Date: 2025-08-06

This migration adds the issue_status_tracking and autofix_results tables
to enable comprehensive security issue lifecycle tracking in DevSecureX.

Tables added:
- issue_status_tracking: Tracks individual issues across scans
- autofix_results: Links AI auto-fix results to issue resolution

Run this script with: python -m migrations.001_add_issue_tracking_tables
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

# SQL statements for creating the new tables
CREATE_ISSUE_STATUS_TRACKING_TABLE = """
CREATE TABLE IF NOT EXISTS issue_status_tracking (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    issue_hash VARCHAR(64) NOT NULL UNIQUE,
    repo_full_name VARCHAR(255) NOT NULL,
    first_detected_scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE SET NULL,
    last_seen_scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    resolution_method VARCHAR(100),
    fixed_in_pr_number INTEGER,
    fixed_at TIMESTAMP WITH TIME ZONE,
    fixed_by VARCHAR(100),
    issue_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    file_path TEXT,
    line_number INTEGER,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
"""

CREATE_AUTOFIX_RESULTS_TABLE = """
CREATE TABLE IF NOT EXISTS autofix_results (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    issue_hash VARCHAR(64) REFERENCES issue_status_tracking(issue_hash) ON DELETE CASCADE NOT NULL,
    pr_number INTEGER NOT NULL,
    repo_full_name VARCHAR(255) NOT NULL,
    fix_applied BOOLEAN NOT NULL DEFAULT FALSE,
    fix_content TEXT,
    ai_confidence_score FLOAT,
    verification_scan_id VARCHAR(36) REFERENCES scans(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
"""

# Indexes for performance optimization
CREATE_ISSUE_TRACKING_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_issue_hash ON issue_status_tracking(issue_hash);",
    "CREATE INDEX IF NOT EXISTS idx_issue_repo_status ON issue_status_tracking(repo_full_name, status);",
    "CREATE INDEX IF NOT EXISTS idx_issue_type_severity ON issue_status_tracking(issue_type, severity);",
    "CREATE INDEX IF NOT EXISTS idx_issue_fixed_at ON issue_status_tracking(fixed_at);",
    "CREATE INDEX IF NOT EXISTS idx_issue_pr ON issue_status_tracking(fixed_in_pr_number);",
    "CREATE INDEX IF NOT EXISTS idx_issue_resolution ON issue_status_tracking(resolution_method);",
]

CREATE_AUTOFIX_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_autofix_issue_hash ON autofix_results(issue_hash);",
    "CREATE INDEX IF NOT EXISTS idx_autofix_pr ON autofix_results(repo_full_name, pr_number);",
    "CREATE INDEX IF NOT EXISTS idx_autofix_verification ON autofix_results(verification_scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_autofix_applied ON autofix_results(fix_applied);",
]

# Trigger for updating updated_at timestamp
CREATE_UPDATED_AT_TRIGGER = """
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_issue_status_tracking_updated_at
    BEFORE UPDATE ON issue_status_tracking
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
"""

# Comments for documentation
ADD_TABLE_COMMENTS = [
    """
    COMMENT ON TABLE issue_status_tracking IS 
    'Tracks individual security issues across scans to monitor resolution lifecycle';
    """,
    """
    COMMENT ON COLUMN issue_status_tracking.issue_hash IS 
    'Unique SHA256 hash identifying an issue (file_path + line + rule_id + description)';
    """,
    """
    COMMENT ON COLUMN issue_status_tracking.status IS 
    'Issue status: open, fixed_auto, fixed_manual, fixed_dependency, false_positive';
    """,
    """
    COMMENT ON TABLE autofix_results IS 
    'Tracks AI auto-fix results and links them to issue resolution';
    """,
    """
    COMMENT ON COLUMN autofix_results.fix_applied IS 
    'Whether the AI-generated fix was successfully applied';
    """,
]

async def run_migration():
    """Run the migration to add issue tracking tables"""
    
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable not set")
    
    # Create async engine
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    try:
        async with engine.begin() as conn:
            print("Starting migration: Add Issue Tracking Tables...")
            
            # Create issue_status_tracking table
            print("Creating issue_status_tracking table...")
            await conn.execute(text(CREATE_ISSUE_STATUS_TRACKING_TABLE))
            
            # Create autofix_results table
            print("Creating autofix_results table...")
            await conn.execute(text(CREATE_AUTOFIX_RESULTS_TABLE))
            
            # Create indexes for issue_status_tracking
            print("Creating indexes for issue_status_tracking...")
            for index_sql in CREATE_ISSUE_TRACKING_INDEXES:
                await conn.execute(text(index_sql))
            
            # Create indexes for autofix_results
            print("Creating indexes for autofix_results...")
            for index_sql in CREATE_AUTOFIX_INDEXES:
                await conn.execute(text(index_sql))
            
            # Create updated_at trigger
            print("Creating updated_at trigger...")
            await conn.execute(text(CREATE_UPDATED_AT_TRIGGER))
            
            # Add table comments
            print("Adding table documentation...")
            for comment_sql in ADD_TABLE_COMMENTS:
                await conn.execute(text(comment_sql))
            
            print("Migration completed successfully!")
            
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
            # Check if tables exist
            result = await conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('issue_status_tracking', 'autofix_results');
            """))
            
            tables = [row[0] for row in result]
            
            if 'issue_status_tracking' not in tables:
                raise Exception("issue_status_tracking table not found")
            
            if 'autofix_results' not in tables:
                raise Exception("autofix_results table not found")
            
            # Check if indexes exist
            result = await conn.execute(text("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename IN ('issue_status_tracking', 'autofix_results');
            """))
            
            indexes = [row[0] for row in result]
            expected_indexes = [
                'idx_issue_hash', 'idx_issue_repo_status', 'idx_autofix_issue_hash', 'idx_autofix_pr'
            ]
            
            for expected_index in expected_indexes:
                if expected_index not in indexes:
                    print(f"Warning: Index {expected_index} not found")
            
            print("Migration verification successful!")
            print(f"Created tables: {', '.join(tables)}")
            print(f"Created indexes: {len(indexes)} indexes")
            
    finally:
        await engine.dispose()

async def rollback_migration():
    """Rollback the migration by dropping the tables"""
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    try:
        async with engine.begin() as conn:
            print("Rolling back migration...")
            
            # Drop tables in reverse order (due to foreign key constraints)
            await conn.execute(text("DROP TABLE IF EXISTS autofix_results CASCADE;"))
            await conn.execute(text("DROP TABLE IF EXISTS issue_status_tracking CASCADE;"))
            
            # Drop the trigger function
            await conn.execute(text("DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;"))
            
            print("Migration rollback completed!")
            
    finally:
        await engine.dispose()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX Issue Tracking Migration")
    parser.add_argument("--action", choices=["migrate", "verify", "rollback"], 
                       default="migrate", help="Action to perform")
    
    args = parser.parse_args()
    
    if args.action == "migrate":
        asyncio.run(run_migration())
    elif args.action == "verify":
        asyncio.run(verify_migration())
    elif args.action == "rollback":
        response = input("Are you sure you want to rollback the migration? This will delete all issue tracking data. (yes/no): ")
        if response.lower() == "yes":
            asyncio.run(rollback_migration())
        else:
            print("Rollback cancelled.")