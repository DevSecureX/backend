"""
Migration 012: Add pr_number field to scan_jobs table

This migration adds the pr_number field to the scan_jobs table to maintain
consistency with the scans table and enable better PR scan tracking.

FIXES APPLIED:
1. Added pr_number column to scan_jobs table
2. Added index for pr_number field for performance
3. Ensures PR scans are properly tracked in both job and scan records

Date: 2025-01-09
"""

import asyncpg
import asyncio
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Migration metadata
MIGRATION_ID = "012_add_pr_number_to_scan_jobs"
MIGRATION_NAME = "Add PR Number Field to ScanJob Model"
MIGRATION_VERSION = "1.0.0"

async def upgrade(connection):
    """Add pr_number column to scan_jobs table"""
    logger.info(f"Starting migration: {MIGRATION_NAME}")
    
    try:
        # Add pr_number column to scan_jobs table
        logger.info("Adding pr_number column to scan_jobs table...")
        await connection.execute("""
            ALTER TABLE scan_jobs 
            ADD COLUMN IF NOT EXISTS pr_number INTEGER;
        """)
        
        # Add index for pr_number
        logger.info("Adding index for pr_number field...")
        await connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_job_pr 
            ON scan_jobs(pr_number);
        """)
        
        logger.info("✅ Migration 012 completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Migration 012 failed: {e}")
        raise

async def downgrade(connection):
    """Remove pr_number column from scan_jobs table"""
    logger.info(f"Downgrading migration: {MIGRATION_NAME}")
    
    try:
        # Remove index first
        await connection.execute("""
            DROP INDEX IF EXISTS idx_job_pr;
        """)
        
        # Remove pr_number column
        await connection.execute("""
            ALTER TABLE scan_jobs 
            DROP COLUMN IF EXISTS pr_number;
        """)
        
        logger.info("✅ Migration 012 downgrade completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Migration 012 downgrade failed: {e}")
        raise

if __name__ == "__main__":
    # For standalone execution, we'll need to connect manually
    import os
    import asyncpg
    
    async def run_migration():
        DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://devsecurex:devsecurex_secure_2024@localhost:5432/devsecurex_db")
        
        conn = await asyncpg.connect(DATABASE_URL)
        try:
            await upgrade(conn)
        finally:
            await conn.close()
    
    asyncio.run(run_migration())