"""
Add user_id column to scan_jobs table - DevSecureX Production Fix

This migration fixes the critical issue where scans don't appear in the GET /scans API
due to missing user_id association in the scan_jobs table. This was working in 
prod-release but broken in the current branch.

CRITICAL FIXES:
- Adds user_id column to scan_jobs table for proper user association
- Creates composite foreign key constraint with repos table
- Adds performance indexes for user-based queries
- Populates existing records with user_id from job_data JSON field

This restores the working functionality from prod-release branch.
"""

import asyncpg
import asyncio
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Migration metadata
MIGRATION_ID = "011_add_user_id_to_scan_jobs"
MIGRATION_NAME = "Add user_id to scan_jobs table - Fix scan visibility"
MIGRATION_VERSION = "1.0.0"

async def upgrade(connection):
    """
    Add user_id column to scan_jobs table and fix scan visibility
    """
    logger.info(f"Starting migration: {MIGRATION_NAME}")
    
    try:
        # 1. Add user_id column (nullable initially for existing records)
        logger.info("Adding user_id column to scan_jobs table...")
        await connection.execute("""
            ALTER TABLE scan_jobs 
            ADD COLUMN IF NOT EXISTS user_id INTEGER;
        """)
        
        # 2. Create index on user_id for performance
        logger.info("Creating performance index on user_id...")
        await connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_job_user_id 
            ON scan_jobs (user_id);
        """)
        
        # 3. Populate user_id for existing records from job_data JSON
        logger.info("Populating user_id for existing scan_jobs...")
        
        # Get all scan_jobs with NULL user_id that have job_data
        jobs_result = await connection.fetch("""
            SELECT id, job_data 
            FROM scan_jobs 
            WHERE user_id IS NULL AND job_data IS NOT NULL
        """)
        
        logger.info(f"Found {len(jobs_result)} scan_jobs to update with user_id")
        
        updated_count = 0
        for job_record in jobs_result:
            job_id = job_record['id']
            job_data = job_record['job_data']
            
            try:
                # Extract user_id from job_data JSON
                if isinstance(job_data, dict):
                    user_id = job_data.get('user_id')
                elif isinstance(job_data, str):
                    data = json.loads(job_data)
                    user_id = data.get('user_id')
                else:
                    logger.warning(f"Unexpected job_data type for job {job_id}: {type(job_data)}")
                    continue
                
                if user_id:
                    await connection.execute("""
                        UPDATE scan_jobs 
                        SET user_id = $1 
                        WHERE id = $2
                    """, user_id, job_id)
                    updated_count += 1
                else:
                    logger.warning(f"No user_id found in job_data for job {job_id}")
                    
            except Exception as e:
                logger.error(f"Error updating job {job_id}: {e}")
                continue
        
        logger.info(f"Successfully updated {updated_count} scan_jobs with user_id")
        
        # 4. Add composite foreign key constraint
        # First check if repos table exists and has the expected structure
        repos_check = await connection.fetchval("""
            SELECT COUNT(*) FROM information_schema.tables 
            WHERE table_name = 'repos' AND table_schema = 'public'
        """)
        
        if repos_check > 0:
            # Check if repos table has the expected columns
            repos_columns = await connection.fetch("""
                SELECT column_name FROM information_schema.columns 
                WHERE table_name = 'repos' AND table_schema = 'public'
                AND column_name IN ('full_name', 'user_id')
            """)
            
            column_names = [col['column_name'] for col in repos_columns]
            
            if 'full_name' in column_names and 'user_id' in column_names:
                logger.info("Creating composite foreign key constraint...")
                
                # Drop existing constraint if it exists
                await connection.execute("""
                    ALTER TABLE scan_jobs 
                    DROP CONSTRAINT IF EXISTS fk_scan_jobs_repo_user;
                """)
                
                # Add composite foreign key constraint
                await connection.execute("""
                    ALTER TABLE scan_jobs 
                    ADD CONSTRAINT fk_scan_jobs_repo_user 
                    FOREIGN KEY (repo_full_name, user_id) 
                    REFERENCES repos (full_name, user_id);
                """)
                
                logger.info("Composite foreign key constraint created successfully")
            else:
                logger.warning("Repos table missing required columns for FK constraint")
        else:
            logger.warning("Repos table not found - skipping FK constraint creation")
        
        # 5. Add composite performance index
        logger.info("Creating composite performance index...")
        await connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_job_user_repo 
            ON scan_jobs (user_id, repo_full_name);
        """)
        
        # 6. Add index for repo queries
        await connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_job_repo_user 
            ON scan_jobs (repo_full_name, user_id);
        """)
        
        # 7. Now make user_id NOT NULL for future records
        # First check if all existing records now have user_id
        null_user_count = await connection.fetchval("""
            SELECT COUNT(*) FROM scan_jobs WHERE user_id IS NULL
        """)
        
        if null_user_count == 0:
            logger.info("Making user_id column NOT NULL...")
            await connection.execute("""
                ALTER TABLE scan_jobs 
                ALTER COLUMN user_id SET NOT NULL;
            """)
        else:
            logger.warning(f"Skipping NOT NULL constraint - {null_user_count} records still have NULL user_id")
        
        # 8. Record migration in migration history
        await connection.execute("""
            INSERT INTO migration_history (migration_id, migration_name, version, applied_at, description)
            VALUES ($1, $2, $3, NOW(), $4)
            ON CONFLICT (migration_id) DO UPDATE SET
                applied_at = NOW(),
                version = EXCLUDED.version,
                description = EXCLUDED.description;
        """, MIGRATION_ID, MIGRATION_NAME, MIGRATION_VERSION, 
        f"Added user_id column to scan_jobs table and populated {updated_count} existing records")
        
        logger.info(f"Migration {MIGRATION_NAME} completed successfully")
        
    except Exception as e:
        logger.error(f"Migration {MIGRATION_NAME} failed: {e}")
        raise


async def downgrade(connection):
    """
    Remove user_id column from scan_jobs table
    """
    logger.info(f"Rolling back migration: {MIGRATION_NAME}")
    
    try:
        # Remove indexes
        await connection.execute("DROP INDEX IF EXISTS idx_scan_job_user_repo;")
        await connection.execute("DROP INDEX IF EXISTS idx_scan_job_repo_user;")  
        await connection.execute("DROP INDEX IF EXISTS idx_scan_job_user_id;")
        
        # Remove foreign key constraint
        await connection.execute("""
            ALTER TABLE scan_jobs 
            DROP CONSTRAINT IF EXISTS fk_scan_jobs_repo_user;
        """)
        
        # Remove user_id column
        await connection.execute("""
            ALTER TABLE scan_jobs 
            DROP COLUMN IF EXISTS user_id;
        """)
        
        # Update migration history
        await connection.execute("""
            UPDATE migration_history 
            SET applied_at = NULL, description = description || ' (ROLLED BACK)'
            WHERE migration_id = $1;
        """, MIGRATION_ID)
        
        logger.info(f"Migration {MIGRATION_NAME} rolled back successfully")
        
    except Exception as e:
        logger.error(f"Rollback of {MIGRATION_NAME} failed: {e}")
        raise


# Migration runner
async def run_migration():
    """Execute the migration"""
    import os
    from urllib.parse import urlparse
    
    # Get database URL from environment
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL environment variable not set")
    
    # Parse database URL
    parsed = urlparse(database_url)
    
    # Create connection
    conn = await asyncpg.connect(
        host=parsed.hostname,
        port=parsed.port or 5432,
        user=parsed.username,
        password=parsed.password,
        database=parsed.path.lstrip('/')
    )
    
    try:
        await upgrade(conn)
        print(f"Migration {MIGRATION_ID} completed successfully!")
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(run_migration())