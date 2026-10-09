"""
Migration 009: Add Name Column to CLI Scan Sessions
Adds the missing 'name' column to cli_scan_sessions table to fix session naming issue
"""

from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

MIGRATION_ID = "009_add_session_name_column"
DESCRIPTION = "Add name column to cli_scan_sessions table for proper session naming"

async def upgrade(connection):
    """Add name column to cli_scan_sessions table"""
    
    try:
        # Check if the name column already exists
        result = await connection.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'cli_scan_sessions' 
              AND column_name = 'name'
        """))
        
        existing_column = result.fetchone()
        
        if existing_column:
            logger.info("Name column already exists in cli_scan_sessions table")
            return
        
        # Add the name column
        await connection.execute(text("""
            ALTER TABLE cli_scan_sessions 
            ADD COLUMN name VARCHAR(255) NOT NULL DEFAULT 'Unnamed Session'
        """))
        
        logger.info("Added name column to cli_scan_sessions table")
        
        # Update existing sessions to have more descriptive names based on creation time
        await connection.execute(text("""
            UPDATE cli_scan_sessions 
            SET name = CASE 
                WHEN name = 'Unnamed Session' OR name IS NULL THEN 
                    'Session ' || TO_CHAR(started_at, 'YYYY-MM-DD HH24:MI')
                ELSE name 
            END
            WHERE name = 'Unnamed Session' OR name IS NULL
        """))
        
        logger.info("Updated existing sessions with descriptive names")
        
        # Add index on name column for better query performance
        await connection.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_cli_session_name ON cli_scan_sessions(name)
        """))
        
        logger.info("Added index on session name column")
        
        # Add comment to document the column
        await connection.execute(text("""
            COMMENT ON COLUMN cli_scan_sessions.name IS 'User-provided session name for identification'
        """))
        
        logger.info("Migration 009: Session name column added successfully")
        
    except Exception as e:
        logger.error(f"Error in migration 009: {str(e)}")
        raise


async def downgrade(connection):
    """Remove name column from cli_scan_sessions table (for development/testing only)"""
    
    try:
        # Drop the index first
        await connection.execute(text("""
            DROP INDEX IF EXISTS idx_cli_session_name
        """))
        
        # Remove the name column
        await connection.execute(text("""
            ALTER TABLE cli_scan_sessions DROP COLUMN IF EXISTS name
        """))
        
        logger.info("Migration 009: Session name column removed successfully")
        
    except Exception as e:
        logger.error(f"Error in migration 009 downgrade: {str(e)}")
        raise