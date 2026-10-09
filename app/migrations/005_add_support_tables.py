#!/usr/bin/env python3
"""
Migration 005: Add Support Tables
Creates support_queries and support_responses tables for the help & support system
"""

import asyncio
import sys
import os
from pathlib import Path

# Add app directory to Python path
app_dir = Path(__file__).parent.parent
sys.path.insert(0, str(app_dir))

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from core.config import get_database_url
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MIGRATION_ID = "005"
DESCRIPTION = "Add Support Tables"

async def migrate_up(engine):
    """Apply migration - Add support tables"""
    async with engine.begin() as conn:
        logger.info("Creating support_queries table...")
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS support_queries (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                subject VARCHAR(255) NOT NULL,
                category VARCHAR(50) NOT NULL DEFAULT 'general',
                priority VARCHAR(20) NOT NULL DEFAULT 'medium',
                message TEXT NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'open',
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE,
                resolved_at TIMESTAMP WITH TIME ZONE,
                
                CONSTRAINT chk_category CHECK (category IN ('general', 'technical', 'billing', 'feature_request')),
                CONSTRAINT chk_priority CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
                CONSTRAINT chk_status CHECK (status IN ('open', 'in_progress', 'resolved', 'closed'))
            );
        """))
        
        logger.info("Creating support_responses table...")
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS support_responses (
                id SERIAL PRIMARY KEY,
                query_id INTEGER NOT NULL REFERENCES support_queries(id) ON DELETE CASCADE,
                responder_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                message TEXT NOT NULL,
                is_admin_response BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """))
        
        logger.info("Creating indexes for support tables...")
        await conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_support_queries_user_id ON support_queries(user_id);
            CREATE INDEX IF NOT EXISTS idx_support_queries_status ON support_queries(status);
            CREATE INDEX IF NOT EXISTS idx_support_queries_category ON support_queries(category);
            CREATE INDEX IF NOT EXISTS idx_support_queries_priority ON support_queries(priority);
            CREATE INDEX IF NOT EXISTS idx_support_queries_created_at ON support_queries(created_at);
            CREATE INDEX IF NOT EXISTS idx_support_queries_user_status ON support_queries(user_id, status);
            
            CREATE INDEX IF NOT EXISTS idx_support_responses_query_id ON support_responses(query_id);
            CREATE INDEX IF NOT EXISTS idx_support_responses_responder_id ON support_responses(responder_id);
            CREATE INDEX IF NOT EXISTS idx_support_responses_created_at ON support_responses(created_at);
        """))
        
        logger.info("Support tables created successfully!")

async def migrate_down(engine):
    """Rollback migration - Remove support tables"""
    async with engine.begin() as conn:
        logger.info("Dropping support tables...")
        await conn.execute(text("DROP TABLE IF EXISTS support_responses CASCADE;"))
        await conn.execute(text("DROP TABLE IF EXISTS support_queries CASCADE;"))
        logger.info("Support tables dropped successfully!")

async def add_migration_record(engine):
    """Add migration record to history"""
    async with engine.begin() as conn:
        await conn.execute(text("""
            INSERT INTO migration_history (migration_id, description, applied_at)
            VALUES (:migration_id, :description, CURRENT_TIMESTAMP)
            ON CONFLICT (migration_id) DO NOTHING
        """), {
            "migration_id": MIGRATION_ID,
            "description": DESCRIPTION
        })

async def remove_migration_record(engine):
    """Remove migration record from history"""
    async with engine.begin() as conn:
        await conn.execute(text("""
            DELETE FROM migration_history WHERE migration_id = :migration_id
        """), {"migration_id": MIGRATION_ID})

async def check_migration_applied(engine):
    """Check if migration is already applied"""
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text("""
                SELECT 1 FROM migration_history WHERE migration_id = :migration_id
            """), {"migration_id": MIGRATION_ID})
            return result.scalar() is not None
    except Exception:
        # If migration_history table doesn't exist, migration is not applied
        return False

async def main():
    if len(sys.argv) < 3:
        print(f"Usage: python {sys.argv[0]} --action [migrate|rollback]")
        sys.exit(1)
    
    action = None
    for i, arg in enumerate(sys.argv):
        if arg == '--action' and i + 1 < len(sys.argv):
            action = sys.argv[i + 1]
            break
    
    if action not in ['migrate', 'rollback']:
        print("Action must be either 'migrate' or 'rollback'")
        sys.exit(1)
    
    # Get database URL from environment
    database_url = get_database_url()
    
    if not database_url:
        logger.error("DATABASE_URL not found in environment variables")
        sys.exit(1)
    
    # Convert to async URL if needed
    if database_url.startswith('postgresql://'):
        database_url = database_url.replace('postgresql://', 'postgresql+asyncpg://', 1)
    elif database_url.startswith('sqlite:'):
        database_url = database_url.replace('sqlite:', 'sqlite+aiosqlite:', 1)
    
    engine = create_async_engine(database_url)
    
    try:
        if action == 'migrate':
            # Check if already applied
            is_applied = await check_migration_applied(engine)
            if is_applied:
                logger.info(f"Migration {MIGRATION_ID} is already applied")
                return
            
            logger.info(f"Applying migration {MIGRATION_ID}: {DESCRIPTION}")
            await migrate_up(engine)
            await add_migration_record(engine)
            logger.info(f"Migration {MIGRATION_ID} applied successfully!")
            
        elif action == 'rollback':
            # Check if applied
            is_applied = await check_migration_applied(engine)
            if not is_applied:
                logger.info(f"Migration {MIGRATION_ID} is not applied")
                return
            
            logger.info(f"Rolling back migration {MIGRATION_ID}: {DESCRIPTION}")
            await migrate_down(engine)
            await remove_migration_record(engine)
            logger.info(f"Migration {MIGRATION_ID} rolled back successfully!")
            
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        sys.exit(1)
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())