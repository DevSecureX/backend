#!/usr/bin/env python3
"""
Create Migration History Table

This creates a table to track all database migrations that have been applied.
Run this before any other migrations.

Run: python app/migrations/000_create_migration_history.py
"""

import asyncio
import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from core.config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def create_migration_history_table():
    """Create the migration history tracking table"""
    settings = get_settings()
    
    # Adjust connection string for async
    if 'sqlite' in settings.database_url.lower():
        db_url = settings.database_url.replace('sqlite:///', 'sqlite+aiosqlite:///')
    else:
        db_url = settings.database_url.replace('postgresql://', 'postgresql+asyncpg://')
    
    engine = create_async_engine(db_url, echo=False)
    
    async with engine.begin() as conn:
        try:
            # Create migration history table
            await conn.execute(text("""
                CREATE TABLE IF NOT EXISTS migration_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    migration_name VARCHAR(255) UNIQUE NOT NULL,
                    applied_at TIMESTAMP NOT NULL,
                    rolled_back_at TIMESTAMP,
                    status VARCHAR(50) NOT NULL DEFAULT 'completed',
                    notes TEXT
                )
            """))
            
            logger.info("✅ Migration history table created successfully!")
            
        except Exception as e:
            # Try PostgreSQL syntax if SQLite fails
            try:
                await conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS migration_history (
                        id SERIAL PRIMARY KEY,
                        migration_name VARCHAR(255) UNIQUE NOT NULL,
                        applied_at TIMESTAMP NOT NULL,
                        rolled_back_at TIMESTAMP,
                        status VARCHAR(50) NOT NULL DEFAULT 'completed',
                        notes TEXT
                    )
                """))
                logger.info("✅ Migration history table created successfully (PostgreSQL)!")
            except Exception as e2:
                logger.error(f"Failed to create migration history table: {e2}")
                raise
    
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(create_migration_history_table())