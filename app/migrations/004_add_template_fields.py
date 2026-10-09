#!/usr/bin/env python3
"""
Migration: Add Template Support Fields
Adds template-specific fields to community_rules table for hybrid template system
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from core.config import DATABASE_URL
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_migration():
    """Add template support fields to community_rules table"""
    
    database_url = get_database_url()
    engine = create_async_engine(database_url)
    
    migration_queries = [
        # Template-specific fields
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS is_template BOOLEAN NOT NULL DEFAULT FALSE;
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS template_category VARCHAR(50) DEFAULT NULL;
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS complexity VARCHAR(20) DEFAULT 'basic';
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS example_usage TEXT DEFAULT NULL;
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS pattern_template TEXT DEFAULT NULL;
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS template_source VARCHAR(20) DEFAULT 'community';
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS is_curated BOOLEAN NOT NULL DEFAULT FALSE;
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS use_case TEXT DEFAULT NULL;
        """,
        
        """
        ALTER TABLE community_rules 
        ADD COLUMN IF NOT EXISTS placeholders JSON DEFAULT NULL;
        """,
        
        # Add indexes for template queries
        """
        CREATE INDEX IF NOT EXISTS idx_rules_template 
        ON community_rules(is_template, template_category, complexity);
        """,
        
        """
        CREATE INDEX IF NOT EXISTS idx_rules_template_source 
        ON community_rules(template_source, is_curated, is_public);
        """,
        
        """
        CREATE INDEX IF NOT EXISTS idx_rules_template_popular 
        ON community_rules(is_template, upvotes, usage_count) 
        WHERE is_template = TRUE;
        """,
    ]
    
    try:
        async with engine.begin() as conn:
            logger.info("🚀 Starting template fields migration...")
            
            for i, query in enumerate(migration_queries, 1):
                logger.info(f"📝 Executing migration step {i}/{len(migration_queries)}")
                await conn.execute(text(query))
            
            logger.info("✅ Template fields migration completed successfully!")
            
    except Exception as e:
        logger.error(f"❌ Migration failed: {e}")
        raise
    finally:
        await engine.dispose()

async def run_rollback():
    """Rollback template support fields (remove columns)"""
    
    database_url = get_database_url()
    engine = create_async_engine(database_url)
    
    rollback_queries = [
        "DROP INDEX IF EXISTS idx_rules_template_popular;",
        "DROP INDEX IF EXISTS idx_rules_template_source;", 
        "DROP INDEX IF EXISTS idx_rules_template;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS placeholders;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS use_case;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS is_curated;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS template_source;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS pattern_template;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS example_usage;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS complexity;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS template_category;",
        "ALTER TABLE community_rules DROP COLUMN IF EXISTS is_template;",
    ]
    
    try:
        async with engine.begin() as conn:
            logger.info("🔄 Starting template fields rollback...")
            
            for i, query in enumerate(rollback_queries, 1):
                logger.info(f"📝 Executing rollback step {i}/{len(rollback_queries)}")
                await conn.execute(text(query))
            
            logger.info("✅ Template fields rollback completed!")
            
    except Exception as e:
        logger.error(f"❌ Rollback failed: {e}")
        raise
    finally:
        await engine.dispose()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Template Support Migration')
    parser.add_argument('--action', choices=['migrate', 'rollback'], 
                       default='migrate', help='Migration action')
    
    args = parser.parse_args()
    
    if args.action == 'migrate':
        asyncio.run(run_migration())
    else:
        asyncio.run(run_rollback())