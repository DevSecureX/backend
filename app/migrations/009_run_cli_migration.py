#!/usr/bin/env python3
"""
Run CLI Session Name Migration (009)
Standalone runner for adding session name column to CLI sessions
"""

import asyncio
import sys
import os
from pathlib import Path
import logging

# Add the app directory to Python path
app_dir = Path(__file__).parent.parent
sys.path.insert(0, str(app_dir))

# Load environment variables
from dotenv import load_dotenv
load_dotenv(app_dir.parent / ".env")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_session_name_migration():
    """Run the CLI session name migration"""
    try:
        from core.database import engine
        # Import the migration module using importlib
        import importlib.util
        migration_file = Path(__file__).parent / "009_add_session_name_column.py"
        spec = importlib.util.spec_from_file_location("session_name_migration", migration_file)
        session_name_migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(session_name_migration)
        upgrade = session_name_migration.upgrade
        
        async with engine.begin() as conn:
            logger.info("Starting CLI session name migration (009)...")
            await upgrade(conn)
            logger.info("CLI session name migration completed successfully!")
            
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        raise

async def rollback_session_name_migration():
    """Rollback the CLI session name migration"""
    try:
        from core.database import engine
        # Import the migration module using importlib
        import importlib.util
        migration_file = Path(__file__).parent / "009_add_session_name_column.py"
        spec = importlib.util.spec_from_file_location("session_name_migration", migration_file)
        session_name_migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(session_name_migration)
        downgrade = session_name_migration.downgrade
        
        response = input("Are you sure you want to rollback the session name migration? This will remove the name column. (yes/no): ")
        if response.lower() != "yes":
            logger.info("Rollback cancelled")
            return
            
        async with engine.begin() as conn:
            logger.info("Starting CLI session name rollback...")
            await downgrade(conn)
            logger.info("CLI session name rollback completed!")
            
    except Exception as e:
        logger.error(f"Rollback failed: {str(e)}")
        raise

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "migrate"
    
    if action == "migrate":
        asyncio.run(run_session_name_migration())
    elif action == "rollback":
        asyncio.run(rollback_session_name_migration())
    else:
        print("Usage: python 009_run_cli_migration.py [migrate|rollback]")
        sys.exit(1)