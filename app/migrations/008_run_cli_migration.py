#!/usr/bin/env python3
"""
Run CLI Scan Tables Migration (008)
Standalone runner for CLI scan infrastructure migration
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

async def run_cli_migration():
    """Run the CLI scan tables migration"""
    try:
        from core.database import engine
        # Import the migration module using importlib
        import importlib.util
        migration_file = Path(__file__).parent / "008_add_cli_scan_tables.py"
        spec = importlib.util.spec_from_file_location("cli_migration", migration_file)
        cli_migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_migration)
        upgrade = cli_migration.upgrade
        
        async with engine.begin() as conn:
            logger.info("Starting CLI scan tables migration (008)...")
            await upgrade(conn)
            logger.info("CLI scan tables migration completed successfully!")
            
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        raise

async def rollback_cli_migration():
    """Rollback the CLI scan tables migration"""
    try:
        from core.database import engine
        # Import the migration module using importlib
        import importlib.util
        migration_file = Path(__file__).parent / "008_add_cli_scan_tables.py"
        spec = importlib.util.spec_from_file_location("cli_migration", migration_file)
        cli_migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli_migration)
        downgrade = cli_migration.downgrade
        
        response = input("Are you sure you want to rollback the CLI migration? This will delete all CLI data. (yes/no): ")
        if response.lower() != "yes":
            logger.info("Rollback cancelled")
            return
            
        async with engine.begin() as conn:
            logger.info("Starting CLI scan tables rollback...")
            await downgrade(conn)
            logger.info("CLI scan tables rollback completed!")
            
    except Exception as e:
        logger.error(f"Rollback failed: {str(e)}")
        raise

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "migrate"
    
    if action == "migrate":
        asyncio.run(run_cli_migration())
    elif action == "rollback":
        asyncio.run(rollback_cli_migration())
    else:
        print("Usage: python 008_run_cli_migration.py [migrate|rollback]")
        sys.exit(1)