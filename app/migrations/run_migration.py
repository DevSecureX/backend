#!/usr/bin/env python3
"""
DevSecureX Migration Runner

Simple script to run database migrations for DevSecureX.
This provides a convenient interface for running specific migrations.

Usage:
    python run_migration.py --migration 001 --action migrate
    python run_migration.py --migration 001 --action verify
    python run_migration.py --migration 001 --action rollback
"""

import asyncio
import argparse
import importlib
import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def main():
    parser = argparse.ArgumentParser(description="DevSecureX Database Migration Runner")
    parser.add_argument("--migration", required=True, 
                       help="Migration number (e.g., 001)")
    parser.add_argument("--action", choices=["migrate", "verify", "rollback"], 
                       default="migrate", help="Action to perform")
    parser.add_argument("--list", action="store_true", 
                       help="List available migrations")
    
    args = parser.parse_args()
    
    if args.list:
        list_migrations()
        return
    
    # Import and run the specific migration
    migration_mapping = {
        "001": "migrations.001_add_issue_tracking_tables",
        "002": "migrations.002_add_ai_assistant_tables"
    }
    
    migration_name = migration_mapping.get(args.migration)
    
    if not migration_name:
        print(f"Unknown migration {args.migration}")
        print("Available migrations: " + ", ".join(migration_mapping.keys()))
        sys.exit(1)
    
    try:
        migration_module = importlib.import_module(migration_name)
        
        if args.action == "migrate":
            print(f"Running migration {args.migration}...")
            asyncio.run(migration_module.run_migration())
        elif args.action == "verify":
            print(f"Verifying migration {args.migration}...")
            asyncio.run(migration_module.verify_migration())
        elif args.action == "rollback":
            response = input(f"Are you sure you want to rollback migration {args.migration}? This may delete data. (yes/no): ")
            if response.lower() == "yes":
                print(f"Rolling back migration {args.migration}...")
                asyncio.run(migration_module.rollback_migration())
            else:
                print("Rollback cancelled.")
                
    except ModuleNotFoundError:
        print(f"Migration {args.migration} not found!")
        print("Available migrations:")
        list_migrations()
        sys.exit(1)
    except Exception as e:
        print(f"Migration failed: {e}")
        sys.exit(1)

def list_migrations():
    """List all available migrations"""
    migrations_dir = Path(__file__).parent / "migrations"
    
    if not migrations_dir.exists():
        print("No migrations directory found!")
        return
    
    migration_files = sorted(migrations_dir.glob("[0-9][0-9][0-9]_*.py"))
    
    if not migration_files:
        print("No migrations found!")
        return
    
    print("Available migrations:")
    for migration_file in migration_files:
        migration_number = migration_file.stem[:3]
        migration_name = migration_file.stem[4:].replace("_", " ").title()
        print(f"  {migration_number}: {migration_name}")

if __name__ == "__main__":
    main()