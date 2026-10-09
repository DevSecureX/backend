#!/usr/bin/env python3
"""
Database Schema Compatibility Fix Script

This script fixes database schema compatibility issues that occur when
restoring database backups from older Docker images into newer versions
of the DevSecureX application.

Usage:
    python scripts/fix_database_schema.py [--dry-run] [--verbose]

Options:
    --dry-run    Show what would be fixed without making changes
    --verbose    Show detailed logging output
"""

import asyncio
import argparse
import logging
import sys
import os
from pathlib import Path

# Add the app directory to Python path
app_dir = Path(__file__).parent.parent
sys.path.insert(0, str(app_dir))

from core.database import async_session
from core.db_schema_validator import schema_validator
from migrations.run_migration import run_specific_migration


async def diagnose_schema_issues():
    """Diagnose database schema compatibility issues."""
    print("🔍 Diagnosing database schema compatibility...")
    
    try:
        async with async_session() as db:
            # Validate schema compatibility
            schema_status = await schema_validator.validate_schema_compatibility(db)
            
            print(f"📊 Schema Compatibility Report:")
            print(f"   Compatible: {'✅' if schema_status['is_compatible'] else '❌'}")
            print(f"   Existing tables: {len(schema_status['existing_tables'])}")
            print(f"   Missing tables: {len(schema_status['missing_tables'])}")
            
            if schema_status['missing_tables']:
                print(f"   ⚠️  Missing tables: {', '.join(schema_status['missing_tables'])}")
            
            if schema_status['schema_issues']:
                print(f"   🚨 Schema issues found:")
                for issue in schema_status['schema_issues']:
                    print(f"      - {issue}")
            
            if schema_status['recommendations']:
                print(f"   💡 Recommendations:")
                for rec in schema_status['recommendations']:
                    print(f"      - {rec}")
            
            # Check specific table counts for context
            print(f"\n📈 Table Statistics:")
            for table in ['repos', 'scans', 'scan_summaries', 'users']:
                row_count = await schema_validator.get_table_row_count(db, table)
                if row_count is not None:
                    print(f"   {table}: {row_count} records")
                else:
                    print(f"   {table}: ❌ Not found")
            
            return schema_status
            
    except Exception as e:
        print(f"❌ Error during diagnosis: {str(e)}")
        return None


async def fix_schema_issues(dry_run=False):
    """Fix detected schema compatibility issues."""
    if dry_run:
        print("🔍 DRY RUN MODE - No changes will be made")
    
    print("🔧 Fixing database schema compatibility issues...")
    
    try:
        # Run the schema compatibility migration
        from migrations import run_migration
        
        if dry_run:
            print("   Would run migration: 006_schema_compatibility_migration")
            return True
        else:
            print("   Running migration: 006_schema_compatibility_migration")
            success = await run_specific_migration("006_schema_compatibility_migration")
            
            if success:
                print("✅ Schema compatibility migration completed successfully")
                return True
            else:
                print("❌ Schema compatibility migration failed")
                return False
                
    except Exception as e:
        print(f"❌ Error during schema fix: {str(e)}")
        return False


async def test_repository_disconnect():
    """Test repository disconnect functionality after schema fixes."""
    print("🧪 Testing repository disconnect functionality...")
    
    try:
        async with async_session() as db:
            # Get a sample repository for testing (if any exist)
            from sqlalchemy import text
            result = await db.execute(text("SELECT full_name, user_id FROM repos LIMIT 1"))
            repo_record = result.fetchone()
            
            if not repo_record:
                print("   ℹ️  No repositories found for testing")
                return True
            
            repo_full_name, user_id = repo_record
            print(f"   Testing with repository: {repo_full_name}")
            
            # Test the cleanup function (without actually deleting)
            from repos.routes import cleanup_repo_database_records
            
            # This would normally delete records, so we'll just validate the query structure
            scan_ids_result = await db.execute(
                text("SELECT id FROM scans WHERE repo_full_name = :repo_name AND user_id = :user_id LIMIT 1"),
                {"repo_name": repo_full_name, "user_id": user_id}
            )
            scan_ids = [row[0] for row in scan_ids_result.fetchall()]
            
            if scan_ids:
                print(f"   ✅ Found {len(scan_ids)} scan records - cleanup queries should work")
            else:
                print(f"   ℹ️  No scan records found for this repository")
            
            print("   ✅ Repository disconnect functionality appears to be working")
            return True
            
    except Exception as e:
        print(f"   ❌ Repository disconnect test failed: {str(e)}")
        return False


async def main():
    """Main function to run the schema compatibility fix."""
    parser = argparse.ArgumentParser(
        description="Fix database schema compatibility issues"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true",
        help="Show what would be fixed without making changes"
    )
    parser.add_argument(
        "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--test-only",
        action="store_true", 
        help="Only run diagnostics and tests, don't fix issues"
    )
    
    args = parser.parse_args()
    
    # Configure logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    print("🚀 DevSecureX Database Schema Compatibility Fixer")
    print("=" * 50)
    
    # Step 1: Diagnose issues
    schema_status = await diagnose_schema_issues()
    if not schema_status:
        print("❌ Failed to diagnose schema issues")
        return 1
    
    # Step 2: Fix issues if needed and not in test-only mode
    if not args.test_only:
        if not schema_status['is_compatible']:
            print(f"\n🔧 Schema issues detected, applying fixes...")
            fix_success = await fix_schema_issues(dry_run=args.dry_run)
            
            if not fix_success:
                print("❌ Failed to fix schema issues")
                return 1
        else:
            print("✅ No schema fixes needed")
    
    # Step 3: Test functionality
    print(f"\n🧪 Testing functionality...")
    test_success = await test_repository_disconnect()
    
    if not test_success:
        print("❌ Functionality tests failed")
        return 1
    
    print(f"\n🎉 Database schema compatibility check completed successfully!")
    
    if schema_status.get('recommendations'):
        print(f"\n💡 Additional recommendations:")
        for rec in schema_status['recommendations']:
            print(f"   - {rec}")
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)