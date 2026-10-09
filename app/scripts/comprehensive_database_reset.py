#!/usr/bin/env python3
"""
Comprehensive Database Reset Script for DevSecureX

This script provides a complete solution to reset and rebuild the database schema
to resolve issues caused by backup restoration and schema mismatches.

Features:
1. Safety backup before reset
2. Complete data wipe while preserving table structure
3. Schema validation and comparison
4. Fresh table recreation with proper migrations
5. Verification of table structure consistency

Usage:
    python app/scripts/comprehensive_database_reset.py [--dry-run] [--force] [--backup-only]
    
Author: DevSecureX Team
"""

import asyncio
import argparse
import logging
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import json
import hashlib
import subprocess

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from sqlalchemy import (
    text, inspect, create_engine, MetaData, 
    Table, Column, String, Integer, DateTime, 
    Boolean, Text, JSON, Float, ForeignKey, Index
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from core.database import engine, async_session, Base
from core.config import DATABASE_URL, get_database_url


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'database_reset_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class DatabaseResetManager:
    """Comprehensive database reset and schema management"""
    
    def __init__(self, dry_run: bool = False, force: bool = False):
        self.dry_run = dry_run
        self.force = force
        self.backup_file = None
        self.schema_comparison = {}
        self.reset_summary = {}
        
        # Get sync engine for schema operations
        sync_db_url = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
        self.sync_engine = create_engine(sync_db_url)
        self.async_engine = engine
        
        logger.info(f"Initialized DatabaseResetManager (dry_run={dry_run}, force={force})")
    
    async def create_safety_backup(self) -> str:
        """Create a comprehensive backup before any destructive operations"""
        logger.info("Creating safety backup of current database state...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"safety_backup_{timestamp}.sql"
        backup_path = os.path.join("scripts", "db-backup", "backups", backup_filename)
        
        # Ensure backup directory exists
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create backup at: {backup_path}")
            return backup_path
        
        try:
            # Extract connection parameters
            if "postgresql+asyncpg://" in DATABASE_URL:
                # Parse PostgreSQL URL
                url_parts = DATABASE_URL.replace("postgresql+asyncpg://", "").split("@")
                user_pass = url_parts[0].split(":")
                host_db = url_parts[1].split("/")
                host_port = host_db[0].split(":")
                
                username = user_pass[0]
                password = user_pass[1]
                host = host_port[0]
                port = host_port[1] if len(host_port) > 1 else "5432"
                database = host_db[1]
                
                # Create pg_dump command
                cmd = [
                    "docker", "exec", "devsecurex-db",
                    "pg_dump", "-U", username, "-d", database,
                    "--verbose", "--no-owner", "--no-privileges",
                    "--clean", "--create"
                ]
                
                logger.info(f"Running backup command: {' '.join(cmd[:4])}...")
                
                # Run backup
                env = os.environ.copy()
                env['PGPASSWORD'] = password
                
                with open(backup_path, 'w') as backup_file:
                    result = subprocess.run(cmd, stdout=backup_file, stderr=subprocess.PIPE, 
                                          text=True, env=env)
                
                if result.returncode == 0:
                    logger.info(f"✅ Backup created successfully: {backup_path}")
                    self.backup_file = backup_path
                    return backup_path
                else:
                    logger.error(f"❌ Backup failed: {result.stderr}")
                    raise Exception(f"Backup failed: {result.stderr}")
                    
            else:
                raise ValueError("Only PostgreSQL databases are supported for backup")
                
        except Exception as e:
            logger.error(f"❌ Failed to create backup: {str(e)}")
            raise
    
    async def get_current_schema(self) -> Dict[str, Any]:
        """Get current database schema information"""
        logger.info("Analyzing current database schema...")
        
        schema_info = {
            "tables": {},
            "indexes": {},
            "constraints": {},
            "statistics": {}
        }
        
        try:
            # Use sync engine for schema inspection
            inspector = inspect(self.sync_engine)
            
            # Get all table names
            table_names = inspector.get_table_names()
            schema_info["statistics"]["total_tables"] = len(table_names)
            
            logger.info(f"Found {len(table_names)} tables in database")
            
            for table_name in table_names:
                # Get table columns
                columns = inspector.get_columns(table_name)
                schema_info["tables"][table_name] = {
                    "columns": columns,
                    "column_count": len(columns)
                }
                
                # Get indexes
                indexes = inspector.get_indexes(table_name)
                schema_info["indexes"][table_name] = indexes
                
                # Get foreign keys
                foreign_keys = inspector.get_foreign_keys(table_name)
                schema_info["constraints"][table_name] = {
                    "foreign_keys": foreign_keys
                }
                
                logger.debug(f"Table {table_name}: {len(columns)} columns, {len(indexes)} indexes")
            
            return schema_info
            
        except Exception as e:
            logger.error(f"❌ Failed to analyze current schema: {str(e)}")
            raise
    
    async def get_expected_schema(self) -> Dict[str, Any]:
        """Get expected schema from SQLAlchemy models"""
        logger.info("Analyzing expected schema from models...")
        
        expected_schema = {
            "tables": {},
            "indexes": {},
            "constraints": {},
            "statistics": {}
        }
        
        try:
            # Import all model modules to ensure they're registered
            from app.auth import models as auth_models
            from app.repos import models as repos_models
            from app.scans import models as scans_models
            from app.support import models as support_models
            from app.custom_rules import models as custom_rules_models
            from app.ai_assistant import models as ai_models
            
            # Get all tables from Base metadata
            metadata = Base.metadata
            expected_schema["statistics"]["total_tables"] = len(metadata.tables)
            
            logger.info(f"Expected {len(metadata.tables)} tables from models")
            
            for table_name, table in metadata.tables.items():
                # Get columns
                columns = []
                for column in table.columns:
                    col_info = {
                        "name": column.name,
                        "type": str(column.type),
                        "nullable": column.nullable,
                        "primary_key": column.primary_key,
                        "foreign_keys": [str(fk) for fk in column.foreign_keys]
                    }
                    columns.append(col_info)
                
                expected_schema["tables"][table_name] = {
                    "columns": columns,
                    "column_count": len(columns)
                }
                
                # Get indexes
                indexes = []
                for index in table.indexes:
                    idx_info = {
                        "name": index.name,
                        "columns": [col.name for col in index.columns],
                        "unique": index.unique
                    }
                    indexes.append(idx_info)
                
                expected_schema["indexes"][table_name] = indexes
                
                logger.debug(f"Model {table_name}: {len(columns)} columns, {len(indexes)} indexes")
            
            return expected_schema
            
        except Exception as e:
            logger.error(f"❌ Failed to analyze expected schema: {str(e)}")
            raise
    
    async def compare_schemas(self) -> Dict[str, Any]:
        """Compare current vs expected schemas"""
        logger.info("Comparing current schema with expected schema...")
        
        current_schema = await self.get_current_schema()
        expected_schema = await self.get_expected_schema()
        
        comparison = {
            "missing_tables": [],
            "extra_tables": [],
            "table_mismatches": {},
            "statistics": {
                "current_tables": current_schema["statistics"]["total_tables"],
                "expected_tables": expected_schema["statistics"]["total_tables"],
                "issues_found": 0
            }
        }
        
        current_tables = set(current_schema["tables"].keys())
        expected_tables = set(expected_schema["tables"].keys())
        
        # Find missing and extra tables
        comparison["missing_tables"] = list(expected_tables - current_tables)
        comparison["extra_tables"] = list(current_tables - expected_tables)
        
        # Compare common tables
        common_tables = current_tables & expected_tables
        for table_name in common_tables:
            current_cols = {col["name"]: col for col in current_schema["tables"][table_name]["columns"]}
            expected_cols = {col["name"]: col for col in expected_schema["tables"][table_name]["columns"]}
            
            table_issues = {
                "missing_columns": list(set(expected_cols.keys()) - set(current_cols.keys())),
                "extra_columns": list(set(current_cols.keys()) - set(expected_cols.keys())),
                "type_mismatches": []
            }
            
            # Check column type mismatches
            for col_name in set(current_cols.keys()) & set(expected_cols.keys()):
                current_type = str(current_cols[col_name].get("type", "")).upper()
                expected_type = str(expected_cols[col_name].get("type", "")).upper()
                
                if current_type != expected_type:
                    table_issues["type_mismatches"].append({
                        "column": col_name,
                        "current_type": current_type,
                        "expected_type": expected_type
                    })
            
            if any([table_issues["missing_columns"], table_issues["extra_columns"], 
                   table_issues["type_mismatches"]]):
                comparison["table_mismatches"][table_name] = table_issues
        
        # Calculate total issues
        comparison["statistics"]["issues_found"] = (
            len(comparison["missing_tables"]) +
            len(comparison["extra_tables"]) +
            len(comparison["table_mismatches"])
        )
        
        self.schema_comparison = comparison
        
        # Log comparison results
        if comparison["statistics"]["issues_found"] == 0:
            logger.info("✅ No schema mismatches found")
        else:
            logger.warning(f"⚠️ Found {comparison['statistics']['issues_found']} schema issues:")
            if comparison["missing_tables"]:
                logger.warning(f"  - Missing tables: {comparison['missing_tables']}")
            if comparison["extra_tables"]:
                logger.warning(f"  - Extra tables: {comparison['extra_tables']}")
            if comparison["table_mismatches"]:
                logger.warning(f"  - Table mismatches: {list(comparison['table_mismatches'].keys())}")
        
        return comparison
    
    async def get_table_row_counts(self) -> Dict[str, int]:
        """Get row counts for all tables"""
        logger.info("Getting current table row counts...")
        
        row_counts = {}
        
        try:
            async with async_session() as session:
                # Get all table names
                result = await session.execute(text("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """))
                tables = [row[0] for row in result.fetchall()]
                
                for table_name in tables:
                    try:
                        result = await session.execute(text(f"SELECT COUNT(*) FROM \"{table_name}\""))
                        count = result.scalar()
                        row_counts[table_name] = count
                        logger.debug(f"Table {table_name}: {count} rows")
                    except Exception as e:
                        logger.warning(f"Could not count rows in {table_name}: {str(e)}")
                        row_counts[table_name] = -1
        
        except Exception as e:
            logger.error(f"❌ Failed to get row counts: {str(e)}")
            raise
        
        total_rows = sum(count for count in row_counts.values() if count > 0)
        logger.info(f"Total rows across all tables: {total_rows}")
        
        return row_counts
    
    async def truncate_all_user_data(self) -> Dict[str, int]:
        """Truncate all user data while preserving table structure"""
        logger.info("Truncating all user data...")
        
        if self.dry_run:
            logger.info("[DRY RUN] Would truncate all user data")
            return {}
        
        # Get row counts before truncation
        before_counts = await self.get_table_row_counts()
        
        try:
            async with async_session() as session:
                # Disable foreign key checks temporarily
                await session.execute(text("SET session_replication_role = replica;"))
                
                # Get all user tables (exclude system tables)
                user_tables = [
                    "users", "blacklisted_tokens", "mail_list", "feedback", "login_attempts",
                    "api_keys", "data_export_requests", "repos", "scans", "scan_summaries",
                    "ai_pattern_cache", "scan_jobs", "compliance_mappings", "issue_feedback",
                    "scan_trends", "pr_security_comments", "pr_security_reviews",
                    "issue_status_tracking", "autofix_results", "ai_rule_generation",
                    "rule_version_history", "rule_collections", "rule_collection_items",
                    "rule_comments", "rule_test_results", "rule_usage_analytics",
                    "rule_feedback", "support_queries", "support_responses",
                    "community_rules", "community_rule_votes", "chat_sessions",
                    "chat_messages", "ai_knowledge_base", "ai_interactions",
                    "ai_prompt_templates", "ai_analysis_cache"
                ]
                
                truncated_counts = {}
                
                for table in user_tables:
                    try:
                        # Check if table exists
                        result = await session.execute(text(f"""
                            SELECT COUNT(*) FROM information_schema.tables 
                            WHERE table_name = '{table}' AND table_schema = 'public'
                        """))
                        
                        if result.scalar() > 0:
                            await session.execute(text(f'TRUNCATE TABLE "{table}" CASCADE;'))
                            truncated_counts[table] = before_counts.get(table, 0)
                            logger.info(f"✅ Truncated {table} ({before_counts.get(table, 0)} rows)")
                        else:
                            logger.debug(f"Table {table} does not exist, skipping")
                    
                    except Exception as e:
                        logger.warning(f"Failed to truncate {table}: {str(e)}")
                
                # Re-enable foreign key checks
                await session.execute(text("SET session_replication_role = DEFAULT;"))
                
                await session.commit()
                logger.info("✅ All user data truncated successfully")
                
                return truncated_counts
        
        except Exception as e:
            logger.error(f"❌ Failed to truncate user data: {str(e)}")
            raise
    
    async def drop_and_recreate_tables(self) -> bool:
        """Drop all tables and recreate from models"""
        logger.info("Dropping and recreating all tables from models...")
        
        if self.dry_run:
            logger.info("[DRY RUN] Would drop and recreate all tables")
            return True
        
        try:
            # Import all models to ensure they're registered
            from app.auth import models as auth_models
            from app.repos import models as repos_models
            from app.scans import models as scans_models
            from app.support import models as support_models
            from app.custom_rules import models as custom_rules_models
            from app.ai_assistant import models as ai_models
            
            # Drop all tables using async engine
            async with self.async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.drop_all)
                logger.info("✅ All tables dropped")
            
            # Recreate all tables using async engine
            async with self.async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                logger.info("✅ All tables recreated from models")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to drop and recreate tables: {str(e)}")
            raise
    
    async def verify_final_schema(self) -> bool:
        """Verify that the final schema matches expectations"""
        logger.info("Verifying final schema consistency...")
        
        try:
            comparison = await self.compare_schemas()
            
            if comparison["statistics"]["issues_found"] == 0:
                logger.info("✅ Final schema verification passed - all tables match models")
                return True
            else:
                logger.error("❌ Final schema verification failed")
                logger.error(f"Issues found: {comparison['statistics']['issues_found']}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Schema verification failed: {str(e)}")
            return False
    
    async def test_basic_functionality(self) -> bool:
        """Test basic database functionality after reset"""
        logger.info("Testing basic database functionality...")
        
        if self.dry_run:
            logger.info("[DRY RUN] Would test basic functionality")
            return True
        
        try:
            async with async_session() as session:
                # Test basic queries on key tables
                test_queries = [
                    ("users", "SELECT COUNT(*) FROM users"),
                    ("repos", "SELECT COUNT(*) FROM repos"),
                    ("scans", "SELECT COUNT(*) FROM scans"),
                    ("community_rules", "SELECT COUNT(*) FROM community_rules"),
                ]
                
                for table_name, query in test_queries:
                    try:
                        result = await session.execute(text(query))
                        count = result.scalar()
                        logger.debug(f"✅ {table_name}: {count} rows (functional)")
                    except Exception as e:
                        logger.error(f"❌ {table_name} query failed: {str(e)}")
                        return False
                
                # Test a simple insert/delete operation
                await session.execute(text("""
                    INSERT INTO users (username, email, hashed_password) 
                    VALUES ('test_reset_user', 'test@reset.com', 'hashed_password')
                """))
                
                await session.execute(text("""
                    DELETE FROM users WHERE username = 'test_reset_user'
                """))
                
                await session.commit()
                logger.info("✅ Basic functionality test passed")
                return True
                
        except Exception as e:
            logger.error(f"❌ Basic functionality test failed: {str(e)}")
            return False
    
    async def generate_reset_summary(self) -> Dict[str, Any]:
        """Generate a comprehensive reset summary"""
        timestamp = datetime.now().isoformat()
        
        summary = {
            "reset_timestamp": timestamp,
            "dry_run": self.dry_run,
            "force_mode": self.force,
            "backup_file": self.backup_file,
            "schema_comparison": self.schema_comparison,
            "operations_completed": [],
            "success": False
        }
        
        return summary
    
    async def execute_full_reset(self) -> bool:
        """Execute the complete database reset process"""
        logger.info("🚀 Starting comprehensive database reset...")
        
        try:
            # Step 1: Create safety backup
            if not self.dry_run:
                backup_file = await self.create_safety_backup()
                logger.info(f"✅ Backup created: {backup_file}")
            
            # Step 2: Compare schemas
            await self.compare_schemas()
            logger.info("✅ Schema comparison completed")
            
            # Step 3: Get current row counts
            if not self.dry_run:
                row_counts = await self.get_table_row_counts()
                total_rows = sum(count for count in row_counts.values() if count > 0)
                logger.info(f"Current database contains {total_rows} total rows")
                
                if total_rows > 1000 and not self.force:
                    logger.warning("⚠️ Database contains significant data (>1000 rows)")
                    logger.warning("Use --force flag to proceed with reset")
                    return False
            
            # Step 4: Drop and recreate all tables
            await self.drop_and_recreate_tables()
            logger.info("✅ Tables dropped and recreated")
            
            # Step 5: Verify final schema
            schema_ok = await self.verify_final_schema()
            if not schema_ok:
                logger.error("❌ Schema verification failed")
                return False
            
            # Step 6: Test basic functionality
            functionality_ok = await self.test_basic_functionality()
            if not functionality_ok:
                logger.error("❌ Basic functionality test failed")
                return False
            
            logger.info("🎉 Database reset completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Database reset failed: {str(e)}")
            return False


async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Comprehensive Database Reset for DevSecureX")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Show what would be done without executing")
    parser.add_argument("--force", action="store_true",
                       help="Force reset even with large amounts of data")
    parser.add_argument("--backup-only", action="store_true",
                       help="Only create backup, don't reset")
    parser.add_argument("--schema-check-only", action="store_true",
                       help="Only compare schemas, don't reset")
    
    args = parser.parse_args()
    
    # Initialize reset manager
    reset_manager = DatabaseResetManager(dry_run=args.dry_run, force=args.force)
    
    try:
        if args.backup_only:
            logger.info("📦 Creating backup only...")
            backup_file = await reset_manager.create_safety_backup()
            logger.info(f"✅ Backup created: {backup_file}")
            return
        
        if args.schema_check_only:
            logger.info("🔍 Schema comparison only...")
            await reset_manager.compare_schemas()
            return
        
        # Execute full reset
        success = await reset_manager.execute_full_reset()
        
        if success:
            logger.info("✅ Database reset completed successfully!")
            logger.info("🔧 You can now start the application with a clean database")
            sys.exit(0)
        else:
            logger.error("❌ Database reset failed!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("🛑 Reset cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())