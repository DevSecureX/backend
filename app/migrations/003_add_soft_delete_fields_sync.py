#!/usr/bin/env python3
"""
Migration: Add Soft Delete Fields to Users Table (Sync Version)
Version: 003
Date: 2025-08-10

This migration adds soft delete functionality to the users table with
30-day retention policy for security and compliance purposes.

Changes:
- Add is_deleted, deleted_at, deletion_reason columns to users table
- Add performance indexes for cleanup operations
- Preserve data for 30 days after deletion for analysis

Run this script with: python3 migrations/003_add_soft_delete_fields_sync.py
"""

import sqlite3
import os
import sys
from datetime import datetime

def run_migration():
    """Run the migration to add soft delete fields"""
    
    db_path = "devsecurex.db"
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found. Creating new database...")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("Starting migration: Add Soft Delete Fields to Users Table...")
        
        # Check if users table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='users';
        """)
        
        if not cursor.fetchone():
            print("Users table not found. Please run the basic table creation first.")
            return False
        
        # Check if soft delete columns already exist
        cursor.execute("PRAGMA table_info(users);")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'is_deleted' in columns:
            print("Soft delete columns already exist. Migration already applied.")
            return True
        
        print("Adding soft delete columns to users table...")
        
        # Add soft delete columns
        cursor.execute("ALTER TABLE users ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT 0;")
        cursor.execute("ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP;")
        cursor.execute("ALTER TABLE users ADD COLUMN deletion_reason TEXT;")
        
        # Create indexes for performance
        print("Creating indexes for soft delete operations...")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_is_deleted ON users(is_deleted);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_active ON users(is_deleted, deleted_at);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_cleanup ON users(is_deleted, deleted_at) WHERE is_deleted = 1;")
        
        # Commit changes
        conn.commit()
        
        print("Migration completed successfully!")
        print("Users table now supports soft delete with 30-day retention policy")
        
        # Verify the migration
        print("\nVerifying migration...")
        cursor.execute("PRAGMA table_info(users);")
        columns = cursor.fetchall()
        
        soft_delete_columns = [col for col in columns if col[1] in ['is_deleted', 'deleted_at', 'deletion_reason']]
        
        if len(soft_delete_columns) == 3:
            print("✓ All soft delete columns added successfully")
            for col in soft_delete_columns:
                print(f"  - {col[1]} ({col[2]})")
        else:
            print("⚠ Warning: Not all soft delete columns were added")
        
        # Test basic operations
        print("\nTesting soft delete operations...")
        
        # Check current user count
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_deleted = 0;")
        active_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_deleted = 1;")
        deleted_users = cursor.fetchone()[0]
        
        print(f"✓ Active users: {active_users}")
        print(f"✓ Soft-deleted users: {deleted_users}")
        
        return True
        
    except sqlite3.Error as e:
        print(f"Migration failed: {e}")
        if 'conn' in locals():
            conn.rollback()
        return False
    
    finally:
        if 'conn' in locals():
            conn.close()

def verify_migration():
    """Verify that the migration was successful"""
    db_path = "devsecurex.db"
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found.")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("Verifying soft delete migration...")
        
        # Check if columns exist
        cursor.execute("PRAGMA table_info(users);")
        columns = {row[1]: row for row in cursor.fetchall()}
        expected_columns = ['is_deleted', 'deleted_at', 'deletion_reason']
        
        for expected_column in expected_columns:
            if expected_column not in columns:
                print(f"❌ {expected_column} column not found in users table")
                return False
        
        # Verify is_deleted column properties
        is_deleted_info = columns['is_deleted']
        if is_deleted_info[3] != 0:  # NOT NULL check
            print("❌ is_deleted column should be NOT NULL")
            return False
        if is_deleted_info[4] != '0':  # DEFAULT check  
            print("❌ is_deleted column should have DEFAULT 0")
            return False
        
        # Check if indexes exist
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='index' AND tbl_name='users'
            AND name IN ('idx_user_active', 'idx_user_cleanup', 'idx_user_is_deleted');
        """)
        
        indexes = [row[0] for row in cursor.fetchall()]
        expected_indexes = ['idx_user_active', 'idx_user_cleanup', 'idx_user_is_deleted']
        
        for expected_index in expected_indexes:
            if expected_index not in indexes:
                print(f"❌ {expected_index} index not found")
                return False
        
        print("✓ Migration verification successful!")
        print(f"✓ Added columns: {', '.join(expected_columns)}")
        print(f"✓ Created indexes: {', '.join(indexes)}")
        
        return True
        
    except sqlite3.Error as e:
        print(f"Verification failed: {e}")
        return False
    
    finally:
        if 'conn' in locals():
            conn.close()

def rollback_migration():
    """Rollback the migration by removing soft delete fields"""
    db_path = "devsecurex.db"
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found.")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        print("Rolling back soft delete fields migration...")
        
        # SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
        print("Warning: SQLite doesn't support DROP COLUMN. Full rollback requires table recreation.")
        print("This rollback will only drop the indexes.")
        
        # Drop indexes
        print("Dropping soft delete indexes...")
        cursor.execute("DROP INDEX IF EXISTS idx_user_active;")
        cursor.execute("DROP INDEX IF EXISTS idx_user_cleanup;")
        cursor.execute("DROP INDEX IF EXISTS idx_user_is_deleted;")
        
        conn.commit()
        print("Migration rollback completed! (Columns remain but indexes removed)")
        
    except sqlite3.Error as e:
        print(f"Rollback failed: {e}")
        if 'conn' in locals():
            conn.rollback()
    
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX Soft Delete Migration (SQLite)")
    parser.add_argument("--action", choices=["migrate", "verify", "rollback"], 
                       default="migrate", help="Action to perform")
    
    args = parser.parse_args()
    
    if args.action == "migrate":
        success = run_migration()
        sys.exit(0 if success else 1)
    elif args.action == "verify":
        success = verify_migration()
        sys.exit(0 if success else 1)
    elif args.action == "rollback":
        response = input("Are you sure you want to rollback the soft delete migration? This will remove soft delete functionality. (yes/no): ")
        if response.lower() == "yes":
            rollback_migration()
        else:
            print("Rollback cancelled.")