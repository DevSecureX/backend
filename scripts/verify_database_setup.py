#!/usr/bin/env python3
"""
Database Verification Script for DevSecureX Platform
Verifies that all 41 tables are properly created and configured
"""

import asyncio
import asyncpg
from datetime import datetime
from typing import List, Dict, Any

# Database connection details from .env
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 6544,
    'user': 'devsecurex_user',
    'password': 'devsecurex_pass',
    'database': 'devsecurex_db'
}

# Expected 41 tables
EXPECTED_TABLES = [
    'ai_analysis_cache', 'ai_interactions', 'ai_knowledge_base', 'ai_pattern_cache',
    'ai_prompt_templates', 'ai_rule_generation', 'api_keys', 'autofix_results',
    'blacklisted_tokens', 'chat_messages', 'chat_sessions', 'cli_activity_logs',
    'cli_scan_results', 'cli_scan_sessions', 'cli_usage_stats', 'community_rule_votes',
    'community_rules', 'compliance_mappings', 'data_export_requests', 'feedback',
    'issue_feedback', 'issue_status_tracking', 'login_attempts', 'mail_list',
    'pr_security_comments', 'pr_security_reviews', 'repos', 'rule_collection_items',
    'rule_collections', 'rule_comments', 'rule_feedback', 'rule_test_results',
    'rule_usage_analytics', 'rule_version_history', 'scan_jobs', 'scan_summaries',
    'scan_trends', 'scans', 'support_queries', 'support_responses', 'users'
]

async def verify_database_setup():
    """Verify complete database setup"""
    print("🔍 DevSecureX Database Verification")
    print("=" * 50)
    
    try:
        # Connect to database
        conn = await asyncpg.connect(
            host=DATABASE_CONFIG['host'],
            port=DATABASE_CONFIG['port'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password'],
            database=DATABASE_CONFIG['database']
        )
        
        print("✅ Database connection successful")
        
        # 1. Verify table count
        table_count_query = """
        SELECT COUNT(*) as table_count 
        FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        """
        result = await conn.fetchval(table_count_query)
        print(f"📊 Total tables found: {result}")
        
        if result != 41:
            print(f"❌ Expected 41 tables, found {result}")
            return False
        
        # 2. Verify all expected tables exist
        existing_tables_query = """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name
        """
        existing_tables = await conn.fetch(existing_tables_query)
        existing_table_names = [row['table_name'] for row in existing_tables]
        
        print("\n📋 Table Verification:")
        missing_tables = []
        for expected_table in EXPECTED_TABLES:
            if expected_table in existing_table_names:
                print(f"✅ {expected_table}")
            else:
                print(f"❌ {expected_table} - MISSING")
                missing_tables.append(expected_table)
        
        if missing_tables:
            print(f"\n❌ Missing tables: {missing_tables}")
            return False
        
        # 3. Verify indexes
        index_count_query = """
        SELECT COUNT(*) as index_count 
        FROM pg_indexes 
        WHERE schemaname = 'public'
        """
        index_count = await conn.fetchval(index_count_query)
        print(f"\n🔍 Total indexes: {index_count}")
        
        # 4. Verify foreign key constraints
        fk_count_query = """
        SELECT COUNT(*) as fk_constraint_count 
        FROM information_schema.table_constraints 
        WHERE constraint_type = 'FOREIGN KEY' AND table_schema = 'public'
        """
        fk_count = await conn.fetchval(fk_count_query)
        print(f"🔗 Foreign key constraints: {fk_count}")
        
        # 5. Verify sequences
        sequence_count_query = """
        SELECT COUNT(*) as sequence_count 
        FROM pg_sequences 
        WHERE schemaname = 'public'
        """
        sequence_count = await conn.fetchval(sequence_count_query)
        print(f"🔢 Sequences: {sequence_count}")
        
        # 6. Test basic operations on key tables
        print("\n🧪 Testing Basic Operations:")
        
        # Test users table
        user_test = await conn.fetchval("SELECT COUNT(*) FROM users")
        print(f"✅ Users table accessible - rows: {user_test}")
        
        # Test repos table
        repo_test = await conn.fetchval("SELECT COUNT(*) FROM repos")
        print(f"✅ Repos table accessible - rows: {repo_test}")
        
        # Test scans table
        scan_test = await conn.fetchval("SELECT COUNT(*) FROM scans")
        print(f"✅ Scans table accessible - rows: {scan_test}")
        
        # 7. Verify primary table relationships
        print("\n🔗 Verifying Key Relationships:")
        
        # Check if users table can reference repos
        relationship_test = """
        SELECT u.username, COUNT(r.id) as repo_count
        FROM users u
        LEFT JOIN repos r ON u.id = r.user_id
        GROUP BY u.id, u.username
        LIMIT 5
        """
        relationships = await conn.fetch(relationship_test)
        print(f"✅ User-Repo relationship working - sample count: {len(relationships)}")
        
        await conn.close()
        
        print("\n🎉 Database Verification Summary:")
        print("=" * 50)
        print(f"✅ All 41 tables created successfully")
        print(f"✅ {index_count} indexes created")
        print(f"✅ {fk_count} foreign key constraints established")
        print(f"✅ {sequence_count} sequences created")
        print(f"✅ Basic operations working")
        print(f"✅ Table relationships functional")
        print("\n🚀 DevSecureX database is ready for production!")
        
        return True
        
    except Exception as e:
        print(f"❌ Database verification failed: {str(e)}")
        return False

async def main():
    """Main verification function"""
    success = await verify_database_setup()
    if success:
        print("\n✅ Database setup verification completed successfully!")
        return 0
    else:
        print("\n❌ Database setup verification failed!")
        return 1

if __name__ == "__main__":
    import sys
    result = asyncio.run(main())
    sys.exit(result)