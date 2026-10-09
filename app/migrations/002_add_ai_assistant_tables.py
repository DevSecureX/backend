#!/usr/bin/env python3
"""
Migration: Add AI Assistant Tables
Version: 002
Date: 2025-08-09

This migration adds all AI assistant tables for chat functionality,
ensuring persistent chat sessions and message history like a modern chat assistant.

Tables added:
- chat_sessions: User chat sessions with metadata
- chat_messages: Individual messages within sessions
- ai_knowledge_base: AI knowledge base for enhanced responses
- ai_interactions: Tracking of AI interactions for analytics
- ai_prompt_templates: Reusable prompt templates
- ai_analysis_cache: Caching for AI analysis results

Run this script with: python run_migration.py --migration 002 --action migrate
"""

import asyncio
import logging
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
import os
import sys

# Add the parent directory to the Python path to import core modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import DATABASE_URL

logger = logging.getLogger(__name__)

# SQL statements for creating AI assistant tables
CREATE_CHAT_SESSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS chat_sessions (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(200),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    session_type VARCHAR(50) DEFAULT 'general',
    session_meta JSONB DEFAULT '{}'::jsonb
);
"""

CREATE_CHAT_MESSAGES_TABLE = """
CREATE TABLE IF NOT EXISTS chat_messages (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(36) NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    message_type VARCHAR(50) DEFAULT 'text',
    msg_meta JSONB DEFAULT '{}'::jsonb,
    model_used VARCHAR(50),
    tokens_used INTEGER,
    processing_time INTEGER,
    confidence_score INTEGER,
    related_scan_id VARCHAR(36),
    related_issue_id VARCHAR(36),
    related_repo VARCHAR(255)
);
"""

CREATE_AI_KNOWLEDGE_BASE_TABLE = """
CREATE TABLE IF NOT EXISTS ai_knowledge_base (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    category VARCHAR(100) NOT NULL,
    subcategory VARCHAR(100),
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    tags JSONB DEFAULT '[]'::jsonb,
    source VARCHAR(200),
    priority INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    kb_meta JSONB DEFAULT '{}'::jsonb
);
"""

CREATE_AI_INTERACTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS ai_interactions (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    interaction_type VARCHAR(50) NOT NULL,
    input_data JSONB NOT NULL,
    ai_response JSONB NOT NULL,
    model_used VARCHAR(50) NOT NULL,
    tokens_used INTEGER,
    processing_time INTEGER,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    user_feedback VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    session_id VARCHAR(36),
    related_scan_id VARCHAR(36),
    related_repo VARCHAR(255)
);
"""

CREATE_AI_PROMPT_TEMPLATES_TABLE = """
CREATE TABLE IF NOT EXISTS ai_prompt_templates (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    category VARCHAR(50) NOT NULL,
    template TEXT NOT NULL,
    variables JSONB DEFAULT '[]'::jsonb,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    version VARCHAR(10) DEFAULT '1.0',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    usage_count INTEGER DEFAULT 0,
    last_used TIMESTAMP WITH TIME ZONE
);
"""

CREATE_AI_ANALYSIS_CACHE_TABLE = """
CREATE TABLE IF NOT EXISTS ai_analysis_cache (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key VARCHAR(255) NOT NULL UNIQUE,
    analysis_type VARCHAR(50) NOT NULL,
    input_hash VARCHAR(64) NOT NULL,
    result JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    access_count INTEGER DEFAULT 1,
    expires_at TIMESTAMP WITH TIME ZONE,
    model_used VARCHAR(50) NOT NULL,
    tokens_used INTEGER,
    quality_score INTEGER
);
"""

# Performance indexes
CREATE_CHAT_SESSIONS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_chat_sessions_updated_at ON chat_sessions(updated_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_chat_sessions_is_active ON chat_sessions(is_active);",
    "CREATE INDEX IF NOT EXISTS idx_chat_sessions_type ON chat_sessions(session_type);",
]

CREATE_CHAT_MESSAGES_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);",
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_user_id ON chat_messages(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp DESC);",
    "CREATE INDEX IF NOT EXISTS idx_chat_messages_role ON chat_messages(role);",
]

CREATE_AI_KNOWLEDGE_BASE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_ai_knowledge_base_category ON ai_knowledge_base(category);",
    "CREATE INDEX IF NOT EXISTS idx_ai_knowledge_base_is_active ON ai_knowledge_base(is_active);",
    "CREATE INDEX IF NOT EXISTS idx_ai_knowledge_base_priority ON ai_knowledge_base(priority DESC);",
]

CREATE_AI_INTERACTIONS_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_ai_interactions_user_id ON ai_interactions(user_id);",
    "CREATE INDEX IF NOT EXISTS idx_ai_interactions_type ON ai_interactions(interaction_type);",
    "CREATE INDEX IF NOT EXISTS idx_ai_interactions_created_at ON ai_interactions(created_at DESC);",
]

CREATE_AI_CACHE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_ai_cache_key ON ai_analysis_cache(cache_key);",
    "CREATE INDEX IF NOT EXISTS idx_ai_cache_expires_at ON ai_analysis_cache(expires_at);",
    "CREATE INDEX IF NOT EXISTS idx_ai_cache_analysis_type ON ai_analysis_cache(analysis_type);",
]

# Updated timestamp triggers
CREATE_UPDATED_AT_TRIGGERS = """
-- Function for updating updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for chat_sessions
DROP TRIGGER IF EXISTS update_chat_sessions_updated_at ON chat_sessions;
CREATE TRIGGER update_chat_sessions_updated_at
    BEFORE UPDATE ON chat_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Triggers for ai_knowledge_base
DROP TRIGGER IF EXISTS update_ai_knowledge_base_updated_at ON ai_knowledge_base;
CREATE TRIGGER update_ai_knowledge_base_updated_at
    BEFORE UPDATE ON ai_knowledge_base
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Triggers for ai_prompt_templates
DROP TRIGGER IF EXISTS update_ai_prompt_templates_updated_at ON ai_prompt_templates;
CREATE TRIGGER update_ai_prompt_templates_updated_at
    BEFORE UPDATE ON ai_prompt_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
"""

# Table comments for documentation
ADD_TABLE_COMMENTS = [
    "COMMENT ON TABLE chat_sessions IS 'User chat sessions with AI assistant';",
    "COMMENT ON TABLE chat_messages IS 'Individual messages within chat sessions';",
    "COMMENT ON TABLE ai_knowledge_base IS 'AI knowledge base for enhanced security responses';",
    "COMMENT ON TABLE ai_interactions IS 'Log of all AI interactions for analytics';",
    "COMMENT ON TABLE ai_prompt_templates IS 'Reusable prompt templates for AI';",
    "COMMENT ON TABLE ai_analysis_cache IS 'Cache for AI analysis results to improve performance';",
]

async def run_migration():
    """Run the migration to add AI assistant tables"""
    
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable not set")
    
    # Create async engine
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    try:
        async with engine.begin() as conn:
            print("Starting migration: Add AI Assistant Tables...")
            
            # Create chat_sessions table
            print("Creating chat_sessions table...")
            await conn.execute(text(CREATE_CHAT_SESSIONS_TABLE))
            
            # Create chat_messages table
            print("Creating chat_messages table...")
            await conn.execute(text(CREATE_CHAT_MESSAGES_TABLE))
            
            # Create ai_knowledge_base table
            print("Creating ai_knowledge_base table...")
            await conn.execute(text(CREATE_AI_KNOWLEDGE_BASE_TABLE))
            
            # Create ai_interactions table
            print("Creating ai_interactions table...")
            await conn.execute(text(CREATE_AI_INTERACTIONS_TABLE))
            
            # Create ai_prompt_templates table
            print("Creating ai_prompt_templates table...")
            await conn.execute(text(CREATE_AI_PROMPT_TEMPLATES_TABLE))
            
            # Create ai_analysis_cache table
            print("Creating ai_analysis_cache table...")
            await conn.execute(text(CREATE_AI_ANALYSIS_CACHE_TABLE))
            
            # Create indexes for chat_sessions
            print("Creating indexes for chat_sessions...")
            for index_sql in CREATE_CHAT_SESSIONS_INDEXES:
                await conn.execute(text(index_sql))
            
            # Create indexes for chat_messages
            print("Creating indexes for chat_messages...")
            for index_sql in CREATE_CHAT_MESSAGES_INDEXES:
                await conn.execute(text(index_sql))
            
            # Create indexes for ai_knowledge_base
            print("Creating indexes for ai_knowledge_base...")
            for index_sql in CREATE_AI_KNOWLEDGE_BASE_INDEXES:
                await conn.execute(text(index_sql))
            
            # Create indexes for ai_interactions
            print("Creating indexes for ai_interactions...")
            for index_sql in CREATE_AI_INTERACTIONS_INDEXES:
                await conn.execute(text(index_sql))
            
            # Create indexes for ai_analysis_cache
            print("Creating indexes for ai_analysis_cache...")
            for index_sql in CREATE_AI_CACHE_INDEXES:
                await conn.execute(text(index_sql))
            
            # Create updated_at triggers
            print("Creating updated_at triggers...")
            await conn.execute(text(CREATE_UPDATED_AT_TRIGGERS))
            
            # Add table comments
            print("Adding table documentation...")
            for comment_sql in ADD_TABLE_COMMENTS:
                await conn.execute(text(comment_sql))
            
            print("Migration completed successfully!")
            
    except Exception as e:
        print(f"Migration failed: {e}")
        raise
    
    finally:
        await engine.dispose()

async def verify_migration():
    """Verify that the migration was successful"""
    engine = create_async_engine(DATABASE_URL, echo=False)
    
    try:
        async with engine.begin() as conn:
            # Check if tables exist
            result = await conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN (
                    'chat_sessions', 'chat_messages', 'ai_knowledge_base',
                    'ai_interactions', 'ai_prompt_templates', 'ai_analysis_cache'
                );
            """))
            
            tables = [row[0] for row in result]
            expected_tables = [
                'chat_sessions', 'chat_messages', 'ai_knowledge_base',
                'ai_interactions', 'ai_prompt_templates', 'ai_analysis_cache'
            ]
            
            for expected_table in expected_tables:
                if expected_table not in tables:
                    raise Exception(f"{expected_table} table not found")
            
            # Check if foreign key constraints exist
            result = await conn.execute(text("""
                SELECT tc.constraint_name, tc.table_name, kcu.column_name, 
                       ccu.table_name AS foreign_table_name,
                       ccu.column_name AS foreign_column_name 
                FROM information_schema.table_constraints AS tc 
                JOIN information_schema.key_column_usage AS kcu
                  ON tc.constraint_name = kcu.constraint_name
                  AND tc.table_schema = kcu.table_schema
                JOIN information_schema.constraint_column_usage AS ccu
                  ON ccu.constraint_name = tc.constraint_name
                  AND ccu.table_schema = tc.table_schema
                WHERE tc.constraint_type = 'FOREIGN KEY' 
                AND tc.table_name IN (
                    'chat_sessions', 'chat_messages', 'ai_interactions'
                );
            """))
            
            foreign_keys = [row[0] for row in result]
            
            # Check if indexes exist
            result = await conn.execute(text("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename IN (
                    'chat_sessions', 'chat_messages', 'ai_knowledge_base',
                    'ai_interactions', 'ai_prompt_templates', 'ai_analysis_cache'
                );
            """))
            
            indexes = [row[0] for row in result]
            
            print("Migration verification successful!")
            print(f"Created tables: {', '.join(tables)}")
            print(f"Created foreign keys: {len(foreign_keys)} constraints")
            print(f"Created indexes: {len(indexes)} indexes")
            
            # Test basic operations
            print("\nTesting basic operations...")
            
            # Test session creation
            await conn.execute(text("""
                INSERT INTO chat_sessions (id, user_id, title, session_type) 
                VALUES ('test-session-123', 1, 'Test Chat', 'general')
                ON CONFLICT (id) DO NOTHING;
            """))
            
            # Test message creation
            await conn.execute(text("""
                INSERT INTO chat_messages (id, session_id, user_id, role, content) 
                VALUES ('test-msg-123', 'test-session-123', 1, 'user', 'Hello AI!')
                ON CONFLICT (id) DO NOTHING;
            """))
            
            # Test retrieval
            result = await conn.execute(text("""
                SELECT cs.title, cm.content 
                FROM chat_sessions cs
                JOIN chat_messages cm ON cs.id = cm.session_id
                WHERE cs.id = 'test-session-123';
            """))
            
            test_data = result.fetchone()
            if test_data:
                print(f"✓ Session and message creation test passed: {test_data[0]} - {test_data[1]}")
            else:
                print("⚠ Warning: Test data not found, but tables exist")
            
            # Cleanup test data
            await conn.execute(text("DELETE FROM chat_messages WHERE id = 'test-msg-123';"))
            await conn.execute(text("DELETE FROM chat_sessions WHERE id = 'test-session-123';"))
            
    finally:
        await engine.dispose()

async def rollback_migration():
    """Rollback the migration by dropping the AI assistant tables"""
    engine = create_async_engine(DATABASE_URL, echo=True)
    
    try:
        async with engine.begin() as conn:
            print("Rolling back AI Assistant tables migration...")
            
            # Drop tables in reverse order (due to foreign key constraints)
            await conn.execute(text("DROP TABLE IF EXISTS ai_analysis_cache CASCADE;"))
            await conn.execute(text("DROP TABLE IF EXISTS ai_prompt_templates CASCADE;"))
            await conn.execute(text("DROP TABLE IF EXISTS ai_interactions CASCADE;"))
            await conn.execute(text("DROP TABLE IF EXISTS ai_knowledge_base CASCADE;"))
            await conn.execute(text("DROP TABLE IF EXISTS chat_messages CASCADE;"))
            await conn.execute(text("DROP TABLE IF EXISTS chat_sessions CASCADE;"))
            
            print("Migration rollback completed!")
            
    finally:
        await engine.dispose()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX AI Assistant Migration")
    parser.add_argument("--action", choices=["migrate", "verify", "rollback"], 
                       default="migrate", help="Action to perform")
    
    args = parser.parse_args()
    
    if args.action == "migrate":
        asyncio.run(run_migration())
    elif args.action == "verify":
        asyncio.run(verify_migration())
    elif args.action == "rollback":
        response = input("Are you sure you want to rollback the AI assistant migration? This will delete all chat data. (yes/no): ")
        if response.lower() == "yes":
            asyncio.run(rollback_migration())
        else:
            print("Rollback cancelled.")