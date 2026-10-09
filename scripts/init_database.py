#!/usr/bin/env python3
"""
Manual Database Initialization Script for DevSecureX
Use this script to manually create all database tables
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add the app directory to Python path
app_dir = Path(__file__).parent / "app"
sys.path.insert(0, str(app_dir))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def initialize_database():
    """Initialize the database with all tables"""
    try:
        # Import database components
        from core.database import create_tables, test_connection, Base
        from sqlalchemy.orm import configure_mappers
        
        logger.info("🚀 Starting DevSecureX Database Initialization")
        
        # Test database connection first
        logger.info("📡 Testing database connection...")
        connection_result = await test_connection()
        
        if connection_result["status"] != "healthy":
            logger.error(f"❌ Database connection failed: {connection_result.get('error', 'Unknown error')}")
            return False
        
        logger.info("✅ Database connection successful")
        
        # Import all model modules to register tables with SQLAlchemy
        logger.info("📚 Importing SQLAlchemy models...")
        
        import auth.models
        import repos.models  
        import scans.models
        import custom_rules.models
        import ai_assistant.models
        import support.models
        import cli_scan.models
        
        # Configure mappers to build relationships
        configure_mappers()
        
        logger.info(f"📋 Models imported: {len(Base.metadata.tables)} tables registered")
        
        # List all tables that will be created
        table_names = list(Base.metadata.tables.keys())
        logger.info(f"🏗️  Tables to create: {', '.join(sorted(table_names))}")
        
        # Create all tables
        logger.info("🔨 Creating database tables...")
        await create_tables()
        
        logger.info("🎉 Database initialization completed successfully!")
        logger.info(f"✅ Created/verified {len(Base.metadata.tables)} tables")
        
        return True
        
    except Exception as e:
        logger.error(f"💥 Database initialization failed: {e}", exc_info=True)
        return False

async def verify_tables():
    """Verify that all tables were created successfully"""
    try:
        from core.database import get_db_session, DatabaseOperation
        from sqlalchemy import text
        
        logger.info("🔍 Verifying table creation...")
        
        async with get_db_session(DatabaseOperation.READ) as session:
            # Get list of all tables in the database
            result = await session.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name;
            """))
            
            db_tables = [row[0] for row in result.fetchall()]
            logger.info(f"📊 Tables found in database: {', '.join(sorted(db_tables))}")
            
            if db_tables:
                logger.info("✅ Table verification successful")
                return True
            else:
                logger.error("❌ No tables found in database")
                return False
                
    except Exception as e:
        logger.error(f"💥 Table verification failed: {e}")
        return False

def main():
    """Main function"""
    # Check if DATABASE_URL is set
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        logger.error("❌ DATABASE_URL environment variable not set")
        logger.info("💡 Please set your DATABASE_URL environment variable:")
        logger.info("   export DATABASE_URL='postgresql+asyncpg://user:pass@host:port/dbname'")
        sys.exit(1)
    
    # Check for the typo in DATABASE_URL
    if 'postgresql+asyncpgp' in database_url:
        logger.error("❌ Found typo in DATABASE_URL: 'postgresql+asyncpgp' should be 'postgresql+asyncpg'")
        logger.info("💡 Please fix your DATABASE_URL:")
        corrected_url = database_url.replace('postgresql+asyncpgp', 'postgresql+asyncpg')
        logger.info(f"   Corrected URL: {corrected_url}")
        sys.exit(1)
    
    logger.info(f"🔗 Using database: {database_url[:50]}...")
    
    # Run the initialization
    success = asyncio.run(initialize_database())
    
    if success:
        # Verify the tables were created
        verification_success = asyncio.run(verify_tables())
        if verification_success:
            logger.info("🎯 Database initialization and verification completed successfully!")
            sys.exit(0)
        else:
            logger.error("❌ Database verification failed")
            sys.exit(1)
    else:
        logger.error("❌ Database initialization failed")
        sys.exit(1)

if __name__ == "__main__":
    main()