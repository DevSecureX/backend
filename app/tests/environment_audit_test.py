#!/usr/bin/env python3
"""
ENVIRONMENT AUDIT TEST SCRIPT
This script directly tests the environment configuration to verify 
that LOCAL and PRODUCTION environments use the correct database and Redis URLs.
"""
import os
import sys
from pathlib import Path

# Add the app directory to Python path
app_dir = Path(__file__).parent / "app"
if str(app_dir) not in sys.path:
    sys.path.insert(0, str(app_dir))

from core.config import EnvironmentConfig
import asyncio

async def audit_environment():
    """Perform comprehensive environment audit"""
    print("=" * 80)
    print("🔍 DEVSECUREX ENVIRONMENT AUDIT")
    print("=" * 80)
    
    env_config = EnvironmentConfig()
    environment = env_config.get_environment()
    
    print(f"📍 CURRENT ENVIRONMENT: {environment}")
    print()
    
    # Environment detection details
    print("🔧 ENVIRONMENT DETECTION:")
    print(f"   APP_ENV: {os.getenv('APP_ENV', 'not set')}")
    print(f"   ENVIRONMENT: {os.getenv('ENVIRONMENT', 'not set')}")
    print(f"   Detected Environment: {environment}")
    print(f"   Is Production: {env_config.is_production()}")
    print(f"   Is Local: {env_config.is_local()}")
    print()
    
    # Environment variables presence
    print("📋 ENVIRONMENT VARIABLES PRESENCE:")
    print(f"   DATABASE_URL: {'✅ SET' if os.getenv('DATABASE_URL') else '❌ NOT SET'}")
    print(f"   LOCAL_DATABASE_URL: {'✅ SET' if os.getenv('LOCAL_DATABASE_URL') else '❌ NOT SET'}")
    print(f"   REDIS_URL: {'✅ SET' if os.getenv('REDIS_URL') else '❌ NOT SET'}")
    print(f"   LOCAL_REDIS_URL: {'✅ SET' if os.getenv('LOCAL_REDIS_URL') else '❌ NOT SET'}")
    print()
    
    # URL configuration analysis
    print("🔗 URL CONFIGURATION ANALYSIS:")
    
    # Database URL
    try:
        database_url = env_config.get_database_url()
        expected_db_source = "LOCAL_DATABASE_URL" if environment in ["local", "development", "dev"] else "DATABASE_URL"
        
        # Determine actual source
        if environment in ["local", "development", "dev"] and os.getenv("LOCAL_DATABASE_URL"):
            actual_db_source = "LOCAL_DATABASE_URL"
        else:
            actual_db_source = "DATABASE_URL"
        
        # Extract connection info safely
        if "localhost" in database_url:
            db_host_info = "localhost (local)"
        elif "neon.tech" in database_url:
            db_host_info = "neon.tech (cloud)"
        else:
            db_host_info = "external"
        
        print(f"   🗄️  DATABASE:")
        print(f"      Expected Source: {expected_db_source}")
        print(f"      Actual Source: {actual_db_source}")
        print(f"      Host Type: {db_host_info}")
        print(f"      URL Length: {len(database_url)} chars")
        print(f"      Status: {'✅ CORRECT' if expected_db_source == actual_db_source else '❌ INCORRECT'}")
        
    except Exception as e:
        print(f"   🗄️  DATABASE: ❌ ERROR - {e}")
    
    print()
    
    # Redis URL
    try:
        redis_url = env_config.get_redis_url()
        expected_redis_source = "LOCAL_REDIS_URL" if environment in ["local", "development", "dev"] else "REDIS_URL"
        
        if redis_url:
            # Determine actual source
            if environment in ["local", "development", "dev"] and os.getenv("LOCAL_REDIS_URL"):
                actual_redis_source = "LOCAL_REDIS_URL"
            else:
                actual_redis_source = "REDIS_URL"
            
            # Extract connection info safely
            if "localhost" in redis_url:
                redis_host_info = "localhost (local)"
            elif "upstash.io" in redis_url:
                redis_host_info = "upstash.io (cloud)"
            else:
                redis_host_info = "external"
            
            print(f"   🔴 REDIS:")
            print(f"      Expected Source: {expected_redis_source}")
            print(f"      Actual Source: {actual_redis_source}")
            print(f"      Host Type: {redis_host_info}")
            print(f"      URL Length: {len(redis_url)} chars")
            print(f"      Status: {'✅ CORRECT' if expected_redis_source == actual_redis_source else '❌ INCORRECT'}")
        else:
            print(f"   🔴 REDIS: ⚠️  NOT CONFIGURED")
            
    except Exception as e:
        print(f"   🔴 REDIS: ❌ ERROR - {e}")
    
    print()
    
    # Test database connection
    print("🧪 CONNECTION TESTS:")
    try:
        from core.database import test_connection
        db_result = await test_connection()
        db_status = "✅ HEALTHY" if db_result['status'] == 'healthy' else f"❌ {db_result['status'].upper()}"
        print(f"   🗄️  Database: {db_status}")
        if db_result['status'] != 'healthy':
            print(f"      Error: {db_result.get('error', 'Unknown')}")
    except Exception as e:
        print(f"   🗄️  Database: ❌ ERROR - {e}")
    
    # Test Redis connection
    try:
        from core.redis import get_redis_client
        redis_client = await get_redis_client()
        if redis_client is not None:
            await redis_client.ping()
            print(f"   🔴 Redis: ✅ HEALTHY")
        else:
            print(f"   🔴 Redis: ⚠️  NOT CONFIGURED")
    except Exception as e:
        print(f"   🔴 Redis: ❌ ERROR - {e}")
    
    print()
    print("=" * 80)
    
    # Summary
    overall_status = "✅ PASSED"
    issues = []
    
    try:
        # Check if environment configuration is correct
        expected_db_source = "LOCAL_DATABASE_URL" if environment in ["local", "development", "dev"] else "DATABASE_URL"
        if environment in ["local", "development", "dev"] and os.getenv("LOCAL_DATABASE_URL"):
            actual_db_source = "LOCAL_DATABASE_URL"
        else:
            actual_db_source = "DATABASE_URL"
            
        if expected_db_source != actual_db_source:
            issues.append(f"Database using {actual_db_source} instead of {expected_db_source}")
            
        expected_redis_source = "LOCAL_REDIS_URL" if environment in ["local", "development", "dev"] else "REDIS_URL"
        redis_url = env_config.get_redis_url()
        if redis_url:
            if environment in ["local", "development", "dev"] and os.getenv("LOCAL_REDIS_URL"):
                actual_redis_source = "LOCAL_REDIS_URL"
            else:
                actual_redis_source = "REDIS_URL"
            if expected_redis_source != actual_redis_source:
                issues.append(f"Redis using {actual_redis_source} instead of {expected_redis_source}")
    except Exception as e:
        issues.append(f"Configuration analysis error: {e}")
    
    if issues:
        overall_status = "❌ FAILED"
        
    print(f"🎯 AUDIT RESULT: {overall_status}")
    if issues:
        print("❌ ISSUES FOUND:")
        for issue in issues:
            print(f"   • {issue}")
    else:
        print("✅ All environment configurations are correct!")
    
    print("=" * 80)

if __name__ == "__main__":
    asyncio.run(audit_environment())