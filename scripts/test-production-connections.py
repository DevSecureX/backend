#!/usr/bin/env python3
"""
Test production database and Redis connections
"""
import os
import asyncio
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Colors for output
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color

def print_success(msg):
    print(f"{GREEN}✅ {msg}{NC}")

def print_error(msg):
    print(f"{RED}❌ {msg}{NC}")

def print_warning(msg):
    print(f"{YELLOW}⚠️  {msg}{NC}")

async def test_database():
    """Test PostgreSQL connection"""
    print("\n🗄️  Testing Production PostgreSQL (Neon)...")
    
    db_url = os.getenv('PROD_POSTGRES_URL') or os.getenv('DATABASE_URL')
    if not db_url:
        print_error("No production database URL found in environment")
        return False
    
    # Mask the password for security
    masked_url = db_url.split('@')[0].split('://')[0] + '://***:***@' + db_url.split('@')[1] if '@' in db_url else db_url
    print(f"   URL: {masked_url}")
    
    try:
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy import text
        
        engine = create_async_engine(db_url)
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT current_database(), current_user, version()"))
            row = result.fetchone()
            
            print_success(f"Database connected!")
            print(f"   • Database: {row[0]}")
            print(f"   • User: {row[1]}")
            print(f"   • Version: {row[2].split(',')[0]}")
            
            # Check tables
            result = await conn.execute(text("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'"))
            table_count = result.scalar()
            print(f"   • Tables: {table_count}")
            
        await engine.dispose()
        return True
        
    except Exception as e:
        print_error(f"Database connection failed: {str(e)}")
        return False

async def test_redis():
    """Test Redis connection"""
    print("\n🔴 Testing Production Redis (Upstash)...")
    
    redis_url = os.getenv('PROD_REDIS_URL') or os.getenv('REDIS_URL')
    if not redis_url:
        print_error("No production Redis URL found in environment")
        return False
    
    # Mask the password for security
    if '@' in redis_url:
        parts = redis_url.split('@')
        masked_url = parts[0].split('://')[0] + '://***:***@' + parts[1]
    else:
        masked_url = redis_url
    print(f"   URL: {masked_url}")
    
    try:
        import redis.asyncio as redis
        
        # Parse the URL and create connection with SSL verification disabled for Upstash
        import ssl
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        r = redis.from_url(redis_url, decode_responses=True, ssl_cert_reqs=None)
        
        # Test basic operations
        await r.ping()
        print_success("Redis connected!")
        
        # Get server info (limited in Upstash)
        try:
            info = await r.info()
            if isinstance(info, dict):
                print(f"   • Server: Upstash Redis")
                print(f"   • Ready: Yes")
        except:
            # Upstash might not support INFO command
            print(f"   • Server: Upstash Redis (limited command support)")
        
        # Test read/write
        test_key = "devsecurex_test_key"
        await r.set(test_key, "Production Redis is working!", ex=60)  # Expires in 60 seconds
        value = await r.get(test_key)
        
        if value == "Production Redis is working!":
            print_success("Read/Write test passed!")
            await r.delete(test_key)  # Clean up
        else:
            print_error("Read/Write test failed!")
            
        await r.close()
        return True
        
    except Exception as e:
        print_error(f"Redis connection failed: {str(e)}")
        if "WRONGPASS" in str(e):
            print_warning("Authentication failed - check Redis password")
        elif "Connection refused" in str(e):
            print_warning("Connection refused - check Redis URL and port")
        return False

async def check_render_env_vars():
    """Check if we're using Render production environment variables"""
    print("\n⚙️  Checking Production Environment Variables...")
    
    env_vars = {
        'APP_ENV': os.getenv('APP_ENV'),
        'DATABASE_URL': '✓' if os.getenv('DATABASE_URL') else '✗',
        'REDIS_URL': '✓' if os.getenv('REDIS_URL') else '✗',
        'PROD_POSTGRES_URL': '✓' if os.getenv('PROD_POSTGRES_URL') else '✗',
        'PROD_REDIS_URL': '✓' if os.getenv('PROD_REDIS_URL') else '✗',
        'GITHUB_CLIENT_ID': '✓' if os.getenv('GITHUB_CLIENT_ID') else '✗',
        'GOOGLE_CLIENT_ID': '✓' if os.getenv('GOOGLE_CLIENT_ID') else '✗',
    }
    
    for key, value in env_vars.items():
        print(f"   • {key}: {value}")
    
    return True

async def main():
    """Run all tests"""
    print("🚀 DevSecureX Production Environment Check")
    print("=" * 50)
    
    # Check environment variables
    await check_render_env_vars()
    
    # Test connections
    db_ok = await test_database()
    redis_ok = await test_redis()
    
    print("\n" + "=" * 50)
    print("📊 Summary:")
    
    if db_ok and redis_ok:
        print_success("All production services are working!")
        print_warning("Remember: Production Redis operations cost money!")
    else:
        if not db_ok:
            print_error("Database connection failed")
        if not redis_ok:
            print_error("Redis connection failed")
        print("\nTroubleshooting:")
        print("1. Check your .env file has PROD_POSTGRES_URL and PROD_REDIS_URL")
        print("2. Ensure the credentials are correct")
        print("3. Check if services are running on Neon/Upstash dashboards")

if __name__ == "__main__":
    asyncio.run(main())