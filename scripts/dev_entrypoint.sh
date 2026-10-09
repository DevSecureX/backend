#!/bin/bash
# Development entrypoint for hot-reload support
# This script ensures proper environment setup for local development

echo "🚀 Starting DevSecureX Backend in DEVELOPMENT mode with hot-reload..."

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 5

# Check PostgreSQL connection
echo "🔍 Checking PostgreSQL connection..."
python -c "
import asyncio
import asyncpg

async def check_db():
    try:
        conn = await asyncpg.connect(
            host='devsecurex-db',
            port=5432,
            user='devsecurex_user',
            password='devsecurex_pass',
            database='devsecurex_db'
        )
        await conn.close()
        print('✅ PostgreSQL is ready!')
        return True
    except Exception as e:
        print(f'⚠️  PostgreSQL connection issue: {e}')
        print('   Continuing anyway...')
        return False

asyncio.run(check_db())
"

# Check Redis connection (non-critical)
echo "🔍 Checking Redis connection..."
python -c "
try:
    import redis
    r = redis.Redis(host='devsecurex-redis', port=6379, socket_connect_timeout=5)
    r.ping()
    print('✅ Redis is ready!')
except Exception as e:
    print(f'⚠️  Redis connection issue: {e}')
    print('   Continuing without Redis...')
"

# Run database migrations if needed
echo "🔄 Checking database migrations..."
python -c "
import asyncio
from core.database import engine, Base
from sqlalchemy.orm import configure_mappers

# Import all models to register with Base
import auth.models
import repos.models
import scans.models
import custom_rules.models
import ai_assistant.models
import support.models

configure_mappers()

async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()

asyncio.run(create_tables())
print('✅ Database tables ready!')
"

# Start uvicorn with hot-reload
echo "🔥 Starting server with hot-reload on port 8010..."
echo "📁 Watching /app directory for changes..."
echo "🌐 API will be available at http://localhost:8010"
echo "📚 Docs available at http://localhost:8010/docs"
echo ""
echo "✨ Hot-reload enabled! Your code changes will be reflected automatically."
echo "ℹ️  Note: Adding new dependencies requires container rebuild."
echo ""

# Use exec to replace shell with uvicorn process
exec python -m uvicorn main:app \
    --host 0.0.0.0 \
    --port 8010 \
    --reload \
    --reload-dir /app \
    --log-level info