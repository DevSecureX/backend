#!/usr/bin/env python3
"""
Test script to verify the app can start properly locally
"""
import os
import sys
import importlib

print("🧪 Testing DevSecureX Backend Startup")
print("=====================================\n")

# Set PYTHONPATH
sys.path.insert(0, '/app' if os.path.exists('/app') else 'app')
os.environ['PYTHONPATH'] = sys.path[0]
print(f"✓ PYTHONPATH set to: {sys.path[0]}")

# Test critical imports
modules_to_test = [
    'main',
    'core.database',
    'core.redis',
    'core.config',
    'auth.routes',
    'repos.routes',
    'scans.routes',
    'scans.workers.manager',
    'scans.workers.scan_worker',
]

errors = []

print("\n📦 Testing imports...")
for module in modules_to_test:
    try:
        importlib.import_module(module)
        print(f"✓ Successfully imported: {module}")
    except Exception as e:
        print(f"✗ Failed to import {module}: {str(e)}")
        errors.append((module, str(e)))

print("\n🔍 Checking environment variables...")
env_vars = [
    ('DATABASE_URL', False),  # (var_name, is_required)
    ('REDIS_URL', False),
    ('SECRET_KEY', False),
    ('OPENAI_API_KEY', False),
    ('ENABLE_BACKGROUND_WORKERS', False),
    ('APP_ENV', False),
]

for var, required in env_vars:
    value = os.getenv(var)
    if value:
        # Mask sensitive values
        if 'KEY' in var or 'SECRET' in var or 'URL' in var:
            masked = value[:10] + '...' if len(value) > 10 else '***'
            print(f"✓ {var} is set: {masked}")
        else:
            print(f"✓ {var} is set: {value}")
    else:
        if required:
            print(f"✗ {var} is NOT set (REQUIRED)")
            errors.append((var, "Required environment variable not set"))
        else:
            print(f"! {var} is NOT set (optional)")

# Summary
print("\n=====================================")
if errors:
    print(f"❌ Found {len(errors)} errors:")
    for item, error in errors:
        print(f"  - {item}: {error}")
    print("\n⚠️  Fix these issues before running the app")
    sys.exit(1)
else:
    print("✅ All checks passed! The app should start successfully.")
    print("\nTo run locally: ./run-local.sh")
    print("To run in Docker: docker-compose up --build")
    sys.exit(0)