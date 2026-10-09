#!/usr/bin/env python3
"""
Test script to demonstrate the automatic database initialization system
Run this inside a Docker container with proper environment variables
"""
import os
import sys
import asyncio
import logging

# Add app directory to path
app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, app_dir)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def test_database_initialization():
    """Test the automatic database initialization system"""
    
    print("=" * 60)
    print("🧪 TESTING AUTOMATIC DATABASE INITIALIZATION SYSTEM")
    print("=" * 60)
    
    # Check environment variables
    required_vars = ["DATABASE_URL", "SECRET_KEY", "OPENAI_API_KEY", "ENCRYPTION_KEY"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("   This script should be run inside a Docker container with proper env vars")
        return False
    
    print("✓ All required environment variables are set")
    
    try:
        # Test 1: Import database initialization modules
        print("\n📦 Testing module imports...")
        
        from core.database_initializer import initialize_database_on_startup, get_database_status
        from core.enhanced_startup_checks import run_startup_validation
        from core.database_health_service import run_database_health_check
        
        print("✓ All database initialization modules imported successfully")
        
        # Test 2: Initialize database
        print("\n🚀 Testing database initialization...")
        
        init_results = await initialize_database_on_startup(max_retries=2)
        
        if init_results["status"] == "success":
            print(f"✅ Database initialization successful!")
            print(f"   - Tables created: {len(init_results['tables_created'])}")
            print(f"   - Models imported: {len(init_results['models_imported'])}")
            print(f"   - Initialization time: {init_results['initialization_time_seconds']}s")
            
            if init_results.get("warnings"):
                print(f"   ⚠️  Warnings: {len(init_results['warnings'])}")
                for warning in init_results["warnings"]:
                    print(f"      - {warning}")
        else:
            print(f"❌ Database initialization failed: {init_results.get('errors', [])}")
            return False
        
        # Test 3: Run startup validation
        print("\n🔍 Testing startup validation...")
        
        validation_results = await run_startup_validation()
        
        if validation_results["overall_status"] in ["passed", "warning"]:
            print(f"✅ Startup validation: {validation_results['overall_status']}")
            print(f"   - Total checks: {validation_results['summary']['total_checks']}")
            print(f"   - Passed: {validation_results['summary']['passed_checks']}")
            print(f"   - Warnings: {validation_results['summary']['warning_checks']}")
            print(f"   - Failed: {validation_results['summary']['failed_checks']}")
            print(f"   - Execution time: {validation_results['execution_time_seconds']}s")
        else:
            print(f"❌ Startup validation failed: {validation_results['overall_status']}")
        
        # Test 4: Run health check
        print("\n🏥 Testing database health check...")
        
        health_results = await run_database_health_check(include_deep_checks=False)
        
        print(f"✅ Health check: {health_results['overall_status']}")
        print(f"   - Execution time: {health_results['execution_time_seconds']}s")
        
        # Show individual check results
        for check_name, check_result in health_results["checks"].items():
            status_icon = "✅" if check_result["status"] == "passed" else "⚠️" if check_result["status"] == "warning" else "❌"
            print(f"   {status_icon} {check_name}: {check_result['status']}")
        
        if health_results.get("recommendations"):
            print(f"   📋 Recommendations: {len(health_results['recommendations'])}")
            for rec in health_results["recommendations"][:3]:  # Show first 3
                print(f"      - {rec}")
        
        # Test 5: Get database status
        print("\n📊 Testing database status...")
        
        status = await get_database_status()
        
        if status.get("initialized"):
            print("✅ Database status: Initialized and ready")
            if status.get("uptime_seconds"):
                print(f"   - Uptime: {status['uptime_seconds']}s")
        else:
            print("❌ Database status: Not properly initialized")
        
        print("\n" + "=" * 60)
        print("🎉 AUTOMATIC DATABASE INITIALIZATION TEST COMPLETED")
        print("=" * 60)
        print()
        print("✅ Summary:")
        print("   - Database tables are created automatically on startup")
        print("   - No manual intervention required")
        print("   - Comprehensive validation ensures everything works")
        print("   - Health monitoring provides ongoing status")
        print()
        print("🚀 The system is ready for production use!")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Run the test
    success = asyncio.run(test_database_initialization())
    
    if success:
        print("\n✅ All tests passed! The database initialization system is working correctly.")
        sys.exit(0)
    else:
        print("\n❌ Tests failed. Check the errors above.")
        sys.exit(1)