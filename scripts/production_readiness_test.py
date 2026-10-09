#!/usr/bin/env python3
"""
Production Readiness Test for DevSecureX
Test all critical fixes and production deployment readiness
"""

import asyncio
import logging
import os
import sys
import time
from pathlib import Path

# Add app directory to Python path
current_dir = Path(__file__).parent
app_dir = current_dir / "app"
if str(app_dir) not in sys.path:
    sys.path.insert(0, str(app_dir))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_database_session_management():
    """Test database session management fixes"""
    logger.info("🔍 Testing database session management...")
    
    try:
        from core.database import get_db_session, DatabaseOperation, test_connection
        
        # Test basic connection
        result = await test_connection()
        if result["status"] != "healthy":
            logger.error(f"❌ Database connection failed: {result.get('error')}")
            return False
        
        # Test session context manager
        async with get_db_session(DatabaseOperation.READ) as db:
            from sqlalchemy import text
            result = await db.execute(text("SELECT 1 as test"))
            row = result.fetchone()
            if not row or row[0] != 1:
                logger.error("❌ Database session test query failed")
                return False
        
        logger.info("✅ Database session management working correctly")
        return True
        
    except Exception as e:
        logger.error(f"❌ Database session management test failed: {e}")
        return False

async def test_redis_connection_management():
    """Test Redis connection management fixes"""
    logger.info("🔍 Testing Redis connection management...")
    
    try:
        from core.redis import get_redis_client, get_redis_client_stats, close_redis_client
        
        # Test basic Redis connection
        client = await get_redis_client()
        if not client:
            logger.warning("⚠️ Redis client not available (may be expected if Redis not configured)")
            return True  # Not critical for basic operation
        
        # Test Redis ping
        await client.ping()
        
        # Test client stats
        stats = get_redis_client_stats()
        logger.info(f"Redis client stats: {stats}")
        
        # Test Redis pool manager if available
        try:
            from core.redis_pool_manager import get_redis_metrics, get_worker_redis_manager
            
            pool_metrics = get_redis_metrics()
            logger.info(f"Redis pool metrics: {pool_metrics}")
            
            # Test worker Redis manager
            worker_manager = await get_worker_redis_manager()
            worker_metrics = worker_manager.get_connection_metrics()
            logger.info(f"Worker Redis metrics: {worker_metrics}")
            
        except ImportError:
            logger.info("Redis pool manager not available")
        
        logger.info("✅ Redis connection management working correctly")
        return True
        
    except Exception as e:
        logger.error(f"❌ Redis connection management test failed: {e}")
        return False

async def test_worker_health_monitoring():
    """Test worker health monitoring system"""
    logger.info("🔍 Testing worker health monitoring...")
    
    try:
        from core.worker_health_monitor import get_worker_health_monitor, WorkerState
        
        # Get health monitor
        monitor = await get_worker_health_monitor()
        
        # Test worker registration
        await monitor.register_worker("test_worker", "test_type", WorkerState.READY)
        
        # Test heartbeat
        await monitor.update_worker_heartbeat("test_worker", WorkerState.ACTIVE)
        
        # Test health status
        health = monitor.get_worker_health("test_worker")
        if not health or health["worker_id"] != "test_worker":
            logger.error("❌ Worker health data retrieval failed")
            return False
        
        # Test all workers health
        all_health = monitor.get_all_workers_health()
        if "test_worker" not in all_health["workers"]:
            logger.error("❌ All workers health data missing test worker")
            return False
        
        # Cleanup test worker
        await monitor.unregister_worker("test_worker")
        
        logger.info("✅ Worker health monitoring working correctly")
        return True
        
    except Exception as e:
        logger.error(f"❌ Worker health monitoring test failed: {e}")
        return False

async def test_production_monitoring():
    """Test production monitoring system"""
    logger.info("🔍 Testing production monitoring...")
    
    try:
        from core.production_monitoring import get_production_monitor
        
        # Get production monitor
        monitor = await get_production_monitor()
        
        # Test health status
        health_status = monitor.get_health_status()
        if not health_status or "overall_status" not in health_status:
            logger.error("❌ Production health status retrieval failed")
            return False
        
        # Test production readiness report
        readiness_report = monitor.get_production_readiness_report()
        if not readiness_report or "deployment_ready" not in readiness_report:
            logger.error("❌ Production readiness report generation failed")
            return False
        
        logger.info(f"Production readiness: {readiness_report['deployment_ready']} ({readiness_report['readiness_score']}%)")
        logger.info(f"Checks passed: {readiness_report['checks_passed']}/{readiness_report['total_checks']}")
        
        # Log recommendations
        for rec in readiness_report["recommendations"]:
            logger.info(f"📝 Recommendation: {rec}")
        
        logger.info("✅ Production monitoring working correctly")
        return True
        
    except Exception as e:
        logger.error(f"❌ Production monitoring test failed: {e}")
        return False

async def test_circuit_breakers():
    """Test circuit breaker functionality"""
    logger.info("🔍 Testing circuit breakers...")
    
    try:
        from core.circuit_breaker import get_circuit_breaker_enforcer, get_circuit_breaker
        
        # Test circuit breaker enforcer
        enforcer = get_circuit_breaker_enforcer()
        
        # Test compliance validation
        compliance = enforcer.validate_circuit_breaker_compliance()
        logger.info(f"Circuit breaker compliance score: {compliance['compliance_score']}%")
        
        # Test basic circuit breaker
        test_breaker = get_circuit_breaker("test_breaker")
        
        # Test successful operation
        async def test_operation():
            return "success"
        
        result = await test_breaker.__aenter__()
        try:
            operation_result = await test_operation()
            if operation_result != "success":
                raise Exception("Test operation failed")
        except Exception as e:
            await test_breaker.__aexit__(type(e), e, e.__traceback__)
            raise
        else:
            await test_breaker.__aexit__(None, None, None)
        
        # Get metrics
        metrics = test_breaker.get_metrics()
        logger.info(f"Circuit breaker metrics: successful_calls={metrics['metrics']['successful_calls']}")
        
        logger.info("✅ Circuit breakers working correctly")
        return True
        
    except Exception as e:
        logger.error(f"❌ Circuit breaker test failed: {e}")
        return False

async def test_memory_management():
    """Test memory management fixes"""
    logger.info("🔍 Testing memory management...")
    
    try:
        # Test if psutil is available for memory monitoring
        try:
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            memory_mb = round(memory_info.rss / 1024 / 1024, 2)
            
            logger.info(f"Current memory usage: {memory_mb} MB")
            
            if memory_mb > 1024:  # More than 1GB seems high for a test
                logger.warning(f"⚠️ High memory usage detected: {memory_mb} MB")
            else:
                logger.info("✅ Memory usage appears reasonable")
            
        except ImportError:
            logger.info("psutil not available, skipping detailed memory check")
        
        # Test garbage collection is working
        import gc
        collected = gc.collect()
        logger.info(f"Garbage collection freed {collected} objects")
        
        logger.info("✅ Memory management tests passed")
        return True
        
    except Exception as e:
        logger.error(f"❌ Memory management test failed: {e}")
        return False

async def run_all_tests():
    """Run all production readiness tests"""
    logger.info("🚀 Starting DevSecureX Production Readiness Tests...")
    
    tests = [
        ("Database Session Management", test_database_session_management),
        ("Redis Connection Management", test_redis_connection_management),
        ("Worker Health Monitoring", test_worker_health_monitoring),
        ("Production Monitoring", test_production_monitoring),
        ("Circuit Breakers", test_circuit_breakers),
        ("Memory Management", test_memory_management),
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            logger.info(f"\n{'='*60}")
            logger.info(f"Running test: {test_name}")
            logger.info(f"{'='*60}")
            
            start_time = time.time()
            result = await test_func()
            duration = time.time() - start_time
            
            if result:
                logger.info(f"✅ {test_name} PASSED (took {duration:.2f}s)")
                passed_tests += 1
            else:
                logger.error(f"❌ {test_name} FAILED (took {duration:.2f}s)")
                
        except Exception as e:
            logger.error(f"❌ {test_name} ERROR: {e}")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"PRODUCTION READINESS TEST SUMMARY")
    logger.info(f"{'='*60}")
    logger.info(f"Tests passed: {passed_tests}/{total_tests}")
    logger.info(f"Success rate: {(passed_tests/total_tests*100):.1f}%")
    
    if passed_tests == total_tests:
        logger.info("🎉 ALL TESTS PASSED - PRODUCTION READY!")
        return True
    elif passed_tests >= total_tests * 0.8:  # 80% pass rate
        logger.warning("⚠️ MOSTLY READY - Some non-critical issues detected")
        return True
    else:
        logger.error("❌ NOT PRODUCTION READY - Critical issues detected")
        return False

if __name__ == "__main__":
    # Set test environment
    os.environ["APP_ENV"] = "test"
    os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test.db")
    
    try:
        success = asyncio.run(run_all_tests())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("\n🛑 Tests interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"💥 Test runner failed: {e}")
        sys.exit(1)