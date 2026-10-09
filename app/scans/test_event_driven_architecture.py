"""
Test script to validate the event-driven architecture implementation.
Run this to test Redis usage reduction and event notifications.
"""
import asyncio
import json
import logging
import os
import time
from typing import Dict, Any

from core.redis import get_redis_client
from core.utils import safe_int_from_env
from .event_driven import event_system, WorkerEventType

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EventDrivenArchitectureTest:
    """Test suite for event-driven worker architecture."""
    
    def __init__(self):
        self.test_worker_id = "test_worker_001"
        self.received_notifications = []
        
    async def test_job_notification_callback(self, event_data: Dict[str, Any]):
        """Callback for receiving job notifications during tests."""
        logger.info(f"Test worker received notification: {event_data}")
        self.received_notifications.append(event_data)
    
    async def test_scan_job_notification(self) -> bool:
        """Test scan job event notification system."""
        logger.info("Testing scan job notification system...")
        
        try:
            # Subscribe to scan job notifications
            subscription_task = await event_system.subscribe_to_scan_jobs(
                self.test_worker_id,
                self.test_job_notification_callback
            )
            
            if not subscription_task:
                logger.error("Failed to create scan job subscription")
                return False
            
            # Wait a moment for subscription to establish
            await asyncio.sleep(0.5)
            
            # Simulate job enqueue by publishing notification
            test_job_data = {
                "id": "test_scan_job_001",
                "repo_full_name": "test/repo",
                "scan_type": "manual",
                "priority": 2,
                "created_at": time.time()
            }
            
            success = await event_system.publish_scan_job_available(test_job_data)
            if not success:
                logger.error("Failed to publish scan job notification")
                return False
            
            # Wait for notification to be received
            await asyncio.sleep(1)
            
            # Clean up subscription
            subscription_task.cancel()
            await asyncio.gather(subscription_task, return_exceptions=True)
            
            # Validate notification was received
            if not self.received_notifications:
                logger.error("No notifications received")
                return False
            
            notification = self.received_notifications[-1]
            if notification.get("type") != WorkerEventType.SCAN_JOB_AVAILABLE.value:
                logger.error(f"Wrong notification type: {notification.get('type')}")
                return False
            
            if notification.get("job_id") != test_job_data["id"]:
                logger.error(f"Wrong job ID in notification: {notification.get('job_id')}")
                return False
            
            logger.info("✓ Scan job notification test passed")
            return True
            
        except Exception as e:
            logger.error(f"Scan job notification test failed: {e}")
            return False
    
    async def test_autofix_job_notification(self) -> bool:
        """Test autofix job event notification system."""
        logger.info("Testing autofix job notification system...")
        
        try:
            # Subscribe to autofix job notifications
            subscription_task = await event_system.subscribe_to_autofix_jobs(
                self.test_worker_id,
                self.test_job_notification_callback
            )
            
            if not subscription_task:
                logger.error("Failed to create autofix job subscription")
                return False
            
            # Wait a moment for subscription to establish
            await asyncio.sleep(0.5)
            
            # Simulate autofix job enqueue
            test_job_data = {
                "id": "test_autofix_job_001",
                "scan_id": "test_scan_001",
                "repo_full_name": "test/repo",
                "created_at": time.time()
            }
            
            success = await event_system.publish_autofix_job_available(test_job_data)
            if not success:
                logger.error("Failed to publish autofix job notification")
                return False
            
            # Wait for notification to be received
            await asyncio.sleep(1)
            
            # Clean up subscription
            subscription_task.cancel()
            await asyncio.gather(subscription_task, return_exceptions=True)
            
            # Validate notification was received
            autofix_notifications = [
                n for n in self.received_notifications 
                if n.get("type") == WorkerEventType.AUTOFIX_JOB_AVAILABLE.value
            ]
            
            if not autofix_notifications:
                logger.error("No autofix notifications received")
                return False
            
            notification = autofix_notifications[-1]
            if notification.get("job_id") != test_job_data["id"]:
                logger.error(f"Wrong job ID in autofix notification: {notification.get('job_id')}")
                return False
            
            logger.info("✓ Autofix job notification test passed")
            return True
            
        except Exception as e:
            logger.error(f"Autofix job notification test failed: {e}")
            return False
    
    async def test_redis_usage_measurement(self) -> Dict[str, Any]:
        """Measure actual Redis usage to validate optimization."""
        logger.info("Measuring Redis usage patterns...")
        
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                logger.error("Redis client not available for usage measurement")
                return {"error": "Redis not available"}
            
            # Get initial stats
            initial_stats = await redis_client.info("stats")
            initial_commands = initial_stats.get("total_commands_processed", 0)
            
            # Perform some test operations
            start_time = time.time()
            
            # Test event publications (simulating job enqueues)
            for i in range(5):
                await event_system.publish_scan_job_available({
                    "id": f"test_job_{i}",
                    "repo_full_name": "test/repo",
                    "scan_type": "manual",
                    "priority": 2,
                    "created_at": time.time()
                })
            
            # Test direct Redis operations (simulating old polling)
            for i in range(10):
                await redis_client.ping()
            
            end_time = time.time()
            
            # Get final stats
            final_stats = await redis_client.info("stats")
            final_commands = final_stats.get("total_commands_processed", 0)
            
            # Calculate usage
            commands_used = final_commands - initial_commands
            time_elapsed = end_time - start_time
            
            usage_stats = {
                "test_duration_seconds": round(time_elapsed, 2),
                "redis_commands_used": commands_used,
                "commands_per_second": round(commands_used / time_elapsed, 2) if time_elapsed > 0 else 0,
                "event_publications": 5,
                "direct_operations": 10,
                "efficiency_ratio": round(5 / commands_used, 3) if commands_used > 0 else 0  # events per Redis command
            }
            
            logger.info(f"Redis usage measurement: {usage_stats}")
            return usage_stats
            
        except Exception as e:
            logger.error(f"Redis usage measurement failed: {e}")
            return {"error": str(e)}
    
    async def test_system_configuration(self) -> Dict[str, Any]:
        """Test system configuration and validate optimization settings."""
        logger.info("Testing system configuration...")
        
        config_validation = {
            "event_driven_enabled": os.getenv("ENABLE_EVENT_DRIVEN_WORKERS", "true").lower() == "true",
            "scan_poll_interval": safe_int_from_env("SCAN_WORKER_POLL_INTERVAL", "120"),
            "autofix_poll_interval": safe_int_from_env("AUTOFIX_WORKER_POLL_INTERVAL", "300"),
            "background_workers_enabled": os.getenv("ENABLE_BACKGROUND_WORKERS", "true").lower() == "true",
            "redis_available": (await get_redis_client()) is not None
        }
        
        # Validate optimization settings
        recommendations = []
        
        if not config_validation["event_driven_enabled"]:
            recommendations.append("Enable ENABLE_EVENT_DRIVEN_WORKERS=true for maximum Redis reduction")
        
        if config_validation["scan_poll_interval"] < 60:
            recommendations.append("Increase SCAN_WORKER_POLL_INTERVAL to at least 60 seconds")
        
        if config_validation["autofix_poll_interval"] < 180:
            recommendations.append("Increase AUTOFIX_WORKER_POLL_INTERVAL to at least 180 seconds")
        
        config_validation["recommendations"] = recommendations
        config_validation["optimization_score"] = max(0, 100 - len(recommendations) * 20)
        
        logger.info(f"System configuration: {config_validation}")
        return config_validation
    
    async def run_full_test_suite(self) -> Dict[str, Any]:
        """Run complete test suite and return results."""
        logger.info("🚀 Starting event-driven architecture test suite...")
        
        results = {
            "timestamp": time.time(),
            "test_results": {},
            "overall_status": "unknown"
        }
        
        # Test 1: System Configuration
        try:
            config_results = await self.test_system_configuration()
            results["test_results"]["configuration"] = {
                "status": "passed",
                "data": config_results
            }
        except Exception as e:
            results["test_results"]["configuration"] = {
                "status": "failed",
                "error": str(e)
            }
        
        # Test 2: Scan Job Notifications
        try:
            scan_test_passed = await self.test_scan_job_notification()
            results["test_results"]["scan_notifications"] = {
                "status": "passed" if scan_test_passed else "failed",
                "notifications_received": len([n for n in self.received_notifications if n.get("type") == WorkerEventType.SCAN_JOB_AVAILABLE.value])
            }
        except Exception as e:
            results["test_results"]["scan_notifications"] = {
                "status": "failed",
                "error": str(e)
            }
        
        # Test 3: Autofix Job Notifications
        try:
            autofix_test_passed = await self.test_autofix_job_notification()
            results["test_results"]["autofix_notifications"] = {
                "status": "passed" if autofix_test_passed else "failed",
                "notifications_received": len([n for n in self.received_notifications if n.get("type") == WorkerEventType.AUTOFIX_JOB_AVAILABLE.value])
            }
        except Exception as e:
            results["test_results"]["autofix_notifications"] = {
                "status": "failed",
                "error": str(e)
            }
        
        # Test 4: Redis Usage Measurement
        try:
            usage_stats = await self.test_redis_usage_measurement()
            results["test_results"]["redis_usage"] = {
                "status": "passed" if "error" not in usage_stats else "failed",
                "data": usage_stats
            }
        except Exception as e:
            results["test_results"]["redis_usage"] = {
                "status": "failed",
                "error": str(e)
            }
        
        # Calculate overall status
        passed_tests = sum(1 for test in results["test_results"].values() if test.get("status") == "passed")
        total_tests = len(results["test_results"])
        
        if passed_tests == total_tests:
            results["overall_status"] = "all_passed"
        elif passed_tests >= total_tests * 0.75:
            results["overall_status"] = "mostly_passed"
        else:
            results["overall_status"] = "failed"
        
        # Summary
        results["summary"] = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "success_rate": round((passed_tests / total_tests) * 100, 1) if total_tests > 0 else 0
        }
        
        logger.info(f"🎯 Test suite completed: {results['summary']}")
        return results

async def main():
    """Run the event-driven architecture test suite."""
    tester = EventDrivenArchitectureTest()
    results = await tester.run_full_test_suite()
    
    print("\n" + "="*60)
    print("EVENT-DRIVEN ARCHITECTURE TEST RESULTS")
    print("="*60)
    print(json.dumps(results, indent=2, default=str))
    print("="*60)
    
    return results

if __name__ == "__main__":
    # Run the test suite
    asyncio.run(main())