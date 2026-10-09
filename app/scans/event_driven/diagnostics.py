"""
Event System Diagnostics and Monitoring
Comprehensive tools to diagnose and fix event-driven architecture issues
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
import time

from core.redis import get_redis_client
from .worker_events import event_system, EventDrivenWorkerSystem

logger = logging.getLogger(__name__)

class EventSystemDiagnostics:
    """Comprehensive diagnostic tools for the event system"""
    
    def __init__(self):
        self.test_worker_id = f"diagnostic_worker_{int(time.time())}"
        self.test_results = []
        
    async def run_comprehensive_diagnosis(self) -> Dict[str, Any]:
        """Run complete diagnostic suite to identify all issues"""
        logger.info("🔍 Starting comprehensive event system diagnosis...")
        
        diagnosis = {
            "timestamp": datetime.utcnow().isoformat(),
            "tests": {},
            "issues": [],
            "recommendations": [],
            "overall_health": "unknown"
        }
        
        # Test 1: Basic Redis connectivity
        redis_test = await self._test_redis_connectivity()
        diagnosis["tests"]["redis_connectivity"] = redis_test
        if not redis_test["passed"]:
            diagnosis["issues"].append("Redis connectivity failed")
            diagnosis["recommendations"].append("Check Redis server and connection configuration")
        
        # Test 2: Pub/Sub channel functionality
        pubsub_test = await self._test_pubsub_functionality()
        diagnosis["tests"]["pubsub_functionality"] = pubsub_test
        if not pubsub_test["passed"]:
            diagnosis["issues"].append("Redis pub/sub functionality broken")
            diagnosis["recommendations"].append("Check Redis pub/sub permissions and configuration")
        
        # Test 3: Event system subscription mechanism
        subscription_test = await self._test_subscription_mechanism()
        diagnosis["tests"]["subscription_mechanism"] = subscription_test
        if not subscription_test["passed"]:
            diagnosis["issues"].append("Worker subscription mechanism failing")
            diagnosis["recommendations"].append("Fix subscription creation and verification logic")
        
        # Test 4: Event publishing mechanism
        publishing_test = await self._test_event_publishing()
        diagnosis["tests"]["event_publishing"] = publishing_test
        if not publishing_test["passed"]:
            diagnosis["issues"].append("Event publishing mechanism failing")
            diagnosis["recommendations"].append("Fix event publishing and ensure proper job data")
        
        # Test 5: End-to-end event flow
        e2e_test = await self._test_end_to_end_flow()
        diagnosis["tests"]["end_to_end_flow"] = e2e_test
        if not e2e_test["passed"]:
            diagnosis["issues"].append("End-to-end event flow broken")
            diagnosis["recommendations"].append("Fix complete event flow from publish to receive")
        
        # Test 6: Real subscriber count verification
        subscriber_test = await self._test_real_subscriber_counts()
        diagnosis["tests"]["subscriber_verification"] = subscriber_test
        if not subscriber_test["passed"]:
            diagnosis["issues"].append("Subscribers not actually registered in Redis")
            diagnosis["recommendations"].append("Fix subscription registration to ensure Redis sees subscribers")
        
        # Calculate overall health
        passed_tests = sum(1 for test in diagnosis["tests"].values() if test.get("passed", False))
        total_tests = len(diagnosis["tests"])
        
        if passed_tests == total_tests:
            diagnosis["overall_health"] = "healthy"
        elif passed_tests >= total_tests * 0.75:
            diagnosis["overall_health"] = "degraded"
        else:
            diagnosis["overall_health"] = "critical"
        
        diagnosis["summary"] = {
            "passed_tests": passed_tests,
            "total_tests": total_tests,
            "health_score": round((passed_tests / total_tests) * 100, 1) if total_tests > 0 else 0,
            "critical_issues": len(diagnosis["issues"])
        }
        
        logger.info(f"🎯 Diagnosis complete: {diagnosis['overall_health']} ({passed_tests}/{total_tests} tests passed)")
        return diagnosis
    
    async def _test_redis_connectivity(self) -> Dict[str, Any]:
        """Test basic Redis connectivity"""
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return {"passed": False, "error": "Redis client unavailable"}
            
            # Test basic operations
            await redis_client.ping()
            test_key = f"diagnostic_test_{int(time.time())}"
            await redis_client.set(test_key, "test_value", ex=10)
            value = await redis_client.get(test_key)
            await redis_client.delete(test_key)
            
            if value == "test_value":
                return {"passed": True, "message": "Redis connectivity working"}
            else:
                return {"passed": False, "error": "Redis set/get failed"}
                
        except Exception as e:
            return {"passed": False, "error": str(e)}
    
    async def _test_pubsub_functionality(self) -> Dict[str, Any]:
        """Test basic Redis pub/sub functionality"""
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                return {"passed": False, "error": "Redis client unavailable"}
            
            test_channel = f"diagnostic_channel_{int(time.time())}"
            test_message = {"test": "message", "timestamp": time.time()}
            
            # Create subscriber
            pubsub = redis_client.pubsub()
            await pubsub.subscribe(test_channel)
            
            # Wait for subscription confirmation
            confirmation_received = False
            async for message in pubsub.listen():
                if message["type"] == "subscribe":
                    confirmation_received = True
                    break
            
            if not confirmation_received:
                await pubsub.close()
                return {"passed": False, "error": "Subscription confirmation not received"}
            
            # Test publishing and receiving
            await redis_client.publish(test_channel, json.dumps(test_message))
            
            message_received = False
            try:
                async for message in asyncio.wait_for(pubsub.listen(), timeout=5.0):
                    if message["type"] == "message":
                        received_data = json.loads(message["data"])
                        if received_data.get("test") == "message":
                            message_received = True
                        break
            except asyncio.TimeoutError:
                pass
            
            await pubsub.close()
            
            if message_received:
                return {"passed": True, "message": "Pub/sub functionality working"}
            else:
                return {"passed": False, "error": "Published message not received"}
                
        except Exception as e:
            return {"passed": False, "error": str(e)}
    
    async def _test_subscription_mechanism(self) -> Dict[str, Any]:
        """Test the event system subscription mechanism"""
        try:
            received_events = []
            
            async def test_callback(event_data):
                received_events.append(event_data)
                logger.info(f"Test callback received: {event_data}")
            
            # Test subscription creation
            subscription_task = await event_system.subscribe_to_scan_jobs(
                self.test_worker_id,
                test_callback
            )
            
            if not subscription_task:
                return {"passed": False, "error": "Failed to create subscription task"}
            
            # Allow time for subscription to establish
            await asyncio.sleep(1.0)
            
            # Check if subscription is tracked
            stats = await event_system.get_system_stats()
            scan_subscribers = stats.get("active_subscribers", {}).get("scan_workers", 0)
            
            # Cleanup
            subscription_task.cancel()
            await asyncio.gather(subscription_task, return_exceptions=True)
            
            if scan_subscribers > 0:
                return {"passed": True, "message": f"Subscription mechanism working ({scan_subscribers} subscribers tracked)"}
            else:
                return {"passed": False, "error": "Subscription created but not tracked in system stats"}
                
        except Exception as e:
            return {"passed": False, "error": str(e)}
    
    async def _test_event_publishing(self) -> Dict[str, Any]:
        """Test event publishing mechanism"""
        try:
            test_job_data = {
                "id": f"diagnostic_job_{int(time.time())}",
                "repo_full_name": "test/diagnostic",
                "scan_type": "manual",
                "priority": 2,
                "created_at": datetime.utcnow().isoformat()
            }
            
            # Test publishing
            success = await event_system.publish_scan_job_available(test_job_data)
            
            if success:
                return {"passed": True, "message": "Event publishing mechanism working"}
            else:
                return {"passed": False, "error": "Event publishing returned False"}
                
        except Exception as e:
            return {"passed": False, "error": str(e)}
    
    async def _test_end_to_end_flow(self) -> Dict[str, Any]:
        """Test complete end-to-end event flow"""
        try:
            received_events = []
            test_completed = asyncio.Event()
            
            async def test_callback(event_data):
                received_events.append(event_data)
                logger.info(f"E2E test callback received: {event_data}")
                test_completed.set()
            
            # Create subscription
            subscription_task = await event_system.subscribe_to_scan_jobs(
                self.test_worker_id,
                test_callback
            )
            
            if not subscription_task:
                return {"passed": False, "error": "Failed to create subscription for E2E test"}
            
            # Allow time for subscription to establish
            await asyncio.sleep(1.0)
            
            # Publish test event
            test_job_data = {
                "id": f"e2e_test_job_{int(time.time())}",
                "repo_full_name": "test/e2e-diagnostic",
                "scan_type": "manual",
                "priority": 2,
                "created_at": datetime.utcnow().isoformat()
            }
            
            publish_success = await event_system.publish_scan_job_available(test_job_data)
            if not publish_success:
                subscription_task.cancel()
                await asyncio.gather(subscription_task, return_exceptions=True)
                return {"passed": False, "error": "Failed to publish test event"}
            
            # Wait for event to be received
            try:
                await asyncio.wait_for(test_completed.wait(), timeout=10.0)
                event_received = True
            except asyncio.TimeoutError:
                event_received = False
            
            # Cleanup
            subscription_task.cancel()
            await asyncio.gather(subscription_task, return_exceptions=True)
            
            if event_received and len(received_events) > 0:
                return {"passed": True, "message": f"End-to-end flow working (received {len(received_events)} events)"}
            else:
                return {"passed": False, "error": f"Event not received in E2E test (timeout after 10s, received {len(received_events)} events)"}
                
        except Exception as e:
            return {"passed": False, "error": str(e)}
    
    async def _test_real_subscriber_counts(self) -> Dict[str, Any]:
        """Test that Redis actually sees subscribers"""
        try:
            # Test with a real subscription
            received_events = []
            
            async def test_callback(event_data):
                received_events.append(event_data)
            
            subscription_task = await event_system.subscribe_to_scan_jobs(
                self.test_worker_id,
                test_callback
            )
            
            if not subscription_task:
                return {"passed": False, "error": "Failed to create subscription for subscriber count test"}
            
            # Allow time for subscription to establish
            await asyncio.sleep(2.0)
            
            # Check Redis subscriber count
            redis_client = await get_redis_client()
            if not redis_client:
                subscription_task.cancel()
                await asyncio.gather(subscription_task, return_exceptions=True)
                return {"passed": False, "error": "Redis client unavailable for subscriber count check"}
            
            # Check subscriber count on scan jobs channel
            scan_channel = event_system.scan_channel
            subscribers = await redis_client.pubsub_numsub(scan_channel)
            count = subscribers.get(scan_channel.encode() if isinstance(scan_channel, str) else scan_channel, 0)
            
            # Cleanup
            subscription_task.cancel()
            await asyncio.gather(subscription_task, return_exceptions=True)
            
            if count > 0:
                return {"passed": True, "message": f"Redis sees {count} real subscribers on {scan_channel}"}
            else:
                return {"passed": False, "error": f"Redis shows 0 subscribers on {scan_channel} despite active subscription"}
                
        except Exception as e:
            return {"passed": False, "error": str(e)}
    
    async def monitor_live_events(self, duration_seconds: int = 60) -> Dict[str, Any]:
        """Monitor live event activity for debugging"""
        logger.info(f"🔍 Starting {duration_seconds}s live event monitoring...")
        
        events_received = []
        monitoring_start = time.time()
        
        async def monitor_callback(event_data):
            timestamp = time.time()
            events_received.append({
                "timestamp": timestamp,
                "relative_time": round(timestamp - monitoring_start, 2),
                "event": event_data
            })
            logger.info(f"📡 Live event received: {event_data.get('type')} - Job: {event_data.get('job_id')}")
        
        # Create monitoring subscription
        subscription_task = await event_system.subscribe_to_scan_jobs(
            f"monitor_{self.test_worker_id}",
            monitor_callback
        )
        
        if not subscription_task:
            return {"error": "Failed to create monitoring subscription"}
        
        try:
            # Monitor for specified duration
            await asyncio.sleep(duration_seconds)
            
        finally:
            # Cleanup
            subscription_task.cancel()
            await asyncio.gather(subscription_task, return_exceptions=True)
        
        return {
            "duration_seconds": duration_seconds,
            "events_received": len(events_received),
            "events": events_received,
            "monitoring_completed": True
        }
    
    async def stress_test_subscriptions(self, num_workers: int = 5, duration_seconds: int = 30) -> Dict[str, Any]:
        """Stress test multiple simultaneous subscriptions"""
        logger.info(f"🔥 Starting stress test with {num_workers} workers for {duration_seconds}s...")
        
        worker_stats = {}
        subscription_tasks = []
        
        for i in range(num_workers):
            worker_id = f"stress_test_worker_{i}_{int(time.time())}"
            events_received = []
            worker_stats[worker_id] = {"events_received": events_received, "subscription_success": False}
            
            async def create_worker_callback(w_id, events_list):
                async def callback(event_data):
                    events_list.append(event_data)
                    logger.debug(f"Worker {w_id} received event: {event_data.get('job_id')}")
                return callback
            
            # Create subscription for this worker
            callback = await create_worker_callback(worker_id, events_received)
            subscription_task = await event_system.subscribe_to_scan_jobs(worker_id, callback)
            
            if subscription_task:
                subscription_tasks.append((worker_id, subscription_task))
                worker_stats[worker_id]["subscription_success"] = True
                logger.info(f"✅ Stress test worker {i+1}/{num_workers} subscribed")
            else:
                logger.error(f"❌ Failed to subscribe stress test worker {i+1}/{num_workers}")
        
        # Allow subscriptions to establish
        await asyncio.sleep(2.0)
        
        # Check Redis subscriber counts
        redis_client = await get_redis_client()
        subscriber_count = 0
        if redis_client:
            subscribers = await redis_client.pubsub_numsub(event_system.scan_channel)
            subscriber_count = subscribers.get(event_system.scan_channel.encode(), 0)
        
        logger.info(f"📊 Stress test: {len(subscription_tasks)} workers subscribed, Redis sees {subscriber_count} subscribers")
        
        # Publish test events during the test
        test_events_published = 0
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration_seconds:
                test_job_data = {
                    "id": f"stress_test_job_{test_events_published}_{int(time.time())}",
                    "repo_full_name": "test/stress-test",
                    "scan_type": "manual",
                    "priority": 2,
                    "created_at": datetime.utcnow().isoformat()
                }
                
                success = await event_system.publish_scan_job_available(test_job_data)
                if success:
                    test_events_published += 1
                    logger.debug(f"Published stress test event {test_events_published}")
                
                await asyncio.sleep(2.0)  # Publish every 2 seconds
                
        finally:
            # Cleanup all subscriptions
            for worker_id, task in subscription_tasks:
                task.cancel()
            
            if subscription_tasks:
                await asyncio.gather(*[task for _, task in subscription_tasks], return_exceptions=True)
        
        # Compile results
        total_events_received = sum(len(stats["events_received"]) for stats in worker_stats.values())
        successful_subscriptions = sum(1 for stats in worker_stats.values() if stats["subscription_success"])
        
        return {
            "num_workers": num_workers,
            "duration_seconds": duration_seconds,
            "successful_subscriptions": successful_subscriptions,
            "redis_subscriber_count": subscriber_count,
            "test_events_published": test_events_published,
            "total_events_received": total_events_received,
            "events_per_worker": round(total_events_received / num_workers, 2) if num_workers > 0 else 0,
            "worker_stats": {worker_id: {"events_received": len(stats["events_received"]), "subscription_success": stats["subscription_success"]} for worker_id, stats in worker_stats.items()}
        }

# Global diagnostic instance
diagnostics = EventSystemDiagnostics()

async def run_quick_health_check() -> Dict[str, Any]:
    """Quick health check for the event system"""
    return await diagnostics.run_comprehensive_diagnosis()

async def monitor_events(duration: int = 60) -> Dict[str, Any]:
    """Monitor live events for debugging"""
    return await diagnostics.monitor_live_events(duration)

async def stress_test(workers: int = 5, duration: int = 30) -> Dict[str, Any]:
    """Stress test the event system"""
    return await diagnostics.stress_test_subscriptions(workers, duration)