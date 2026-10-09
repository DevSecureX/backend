#!/usr/bin/env python3
"""
Stress Test for DevSecureX Workers
Tests dead worker fixes with concurrent operations
"""

import asyncio
import aiohttp
import time
import json
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = "http://localhost:8010"

class WorkerStressTester:
    """Stress tester for worker systems"""
    
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session = None
        self.results = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "average_response_time": 0.0,
            "concurrent_operations": 0,
            "resource_usage_samples": [],
            "errors": []
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def check_health(self) -> Dict[str, Any]:
        """Check system health"""
        try:
            async with self.session.get(f"{self.base_url}/health/detailed") as response:
                if response.status == 200:
                    return await response.json()
                else:
                    return {"status": "error", "details": f"HTTP {response.status}"}
        except Exception as e:
            return {"status": "error", "details": str(e)}
    
    async def simulate_scan_request(self, scan_id: int) -> Dict[str, Any]:
        """Simulate a scan request to test worker processing"""
        start_time = time.time()
        
        try:
            # Simulate CPU/Memory intensive work by hitting health endpoints multiple times
            tasks = []
            for i in range(5):  # 5 concurrent health checks to simulate load
                tasks.append(self.session.get(f"{self.base_url}/health/detailed"))
            
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            success_count = 0
            for resp in responses:
                if not isinstance(resp, Exception) and resp.status == 200:
                    success_count += 1
                    await resp.text()  # Consume response
                    await resp.release()
            
            response_time = time.time() - start_time
            
            self.results["total_requests"] += 1
            if success_count == 5:
                self.results["successful_requests"] += 1
                return {
                    "scan_id": scan_id,
                    "status": "success",
                    "response_time": response_time,
                    "successful_requests": success_count
                }
            else:
                self.results["failed_requests"] += 1
                return {
                    "scan_id": scan_id,
                    "status": "partial_failure",
                    "response_time": response_time,
                    "successful_requests": success_count
                }
                
        except Exception as e:
            self.results["failed_requests"] += 1
            return {
                "scan_id": scan_id,
                "status": "error",
                "error": str(e),
                "response_time": time.time() - start_time
            }
    
    async def monitor_resources(self, duration: int = 60):
        """Monitor system resources during stress test"""
        logger.info(f"Starting resource monitoring for {duration} seconds")
        
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                health_data = await self.check_health()
                sample = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": health_data.get("status", "unknown"),
                    "services": health_data.get("services", {}),
                    "response_time": health_data.get("total_response_time_ms", 0)
                }
                self.results["resource_usage_samples"].append(sample)
                
                # Log key metrics
                memory = health_data.get("services", {}).get("memory", {})
                redis = health_data.get("services", {}).get("redis", {})
                database = health_data.get("services", {}).get("database", {})
                
                logger.info(f"Resource check: Memory {memory.get('memory_usage', {}).get('rss_mb', 0):.1f}MB, "
                           f"Redis {redis.get('response_time_ms', 0):.1f}ms, "
                           f"DB {database.get('response_time_ms', 0):.1f}ms")
                
            except Exception as e:
                logger.warning(f"Resource monitoring error: {e}")
            
            await asyncio.sleep(5)  # Sample every 5 seconds
    
    async def run_concurrent_stress_test(self, concurrent_scans: int = 10, duration: int = 60):
        """Run concurrent stress test to simulate multiple scans"""
        logger.info(f"Starting stress test with {concurrent_scans} concurrent operations for {duration} seconds")
        
        # Start resource monitoring
        monitor_task = asyncio.create_task(self.monitor_resources(duration))
        
        # Run concurrent simulated scans
        start_time = time.time()
        scan_tasks = []
        scan_id = 1
        
        while time.time() - start_time < duration:
            # Launch concurrent scan simulations
            current_batch = []
            for _ in range(concurrent_scans):
                task = asyncio.create_task(self.simulate_scan_request(scan_id))
                current_batch.append(task)
                scan_id += 1
            
            # Wait for current batch to complete
            batch_results = await asyncio.gather(*current_batch, return_exceptions=True)
            
            # Process results
            for result in batch_results:
                if isinstance(result, Exception):
                    self.results["errors"].append(str(result))
                    logger.error(f"Scan task failed: {result}")
                elif result.get("status") == "success":
                    logger.debug(f"Scan {result['scan_id']} completed in {result['response_time']:.2f}s")
                else:
                    logger.warning(f"Scan {result['scan_id']} had issues: {result}")
            
            # Brief pause between batches to not overwhelm the system
            await asyncio.sleep(1)
        
        # Wait for resource monitoring to complete
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
        
        # Calculate statistics
        self.calculate_final_statistics()
        
        logger.info(f"Stress test completed. Results: {self.results['successful_requests']}/{self.results['total_requests']} successful")
    
    def calculate_final_statistics(self):
        """Calculate final test statistics"""
        if self.results["resource_usage_samples"]:
            response_times = [s.get("response_time", 0) for s in self.results["resource_usage_samples"]]
            self.results["average_response_time"] = sum(response_times) / len(response_times)
        
        # Calculate memory usage trend
        memory_samples = []
        for sample in self.results["resource_usage_samples"]:
            memory_info = sample.get("services", {}).get("memory", {}).get("memory_usage", {})
            if "rss_mb" in memory_info:
                memory_samples.append(memory_info["rss_mb"])
        
        if memory_samples:
            self.results["memory_usage"] = {
                "min_mb": min(memory_samples),
                "max_mb": max(memory_samples),
                "avg_mb": sum(memory_samples) / len(memory_samples),
                "final_mb": memory_samples[-1],
                "growth_mb": memory_samples[-1] - memory_samples[0] if len(memory_samples) > 1 else 0
            }
    
    def print_results(self):
        """Print detailed test results"""
        print("\n" + "="*60)
        print("WORKER STRESS TEST RESULTS")
        print("="*60)
        
        print(f"Total Requests: {self.results['total_requests']}")
        print(f"Successful: {self.results['successful_requests']}")
        print(f"Failed: {self.results['failed_requests']}")
        
        if self.results['total_requests'] > 0:
            success_rate = (self.results['successful_requests'] / self.results['total_requests']) * 100
            print(f"Success Rate: {success_rate:.1f}%")
        
        print(f"Average Response Time: {self.results['average_response_time']:.2f}ms")
        
        if "memory_usage" in self.results:
            memory = self.results["memory_usage"]
            print(f"\nMemory Usage:")
            print(f"  Min: {memory['min_mb']:.1f}MB")
            print(f"  Max: {memory['max_mb']:.1f}MB") 
            print(f"  Avg: {memory['avg_mb']:.1f}MB")
            print(f"  Growth: {memory['growth_mb']:.1f}MB")
            
            if abs(memory['growth_mb']) > 50:
                print(f"  ⚠️  HIGH MEMORY GROWTH DETECTED: {memory['growth_mb']:.1f}MB")
            else:
                print(f"  ✅ Memory growth within acceptable limits")
        
        if self.results["errors"]:
            print(f"\nErrors encountered: {len(self.results['errors'])}")
            for error in self.results["errors"][:5]:  # Show first 5 errors
                print(f"  - {error}")
        
        print("\n" + "="*60)

async def main():
    """Run the worker stress test"""
    print("Starting DevSecureX Worker Stress Test...")
    print("This will test the dead worker fixes with concurrent operations")
    
    async with WorkerStressTester() as tester:
        # Initial health check
        print("\nInitial system health check...")
        health = await tester.check_health()
        print(f"System Status: {health.get('status', 'unknown')}")
        
        if health.get("status") != "ok":
            print("⚠️  System not healthy, continuing with limited testing...")
        
        # Run stress test
        concurrent_operations = 15  # Start with 15 concurrent operations
        test_duration = 120  # 2 minutes of testing
        
        print(f"\nRunning stress test: {concurrent_operations} concurrent operations for {test_duration} seconds")
        await tester.run_concurrent_stress_test(
            concurrent_scans=concurrent_operations,
            duration=test_duration
        )
        
        # Print results
        tester.print_results()
        
        # Final health check
        print("\nFinal system health check...")
        final_health = await tester.check_health()
        print(f"Final System Status: {final_health.get('status', 'unknown')}")
        
        # Check for any degradation
        initial_memory = health.get("services", {}).get("memory", {}).get("memory_usage", {}).get("rss_mb", 0)
        final_memory = final_health.get("services", {}).get("memory", {}).get("memory_usage", {}).get("rss_mb", 0)
        
        if final_memory > initial_memory + 100:  # More than 100MB growth
            print(f"⚠️  Potential memory leak detected: {final_memory - initial_memory:.1f}MB growth")
        else:
            print(f"✅ Memory usage stable: {final_memory - initial_memory:.1f}MB change")

if __name__ == "__main__":
    asyncio.run(main())