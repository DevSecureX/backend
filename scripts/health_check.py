#!/usr/bin/env python3
"""
Production health check script for DevSecureX Backend
Can be used for deployment verification and monitoring
"""
import asyncio
import httpx
import os
import sys
import json
from typing import Dict, Any

async def check_health_endpoint(base_url: str, endpoint: str = "/health") -> Dict[str, Any]:
    """Check a health endpoint and return the result"""
    url = f"{base_url}{endpoint}"
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            
            result = {
                "endpoint": endpoint,
                "status_code": response.status_code,
                "response_time_ms": response.elapsed.total_seconds() * 1000,
                "success": response.status_code == 200
            }
            
            if response.status_code == 200:
                try:
                    result["data"] = response.json()
                except:
                    result["data"] = {"text": response.text[:200]}
            else:
                result["error"] = response.text[:200]
                
            return result
            
    except Exception as e:
        return {
            "endpoint": endpoint,
            "success": False,
            "error": str(e)
        }

async def comprehensive_health_check(base_url: str) -> Dict[str, Any]:
    """Run comprehensive health checks against the API"""
    
    health_checks = [
        "/health",
        "/health/detailed", 
        "/ready",
        "/live",
        "/metrics"
    ]
    
    results = {}
    
    print(f"🔍 Running health checks against: {base_url}")
    
    for endpoint in health_checks:
        print(f"  Checking {endpoint}...")
        result = await check_health_endpoint(base_url, endpoint)
        results[endpoint] = result
        
        if result["success"]:
            print(f"  ✅ {endpoint} - OK ({result.get('response_time_ms', 0):.0f}ms)")
        else:
            print(f"  ❌ {endpoint} - FAILED: {result.get('error', 'Unknown error')}")
    
    return results

def print_summary(results: Dict[str, Any]):
    """Print a summary of health check results"""
    
    total_checks = len(results)
    passed_checks = sum(1 for result in results.values() if result["success"])
    
    print(f"\n📊 Health Check Summary:")
    print(f"  Total checks: {total_checks}")
    print(f"  Passed: {passed_checks}")
    print(f"  Failed: {total_checks - passed_checks}")
    print(f"  Success rate: {(passed_checks/total_checks)*100:.1f}%")
    
    if passed_checks == total_checks:
        print("🎉 All health checks passed! API is ready for production.")
        return True
    else:
        print("⚠️  Some health checks failed. Review the issues above.")
        return False

async def main():
    """Main health check function"""
    
    # Get base URL from environment or command line
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = os.getenv('HEALTH_CHECK_URL', 'http://localhost:8000')
    
    # Remove trailing slash
    base_url = base_url.rstrip('/')
    
    print(f"🚀 DevSecureX Backend Health Check")
    print(f"Target: {base_url}")
    print("-" * 50)
    
    try:
        results = await comprehensive_health_check(base_url)
        
        # Print detailed results if requested
        if "--verbose" in sys.argv or "-v" in sys.argv:
            print(f"\n📋 Detailed Results:")
            print(json.dumps(results, indent=2))
        
        # Print summary
        success = print_summary(results)
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n⚠️ Health check interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Health check failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())