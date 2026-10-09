#!/usr/bin/env python3
"""
Redis Performance Analysis and Optimization Report
Comprehensive testing of Redis optimization implementation
"""

import time
import asyncio
import subprocess
import json
from datetime import datetime, timedelta
from collections import defaultdict
import statistics

class RedisPerformanceAnalyzer:
    def __init__(self):
        self.metrics = {
            "redis_commands_per_minute": [],
            "command_types": defaultdict(int),
            "connection_info": {},
            "optimization_status": {},
            "performance_comparison": {}
        }
        
    def count_redis_operations(self, duration_minutes=5):
        """Monitor Redis operations for specified duration"""
        print(f"\n🔍 Monitoring Redis operations for {duration_minutes} minutes...")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        command_counts = []
        total_commands = 0
        
        # Start Redis monitor
        process = subprocess.Popen(
            ["docker", "exec", "devsecurex-redis", "redis-cli", "MONITOR"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        print("✅ Redis monitoring started...")
        minute_start = time.time()
        minute_commands = 0
        
        try:
            while time.time() < end_time:
                line = process.stdout.readline()
                if line:
                    total_commands += 1
                    minute_commands += 1
                    
                    # Extract command type
                    parts = line.strip().split('"')
                    if len(parts) >= 4:
                        command = parts[3].upper()
                        self.metrics["command_types"][command] += 1
                
                # Track per-minute metrics
                current_time = time.time()
                if current_time - minute_start >= 60:
                    commands_per_minute = minute_commands
                    command_counts.append(commands_per_minute)
                    print(f"⏱️  Minute {len(command_counts)}: {commands_per_minute} commands")
                    
                    minute_start = current_time
                    minute_commands = 0
                    
        except KeyboardInterrupt:
            print("\n⚠️  Monitoring interrupted")
        finally:
            process.terminate()
            process.wait()
        
        # Final partial minute
        if minute_commands > 0:
            partial_duration = (time.time() - minute_start) / 60
            estimated_full_minute = int(minute_commands / partial_duration) if partial_duration > 0 else minute_commands
            command_counts.append(estimated_full_minute)
            print(f"⏱️  Final partial minute: {minute_commands} commands (estimated: {estimated_full_minute}/min)")
        
        self.metrics["redis_commands_per_minute"] = command_counts
        self.metrics["total_commands"] = total_commands
        self.metrics["monitoring_duration"] = duration_minutes
        
        return {
            "total_commands": total_commands,
            "commands_per_minute": command_counts,
            "average_commands_per_minute": statistics.mean(command_counts) if command_counts else 0,
            "peak_commands_per_minute": max(command_counts) if command_counts else 0,
            "min_commands_per_minute": min(command_counts) if command_counts else 0
        }
    
    def get_redis_info(self):
        """Get Redis server information"""
        print("\n📊 Gathering Redis server information...")
        
        try:
            # Basic Redis info
            result = subprocess.run(
                ["docker", "exec", "devsecurex-redis", "redis-cli", "INFO", "server"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                info_lines = result.stdout.strip().split('\n')
                info_dict = {}
                for line in info_lines:
                    if ':' in line and not line.startswith('#'):
                        key, value = line.split(':', 1)
                        info_dict[key] = value
                
                self.metrics["connection_info"]["server_info"] = info_dict
            
            # Memory info
            result = subprocess.run(
                ["docker", "exec", "devsecurex-redis", "redis-cli", "INFO", "memory"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                memory_lines = result.stdout.strip().split('\n')
                memory_dict = {}
                for line in memory_lines:
                    if ':' in line and not line.startswith('#'):
                        key, value = line.split(':', 1)
                        memory_dict[key] = value
                
                self.metrics["connection_info"]["memory_info"] = memory_dict
            
            # Connection stats
            result = subprocess.run(
                ["docker", "exec", "devsecurex-redis", "redis-cli", "INFO", "clients"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                client_lines = result.stdout.strip().split('\n')
                client_dict = {}
                for line in client_lines:
                    if ':' in line and not line.startswith('#'):
                        key, value = line.split(':', 1)
                        client_dict[key] = value
                
                self.metrics["connection_info"]["client_info"] = client_dict
                
            print("✅ Redis information collected")
            
        except Exception as e:
            print(f"⚠️  Error collecting Redis info: {e}")
            
    def check_worker_intervals(self):
        """Check if workers are using optimized polling intervals"""
        print("\n🔧 Checking worker polling intervals...")
        
        try:
            result = subprocess.run(
                ["docker", "logs", "devsecurex-backend-core", "--tail", "100"],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0:
                logs = result.stdout
                
                # Look for polling interval indicators
                optimizations = {
                    "event_driven_enabled": "successfully subscribed to event-driven" in logs.lower(),
                    "fallback_polling_300s": "fallback poll: 300.0s" in logs,
                    "fallback_polling_600s": "fallback poll: 600.0s" in logs,
                    "redis_connection_working": "Simple Redis client created successfully" in logs,
                    "worker_ping_intervals": "using ping interval: 300s" in logs,
                    "redis_errors": "Redis connection error" in logs or "Failed to create Redis pool" in logs
                }
                
                self.metrics["optimization_status"] = optimizations
                
                # Calculate optimization score
                positive_indicators = sum([
                    optimizations["event_driven_enabled"],
                    optimizations["fallback_polling_300s"],
                    optimizations["fallback_polling_600s"],
                    optimizations["redis_connection_working"],
                    optimizations["worker_ping_intervals"],
                    not optimizations["redis_errors"]  # No errors is good
                ])
                
                optimization_score = (positive_indicators / 6) * 100
                self.metrics["optimization_score"] = optimization_score
                
                print(f"✅ Optimization analysis complete - Score: {optimization_score:.1f}%")
                
        except Exception as e:
            print(f"⚠️  Error checking worker intervals: {e}")
    
    def generate_performance_comparison(self, baseline_ops_per_minute=64):
        """Generate performance comparison with baseline"""
        print(f"\n📈 Comparing with baseline ({baseline_ops_per_minute} ops/minute)...")
        
        if self.metrics["redis_commands_per_minute"]:
            current_avg = statistics.mean(self.metrics["redis_commands_per_minute"])
            reduction_percentage = ((baseline_ops_per_minute - current_avg) / baseline_ops_per_minute) * 100
            
            self.metrics["performance_comparison"] = {
                "baseline_ops_per_minute": baseline_ops_per_minute,
                "current_avg_ops_per_minute": current_avg,
                "reduction_percentage": reduction_percentage,
                "performance_improvement": reduction_percentage > 0,
                "ops_saved_per_minute": baseline_ops_per_minute - current_avg,
                "ops_saved_per_hour": (baseline_ops_per_minute - current_avg) * 60,
                "ops_saved_per_day": (baseline_ops_per_minute - current_avg) * 60 * 24
            }
            
            print(f"✅ Performance comparison complete - {reduction_percentage:.1f}% reduction")
        else:
            print("⚠️  No operation data available for comparison")
    
    def generate_report(self):
        """Generate comprehensive performance report"""
        print("\n📋 Generating comprehensive performance report...")
        
        report = {
            "report_timestamp": datetime.now().isoformat(),
            "optimization_summary": {
                "redis_connection_status": "✅ Working" if not self.metrics["optimization_status"].get("redis_errors", True) else "❌ Issues",
                "event_driven_architecture": "✅ Enabled" if self.metrics["optimization_status"].get("event_driven_enabled", False) else "❌ Disabled",
                "polling_optimization": "✅ 5-10 min intervals" if self.metrics["optimization_status"].get("fallback_polling_300s", False) else "⚠️ Unknown",
                "optimization_score": f"{self.metrics.get('optimization_score', 0):.1f}%"
            },
            "redis_performance": {
                "monitoring_duration": f"{self.metrics.get('monitoring_duration', 0)} minutes",
                "total_commands_observed": self.metrics.get("total_commands", 0),
                "average_commands_per_minute": round(statistics.mean(self.metrics["redis_commands_per_minute"]), 2) if self.metrics["redis_commands_per_minute"] else 0,
                "peak_commands_per_minute": max(self.metrics["redis_commands_per_minute"]) if self.metrics["redis_commands_per_minute"] else 0,
                "min_commands_per_minute": min(self.metrics["redis_commands_per_minute"]) if self.metrics["redis_commands_per_minute"] else 0,
                "command_distribution": dict(self.metrics["command_types"])
            },
            "performance_improvement": self.metrics.get("performance_comparison", {}),
            "redis_server_status": {
                "connected_clients": self.metrics["connection_info"].get("client_info", {}).get("connected_clients", "Unknown"),
                "used_memory": self.metrics["connection_info"].get("memory_info", {}).get("used_memory_human", "Unknown"),
                "redis_version": self.metrics["connection_info"].get("server_info", {}).get("redis_version", "Unknown")
            }
        }
        
        return report
    
    def print_report(self, report):
        """Print formatted performance report"""
        print("\n" + "="*80)
        print("🚀 REDIS OPTIMIZATION PERFORMANCE REPORT")
        print("="*80)
        
        print(f"\n📊 OPTIMIZATION SUMMARY:")
        print(f"   Redis Connection: {report['optimization_summary']['redis_connection_status']}")
        print(f"   Event-Driven Architecture: {report['optimization_summary']['event_driven_architecture']}")
        print(f"   Polling Optimization: {report['optimization_summary']['polling_optimization']}")
        print(f"   Overall Optimization Score: {report['optimization_summary']['optimization_score']}")
        
        print(f"\n⚡ REDIS PERFORMANCE METRICS:")
        print(f"   Monitoring Duration: {report['redis_performance']['monitoring_duration']}")
        print(f"   Average Commands/Minute: {report['redis_performance']['average_commands_per_minute']}")
        print(f"   Peak Commands/Minute: {report['redis_performance']['peak_commands_per_minute']}")
        print(f"   Total Commands Observed: {report['redis_performance']['total_commands_observed']}")
        
        if report['performance_improvement']:
            print(f"\n🎯 PERFORMANCE IMPROVEMENT:")
            improvement = report['performance_improvement']
            print(f"   Baseline: {improvement.get('baseline_ops_per_minute', 'N/A')} ops/minute")
            print(f"   Current: {improvement.get('current_avg_ops_per_minute', 'N/A'):.1f} ops/minute")
            print(f"   Reduction: {improvement.get('reduction_percentage', 0):.1f}%")
            print(f"   Operations Saved: {improvement.get('ops_saved_per_minute', 0):.1f}/min, {improvement.get('ops_saved_per_hour', 0):.0f}/hour")
        
        print(f"\n🔧 REDIS SERVER STATUS:")
        print(f"   Redis Version: {report['redis_server_status']['redis_version']}")
        print(f"   Connected Clients: {report['redis_server_status']['connected_clients']}")
        print(f"   Memory Usage: {report['redis_server_status']['used_memory']}")
        
        if report['redis_performance']['command_distribution']:
            print(f"\n📈 COMMAND DISTRIBUTION:")
            for cmd, count in sorted(report['redis_performance']['command_distribution'].items(), key=lambda x: x[1], reverse=True):
                print(f"   {cmd}: {count} operations")
        
        print("\n" + "="*80)
        print("✅ OPTIMIZATION STATUS: SUCCESS" if float(report['optimization_summary']['optimization_score'].rstrip('%')) > 70 else "⚠️  NEEDS ATTENTION")
        print("="*80)

def main():
    print("🔍 DevSecureX Redis Performance Analysis")
    print("=" * 50)
    
    analyzer = RedisPerformanceAnalyzer()
    
    # Step 1: Check optimization status
    analyzer.check_worker_intervals()
    
    # Step 2: Gather Redis server information
    analyzer.get_redis_info()
    
    # Step 3: Monitor Redis operations (5 minutes)
    print(f"\n⏳ Starting 5-minute Redis operation monitoring...")
    print("This will track all Redis commands to measure optimization effectiveness...")
    
    operation_stats = analyzer.count_redis_operations(duration_minutes=5)
    
    # Step 4: Generate performance comparison
    analyzer.generate_performance_comparison(baseline_ops_per_minute=64)
    
    # Step 5: Generate and display report
    report = analyzer.generate_report()
    analyzer.print_report(report)
    
    # Step 6: Save report to file
    report_file = f"redis_optimization_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n💾 Detailed report saved to: {report_file}")
    print(f"📝 Summary: Redis optimization achieved {report['performance_improvement'].get('reduction_percentage', 0):.1f}% reduction in operations")

if __name__ == "__main__":
    main()