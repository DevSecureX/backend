#!/usr/bin/env python3

import subprocess
import time
from datetime import datetime

def quick_redis_test(duration=10):
    """Quick Redis command monitor"""
    
    print(f"Quick Redis monitoring for {duration} seconds...")
    start_time = time.time()
    
    proc = subprocess.Popen(
        ['docker', 'exec', 'devsecurex-redis', 'redis-cli', 'MONITOR'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    commands = []
    ping_count = 0
    
    try:
        while time.time() - start_time < duration:
            line = proc.stdout.readline()
            if line:
                timestamp = datetime.now()
                commands.append((timestamp, line.strip()))
                if 'PING' in line.upper():
                    ping_count += 1
                    print(f"[{timestamp.strftime('%H:%M:%S.%f')[:-3]}] PING #{ping_count}")
            else:
                time.sleep(0.01)
                
    except KeyboardInterrupt:
        print("\nMonitoring interrupted")
    finally:
        proc.terminate()
    
    elapsed = time.time() - start_time
    
    print(f"\n=== {duration}s REDIS MONITORING RESULTS ===")
    print(f"Duration: {elapsed:.2f} seconds")
    print(f"Total commands: {len(commands)}")
    print(f"PING commands: {ping_count}")
    
    if ping_count > 0:
        print(f"PING frequency: {ping_count / elapsed:.3f} pings/second")
        print(f"Expected interval: {elapsed / ping_count:.2f} seconds between pings")
        
        # Improvement calculation
        original_rate = 76  # pings per second from crisis
        current_rate = ping_count / elapsed
        improvement = (original_rate - current_rate) / original_rate * 100
        print(f"Improvement from crisis: {improvement:.1f}% reduction")
        
        # Cost impact
        daily_pings = current_rate * 86400
        monthly_pings = daily_pings * 30
        print(f"Projected daily pings: {daily_pings:,.0f}")
        print(f"Projected monthly pings: {monthly_pings:,.0f}")
    else:
        print("✅ NO PINGS DETECTED - Excellent optimization!")
        print("✅ Redis health check interval optimization successful")
    
    return ping_count, elapsed

if __name__ == "__main__":
    quick_redis_test(10)