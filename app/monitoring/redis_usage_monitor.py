"""
Redis Usage Monitor for DevSecureX
Monitors Redis command usage to prevent quota exhaustion
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

from core.redis import get_redis_client
from core.utils import utc_now_iso, utc_now
from datetime import datetime

logger = logging.getLogger(__name__)

@dataclass
class RedisUsageStats:
    """Redis usage statistics"""
    timestamp: str
    total_commands: int
    commands_per_minute: float
    memory_used_bytes: int
    memory_used_mb: float
    connected_clients: int
    keyspace_hits: int
    keyspace_misses: int
    hit_rate_percent: float
    uptime_seconds: int
    
    # Custom metrics for DevSecureX
    zpopmin_calls: int = 0
    scan_calls: int = 0
    ping_calls: int = 0
    estimated_daily_usage: int = 0
    quota_burn_rate_percent: float = 0.0

class RedisUsageMonitor:
    """Monitor Redis usage and provide alerts for quota management"""
    
    def __init__(self):
        self.monitoring = False
        self._stop_monitoring = False
        self.daily_quota = int(os.getenv("REDIS_DAILY_QUOTA", "500000"))  # Default 500k requests/day
        self.alert_threshold = float(os.getenv("REDIS_ALERT_THRESHOLD", "0.8"))  # Alert at 80%
        
        self.stats_history: List[RedisUsageStats] = []
        self.max_history_size = int(os.getenv("REDIS_STATS_HISTORY_SIZE", "100"))
        
        # Command tracking
        self.command_counts: Dict[str, int] = {}
        self.last_reset = time.time()
        
        logger.info(f"Redis Usage Monitor initialized - Daily quota: {self.daily_quota:,}")
    
    async def get_current_stats(self) -> Optional[RedisUsageStats]:
        """Get current Redis usage statistics"""
        try:
            redis_client = await get_redis_client()
            if not redis_client:
                logger.warning("Redis client not available for usage monitoring")
                return None
            
            # Get Redis INFO stats
            info = await redis_client.info()
            
            # Extract key metrics
            total_commands = info.get('total_commands_processed', 0)
            memory_used = info.get('used_memory', 0)
            connected_clients = info.get('connected_clients', 0)
            keyspace_hits = info.get('keyspace_hits', 0)
            keyspace_misses = info.get('keyspace_misses', 0)
            uptime_seconds = info.get('uptime_in_seconds', 0)
            
            # Calculate derived metrics
            total_keyspace_ops = keyspace_hits + keyspace_misses
            hit_rate = (keyspace_hits / max(1, total_keyspace_ops)) * 100
            memory_mb = memory_used / (1024 * 1024)
            
            # Calculate commands per minute (rough estimate)
            commands_per_minute = total_commands / max(1, uptime_seconds / 60)
            
            # Estimate daily usage based on current rate
            estimated_daily = int(commands_per_minute * 60 * 24)
            quota_burn_rate = (estimated_daily / self.daily_quota) * 100
            
            # Count specific commands we care about (would need Redis MONITOR for exact counts)
            zpopmin_calls = self.command_counts.get('ZPOPMIN', 0)
            scan_calls = self.command_counts.get('SCAN', 0) 
            ping_calls = self.command_counts.get('PING', 0)
            
            stats = RedisUsageStats(
                timestamp=utc_now_iso(),
                total_commands=total_commands,
                commands_per_minute=commands_per_minute,
                memory_used_bytes=memory_used,
                memory_used_mb=memory_mb,
                connected_clients=connected_clients,
                keyspace_hits=keyspace_hits,
                keyspace_misses=keyspace_misses,
                hit_rate_percent=hit_rate,
                uptime_seconds=uptime_seconds,
                zpopmin_calls=zpopmin_calls,
                scan_calls=scan_calls,
                ping_calls=ping_calls,
                estimated_daily_usage=estimated_daily,
                quota_burn_rate_percent=quota_burn_rate
            )
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting Redis usage stats: {e}")
            return None
    
    async def check_quota_usage(self) -> Dict[str, Any]:
        """Check quota usage and return alert status"""
        stats = await self.get_current_stats()
        if not stats:
            return {"status": "unknown", "error": "Could not retrieve Redis stats"}
        
        # Check if we're over the alert threshold
        is_critical = stats.quota_burn_rate_percent >= (self.alert_threshold * 100)
        is_warning = stats.quota_burn_rate_percent >= ((self.alert_threshold - 0.1) * 100)
        
        status = "critical" if is_critical else "warning" if is_warning else "healthy"
        
        result = {
            "status": status,
            "quota_usage_percent": stats.quota_burn_rate_percent,
            "estimated_daily_usage": stats.estimated_daily_usage,
            "daily_quota": self.daily_quota,
            "commands_per_minute": stats.commands_per_minute,
            "memory_used_mb": stats.memory_used_mb,
            "hit_rate_percent": stats.hit_rate_percent,
            "recommendations": []
        }
        
        # Add recommendations based on usage
        if is_critical:
            result["recommendations"].extend([
                "IMMEDIATE ACTION REQUIRED: Disable background workers",
                "Set ENABLE_BACKGROUND_WORKERS=false",
                "Set ENABLE_AUTOFIX_WORKERS=false", 
                "Increase polling intervals to 60+ seconds",
                "Consider switching to webhook-based scanning"
            ])
        elif is_warning:
            result["recommendations"].extend([
                "Consider reducing worker count",
                "Increase cache TTL values",
                "Optimize polling frequencies",
                "Monitor closely for next few hours"
            ])
        else:
            result["recommendations"].append("Usage is within normal limits")
        
        return result
    
    async def start_monitoring(self, interval_minutes: int = 30):
        """Start event-driven monitoring with extended intervals (Phase 3 optimization)
        
        Now uses 30-minute intervals instead of 5-minute (83% reduction in Redis calls)
        Publishes events only when thresholds are crossed
        """
        if self.monitoring:
            logger.warning("Redis monitoring already running")
            return
        
        self.monitoring = True
        self._stop_monitoring = False
        
        logger.info(f"🎯 Starting PHASE 3 Redis monitoring (interval: {interval_minutes} minutes) - 83% polling reduction")
        
        # Initialize event-driven monitoring
        try:
            from monitoring.event_driven_monitoring import get_event_driven_monitoring
            self.event_monitoring = get_event_driven_monitoring()
        except ImportError:
            logger.warning("Event-driven monitoring not available, using extended intervals only")
            self.event_monitoring = None
        
        while not self._stop_monitoring and self.monitoring:
            try:
                # Get current stats
                stats = await self.get_current_stats()
                if stats:
                    # Add to history
                    self.stats_history.append(stats)
                    
                    # Trim history if too large
                    if len(self.stats_history) > self.max_history_size:
                        self.stats_history = self.stats_history[-self.max_history_size:]
                    
                    # Check for alerts and publish events if thresholds crossed
                    alert_check = await self.check_quota_usage()
                    
                    # EVENT-DRIVEN: Only log/alert on status changes or critical thresholds
                    if alert_check["status"] == "critical":
                        # Always log critical status
                        logger.error(f"🚨 PHASE 3: REDIS QUOTA CRITICAL: {alert_check['quota_usage_percent']:.1f}% burn rate")
                        logger.error(f"Daily estimate: {alert_check['estimated_daily_usage']:,} / {self.daily_quota:,}")
                        
                        # Publish critical event
                        if self.event_monitoring:
                            from monitoring.event_driven_monitoring import MonitoringEvent, MonitoringEventType, Severity
                            from datetime import timezone
                            
                            await self.event_monitoring.publish_event(MonitoringEvent(
                                event_type=MonitoringEventType.REDIS_USAGE_ALERT,
                                component="redis_quota",
                                severity=Severity.CRITICAL,
                                message=f"Redis quota CRITICAL: {alert_check['quota_usage_percent']:.1f}% burn rate",
                                details={
                                    "quota_usage_percent": alert_check['quota_usage_percent'],
                                    "estimated_daily_usage": alert_check['estimated_daily_usage'],
                                    "daily_quota": self.daily_quota,
                                    "commands_per_minute": alert_check['commands_per_minute']
                                },
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                source="redis_usage_monitor",
                                requires_action=True
                            ))
                    
                    elif alert_check["status"] == "warning":
                        # Log warning less frequently
                        logger.warning(f"⚠️  PHASE 3: Redis quota warning: {alert_check['quota_usage_percent']:.1f}% burn rate")
                    
                    else:
                        # Only log healthy status occasionally (every 6th check = 3 hours)
                        if len(self.stats_history) % 6 == 0:
                            logger.info(f"✅ PHASE 3: Redis usage healthy: {alert_check['quota_usage_percent']:.1f}% burn rate")
                
                # PHASE 3: Extended 30-minute intervals (was 5 minutes)
                await asyncio.sleep(interval_minutes * 60)
                
            except Exception as e:
                logger.error(f"Error in Redis monitoring loop: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retrying (was 1 minute)
    
    async def stop_monitoring(self):
        """Stop monitoring"""
        self._stop_monitoring = True
        self.monitoring = False
        logger.info("Redis usage monitoring stopped")
    
    def get_stats_summary(self) -> Dict[str, Any]:
        """Get summary of recent stats"""
        if not self.stats_history:
            return {"error": "No stats available"}
        
        recent_stats = self.stats_history[-10:]  # Last 10 readings
        
        avg_commands_per_minute = sum(s.commands_per_minute for s in recent_stats) / len(recent_stats)
        avg_memory_mb = sum(s.memory_used_mb for s in recent_stats) / len(recent_stats)
        avg_hit_rate = sum(s.hit_rate_percent for s in recent_stats) / len(recent_stats)
        
        latest = recent_stats[-1]
        
        return {
            "latest_stats": asdict(latest),
            "averages_last_10": {
                "commands_per_minute": avg_commands_per_minute,
                "memory_used_mb": avg_memory_mb,
                "hit_rate_percent": avg_hit_rate
            },
            "total_readings": len(self.stats_history),
            "monitoring_active": self.monitoring
        }
    
    def get_usage_trend(self) -> Dict[str, Any]:
        """Analyze usage trend"""
        if len(self.stats_history) < 2:
            return {"error": "Not enough data for trend analysis"}
        
        # Compare latest vs 1 hour ago (assuming 5-min intervals)
        latest = self.stats_history[-1]
        hour_ago_idx = max(0, len(self.stats_history) - 12)
        hour_ago = self.stats_history[hour_ago_idx]
        
        commands_trend = latest.commands_per_minute - hour_ago.commands_per_minute
        memory_trend = latest.memory_used_mb - hour_ago.memory_used_mb
        quota_trend = latest.quota_burn_rate_percent - hour_ago.quota_burn_rate_percent
        
        return {
            "trend_period_minutes": (len(self.stats_history) - hour_ago_idx) * 5,
            "commands_per_minute_change": commands_trend,
            "memory_mb_change": memory_trend, 
            "quota_burn_rate_change": quota_trend,
            "trend_direction": "increasing" if commands_trend > 0 else "decreasing" if commands_trend < 0 else "stable"
        }

# Global monitor instance
_monitor: Optional[RedisUsageMonitor] = None

def get_redis_monitor() -> RedisUsageMonitor:
    """Get the global Redis monitor instance"""
    global _monitor
    if _monitor is None:
        _monitor = RedisUsageMonitor()
    return _monitor

async def start_redis_monitoring():
    """Start Redis usage monitoring"""
    monitor = get_redis_monitor()
    # Start monitoring in background task
    asyncio.create_task(monitor.start_monitoring())

async def stop_redis_monitoring():
    """Stop Redis usage monitoring"""
    monitor = get_redis_monitor()
    await monitor.stop_monitoring()

# CLI command for checking Redis usage
async def cli_check_redis_usage():
    """CLI command to check current Redis usage"""
    monitor = get_redis_monitor()
    
    print("\n🔍 DevSecureX Redis Usage Check")
    print("=" * 50)
    
    alert_check = await monitor.check_quota_usage()
    
    status_emoji = {"healthy": "✅", "warning": "⚠️", "critical": "🚨", "unknown": "❓"}
    print(f"\nStatus: {status_emoji.get(alert_check['status'], '?')} {alert_check['status'].upper()}")
    
    if 'error' not in alert_check:
        print(f"Daily Usage Estimate: {alert_check['estimated_daily_usage']:,} / {alert_check['daily_quota']:,}")
        print(f"Quota Burn Rate: {alert_check['quota_usage_percent']:.1f}%")
        print(f"Commands/Minute: {alert_check['commands_per_minute']:.1f}")
        print(f"Memory Used: {alert_check['memory_used_mb']:.1f} MB")
        print(f"Cache Hit Rate: {alert_check['hit_rate_percent']:.1f}%")
        
        if alert_check['recommendations']:
            print(f"\n📋 Recommendations:")
            for rec in alert_check['recommendations']:
                print(f"  • {rec}")
    else:
        print(f"Error: {alert_check['error']}")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    # Run CLI check
    asyncio.run(cli_check_redis_usage())