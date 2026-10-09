"""
Event-Driven Monitoring System for DevSecureX
Phase 3: Final polling elimination for background monitoring systems

This system replaces all background monitoring loops with event-driven notifications,
achieving the final 15% reduction needed to reach <1,000 Redis calls/day.

Key Features:
- System health events (SYSTEM_HEALTH_STATUS_CHANGE)
- Database connectivity events (DATABASE_CONNECTIVITY_EVENT)
- Performance threshold events (PERFORMANCE_THRESHOLD_BREACH)
- Resource utilization events (RESOURCE_UTILIZATION_EVENT)
- Application status events (APPLICATION_STATUS_CHANGE)
- Monitoring alert events (MONITORING_ALERT_EVENT)
"""

import asyncio
import logging
import time
import psutil
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, asdict
from enum import Enum
import json

from core.redis_optimized import get_redis_optimizer
from core.database import get_connection_health
from monitoring.structured_logging import get_logger

logger_instance = get_logger()
logger = logger_instance.get_logger()

class MonitoringEventType(Enum):
    """Types of monitoring events"""
    SYSTEM_HEALTH_STATUS_CHANGE = "system_health_status_change"
    DATABASE_CONNECTIVITY_EVENT = "database_connectivity_event"
    PERFORMANCE_THRESHOLD_BREACH = "performance_threshold_breach"
    RESOURCE_UTILIZATION_EVENT = "resource_utilization_event"
    APPLICATION_STATUS_CHANGE = "application_status_change"
    MONITORING_ALERT_EVENT = "monitoring_alert_event"
    REDIS_USAGE_ALERT = "redis_usage_alert"
    TIMEOUT_EVENT = "timeout_event"

class Severity(Enum):
    """Event severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

@dataclass
class MonitoringEvent:
    """Event-driven monitoring event"""
    event_type: MonitoringEventType
    component: str
    severity: Severity
    message: str
    details: Dict[str, Any]
    timestamp: str
    source: str
    requires_action: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "component": self.component,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
            "source": self.source,
            "requires_action": self.requires_action
        }

class EventDrivenMonitoringSystem:
    """
    Event-driven monitoring system that eliminates polling loops
    
    Instead of continuous polling:
    - Monitors critical thresholds
    - Publishes events only on significant changes
    - Uses extended safe intervals for essential checks
    - Achieves <1,000 Redis calls/day system-wide
    """
    
    def __init__(self):
        self.running = False
        self.event_subscribers: Dict[MonitoringEventType, List[Callable]] = {}
        self.last_event_times: Dict[str, datetime] = {}
        
        # Event suppression to prevent spam (cooldown periods)
        self.event_cooldowns = {
            MonitoringEventType.SYSTEM_HEALTH_STATUS_CHANGE: timedelta(minutes=5),
            MonitoringEventType.DATABASE_CONNECTIVITY_EVENT: timedelta(minutes=2),
            MonitoringEventType.PERFORMANCE_THRESHOLD_BREACH: timedelta(minutes=1),
            MonitoringEventType.RESOURCE_UTILIZATION_EVENT: timedelta(minutes=3),
            MonitoringEventType.APPLICATION_STATUS_CHANGE: timedelta(minutes=10),
            MonitoringEventType.MONITORING_ALERT_EVENT: timedelta(minutes=1),
            MonitoringEventType.REDIS_USAGE_ALERT: timedelta(minutes=15),
            MonitoringEventType.TIMEOUT_EVENT: timedelta(seconds=30)
        }
        
        # Last known states for change detection
        self.last_states = {
            "system_health": None,
            "database_status": None,
            "redis_status": None,
            "cpu_critical": False,
            "memory_critical": False,
            "disk_critical": False
        }
        
        # Performance thresholds
        self.thresholds = {
            "cpu_warning": 80.0,
            "cpu_critical": 90.0,
            "memory_warning": 80.0,
            "memory_critical": 90.0,
            "disk_warning": 80.0,
            "disk_critical": 90.0,
            "redis_quota_warning": 70.0,
            "redis_quota_critical": 85.0,
            "db_response_warning": 5.0,  # seconds
            "db_response_critical": 10.0,  # seconds
        }
        
        # Extended safe intervals (Phase 3 optimization)
        self.check_intervals = {
            "system_health": 300,      # 5 minutes (was 60 seconds) = 83% reduction
            "resource_utilization": 180, # 3 minutes (was 15 seconds) = 92% reduction  
            "database_connectivity": 600, # 10 minutes (was 60 seconds) = 90% reduction
            "redis_usage": 1800,       # 30 minutes (was 5 minutes) = 83% reduction
            "cleanup": 86400           # Daily cleanup (unchanged)
        }
        
        # Event statistics
        self.event_stats = {
            "total_events_published": 0,
            "events_by_type": {},
            "events_suppressed": 0,
            "last_activity": None
        }
        
        logger.info("🎯 Event-Driven Monitoring System initialized")
        logger.info(f"📊 Extended intervals: Health={self.check_intervals['system_health']}s, Resources={self.check_intervals['resource_utilization']}s")
    
    def subscribe_to_event(self, event_type: MonitoringEventType, callback: Callable):
        """Subscribe to monitoring events"""
        if event_type not in self.event_subscribers:
            self.event_subscribers[event_type] = []
        
        self.event_subscribers[event_type].append(callback)
        logger.info(f"Subscribed to {event_type.value} events")
    
    async def publish_event(self, event: MonitoringEvent) -> bool:
        """Publish a monitoring event (with suppression)"""
        
        # Check cooldown to prevent event spam
        event_key = f"{event.event_type.value}_{event.component}"
        now = datetime.now(timezone.utc)
        
        if event_key in self.last_event_times:
            last_time = self.last_event_times[event_key]
            cooldown = self.event_cooldowns.get(event.event_type, timedelta(minutes=1))
            
            if now - last_time < cooldown:
                self.event_stats["events_suppressed"] += 1
                logger.debug(f"Event suppressed (cooldown): {event_key}")
                return False
        
        self.last_event_times[event_key] = now
        
        # Update statistics
        self.event_stats["total_events_published"] += 1
        self.event_stats["last_activity"] = event.timestamp
        
        if event.event_type.value not in self.event_stats["events_by_type"]:
            self.event_stats["events_by_type"][event.event_type.value] = 0
        self.event_stats["events_by_type"][event.event_type.value] += 1
        
        # Log the event
        log_level = {
            Severity.INFO: logger.info,
            Severity.WARNING: logger.warning,
            Severity.CRITICAL: logger.error
        }[event.severity]
        
        log_level(
            f"🔔 {event.severity.value.upper()} EVENT: {event.message}",
            event_type=event.event_type.value,
            component=event.component,
            source=event.source,
            requires_action=event.requires_action,
            **event.details
        )
        
        # Notify subscribers
        subscribers = self.event_subscribers.get(event.event_type, [])
        for callback in subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event)
                else:
                    callback(event)
            except Exception as e:
                logger.error(f"Error in event subscriber: {e}")
        
        return True
    
    async def start_monitoring(self):
        """Start event-driven monitoring with extended intervals"""
        if self.running:
            return
        
        self.running = True
        logger.info("🚀 Starting event-driven monitoring system")
        
        # Start monitoring tasks with extended intervals
        monitoring_tasks = [
            self._monitor_system_health(),
            self._monitor_resource_utilization(),
            self._monitor_database_connectivity(),
            self._monitor_redis_usage(),
            self._cleanup_old_data()
        ]
        
        await asyncio.gather(*monitoring_tasks, return_exceptions=True)
    
    async def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        logger.info("🛑 Event-driven monitoring system stopped")
    
    async def _monitor_system_health(self):
        """Monitor overall system health with 5-minute intervals"""
        logger.info("📊 Started system health monitoring (5-minute intervals)")
        
        while self.running:
            try:
                # Get current system health
                current_health = await self._get_current_system_health()
                
                # Check for health state changes
                if self.last_states["system_health"] != current_health["status"]:
                    await self.publish_event(MonitoringEvent(
                        event_type=MonitoringEventType.SYSTEM_HEALTH_STATUS_CHANGE,
                        component="system",
                        severity=self._get_severity_from_health(current_health["status"]),
                        message=f"System health changed to {current_health['status']}",
                        details=current_health,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        source="event_driven_monitoring",
                        requires_action=current_health["status"] in ["critical", "degraded"]
                    ))
                    
                    self.last_states["system_health"] = current_health["status"]
                
                await asyncio.sleep(self.check_intervals["system_health"])
                
            except Exception as e:
                logger.error(f"Error in system health monitoring: {e}")
                await asyncio.sleep(60)  # Short retry interval
    
    async def _monitor_resource_utilization(self):
        """Monitor system resources with 3-minute intervals"""
        logger.info("💻 Started resource utilization monitoring (3-minute intervals)")
        
        while self.running:
            try:
                # Get current resource usage
                resources = await self._get_resource_utilization()
                
                # Check for threshold breaches
                for resource, value in resources.items():
                    if resource in ["cpu_percent", "memory_percent", "disk_percent"]:
                        resource_name = resource.replace("_percent", "")
                        warning_threshold = self.thresholds.get(f"{resource_name}_warning", 80)
                        critical_threshold = self.thresholds.get(f"{resource_name}_critical", 90)
                        
                        current_critical = value >= critical_threshold
                        last_critical = self.last_states.get(f"{resource_name}_critical", False)
                        
                        # Only publish events on state changes
                        if current_critical != last_critical:
                            severity = Severity.CRITICAL if current_critical else Severity.WARNING
                            
                            await self.publish_event(MonitoringEvent(
                                event_type=MonitoringEventType.RESOURCE_UTILIZATION_EVENT,
                                component=resource_name,
                                severity=severity,
                                message=f"{resource_name.upper()} usage: {value:.1f}% (threshold: {critical_threshold}%)",
                                details={
                                    "current_usage": value,
                                    "warning_threshold": warning_threshold,
                                    "critical_threshold": critical_threshold,
                                    "trend": "increasing" if current_critical else "decreasing"
                                },
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                source="resource_monitor",
                                requires_action=current_critical
                            ))
                            
                            self.last_states[f"{resource_name}_critical"] = current_critical
                
                await asyncio.sleep(self.check_intervals["resource_utilization"])
                
            except Exception as e:
                logger.error(f"Error in resource monitoring: {e}")
                await asyncio.sleep(60)
    
    async def _monitor_database_connectivity(self):
        """Monitor database connectivity with 10-minute intervals"""
        logger.info("🗄️ Started database connectivity monitoring (10-minute intervals)")
        
        while self.running:
            try:
                start_time = time.time()
                
                # Test database connectivity
                try:
                    health_data = await get_connection_health()
                    response_time = time.time() - start_time
                    
                    current_status = "healthy" if health_data.get("connection_test", {}).get("status") == "healthy" else "unhealthy"
                    
                    # Check for status changes
                    if self.last_states["database_status"] != current_status:
                        severity = Severity.CRITICAL if current_status == "unhealthy" else Severity.INFO
                        
                        await self.publish_event(MonitoringEvent(
                            event_type=MonitoringEventType.DATABASE_CONNECTIVITY_EVENT,
                            component="database",
                            severity=severity,
                            message=f"Database status changed to {current_status}",
                            details={
                                "status": current_status,
                                "response_time_ms": response_time * 1000,
                                "health_data": health_data
                            },
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            source="database_monitor",
                            requires_action=current_status == "unhealthy"
                        ))
                        
                        self.last_states["database_status"] = current_status
                    
                    # Check for performance degradation
                    if response_time > self.thresholds["db_response_critical"]:
                        await self.publish_event(MonitoringEvent(
                            event_type=MonitoringEventType.PERFORMANCE_THRESHOLD_BREACH,
                            component="database",
                            severity=Severity.CRITICAL,
                            message=f"Database response time critical: {response_time:.2f}s",
                            details={
                                "response_time_seconds": response_time,
                                "threshold": self.thresholds["db_response_critical"]
                            },
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            source="database_monitor",
                            requires_action=True
                        ))
                
                except Exception as db_error:
                    if self.last_states["database_status"] != "error":
                        await self.publish_event(MonitoringEvent(
                            event_type=MonitoringEventType.DATABASE_CONNECTIVITY_EVENT,
                            component="database",
                            severity=Severity.CRITICAL,
                            message=f"Database connectivity failed: {str(db_error)}",
                            details={"error": str(db_error)},
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            source="database_monitor",
                            requires_action=True
                        ))
                        
                        self.last_states["database_status"] = "error"
                
                await asyncio.sleep(self.check_intervals["database_connectivity"])
                
            except Exception as e:
                logger.error(f"Error in database monitoring: {e}")
                await asyncio.sleep(120)
    
    async def _monitor_redis_usage(self):
        """Monitor Redis usage with 30-minute intervals"""
        logger.info("📊 Started Redis usage monitoring (30-minute intervals)")
        
        while self.running:
            try:
                # Get Redis usage statistics
                redis_stats = await self._get_redis_usage_stats()
                
                if redis_stats:
                    quota_usage = redis_stats.get("quota_burn_rate_percent", 0)
                    
                    # Check for quota threshold breaches
                    if quota_usage >= self.thresholds["redis_quota_critical"]:
                        await self.publish_event(MonitoringEvent(
                            event_type=MonitoringEventType.REDIS_USAGE_ALERT,
                            component="redis",
                            severity=Severity.CRITICAL,
                            message=f"Redis quota CRITICAL: {quota_usage:.1f}% burn rate",
                            details={
                                "quota_usage_percent": quota_usage,
                                "daily_estimate": redis_stats.get("estimated_daily_usage", 0),
                                "commands_per_minute": redis_stats.get("commands_per_minute", 0)
                            },
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            source="redis_monitor",
                            requires_action=True
                        ))
                    elif quota_usage >= self.thresholds["redis_quota_warning"]:
                        await self.publish_event(MonitoringEvent(
                            event_type=MonitoringEventType.REDIS_USAGE_ALERT,
                            component="redis",
                            severity=Severity.WARNING,
                            message=f"Redis quota WARNING: {quota_usage:.1f}% burn rate",
                            details={
                                "quota_usage_percent": quota_usage,
                                "daily_estimate": redis_stats.get("estimated_daily_usage", 0)
                            },
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            source="redis_monitor",
                            requires_action=False
                        ))
                
                await asyncio.sleep(self.check_intervals["redis_usage"])
                
            except Exception as e:
                logger.error(f"Error in Redis usage monitoring: {e}")
                await asyncio.sleep(300)  # 5-minute retry
    
    async def _cleanup_old_data(self):
        """Daily cleanup of old monitoring data"""
        logger.info("🧹 Started daily cleanup monitoring")
        
        while self.running:
            try:
                # Clean up old event records
                cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
                
                # Remove old event times
                old_keys = [
                    key for key, timestamp in self.last_event_times.items()
                    if timestamp < cutoff_time
                ]
                
                for key in old_keys:
                    del self.last_event_times[key]
                
                if old_keys:
                    logger.info(f"🗑️ Cleaned up {len(old_keys)} old event records")
                
                await asyncio.sleep(self.check_intervals["cleanup"])
                
            except Exception as e:
                logger.error(f"Error in cleanup monitoring: {e}")
                await asyncio.sleep(3600)  # 1-hour retry
    
    async def _get_current_system_health(self) -> Dict[str, Any]:
        """Get current system health summary"""
        try:
            # Simplified health check to minimize Redis calls
            from monitoring.comprehensive_health import get_health_system
            health_system = get_health_system()
            
            # Use quick health check instead of full system check
            quick_health = await health_system.get_quick_health()
            
            return {
                "status": "healthy" if quick_health.get("healthy", False) else "degraded",
                "healthy_components": quick_health.get("healthy_components", 0),
                "total_components": quick_health.get("checked_components", 0),
                "timestamp": quick_health.get("timestamp")
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    async def _get_resource_utilization(self) -> Dict[str, float]:
        """Get current system resource utilization"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "memory_available_gb": psutil.virtual_memory().available / (1024**3)
            }
        except Exception as e:
            logger.error(f"Failed to get resource utilization: {e}")
            return {}
    
    async def _get_redis_usage_stats(self) -> Optional[Dict[str, Any]]:
        """Get Redis usage statistics"""
        try:
            from monitoring.redis_usage_monitor import get_redis_monitor
            monitor = get_redis_monitor()
            return await monitor.check_quota_usage()
        except Exception as e:
            logger.error(f"Failed to get Redis usage stats: {e}")
            return None
    
    def _get_severity_from_health(self, health_status: str) -> Severity:
        """Convert health status to event severity"""
        severity_mapping = {
            "healthy": Severity.INFO,
            "good": Severity.INFO,
            "degraded": Severity.WARNING,
            "fair": Severity.WARNING,
            "unhealthy": Severity.CRITICAL,
            "poor": Severity.CRITICAL,
            "critical": Severity.CRITICAL,
            "error": Severity.CRITICAL
        }
        return severity_mapping.get(health_status, Severity.WARNING)
    
    async def force_health_check(self) -> Dict[str, Any]:
        """Force immediate health check (for testing/debugging)"""
        logger.info("🔍 Forcing immediate health check...")
        
        results = {
            "system_health": await self._get_current_system_health(),
            "resources": await self._get_resource_utilization(),
            "redis_usage": await self._get_redis_usage_stats(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return results
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring system statistics"""
        return {
            "running": self.running,
            "event_stats": self.event_stats,
            "active_subscribers": sum(len(subs) for subs in self.event_subscribers.values()),
            "check_intervals": self.check_intervals,
            "last_states": self.last_states,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

# Global instance
_monitoring_system: Optional[EventDrivenMonitoringSystem] = None

def get_event_driven_monitoring() -> EventDrivenMonitoringSystem:
    """Get global event-driven monitoring instance"""
    global _monitoring_system
    if _monitoring_system is None:
        _monitoring_system = EventDrivenMonitoringSystem()
    return _monitoring_system

async def start_event_driven_monitoring():
    """Start the global event-driven monitoring system"""
    monitoring = get_event_driven_monitoring()
    await monitoring.start_monitoring()

async def stop_event_driven_monitoring():
    """Stop the global event-driven monitoring system"""
    monitoring = get_event_driven_monitoring()
    await monitoring.stop_monitoring()

# Utility functions for manual event publishing
async def publish_timeout_event(endpoint: str, duration: float, timeout_limit: float):
    """Publish a timeout event"""
    monitoring = get_event_driven_monitoring()
    await monitoring.publish_event(MonitoringEvent(
        event_type=MonitoringEventType.TIMEOUT_EVENT,
        component=endpoint,
        severity=Severity.WARNING if duration < timeout_limit * 1.5 else Severity.CRITICAL,
        message=f"Endpoint timeout: {endpoint} took {duration:.2f}s",
        details={
            "endpoint": endpoint,
            "actual_duration": duration,
            "timeout_limit": timeout_limit
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
        source="timeout_monitor",
        requires_action=duration > timeout_limit * 2
    ))

async def publish_application_status_event(component: str, status: str, details: Dict[str, Any]):
    """Publish an application status change event"""
    monitoring = get_event_driven_monitoring()
    severity = Severity.CRITICAL if status in ["error", "failed"] else Severity.INFO
    
    await monitoring.publish_event(MonitoringEvent(
        event_type=MonitoringEventType.APPLICATION_STATUS_CHANGE,
        component=component,
        severity=severity,
        message=f"{component} status: {status}",
        details=details,
        timestamp=datetime.now(timezone.utc).isoformat(),
        source="application_monitor",
        requires_action=severity == Severity.CRITICAL
    ))

# Initialize on import
try:
    logger.info("🎯 Event-driven monitoring system ready for Phase 3 optimization")
except Exception as e:
    print(f"Failed to initialize event-driven monitoring: {e}")