"""
Comprehensive Health Check System for DevSecureX Backend

Multi-level health monitoring system with:
- Application-level health checks
- Database connection health with performance metrics
- Redis cluster health monitoring
- External service dependency checks
- Resource utilization monitoring
- SLA compliance monitoring
- Automated incident response
- Integration with monitoring systems
"""

import asyncio
import logging
import sys
import time
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Callable
from dataclasses import dataclass, asdict
from enum import Enum

from monitoring.prometheus_metrics import get_metrics
from monitoring.structured_logging import get_logger
from core.database import get_db, get_connection_health, get_pool_status
from core.cache import cache_health_check
from core.redis import get_redis_client
from core.utils import utc_now_iso

logger_instance = get_logger()
logger = logger_instance.get_logger()

class HealthStatus(Enum):
    """Health check status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

class ComponentType(Enum):
    """Types of system components"""
    DATABASE = "database"
    CACHE = "cache"
    EXTERNAL_SERVICE = "external_service"
    QUEUE = "queue"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    APPLICATION = "application"

@dataclass
class HealthCheckResult:
    """Result of a health check"""
    component: str
    component_type: ComponentType
    status: HealthStatus
    message: str
    details: Dict[str, Any]
    check_duration_ms: float
    timestamp: str
    metrics: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[str]] = None

@dataclass
class SystemHealth:
    """Overall system health summary"""
    overall_status: HealthStatus
    healthy_components: int
    degraded_components: int
    unhealthy_components: int
    critical_components: int
    total_components: int
    check_duration_ms: float
    timestamp: str
    components: List[HealthCheckResult]
    sla_compliance: Dict[str, float]
    recommendations: List[str]

class HealthChecker:
    """Individual health check implementation"""
    
    def __init__(self, name: str, component_type: ComponentType, 
                 check_function: Callable, timeout_seconds: int = 30,
                 critical: bool = False):
        self.name = name
        self.component_type = component_type
        self.check_function = check_function
        self.timeout_seconds = timeout_seconds
        self.critical = critical
        
        # Performance tracking
        self.last_check_time: Optional[datetime] = None
        self.last_result: Optional[HealthCheckResult] = None
        self.check_history: List[HealthCheckResult] = []
        self.max_history = 100
    
    async def execute(self) -> HealthCheckResult:
        """Execute the health check with timeout and error handling"""
        start_time = time.time()
        
        try:
            # Execute with timeout
            result = await asyncio.wait_for(
                self.check_function(),
                timeout=self.timeout_seconds
            )
            
            check_duration = (time.time() - start_time) * 1000
            
            # Create result object
            health_result = HealthCheckResult(
                component=self.name,
                component_type=self.component_type,
                status=result.get('status', HealthStatus.UNKNOWN),
                message=result.get('message', 'Health check completed'),
                details=result.get('details', {}),
                check_duration_ms=check_duration,
                timestamp=utc_now_iso(),
                metrics=result.get('metrics'),
                recommendations=result.get('recommendations')
            )
            
            # Update tracking
            self.last_check_time = datetime.utcnow()
            self.last_result = health_result
            self._add_to_history(health_result)
            
            # Log result
            logger.info(
                f"Health check completed: {self.name}",
                component=self.name,
                status=health_result.status.value,
                duration_ms=check_duration,
                event_type="health_check"
            )
            
            return health_result
            
        except asyncio.TimeoutError:
            check_duration = (time.time() - start_time) * 1000
            health_result = HealthCheckResult(
                component=self.name,
                component_type=self.component_type,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {self.timeout_seconds}s",
                details={"timeout": True, "timeout_seconds": self.timeout_seconds},
                check_duration_ms=check_duration,
                timestamp=utc_now_iso(),
                recommendations=["Investigate component performance", "Check resource availability"]
            )
            
            self.last_result = health_result
            self._add_to_history(health_result)
            
            logger.error(
                f"Health check timeout: {self.name}",
                component=self.name,
                timeout_seconds=self.timeout_seconds,
                event_type="health_check_timeout"
            )
            
            return health_result
            
        except Exception as e:
            check_duration = (time.time() - start_time) * 1000
            health_result = HealthCheckResult(
                component=self.name,
                component_type=self.component_type,
                status=HealthStatus.CRITICAL,
                message=f"Health check failed: {str(e)}",
                details={"error": str(e), "error_type": type(e).__name__},
                check_duration_ms=check_duration,
                timestamp=utc_now_iso(),
                recommendations=["Check component logs", "Verify component configuration"]
            )
            
            self.last_result = health_result
            self._add_to_history(health_result)
            
            logger.error(
                f"Health check error: {self.name}",
                component=self.name,
                error=str(e),
                error_type=type(e).__name__,
                event_type="health_check_error"
            )
            
            return health_result
    
    def _add_to_history(self, result: HealthCheckResult):
        """Add result to history with size management"""
        self.check_history.append(result)
        if len(self.check_history) > self.max_history:
            self.check_history = self.check_history[-self.max_history:]
    
    def get_success_rate(self, hours: int = 24) -> float:
        """Get success rate for the last N hours"""
        if not self.check_history:
            return 0.0
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        recent_checks = [
            check for check in self.check_history
            if datetime.fromisoformat(check.timestamp) > cutoff_time
        ]
        
        if not recent_checks:
            return 0.0
        
        successful = sum(1 for check in recent_checks 
                        if check.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED])
        
        return (successful / len(recent_checks)) * 100

class ComprehensiveHealthSystem:
    """Comprehensive health monitoring system"""
    
    def __init__(self):
        self.health_checkers: Dict[str, HealthChecker] = {}
        self.running = False
        self.check_interval = 300  # PHASE 3: Extended to 5 minutes (was 60 seconds) - 80% reduction
        self.parallel_checks = True
        self.event_driven_enabled = True  # Enable event-driven monitoring
        
        # Performance tracking
        self.total_checks = 0
        self.failed_checks = 0
        self.average_check_duration = 0.0
        
        # SLA configuration
        self.sla_targets = {
            'availability': 99.9,  # 99.9% uptime
            'response_time': 5000,  # 5 seconds max response time
            'error_rate': 1.0      # Max 1% error rate
        }
        
        # Initialize built-in health checks
        self._initialize_health_checks()
        
        # PHASE 3: Initialize event-driven monitoring integration
        self.event_monitoring = None
        self.last_overall_health = None
        try:
            from monitoring.event_driven_monitoring import get_event_driven_monitoring
            self.event_monitoring = get_event_driven_monitoring()
            logger.info("🎯 PHASE 3: Health system integrated with event-driven monitoring")
        except ImportError:
            logger.warning("Event-driven monitoring not available")
    
    def _initialize_health_checks(self):
        """Initialize all built-in health checks"""
        
        # Database health check
        self.register_health_check(
            "database_primary",
            ComponentType.DATABASE,
            self._check_database_health,
            timeout_seconds=30,
            critical=True
        )
        
        # Redis cache health check
        self.register_health_check(
            "redis_cache",
            ComponentType.CACHE,
            self._check_redis_health,
            timeout_seconds=15,
            critical=True
        )
        
        # Application health check
        self.register_health_check(
            "application",
            ComponentType.APPLICATION,
            self._check_application_health,
            timeout_seconds=10,
            critical=True
        )
        
        # System resources check
        self.register_health_check(
            "system_resources",
            ComponentType.APPLICATION,
            self._check_system_resources,
            timeout_seconds=5,
            critical=False
        )
        
        # Task system health check
        self.register_health_check(
            "task_system",
            ComponentType.QUEUE,
            self._check_task_system_health,
            timeout_seconds=15,
            critical=False
        )
        
        logger.info("Comprehensive health checks initialized", 
                   total_checks=len(self.health_checkers))
    
    def register_health_check(self, name: str, component_type: ComponentType,
                            check_function: Callable, timeout_seconds: int = 30,
                            critical: bool = False):
        """Register a new health check"""
        self.health_checkers[name] = HealthChecker(
            name=name,
            component_type=component_type,
            check_function=check_function,
            timeout_seconds=timeout_seconds,
            critical=critical
        )
        
        logger.info(f"Registered health check: {name}", 
                   component_type=component_type.value, critical=critical)
    
    async def run_all_checks(self) -> SystemHealth:
        """Run all registered health checks"""
        start_time = time.time()
        results = []
        
        try:
            if self.parallel_checks:
                # Run checks in parallel
                tasks = [checker.execute() for checker in self.health_checkers.values()]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Handle exceptions
                valid_results = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        checker_name = list(self.health_checkers.keys())[i]
                        error_result = HealthCheckResult(
                            component=checker_name,
                            component_type=ComponentType.APPLICATION,
                            status=HealthStatus.CRITICAL,
                            message=f"Health check execution failed: {str(result)}",
                            details={"error": str(result)},
                            check_duration_ms=0.0,
                            timestamp=utc_now_iso()
                        )
                        valid_results.append(error_result)
                    else:
                        valid_results.append(result)
                
                results = valid_results
            else:
                # Run checks sequentially
                for checker in self.health_checkers.values():
                    result = await checker.execute()
                    results.append(result)
            
            # Calculate overall health
            system_health = self._calculate_system_health(results, start_time)
            
            # Update metrics
            self._update_health_metrics(system_health)
            
            # PHASE 3: Publish health status change events
            await self._publish_health_change_events(system_health)
            
            # Log system health summary
            logger.info(
                "PHASE 3: System health check completed",
                overall_status=system_health.overall_status.value,
                healthy_components=system_health.healthy_components,
                degraded_components=system_health.degraded_components,
                unhealthy_components=system_health.unhealthy_components,
                critical_components=system_health.critical_components,
                duration_ms=system_health.check_duration_ms,
                event_type="system_health_check",
                phase="3_event_driven"
            )
            
            return system_health
            
        except Exception as e:
            check_duration = (time.time() - start_time) * 1000
            
            # Create error system health
            error_health = SystemHealth(
                overall_status=HealthStatus.CRITICAL,
                healthy_components=0,
                degraded_components=0,
                unhealthy_components=0,
                critical_components=1,
                total_components=len(self.health_checkers),
                check_duration_ms=check_duration,
                timestamp=utc_now_iso(),
                components=results,
                sla_compliance={},
                recommendations=["Investigate health check system failure"]
            )
            
            logger.error(
                "System health check failed",
                error=str(e),
                error_type=type(e).__name__,
                event_type="system_health_check_error"
            )
            
            return error_health
    
    def _calculate_system_health(self, results: List[HealthCheckResult], 
                               start_time: float) -> SystemHealth:
        """Calculate overall system health from component results"""
        
        check_duration = (time.time() - start_time) * 1000
        
        # Count component statuses
        status_counts = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.DEGRADED: 0,
            HealthStatus.UNHEALTHY: 0,
            HealthStatus.CRITICAL: 0
        }
        
        critical_components = []
        
        for result in results:
            status_counts[result.status] += 1
            
            # Track critical component failures
            checker = self.health_checkers.get(result.component)
            if checker and checker.critical and result.status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]:
                critical_components.append(result.component)
        
        # Determine overall status
        overall_status = self._determine_overall_status(status_counts, critical_components)
        
        # Calculate SLA compliance
        sla_compliance = self._calculate_sla_compliance(results)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(results, status_counts)
        
        return SystemHealth(
            overall_status=overall_status,
            healthy_components=status_counts[HealthStatus.HEALTHY],
            degraded_components=status_counts[HealthStatus.DEGRADED],
            unhealthy_components=status_counts[HealthStatus.UNHEALTHY],
            critical_components=status_counts[HealthStatus.CRITICAL],
            total_components=len(results),
            check_duration_ms=check_duration,
            timestamp=utc_now_iso(),
            components=results,
            sla_compliance=sla_compliance,
            recommendations=recommendations
        )
    
    def _determine_overall_status(self, status_counts: Dict[HealthStatus, int], 
                                critical_components: List[str]) -> HealthStatus:
        """Determine overall system health status"""
        
        # Critical components failing = system critical
        if critical_components:
            return HealthStatus.CRITICAL
        
        # Any critical status = system critical
        if status_counts[HealthStatus.CRITICAL] > 0:
            return HealthStatus.CRITICAL
        
        # Multiple unhealthy components = system unhealthy
        if status_counts[HealthStatus.UNHEALTHY] >= 2:
            return HealthStatus.UNHEALTHY
        
        # Single unhealthy component = system degraded
        if status_counts[HealthStatus.UNHEALTHY] == 1:
            return HealthStatus.DEGRADED
        
        # Any degraded components = system degraded
        if status_counts[HealthStatus.DEGRADED] > 0:
            return HealthStatus.DEGRADED
        
        # All healthy = system healthy
        return HealthStatus.HEALTHY
    
    def _calculate_sla_compliance(self, results: List[HealthCheckResult]) -> Dict[str, float]:
        """Calculate SLA compliance metrics"""
        
        sla_compliance = {}
        
        # Availability SLA (percentage of healthy components)
        total_components = len(results)
        if total_components > 0:
            healthy_count = sum(1 for r in results if r.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED])
            availability = (healthy_count / total_components) * 100
            sla_compliance['availability'] = availability
        
        # Response time SLA (average check duration)
        if results:
            avg_response_time = sum(r.check_duration_ms for r in results) / len(results)
            response_time_compliance = max(0, 100 - (avg_response_time / self.sla_targets['response_time'] * 100))
            sla_compliance['response_time'] = response_time_compliance
        
        # Error rate SLA
        if total_components > 0:
            error_count = sum(1 for r in results if r.status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL])
            error_rate = (error_count / total_components) * 100
            error_rate_compliance = max(0, 100 - (error_rate / self.sla_targets['error_rate']))
            sla_compliance['error_rate'] = error_rate_compliance
        
        return sla_compliance
    
    def _generate_recommendations(self, results: List[HealthCheckResult], 
                                status_counts: Dict[HealthStatus, int]) -> List[str]:
        """Generate system recommendations based on health results"""
        
        recommendations = []
        
        # Critical component recommendations
        critical_results = [r for r in results if r.status == HealthStatus.CRITICAL]
        for result in critical_results:
            recommendations.append(f"URGENT: Fix critical component '{result.component}' - {result.message}")
        
        # Unhealthy component recommendations
        unhealthy_results = [r for r in results if r.status == HealthStatus.UNHEALTHY]
        for result in unhealthy_results:
            recommendations.append(f"Fix unhealthy component '{result.component}' - {result.message}")
        
        # Performance recommendations
        slow_results = [r for r in results if r.check_duration_ms > 5000]  # 5 second threshold
        if slow_results:
            recommendations.append(f"Investigate performance issues in {len(slow_results)} components")
        
        # High error rate recommendation
        if status_counts[HealthStatus.UNHEALTHY] + status_counts[HealthStatus.CRITICAL] > 2:
            recommendations.append("System experiencing high error rate - investigate common causes")
        
        # Add component-specific recommendations
        for result in results:
            if result.recommendations:
                recommendations.extend(result.recommendations)
        
        return recommendations[:10]  # Limit to top 10 recommendations
    
    async def _publish_health_change_events(self, system_health: SystemHealth):
        """PHASE 3: Publish health status change events"""
        if not self.event_monitoring:
            return
        
        try:
            # Check for overall health status changes
            current_status = system_health.overall_status.value
            if self.last_overall_health != current_status:
                from monitoring.event_driven_monitoring import MonitoringEvent, MonitoringEventType, Severity
                from datetime import timezone
                
                severity = Severity.CRITICAL if current_status in ["critical", "unhealthy"] else \
                          Severity.WARNING if current_status in ["degraded", "fair"] else Severity.INFO
                
                await self.event_monitoring.publish_event(MonitoringEvent(
                    event_type=MonitoringEventType.SYSTEM_HEALTH_STATUS_CHANGE,
                    component="system",
                    severity=severity,
                    message=f"System health changed from {self.last_overall_health or 'unknown'} to {current_status}",
                    details={
                        "previous_status": self.last_overall_health,
                        "current_status": current_status,
                        "healthy_components": system_health.healthy_components,
                        "degraded_components": system_health.degraded_components,
                        "unhealthy_components": system_health.unhealthy_components,
                        "critical_components": system_health.critical_components,
                        "total_components": system_health.total_components,
                        "check_duration_ms": system_health.check_duration_ms,
                        "recommendations": system_health.recommendations[:5]  # Top 5 recommendations
                    },
                    timestamp=system_health.timestamp,
                    source="comprehensive_health_system",
                    requires_action=severity in [Severity.CRITICAL, Severity.WARNING]
                ))
                
                self.last_overall_health = current_status
            
            # Publish events for critical component failures
            for component in system_health.components:
                if component.status in [HealthStatus.CRITICAL, HealthStatus.UNHEALTHY]:
                    # Check if this is a critical component
                    checker = self.health_checkers.get(component.component)
                    if checker and checker.critical:
                        await self.event_monitoring.publish_event(MonitoringEvent(
                            event_type=MonitoringEventType.APPLICATION_STATUS_CHANGE,
                            component=component.component,
                            severity=Severity.CRITICAL,
                            message=f"Critical component '{component.component}' is {component.status.value}: {component.message}",
                            details={
                                "component_type": component.component_type.value,
                                "status": component.status.value,
                                "message": component.message,
                                "check_duration_ms": component.check_duration_ms,
                                "details": component.details,
                                "recommendations": component.recommendations
                            },
                            timestamp=component.timestamp,
                            source="health_component_monitor",
                            requires_action=True
                        ))
        
        except Exception as e:
            logger.error(f"Failed to publish health change events: {e}")
    
    def _update_health_metrics(self, system_health: SystemHealth):
        """Update Prometheus metrics with health check results"""
        
        try:
            metrics = get_metrics()
            
            # System health score (0-100)
            health_score = self._calculate_health_score(system_health)
            metrics.record_system_health_score(health_score)
            
            # Component health metrics
            for result in system_health.components:
                is_healthy = result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]
                metrics.record_component_health(result.component, is_healthy)
            
            # SLA compliance metrics
            for sla_type, compliance in system_health.sla_compliance.items():
                metrics.record_sla_compliance("system", sla_type, compliance)
                
                # Record SLA violations if below target
                if compliance < self.sla_targets.get(sla_type, 100):
                    severity = "critical" if compliance < 90 else "warning"
                    metrics.record_sla_violation("system", sla_type, severity)
            
        except Exception as e:
            logger.error(f"Failed to update health metrics: {e}", exc_info=True)
    
    def _calculate_health_score(self, system_health: SystemHealth) -> float:
        """Calculate overall system health score (0-100)"""
        
        if system_health.total_components == 0:
            return 0.0
        
        # Weight different statuses
        weights = {
            HealthStatus.HEALTHY: 1.0,
            HealthStatus.DEGRADED: 0.7,
            HealthStatus.UNHEALTHY: 0.3,
            HealthStatus.CRITICAL: 0.0
        }
        
        total_score = 0.0
        for result in system_health.components:
            # Apply critical component penalty
            checker = self.health_checkers.get(result.component)
            weight = weights[result.status]
            
            if checker and checker.critical and result.status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]:
                weight *= 0.5  # Heavy penalty for critical component failures
            
            total_score += weight
        
        return (total_score / system_health.total_components) * 100
    
    # ===========================================
    # BUILT-IN HEALTH CHECKS
    # ===========================================
    
    async def _check_database_health(self) -> Dict[str, Any]:
        """Check database health"""
        
        try:
            # Get database health from existing system
            health_data = await get_connection_health()
            
            # Determine status based on connection test
            if health_data.get("connection_test", {}).get("status") == "healthy":
                status = HealthStatus.HEALTHY
                message = "Database is healthy"
            else:
                status = HealthStatus.UNHEALTHY
                message = "Database connection issues detected"
            
            # Check performance metrics
            pool_status = await get_pool_status()
            if pool_status.get('pool_usage_percentage', 0) > 90:
                status = HealthStatus.DEGRADED
                message = "Database pool utilization high"
            
            return {
                'status': status,
                'message': message,
                'details': health_data,
                'metrics': {
                    'pool_status': pool_status,
                    'connection_count': health_data.get('pool_info', {}).get('pool_size', 0)
                },
                'recommendations': self._get_database_recommendations(health_data, pool_status)
            }
            
        except Exception as e:
            return {
                'status': HealthStatus.CRITICAL,
                'message': f"Database health check failed: {str(e)}",
                'details': {'error': str(e)},
                'recommendations': ['Check database connectivity', 'Verify database configuration']
            }
    
    async def _check_redis_health(self) -> Dict[str, Any]:
        """Check Redis health"""
        
        try:
            # Get Redis health from existing system
            redis_health = await cache_health_check()
            
            if redis_health.get('redis_available', False):
                status = HealthStatus.HEALTHY
                message = "Redis is healthy"
                
                # Check performance metrics
                if redis_health.get('redis_optimizer_enabled', False):
                    optimizer_stats = redis_health.get('redis_optimizer_stats', {})
                    if optimizer_stats.get('cache_hit_rate', 0) < 80:
                        status = HealthStatus.DEGRADED
                        message = "Redis cache hit rate is low"
                
            else:
                status = HealthStatus.UNHEALTHY
                message = "Redis is not available"
            
            return {
                'status': status,
                'message': message,
                'details': redis_health,
                'metrics': {
                    'cache_hit_rate': redis_health.get('redis_optimizer_stats', {}).get('cache_hit_rate', 0),
                    'connection_count': redis_health.get('connection_pool_size', 0)
                },
                'recommendations': self._get_redis_recommendations(redis_health)
            }
            
        except Exception as e:
            return {
                'status': HealthStatus.CRITICAL,
                'message': f"Redis health check failed: {str(e)}",
                'details': {'error': str(e)},
                'recommendations': ['Check Redis connectivity', 'Verify Redis configuration']
            }
    
    async def _check_application_health(self) -> Dict[str, Any]:
        """Check application health"""
        
        try:
            # Basic application health indicators
            import os
            uptime = time.time() - psutil.boot_time()
            
            status = HealthStatus.HEALTHY
            message = "Application is healthy"
            
            details = {
                'uptime_seconds': uptime,
                'pid': os.getpid(),
                'python_version': sys.version,
                'environment': os.getenv('APP_ENV', 'unknown')
            }
            
            return {
                'status': status,
                'message': message,
                'details': details,
                'metrics': {
                    'uptime_hours': uptime / 3600
                }
            }
            
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"Application health check failed: {str(e)}",
                'details': {'error': str(e)}
            }
    
    async def _check_system_resources(self) -> Dict[str, Any]:
        """Check system resource utilization"""
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Determine status based on resource usage
            status = HealthStatus.HEALTHY
            message = "System resources are healthy"
            recommendations = []
            
            if cpu_percent > 90:
                status = HealthStatus.CRITICAL
                message = "Critical CPU usage"
                recommendations.append("Investigate high CPU processes")
            elif cpu_percent > 80:
                status = HealthStatus.DEGRADED
                message = "High CPU usage"
                recommendations.append("Monitor CPU usage trends")
            
            if memory_percent > 95:
                status = HealthStatus.CRITICAL
                message = "Critical memory usage"
                recommendations.append("Free memory or add more RAM")
            elif memory_percent > 85:
                status = HealthStatus.DEGRADED
                message = "High memory usage"
                recommendations.append("Monitor memory usage")
            
            if disk_percent > 90:
                status = HealthStatus.CRITICAL
                message = "Critical disk space"
                recommendations.append("Free disk space immediately")
            elif disk_percent > 80:
                status = HealthStatus.DEGRADED
                message = "Low disk space"
                recommendations.append("Monitor disk usage")
            
            details = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'memory_available_gb': memory.available / (1024**3),
                'disk_percent': disk_percent,
                'disk_free_gb': disk.free / (1024**3)
            }
            
            return {
                'status': status,
                'message': message,
                'details': details,
                'metrics': details,
                'recommendations': recommendations
            }
            
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"System resources check failed: {str(e)}",
                'details': {'error': str(e)}
            }
    
    async def _check_task_system_health(self) -> Dict[str, Any]:
        """Check task system health"""
        
        try:
            # Try to import and check task system
            from core.task_system.integration_layer import get_task_system
            
            task_system = get_task_system()
            if not task_system:
                return {
                    'status': HealthStatus.DEGRADED,
                    'message': "Task system not initialized",
                    'details': {'initialized': False}
                }
            
            # Get task system health
            health_info = await task_system.get_system_health()
            
            if health_info.get('task_system_running', False):
                active_alerts = health_info.get('active_alerts', 0)
                
                if active_alerts == 0:
                    status = HealthStatus.HEALTHY
                    message = "Task system is healthy"
                elif active_alerts < 3:
                    status = HealthStatus.DEGRADED
                    message = f"Task system has {active_alerts} active alerts"
                else:
                    status = HealthStatus.UNHEALTHY
                    message = f"Task system has {active_alerts} active alerts"
            else:
                status = HealthStatus.UNHEALTHY
                message = "Task system is not running"
            
            return {
                'status': status,
                'message': message,
                'details': health_info,
                'metrics': {
                    'active_alerts': health_info.get('active_alerts', 0),
                    'running': health_info.get('task_system_running', False)
                }
            }
            
        except ImportError:
            return {
                'status': HealthStatus.DEGRADED,
                'message': "Task system not available",
                'details': {'available': False}
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"Task system health check failed: {str(e)}",
                'details': {'error': str(e)}
            }
    
    def _get_database_recommendations(self, health_data: Dict[str, Any], 
                                    pool_status: Dict[str, Any]) -> List[str]:
        """Get database-specific recommendations"""
        recommendations = []
        
        pool_usage = pool_status.get('pool_usage_percentage', 0)
        if pool_usage > 90:
            recommendations.append("Consider increasing database connection pool size")
        
        slow_queries = health_data.get('performance_metrics', {}).get('slow_queries', 0)
        if slow_queries > 0:
            recommendations.append("Investigate slow query performance")
        
        return recommendations
    
    def _get_redis_recommendations(self, redis_health: Dict[str, Any]) -> List[str]:
        """Get Redis-specific recommendations"""
        recommendations = []
        
        if not redis_health.get('redis_available', False):
            recommendations.append("Check Redis server status and connectivity")
        
        optimizer_stats = redis_health.get('redis_optimizer_stats', {})
        hit_rate = optimizer_stats.get('cache_hit_rate', 0)
        if hit_rate < 80:
            recommendations.append("Improve cache hit rate through better cache strategies")
        
        return recommendations
    
    # ===========================================
    # PUBLIC API
    # ===========================================
    
    async def get_quick_health(self) -> Dict[str, Any]:
        """Get quick system health summary"""
        
        try:
            # Run only critical checks quickly
            critical_checkers = {
                name: checker for name, checker in self.health_checkers.items() 
                if checker.critical
            }
            
            tasks = [checker.execute() for checker in critical_checkers.values()]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            healthy_count = 0
            total_count = len(results)
            
            for result in results:
                if not isinstance(result, Exception) and result.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]:
                    healthy_count += 1
            
            overall_healthy = healthy_count == total_count and total_count > 0
            
            return {
                'healthy': overall_healthy,
                'checked_components': total_count,
                'healthy_components': healthy_count,
                'timestamp': utc_now_iso()
            }
            
        except Exception as e:
            logger.error(f"Quick health check failed: {e}", exc_info=True)
            return {
                'healthy': False,
                'error': str(e),
                'timestamp': utc_now_iso()
            }
    
    def get_component_history(self, component_name: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get health history for a specific component"""
        
        checker = self.health_checkers.get(component_name)
        if not checker:
            return []
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        recent_checks = [
            asdict(check) for check in checker.check_history
            if datetime.fromisoformat(check.timestamp) > cutoff_time
        ]
        
        return recent_checks
    
    def get_system_summary(self) -> Dict[str, Any]:
        """Get system health summary with statistics"""
        
        summary = {
            'total_components': len(self.health_checkers),
            'critical_components': sum(1 for c in self.health_checkers.values() if c.critical),
            'last_check_times': {},
            'success_rates': {},
            'component_types': {}
        }
        
        for name, checker in self.health_checkers.items():
            summary['last_check_times'][name] = checker.last_check_time.isoformat() if checker.last_check_time else None
            summary['success_rates'][name] = checker.get_success_rate()
            summary['component_types'][name] = checker.component_type.value
        
        return summary

# Global health system instance
_health_system: Optional[ComprehensiveHealthSystem] = None

def get_health_system() -> ComprehensiveHealthSystem:
    """Get the global health system instance"""
    global _health_system
    
    if _health_system is None:
        _health_system = ComprehensiveHealthSystem()
    
    return _health_system

def init_health_system() -> ComprehensiveHealthSystem:
    """Initialize the global health system"""
    global _health_system
    
    if _health_system is None:
        _health_system = ComprehensiveHealthSystem()
        logger.info("Comprehensive health system initialized")
    
    return _health_system

# Initialize health system on module import
try:
    init_health_system()
except Exception as e:
    print(f"Failed to initialize health system on import: {e}", file=sys.stderr)