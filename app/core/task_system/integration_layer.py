"""
Integration Layer for DevSecureX Task System

This module provides seamless integration between the new auto-scaling task system
and existing DevSecureX components (scan workers, autofix workers, etc.)
"""

import asyncio
import logging
import os
from typing import Dict, Any, Optional, List
from datetime import datetime

from core.utils import utc_now_iso
from .auto_scaling_manager import AutoScalingTaskManager, ScalingPolicy
from .priority_queue import TaskPriority, TaskType
from .retry_handler import RetryPolicy
from .task_monitor import TaskMonitor

logger = logging.getLogger(__name__)

class DevSecureXTaskSystem:
    """Main integration class for DevSecureX task system"""
    
    def __init__(self):
        # Configuration from environment
        self.min_workers = int(os.getenv("TASK_SYSTEM_MIN_WORKERS", "2"))
        self.max_workers = int(os.getenv("TASK_SYSTEM_MAX_WORKERS", "15"))
        self.scaling_policy = ScalingPolicy(os.getenv("TASK_SYSTEM_SCALING_POLICY", "reactive"))
        self.enabled = os.getenv("ENABLE_TASK_SYSTEM", "true").lower() == "true"
        
        # Core components
        self.auto_scaling_manager = None
        self.task_monitor = None
        self.running = False
        
        # Legacy integration
        self.legacy_scan_manager = None
        self.legacy_autofix_manager = None
    
    async def initialize(self):
        """Initialize the task system"""
        
        if not self.enabled:
            logger.info("Task system disabled by configuration")
            return
        
        try:
            logger.info(f"Initializing DevSecureX Task System (workers: {self.min_workers}-{self.max_workers}, policy: {self.scaling_policy.value})")
            
            # Initialize auto-scaling manager
            self.auto_scaling_manager = AutoScalingTaskManager(
                min_workers=self.min_workers,
                max_workers=self.max_workers,
                scaling_policy=self.scaling_policy,
                redis_key_prefix="devsecurex_tasks"
            )
            
            # Initialize task monitor
            self.task_monitor = TaskMonitor(
                redis_key_prefix="devsecurex_monitor"
            )
            
            # Import and set up legacy integrations
            await self._setup_legacy_integration()
            
            logger.info("DevSecureX Task System initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize task system: {e}", exc_info=True)
            raise
    
    async def start(self):
        """Start the task system"""
        
        if not self.enabled:
            logger.info("Task system startup skipped (disabled)")
            return
        
        if self.running:
            logger.warning("Task system already running")
            return
        
        try:
            logger.info("Starting DevSecureX Task System...")
            
            # Start core components
            if self.auto_scaling_manager:
                await self.auto_scaling_manager.start()
            
            if self.task_monitor:
                await self.task_monitor.start()
            
            # Start legacy integration if enabled
            await self._start_legacy_integration()
            
            self.running = True
            logger.info("DevSecureX Task System started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start task system: {e}", exc_info=True)
            raise
    
    async def stop(self):
        """Stop the task system"""
        
        if not self.running:
            return
        
        logger.info("Stopping DevSecureX Task System...")
        
        try:
            # Stop core components
            if self.auto_scaling_manager:
                await self.auto_scaling_manager.stop()
            
            if self.task_monitor:
                await self.task_monitor.stop()
            
            # Stop legacy integration
            await self._stop_legacy_integration()
            
            self.running = False
            logger.info("DevSecureX Task System stopped")
            
        except Exception as e:
            logger.error(f"Error stopping task system: {e}", exc_info=True)
    
    async def _setup_legacy_integration(self):
        """Set up integration with existing DevSecureX workers"""
        
        try:
            # Check if legacy workers are enabled
            enable_legacy_workers = os.getenv("ENABLE_BACKGROUND_WORKERS", "false").lower() == "true"
            
            if enable_legacy_workers and not self.enabled:
                # Legacy mode - run existing workers
                logger.info("Running in legacy worker mode")
                
                from scans.workers.manager import WorkerManager
                # Basic autofix worker manager removed - using enterprise system
                
                self.legacy_scan_manager = WorkerManager()
                # Legacy autofix manager removed - enterprise system handles this
                
            elif self.enabled:
                # New system mode - integrate existing workers with new system
                logger.info("Integrating legacy workers with new task system")
                
                # This will be handled by the auto-scaling manager's worker creation
                pass
            
        except Exception as e:
            logger.error(f"Error setting up legacy integration: {e}", exc_info=True)
    
    async def _start_legacy_integration(self):
        """Start legacy worker integration if needed"""
        
        try:
            if self.legacy_scan_manager:
                await self.legacy_scan_manager.start()
                logger.info("Started legacy scan workers")
            
            if self.legacy_autofix_manager:
                await self.legacy_autofix_manager.start()
                logger.info("Started legacy autofix workers")
                
        except Exception as e:
            logger.error(f"Error starting legacy integration: {e}", exc_info=True)
    
    async def _stop_legacy_integration(self):
        """Stop legacy worker integration"""
        
        try:
            if self.legacy_scan_manager:
                await self.legacy_scan_manager.stop()
                logger.info("Stopped legacy scan workers")
            
            if self.legacy_autofix_manager:
                await self.legacy_autofix_manager.stop()
                logger.info("Stopped legacy autofix workers")
                
        except Exception as e:
            logger.error(f"Error stopping legacy integration: {e}", exc_info=True)
    
    # Public API Methods
    
    async def enqueue_security_scan(
        self,
        repo_full_name: str,
        scan_data: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        user_id: Optional[int] = None
    ) -> str:
        """Enqueue a security scan task"""
        
        if not self.enabled or not self.auto_scaling_manager:
            # Fall back to legacy system
            return await self._enqueue_legacy_scan(repo_full_name, scan_data)
        
        try:
            # Enhance scan data with user context
            enhanced_scan_data = {
                **scan_data,
                'user_id': user_id,
                'repo_full_name': repo_full_name,
                'enqueued_at': utc_now_iso()
            }
            
            # Determine priority based on scan type
            if scan_data.get('scan_type') == 'pr_scan':
                priority = TaskPriority.HIGH
            elif scan_data.get('scan_type') == 'push_scan':
                priority = TaskPriority.NORMAL
            elif scan_data.get('severity') == 'critical':
                priority = TaskPriority.CRITICAL
            
            # Enqueue with new system
            task_id = await self.auto_scaling_manager.enqueue_task(
                task_type=TaskType.SECURITY_SCAN,
                payload=enhanced_scan_data,
                priority=priority,
                expires_in_seconds=3600,  # 1 hour
                max_retries=3,
                timeout_seconds=1800,     # 30 minutes
                preferred_worker_tags=['security', 'scan'],
                resource_requirements={'cpu': 2.0, 'memory': 1024},
                estimated_duration_seconds=300
            )
            
            logger.info(f"Enqueued security scan {task_id} for {repo_full_name} with priority {priority.name}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error enqueuing security scan: {e}", exc_info=True)
            # Fall back to legacy system
            return await self._enqueue_legacy_scan(repo_full_name, scan_data)
    
    async def enqueue_autofix_task(
        self,
        scan_id: str,
        user_id: int,
        repo_full_name: str,
        autofix_data: Dict[str, Any],
        priority: TaskPriority = TaskPriority.HIGH
    ) -> str:
        """Enqueue an autofix task"""
        
        if not self.enabled or not self.auto_scaling_manager:
            # Fall back to legacy system
            return await self._enqueue_legacy_autofix(scan_id, user_id, repo_full_name, autofix_data)
        
        try:
            # Enhance autofix data
            enhanced_autofix_data = {
                **autofix_data,
                'scan_id': scan_id,
                'user_id': user_id,
                'repo_full_name': repo_full_name,
                'enqueued_at': utc_now_iso()
            }
            
            # Enqueue with new system
            task_id = await self.auto_scaling_manager.enqueue_task(
                task_type=TaskType.AUTOFIX,
                payload=enhanced_autofix_data,
                priority=priority,
                expires_in_seconds=7200,  # 2 hours
                max_retries=2,            # Fewer retries for autofix
                timeout_seconds=1800,     # 30 minutes
                preferred_worker_tags=['autofix', 'git', 'ai'],
                resource_requirements={'cpu': 1.5, 'memory': 768},
                estimated_duration_seconds=600
            )
            
            logger.info(f"Enqueued autofix task {task_id} for scan {scan_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error enqueuing autofix task: {e}", exc_info=True)
            # Fall back to legacy system
            return await self._enqueue_legacy_autofix(scan_id, user_id, repo_full_name, autofix_data)
    
    async def enqueue_report_generation(
        self,
        report_type: str,
        report_data: Dict[str, Any],
        priority: TaskPriority = TaskPriority.LOW
    ) -> str:
        """Enqueue a report generation task"""
        
        if not self.enabled or not self.auto_scaling_manager:
            logger.warning("Report generation task system not available")
            return None
        
        try:
            task_id = await self.auto_scaling_manager.enqueue_task(
                task_type=TaskType.REPORT_GENERATION,
                payload={
                    'report_type': report_type,
                    'report_data': report_data,
                    'enqueued_at': utc_now_iso()
                },
                priority=priority,
                expires_in_seconds=3600,
                max_retries=2,
                timeout_seconds=600,
                preferred_worker_tags=['report', 'io-intensive'],
                resource_requirements={'cpu': 0.5, 'memory': 256},
                estimated_duration_seconds=120
            )
            
            logger.info(f"Enqueued report generation task {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error enqueuing report generation: {e}", exc_info=True)
            return None
    
    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a task"""
        
        if not self.enabled or not self.auto_scaling_manager:
            return None
        
        return await self.auto_scaling_manager.get_task_status(task_id)
    
    async def get_system_health(self) -> Dict[str, Any]:
        """Get comprehensive system health information"""
        
        try:
            health_info = {
                'timestamp': utc_now_iso(),
                'task_system_enabled': self.enabled,
                'task_system_running': self.running,
                'components': {}
            }
            
            if self.enabled and self.running:
                # Get auto-scaling manager stats
                if self.auto_scaling_manager:
                    scaling_stats = await self.auto_scaling_manager.get_system_stats()
                    health_info['components']['auto_scaling_manager'] = {
                        'status': 'healthy',
                        'stats': scaling_stats
                    }
                
                # Get task monitor stats
                if self.task_monitor:
                    monitor_report = await self.task_monitor.get_performance_report()
                    health_info['components']['task_monitor'] = {
                        'status': 'healthy',
                        'performance_report': monitor_report
                    }
                    
                    # Get active alerts
                    active_alerts = await self.task_monitor.get_active_alerts()
                    health_info['active_alerts'] = len(active_alerts)
                    health_info['alerts'] = [
                        {
                            'level': alert.level.value,
                            'title': alert.title,
                            'message': alert.message,
                            'created_at': alert.created_at
                        }
                        for alert in active_alerts
                    ]
            
            # Legacy system health
            if self.legacy_scan_manager or self.legacy_autofix_manager:
                health_info['legacy_workers'] = {
                    'scan_workers': 'active' if self.legacy_scan_manager else 'inactive',
                    'autofix_workers': 'active' if self.legacy_autofix_manager else 'inactive'
                }
            
            return health_info
            
        except Exception as e:
            logger.error(f"Error getting system health: {e}", exc_info=True)
            return {
                'timestamp': utc_now_iso(),
                'task_system_enabled': self.enabled,
                'task_system_running': False,
                'error': str(e)
            }
    
    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        
        if not self.enabled or not self.task_monitor:
            return {'error': 'Task monitoring not available'}
        
        return await self.task_monitor.get_performance_report()
    
    async def get_scaling_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get scaling history"""
        
        if not self.enabled or not self.auto_scaling_manager:
            return []
        
        return await self.auto_scaling_manager.get_scaling_history(limit)
    
    async def update_scaling_config(self, config_updates: Dict[str, Any]) -> bool:
        """Update scaling configuration"""
        
        if not self.enabled or not self.auto_scaling_manager:
            return False
        
        return await self.auto_scaling_manager.update_scaling_config(config_updates)
    
    # Legacy integration methods
    
    async def _enqueue_legacy_scan(self, repo_full_name: str, scan_data: Dict[str, Any]) -> str:
        """Enqueue scan using fortress queue system (unified queue)"""
        
        try:
            # Use fortress queue (unified queue system) for all scans
            from scans.unified_queue import get_unified_queue_manager, UnifiedJobPriority
            
            queue_manager = await get_unified_queue_manager()
            
            # Map task priorities to unified queue priorities
            priority_map = {
                TaskPriority.CRITICAL: UnifiedJobPriority.URGENT,
                TaskPriority.HIGH: UnifiedJobPriority.HIGH,
                TaskPriority.NORMAL: UnifiedJobPriority.NORMAL,
                TaskPriority.LOW: UnifiedJobPriority.LOW
            }
            
            # Determine priority from scan data or default to NORMAL
            task_priority = TaskPriority.NORMAL
            if scan_data.get('severity') == 'critical':
                task_priority = TaskPriority.CRITICAL
            elif scan_data.get('scan_type') == 'pr_scan':
                task_priority = TaskPriority.HIGH
                
            unified_priority = priority_map.get(task_priority, UnifiedJobPriority.NORMAL)
            
            # Enqueue using fortress queue system
            job_id = await queue_manager.enqueue_scan(
                repo_full_name=repo_full_name,
                user_id=scan_data.get('user_id'),
                scan_type=scan_data.get('scan_type', 'manual'),
                scan_config=scan_data,
                priority=unified_priority
            )
            
            logger.info(f"🏰 FORTRESS: Enqueued scan {job_id} for {repo_full_name} via legacy fallback")
            return job_id
            
        except Exception as e:
            logger.error(f"Error enqueuing scan via fortress queue: {e}", exc_info=True)
            raise
    
    async def _enqueue_legacy_autofix(
        self,
        scan_id: str,
        user_id: int,
        repo_full_name: str,
        autofix_data: Dict[str, Any]
    ) -> str:
        """Enqueue autofix using legacy system"""
        
        try:
            from scans.autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager, AutofixPriority
            
            legacy_queue = await get_enterprise_autofix_queue_manager()
            
            job_id = await legacy_queue.enqueue_autofix_job(
                scan_id=scan_id,
                user_id=user_id,
                repo_full_name=repo_full_name,
                autofix_data=autofix_data,
                priority=AutofixPriority.HIGH
            )
            
            logger.info(f"Enqueued legacy autofix {job_id} for scan {scan_id}")
            return job_id
            
        except Exception as e:
            logger.error(f"Error enqueuing legacy autofix: {e}", exc_info=True)
            raise


# Global instance
task_system: Optional[DevSecureXTaskSystem] = None

async def initialize_task_system():
    """Initialize the global task system"""
    global task_system
    
    if task_system is None:
        task_system = DevSecureXTaskSystem()
        await task_system.initialize()
    
    return task_system

async def start_task_system():
    """Start the global task system"""
    global task_system
    
    if task_system:
        await task_system.start()
    else:
        logger.warning("Task system not initialized")

async def stop_task_system():
    """Stop the global task system"""
    global task_system
    
    if task_system:
        await task_system.stop()

def get_task_system() -> Optional[DevSecureXTaskSystem]:
    """Get the global task system instance"""
    return task_system

# Convenience functions for backward compatibility

async def enqueue_security_scan(
    repo_full_name: str,
    scan_data: Dict[str, Any],
    priority: str = "normal",
    user_id: Optional[int] = None
) -> str:
    """Convenience function to enqueue security scan"""
    
    priority_map = {
        'critical': TaskPriority.CRITICAL,
        'high': TaskPriority.HIGH,
        'normal': TaskPriority.NORMAL,
        'low': TaskPriority.LOW
    }
    
    task_priority = priority_map.get(priority.lower(), TaskPriority.NORMAL)
    
    if task_system:
        return await task_system.enqueue_security_scan(
            repo_full_name, scan_data, task_priority, user_id
        )
    else:
        # Use fortress queue system (unified queue) as fallback
        from scans.unified_queue import get_unified_queue_manager, UnifiedJobPriority
        
        try:
            queue_manager = await get_unified_queue_manager()
            job_id = await queue_manager.enqueue_scan(
                repo_full_name=repo_full_name,
                user_id=user_id,
                scan_type='manual',
                scan_config=scan_data,
                priority=UnifiedJobPriority.NORMAL
            )
            logger.info(f"🏰 FORTRESS: Fallback scan queued {job_id} for {repo_full_name}")
            return job_id
        except Exception as e:
            logger.error(f"Fortress queue fallback failed: {e}")
            raise

async def enqueue_autofix_task(
    scan_id: str,
    user_id: int,
    repo_full_name: str,
    autofix_data: Dict[str, Any]
) -> str:
    """Convenience function to enqueue autofix task"""
    
    if task_system:
        return await task_system.enqueue_autofix_task(
            scan_id, user_id, repo_full_name, autofix_data
        )
    else:
        # Direct legacy fallback - using enterprise autofix system
        from scans.autofix_queue.enterprise_autofix_queue import get_enterprise_autofix_queue_manager, AutofixPriority
        
        legacy_queue = await get_enterprise_autofix_queue_manager()
        return await legacy_queue.enqueue_autofix_job(
            scan_id=scan_id,
            user_id=user_id,
            repo_full_name=repo_full_name,
            autofix_data=autofix_data,
            priority=AutofixPriority.HIGH
        )