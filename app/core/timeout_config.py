"""
Centralized Timeout Configuration for DevSecureX Backend
Manages all timeout settings across the application
"""

import os
import logging
from typing import Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)

class OperationType(str, Enum):
    """Types of operations with different timeout requirements"""
    SCAN_TRIGGER = "scan_trigger"           # Code scanning operations
    PR_SCANNING = "pr_scanning"             # Pull request analysis
    REPO_SCANNING = "repo_scanning"         # Repository scanning
    CLI_SCANNING = "cli_scanning"           # CLI scanning operations
    GITHUB_API = "github_api"               # GitHub API operations
    DATABASE_QUERY = "database_query"       # Database operations
    REDIS_OPERATION = "redis_operation"     # Redis cache operations
    HEALTH_CHECK = "health_check"           # Health check endpoints
    ANALYTICS = "analytics"                 # Analytics queries
    AI_ASSISTANT = "ai_assistant"           # AI/OpenAI operations
    DEFAULT = "default"                     # Default operations

class TimeoutConfig:
    """Centralized timeout configuration manager"""
    
    def __init__(self):
        # Base timeout configurations (in seconds)
        self._timeouts = {
            OperationType.SCAN_TRIGGER: int(os.getenv('TIMEOUT_SCAN_TRIGGER', '900')),      # 15 minutes
            OperationType.PR_SCANNING: int(os.getenv('TIMEOUT_PR_SCANNING', '600')),        # 10 minutes
            OperationType.REPO_SCANNING: int(os.getenv('TIMEOUT_REPO_SCANNING', '600')),    # 10 minutes
            OperationType.CLI_SCANNING: int(os.getenv('TIMEOUT_CLI_SCANNING', '480')),       # 8 minutes for CLI scans
            OperationType.GITHUB_API: int(os.getenv('TIMEOUT_GITHUB_API', '120')),          # 2 minutes
            OperationType.DATABASE_QUERY: int(os.getenv('TIMEOUT_DATABASE_QUERY', '300')),  # 5 minutes
            OperationType.REDIS_OPERATION: int(os.getenv('TIMEOUT_REDIS_OPERATION', '60')), # 1 minute
            OperationType.HEALTH_CHECK: int(os.getenv('TIMEOUT_HEALTH_CHECK', '30')),       # 30 seconds
            OperationType.ANALYTICS: int(os.getenv('TIMEOUT_ANALYTICS', '120')),            # 2 minutes
            OperationType.AI_ASSISTANT: int(os.getenv('TIMEOUT_AI_ASSISTANT', '180')),      # 3 minutes
            OperationType.DEFAULT: int(os.getenv('TIMEOUT_DEFAULT', '60')),                 # 1 minute
        }
        
        # Endpoint to operation type mapping
        self._endpoint_mappings = {
            "/scans/trigger": OperationType.SCAN_TRIGGER,
            "/scans/repos": OperationType.PR_SCANNING,
            "/repos/scan": OperationType.REPO_SCANNING,
            "/cli-scan/scan": OperationType.CLI_SCANNING,
            "/cli-scan": OperationType.CLI_SCANNING,
            "/repos/available": OperationType.GITHUB_API,
            "/analytics": OperationType.ANALYTICS,
            "/ai": OperationType.AI_ASSISTANT,
            "/health": OperationType.HEALTH_CHECK,
            "/health/detailed": OperationType.HEALTH_CHECK,
            "/ready": OperationType.HEALTH_CHECK,
            "/live": OperationType.HEALTH_CHECK,
        }
        
        logger.info(f"Timeout configuration loaded: {dict(self._timeouts)}")
    
    def get_timeout(self, operation_type: OperationType) -> int:
        """Get timeout for specific operation type"""
        return self._timeouts.get(operation_type, self._timeouts[OperationType.DEFAULT])
    
    def get_timeout_for_endpoint(self, endpoint_path: str) -> int:
        """Get timeout for specific endpoint path"""
        # Check for exact matches first
        if endpoint_path in self._endpoint_mappings:
            operation_type = self._endpoint_mappings[endpoint_path]
            return self.get_timeout(operation_type)
        
        # Check for partial matches
        for endpoint_pattern, operation_type in self._endpoint_mappings.items():
            if endpoint_pattern in endpoint_path:
                return self.get_timeout(operation_type)
        
        # Return default timeout
        return self.get_timeout(OperationType.DEFAULT)
    
    def get_all_timeouts(self) -> Dict[str, int]:
        """Get all configured timeouts"""
        return {op_type.value: timeout for op_type, timeout in self._timeouts.items()}
    
    def update_timeout(self, operation_type: OperationType, timeout_seconds: int) -> None:
        """Update timeout for specific operation type"""
        self._timeouts[operation_type] = timeout_seconds
        logger.info(f"Updated timeout for {operation_type.value}: {timeout_seconds}s")

class TimeoutManager:
    """Singleton timeout manager"""
    _instance: Optional[TimeoutConfig] = None
    
    @classmethod
    def get_config(cls) -> TimeoutConfig:
        """Get singleton timeout configuration instance"""
        if cls._instance is None:
            cls._instance = TimeoutConfig()
        return cls._instance

# Convenience functions for common usage
def get_timeout(operation_type: OperationType) -> int:
    """Get timeout for operation type"""
    return TimeoutManager.get_config().get_timeout(operation_type)

def get_endpoint_timeout(endpoint_path: str) -> int:
    """Get timeout for endpoint path"""
    return TimeoutManager.get_config().get_timeout_for_endpoint(endpoint_path)

def get_scan_timeout() -> int:
    """Get timeout for scan operations"""
    return get_timeout(OperationType.SCAN_TRIGGER)

def get_cli_scan_timeout() -> int:
    """Get timeout for CLI scan operations"""
    return get_timeout(OperationType.CLI_SCANNING)

def get_github_timeout() -> int:
    """Get timeout for GitHub API operations"""
    return get_timeout(OperationType.GITHUB_API)

def get_database_timeout() -> int:
    """Get timeout for database operations"""
    return get_timeout(OperationType.DATABASE_QUERY)

def get_redis_timeout() -> int:
    """Get timeout for Redis operations"""
    return get_timeout(OperationType.REDIS_OPERATION)

# Environment-specific timeout adjustments
def is_production() -> bool:
    """Check if running in production environment"""
    return os.getenv("APP_ENV", "development").lower() == "production"

def apply_environment_adjustments():
    """Apply environment-specific timeout adjustments"""
    config = TimeoutManager.get_config()
    
    if is_production():
        # In production, allow longer timeouts but with monitoring
        logger.info("Applying production timeout adjustments")
        config.update_timeout(OperationType.SCAN_TRIGGER, min(900, config.get_timeout(OperationType.SCAN_TRIGGER)))
        config.update_timeout(OperationType.PR_SCANNING, min(600, config.get_timeout(OperationType.PR_SCANNING)))
    else:
        # In development, use shorter timeouts for faster feedback
        logger.info("Applying development timeout adjustments")
        config.update_timeout(OperationType.DEFAULT, min(60, config.get_timeout(OperationType.DEFAULT)))

# Initialize on module import
apply_environment_adjustments()