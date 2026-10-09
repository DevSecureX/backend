#!/usr/bin/env python3
"""
Environment Variable Validation Utility

Prevents integer parsing errors by ensuring all environment variables
are properly validated and converted to the correct types.

This utility is designed to catch and fix the root cause of startup
failures related to decimal environment variables being parsed as integers.
"""

import os
import logging
from typing import Union, Optional, Any, Dict, List
import warnings

logger = logging.getLogger(__name__)

class EnvironmentVariableError(Exception):
    """Raised when environment variable parsing fails"""
    pass

class EnvValidator:
    """Environment variable validation and safe parsing"""

    # Known problematic variables that should be floats, not integers
    FLOAT_VARIABLES = {
        'HIGH_FAILURE_RATE_THRESHOLD': '0.5',
        'DB_RETRY_DELAY': '0.5',
        'UNIFIED_WORKER_POLL_INTERVAL': '1.5',
        'WORKER_HEARTBEAT_TIMEOUT': '300.0',
        'DEAD_WORKER_THRESHOLD': '600.0',
        'HIGH_MEMORY_THRESHOLD_MB': '1024.0',
        'HIGH_CPU_THRESHOLD': '90.0',
        'SLOW_REQUEST_THRESHOLD': '5.0',
        'MEMORY_CLEANUP_THRESHOLD_MB': '1536.0',
        'ALERT_TIMEOUT_RATE': '10.0',
        'ALERT_AVG_RESPONSE_TIME': '60.0',
        'ALERT_MAX_RESPONSE_TIME': '300.0',
        'DB_SLOW_QUERY_THRESHOLD': '1.0',
        'DB_DEADLOCK_RETRY_DELAY': '0.1',
        'VALIDATION_RETRY_DELAY': '5.0',
        'REDIS_ALERT_THRESHOLD': '0.8',
        'TRACE_SAMPLE_RATE': '1.0',
        'MEMORY_GB': '2.0'
    }

    # Variables that should definitely be integers
    INTEGER_VARIABLES = {
        'PORT': '8000',
        'DB_POOL_SIZE': '40',
        'DB_MAX_OVERFLOW': '60',
        'DB_POOL_TIMEOUT': '60',
        'DB_POOL_RECYCLE': '3600',
        'DB_HEALTH_CHECK_INTERVAL': '30',
        'DB_MAX_RETRIES': '3',
        'DB_QUERY_TIMEOUT': '30',
        'VALIDATION_TIMEOUT_SECONDS': '60',
        'VALIDATION_MAX_RETRIES': '3',
        'MAX_WORKER_RESTARTS': '3'
    }

    @classmethod
    def safe_int(cls, value: str, var_name: str, default: str) -> int:
        """Safely parse integer environment variable"""
        try:
            # Check if this variable is known to be a float
            if var_name in cls.FLOAT_VARIABLES:
                logger.warning(f"Variable {var_name} is being parsed as int() but is known to contain decimal values. Consider using float() instead.")
                # Convert to float first, then to int
                float_val = float(value)
                return int(float_val)

            return int(value)
        except ValueError as e:
            logger.error(f"Failed to parse {var_name}='{value}' as integer. Using default '{default}'")
            try:
                # Try to parse default as int
                return int(default)
            except ValueError:
                # If default is also problematic, use a safe fallback
                logger.error(f"Default value '{default}' for {var_name} is also invalid. Using 0.")
                return 0

    @classmethod
    def safe_float(cls, value: str, var_name: str, default: str) -> float:
        """Safely parse float environment variable"""
        try:
            return float(value)
        except ValueError as e:
            logger.error(f"Failed to parse {var_name}='{value}' as float. Using default '{default}'")
            try:
                return float(default)
            except ValueError:
                logger.error(f"Default value '{default}' for {var_name} is also invalid. Using 0.0.")
                return 0.0

    @classmethod
    def get_int(cls, var_name: str, default: str) -> int:
        """Get integer environment variable with validation"""
        value = os.getenv(var_name, default)
        return cls.safe_int(value, var_name, default)

    @classmethod
    def get_float(cls, var_name: str, default: str) -> float:
        """Get float environment variable with validation"""
        value = os.getenv(var_name, default)
        return cls.safe_float(value, var_name, default)

    @classmethod
    def validate_all_env_vars(cls) -> Dict[str, Any]:
        """Validate all known environment variables and return a report"""
        report = {
            'valid': [],
            'warnings': [],
            'errors': [],
            'fixes_applied': []
        }

        # Check float variables
        for var_name, default_val in cls.FLOAT_VARIABLES.items():
            env_value = os.getenv(var_name)
            if env_value is not None:
                try:
                    float(env_value)
                    report['valid'].append(f"{var_name}={env_value} (float)")
                except ValueError:
                    report['errors'].append(f"{var_name}={env_value} cannot be parsed as float")

        # Check integer variables
        for var_name, default_val in cls.INTEGER_VARIABLES.items():
            env_value = os.getenv(var_name)
            if env_value is not None:
                try:
                    # Check if it's accidentally a decimal
                    if '.' in env_value:
                        report['warnings'].append(f"{var_name}={env_value} contains decimal but should be integer")
                    else:
                        int(env_value)
                        report['valid'].append(f"{var_name}={env_value} (int)")
                except ValueError:
                    report['errors'].append(f"{var_name}={env_value} cannot be parsed as integer")

        return report

    @classmethod
    def fix_problematic_env_vars(cls) -> List[str]:
        """Fix any problematic environment variables by setting proper defaults"""
        fixes_applied = []

        # Fix variables that are decimals but might be parsed as integers
        for var_name, default_val in cls.FLOAT_VARIABLES.items():
            current_value = os.getenv(var_name)
            if current_value is None:
                # Set the default if not set
                os.environ[var_name] = default_val
                fixes_applied.append(f"Set {var_name}={default_val} (was unset)")
            else:
                try:
                    # Validate that it can be parsed as float
                    float(current_value)
                except ValueError:
                    # Fix invalid value
                    os.environ[var_name] = default_val
                    fixes_applied.append(f"Fixed {var_name}={default_val} (was invalid: {current_value})")

        return fixes_applied

# Utility functions for safe environment variable access
def safe_getenv_int(var_name: str, default: str) -> int:
    """Safe wrapper for int(os.getenv())"""
    return EnvValidator.get_int(var_name, default)

def safe_getenv_float(var_name: str, default: str) -> float:
    """Safe wrapper for float(os.getenv())"""
    return EnvValidator.get_float(var_name, default)

# Auto-fix on import if enabled
if os.getenv("AUTO_FIX_ENV_VARS", "false").lower() == "true":
    fixes = EnvValidator.fix_problematic_env_vars()
    if fixes:
        logger.info(f"Applied {len(fixes)} environment variable fixes: {fixes}")

# Validation on import if enabled
if os.getenv("VALIDATE_ENV_VARS", "false").lower() == "true":
    report = EnvValidator.validate_all_env_vars()
    if report['errors']:
        logger.error(f"Environment variable errors detected: {report['errors']}")
    if report['warnings']:
        logger.warning(f"Environment variable warnings: {report['warnings']}")