"""
Application startup checks for database schema compatibility.

This module provides startup checks that run when the application starts
to detect and optionally fix database schema compatibility issues.
"""

import logging
import os
from typing import Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import async_session
from core.db_schema_validator import schema_validator

logger = logging.getLogger(__name__)


class StartupHealthChecker:
    """Performs health checks during application startup."""
    
    def __init__(self):
        self.auto_fix_enabled = os.getenv("AUTO_FIX_SCHEMA", "false").lower() == "true"
        self.strict_mode = os.getenv("STRICT_SCHEMA_CHECK", "false").lower() == "true"
    
    async def run_all_checks(self) -> Dict[str, any]:
        """
        Run all startup health checks.
        
        Returns:
            Dict containing check results and recommendations
        """
        logger.info("Running application startup health checks...")
        
        health_status = {
            "overall_health": "healthy",
            "checks_passed": 0,
            "checks_failed": 0,
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        # Database connectivity check
        db_health = await self._check_database_connectivity()
        if db_health["status"] == "healthy":
            health_status["checks_passed"] += 1
        else:
            health_status["checks_failed"] += 1
            health_status["errors"].append(db_health["message"])
            health_status["overall_health"] = "unhealthy"
        
        # Schema compatibility check
        if db_health["status"] == "healthy":
            schema_health = await self._check_schema_compatibility()
            
            if schema_health["status"] == "healthy":
                health_status["checks_passed"] += 1
            elif schema_health["status"] == "warning":
                health_status["checks_passed"] += 1  # Still operational
                health_status["warnings"].extend(schema_health["warnings"])
                health_status["recommendations"].extend(schema_health["recommendations"])
                if health_status["overall_health"] == "healthy":
                    health_status["overall_health"] = "degraded"
            else:
                health_status["checks_failed"] += 1
                health_status["errors"].append(schema_health["message"])
                health_status["overall_health"] = "unhealthy"
        
        # Log results
        logger.info(f"Startup health check completed: {health_status['overall_health']}")
        if health_status["warnings"]:
            for warning in health_status["warnings"]:
                logger.warning(f"Startup warning: {warning}")
        if health_status["errors"]:
            for error in health_status["errors"]:
                logger.error(f"Startup error: {error}")
        
        return health_status
    
    async def _check_database_connectivity(self) -> Dict[str, str]:
        """Check basic database connectivity."""
        try:
            async with async_session() as db:
                from sqlalchemy import text
                await db.execute(text("SELECT 1"))
                
            return {
                "status": "healthy",
                "message": "Database connectivity successful"
            }
            
        except Exception as e:
            return {
                "status": "unhealthy", 
                "message": f"Database connectivity failed: {str(e)}"
            }
    
    async def _check_schema_compatibility(self) -> Dict[str, any]:
        """Check database schema compatibility and optionally fix issues."""
        try:
            async with async_session() as db:
                schema_status = await schema_validator.validate_schema_compatibility(db)
                
                if schema_status['is_compatible']:
                    return {
                        "status": "healthy",
                        "message": "Database schema is compatible"
                    }
                
                # Schema issues detected
                warnings = []
                recommendations = []
                
                if schema_status['missing_tables']:
                    warnings.append(f"Missing tables: {', '.join(schema_status['missing_tables'])}")
                
                for issue in schema_status['schema_issues']:
                    warnings.append(issue)
                
                for rec in schema_status['recommendations']:
                    recommendations.append(rec)
                
                # Attempt auto-fix if enabled
                if self.auto_fix_enabled and not self.strict_mode:
                    logger.info("Auto-fix enabled, attempting to fix schema issues...")
                    fix_success = await self._attempt_schema_fix()
                    
                    if fix_success:
                        recommendations.append("Schema issues were automatically fixed")
                        return {
                            "status": "healthy",
                            "message": "Schema issues detected and automatically fixed",
                            "warnings": warnings,
                            "recommendations": recommendations
                        }
                    else:
                        recommendations.append("Auto-fix failed, manual intervention required")
                
                # Determine severity
                if self.strict_mode:
                    return {
                        "status": "unhealthy",
                        "message": "Schema compatibility issues detected (strict mode)",
                        "warnings": warnings,
                        "recommendations": recommendations
                    }
                else:
                    return {
                        "status": "warning",
                        "message": "Schema compatibility issues detected but application can continue",
                        "warnings": warnings,
                        "recommendations": recommendations
                    }
                
        except Exception as e:
            return {
                "status": "unhealthy",
                "message": f"Schema compatibility check failed: {str(e)}"
            }
    
    async def _attempt_schema_fix(self) -> bool:
        """Attempt to automatically fix schema issues."""
        try:
            from migrations.run_migration import run_specific_migration
            
            logger.info("Running schema compatibility migration...")
            success = await run_specific_migration("006_schema_compatibility_migration")
            
            if success:
                logger.info("Schema compatibility migration completed successfully")
                return True
            else:
                logger.error("Schema compatibility migration failed")
                return False
                
        except Exception as e:
            logger.error(f"Auto-fix attempt failed: {str(e)}")
            return False


# Global instance
startup_checker = StartupHealthChecker()


async def run_startup_checks() -> bool:
    """
    Run startup checks and return whether the application should start.
    
    Returns:
        bool: True if application should start, False if critical issues found
    """
    health_status = await startup_checker.run_all_checks()
    
    if health_status["overall_health"] == "unhealthy":
        logger.critical("Critical startup issues detected. Application startup aborted.")
        
        # Print actionable error information
        print("\n" + "=" * 60)
        print("🚨 CRITICAL STARTUP ISSUES DETECTED")
        print("=" * 60)
        
        for error in health_status["errors"]:
            print(f"❌ {error}")
        
        if health_status["recommendations"]:
            print(f"\n💡 Recommendations:")
            for rec in health_status["recommendations"]:
                print(f"   - {rec}")
        
        print(f"\nTo fix schema issues, run:")
        print(f"   python scripts/fix_database_schema.py")
        print("=" * 60)
        
        return False
    
    elif health_status["overall_health"] == "degraded":
        logger.warning("Application starting with warnings. Monitor for issues.")
        
        if health_status["warnings"]:
            print("\n⚠️  Startup Warnings:")
            for warning in health_status["warnings"]:
                print(f"   - {warning}")
        
        if health_status["recommendations"]:
            print(f"\n💡 Recommendations:")
            for rec in health_status["recommendations"]:
                print(f"   - {rec}")
    
    return True