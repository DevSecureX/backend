#!/usr/bin/env python3
"""
DevSecureX Health Check Endpoints

FastAPI endpoints for monitoring system health, schema validation status,
and corruption prevention system status.

Created: 2025-09-03
"""

import asyncio
import logging
import os
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel

from core.corruption_prevention import get_corruption_prevention, run_corruption_check, get_system_status
from core.startup_validator import get_startup_validation_summary
from core.schema_validator import SchemaValidator
from core.migration_manager import get_migration_status
from core.database import get_connection_health, get_pool_status

logger = logging.getLogger(__name__)

# Response models
class HealthSummary(BaseModel):
    status: str
    timestamp: str
    version: str = "1.0.0"
    environment: str = "production"

class DetailedHealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str = "1.0.0"
    environment: str
    components: Dict[str, Any]
    startup_validation: Dict[str, Any]
    corruption_prevention: Dict[str, Any]
    database: Dict[str, Any]
    migrations: Dict[str, Any]
    recommendations: list[str]

class CorruptionCheckResponse(BaseModel):
    status: str
    timestamp: str
    total_issues: int
    critical_issues: int
    auto_fixable_issues: int
    issues: list[Dict[str, Any]]
    system_metrics: Dict[str, Any]
    recommendations: list[str]

class SchemaValidationResponse(BaseModel):
    status: str
    timestamp: str
    total_issues: int
    critical_issues: int
    error_issues: int
    warning_issues: int
    auto_fixable_issues: int
    issues: list[Dict[str, Any]]

# Create router
health_router = APIRouter(prefix="/health", tags=["health"])

@health_router.get("/", response_model=HealthSummary)
async def basic_health_check():
    """
    Basic health check endpoint for load balancers and monitoring systems.
    Returns simple status without expensive checks.
    """
    try:
        # Quick database connectivity test
        health = await get_connection_health()
        db_status = health.get("connection_test", {}).get("status", "unknown")
        
        if db_status == "healthy":
            status = "healthy"
        else:
            status = "unhealthy"
        
        return HealthSummary(
            status=status,
            timestamp=datetime.utcnow().isoformat(),
            environment=os.getenv("APP_ENV", "production")
        )
    
    except Exception as e:
        logger.error(f"Basic health check failed: {e}")
        return HealthSummary(
            status="unhealthy",
            timestamp=datetime.utcnow().isoformat(),
            environment=os.getenv("APP_ENV", "production")
        )

@health_router.get("/detailed", response_model=DetailedHealthResponse)
async def detailed_health_check():
    """
    Comprehensive health check including all system components.
    Use sparingly as this performs extensive checks.
    """
    try:
        timestamp = datetime.utcnow()
        
        # Get all health information
        startup_validation = get_startup_validation_summary()
        corruption_status = await get_system_status()
        database_health = await get_connection_health()
        migration_status = await get_migration_status()
        
        # Determine overall status
        overall_status = "healthy"
        
        # Check database health
        db_status = database_health.get("connection_test", {}).get("status", "unknown")
        if db_status != "healthy":
            overall_status = "unhealthy"
        
        # Check startup validation
        if startup_validation.get("status") == "not_run" or startup_validation.get("summary", {}).get("critical_issues", 0) > 0:
            overall_status = "degraded"
        
        # Check corruption prevention
        if corruption_status.get("status") in ["critical", "degraded"]:
            overall_status = corruption_status["status"]
        
        # Check migrations
        if migration_status.get("pending", 0) > 0:
            if overall_status == "healthy":
                overall_status = "warning"
        
        # Collect recommendations
        recommendations = []
        if startup_validation.get("summary", {}).get("critical_issues", 0) > 0:
            recommendations.append("Critical schema validation issues detected - run startup validation")
        
        if corruption_status.get("critical_issues", 0) > 0:
            recommendations.append("Critical corruption issues detected - run corruption prevention checks")
        
        if migration_status.get("pending", 0) > 0:
            recommendations.append(f"{migration_status['pending']} database migrations pending")
        
        recommendations.extend(corruption_status.get("recommendations", []))
        
        return DetailedHealthResponse(
            status=overall_status,
            timestamp=timestamp.isoformat(),
            environment=os.getenv("APP_ENV", "production"),
            components={
                "database": {
                    "status": db_status,
                    "response_time_ms": database_health.get("connection_test", {}).get("response_time_ms", 0),
                    "pool_status": database_health.get("pool_status", {})
                },
                "startup_validation": {
                    "status": startup_validation.get("status", "unknown"),
                    "issues": startup_validation.get("summary", {})
                },
                "corruption_prevention": {
                    "status": corruption_status.get("status", "unknown"),
                    "recent_issues": corruption_status.get("recent_issues", 0)
                },
                "migrations": {
                    "status": "up_to_date" if migration_status.get("pending", 0) == 0 else "pending",
                    "pending_count": migration_status.get("pending", 0)
                }
            },
            startup_validation=startup_validation,
            corruption_prevention=corruption_status,
            database=database_health,
            migrations=migration_status,
            recommendations=recommendations
        )
    
    except Exception as e:
        logger.error(f"Detailed health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@health_router.get("/database")
async def database_health_check():
    """
    Database-specific health check with connection pool and performance metrics.
    """
    try:
        health = await get_connection_health()
        pool_status = await get_pool_status()
        
        # Add pool status to health response
        health["detailed_pool_status"] = pool_status
        
        return health
    
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Database health check failed: {str(e)}")

@health_router.get("/startup-validation")
async def startup_validation_status():
    """
    Get startup validation status and results.
    """
    try:
        summary = get_startup_validation_summary()
        
        if summary.get("status") == "not_initialized":
            return {
                "status": "not_run",
                "message": "Startup validation has not been run yet",
                "recommendation": "Run startup validation to check system status"
            }
        
        return summary
    
    except Exception as e:
        logger.error(f"Startup validation status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Startup validation status failed: {str(e)}")

@health_router.post("/corruption-check", response_model=CorruptionCheckResponse)
async def run_corruption_prevention_check(
    auto_fix: bool = Query(False, description="Enable automatic fixes for detected issues")
):
    """
    Run comprehensive corruption prevention check.
    This is an expensive operation that should be used sparingly.
    """
    try:
        logger.info(f"Running corruption prevention check (auto_fix={auto_fix})")
        
        report = await run_corruption_check(auto_fix=auto_fix)
        
        return CorruptionCheckResponse(
            status=report.overall_status,
            timestamp=report.timestamp.isoformat(),
            total_issues=len(report.corruption_issues),
            critical_issues=len(report.critical_issues),
            auto_fixable_issues=len([i for i in report.corruption_issues if i.auto_fixable]),
            issues=[issue.to_dict() for issue in report.corruption_issues],
            system_metrics=report.system_metrics,
            recommendations=report.recommendations
        )
    
    except Exception as e:
        logger.error(f"Corruption prevention check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Corruption check failed: {str(e)}")

@health_router.get("/corruption-status")
async def corruption_prevention_status():
    """
    Get current corruption prevention system status without running checks.
    """
    try:
        status = await get_system_status()
        return status
    
    except Exception as e:
        logger.error(f"Corruption prevention status failed: {e}")
        raise HTTPException(status_code=500, detail=f"Corruption status failed: {str(e)}")

@health_router.post("/schema-validation", response_model=SchemaValidationResponse)
async def run_schema_validation(
    auto_fix: bool = Query(False, description="Enable automatic fixes for detected issues"),
    table: Optional[str] = Query(None, description="Validate specific table only")
):
    """
    Run schema validation check.
    This performs extensive schema comparison and can be expensive.
    """
    try:
        logger.info(f"Running schema validation (auto_fix={auto_fix}, table={table})")
        
        validator = SchemaValidator(auto_fix=auto_fix, dry_run=not auto_fix)
        
        # TODO: Add table filtering if needed
        
        report = await validator.validate_schema()
        
        # Apply fixes if auto_fix is enabled
        if auto_fix and report.auto_fixable_issues:
            fix_results = await validator.apply_fixes()
            logger.info(f"Applied {fix_results.get('applied', 0)} fixes")
        
        return SchemaValidationResponse(
            status="healthy" if len(report.issues) == 0 else ("critical" if report.critical_issues_count > 0 else "warning"),
            timestamp=report.timestamp.isoformat(),
            total_issues=len(report.issues),
            critical_issues=report.critical_issues_count,
            error_issues=report.error_issues_count,
            warning_issues=report.warning_issues_count,
            auto_fixable_issues=len(report.auto_fixable_issues),
            issues=[issue.to_dict() for issue in report.issues]
        )
    
    except Exception as e:
        logger.error(f"Schema validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Schema validation failed: {str(e)}")

@health_router.get("/migrations")
async def migration_status():
    """
    Get current migration status including pending migrations.
    """
    try:
        status = await get_migration_status()
        return status
    
    except Exception as e:
        logger.error(f"Migration status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Migration status failed: {str(e)}")

@health_router.get("/readiness")
async def readiness_check():
    """
    Kubernetes/container readiness probe.
    Returns 200 if the application is ready to serve traffic.
    """
    try:
        # Check if startup validation passed
        startup_summary = get_startup_validation_summary()
        
        # If startup validation failed or found critical issues, not ready
        if (startup_summary.get("status") in ["not_initialized", "not_run"] or 
            startup_summary.get("summary", {}).get("critical_issues", 0) > 0):
            raise HTTPException(status_code=503, detail="Startup validation failed or pending")
        
        # Quick database connectivity test
        health = await get_connection_health()
        db_status = health.get("connection_test", {}).get("status", "unknown")
        
        if db_status != "healthy":
            raise HTTPException(status_code=503, detail="Database not healthy")
        
        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
            "startup_validation": "passed",
            "database": "healthy"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        raise HTTPException(status_code=503, detail=f"Readiness check failed: {str(e)}")

@health_router.get("/liveness")
async def liveness_check():
    """
    Kubernetes/container liveness probe.
    Returns 200 if the application is alive (but may not be ready).
    """
    try:
        # Very basic check - just ensure the application is responding
        return {
            "status": "alive",
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": (datetime.utcnow() - datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds()
        }
    
    except Exception as e:
        logger.error(f"Liveness check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Liveness check failed: {str(e)}")

# Add a startup event to register health check info
startup_info = {
    "startup_time": datetime.utcnow(),
    "version": "1.0.0",
    "features": [
        "schema_validation",
        "corruption_prevention", 
        "automated_migration",
        "startup_validation",
        "backup_validation"
    ]
}

@health_router.get("/info")
async def application_info():
    """
    Get application information and feature status.
    """
    return {
        **startup_info,
        "current_time": datetime.utcnow().isoformat(),
        "environment": os.getenv("APP_ENV", "production"),
        "configuration": {
            "startup_validation_enabled": os.getenv("STARTUP_VALIDATION_ENABLED", "true"),
            "auto_fix_enabled": os.getenv("STARTUP_AUTO_FIX_ENABLED", "false"),
            "corruption_prevention_enabled": os.getenv("CORRUPTION_PREVENTION_ENABLED", "true"),
            "migration_auto_run": os.getenv("MIGRATION_AUTO_RUN", "true")
        }
    }