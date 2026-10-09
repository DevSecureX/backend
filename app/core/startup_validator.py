#!/usr/bin/env python3
"""
DevSecureX Startup Schema Validator

Integrated schema validation system that runs during application startup
to ensure database consistency and prevent corruption issues.

Features:
- Automatic schema validation on startup
- Critical issue detection and blocking
- Auto-fix capabilities with safety controls  
- Comprehensive logging and reporting
- Environment-specific behavior

Created: 2025-09-03
"""

import asyncio
import logging
import os
import sys
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.schema_validator import SchemaValidator, ValidationSeverity, ValidationReport
from core.database import test_connection, create_tables

# Configure logging
logger = logging.getLogger(__name__)

class StartupValidationConfig:
    """Configuration for startup validation behavior"""
    
    def __init__(self):
        # Environment-based configuration
        self.environment = os.getenv("APP_ENV", "production").lower()
        
        # Validation behavior
        self.enabled = self._get_bool_env("STARTUP_VALIDATION_ENABLED", True)
        self.auto_fix_enabled = self._get_bool_env("STARTUP_AUTO_FIX_ENABLED", self.environment != "production")
        self.block_on_critical = self._get_bool_env("STARTUP_BLOCK_ON_CRITICAL", True)
        self.block_on_errors = self._get_bool_env("STARTUP_BLOCK_ON_ERRORS", self.environment == "production")
        
        # File paths
        self.report_dir = os.getenv("VALIDATION_REPORT_DIR", "/tmp/devsecurex-validation")
        self.create_report_dir()
        
        # Timeouts
        self.validation_timeout = int(os.getenv("VALIDATION_TIMEOUT_SECONDS", "60"))
        self.database_timeout = int(os.getenv("DB_CONNECTION_TIMEOUT", "30"))
        
        # Retry configuration
        self.max_retries = int(os.getenv("VALIDATION_MAX_RETRIES", "3"))
        self.retry_delay = float(os.getenv("VALIDATION_RETRY_DELAY", "5.0"))
        
    def _get_bool_env(self, key: str, default: bool) -> bool:
        """Get boolean environment variable"""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def create_report_dir(self):
        """Create validation report directory"""
        try:
            Path(self.report_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning(f"Failed to create report directory {self.report_dir}: {e}")
            self.report_dir = "/tmp"

class StartupValidator:
    """Startup-integrated schema validator"""
    
    def __init__(self, config: Optional[StartupValidationConfig] = None):
        self.config = config or StartupValidationConfig()
        self.validation_report: Optional[ValidationReport] = None
        self.startup_time = datetime.utcnow()
        
    async def validate_and_fix_on_startup(self) -> bool:
        """
        Main startup validation function
        Returns True if startup should continue, False if it should be blocked
        """
        if not self.config.enabled:
            logger.info("Startup validation disabled")
            return True
        
        logger.info("🚀 Starting DevSecureX startup validation...")
        logger.info(f"Environment: {self.config.environment}")
        logger.info(f"Auto-fix enabled: {self.config.auto_fix_enabled}")
        logger.info(f"Block on critical: {self.config.block_on_critical}")
        logger.info(f"Block on errors: {self.config.block_on_errors}")
        
        try:
            # Step 1: Test database connection
            if not await self._test_database_connection():
                logger.error("❌ Database connection failed - blocking startup")
                return False
            
            # Step 2: Ensure tables exist
            await self._ensure_tables_exist()
            
            # Step 3: Run schema validation with retry logic
            validation_success = await self._run_validation_with_retry()
            
            if not validation_success:
                logger.error("❌ Schema validation failed after retries - blocking startup")
                return False
            
            # Step 4: Analyze validation results
            should_continue = await self._analyze_validation_results()
            
            # Step 5: Apply fixes if enabled and safe
            if should_continue and self.config.auto_fix_enabled and self.validation_report:
                await self._apply_safe_fixes()
            
            # Step 6: Save validation report
            await self._save_startup_report()
            
            if should_continue:
                logger.info("✅ Startup validation completed successfully")
            else:
                logger.error("❌ Startup validation failed - blocking startup")
            
            return should_continue
            
        except Exception as e:
            logger.error(f"❌ Startup validation crashed: {e}")
            logger.exception("Startup validation exception details:")
            
            # In production, block startup on validation crashes
            if self.config.environment == "production":
                return False
            
            # In development, allow startup to continue with warning
            logger.warning("⚠️ Allowing startup to continue despite validation failure (dev environment)")
            return True
    
    async def _test_database_connection(self) -> bool:
        """Test database connection with timeout"""
        logger.info("🔌 Testing database connection...")
        
        try:
            # Use asyncio.wait_for to implement timeout
            connection_test = await asyncio.wait_for(
                test_connection(),
                timeout=self.config.database_timeout
            )
            
            if connection_test.get('status') == 'healthy':
                logger.info("✅ Database connection healthy")
                return True
            else:
                logger.error(f"❌ Database connection unhealthy: {connection_test}")
                return False
                
        except asyncio.TimeoutError:
            logger.error(f"❌ Database connection timeout ({self.config.database_timeout}s)")
            return False
        except Exception as e:
            logger.error(f"❌ Database connection test failed: {e}")
            return False
    
    async def _ensure_tables_exist(self):
        """Ensure all required tables exist"""
        logger.info("🏗️ Ensuring database tables exist...")
        
        try:
            await create_tables()
            logger.info("✅ Database tables verified/created")
        except Exception as e:
            logger.warning(f"⚠️ Table creation had issues: {e}")
            # Don't block startup for table creation issues in development
            if self.config.environment == "production":
                raise
    
    async def _run_validation_with_retry(self) -> bool:
        """Run schema validation with retry logic"""
        logger.info("🔍 Running schema validation...")
        
        for attempt in range(1, self.config.max_retries + 1):
            try:
                logger.info(f"Schema validation attempt {attempt}/{self.config.max_retries}")
                
                validator = SchemaValidator(
                    auto_fix=False,  # We'll handle fixes separately
                    dry_run=True
                )
                
                # Run validation with timeout
                self.validation_report = await asyncio.wait_for(
                    validator.validate_schema(),
                    timeout=self.config.validation_timeout
                )
                
                logger.info("✅ Schema validation completed successfully")
                return True
                
            except asyncio.TimeoutError:
                logger.warning(f"⏰ Schema validation timeout on attempt {attempt}")
                if attempt < self.config.max_retries:
                    await asyncio.sleep(self.config.retry_delay)
                    continue
                else:
                    logger.error("❌ Schema validation failed due to timeout")
                    return False
                    
            except Exception as e:
                logger.warning(f"⚠️ Schema validation error on attempt {attempt}: {e}")
                if attempt < self.config.max_retries:
                    await asyncio.sleep(self.config.retry_delay)
                    continue
                else:
                    logger.error(f"❌ Schema validation failed after {self.config.max_retries} attempts: {e}")
                    return False
        
        return False
    
    async def _analyze_validation_results(self) -> bool:
        """Analyze validation results and determine if startup should continue"""
        if not self.validation_report:
            logger.error("❌ No validation report available")
            return False
        
        critical_count = self.validation_report.critical_issues_count
        error_count = self.validation_report.error_issues_count
        warning_count = self.validation_report.warning_issues_count
        auto_fixable_count = len(self.validation_report.auto_fixable_issues)
        
        logger.info(f"📊 Validation Results:")
        logger.info(f"   🔴 Critical Issues: {critical_count}")
        logger.info(f"   🟡 Error Issues: {error_count}")
        logger.info(f"   ⚠️  Warning Issues: {warning_count}")
        logger.info(f"   🔧 Auto-fixable: {auto_fixable_count}")
        
        # Log specific critical and error issues
        if critical_count > 0:
            logger.error("🔴 CRITICAL ISSUES FOUND:")
            for issue in self.validation_report.issues:
                if issue.severity == ValidationSeverity.CRITICAL:
                    logger.error(f"   - {issue.table_name}.{issue.column_name or 'TABLE'}: {issue.issue_description}")
        
        if error_count > 0:
            logger.error("🟡 ERROR ISSUES FOUND:")
            for issue in self.validation_report.issues:
                if issue.severity == ValidationSeverity.ERROR:
                    logger.error(f"   - {issue.table_name}.{issue.column_name or 'TABLE'}: {issue.issue_description}")
        
        # Determine if startup should be blocked
        should_block = False
        
        if critical_count > 0 and self.config.block_on_critical:
            logger.error("❌ Blocking startup due to critical schema issues")
            should_block = True
        
        if error_count > 0 and self.config.block_on_errors:
            logger.error("❌ Blocking startup due to error schema issues")
            should_block = True
        
        if should_block:
            # Show how many issues could be auto-fixed
            if auto_fixable_count > 0:
                logger.info(f"💡 {auto_fixable_count} issues could be auto-fixed. Enable auto-fix to resolve them.")
                logger.info("   Set STARTUP_AUTO_FIX_ENABLED=true to enable auto-fixing")
            
            # Provide migration script information
            logger.info("📜 Run schema validation manually to generate migration script:")
            logger.info("   python -m core.schema_validator --migration-script schema_fixes.sql")
            
            return False
        
        return True
    
    async def _apply_safe_fixes(self):
        """Apply auto-fixable issues with safety checks"""
        if not self.validation_report or not self.validation_report.auto_fixable_issues:
            logger.info("ℹ️ No auto-fixable issues to apply")
            return
        
        auto_fixable_issues = self.validation_report.auto_fixable_issues
        
        # Filter out high-risk fixes in production
        if self.config.environment == "production":
            safe_issues = [
                issue for issue in auto_fixable_issues 
                if issue.estimated_risk in ["low", "medium"] and not issue.requires_data_migration
            ]
            
            if len(safe_issues) < len(auto_fixable_issues):
                logger.warning(f"⚠️ Skipping {len(auto_fixable_issues) - len(safe_issues)} high-risk fixes in production")
        else:
            safe_issues = auto_fixable_issues
        
        if not safe_issues:
            logger.info("ℹ️ No safe auto-fixes to apply")
            return
        
        logger.info(f"🔧 Applying {len(safe_issues)} safe auto-fixes...")
        
        try:
            validator = SchemaValidator(auto_fix=True, dry_run=False)
            validator.validation_report = self.validation_report
            
            fix_results = await validator.apply_fixes(safe_issues)
            
            applied = fix_results.get('applied', 0)
            failed = fix_results.get('failed', 0)
            
            if applied > 0:
                logger.info(f"✅ Successfully applied {applied} auto-fixes")
            
            if failed > 0:
                logger.warning(f"⚠️ {failed} auto-fixes failed")
                # Don't block startup for failed auto-fixes
                
        except Exception as e:
            logger.error(f"❌ Auto-fix process failed: {e}")
            # Don't block startup for auto-fix failures
    
    async def _save_startup_report(self):
        """Save startup validation report"""
        if not self.validation_report:
            return
        
        try:
            timestamp = self.startup_time.strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(self.config.report_dir, f"startup_validation_{timestamp}.json")
            
            # Add startup-specific metadata
            report_dict = self.validation_report.to_dict()
            report_dict["startup_metadata"] = {
                "environment": self.config.environment,
                "startup_time": self.startup_time.isoformat(),
                "auto_fix_enabled": self.config.auto_fix_enabled,
                "configuration": {
                    "block_on_critical": self.config.block_on_critical,
                    "block_on_errors": self.config.block_on_errors,
                    "validation_timeout": self.config.validation_timeout,
                    "max_retries": self.config.max_retries
                }
            }
            
            self.validation_report.save_to_file(report_file)
            logger.info(f"📄 Startup validation report saved: {report_file}")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to save startup validation report: {e}")
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """Get validation summary for health checks"""
        if not self.validation_report:
            return {"status": "not_run", "message": "Validation not run"}
        
        return {
            "status": "completed",
            "timestamp": self.validation_report.timestamp.isoformat(),
            "environment": self.config.environment,
            "summary": {
                "total_issues": len(self.validation_report.issues),
                "critical_issues": self.validation_report.critical_issues_count,
                "error_issues": self.validation_report.error_issues_count,
                "warning_issues": self.validation_report.warning_issues_count,
                "auto_fixable_issues": len(self.validation_report.auto_fixable_issues)
            },
            "configuration": {
                "auto_fix_enabled": self.config.auto_fix_enabled,
                "block_on_critical": self.config.block_on_critical,
                "block_on_errors": self.config.block_on_errors
            }
        }

# Global startup validator instance
_startup_validator: Optional[StartupValidator] = None

async def run_startup_validation() -> bool:
    """
    Main entry point for startup validation
    Returns True if startup should continue, False if it should be blocked
    """
    global _startup_validator
    
    _startup_validator = StartupValidator()
    return await _startup_validator.validate_and_fix_on_startup()

def get_startup_validation_summary() -> Dict[str, Any]:
    """Get startup validation summary for health checks"""
    global _startup_validator
    
    if _startup_validator:
        return _startup_validator.get_validation_summary()
    
    return {"status": "not_initialized", "message": "Startup validation not initialized"}

async def main():
    """CLI entry point for testing startup validation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX Startup Validator")
    parser.add_argument("--environment", choices=['development', 'staging', 'production'], 
                       default='development', help="Environment to simulate")
    parser.add_argument("--auto-fix", action="store_true", help="Enable auto-fix")
    parser.add_argument("--no-block", action="store_true", help="Don't block on errors/critical issues")
    
    args = parser.parse_args()
    
    # Override environment variables for testing
    os.environ["APP_ENV"] = args.environment
    if args.auto_fix:
        os.environ["STARTUP_AUTO_FIX_ENABLED"] = "true"
    if args.no_block:
        os.environ["STARTUP_BLOCK_ON_CRITICAL"] = "false"
        os.environ["STARTUP_BLOCK_ON_ERRORS"] = "false"
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run startup validation
    success = await run_startup_validation()
    
    if success:
        print("\n✅ Startup validation passed - application would start")
        sys.exit(0)
    else:
        print("\n❌ Startup validation failed - application would be blocked")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())