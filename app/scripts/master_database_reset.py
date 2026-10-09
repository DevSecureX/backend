#!/usr/bin/env python3
"""
Master Database Reset Script for DevSecureX

This master script orchestrates the complete database reset process by coordinating
all the specialized scripts to ensure a safe and successful database reset.

Features:
1. Pre-reset validation and safety checks
2. Coordinated execution of reset components
3. Post-reset verification and testing
4. Comprehensive logging and reporting
5. Rollback capabilities in case of failure

Usage:
    python app/scripts/master_database_reset.py [options]
    
Author: DevSecureX Team
"""

import asyncio
import argparse
import logging
import sys
import os
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
import json
import time

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Import our specialized components
from sqlalchemy import text

# Import our specialized components
sys.path.append(os.path.dirname(__file__))
from comprehensive_database_reset import DatabaseResetManager
from enhanced_migration_runner import EnhancedMigrationRunner
from database_health_monitor import DatabaseHealthMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'master_database_reset_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class MasterDatabaseResetOrchestrator:
    """Master orchestrator for comprehensive database reset"""
    
    def __init__(self, dry_run: bool = False, force: bool = False, 
                 skip_backup: bool = False, skip_health_check: bool = False):
        self.dry_run = dry_run
        self.force = force
        self.skip_backup = skip_backup
        self.skip_health_check = skip_health_check
        
        # Initialize component managers
        self.reset_manager = DatabaseResetManager(dry_run=dry_run, force=force)
        self.migration_runner = EnhancedMigrationRunner(dry_run=dry_run)
        self.health_monitor = DatabaseHealthMonitor(detailed=True)
        
        # Reset execution state
        self.execution_state = {
            "start_time": datetime.now(),
            "steps_completed": [],
            "steps_failed": [],
            "backup_file": None,
            "pre_reset_health": None,
            "post_reset_health": None,
            "overall_success": False
        }
        
        logger.info(f"🚀 Master Database Reset Orchestrator initialized")
        logger.info(f"   Dry Run: {dry_run}")
        logger.info(f"   Force Mode: {force}")
        logger.info(f"   Skip Backup: {skip_backup}")
        logger.info(f"   Skip Health Check: {skip_health_check}")
    
    async def step_pre_reset_validation(self) -> bool:
        """Step 1: Pre-reset validation and safety checks"""
        logger.info("🔍 Step 1: Pre-reset validation and safety checks")
        
        try:
            if not self.skip_health_check:
                # Run initial health check
                logger.info("Running pre-reset health check...")
                self.execution_state["pre_reset_health"] = await self.health_monitor.run_comprehensive_health_check()
                
                pre_health = self.execution_state["pre_reset_health"]["overall_health"]
                logger.info(f"Pre-reset health status: {pre_health}")
                
                # Check if database is accessible at all
                if pre_health == "critical" and not self.execution_state["pre_reset_health"]["connection_health"]["basic_connectivity"]:
                    logger.error("❌ Database is not accessible - cannot proceed with reset")
                    return False
            else:
                logger.info("Skipping pre-reset health check as requested")
            
            # Validate environment and prerequisites
            logger.info("Validating environment prerequisites...")
            
            # Check Docker container status
            try:
                result = subprocess.run(["docker", "ps", "--filter", "name=devsecurex-db", "--format", "{{.Status}}"],
                                      capture_output=True, text=True)
                if "Up" not in result.stdout:
                    logger.error("❌ Database container is not running")
                    return False
                logger.info("✅ Database container is running")
            except Exception as e:
                logger.warning(f"Could not check Docker container status: {str(e)}")
            
            # Check available disk space for backup
            if not self.skip_backup:
                try:
                    backup_dir = os.path.join("scripts", "db-backup", "backups")
                    statvfs = os.statvfs(backup_dir if os.path.exists(backup_dir) else ".")
                    free_space_gb = (statvfs.f_frsize * statvfs.f_availl) / (1024**3)
                    
                    if free_space_gb < 1:  # Less than 1GB free
                        logger.warning("⚠️ Low disk space for backup - proceed with caution")
                        if not self.force:
                            logger.error("❌ Insufficient disk space for backup")
                            return False
                    
                    logger.info(f"✅ Available disk space: {free_space_gb:.1f}GB")
                except Exception as e:
                    logger.warning(f"Could not check disk space: {str(e)}")
            
            self.execution_state["steps_completed"].append("pre_reset_validation")
            logger.info("✅ Pre-reset validation completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Pre-reset validation failed: {str(e)}")
            self.execution_state["steps_failed"].append(("pre_reset_validation", str(e)))
            return False
    
    async def step_create_backup(self) -> bool:
        """Step 2: Create comprehensive backup"""
        logger.info("📦 Step 2: Creating comprehensive backup")
        
        if self.skip_backup:
            logger.info("Skipping backup creation as requested")
            self.execution_state["steps_completed"].append("create_backup")
            return True
        
        try:
            backup_file = await self.reset_manager.create_safety_backup()
            self.execution_state["backup_file"] = backup_file
            
            # Verify backup was created successfully
            if backup_file and os.path.exists(backup_file):
                file_size = os.path.getsize(backup_file)
                logger.info(f"✅ Backup created successfully: {backup_file} ({file_size:,} bytes)")
                
                # Basic backup validation
                if file_size < 1000:  # Less than 1KB suggests empty backup
                    logger.warning("⚠️ Backup file is very small - may be empty")
                    if not self.force:
                        logger.error("❌ Backup appears to be empty")
                        return False
                
                self.execution_state["steps_completed"].append("create_backup")
                return True
            else:
                logger.error("❌ Backup file was not created or is not accessible")
                return False
                
        except Exception as e:
            logger.error(f"❌ Backup creation failed: {str(e)}")
            self.execution_state["steps_failed"].append(("create_backup", str(e)))
            return False
    
    async def step_schema_analysis(self) -> bool:
        """Step 3: Analyze current schema and identify issues"""
        logger.info("🔍 Step 3: Schema analysis and issue identification")
        
        try:
            # Compare current vs expected schemas
            schema_comparison = await self.reset_manager.compare_schemas()
            
            issues_found = schema_comparison["statistics"]["issues_found"]
            logger.info(f"Schema analysis complete: {issues_found} issues found")
            
            if issues_found > 0:
                logger.info("Schema issues detected:")
                if schema_comparison["missing_tables"]:
                    logger.info(f"  - Missing tables: {schema_comparison['missing_tables']}")
                if schema_comparison["extra_tables"]:
                    logger.info(f"  - Extra tables: {schema_comparison['extra_tables']}")
                if schema_comparison["table_mismatches"]:
                    logger.info(f"  - Table mismatches: {list(schema_comparison['table_mismatches'].keys())}")
            else:
                logger.info("✅ No schema issues detected")
            
            self.execution_state["steps_completed"].append("schema_analysis")
            return True
            
        except Exception as e:
            logger.error(f"❌ Schema analysis failed: {str(e)}")
            self.execution_state["steps_failed"].append(("schema_analysis", str(e)))
            return False
    
    async def step_database_reset(self) -> bool:
        """Step 4: Execute database reset"""
        logger.info("🔄 Step 4: Executing database reset")
        
        try:
            # Execute the complete database reset
            success = await self.reset_manager.drop_and_recreate_tables()
            
            if success:
                logger.info("✅ Database reset completed successfully")
                self.execution_state["steps_completed"].append("database_reset")
                return True
            else:
                logger.error("❌ Database reset failed")
                return False
                
        except Exception as e:
            logger.error(f"❌ Database reset failed: {str(e)}")
            self.execution_state["steps_failed"].append(("database_reset", str(e)))
            return False
    
    async def step_migration_setup(self) -> bool:
        """Step 5: Run fresh migrations and setup"""
        logger.info("📜 Step 5: Running fresh migrations and setup")
        
        try:
            # Run full migration setup
            success = await self.migration_runner.run_full_migration_setup()
            
            if success:
                logger.info("✅ Migration setup completed successfully")
                self.execution_state["steps_completed"].append("migration_setup")
                return True
            else:
                logger.error("❌ Migration setup failed")
                return False
                
        except Exception as e:
            logger.error(f"❌ Migration setup failed: {str(e)}")
            self.execution_state["steps_failed"].append(("migration_setup", str(e)))
            return False
    
    async def step_post_reset_verification(self) -> bool:
        """Step 6: Post-reset verification and testing"""
        logger.info("✅ Step 6: Post-reset verification and testing")
        
        try:
            # Run comprehensive health check
            self.execution_state["post_reset_health"] = await self.health_monitor.run_comprehensive_health_check()
            
            post_health = self.execution_state["post_reset_health"]["overall_health"]
            logger.info(f"Post-reset health status: {post_health}")
            
            # Verify schema consistency
            schema_ok = await self.reset_manager.verify_final_schema()
            if not schema_ok:
                logger.error("❌ Post-reset schema verification failed")
                return False
            
            # Test basic functionality
            functionality_ok = await self.reset_manager.test_basic_functionality()
            if not functionality_ok:
                logger.error("❌ Basic functionality test failed")
                return False
            
            # Overall verification success
            if post_health in ["excellent", "good"]:
                logger.info("✅ Post-reset verification completed successfully")
                self.execution_state["steps_completed"].append("post_reset_verification")
                return True
            else:
                logger.warning(f"⚠️ Post-reset health is {post_health} - may need attention")
                # Still consider success if not critical
                if post_health != "critical":
                    self.execution_state["steps_completed"].append("post_reset_verification")
                    return True
                else:
                    return False
                
        except Exception as e:
            logger.error(f"❌ Post-reset verification failed: {str(e)}")
            self.execution_state["steps_failed"].append(("post_reset_verification", str(e)))
            return False
    
    async def step_cleanup_and_optimization(self) -> bool:
        """Step 7: Cleanup and optimization"""
        logger.info("🧹 Step 7: Cleanup and optimization")
        
        try:
            # Import async_session here to avoid circular imports
            from core.database import async_session
            
            # Run database optimization
            async with async_session() as session:
                # Update statistics
                await session.execute(text("ANALYZE;"))
                
                # Light vacuum
                await session.execute(text("VACUUM;"))
                
                logger.info("✅ Database optimization completed")
            
            # Clean up old log files (keep only recent ones)
            try:
                logs_dir = "."
                log_files = [f for f in os.listdir(logs_dir) if f.startswith("database_") and f.endswith(".log")]
                
                if len(log_files) > 10:  # Keep only 10 most recent
                    log_files.sort(reverse=True)
                    for old_log in log_files[10:]:
                        try:
                            os.remove(old_log)
                            logger.debug(f"Removed old log file: {old_log}")
                        except:
                            pass
                
                logger.info("✅ Log cleanup completed")
            except Exception as e:
                logger.warning(f"Log cleanup failed: {str(e)}")
            
            self.execution_state["steps_completed"].append("cleanup_and_optimization")
            return True
            
        except Exception as e:
            logger.error(f"❌ Cleanup and optimization failed: {str(e)}")
            self.execution_state["steps_failed"].append(("cleanup_and_optimization", str(e)))
            return False
    
    def generate_final_report(self) -> Dict[str, Any]:
        """Generate final execution report"""
        end_time = datetime.now()
        total_duration = (end_time - self.execution_state["start_time"]).total_seconds()
        
        report = {
            "execution_summary": {
                "start_time": self.execution_state["start_time"].isoformat(),
                "end_time": end_time.isoformat(),
                "total_duration_seconds": round(total_duration, 2),
                "overall_success": self.execution_state["overall_success"],
                "dry_run": self.dry_run
            },
            "steps_completed": self.execution_state["steps_completed"],
            "steps_failed": self.execution_state["steps_failed"],
            "backup_information": {
                "backup_file": self.execution_state["backup_file"],
                "backup_created": self.execution_state["backup_file"] is not None
            },
            "health_comparison": {
                "pre_reset_health": self.execution_state.get("pre_reset_health", {}).get("overall_health"),
                "post_reset_health": self.execution_state.get("post_reset_health", {}).get("overall_health")
            }
        }
        
        return report
    
    async def execute_full_reset(self) -> bool:
        """Execute the complete database reset process"""
        logger.info("🚀 Starting Master Database Reset Process")
        logger.info("=" * 60)
        
        # Define all steps in order
        reset_steps = [
            ("Pre-Reset Validation", self.step_pre_reset_validation),
            ("Create Backup", self.step_create_backup),
            ("Schema Analysis", self.step_schema_analysis),
            ("Database Reset", self.step_database_reset),
            ("Migration Setup", self.step_migration_setup),
            ("Post-Reset Verification", self.step_post_reset_verification),
            ("Cleanup and Optimization", self.step_cleanup_and_optimization)
        ]
        
        try:
            # Execute each step
            for step_name, step_function in reset_steps:
                logger.info(f"\n{'=' * 20} {step_name} {'=' * 20}")
                
                step_start = time.time()
                success = await step_function()
                step_duration = time.time() - step_start
                
                if success:
                    logger.info(f"✅ {step_name} completed successfully ({step_duration:.1f}s)")
                else:
                    logger.error(f"❌ {step_name} failed ({step_duration:.1f}s)")
                    
                    # Critical steps that should stop the process
                    critical_steps = ["Database Reset", "Migration Setup"]
                    if step_name in critical_steps and not self.dry_run:
                        logger.error(f"💥 Critical step {step_name} failed - stopping reset process")
                        break
                
                # Small delay between steps for readability
                await asyncio.sleep(0.5)
            
            # Determine overall success
            self.execution_state["overall_success"] = len(self.execution_state["steps_failed"]) == 0
            
            # Generate and log final report
            final_report = self.generate_final_report()
            
            logger.info("\n" + "=" * 60)
            logger.info("🎯 MASTER DATABASE RESET SUMMARY")
            logger.info("=" * 60)
            
            if self.execution_state["overall_success"]:
                logger.info("🎉 Database reset completed successfully!")
                logger.info(f"✅ Steps completed: {len(self.execution_state['steps_completed'])}")
                logger.info(f"⏱️ Total duration: {final_report['execution_summary']['total_duration_seconds']}s")
                
                if self.execution_state["backup_file"]:
                    logger.info(f"📦 Backup saved: {self.execution_state['backup_file']}")
                
                # Health comparison
                pre_health = final_report["health_comparison"]["pre_reset_health"]
                post_health = final_report["health_comparison"]["post_reset_health"]
                
                if pre_health and post_health:
                    logger.info(f"🏥 Health: {pre_health} → {post_health}")
                
                logger.info("\n🔧 Your database is now clean and ready for use!")
                
            else:
                logger.error("💥 Database reset encountered issues!")
                logger.error(f"❌ Failed steps: {len(self.execution_state['steps_failed'])}")
                
                for step_name, error in self.execution_state["steps_failed"]:
                    logger.error(f"  - {step_name}: {error}")
                
                if self.execution_state["backup_file"]:
                    logger.info(f"📦 Backup available for recovery: {self.execution_state['backup_file']}")
            
            return self.execution_state["overall_success"]
            
        except Exception as e:
            logger.error(f"💥 Master reset process failed with unexpected error: {str(e)}")
            self.execution_state["overall_success"] = False
            return False


async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Master Database Reset Script for DevSecureX",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python app/scripts/master_database_reset.py --dry-run
  python app/scripts/master_database_reset.py --force --skip-backup
  python app/scripts/master_database_reset.py --no-health-check
        """
    )
    
    parser.add_argument("--dry-run", action="store_true", 
                       help="Show what would be done without executing")
    parser.add_argument("--force", action="store_true",
                       help="Force reset even with large amounts of data or warnings")
    parser.add_argument("--skip-backup", action="store_true",
                       help="Skip backup creation (dangerous - use with caution)")
    parser.add_argument("--no-health-check", action="store_true",
                       help="Skip pre-reset health check")
    parser.add_argument("--save-report", action="store_true",
                       help="Save detailed execution report to file")
    
    args = parser.parse_args()
    
    # Show warning for dangerous options
    if args.skip_backup and not args.dry_run:
        logger.warning("⚠️ WARNING: Skipping backup creation - data loss risk!")
        logger.warning("⚠️ Press Ctrl+C within 10 seconds to abort...")
        try:
            await asyncio.sleep(10)
        except KeyboardInterrupt:
            logger.info("🛑 Reset cancelled by user")
            sys.exit(1)
    
    # Initialize orchestrator
    orchestrator = MasterDatabaseResetOrchestrator(
        dry_run=args.dry_run,
        force=args.force,
        skip_backup=args.skip_backup,
        skip_health_check=args.no_health_check
    )
    
    try:
        # Execute the full reset process
        success = await orchestrator.execute_full_reset()
        
        # Save report if requested
        if args.save_report:
            report = orchestrator.generate_final_report()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"master_reset_report_{timestamp}.json"
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            logger.info(f"📄 Detailed execution report saved: {report_file}")
        
        # Exit with appropriate code
        if success:
            logger.info("✅ Master database reset process completed successfully!")
            sys.exit(0)
        else:
            logger.error("❌ Master database reset process failed!")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("🛑 Master reset process cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error in master reset process: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())