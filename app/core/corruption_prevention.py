#!/usr/bin/env python3
"""
DevSecureX Corruption Prevention System

Comprehensive system for preventing database schema and data corruption issues.
Includes proactive monitoring, automatic fixes, and preventive measures.

Features:
- Real-time schema drift detection
- Automatic corruption pattern detection  
- Proactive backup validation
- Quote corruption prevention
- Data integrity monitoring
- Automated health checks

Created: 2025-09-03
"""

import asyncio
import logging
import os
import sys
import time
import json
import hashlib
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import re
import subprocess
from pathlib import Path

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sqlalchemy import text, inspect, MetaData
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from core.database import get_db_session, DatabaseOperation, get_connection_health
from core.schema_validator import SchemaValidator, ValidationSeverity
from core.migration_manager import MigrationManager

# Configure logging
logger = logging.getLogger(__name__)

class CorruptionType(Enum):
    """Types of corruption that can be detected"""
    QUOTE_CORRUPTION = "quote_corruption"
    SCHEMA_DRIFT = "schema_drift"
    DATA_TYPE_MISMATCH = "data_type_mismatch" 
    CONSTRAINT_VIOLATION = "constraint_violation"
    BACKUP_CORRUPTION = "backup_corruption"
    CONNECTION_POLLUTION = "connection_pollution"
    INDEX_CORRUPTION = "index_corruption"
    FOREIGN_KEY_VIOLATION = "foreign_key_violation"

class CorruptionSeverity(Enum):
    """Severity levels for corruption issues"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class CorruptionIssue:
    """Represents a detected corruption issue"""
    corruption_type: CorruptionType
    severity: CorruptionSeverity
    description: str
    table_name: Optional[str] = None
    column_name: Optional[str] = None
    detected_at: datetime = field(default_factory=datetime.utcnow)
    auto_fixable: bool = False
    fix_sql: Optional[str] = None
    original_value: Optional[str] = None
    corrected_value: Optional[str] = None
    detection_details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "corruption_type": self.corruption_type.value,
            "severity": self.severity.value,
            "description": self.description,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "detected_at": self.detected_at.isoformat(),
            "auto_fixable": self.auto_fixable,
            "fix_sql": self.fix_sql,
            "original_value": self.original_value,
            "corrected_value": self.corrected_value,
            "detection_details": self.detection_details
        }

@dataclass
class HealthReport:
    """System health report"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    overall_status: str = "healthy"
    corruption_issues: List[CorruptionIssue] = field(default_factory=list)
    system_metrics: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    @property
    def critical_issues(self) -> List[CorruptionIssue]:
        return [i for i in self.corruption_issues if i.severity == CorruptionSeverity.CRITICAL]
    
    @property
    def high_priority_issues(self) -> List[CorruptionIssue]:
        return [i for i in self.corruption_issues if i.severity in [CorruptionSeverity.HIGH, CorruptionSeverity.CRITICAL]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "overall_status": self.overall_status,
            "summary": {
                "total_issues": len(self.corruption_issues),
                "critical_issues": len(self.critical_issues),
                "high_priority_issues": len(self.high_priority_issues),
                "auto_fixable_issues": len([i for i in self.corruption_issues if i.auto_fixable])
            },
            "corruption_issues": [issue.to_dict() for issue in self.corruption_issues],
            "system_metrics": self.system_metrics,
            "recommendations": self.recommendations
        }

class CorruptionPrevention:
    """Main corruption prevention system"""
    
    def __init__(self, auto_fix: bool = False):
        self.auto_fix = auto_fix
        self.detection_patterns = self._load_corruption_patterns()
        self.health_report = HealthReport()
        
        # Configuration
        self.config = {
            "check_interval_seconds": int(os.getenv("CORRUPTION_CHECK_INTERVAL", "300")),  # 5 minutes
            "backup_validation_enabled": os.getenv("BACKUP_VALIDATION_ENABLED", "true").lower() == "true",
            "auto_fix_enabled": auto_fix,
            "max_auto_fixes_per_run": int(os.getenv("MAX_AUTO_FIXES", "5")),
            "alert_threshold_critical": int(os.getenv("CRITICAL_ALERT_THRESHOLD", "1")),
            "retention_days": int(os.getenv("HEALTH_REPORT_RETENTION_DAYS", "7"))
        }
        
        # Statistics
        self.stats = {
            "total_checks": 0,
            "issues_detected": 0,
            "issues_fixed": 0,
            "last_check": None,
            "uptime_start": datetime.utcnow()
        }
    
    def _load_corruption_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load known corruption patterns for detection"""
        return {
            "quote_corruption": [
                {"pattern": r"'''([^']+)'''", "description": "Triple quote corruption"},
                {"pattern": r"''''([^']+)''''", "description": "Quadruple quote corruption"},
                {"pattern": r"'UTC'\s*:\s*'UTC'", "description": "Duplicate UTC string"},
                {"pattern": r"'([^']*)':\s*'([^']*)'", "description": "Key-value quote duplication"}
            ],
            "sql_injection_patterns": [
                {"pattern": r";\s*(DROP|DELETE|UPDATE|INSERT)\s+", "description": "Potential SQL injection", "flags": re.IGNORECASE},
                {"pattern": r"UNION\s+SELECT", "description": "Union-based SQL injection", "flags": re.IGNORECASE},
                {"pattern": r"--\s*\w+", "description": "SQL comment injection"}
            ],
            "data_corruption": [
                {"pattern": r"\x00", "description": "Null byte in data"},
                {"pattern": r"[\x01-\x08\x0B-\x0C\x0E-\x1F]", "description": "Control characters in data"},
                {"pattern": r"�", "description": "Unicode replacement character (encoding issue)"}
            ]
        }
    
    async def run_comprehensive_check(self) -> HealthReport:
        """Run comprehensive corruption check"""
        logger.info("🔍 Starting comprehensive corruption prevention check...")
        
        self.health_report = HealthReport()
        self.stats["total_checks"] += 1
        self.stats["last_check"] = datetime.utcnow()
        
        try:
            # Step 1: Database connectivity and health
            await self._check_database_health()
            
            # Step 2: Schema integrity check
            await self._check_schema_integrity()
            
            # Step 3: Data corruption patterns
            await self._check_data_corruption_patterns()
            
            # Step 4: Quote corruption detection
            await self._check_quote_corruption()
            
            # Step 5: Backup integrity validation
            if self.config["backup_validation_enabled"]:
                await self._validate_backup_integrity()
            
            # Step 6: Connection pool health
            await self._check_connection_pool_health()
            
            # Step 7: Index and constraint integrity
            await self._check_index_integrity()
            
            # Step 8: Generate recommendations
            self._generate_recommendations()
            
            # Step 9: Apply auto-fixes if enabled
            if self.auto_fix:
                await self._apply_auto_fixes()
            
            # Step 10: Determine overall health status
            self._determine_overall_status()
            
        except Exception as e:
            logger.error(f"Corruption check failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.CONNECTION_POLLUTION,
                    severity=CorruptionSeverity.CRITICAL,
                    description=f"Corruption check failed: {str(e)}",
                    detection_details={"error": str(e)}
                )
            )
        
        # Update statistics
        self.stats["issues_detected"] += len(self.health_report.corruption_issues)
        
        logger.info(f"✅ Corruption check completed: {len(self.health_report.corruption_issues)} issues found")
        return self.health_report
    
    async def _check_database_health(self):
        """Check basic database health and connectivity"""
        try:
            health = await get_connection_health()
            
            connection_test = health.get("connection_test", {})
            if connection_test.get("status") != "healthy":
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.CONNECTION_POLLUTION,
                        severity=CorruptionSeverity.HIGH,
                        description="Database connection health check failed",
                        detection_details=connection_test
                    )
                )
            
            # Check pool health
            pool_status = health.get("pool_status", {})
            if "error" in pool_status:
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.CONNECTION_POLLUTION,
                        severity=CorruptionSeverity.MEDIUM,
                        description=f"Connection pool issue: {pool_status['error']}",
                        detection_details=pool_status
                    )
                )
            
            self.health_report.system_metrics["database_health"] = health
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.CONNECTION_POLLUTION,
                    severity=CorruptionSeverity.CRITICAL,
                    description=f"Database health check error: {str(e)}"
                )
            )
    
    async def _check_schema_integrity(self):
        """Check schema integrity using schema validator"""
        try:
            validator = SchemaValidator(dry_run=True)
            validation_report = await validator.validate_schema()
            
            # Convert validation issues to corruption issues
            for issue in validation_report.issues:
                if issue.severity == ValidationSeverity.CRITICAL:
                    severity = CorruptionSeverity.CRITICAL
                elif issue.severity == ValidationSeverity.ERROR:
                    severity = CorruptionSeverity.HIGH
                elif issue.severity == ValidationSeverity.WARNING:
                    severity = CorruptionSeverity.MEDIUM
                else:
                    severity = CorruptionSeverity.LOW
                
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.SCHEMA_DRIFT,
                        severity=severity,
                        description=issue.issue_description,
                        table_name=issue.table_name,
                        column_name=issue.column_name,
                        auto_fixable=issue.auto_fixable,
                        fix_sql=issue.fix_sql,
                        detection_details={
                            "validation_action": issue.action.value,
                            "model_definition": issue.model_definition,
                            "database_definition": issue.database_definition
                        }
                    )
                )
            
            self.health_report.system_metrics["schema_validation"] = {
                "total_issues": len(validation_report.issues),
                "critical_issues": validation_report.critical_issues_count,
                "error_issues": validation_report.error_issues_count,
                "warning_issues": validation_report.warning_issues_count
            }
            
        except Exception as e:
            logger.error(f"Schema integrity check failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.SCHEMA_DRIFT,
                    severity=CorruptionSeverity.HIGH,
                    description=f"Schema validation error: {str(e)}"
                )
            )
    
    async def _check_data_corruption_patterns(self):
        """Check for known data corruption patterns"""
        try:
            # Check critical tables for corruption patterns
            critical_tables = ["users", "migration_history"]
            
            async with get_db_session(DatabaseOperation.READ) as session:
                for table_name in critical_tables:
                    # Check if table exists
                    result = await session.execute(text(f"""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'public' 
                            AND table_name = :table_name
                        );
                    """), {"table_name": table_name})
                    
                    if not result.scalar():
                        continue
                    
                    # Sample data for corruption patterns
                    sample_result = await session.execute(text(f"""
                        SELECT * FROM "{table_name}" LIMIT 100;
                    """))
                    
                    for row in sample_result:
                        for column_name, value in zip(sample_result.keys(), row):
                            if value is None:
                                continue
                                
                            value_str = str(value)
                            
                            # Check against known corruption patterns
                            for pattern_type, patterns in self.detection_patterns.items():
                                for pattern_info in patterns:
                                    pattern = pattern_info["pattern"]
                                    flags = pattern_info.get("flags", 0)
                                    
                                    if re.search(pattern, value_str, flags):
                                        severity = CorruptionSeverity.HIGH if pattern_type == "sql_injection_patterns" else CorruptionSeverity.MEDIUM
                                        
                                        self.health_report.corruption_issues.append(
                                            CorruptionIssue(
                                                corruption_type=CorruptionType.DATA_TYPE_MISMATCH if pattern_type == "data_corruption" else CorruptionType.QUOTE_CORRUPTION,
                                                severity=severity,
                                                description=f"Detected {pattern_info['description']} in {table_name}.{column_name}",
                                                table_name=table_name,
                                                column_name=column_name,
                                                original_value=value_str[:100],  # Truncate for security
                                                detection_details={
                                                    "pattern_type": pattern_type,
                                                    "pattern": pattern,
                                                    "description": pattern_info["description"]
                                                }
                                            )
                                        )
                                        
                                        # Only report first match per value to avoid spam
                                        break
        
        except Exception as e:
            logger.error(f"Data corruption pattern check failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.DATA_TYPE_MISMATCH,
                    severity=CorruptionSeverity.MEDIUM,
                    description=f"Data corruption check error: {str(e)}"
                )
            )
    
    async def _check_quote_corruption(self):
        """Specific check for quote corruption issues"""
        try:
            async with get_db_session(DatabaseOperation.READ) as session:
                # Check for quote corruption in column defaults
                result = await session.execute(text("""
                    SELECT 
                        table_name,
                        column_name,
                        column_default
                    FROM information_schema.columns 
                    WHERE column_default IS NOT NULL
                    AND (
                        column_default LIKE '%''''%'
                        OR column_default LIKE '%\"\"\"%'
                        OR column_default ~ ''''{2,}'
                    );
                """))
                
                for row in result:
                    table_name, column_name, default_value = row
                    
                    # Analyze the corruption
                    corrupted_quotes = re.findall(r"'{3,}|'{2}", default_value)
                    if corrupted_quotes:
                        # Generate a fix
                        corrected_value = re.sub(r"'{3,}", "'", default_value)
                        fix_sql = f"ALTER TABLE \"{table_name}\" ALTER COLUMN \"{column_name}\" SET DEFAULT {corrected_value};"
                        
                        self.health_report.corruption_issues.append(
                            CorruptionIssue(
                                corruption_type=CorruptionType.QUOTE_CORRUPTION,
                                severity=CorruptionSeverity.HIGH,
                                description=f"Quote corruption detected in default value: {table_name}.{column_name}",
                                table_name=table_name,
                                column_name=column_name,
                                auto_fixable=True,
                                fix_sql=fix_sql,
                                original_value=default_value,
                                corrected_value=corrected_value,
                                detection_details={
                                    "corrupted_quotes": corrupted_quotes,
                                    "quote_count": len(corrupted_quotes)
                                }
                            )
                        )
        
        except Exception as e:
            logger.error(f"Quote corruption check failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.QUOTE_CORRUPTION,
                    severity=CorruptionSeverity.MEDIUM,
                    description=f"Quote corruption check error: {str(e)}"
                )
            )
    
    async def _validate_backup_integrity(self):
        """Validate backup file integrity"""
        try:
            backup_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'scripts', 'db-backup', 'backups')
            
            if not os.path.exists(backup_dir):
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.BACKUP_CORRUPTION,
                        severity=CorruptionSeverity.MEDIUM,
                        description="Backup directory not found",
                        detection_details={"backup_dir": backup_dir}
                    )
                )
                return
            
            backup_files = list(Path(backup_dir).glob("*.sql*"))
            
            if not backup_files:
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.BACKUP_CORRUPTION,
                        severity=CorruptionSeverity.MEDIUM,
                        description="No backup files found",
                        detection_details={"backup_dir": backup_dir}
                    )
                )
                return
            
            # Check most recent backup
            latest_backup = max(backup_files, key=lambda p: p.stat().st_mtime)
            
            # Basic integrity checks
            file_size = latest_backup.stat().st_size
            if file_size < 1024:  # Less than 1KB is suspicious
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.BACKUP_CORRUPTION,
                        severity=CorruptionSeverity.HIGH,
                        description=f"Backup file suspiciously small: {file_size} bytes",
                        detection_details={"file_path": str(latest_backup), "file_size": file_size}
                    )
                )
            
            # Check for corruption patterns in backup
            try:
                with open(latest_backup, 'r', encoding='utf-8') as f:
                    # Read first 10KB for pattern checking
                    sample_content = f.read(10240)
                    
                    # Check for quote corruption
                    if "''''" in sample_content:
                        self.health_report.corruption_issues.append(
                            CorruptionIssue(
                                corruption_type=CorruptionType.BACKUP_CORRUPTION,
                                severity=CorruptionSeverity.HIGH,
                                description=f"Quote corruption detected in backup file",
                                detection_details={"file_path": str(latest_backup)}
                            )
                        )
            except Exception as e:
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.BACKUP_CORRUPTION,
                        severity=CorruptionSeverity.MEDIUM,
                        description=f"Could not validate backup content: {str(e)}",
                        detection_details={"file_path": str(latest_backup), "error": str(e)}
                    )
                )
            
            self.health_report.system_metrics["backup_validation"] = {
                "backup_count": len(backup_files),
                "latest_backup": str(latest_backup),
                "latest_backup_size": file_size,
                "latest_backup_age_hours": (datetime.utcnow() - datetime.fromtimestamp(latest_backup.stat().st_mtime)).total_seconds() / 3600
            }
        
        except Exception as e:
            logger.error(f"Backup validation failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.BACKUP_CORRUPTION,
                    severity=CorruptionSeverity.MEDIUM,
                    description=f"Backup validation error: {str(e)}"
                )
            )
    
    async def _check_connection_pool_health(self):
        """Check connection pool for pollution or issues"""
        try:
            health = await get_connection_health()
            pool_status = health.get("pool_status", {})
            
            # Check for high usage
            usage_percent = pool_status.get("usage_percent", 0)
            if usage_percent > 90:
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.CONNECTION_POLLUTION,
                        severity=CorruptionSeverity.HIGH,
                        description=f"Connection pool usage critically high: {usage_percent}%",
                        detection_details=pool_status
                    )
                )
            elif usage_percent > 75:
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.CONNECTION_POLLUTION,
                        severity=CorruptionSeverity.MEDIUM,
                        description=f"Connection pool usage high: {usage_percent}%",
                        detection_details=pool_status
                    )
                )
            
            # Check for connection errors
            metrics = health.get("connection_test", {}).get("metrics", {})
            recent_errors = metrics.get("recent_errors", 0)
            if recent_errors > 5:
                self.health_report.corruption_issues.append(
                    CorruptionIssue(
                        corruption_type=CorruptionType.CONNECTION_POLLUTION,
                        severity=CorruptionSeverity.HIGH,
                        description=f"High number of recent connection errors: {recent_errors}",
                        detection_details={"metrics": metrics}
                    )
                )
        
        except Exception as e:
            logger.error(f"Connection pool health check failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.CONNECTION_POLLUTION,
                    severity=CorruptionSeverity.MEDIUM,
                    description=f"Connection pool check error: {str(e)}"
                )
            )
    
    async def _check_index_integrity(self):
        """Check database indexes and constraints for corruption"""
        try:
            async with get_db_session(DatabaseOperation.READ) as session:
                # Check for invalid indexes
                result = await session.execute(text("""
                    SELECT 
                        schemaname,
                        tablename,
                        indexname,
                        indexdef
                    FROM pg_indexes 
                    WHERE schemaname = 'public'
                    AND indexdef IS NULL;
                """))
                
                for row in result:
                    self.health_report.corruption_issues.append(
                        CorruptionIssue(
                            corruption_type=CorruptionType.INDEX_CORRUPTION,
                            severity=CorruptionSeverity.MEDIUM,
                            description=f"Invalid index detected: {row[2]} on table {row[1]}",
                            table_name=row[1],
                            detection_details={"index_name": row[2], "schema": row[0]}
                        )
                    )
                
                # Check for foreign key constraint violations
                # This is a more complex check that would need table-specific logic
                # For now, we'll do a basic check for constraint violations
                
                # Check constraint status
                constraint_result = await session.execute(text("""
                    SELECT 
                        conname,
                        conrelid::regclass AS table_name,
                        confrelid::regclass AS referenced_table,
                        contype
                    FROM pg_constraint 
                    WHERE contype = 'f'
                    AND NOT convalidated;
                """))
                
                for row in constraint_result:
                    self.health_report.corruption_issues.append(
                        CorruptionIssue(
                            corruption_type=CorruptionType.FOREIGN_KEY_VIOLATION,
                            severity=CorruptionSeverity.HIGH,
                            description=f"Unvalidated foreign key constraint: {row[0]}",
                            table_name=str(row[1]),
                            detection_details={
                                "constraint_name": row[0],
                                "referenced_table": str(row[2]),
                                "constraint_type": row[3]
                            }
                        )
                    )
        
        except Exception as e:
            logger.error(f"Index integrity check failed: {e}")
            self.health_report.corruption_issues.append(
                CorruptionIssue(
                    corruption_type=CorruptionType.INDEX_CORRUPTION,
                    severity=CorruptionSeverity.MEDIUM,
                    description=f"Index integrity check error: {str(e)}"
                )
            )
    
    def _generate_recommendations(self):
        """Generate recommendations based on detected issues"""
        self.health_report.recommendations = []
        
        if self.health_report.critical_issues:
            self.health_report.recommendations.append(
                "CRITICAL: Immediate action required - critical corruption issues detected"
            )
        
        quote_issues = [i for i in self.health_report.corruption_issues if i.corruption_type == CorruptionType.QUOTE_CORRUPTION]
        if quote_issues:
            fixable_count = len([i for i in quote_issues if i.auto_fixable])
            self.health_report.recommendations.append(
                f"Fix {fixable_count} quote corruption issues by enabling auto-fix or running manual SQL fixes"
            )
        
        schema_issues = [i for i in self.health_report.corruption_issues if i.corruption_type == CorruptionType.SCHEMA_DRIFT]
        if schema_issues:
            self.health_report.recommendations.append(
                f"Run schema migration to fix {len(schema_issues)} schema drift issues"
            )
        
        backup_issues = [i for i in self.health_report.corruption_issues if i.corruption_type == CorruptionType.BACKUP_CORRUPTION]
        if backup_issues:
            self.health_report.recommendations.append(
                "Review and regenerate database backups to ensure integrity"
            )
        
        connection_issues = [i for i in self.health_report.corruption_issues if i.corruption_type == CorruptionType.CONNECTION_POLLUTION]
        if connection_issues:
            self.health_report.recommendations.append(
                "Monitor and optimize database connection pool settings"
            )
    
    async def _apply_auto_fixes(self):
        """Apply automatic fixes for detected issues"""
        if not self.auto_fix:
            return
        
        auto_fixable_issues = [i for i in self.health_report.corruption_issues if i.auto_fixable and i.fix_sql]
        
        if not auto_fixable_issues:
            logger.info("No auto-fixable corruption issues found")
            return
        
        # Limit the number of fixes per run
        issues_to_fix = auto_fixable_issues[:self.config["max_auto_fixes_per_run"]]
        
        logger.info(f"🔧 Applying {len(issues_to_fix)} auto-fixes...")
        
        fixed_count = 0
        
        async with get_db_session(DatabaseOperation.ADMIN) as session:
            for issue in issues_to_fix:
                try:
                    logger.info(f"Applying fix for {issue.table_name}.{issue.column_name}: {issue.corruption_type.value}")
                    await session.execute(text(issue.fix_sql))
                    fixed_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to apply auto-fix: {e}")
                    # Remove auto-fixable flag if fix failed
                    issue.auto_fixable = False
            
            await session.commit()
        
        self.stats["issues_fixed"] += fixed_count
        logger.info(f"✅ Applied {fixed_count} auto-fixes successfully")
    
    def _determine_overall_status(self):
        """Determine overall system health status"""
        if self.health_report.critical_issues:
            self.health_report.overall_status = "critical"
        elif len(self.health_report.high_priority_issues) > 0:
            self.health_report.overall_status = "degraded"
        elif len(self.health_report.corruption_issues) > 0:
            self.health_report.overall_status = "warning"
        else:
            self.health_report.overall_status = "healthy"
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics"""
        uptime_hours = (datetime.utcnow() - self.stats["uptime_start"]).total_seconds() / 3600
        
        return {
            "status": self.health_report.overall_status,
            "last_check": self.stats["last_check"].isoformat() if self.stats["last_check"] else None,
            "statistics": {
                "uptime_hours": round(uptime_hours, 2),
                "total_checks": self.stats["total_checks"],
                "issues_detected": self.stats["issues_detected"],
                "issues_fixed": self.stats["issues_fixed"],
                "fix_success_rate": (self.stats["issues_fixed"] / max(self.stats["issues_detected"], 1)) * 100
            },
            "configuration": self.config,
            "recent_issues": len(self.health_report.corruption_issues),
            "critical_issues": len(self.health_report.critical_issues),
            "recommendations": self.health_report.recommendations
        }
    
    async def save_health_report(self, file_path: Optional[str] = None) -> str:
        """Save health report to file"""
        if file_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            file_path = f"/tmp/devsecurex_health_report_{timestamp}.json"
        
        with open(file_path, 'w') as f:
            json.dump(self.health_report.to_dict(), f, indent=2, default=str)
        
        logger.info(f"📄 Health report saved: {file_path}")
        return file_path

# Global corruption prevention instance
_corruption_prevention: Optional[CorruptionPrevention] = None

def get_corruption_prevention(auto_fix: bool = False) -> CorruptionPrevention:
    """Get global corruption prevention instance"""
    global _corruption_prevention
    
    if _corruption_prevention is None:
        _corruption_prevention = CorruptionPrevention(auto_fix=auto_fix)
    
    return _corruption_prevention

async def run_corruption_check(auto_fix: bool = False) -> HealthReport:
    """Run corruption prevention check"""
    prevention = get_corruption_prevention(auto_fix=auto_fix)
    return await prevention.run_comprehensive_check()

async def get_system_status() -> Dict[str, Any]:
    """Get current system status"""
    prevention = get_corruption_prevention()
    return prevention.get_system_status()

async def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX Corruption Prevention System")
    parser.add_argument("--auto-fix", action="store_true", help="Enable automatic fixes")
    parser.add_argument("--output", "-o", help="Output file for health report")
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    try:
        if args.status:
            # Show system status
            status = await get_system_status()
            print("\n🔍 Corruption Prevention System Status")
            print("=" * 50)
            print(f"Overall Status: {status['status']}")
            print(f"Uptime: {status['statistics']['uptime_hours']:.2f} hours")
            print(f"Total Checks: {status['statistics']['total_checks']}")
            print(f"Issues Detected: {status['statistics']['issues_detected']}")
            print(f"Issues Fixed: {status['statistics']['issues_fixed']}")
            print(f"Recent Issues: {status['recent_issues']}")
            print(f"Critical Issues: {status['critical_issues']}")
            
            if status['recommendations']:
                print(f"\n📋 Recommendations:")
                for rec in status['recommendations']:
                    print(f"  • {rec}")
        else:
            # Run comprehensive check
            report = await run_corruption_check(auto_fix=args.auto_fix)
            
            print(f"\n🔍 Corruption Prevention Report")
            print("=" * 50)
            print(f"Overall Status: {report.overall_status}")
            print(f"Total Issues: {len(report.corruption_issues)}")
            print(f"Critical Issues: {len(report.critical_issues)}")
            print(f"Auto-fixable Issues: {len([i for i in report.corruption_issues if i.auto_fixable])}")
            
            if report.corruption_issues:
                print(f"\n📋 Issues Found:")
                for i, issue in enumerate(report.corruption_issues[:10], 1):  # Show first 10
                    severity_emoji = {
                        CorruptionSeverity.CRITICAL: "🔴",
                        CorruptionSeverity.HIGH: "🟡",
                        CorruptionSeverity.MEDIUM: "⚠️",
                        CorruptionSeverity.LOW: "ℹ️"
                    }[issue.severity]
                    
                    print(f"  {i:2d}. {severity_emoji} [{issue.corruption_type.value}] {issue.description}")
                    if issue.table_name:
                        print(f"      Table: {issue.table_name}.{issue.column_name or 'N/A'}")
                    if issue.auto_fixable:
                        print(f"      🔧 Auto-fixable")
                
                if len(report.corruption_issues) > 10:
                    print(f"  ... and {len(report.corruption_issues) - 10} more issues")
            
            # Save report if requested
            if args.output:
                prevention = get_corruption_prevention()
                await prevention.save_health_report(args.output)
                print(f"📄 Report saved to: {args.output}")
        
        sys.exit(0 if report.overall_status in ['healthy', 'warning'] else 1)
        
    except Exception as e:
        logger.error(f"Corruption prevention system failed: {e}")
        sys.exit(2)

if __name__ == "__main__":
    asyncio.run(main())