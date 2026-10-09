#!/usr/bin/env python3
"""
DevSecureX Schema Validator

Advanced database schema validation system that compares SQLAlchemy models
against the actual database schema and provides automated fixing capabilities.

This module prevents schema corruption issues by:
1. Detecting mismatches between models and database
2. Auto-fixing common schema issues
3. Providing detailed validation reports
4. Ensuring consistent schema across deployments

Created: 2025-09-03
"""

import asyncio
import logging
import sys
import os
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path

from sqlalchemy import text, inspect, MetaData, Table, Column
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.schema import CreateTable
from sqlalchemy.types import TypeEngine
from sqlalchemy.sql.sqltypes import String, Integer, Boolean, DateTime, Text, BigInteger, Float
from sqlalchemy.dialects import postgresql

# Import all models to ensure they're registered
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from core.database import engine, Base, get_db_session, DatabaseOperation
    from core.config import get_database_url
    
    # Import all model modules to ensure they're registered with Base
    from auth import models as auth_models
    from repos import models as repos_models
    from scans import models as scans_models
    from ai_assistant import models as ai_models
    from support import models as support_models
    from custom_rules import models as custom_rules_models
    from analytics import models as analytics_models
    from cli_scan import models as cli_models
except ImportError as e:
    logging.error(f"Failed to import required modules: {e}")
    sys.exit(1)

# Configure logging
logger = logging.getLogger(__name__)

class ValidationSeverity(Enum):
    """Validation issue severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class ValidationAction(Enum):
    """Available validation actions"""
    ADD_COLUMN = "add_column"
    DROP_COLUMN = "drop_column"
    ALTER_COLUMN = "alter_column"
    CREATE_TABLE = "create_table"
    DROP_TABLE = "drop_table"
    ADD_INDEX = "add_index"
    DROP_INDEX = "drop_index"
    ADD_CONSTRAINT = "add_constraint"
    DROP_CONSTRAINT = "drop_constraint"
    UPDATE_DEFAULT = "update_default"
    FIX_DATA_TYPE = "fix_data_type"

@dataclass
class ValidationIssue:
    """Represents a schema validation issue"""
    severity: ValidationSeverity
    action: ValidationAction
    table_name: str
    column_name: Optional[str] = None
    issue_description: str = ""
    fix_sql: Optional[str] = None
    model_definition: Optional[str] = None
    database_definition: Optional[str] = None
    auto_fixable: bool = False
    requires_data_migration: bool = False
    estimated_risk: str = "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "severity": self.severity.value,
            "action": self.action.value,
            "table_name": self.table_name,
            "column_name": self.column_name,
            "issue_description": self.issue_description,
            "fix_sql": self.fix_sql,
            "model_definition": self.model_definition,
            "database_definition": self.database_definition,
            "auto_fixable": self.auto_fixable,
            "requires_data_migration": self.requires_data_migration,
            "estimated_risk": self.estimated_risk
        }

@dataclass
class ValidationReport:
    """Complete schema validation report"""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    total_tables_checked: int = 0
    total_columns_checked: int = 0
    issues: List[ValidationIssue] = field(default_factory=list)
    database_info: Dict[str, Any] = field(default_factory=dict)
    model_info: Dict[str, Any] = field(default_factory=dict)
    validation_config: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def critical_issues_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.CRITICAL])
    
    @property
    def error_issues_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.ERROR])
    
    @property
    def warning_issues_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.WARNING])
    
    @property
    def auto_fixable_issues(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.auto_fixable]
    
    @property
    def manual_fix_required_issues(self) -> List[ValidationIssue]:
        return [i for i in self.issues if not i.auto_fixable]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total_tables_checked": self.total_tables_checked,
                "total_columns_checked": self.total_columns_checked,
                "total_issues": len(self.issues),
                "critical_issues": self.critical_issues_count,
                "error_issues": self.error_issues_count,
                "warning_issues": self.warning_issues_count,
                "auto_fixable_issues": len(self.auto_fixable_issues),
                "manual_fix_required": len(self.manual_fix_required_issues)
            },
            "issues": [issue.to_dict() for issue in self.issues],
            "database_info": self.database_info,
            "model_info": self.model_info,
            "validation_config": self.validation_config
        }
    
    def save_to_file(self, file_path: str):
        """Save validation report to JSON file"""
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

class SchemaValidator:
    """Advanced schema validation system"""
    
    def __init__(self, auto_fix: bool = False, dry_run: bool = True):
        self.auto_fix = auto_fix
        self.dry_run = dry_run
        self.engine = engine
        self.validation_report = ValidationReport()
        self.type_mapping = self._create_type_mapping()
        
        # Configuration
        self.validation_config = {
            "check_missing_tables": True,
            "check_extra_tables": True,
            "check_missing_columns": True,
            "check_extra_columns": True,
            "check_column_types": True,
            "check_column_defaults": True,
            "check_nullable_constraints": True,
            "check_indexes": True,
            "check_foreign_keys": True,
            "check_unique_constraints": True,
            "ignore_tables": set(['alembic_version', 'migration_history']),
            "ignore_columns": set(['created_at', 'updated_at']),  # Skip auto-managed columns
        }
    
    def _create_type_mapping(self) -> Dict[str, Set[str]]:
        """Create mapping of compatible SQL types"""
        return {
            'integer': {'integer', 'int4', 'int', 'bigint', 'int8'},
            'bigint': {'bigint', 'int8', 'integer', 'int4'},
            'varchar': {'varchar', 'character varying', 'text', 'string'},
            'text': {'text', 'varchar', 'character varying', 'string'},
            'boolean': {'boolean', 'bool'},
            'timestamp': {'timestamp', 'timestamp with time zone', 'datetime'},
            'datetime': {'datetime', 'timestamp', 'timestamp with time zone'},
            'numeric': {'numeric', 'decimal', 'money'},
            'float': {'float', 'real', 'double precision'},
        }
    
    def _normalize_type_name(self, type_name: str) -> str:
        """Normalize database type names for comparison"""
        type_name = type_name.lower().strip()
        
        # Handle PostgreSQL-specific type names
        if 'character varying' in type_name:
            return 'varchar'
        elif 'timestamp with time zone' in type_name:
            return 'timestamp'
        elif type_name in ['int4', 'integer']:
            return 'integer'
        elif type_name in ['int8', 'bigint']:
            return 'bigint'
        elif type_name == 'bool':
            return 'boolean'
        
        return type_name
    
    def _types_are_compatible(self, model_type: str, db_type: str) -> bool:
        """Check if model and database types are compatible"""
        model_type = self._normalize_type_name(str(model_type))
        db_type = self._normalize_type_name(db_type)
        
        if model_type == db_type:
            return True
        
        # Check type compatibility mapping
        for base_type, compatible_types in self.type_mapping.items():
            if model_type in compatible_types and db_type in compatible_types:
                return True
        
        return False
    
    async def validate_schema(self) -> ValidationReport:
        """Perform comprehensive schema validation"""
        logger.info("Starting comprehensive schema validation...")
        
        self.validation_report.validation_config = self.validation_config.copy()
        self.validation_report.validation_config['ignore_tables'] = list(self.validation_config['ignore_tables'])
        self.validation_report.validation_config['ignore_columns'] = list(self.validation_config['ignore_columns'])
        
        try:
            # Get database schema information
            db_schema = await self._get_database_schema()
            model_schema = self._get_model_schema()
            
            self.validation_report.database_info = {
                "total_tables": len(db_schema),
                "table_names": list(db_schema.keys())
            }
            
            self.validation_report.model_info = {
                "total_tables": len(model_schema),
                "table_names": list(model_schema.keys())
            }
            
            # Perform validation checks
            await self._validate_tables(model_schema, db_schema)
            
            # Calculate totals
            self.validation_report.total_tables_checked = max(len(model_schema), len(db_schema))
            self.validation_report.total_columns_checked = sum(
                len(table_info.get('columns', {})) for table_info in db_schema.values()
            )
            
            logger.info(f"Schema validation completed: {len(self.validation_report.issues)} issues found")
            
        except Exception as e:
            logger.error(f"Schema validation failed: {e}")
            critical_issue = ValidationIssue(
                severity=ValidationSeverity.CRITICAL,
                action=ValidationAction.CREATE_TABLE,  # Placeholder
                table_name="VALIDATION_ERROR",
                issue_description=f"Schema validation failed: {str(e)}",
                auto_fixable=False,
                estimated_risk="high"
            )
            self.validation_report.issues.append(critical_issue)
        
        return self.validation_report
    
    async def _get_database_schema(self) -> Dict[str, Any]:
        """Get current database schema information"""
        logger.info("Retrieving database schema...")
        
        schema_info = {}
        
        async with self.engine.connect() as conn:
            inspector = inspect(conn.sync_connection)
            
            # Get all table names
            table_names = inspector.get_table_names()
            
            for table_name in table_names:
                if table_name in self.validation_config['ignore_tables']:
                    continue
                
                table_info = {
                    'columns': {},
                    'indexes': [],
                    'foreign_keys': [],
                    'constraints': []
                }
                
                # Get column information
                columns = inspector.get_columns(table_name)
                for column in columns:
                    column_info = {
                        'type': str(column['type']),
                        'nullable': column['nullable'],
                        'default': column['default'],
                        'primary_key': column.get('primary_key', False),
                        'autoincrement': column.get('autoincrement', False)
                    }
                    table_info['columns'][column['name']] = column_info
                
                # Get indexes
                try:
                    indexes = inspector.get_indexes(table_name)
                    table_info['indexes'] = [
                        {
                            'name': idx['name'],
                            'columns': idx['column_names'],
                            'unique': idx['unique']
                        }
                        for idx in indexes
                    ]
                except Exception as e:
                    logger.warning(f"Failed to get indexes for {table_name}: {e}")
                
                # Get foreign keys
                try:
                    foreign_keys = inspector.get_foreign_keys(table_name)
                    table_info['foreign_keys'] = [
                        {
                            'name': fk.get('name', ''),
                            'constrained_columns': fk['constrained_columns'],
                            'referred_table': fk['referred_table'],
                            'referred_columns': fk['referred_columns']
                        }
                        for fk in foreign_keys
                    ]
                except Exception as e:
                    logger.warning(f"Failed to get foreign keys for {table_name}: {e}")
                
                schema_info[table_name] = table_info
        
        return schema_info
    
    def _get_model_schema(self) -> Dict[str, Any]:
        """Get SQLAlchemy model schema information"""
        logger.info("Retrieving SQLAlchemy model schema...")
        
        model_schema = {}
        
        for table_name, table in Base.metadata.tables.items():
            if table_name in self.validation_config['ignore_tables']:
                continue
            
            table_info = {
                'columns': {},
                'indexes': [],
                'foreign_keys': [],
                'constraints': []
            }
            
            # Get column information
            for column in table.columns:
                column_info = {
                    'type': str(column.type),
                    'nullable': column.nullable,
                    'default': str(column.default) if column.default else None,
                    'primary_key': column.primary_key,
                    'autoincrement': getattr(column, 'autoincrement', False)
                }
                table_info['columns'][column.name] = column_info
            
            # Get indexes
            for index in table.indexes:
                index_info = {
                    'name': index.name,
                    'columns': [col.name for col in index.columns],
                    'unique': index.unique
                }
                table_info['indexes'].append(index_info)
            
            # Get foreign keys
            for fk in table.foreign_keys:
                fk_info = {
                    'name': fk.constraint.name if fk.constraint else '',
                    'constrained_columns': [fk.parent.name],
                    'referred_table': fk.column.table.name,
                    'referred_columns': [fk.column.name]
                }
                table_info['foreign_keys'].append(fk_info)
            
            model_schema[table_name] = table_info
        
        return model_schema
    
    async def _validate_tables(self, model_schema: Dict[str, Any], db_schema: Dict[str, Any]):
        """Validate table-level differences"""
        
        model_tables = set(model_schema.keys())
        db_tables = set(db_schema.keys())
        
        # Check for missing tables (in model but not in database)
        if self.validation_config['check_missing_tables']:
            missing_tables = model_tables - db_tables
            for table_name in missing_tables:
                issue = ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    action=ValidationAction.CREATE_TABLE,
                    table_name=table_name,
                    issue_description=f"Table '{table_name}' exists in models but not in database",
                    fix_sql=self._generate_create_table_sql(table_name, model_schema[table_name]),
                    auto_fixable=True,
                    estimated_risk="medium"
                )
                self.validation_report.issues.append(issue)
        
        # Check for extra tables (in database but not in model)
        if self.validation_config['check_extra_tables']:
            extra_tables = db_tables - model_tables
            for table_name in extra_tables:
                issue = ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    action=ValidationAction.DROP_TABLE,
                    table_name=table_name,
                    issue_description=f"Table '{table_name}' exists in database but not in models",
                    fix_sql=f"DROP TABLE IF EXISTS \"{table_name}\";",
                    auto_fixable=False,  # Dropping tables requires manual confirmation
                    estimated_risk="high"
                )
                self.validation_report.issues.append(issue)
        
        # Validate columns for common tables
        common_tables = model_tables & db_tables
        for table_name in common_tables:
            await self._validate_table_columns(table_name, model_schema[table_name], db_schema[table_name])
    
    async def _validate_table_columns(self, table_name: str, model_table: Dict[str, Any], db_table: Dict[str, Any]):
        """Validate column-level differences for a specific table"""
        
        model_columns = set(model_table['columns'].keys())
        db_columns = set(db_table['columns'].keys())
        
        # Check for missing columns (in model but not in database)
        if self.validation_config['check_missing_columns']:
            missing_columns = model_columns - db_columns
            for column_name in missing_columns:
                if column_name in self.validation_config['ignore_columns']:
                    continue
                
                column_info = model_table['columns'][column_name]
                issue = ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    action=ValidationAction.ADD_COLUMN,
                    table_name=table_name,
                    column_name=column_name,
                    issue_description=f"Column '{column_name}' exists in model but not in database",
                    fix_sql=self._generate_add_column_sql(table_name, column_name, column_info),
                    model_definition=str(column_info),
                    auto_fixable=True,
                    estimated_risk="medium"
                )
                self.validation_report.issues.append(issue)
        
        # Check for extra columns (in database but not in model)
        if self.validation_config['check_extra_columns']:
            extra_columns = db_columns - model_columns
            for column_name in extra_columns:
                if column_name in self.validation_config['ignore_columns']:
                    continue
                
                column_info = db_table['columns'][column_name]
                issue = ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    action=ValidationAction.DROP_COLUMN,
                    table_name=table_name,
                    column_name=column_name,
                    issue_description=f"Column '{column_name}' exists in database but not in model",
                    fix_sql=f"ALTER TABLE \"{table_name}\" DROP COLUMN IF EXISTS \"{column_name}\";",
                    database_definition=str(column_info),
                    auto_fixable=False,  # Dropping columns requires manual confirmation
                    estimated_risk="high"
                )
                self.validation_report.issues.append(issue)
        
        # Validate common columns
        common_columns = model_columns & db_columns
        for column_name in common_columns:
            if column_name in self.validation_config['ignore_columns']:
                continue
            
            model_column = model_table['columns'][column_name]
            db_column = db_table['columns'][column_name]
            
            await self._validate_column_properties(table_name, column_name, model_column, db_column)
    
    async def _validate_column_properties(self, table_name: str, column_name: str, 
                                        model_column: Dict[str, Any], db_column: Dict[str, Any]):
        """Validate individual column properties"""
        
        # Check data types
        if self.validation_config['check_column_types']:
            if not self._types_are_compatible(model_column['type'], db_column['type']):
                issue = ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    action=ValidationAction.ALTER_COLUMN,
                    table_name=table_name,
                    column_name=column_name,
                    issue_description=f"Column type mismatch: model='{model_column['type']}', db='{db_column['type']}'",
                    fix_sql=self._generate_alter_column_type_sql(table_name, column_name, model_column['type']),
                    model_definition=f"type: {model_column['type']}",
                    database_definition=f"type: {db_column['type']}",
                    auto_fixable=False,  # Type changes can be risky
                    requires_data_migration=True,
                    estimated_risk="high"
                )
                self.validation_report.issues.append(issue)
        
        # Check nullable constraints
        if self.validation_config['check_nullable_constraints']:
            if model_column['nullable'] != db_column['nullable']:
                severity = ValidationSeverity.WARNING if db_column['nullable'] and not model_column['nullable'] else ValidationSeverity.ERROR
                
                issue = ValidationIssue(
                    severity=severity,
                    action=ValidationAction.ALTER_COLUMN,
                    table_name=table_name,
                    column_name=column_name,
                    issue_description=f"Nullable constraint mismatch: model='{model_column['nullable']}', db='{db_column['nullable']}'",
                    fix_sql=self._generate_alter_nullable_sql(table_name, column_name, model_column['nullable']),
                    model_definition=f"nullable: {model_column['nullable']}",
                    database_definition=f"nullable: {db_column['nullable']}",
                    auto_fixable=not (not db_column['nullable'] and model_column['nullable']),  # Can't easily make non-null column nullable
                    requires_data_migration=not db_column['nullable'] and model_column['nullable'],
                    estimated_risk="medium"
                )
                self.validation_report.issues.append(issue)
        
        # Check defaults (this is where the quote corruption typically happens)
        if self.validation_config['check_column_defaults']:
            model_default = self._normalize_default_value(model_column.get('default'))
            db_default = self._normalize_default_value(db_column.get('default'))
            
            if model_default != db_default:
                # Special handling for common quote corruption issues
                is_quote_corruption = self._detect_quote_corruption(model_default, db_default)
                severity = ValidationSeverity.CRITICAL if is_quote_corruption else ValidationSeverity.WARNING
                
                issue = ValidationIssue(
                    severity=severity,
                    action=ValidationAction.UPDATE_DEFAULT,
                    table_name=table_name,
                    column_name=column_name,
                    issue_description=f"Default value mismatch{' (quote corruption detected)' if is_quote_corruption else ''}: model='{model_default}', db='{db_default}'",
                    fix_sql=self._generate_alter_default_sql(table_name, column_name, model_default),
                    model_definition=f"default: {model_default}",
                    database_definition=f"default: {db_default}",
                    auto_fixable=True,
                    estimated_risk="low" if not is_quote_corruption else "medium"
                )
                self.validation_report.issues.append(issue)
    
    def _normalize_default_value(self, default_value: Any) -> Optional[str]:
        """Normalize default values for comparison"""
        if default_value is None:
            return None
        
        default_str = str(default_value).strip()
        
        # Remove common PostgreSQL function wrappers
        if default_str.startswith('nextval('):
            return 'nextval(...)'  # Normalize sequence defaults
        
        # Handle timezone function
        if 'now()' in default_str.lower():
            return 'now()'
        
        # Remove extra quotes
        default_str = default_str.strip("'\"")
        
        # Handle boolean values
        if default_str.lower() in ['true', 'false']:
            return default_str.lower()
        
        return default_str
    
    def _detect_quote_corruption(self, model_default: Optional[str], db_default: Optional[str]) -> bool:
        """Detect quote corruption issues like 'UTC' becoming '''UTC'''"""
        if not model_default or not db_default:
            return False
        
        # Check for multiple quotes
        if db_default.count("'") > 2 and model_default.count("'") <= 2:
            return True
        
        # Check for specific patterns
        corrupted_patterns = ["'''", '"""', "''''"]
        return any(pattern in db_default for pattern in corrupted_patterns)
    
    def _generate_create_table_sql(self, table_name: str, table_info: Dict[str, Any]) -> str:
        """Generate CREATE TABLE SQL from model information"""
        try:
            table = Base.metadata.tables[table_name]
            create_sql = str(CreateTable(table).compile(dialect=postgresql.dialect()))
            return create_sql + ";"
        except Exception as e:
            logger.warning(f"Failed to generate CREATE TABLE SQL for {table_name}: {e}")
            return f"-- CREATE TABLE \"{table_name}\" (...); -- Generation failed: {e}"
    
    def _generate_add_column_sql(self, table_name: str, column_name: str, column_info: Dict[str, Any]) -> str:
        """Generate ADD COLUMN SQL"""
        column_type = column_info['type']
        nullable = "NULL" if column_info['nullable'] else "NOT NULL"
        default_clause = ""
        
        if column_info['default']:
            default_value = column_info['default']
            # Handle different default value types
            if 'now()' in str(default_value).lower():
                default_clause = " DEFAULT now()"
            elif str(default_value).lower() in ['true', 'false']:
                default_clause = f" DEFAULT {str(default_value).upper()}"
            else:
                default_clause = f" DEFAULT '{default_value}'"
        
        return f"ALTER TABLE \"{table_name}\" ADD COLUMN \"{column_name}\" {column_type} {nullable}{default_clause};"
    
    def _generate_alter_column_type_sql(self, table_name: str, column_name: str, new_type: str) -> str:
        """Generate ALTER COLUMN TYPE SQL"""
        return f"ALTER TABLE \"{table_name}\" ALTER COLUMN \"{column_name}\" TYPE {new_type};"
    
    def _generate_alter_nullable_sql(self, table_name: str, column_name: str, nullable: bool) -> str:
        """Generate ALTER COLUMN nullable constraint SQL"""
        constraint = "DROP NOT NULL" if nullable else "SET NOT NULL"
        return f"ALTER TABLE \"{table_name}\" ALTER COLUMN \"{column_name}\" {constraint};"
    
    def _generate_alter_default_sql(self, table_name: str, column_name: str, default_value: Optional[str]) -> str:
        """Generate ALTER COLUMN DEFAULT SQL"""
        if default_value is None:
            return f"ALTER TABLE \"{table_name}\" ALTER COLUMN \"{column_name}\" DROP DEFAULT;"
        
        # Handle different default value types
        if 'now()' in str(default_value).lower():
            default_clause = "now()"
        elif str(default_value).lower() in ['true', 'false']:
            default_clause = str(default_value).upper()
        else:
            default_clause = f"'{default_value}'"
        
        return f"ALTER TABLE \"{table_name}\" ALTER COLUMN \"{column_name}\" SET DEFAULT {default_clause};"
    
    async def apply_fixes(self, issues: List[ValidationIssue] = None) -> Dict[str, Any]:
        """Apply auto-fixable validation issues"""
        if issues is None:
            issues = self.validation_report.auto_fixable_issues
        
        if not issues:
            logger.info("No auto-fixable issues found")
            return {"applied": 0, "failed": 0, "skipped": 0}
        
        if self.dry_run:
            logger.info(f"DRY RUN: Would apply {len(issues)} fixes")
            return {"dry_run": True, "would_apply": len(issues)}
        
        applied_count = 0
        failed_count = 0
        skipped_count = 0
        
        async with get_db_session(DatabaseOperation.ADMIN) as session:
            for issue in issues:
                if not issue.auto_fixable or not issue.fix_sql:
                    skipped_count += 1
                    continue
                
                try:
                    logger.info(f"Applying fix for {issue.table_name}.{issue.column_name or 'TABLE'}: {issue.action.value}")
                    logger.debug(f"SQL: {issue.fix_sql}")
                    
                    await session.execute(text(issue.fix_sql))
                    applied_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to apply fix for {issue.table_name}: {e}")
                    failed_count += 1
            
            await session.commit()
        
        logger.info(f"Applied {applied_count} fixes, {failed_count} failed, {skipped_count} skipped")
        return {"applied": applied_count, "failed": failed_count, "skipped": skipped_count}
    
    def generate_migration_script(self, output_file: str = None) -> str:
        """Generate a migration script from validation issues"""
        if output_file is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = f"/tmp/schema_validation_migration_{timestamp}.sql"
        
        migration_content = [
            "-- DevSecureX Schema Validation Migration Script",
            f"-- Generated: {datetime.utcnow().isoformat()}",
            f"-- Total Issues: {len(self.validation_report.issues)}",
            f"-- Auto-fixable: {len(self.validation_report.auto_fixable_issues)}",
            "",
            "BEGIN;",
            ""
        ]
        
        # Group fixes by severity
        for severity in [ValidationSeverity.CRITICAL, ValidationSeverity.ERROR, ValidationSeverity.WARNING]:
            severity_issues = [i for i in self.validation_report.issues if i.severity == severity and i.fix_sql]
            
            if severity_issues:
                migration_content.extend([
                    f"-- {severity.value.upper()} SEVERITY FIXES",
                    f"-- Count: {len(severity_issues)}",
                    ""
                ])
                
                for issue in severity_issues:
                    migration_content.extend([
                        f"-- Fix: {issue.issue_description}",
                        f"-- Table: {issue.table_name}" + (f", Column: {issue.column_name}" if issue.column_name else ""),
                        f"-- Risk Level: {issue.estimated_risk}",
                        f"-- Auto-fixable: {issue.auto_fixable}",
                        issue.fix_sql,
                        ""
                    ])
        
        migration_content.extend([
            "COMMIT;",
            "",
            "-- End of migration script"
        ])
        
        script_content = "\n".join(migration_content)
        
        with open(output_file, 'w') as f:
            f.write(script_content)
        
        logger.info(f"Migration script generated: {output_file}")
        return output_file

async def main():
    """Command-line interface for schema validation"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DevSecureX Schema Validator")
    parser.add_argument("--auto-fix", action="store_true", help="Automatically apply fixable issues")
    parser.add_argument("--dry-run", action="store_false", dest="apply_changes", help="Show what would be changed without applying")
    parser.add_argument("--output", "-o", help="Output file for validation report (JSON)")
    parser.add_argument("--migration-script", help="Generate migration script file")
    parser.add_argument("--severity", choices=['info', 'warning', 'error', 'critical'], help="Minimum severity level to report")
    parser.add_argument("--table", help="Validate specific table only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Create validator
    validator = SchemaValidator(
        auto_fix=args.auto_fix,
        dry_run=not args.apply_changes
    )
    
    # Filter by table if specified
    if args.table:
        validator.validation_config['ignore_tables'] = set()
        # Only validate the specified table
        # This would require additional logic to filter models
    
    try:
        # Run validation
        report = await validator.validate_schema()
        
        # Filter by severity if specified
        if args.severity:
            severity_filter = ValidationSeverity(args.severity)
            severity_levels = {
                ValidationSeverity.INFO: 0,
                ValidationSeverity.WARNING: 1,
                ValidationSeverity.ERROR: 2,
                ValidationSeverity.CRITICAL: 3
            }
            min_level = severity_levels[severity_filter]
            report.issues = [
                issue for issue in report.issues 
                if severity_levels[issue.severity] >= min_level
            ]
        
        # Print summary
        print(f"\n🔍 Schema Validation Report")
        print(f"{'='*50}")
        print(f"📊 Total Tables: {report.total_tables_checked}")
        print(f"📊 Total Columns: {report.total_columns_checked}")
        print(f"📊 Total Issues: {len(report.issues)}")
        print(f"🔴 Critical: {report.critical_issues_count}")
        print(f"🟡 Errors: {report.error_issues_count}")
        print(f"⚠️  Warnings: {report.warning_issues_count}")
        print(f"🔧 Auto-fixable: {len(report.auto_fixable_issues)}")
        
        # Show issues
        if report.issues:
            print(f"\n📋 Issues Found:")
            print(f"{'-'*50}")
            
            for i, issue in enumerate(report.issues, 1):
                severity_emoji = {
                    ValidationSeverity.CRITICAL: "🔴",
                    ValidationSeverity.ERROR: "🟡", 
                    ValidationSeverity.WARNING: "⚠️",
                    ValidationSeverity.INFO: "ℹ️"
                }[issue.severity]
                
                print(f"{i:2d}. {severity_emoji} [{issue.severity.value.upper()}] {issue.table_name}")
                if issue.column_name:
                    print(f"     Column: {issue.column_name}")
                print(f"     {issue.issue_description}")
                if issue.auto_fixable:
                    print(f"     🔧 Auto-fixable: {issue.fix_sql[:100]}...")
                print()
        
        # Apply fixes if requested
        if args.auto_fix and report.auto_fixable_issues:
            print(f"\n🔧 Applying {len(report.auto_fixable_issues)} auto-fixable issues...")
            fix_results = await validator.apply_fixes()
            print(f"✅ Applied: {fix_results.get('applied', 0)}")
            print(f"❌ Failed: {fix_results.get('failed', 0)}")
            print(f"⏭️  Skipped: {fix_results.get('skipped', 0)}")
        
        # Save report
        if args.output:
            report.save_to_file(args.output)
            print(f"📄 Report saved to: {args.output}")
        
        # Generate migration script
        if args.migration_script:
            script_path = validator.generate_migration_script(args.migration_script)
            print(f"📜 Migration script generated: {script_path}")
        
        # Exit with appropriate code
        if report.critical_issues_count > 0:
            sys.exit(2)  # Critical issues
        elif report.error_issues_count > 0:
            sys.exit(1)  # Errors
        else:
            sys.exit(0)  # Success
    
    except Exception as e:
        logger.error(f"Schema validation failed: {e}")
        sys.exit(3)  # Validation failure

if __name__ == "__main__":
    asyncio.run(main())