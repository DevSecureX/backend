"""
Database Schema Validator
Validates schema compatibility with current codebase and provides safe cleanup methods.
"""

import logging
from typing import Dict, List, Set, Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, inspect
from sqlalchemy.exc import ProgrammingError

logger = logging.getLogger(__name__)


class DatabaseSchemaValidator:
    """Validates database schema compatibility and provides safe cleanup operations."""
    
    EXPECTED_TABLES = {
        'users', 'repos', 'scans', 'scan_summaries', 'scan_jobs',
        'issue_feedback', 'pr_security_comments', 'pr_security_reviews',
        'community_rules', 'community_rule_votes', 'blacklisted_tokens',
        'login_attempts', 'chat_sessions', 'chat_messages', 'support_tickets'
    }
    
    # Table name variations found in different schema versions
    TABLE_VARIATIONS = {
        'compliance_mapping': ['compliance_mappings', 'compliance_mapping'],
        'compliance_mappings': ['compliance_mappings', 'compliance_mapping']
    }
    
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self._table_cache: Optional[Set[str]] = None
    
    async def get_existing_tables(self) -> Set[str]:
        """Get list of existing tables in database, cached for performance."""
        if self._table_cache is not None:
            return self._table_cache
            
        try:
            result = await self.db.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
            """))
            self._table_cache = {row[0] for row in result.fetchall()}
            logger.info(f"Found {len(self._table_cache)} tables in database")
            return self._table_cache
        except Exception as e:
            logger.error(f"Failed to get table list: {e}")
            return set()
    
    async def validate_schema_compatibility(self) -> Dict[str, any]:
        """Validate database schema compatibility with current codebase."""
        existing_tables = await self.get_existing_tables()
        
        missing_tables = self.EXPECTED_TABLES - existing_tables
        extra_tables = existing_tables - self.EXPECTED_TABLES
        
        # Check for table variations
        table_variations = {}
        for canonical_name, variations in self.TABLE_VARIATIONS.items():
            found_variations = [v for v in variations if v in existing_tables]
            if found_variations:
                table_variations[canonical_name] = found_variations
        
        compatibility_score = (len(existing_tables & self.EXPECTED_TABLES) / len(self.EXPECTED_TABLES)) * 100
        
        return {
            'compatible': len(missing_tables) == 0,
            'compatibility_score': compatibility_score,
            'existing_tables': list(existing_tables),
            'missing_tables': list(missing_tables),
            'extra_tables': list(extra_tables),
            'table_variations': table_variations,
            'total_expected': len(self.EXPECTED_TABLES),
            'total_found': len(existing_tables)
        }
    
    async def table_exists(self, table_name: str) -> bool:
        """Check if a table exists, considering variations."""
        existing_tables = await self.get_existing_tables()
        
        # Direct match
        if table_name in existing_tables:
            return True
            
        # Check variations
        if table_name in self.TABLE_VARIATIONS:
            return any(variation in existing_tables for variation in self.TABLE_VARIATIONS[table_name])
            
        return False
    
    async def get_actual_table_name(self, requested_table: str) -> Optional[str]:
        """Get the actual table name, considering variations."""
        existing_tables = await self.get_existing_tables()
        
        # Direct match
        if requested_table in existing_tables:
            return requested_table
            
        # Check variations
        if requested_table in self.TABLE_VARIATIONS:
            for variation in self.TABLE_VARIATIONS[requested_table]:
                if variation in existing_tables:
                    return variation
                    
        return None
    
    async def safe_delete_from_table(self, table_name: str, condition: str, params: Dict = None) -> int:
        """Safely delete from table, checking existence first."""
        actual_table = await self.get_actual_table_name(table_name)
        if not actual_table:
            logger.warning(f"Table {table_name} does not exist, skipping deletion")
            return 0
            
        try:
            query = f"DELETE FROM {actual_table} WHERE {condition}"
            result = await self.db.execute(text(query), params or {})
            deleted_count = result.rowcount
            logger.info(f"Deleted {deleted_count} records from {actual_table}")
            return deleted_count
        except Exception as e:
            logger.error(f"Failed to delete from {actual_table}: {e}")
            return 0
    
    async def safe_update_table(self, table_name: str, set_clause: str, condition: str, params: Dict = None) -> int:
        """Safely update table, checking existence first."""
        actual_table = await self.get_actual_table_name(table_name)
        if not actual_table:
            logger.warning(f"Table {table_name} does not exist, skipping update")
            return 0
            
        try:
            query = f"UPDATE {actual_table} SET {set_clause} WHERE {condition}"
            result = await self.db.execute(text(query), params or {})
            updated_count = result.rowcount
            logger.info(f"Updated {updated_count} records in {actual_table}")
            return updated_count
        except Exception as e:
            logger.error(f"Failed to update {actual_table}: {e}")
            return 0
    
    async def safe_select_from_table(self, table_name: str, select_clause: str, condition: str = "", params: Dict = None):
        """Safely select from table, checking existence first."""
        actual_table = await self.get_actual_table_name(table_name)
        if not actual_table:
            logger.warning(f"Table {table_name} does not exist, returning empty result")
            return []
            
        try:
            where_clause = f" WHERE {condition}" if condition else ""
            query = f"SELECT {select_clause} FROM {actual_table}{where_clause}"
            result = await self.db.execute(text(query), params or {})
            return result.fetchall()
        except Exception as e:
            logger.error(f"Failed to select from {actual_table}: {e}")
            return []
    
    async def get_schema_health_report(self) -> Dict[str, any]:
        """Generate comprehensive schema health report."""
        compatibility = await self.validate_schema_compatibility()
        
        health_issues = []
        if compatibility['missing_tables']:
            health_issues.append(f"Missing {len(compatibility['missing_tables'])} expected tables")
        if compatibility['table_variations']:
            health_issues.append(f"Found {len(compatibility['table_variations'])} table name variations")
        if compatibility['compatibility_score'] < 90:
            health_issues.append(f"Low compatibility score: {compatibility['compatibility_score']:.1f}%")
        
        return {
            'healthy': len(health_issues) == 0,
            'issues': health_issues,
            'recommendations': self._get_health_recommendations(compatibility),
            'compatibility': compatibility
        }
    
    def _get_health_recommendations(self, compatibility: Dict) -> List[str]:
        """Generate recommendations based on compatibility analysis."""
        recommendations = []
        
        if compatibility['missing_tables']:
            recommendations.append("Run database migrations to create missing tables")
        
        if compatibility['table_variations']:
            recommendations.append("Standardize table names using migration script")
        
        if compatibility['compatibility_score'] < 50:
            recommendations.append("Consider full database schema migration")
        elif compatibility['compatibility_score'] < 90:
            recommendations.append("Run schema validation and fix minor issues")
        
        if not compatibility['compatible']:
            recommendations.append("Use safe database operations that handle missing tables")
        
        return recommendations