#!/usr/bin/env python3
"""
Database Health Monitor for DevSecureX

This script provides comprehensive database health monitoring including:
1. Connection testing and pool health
2. Schema integrity verification
3. Performance monitoring
4. Index usage analysis
5. Data consistency checks
6. Security validation

Usage:
    python app/scripts/database_health_monitor.py [options]
    
Author: DevSecureX Team
"""

import asyncio
import argparse
import logging
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import json
import time

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from sqlalchemy import text, inspect
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from core.database import engine, async_session, get_db_pool_status
from core.config import DATABASE_URL


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'db_health_monitor_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class DatabaseHealthMonitor:
    """Comprehensive database health monitoring and diagnostics"""
    
    def __init__(self, detailed: bool = False):
        self.detailed = detailed
        self.async_engine = engine
        self.health_report = {
            "timestamp": datetime.now().isoformat(),
            "overall_health": "unknown",
            "connection_health": {},
            "schema_health": {},
            "performance_health": {},
            "data_health": {},
            "security_health": {},
            "recommendations": []
        }
        
        logger.info(f"Initialized DatabaseHealthMonitor (detailed={detailed})")
    
    async def test_connection_health(self) -> Dict[str, Any]:
        """Test database connection and pool health"""
        logger.info("Testing database connection health...")
        
        connection_health = {
            "basic_connectivity": False,
            "pool_status": {},
            "response_time_ms": None,
            "max_connections": None,
            "active_connections": None,
            "issues": []
        }
        
        try:
            # Test basic connectivity with timing
            start_time = time.time()
            async with async_session() as session:
                result = await session.execute(text("SELECT 1 as test"))
                test_value = result.scalar()
                
                if test_value == 1:
                    connection_health["basic_connectivity"] = True
                    connection_health["response_time_ms"] = int((time.time() - start_time) * 1000)
                    logger.info(f"✅ Basic connectivity OK ({connection_health['response_time_ms']}ms)")
                else:
                    connection_health["issues"].append("Basic connectivity test failed")
            
            # Get pool status
            try:
                pool_status = await get_db_pool_status()
                connection_health["pool_status"] = pool_status
                
                if pool_status.get("health") == "critical":
                    connection_health["issues"].append("Connection pool utilization critical")
                elif pool_status.get("utilization_percent", 0) > 80:
                    connection_health["issues"].append("High connection pool utilization")
                
                logger.info(f"Pool utilization: {pool_status.get('utilization_percent', 'unknown')}%")
                
            except Exception as e:
                logger.warning(f"Could not get pool status: {str(e)}")
                connection_health["issues"].append(f"Pool status unavailable: {str(e)}")
            
            # Get database connection limits
            async with async_session() as session:
                result = await session.execute(text("SHOW max_connections"))
                connection_health["max_connections"] = int(result.scalar())
                
                result = await session.execute(text("""
                    SELECT COUNT(*) FROM pg_stat_activity 
                    WHERE state = 'active'
                """))
                connection_health["active_connections"] = result.scalar()
                
                logger.info(f"Connections: {connection_health['active_connections']}/{connection_health['max_connections']}")
        
        except Exception as e:
            logger.error(f"❌ Connection health test failed: {str(e)}")
            connection_health["issues"].append(f"Connection test failed: {str(e)}")
        
        return connection_health
    
    async def test_schema_health(self) -> Dict[str, Any]:
        """Test database schema health and integrity"""
        logger.info("Testing database schema health...")
        
        schema_health = {
            "table_count": 0,
            "missing_tables": [],
            "orphaned_tables": [],
            "constraint_issues": [],
            "index_health": {},
            "issues": []
        }
        
        try:
            # Get current table count
            async with async_session() as session:
                result = await session.execute(text("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                """))
                schema_health["table_count"] = result.scalar()
                
                # Check for expected core tables
                expected_tables = [
                    "users", "repos", "scans", "community_rules", 
                    "migration_history", "blacklisted_tokens"
                ]
                
                for table in expected_tables:
                    result = await session.execute(text(f"""
                        SELECT COUNT(*) FROM information_schema.tables 
                        WHERE table_name = '{table}' AND table_schema = 'public'
                    """))
                    
                    if result.scalar() == 0:
                        schema_health["missing_tables"].append(table)
                        schema_health["issues"].append(f"Missing core table: {table}")
                
                # Check for constraint violations
                result = await session.execute(text("""
                    SELECT conrelid::regclass AS table_name, conname AS constraint_name
                    FROM pg_constraint
                    WHERE NOT convalidated
                """))
                
                invalid_constraints = result.fetchall()
                if invalid_constraints:
                    for row in invalid_constraints:
                        constraint_issue = f"{row[0]}.{row[1]}"
                        schema_health["constraint_issues"].append(constraint_issue)
                        schema_health["issues"].append(f"Invalid constraint: {constraint_issue}")
                
                # Analyze index health
                result = await session.execute(text("""
                    SELECT 
                        schemaname,
                        tablename,
                        indexname,
                        idx_scan,
                        idx_tup_read,
                        idx_tup_fetch
                    FROM pg_stat_user_indexes
                    WHERE idx_scan = 0 AND schemaname = 'public'
                """))
                
                unused_indexes = result.fetchall()
                if unused_indexes and len(unused_indexes) > 5:
                    schema_health["issues"].append(f"Found {len(unused_indexes)} unused indexes")
                
                schema_health["index_health"] = {
                    "unused_indexes": len(unused_indexes),
                    "total_indexes": await self._get_total_index_count(session)
                }
                
                logger.info(f"Schema: {schema_health['table_count']} tables, {len(schema_health['issues'])} issues")
        
        except Exception as e:
            logger.error(f"❌ Schema health test failed: {str(e)}")
            schema_health["issues"].append(f"Schema test failed: {str(e)}")
        
        return schema_health
    
    async def _get_total_index_count(self, session) -> int:
        """Helper to get total index count"""
        try:
            result = await session.execute(text("""
                SELECT COUNT(*) FROM pg_indexes 
                WHERE schemaname = 'public'
            """))
            return result.scalar()
        except:
            return 0
    
    async def test_performance_health(self) -> Dict[str, Any]:
        """Test database performance metrics"""
        logger.info("Testing database performance health...")
        
        performance_health = {
            "query_performance": {},
            "table_stats": {},
            "slow_queries": [],
            "lock_issues": [],
            "issues": []
        }
        
        try:
            async with async_session() as session:
                # Test query performance on key tables
                key_tables = ["users", "repos", "scans"]
                
                for table in key_tables:
                    start_time = time.time()
                    try:
                        result = await session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                        count = result.scalar()
                        query_time = int((time.time() - start_time) * 1000)
                        
                        performance_health["query_performance"][table] = {
                            "count": count,
                            "query_time_ms": query_time
                        }
                        
                        if query_time > 1000:  # Over 1 second
                            performance_health["issues"].append(f"Slow count query on {table}: {query_time}ms")
                        
                        logger.debug(f"Table {table}: {count} rows in {query_time}ms")
                        
                    except Exception as e:
                        logger.warning(f"Could not test performance for {table}: {str(e)}")
                
                # Check for long-running queries
                result = await session.execute(text("""
                    SELECT query, state, query_start, 
                           EXTRACT(EPOCH FROM (NOW() - query_start)) as duration_seconds
                    FROM pg_stat_activity 
                    WHERE state != 'idle' 
                    AND query_start < NOW() - INTERVAL '30 seconds'
                    AND query NOT LIKE '%pg_stat_activity%'
                """))
                
                long_queries = result.fetchall()
                for row in long_queries:
                    performance_health["slow_queries"].append({
                        "query": row[0][:100] + "..." if len(row[0]) > 100 else row[0],
                        "state": row[1],
                        "duration_seconds": float(row[3])
                    })
                
                if long_queries:
                    performance_health["issues"].append(f"Found {len(long_queries)} long-running queries")
                
                # Check for locks
                result = await session.execute(text("""
                    SELECT COUNT(*) FROM pg_locks 
                    WHERE NOT granted
                """))
                
                lock_count = result.scalar()
                if lock_count > 0:
                    performance_health["lock_issues"].append(f"{lock_count} blocked queries")
                    performance_health["issues"].append(f"Database contention: {lock_count} blocked queries")
                
                logger.info(f"Performance: {len(performance_health['issues'])} issues found")
        
        except Exception as e:
            logger.error(f"❌ Performance health test failed: {str(e)}")
            performance_health["issues"].append(f"Performance test failed: {str(e)}")
        
        return performance_health
    
    async def test_data_health(self) -> Dict[str, Any]:
        """Test data consistency and integrity"""
        logger.info("Testing data health and consistency...")
        
        data_health = {
            "row_counts": {},
            "data_consistency": {},
            "referential_integrity": [],
            "issues": []
        }
        
        try:
            async with async_session() as session:
                # Get row counts for key tables
                key_tables = ["users", "repos", "scans", "community_rules"]
                
                for table in key_tables:
                    try:
                        result = await session.execute(text(f"SELECT COUNT(*) FROM {table}"))
                        count = result.scalar()
                        data_health["row_counts"][table] = count
                        logger.debug(f"Table {table}: {count} rows")
                    except Exception as e:
                        logger.warning(f"Could not count rows in {table}: {str(e)}")
                        data_health["row_counts"][table] = -1
                
                # Check referential integrity
                integrity_checks = [
                    ("repos", "user_id", "users", "id", "Repos with invalid user_id"),
                    ("scans", "user_id", "users", "id", "Scans with invalid user_id"),
                    ("community_rules", "author_id", "users", "id", "Rules with invalid author_id")
                ]
                
                for child_table, child_col, parent_table, parent_col, description in integrity_checks:
                    try:
                        result = await session.execute(text(f"""
                            SELECT COUNT(*) FROM {child_table} c
                            LEFT JOIN {parent_table} p ON c.{child_col} = p.{parent_col}
                            WHERE p.{parent_col} IS NULL AND c.{child_col} IS NOT NULL
                        """))
                        
                        orphan_count = result.scalar()
                        if orphan_count > 0:
                            data_health["referential_integrity"].append({
                                "description": description,
                                "orphan_count": orphan_count
                            })
                            data_health["issues"].append(f"{description}: {orphan_count} orphaned records")
                    
                    except Exception as e:
                        logger.warning(f"Could not check integrity for {child_table}: {str(e)}")
                
                # Check for data anomalies
                if data_health["row_counts"].get("users", 0) == 0:
                    data_health["issues"].append("No users in database - system may be unusable")
                
                if data_health["row_counts"].get("repos", 0) > data_health["row_counts"].get("users", 0) * 50:
                    data_health["issues"].append("Suspiciously high repo:user ratio")
                
                logger.info(f"Data health: {len(data_health['issues'])} issues found")
        
        except Exception as e:
            logger.error(f"❌ Data health test failed: {str(e)}")
            data_health["issues"].append(f"Data health test failed: {str(e)}")
        
        return data_health
    
    async def test_security_health(self) -> Dict[str, Any]:
        """Test security-related database health"""
        logger.info("Testing security health...")
        
        security_health = {
            "user_security": {},
            "access_patterns": {},
            "potential_issues": [],
            "issues": []
        }
        
        try:
            async with async_session() as session:
                # Check for users without proper password security
                result = await session.execute(text("""
                    SELECT COUNT(*) FROM users 
                    WHERE hashed_password IS NULL AND is_github_connected = false
                """))
                
                users_no_auth = result.scalar()
                if users_no_auth > 0:
                    security_health["potential_issues"].append(f"{users_no_auth} users with no authentication method")
                
                # Check for old blacklisted tokens
                result = await session.execute(text("""
                    SELECT COUNT(*) FROM blacklisted_tokens 
                    WHERE expires_at < NOW() - INTERVAL '30 days'
                """))
                
                old_tokens = result.scalar()
                if old_tokens > 100:
                    security_health["potential_issues"].append(f"{old_tokens} old blacklisted tokens (cleanup needed)")
                
                # Check for failed login patterns
                result = await session.execute(text("""
                    SELECT COUNT(*) FROM login_attempts 
                    WHERE success = false 
                    AND created_at > NOW() - INTERVAL '24 hours'
                """))
                
                failed_logins = result.scalar()
                security_health["access_patterns"]["failed_logins_24h"] = failed_logins
                
                if failed_logins > 1000:
                    security_health["issues"].append("High number of failed login attempts in last 24h")
                
                logger.info(f"Security: {len(security_health['issues'])} issues, {len(security_health['potential_issues'])} potential issues")
        
        except Exception as e:
            logger.error(f"❌ Security health test failed: {str(e)}")
            security_health["issues"].append(f"Security test failed: {str(e)}")
        
        return security_health
    
    def generate_recommendations(self) -> List[str]:
        """Generate health recommendations based on findings"""
        recommendations = []
        
        # Connection health recommendations
        if self.health_report["connection_health"].get("pool_status", {}).get("utilization_percent", 0) > 80:
            recommendations.append("Consider increasing database connection pool size")
        
        # Schema health recommendations
        if self.health_report["schema_health"].get("missing_tables"):
            recommendations.append("Run database migrations to create missing tables")
        
        if self.health_report["schema_health"].get("index_health", {}).get("unused_indexes", 0) > 10:
            recommendations.append("Consider removing unused indexes to improve write performance")
        
        # Performance recommendations
        slow_queries = len(self.health_report["performance_health"].get("slow_queries", []))
        if slow_queries > 0:
            recommendations.append(f"Investigate {slow_queries} slow-running queries")
        
        # Data health recommendations
        if self.health_report["data_health"].get("referential_integrity"):
            recommendations.append("Fix referential integrity issues to maintain data consistency")
        
        # Security recommendations
        if self.health_report["security_health"].get("potential_issues"):
            recommendations.append("Review security potential issues and implement necessary fixes")
        
        # General recommendations
        total_issues = sum([
            len(self.health_report["connection_health"].get("issues", [])),
            len(self.health_report["schema_health"].get("issues", [])),
            len(self.health_report["performance_health"].get("issues", [])),
            len(self.health_report["data_health"].get("issues", [])),
            len(self.health_report["security_health"].get("issues", []))
        ])
        
        if total_issues == 0:
            recommendations.append("Database health is excellent! Consider regular monitoring.")
        elif total_issues > 10:
            recommendations.append("Database has multiple issues - prioritize fixing critical problems first")
        
        return recommendations
    
    def calculate_overall_health(self) -> str:
        """Calculate overall database health score"""
        total_issues = sum([
            len(self.health_report["connection_health"].get("issues", [])),
            len(self.health_report["schema_health"].get("issues", [])),
            len(self.health_report["performance_health"].get("issues", [])),
            len(self.health_report["data_health"].get("issues", [])),
            len(self.health_report["security_health"].get("issues", []))
        ])
        
        # Basic connectivity is critical
        if not self.health_report["connection_health"].get("basic_connectivity", False):
            return "critical"
        
        # Missing core tables is critical
        if self.health_report["schema_health"].get("missing_tables"):
            return "critical"
        
        # Too many issues overall
        if total_issues > 10:
            return "poor"
        elif total_issues > 5:
            return "fair"
        elif total_issues > 0:
            return "good"
        else:
            return "excellent"
    
    async def run_comprehensive_health_check(self) -> Dict[str, Any]:
        """Run comprehensive database health check"""
        logger.info("🔍 Starting comprehensive database health check...")
        
        start_time = time.time()
        
        try:
            # Run all health tests
            self.health_report["connection_health"] = await self.test_connection_health()
            self.health_report["schema_health"] = await self.test_schema_health()
            self.health_report["performance_health"] = await self.test_performance_health()
            self.health_report["data_health"] = await self.test_data_health()
            self.health_report["security_health"] = await self.test_security_health()
            
            # Generate recommendations
            self.health_report["recommendations"] = self.generate_recommendations()
            
            # Calculate overall health
            self.health_report["overall_health"] = self.calculate_overall_health()
            
            # Add timing information
            self.health_report["check_duration_seconds"] = round(time.time() - start_time, 2)
            
            # Log summary
            overall_health = self.health_report["overall_health"]
            logger.info(f"🏥 Overall Database Health: {overall_health.upper()}")
            logger.info(f"⏱️ Health check completed in {self.health_report['check_duration_seconds']}s")
            
            # Health status emoji
            health_emoji = {
                "excellent": "🟢",
                "good": "🟡", 
                "fair": "🟠",
                "poor": "🔴",
                "critical": "💀"
            }
            
            logger.info(f"{health_emoji.get(overall_health, '❓')} Health Status: {overall_health}")
            
            return self.health_report
            
        except Exception as e:
            logger.error(f"❌ Health check failed: {str(e)}")
            self.health_report["overall_health"] = "critical"
            self.health_report["check_error"] = str(e)
            return self.health_report


async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description="Database Health Monitor for DevSecureX")
    parser.add_argument("--detailed", action="store_true",
                       help="Run detailed health checks")
    parser.add_argument("--json", action="store_true",
                       help="Output results in JSON format")
    parser.add_argument("--save-report", action="store_true",
                       help="Save detailed report to file")
    parser.add_argument("--connection-only", action="store_true",
                       help="Test connection health only")
    parser.add_argument("--schema-only", action="store_true",
                       help="Test schema health only")
    parser.add_argument("--performance-only", action="store_true",
                       help="Test performance health only")
    
    args = parser.parse_args()
    
    # Initialize health monitor
    monitor = DatabaseHealthMonitor(detailed=args.detailed)
    
    try:
        if args.connection_only:
            logger.info("🔌 Testing connection health only...")
            result = await monitor.test_connection_health()
        elif args.schema_only:
            logger.info("🏗️ Testing schema health only...")
            result = await monitor.test_schema_health()
        elif args.performance_only:
            logger.info("⚡ Testing performance health only...")
            result = await monitor.test_performance_health()
        else:
            # Run comprehensive health check
            result = await monitor.run_comprehensive_health_check()
        
        # Output results
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        
        # Save report if requested
        if args.save_report:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"db_health_report_{timestamp}.json"
            with open(report_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            logger.info(f"📄 Detailed report saved to: {report_file}")
        
        # Exit with appropriate code
        if isinstance(result, dict):
            overall_health = result.get("overall_health", "unknown")
            if overall_health in ["critical", "poor"]:
                sys.exit(1)
            else:
                sys.exit(0)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.info("🛑 Health check cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())