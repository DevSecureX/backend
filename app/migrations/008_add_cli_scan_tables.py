"""
Migration 008: Add CLI Scan Tables
Creates comprehensive CLI scanning infrastructure tables for enterprise-grade data persistence
"""

from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

MIGRATION_ID = "008_add_cli_scan_tables"
DESCRIPTION = "Add comprehensive CLI scan tables for enterprise data persistence"

async def upgrade(connection):
    """Create CLI scan tables with proper indexes and constraints"""
    
    try:
        # Create cli_scan_results table
        await connection.execute(text("""
            CREATE TABLE IF NOT EXISTS cli_scan_results (
                id SERIAL PRIMARY KEY,
                scan_id VARCHAR(64) UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                scan_metadata JSONB NOT NULL DEFAULT '{}',
                results_data JSONB NOT NULL DEFAULT '{}',
                file_count INTEGER NOT NULL DEFAULT 0,
                total_score FLOAT NOT NULL DEFAULT 0.0,
                issue_counts JSONB NOT NULL DEFAULT '{}',
                total_issues INTEGER NOT NULL DEFAULT 0,
                tools_used JSONB NOT NULL DEFAULT '[]',
                scan_duration FLOAT NOT NULL DEFAULT 0.0,
                status VARCHAR(20) NOT NULL DEFAULT 'completed' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'timeout', 'cancelled')),
                error_message TEXT,
                compliance_data JSONB,
                risk_assessment JSONB,
                languages_detected JSONB,
                dependency_files_count INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE
            )
        """))
        
        # Create indexes for cli_scan_results
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_scan_id ON cli_scan_results(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_user_id ON cli_scan_results(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_file_count ON cli_scan_results(file_count)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_total_score ON cli_scan_results(total_score)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_total_issues ON cli_scan_results(total_issues)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_status ON cli_scan_results(status)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_created_at ON cli_scan_results(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_user_date ON cli_scan_results(user_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_status_date ON cli_scan_results(status, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_score_issues ON cli_scan_results(total_score, total_issues)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_user_status ON cli_scan_results(user_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_duration_performance ON cli_scan_results(scan_duration, file_count)",
            "CREATE INDEX IF NOT EXISTS idx_cli_scan_cleanup ON cli_scan_results(created_at, status)"
        ]
        
        for index_sql in indexes:
            await connection.execute(text(index_sql))
        
        logger.info("Created cli_scan_results table with indexes")
        
        # Create cli_activity_logs table
        await connection.execute(text("""
            CREATE TABLE IF NOT EXISTS cli_activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                scan_id VARCHAR(64) REFERENCES cli_scan_results(scan_id) ON DELETE SET NULL,
                activity_type VARCHAR(50) NOT NULL CHECK (activity_type IN (
                    'scan_start', 'scan_complete', 'scan_error', 'scan_timeout', 
                    'scan_cancelled', 'command_executed', 'results_retrieved', 
                    'usage_stats_accessed', 'api_error'
                )),
                command VARCHAR(500),
                parameters JSONB,
                endpoint VARCHAR(100),
                response_status VARCHAR(20),
                http_status_code INTEGER,
                duration FLOAT,
                error_details JSONB,
                error_type VARCHAR(100),
                client_info JSONB,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
            )
        """))
        
        # Create indexes for cli_activity_logs
        activity_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_user_id ON cli_activity_logs(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_scan_id ON cli_activity_logs(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_type ON cli_activity_logs(activity_type)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_error_type ON cli_activity_logs(error_type)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_created_at ON cli_activity_logs(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_user_type_date ON cli_activity_logs(user_id, activity_type, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_scan_type ON cli_activity_logs(scan_id, activity_type)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_error_analysis ON cli_activity_logs(error_type, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_performance ON cli_activity_logs(duration, activity_type)",
            "CREATE INDEX IF NOT EXISTS idx_cli_activity_cleanup ON cli_activity_logs(created_at)"
        ]
        
        for index_sql in activity_indexes:
            await connection.execute(text(index_sql))
        
        logger.info("Created cli_activity_logs table with indexes")
        
        # Create cli_usage_stats table
        await connection.execute(text("""
            CREATE TABLE IF NOT EXISTS cli_usage_stats (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                date TIMESTAMP WITH TIME ZONE NOT NULL,
                total_scans INTEGER NOT NULL DEFAULT 0,
                successful_scans INTEGER NOT NULL DEFAULT 0,
                failed_scans INTEGER NOT NULL DEFAULT 0,
                timeout_scans INTEGER NOT NULL DEFAULT 0,
                cancelled_scans INTEGER NOT NULL DEFAULT 0,
                total_issues_found INTEGER NOT NULL DEFAULT 0,
                critical_issues INTEGER NOT NULL DEFAULT 0,
                high_issues INTEGER NOT NULL DEFAULT 0,
                medium_issues INTEGER NOT NULL DEFAULT 0,
                low_issues INTEGER NOT NULL DEFAULT 0,
                total_scan_duration FLOAT NOT NULL DEFAULT 0.0,
                avg_scan_duration FLOAT NOT NULL DEFAULT 0.0,
                min_scan_duration FLOAT,
                max_scan_duration FLOAT,
                total_files_scanned INTEGER NOT NULL DEFAULT 0,
                avg_files_per_scan FLOAT NOT NULL DEFAULT 0.0,
                tools_usage_count JSONB NOT NULL DEFAULT '{}',
                file_types_scanned JSONB NOT NULL DEFAULT '{}',
                languages_detected JSONB NOT NULL DEFAULT '{}',
                compliance_scores JSONB,
                risk_trends JSONB,
                success_rate FLOAT NOT NULL DEFAULT 0.0,
                avg_issues_per_scan FLOAT NOT NULL DEFAULT 0.0,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE
            )
        """))
        
        # Create indexes for cli_usage_stats
        stats_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_user_id ON cli_usage_stats(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_date ON cli_usage_stats(date)",
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_user_date ON cli_usage_stats(user_id, date)",
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_success_rate ON cli_usage_stats(success_rate, total_scans)",
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_performance ON cli_usage_stats(avg_scan_duration, avg_files_per_scan)",
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_issues ON cli_usage_stats(total_issues_found, critical_issues)",
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_date_range ON cli_usage_stats(date)",
            "CREATE INDEX IF NOT EXISTS idx_cli_stats_cleanup ON cli_usage_stats(created_at)"
        ]
        
        for index_sql in stats_indexes:
            await connection.execute(text(index_sql))
        
        logger.info("Created cli_usage_stats table with indexes")
        
        # Create cli_scan_sessions table
        await connection.execute(text("""
            CREATE TABLE IF NOT EXISTS cli_scan_sessions (
                id SERIAL PRIMARY KEY,
                session_id VARCHAR(64) UNIQUE NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL DEFAULT 'Unnamed Session',
                status VARCHAR(20) NOT NULL DEFAULT 'active',
                session_data JSONB,
                current_operation VARCHAR(100),
                operations_completed JSONB NOT NULL DEFAULT '[]',
                total_operations INTEGER NOT NULL DEFAULT 1,
                progress_percentage FLOAT NOT NULL DEFAULT 0.0,
                started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                last_activity TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                client_info JSONB
            )
        """))
        
        # Create indexes for cli_scan_sessions
        session_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_cli_session_session_id ON cli_scan_sessions(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_cli_session_user_id ON cli_scan_sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_cli_session_status ON cli_scan_sessions(status)",
            "CREATE INDEX IF NOT EXISTS idx_cli_session_last_activity ON cli_scan_sessions(last_activity)",
            "CREATE INDEX IF NOT EXISTS idx_cli_session_expires_at ON cli_scan_sessions(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_cli_session_user_status ON cli_scan_sessions(user_id, status)",
            "CREATE INDEX IF NOT EXISTS idx_cli_session_activity ON cli_scan_sessions(last_activity, status)",
            "CREATE INDEX IF NOT EXISTS idx_cli_session_cleanup ON cli_scan_sessions(expires_at, status)"
        ]
        
        for index_sql in session_indexes:
            await connection.execute(text(index_sql))
        
        logger.info("Created cli_scan_sessions table with indexes")
        
        # Add unique constraints
        try:
            await connection.execute(text("""
                ALTER TABLE cli_usage_stats 
                ADD CONSTRAINT uq_cli_stats_user_date 
                UNIQUE (user_id, date)
            """))
            logger.info("Added unique constraint uq_cli_stats_user_date")
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.info("Unique constraint uq_cli_stats_user_date already exists")
            else:
                raise
        
        logger.info("Added unique constraints")
        
        # Update updated_at triggers for tables that need them
        trigger_tables = ['cli_scan_results', 'cli_usage_stats']
        for table in trigger_tables:
            # Create function
            await connection.execute(text(f"""
                CREATE OR REPLACE FUNCTION update_{table}_updated_at()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = NOW();
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """))
            
            # Drop existing trigger
            await connection.execute(text(f"""
                DROP TRIGGER IF EXISTS trigger_update_{table}_updated_at ON {table};
            """))
            
            # Create new trigger
            await connection.execute(text(f"""
                CREATE TRIGGER trigger_update_{table}_updated_at
                    BEFORE UPDATE ON {table}
                    FOR EACH ROW
                    EXECUTE FUNCTION update_{table}_updated_at();
            """))
        
        logger.info("Created update triggers for timestamp columns")
        
        # Create stored procedures for common operations
        await connection.execute(text("""
            CREATE OR REPLACE FUNCTION calculate_cli_usage_stats(p_user_id INTEGER, p_date DATE)
            RETURNS VOID AS $$
            BEGIN
                INSERT INTO cli_usage_stats (
                    user_id, date, total_scans, successful_scans, failed_scans, 
                    timeout_scans, cancelled_scans, total_issues_found, 
                    critical_issues, high_issues, medium_issues, low_issues,
                    total_scan_duration, avg_scan_duration, min_scan_duration, max_scan_duration,
                    total_files_scanned, avg_files_per_scan, success_rate, avg_issues_per_scan
                )
                SELECT 
                    p_user_id,
                    p_date::timestamp with time zone,
                    COUNT(*) as total_scans,
                    COUNT(*) FILTER (WHERE status = 'completed') as successful_scans,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
                    COUNT(*) FILTER (WHERE status = 'timeout') as timeout_scans,
                    COUNT(*) FILTER (WHERE status = 'cancelled') as cancelled_scans,
                    COALESCE(SUM(total_issues), 0) as total_issues_found,
                    COALESCE(SUM((issue_counts->>'critical')::int), 0) as critical_issues,
                    COALESCE(SUM((issue_counts->>'high')::int), 0) as high_issues,
                    COALESCE(SUM((issue_counts->>'medium')::int), 0) as medium_issues,
                    COALESCE(SUM((issue_counts->>'low')::int), 0) as low_issues,
                    COALESCE(SUM(scan_duration), 0.0) as total_scan_duration,
                    COALESCE(AVG(scan_duration), 0.0) as avg_scan_duration,
                    MIN(scan_duration) as min_scan_duration,
                    MAX(scan_duration) as max_scan_duration,
                    COALESCE(SUM(file_count), 0) as total_files_scanned,
                    COALESCE(AVG(file_count), 0.0) as avg_files_per_scan,
                    CASE WHEN COUNT(*) > 0 THEN 
                        (COUNT(*) FILTER (WHERE status = 'completed') * 100.0 / COUNT(*))
                    ELSE 0.0 END as success_rate,
                    CASE WHEN COUNT(*) > 0 THEN 
                        COALESCE(SUM(total_issues), 0) * 1.0 / COUNT(*)
                    ELSE 0.0 END as avg_issues_per_scan
                FROM cli_scan_results
                WHERE user_id = p_user_id 
                  AND DATE(created_at) = p_date
                ON CONFLICT (user_id, date) 
                DO UPDATE SET
                    total_scans = EXCLUDED.total_scans,
                    successful_scans = EXCLUDED.successful_scans,
                    failed_scans = EXCLUDED.failed_scans,
                    timeout_scans = EXCLUDED.timeout_scans,
                    cancelled_scans = EXCLUDED.cancelled_scans,
                    total_issues_found = EXCLUDED.total_issues_found,
                    critical_issues = EXCLUDED.critical_issues,
                    high_issues = EXCLUDED.high_issues,
                    medium_issues = EXCLUDED.medium_issues,
                    low_issues = EXCLUDED.low_issues,
                    total_scan_duration = EXCLUDED.total_scan_duration,
                    avg_scan_duration = EXCLUDED.avg_scan_duration,
                    min_scan_duration = EXCLUDED.min_scan_duration,
                    max_scan_duration = EXCLUDED.max_scan_duration,
                    total_files_scanned = EXCLUDED.total_files_scanned,
                    avg_files_per_scan = EXCLUDED.avg_files_per_scan,
                    success_rate = EXCLUDED.success_rate,
                    avg_issues_per_scan = EXCLUDED.avg_issues_per_scan,
                    updated_at = NOW();
            END;
            $$ LANGUAGE plpgsql;
        """))
        
        logger.info("Created CLI usage statistics calculation function")
        
        # Add comment documentation
        comments = [
            ("cli_scan_results", "Comprehensive CLI scan results with full data persistence for enterprise synchronization"),
            ("cli_activity_logs", "CLI activity logging for analytics, monitoring, and audit trails"),
            ("cli_usage_stats", "Aggregated CLI usage statistics for performance analytics and insights"),
            ("cli_scan_sessions", "CLI scan session tracking for multi-step operations and state management")
        ]
        
        for table, comment in comments:
            await connection.execute(text(f"COMMENT ON TABLE {table} IS '{comment}'"))
        
        logger.info("Added table documentation comments")
        logger.info("Migration 008: CLI scan tables created successfully")
        
    except Exception as e:
        logger.error(f"Error in migration 008: {str(e)}")
        raise


async def downgrade(connection):
    """Remove CLI scan tables (for development/testing only)"""
    
    try:
        # Drop tables in reverse order due to foreign key constraints
        tables_to_drop = [
            'cli_scan_sessions',
            'cli_usage_stats', 
            'cli_activity_logs',
            'cli_scan_results'
        ]
        
        for table in tables_to_drop:
            await connection.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
            logger.info(f"Dropped table: {table}")
        
        # Drop functions
        functions_to_drop = [
            'calculate_cli_usage_stats(INTEGER, DATE)',
            'update_cli_scan_results_updated_at()',
            'update_cli_usage_stats_updated_at()'
        ]
        
        for func in functions_to_drop:
            await connection.execute(text(f"DROP FUNCTION IF EXISTS {func} CASCADE"))
            logger.info(f"Dropped function: {func}")
        
        logger.info("Migration 008: CLI scan tables removed successfully")
        
    except Exception as e:
        logger.error(f"Error in migration 008 downgrade: {str(e)}")
        raise