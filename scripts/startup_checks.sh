#!/bin/bash

# DevSecureX Startup Checks Script
# Comprehensive startup validation and schema checking for Docker deployment
# 
# This script runs before the main application starts to ensure:
# 1. Database connectivity
# 2. Schema consistency 
# 3. Critical migration execution
# 4. Data integrity validation
#
# Created: 2025-09-03

set -e  # Exit on any error

# Configuration
APP_ENV="${APP_ENV:-production}"
STARTUP_VALIDATION_ENABLED="${STARTUP_VALIDATION_ENABLED:-true}"
STARTUP_AUTO_FIX_ENABLED="${STARTUP_AUTO_FIX_ENABLED:-false}"
STARTUP_BLOCK_ON_CRITICAL="${STARTUP_BLOCK_ON_CRITICAL:-true}"
STARTUP_BLOCK_ON_ERRORS="${STARTUP_BLOCK_ON_ERRORS:-true}"
MIGRATION_AUTO_RUN="${MIGRATION_AUTO_RUN:-true}"
MAX_STARTUP_TIME="${MAX_STARTUP_TIME:-300}"  # 5 minutes max startup time

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SCRIPT_DIR}/../app"
BACKEND_DIR="${SCRIPT_DIR}/.."
VALIDATION_REPORT_DIR="${VALIDATION_REPORT_DIR:-/tmp/devsecurex-validation}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $(date '+%Y-%m-%d %H:%M:%S') 🚀 $1"
}

# Function to check if we're in Docker
is_docker() {
    [ -f /.dockerenv ] || grep -q 'docker\|lxc' /proc/1/cgroup 2>/dev/null
}

# Function to wait for database
wait_for_database() {
    log_step "Waiting for database connectivity..."
    
    local max_attempts=30
    local attempt=1
    local db_ready=false
    
    while [ $attempt -le $max_attempts ]; do
        log_info "Database connection attempt $attempt/$max_attempts"
        
        # Try to connect to database using Python
        if cd "$APP_DIR" && python3 -c "
import asyncio
import sys
sys.path.insert(0, '.')
from core.database import test_connection

async def main():
    try:
        result = await test_connection()
        if result.get('status') == 'healthy':
            print('Database connection successful')
            sys.exit(0)
        else:
            print(f'Database unhealthy: {result}')
            sys.exit(1)
    except Exception as e:
        print(f'Database connection failed: {e}')
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
        " 2>/dev/null; then
            log_success "Database is ready!"
            db_ready=true
            break
        else
            log_warning "Database not ready yet, waiting 2 seconds..."
            sleep 2
            attempt=$((attempt + 1))
        fi
    done
    
    if [ "$db_ready" = false ]; then
        log_error "Database failed to become ready after $max_attempts attempts"
        return 1
    fi
    
    return 0
}

# Function to run schema validation
run_schema_validation() {
    if [ "$STARTUP_VALIDATION_ENABLED" != "true" ]; then
        log_info "Schema validation disabled, skipping..."
        return 0
    fi
    
    log_step "Running comprehensive schema validation..."
    
    # Create validation report directory
    mkdir -p "$VALIDATION_REPORT_DIR"
    
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local report_file="$VALIDATION_REPORT_DIR/startup_validation_$timestamp.json"
    local migration_script="$VALIDATION_REPORT_DIR/startup_migration_$timestamp.sql"
    
    cd "$APP_DIR"
    
    # Run startup validator
    if python3 -m core.startup_validator; then
        log_success "Schema validation passed"
        return 0
    else
        local exit_code=$?
        log_error "Schema validation failed with exit code $exit_code"
        
        # Try to generate migration script for manual review
        log_info "Generating migration script for manual review..."
        if python3 -m core.schema_validator --migration-script "$migration_script" --output "$report_file" 2>/dev/null; then
            log_info "Migration script generated: $migration_script"
            log_info "Validation report saved: $report_file"
        fi
        
        return $exit_code
    fi
}

# Function to run database migrations
run_database_migrations() {
    if [ "$MIGRATION_AUTO_RUN" != "true" ]; then
        log_info "Auto-migration disabled, skipping..."
        return 0
    fi
    
    log_step "Running database migrations..."
    
    cd "$APP_DIR"
    
    # Check migration status first
    log_info "Checking migration status..."
    if python3 -m core.migration_manager --status; then
        log_info "Migration status check completed"
    fi
    
    # Run pending migrations
    log_info "Running pending migrations..."
    if python3 -m core.migration_manager --verbose; then
        log_success "Database migrations completed successfully"
        return 0
    else
        local exit_code=$?
        log_error "Database migration failed with exit code $exit_code"
        return $exit_code
    fi
}

# Function to perform final health checks
run_health_checks() {
    log_step "Running final health checks..."
    
    cd "$APP_DIR"
    
    # Test database connection and pool health
    log_info "Testing database connection and pool health..."
    if python3 -c "
import asyncio
import sys
sys.path.insert(0, '.')
from core.database import get_connection_health

async def main():
    try:
        health = await get_connection_health()
        print(f'Database health status: {health.get(\"connection_test\", {}).get(\"status\", \"unknown\")}')
        
        # Check for critical issues
        pool_status = health.get('pool_status', {})
        if 'error' in pool_status:
            print(f'Pool error: {pool_status[\"error\"]}')
            sys.exit(1)
            
        connection_test = health.get('connection_test', {})
        if connection_test.get('status') != 'healthy':
            print(f'Connection test failed: {connection_test}')
            sys.exit(1)
            
        print('All health checks passed')
        sys.exit(0)
    except Exception as e:
        print(f'Health check failed: {e}')
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
    "; then
        log_success "Database health checks passed"
    else
        log_error "Database health checks failed"
        return 1
    fi
    
    # Check if critical tables exist
    log_info "Verifying critical tables exist..."
    if python3 -c "
import asyncio
import sys
sys.path.insert(0, '.')
from core.database import get_db_session, DatabaseOperation
from sqlalchemy import text

async def main():
    try:
        async with get_db_session(DatabaseOperation.READ) as session:
            # Check for some critical tables
            critical_tables = ['users', 'migration_history']
            
            for table in critical_tables:
                result = await session.execute(text(f'''
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = :table_name
                    );
                '''), {'table_name': table})
                
                exists = result.scalar()
                if not exists:
                    print(f'Critical table missing: {table}')
                    sys.exit(1)
                else:
                    print(f'Table verified: {table}')
            
            print('All critical tables verified')
            sys.exit(0)
    except Exception as e:
        print(f'Table verification failed: {e}')
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
    "; then
        log_success "Critical tables verified"
    else
        log_error "Critical table verification failed"
        return 1
    fi
    
    return 0
}

# Function to create startup success marker
create_startup_marker() {
    local marker_file="/tmp/.devsecurex_startup_success"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat > "$marker_file" << EOF
{
    "startup_completed": true,
    "timestamp": "$timestamp",
    "environment": "$APP_ENV",
    "validation_enabled": $STARTUP_VALIDATION_ENABLED,
    "auto_fix_enabled": $STARTUP_AUTO_FIX_ENABLED,
    "migrations_run": $MIGRATION_AUTO_RUN,
    "version": "1.0.0"
}
EOF
    
    log_success "Startup marker created: $marker_file"
}

# Function to handle startup failure
handle_startup_failure() {
    local step="$1"
    local exit_code="$2"
    
    log_error "🚨 STARTUP FAILED at step: $step (exit code: $exit_code)"
    log_error "Environment: $APP_ENV"
    log_error "Validation enabled: $STARTUP_VALIDATION_ENABLED"
    log_error "Auto-fix enabled: $STARTUP_AUTO_FIX_ENABLED"
    
    # Create failure marker
    local failure_marker="/tmp/.devsecurex_startup_failure"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat > "$failure_marker" << EOF
{
    "startup_failed": true,
    "failed_step": "$step",
    "exit_code": $exit_code,
    "timestamp": "$timestamp",
    "environment": "$APP_ENV",
    "validation_enabled": $STARTUP_VALIDATION_ENABLED,
    "auto_fix_enabled": $STARTUP_AUTO_FIX_ENABLED
}
EOF
    
    # Show help information
    echo ""
    log_error "🔧 TROUBLESHOOTING STEPS:"
    log_error "1. Check validation reports in: $VALIDATION_REPORT_DIR"
    log_error "2. Run manual schema validation: python3 -m core.schema_validator"
    log_error "3. Check migration status: python3 -m core.migration_manager --status"
    log_error "4. Review database connectivity and configuration"
    echo ""
    log_error "🚑 EMERGENCY OPTIONS:"
    log_error "- Disable validation: STARTUP_VALIDATION_ENABLED=false"
    log_error "- Enable auto-fix: STARTUP_AUTO_FIX_ENABLED=true"
    log_error "- Skip migrations: MIGRATION_AUTO_RUN=false"
    
    exit $exit_code
}

# Main startup check function
main() {
    local start_time=$(date +%s)
    
    log_info "🚀 DevSecureX Startup Checks Beginning"
    log_info "Environment: $APP_ENV"
    log_info "Docker: $(is_docker && echo 'Yes' || echo 'No')"
    log_info "Validation enabled: $STARTUP_VALIDATION_ENABLED"
    log_info "Auto-fix enabled: $STARTUP_AUTO_FIX_ENABLED"
    log_info "Auto-migration: $MIGRATION_AUTO_RUN"
    echo ""
    
    # Step 1: Wait for database
    if ! wait_for_database; then
        handle_startup_failure "database_connectivity" 1
    fi
    
    # Step 2: Run database migrations
    if ! run_database_migrations; then
        handle_startup_failure "database_migrations" 2
    fi
    
    # Step 3: Run schema validation
    if ! run_schema_validation; then
        handle_startup_failure "schema_validation" 3
    fi
    
    # Step 4: Final health checks
    if ! run_health_checks; then
        handle_startup_failure "health_checks" 4
    fi
    
    # Calculate startup time
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Check if startup took too long
    if [ $duration -gt $MAX_STARTUP_TIME ]; then
        log_warning "⏰ Startup took ${duration}s (max: ${MAX_STARTUP_TIME}s)"
    fi
    
    # Create success marker
    create_startup_marker
    
    log_success "✅ All startup checks completed successfully! (${duration}s)"
    log_success "🎯 DevSecureX is ready to start"
    
    return 0
}

# Handle script interruption
trap 'log_error "Startup checks interrupted!"; exit 130' INT TERM

# Run main function with error handling
if main "$@"; then
    exit 0
else
    exit_code=$?
    log_error "Startup checks failed with exit code $exit_code"
    exit $exit_code
fi