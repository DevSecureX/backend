#!/bin/sh

# DevSecureX Enhanced Entrypoint Script
# Now includes comprehensive startup validation and schema checking

# Configuration
APP_ENV="${APP_ENV:-production}"
PORT="${PORT:-8000}"
STARTUP_VALIDATION_ENABLED="${STARTUP_VALIDATION_ENABLED:-true}"
STARTUP_AUTO_FIX_ENABLED="${STARTUP_AUTO_FIX_ENABLED:-false}"
STARTUP_BLOCK_ON_CRITICAL="${STARTUP_BLOCK_ON_CRITICAL:-true}"
STARTUP_BLOCK_ON_ERRORS="${STARTUP_BLOCK_ON_ERRORS:-true}"
MIGRATION_AUTO_RUN="${MIGRATION_AUTO_RUN:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[ENTRYPOINT INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_success() {
    echo -e "${GREEN}[ENTRYPOINT SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_warning() {
    echo -e "${YELLOW}[ENTRYPOINT WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[ENTRYPOINT ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

# Function to show environment info (security-conscious)
show_environment_info() {
    log_info "🌍 Environment Information:"
    log_info "  APP_ENV: $APP_ENV"
    log_info "  PORT: $PORT"
    log_info "  DATABASE_URL: ${DATABASE_URL:0:30}..." # Show first 30 chars for debugging
    log_info "  REDIS_URL: ${REDIS_URL:0:30}..."
    log_info ""
    log_info "🔧 Startup Configuration:"
    log_info "  Validation enabled: $STARTUP_VALIDATION_ENABLED"
    log_info "  Auto-fix enabled: $STARTUP_AUTO_FIX_ENABLED" 
    log_info "  Block on critical: $STARTUP_BLOCK_ON_CRITICAL"
    log_info "  Block on errors: $STARTUP_BLOCK_ON_ERRORS"
    log_info "  Auto-migration: $MIGRATION_AUTO_RUN"
    echo ""
}

# Function to run startup checks
run_startup_checks() {
    if [ "$STARTUP_VALIDATION_ENABLED" != "true" ]; then
        log_info "⏭️ Startup validation disabled, skipping checks"
        return 0
    fi
    
    log_info "🔍 Running DevSecureX startup validation..."
    
    # Check if startup checks script exists
    STARTUP_SCRIPT="/app/../scripts/startup_checks.sh"
    
    if [ -f "$STARTUP_SCRIPT" ]; then
        log_info "📋 Found startup checks script, executing..."
        
        # Make sure it's executable
        chmod +x "$STARTUP_SCRIPT" 2>/dev/null || true
        
        # Run startup checks with timeout to prevent hanging
        if timeout 300 "$STARTUP_SCRIPT"; then
            log_success "✅ Startup validation completed successfully"
            return 0
        else
            local exit_code=$?
            log_error "❌ Startup validation failed (exit code: $exit_code)"
            
            # Check if we should block startup
            if [ "$exit_code" -eq 124 ]; then
                log_error "⏰ Startup validation timed out (5 minutes)"
            fi
            
            # Show startup failure marker if it exists
            if [ -f "/tmp/.devsecurex_startup_failure" ]; then
                log_error "📄 Startup failure details:"
                cat "/tmp/.devsecurex_startup_failure" | head -10
            fi
            
            return $exit_code
        fi
    else
        log_warning "⚠️ Startup checks script not found at $STARTUP_SCRIPT"
        log_warning "Running basic database connectivity check..."
        
        # Fallback: basic database test
        if python3 -c "
import asyncio
import sys
sys.path.insert(0, '/app')
from core.database import test_connection

async def main():
    try:
        result = await test_connection()
        if result.get('status') == 'healthy':
            print('✅ Basic database connectivity check passed')
            sys.exit(0)
        else:
            print(f'❌ Database connectivity check failed: {result}')
            sys.exit(1)
    except Exception as e:
        print(f'❌ Database connectivity check error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
        "; then
            log_success "✅ Basic database connectivity confirmed"
            return 0
        else
            log_error "❌ Basic database connectivity check failed"
            return 1
        fi
    fi
}

# Function to handle startup failure
handle_startup_failure() {
    local exit_code="$1"
    
    log_error "🚨 STARTUP VALIDATION FAILED (exit code: $exit_code)"
    log_error ""
    log_error "🔧 Possible solutions:"
    log_error "1. Check database connectivity and schema"
    log_error "2. Review validation logs in /tmp/devsecurex-validation/"
    log_error "3. Enable auto-fix: STARTUP_AUTO_FIX_ENABLED=true"
    log_error "4. Disable validation (not recommended): STARTUP_VALIDATION_ENABLED=false"
    log_error ""
    
    # In development, we might want to start anyway with warnings
    if [ "$APP_ENV" = "development" ] || [ "$APP_ENV" = "local" ]; then
        log_warning "⚠️ Development environment detected"
        log_warning "Starting application despite validation failure"
        log_warning "🚨 THIS IS NOT RECOMMENDED FOR PRODUCTION!"
        return 0
    fi
    
    # In production, exit with failure
    log_error "❌ Blocking application startup due to validation failure"
    log_error "🛑 Application will not start until issues are resolved"
    exit $exit_code
}

# Function to start the application
start_application() {
    log_success "🎯 All startup checks passed - starting FastAPI application"
    log_info "🚀 Starting on port $PORT with environment: $APP_ENV"
    
    # Create startup success marker
    echo "{\"startup_success\": true, \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"environment\": \"$APP_ENV\"}" > /tmp/.devsecurex_startup_success
    
    # Start the FastAPI application with enhanced configuration
    if [ "$APP_ENV" = "development" ] || [ "$APP_ENV" = "local" ]; then
        # Development mode with reload
        log_info "🔄 Development mode: enabling auto-reload"
        exec uvicorn main:app --host 0.0.0.0 --port $PORT --reload --log-level debug
    else
        # Production mode with optimized settings
        log_info "⚡ Production mode: optimized for performance"
        exec uvicorn main:app \
            --host 0.0.0.0 \
            --port $PORT \
            --workers ${UVICORN_WORKERS:-1} \
            --worker-class uvicorn.workers.UvicornWorker \
            --limit-concurrency ${UVICORN_LIMIT_CONCURRENCY:-100} \
            --timeout-keep-alive ${UVICORN_TIMEOUT_KEEP_ALIVE:-5} \
            --log-level info \
            --access-log \
            --no-use-colors
    fi
}

# Main execution flow
main() {
    echo ""
    log_info "🚀 DevSecureX Backend Starting..."
    log_info "=================================="
    echo ""
    
    # Show environment information
    show_environment_info
    
    # Run startup checks
    if run_startup_checks; then
        log_success "✅ Startup validation completed successfully"
    else
        handle_startup_failure $?
    fi
    
    # Start the application
    start_application
}

# Handle script interruption gracefully
trap 'log_error "Entrypoint interrupted!"; exit 130' INT TERM

# Run main function
main "$@"