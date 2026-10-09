#!/bin/bash

# DevSecureX PostgreSQL Backup Script
# This script creates a backup of the PostgreSQL database running in Docker

set -e  # Exit on any error

# Configuration
CONTAINER_NAME="devsecurex-db"
DB_NAME="devsecurex_db"
DB_USER="devsecurex_user"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="devsecurex_backup_${TIMESTAMP}.sql"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if container is running
check_container() {
    if ! docker ps --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
        print_error "Container '${CONTAINER_NAME}' is not running!"
        print_status "Please start the container with: docker-compose up -d"
        exit 1
    fi
}

# Function to create backup directory
create_backup_dir() {
    if [ ! -d "${BACKUP_DIR}" ]; then
        mkdir -p "${BACKUP_DIR}"
        print_status "Created backup directory: ${BACKUP_DIR}"
    fi
}

# Function to create database backup
create_backup() {
    print_status "Starting backup of database '${DB_NAME}' from container '${CONTAINER_NAME}'..."
    
    # Create the backup using pg_dump inside the container with proper escaping
    # Use --inserts and --column-inserts to avoid COPY issues and ensure proper quoting
    # --no-tablespaces prevents tablespace-specific issues
    # --quote-all-identifiers ensures proper identifier quoting
    docker exec -t "${CONTAINER_NAME}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" \
        --verbose \
        --clean \
        --no-owner \
        --no-privileges \
        --no-tablespaces \
        --quote-all-identifiers \
        --inserts \
        --column-inserts \
        --encoding=UTF8 > "${BACKUP_PATH}"
    
    if [ $? -eq 0 ]; then
        # Get backup file size
        BACKUP_SIZE=$(du -h "${BACKUP_PATH}" | cut -f1)
        print_success "Backup created successfully!"
        print_status "Backup file: ${BACKUP_PATH}"
        print_status "Backup size: ${BACKUP_SIZE}"
    else
        print_error "Backup failed!"
        exit 1
    fi
}

# Function to validate backup integrity
validate_backup() {
    print_status "Validating backup integrity..."
    
    # Check if backup file is not empty
    if [ ! -s "${BACKUP_PATH}" ]; then
        print_error "Backup file is empty!"
        return 1
    fi
    
    # Basic SQL syntax validation
    local syntax_errors=0
    
    # Check for common corruption patterns
    if grep -q "''''" "${BACKUP_PATH}"; then
        print_warning "Found potential quote corruption ('''')"
        syntax_errors=$((syntax_errors + 1))
    fi
    
    # Check for incomplete statements
    if tail -n 10 "${BACKUP_PATH}" | grep -q "^\s*$" && ! tail -n 10 "${BACKUP_PATH}" | grep -q "COMMIT"; then
        print_warning "Backup may be incomplete (no COMMIT found at end)"
        syntax_errors=$((syntax_errors + 1))
    fi
    
    # Check for expected table count
    local table_count=$(grep -c "CREATE TABLE" "${BACKUP_PATH}" || echo "0")
    if [ "$table_count" -lt 10 ]; then
        print_warning "Expected more tables in backup (found: $table_count)"
        syntax_errors=$((syntax_errors + 1))
    fi
    
    # Try to validate SQL syntax with PostgreSQL if available
    if command -v psql &> /dev/null; then
        print_status "Performing syntax validation..."
        # Create a test database connection string for syntax checking
        if docker exec -t "${CONTAINER_NAME}" psql -U "${DB_USER}" -d postgres -f /dev/null < "${BACKUP_PATH}" >/dev/null 2>&1; then
            print_success "SQL syntax validation passed"
        else
            print_warning "SQL syntax validation failed - backup may have issues"
            syntax_errors=$((syntax_errors + 1))
        fi
    fi
    
    if [ "$syntax_errors" -eq 0 ]; then
        print_success "Backup validation passed"
        return 0
    else
        print_warning "Backup validation found $syntax_errors potential issues"
        return 1
    fi
}

# Function to compress backup (optional)
compress_backup() {
    if command -v gzip &> /dev/null; then
        print_status "Compressing backup file..."
        gzip "${BACKUP_PATH}"
        BACKUP_PATH="${BACKUP_PATH}.gz"
        BACKUP_SIZE=$(du -h "${BACKUP_PATH}" | cut -f1)
        print_success "Backup compressed successfully!"
        print_status "Compressed backup: ${BACKUP_PATH}"
        print_status "Compressed size: ${BACKUP_SIZE}"
    else
        print_warning "gzip not available, backup will remain uncompressed"
    fi
}

# Function to clean old backups (keep last 7 days)
cleanup_old_backups() {
    if [ "$1" = "--cleanup" ]; then
        print_status "Cleaning up old backups (keeping last 7 days)..."
        find "${BACKUP_DIR}" -name "devsecurex_backup_*.sql*" -type f -mtime +7 -delete
        print_success "Old backups cleaned up!"
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --cleanup     Clean up backups older than 7 days"
    echo "  --compress    Compress the backup file with gzip"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Create a basic backup"
    echo "  $0 --compress         # Create and compress backup"
    echo "  $0 --cleanup          # Create backup and clean old ones"
    echo "  $0 --compress --cleanup # Create compressed backup and clean old ones"
}

# Main execution
main() {
    local compress_flag=false
    local cleanup_flag=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --compress)
                compress_flag=true
                shift
                ;;
            --cleanup)
                cleanup_flag=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    print_status "DevSecureX Database Backup Script"
    print_status "=================================="
    
    # Execute backup steps
    check_container
    create_backup_dir
    create_backup
    
    # Validate backup before compression
    validate_backup
    if [ $? -ne 0 ]; then
        print_error "Backup validation failed! Please check the backup manually."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_error "Backup process aborted due to validation failure"
            exit 1
        fi
    fi
    
    if [ "$compress_flag" = true ]; then
        compress_backup
    fi
    
    if [ "$cleanup_flag" = true ]; then
        cleanup_old_backups --cleanup
    fi
    
    print_success "Backup process completed successfully!"
    print_status "Backup location: ${BACKUP_PATH}"
}

# Handle script interruption
trap 'print_error "Backup process interrupted!"; exit 1' INT TERM

# Run main function with all arguments
main "$@"