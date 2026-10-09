#!/bin/bash

# DevSecureX PostgreSQL Restore Script
# This script restores a backup of the PostgreSQL database running in Docker

set -e  # Exit on any error

# Configuration
CONTAINER_NAME="devsecurex-db"
DB_NAME="devsecurex_db"
DB_USER="devsecurex_user"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/backups"

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

# Function to list available backups
list_backups() {
    print_status "Available backup files in ${BACKUP_DIR}:"
    echo ""
    
    if [ ! -d "${BACKUP_DIR}" ]; then
        print_error "Backup directory '${BACKUP_DIR}' does not exist!"
        exit 1
    fi
    
    local backup_files=($(find "${BACKUP_DIR}" -name "devsecurex_backup_*.sql*" -type f | sort -r))
    
    if [ ${#backup_files[@]} -eq 0 ]; then
        print_warning "No backup files found in ${BACKUP_DIR}"
        print_status "Please create a backup first using: ./scripts/backup_db.sh"
        exit 1
    fi
    
    local i=1
    for backup in "${backup_files[@]}"; do
        local filename=$(basename "${backup}")
        local size=$(du -h "${backup}" | cut -f1)
        local date=$(stat -f %Sm -t "%Y-%m-%d %H:%M:%S" "${backup}" 2>/dev/null || stat -c %y "${backup}" 2>/dev/null | cut -d' ' -f1-2)
        printf "%2d. %-40s (%s) - %s\n" "$i" "$filename" "$size" "$date"
        ((i++))
    done
    
    echo ""
    return 0
}

# Function to get backup file path
get_backup_file() {
    local selection="$1"
    local backup_files=($(find "${BACKUP_DIR}" -name "devsecurex_backup_*.sql*" -type f | sort -r))
    
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        # Selection by number
        local index=$((selection - 1))
        if [ $index -ge 0 ] && [ $index -lt ${#backup_files[@]} ]; then
            echo "${backup_files[$index]}"
        else
            print_error "Invalid selection number: $selection"
            exit 1
        fi
    else
        # Direct file path
        if [ -f "$selection" ]; then
            echo "$selection"
        elif [ -f "${BACKUP_DIR}/$selection" ]; then
            echo "${BACKUP_DIR}/$selection"
        else
            print_error "Backup file not found: $selection"
            exit 1
        fi
    fi
}

# Function to decompress backup if needed
prepare_backup_file() {
    local backup_file="$1"
    local temp_file=""
    
    if [[ "$backup_file" == *.gz ]]; then
        print_status "Decompressing backup file..."
        temp_file="/tmp/$(basename "${backup_file}" .gz)"
        gunzip -c "$backup_file" > "$temp_file"
        echo "$temp_file"
    else
        echo "$backup_file"
    fi
}

# Function to create database backup before restore (safety)
create_safety_backup() {
    if [ "$1" != "--no-safety-backup" ]; then
        local safety_backup_file="${BACKUP_DIR}/safety_backup_$(date +"%Y%m%d_%H%M%S").sql"
        print_warning "Creating safety backup before restore..."
        
        docker exec -t "${CONTAINER_NAME}" pg_dump -U "${DB_USER}" -d "${DB_NAME}" \
            --clean --no-owner --no-privileges --no-tablespaces \
            --quote-all-identifiers --inserts --column-inserts --encoding=UTF8 > "${safety_backup_file}"
        
        if [ $? -eq 0 ]; then
            print_success "Safety backup created: ${safety_backup_file}"
        else
            print_error "Failed to create safety backup!"
            read -p "Continue without safety backup? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
}

# Function to stop application containers (optional)
stop_app_containers() {
    if [ "$1" = "--stop-app" ]; then
        print_status "Stopping application containers..."
        docker-compose stop backend 2>/dev/null || true
        print_success "Application containers stopped"
    fi
}

# Function to start application containers
start_app_containers() {
    if [ "$1" = "--stop-app" ]; then
        print_status "Starting application containers..."
        docker-compose up -d backend 2>/dev/null || true
        print_success "Application containers started"
    fi
}

# Function to validate backup before restore
validate_backup_file() {
    local backup_file="$1"
    print_status "Validating backup file before restore..."
    
    # Check if backup file exists and is not empty
    if [ ! -s "$backup_file" ]; then
        print_error "Backup file is empty or doesn't exist: $backup_file"
        return 1
    fi
    
    # Check for common corruption patterns
    local corruption_found=false
    
    if grep -q "''''" "$backup_file"; then
        print_warning "Found potential quote corruption ('''')"
        corruption_found=true
    fi
    
    # Check for incomplete SQL
    if ! tail -n 5 "$backup_file" | grep -q -E "(COMMIT|\\\\\\.|--|$)"; then
        print_warning "Backup may be incomplete (no proper ending)"
        corruption_found=true
    fi
    
    # Check for expected table structures
    local table_count=$(grep -c "CREATE TABLE" "$backup_file" || echo "0")
    if [ "$table_count" -lt 5 ]; then
        print_warning "Backup contains fewer tables than expected ($table_count found)"
        corruption_found=true
    fi
    
    if [ "$corruption_found" = true ]; then
        print_warning "Backup validation found potential issues!"
        read -p "Continue with restore anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    else
        print_success "Backup file validation passed"
    fi
    
    return 0
}

# Function to restore database
restore_database() {
    local backup_file="$1"
    local restore_file=$(prepare_backup_file "$backup_file")
    
    # Validate backup before restore
    if ! validate_backup_file "$restore_file"; then
        print_error "Backup validation failed, aborting restore"
        return 1
    fi
    
    print_status "Restoring database from: $(basename "$backup_file")"
    print_warning "This will replace all current data in the database!"
    
    # Perform the restore with better error handling
    docker exec -i "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" \
        --set ON_ERROR_STOP=on \
        --single-transaction < "$restore_file"
    
    if [ $? -eq 0 ]; then
        print_success "Database restored successfully!"
    else
        print_error "Database restore failed!"
        exit 1
    fi
    
    # Clean up temporary decompressed file
    if [ "$restore_file" != "$backup_file" ]; then
        rm -f "$restore_file"
    fi
}

# Function to verify restore
verify_restore() {
    print_status "Verifying database restore..."
    
    # Check if we can connect and get basic table count
    local table_count=$(docker exec -t "${CONTAINER_NAME}" psql -U "${DB_USER}" -d "${DB_NAME}" -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' \n\r')
    
    if [ "$table_count" -gt 0 ]; then
        print_success "Restore verification passed - found $table_count tables"
    else
        print_warning "Restore verification: No tables found or connection failed"
    fi
}

# Function to show usage
show_usage() {
    echo "DevSecureX Database Restore Script"
    echo "Usage: $0 [OPTIONS] [BACKUP_FILE_OR_NUMBER]"
    echo ""
    echo "Options:"
    echo "  --list                List available backup files"
    echo "  --interactive        Interactive mode to select backup file"
    echo "  --no-safety-backup   Skip creating safety backup before restore"
    echo "  --stop-app          Stop application containers during restore"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --list                              # List available backups"
    echo "  $0 --interactive                       # Interactive restore"
    echo "  $0 1                                   # Restore using backup #1 from list"
    echo "  $0 devsecurex_backup_20241227_143022.sql.gz  # Restore specific file"
    echo "  $0 --stop-app ./backups/my_backup.sql  # Stop app and restore"
    echo ""
    echo "Safety Features:"
    echo "  - Creates a safety backup before restore (unless --no-safety-backup)"
    echo "  - Confirms destructive operations"
    echo "  - Verifies restore success"
}

# Function for interactive mode
interactive_mode() {
    print_status "Interactive Restore Mode"
    print_status "======================="
    echo ""
    
    list_backups
    
    echo ""
    read -p "Select backup number to restore (or 'q' to quit): " selection
    
    if [ "$selection" = "q" ] || [ "$selection" = "Q" ]; then
        print_status "Restore cancelled by user"
        exit 0
    fi
    
    if ! [[ "$selection" =~ ^[0-9]+$ ]]; then
        print_error "Please enter a valid number or 'q' to quit"
        exit 1
    fi
    
    local backup_file=$(get_backup_file "$selection")
    local backup_name=$(basename "$backup_file")
    
    echo ""
    print_warning "You are about to restore from: $backup_name"
    print_warning "This will REPLACE all current data in the database!"
    echo ""
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirmation
    
    if [ "$confirmation" != "yes" ]; then
        print_status "Restore cancelled by user"
        exit 0
    fi
    
    echo "$backup_file"
}

# Main function
main() {
    local backup_file=""
    local interactive_flag=false
    local list_flag=false
    local no_safety_backup=""
    local stop_app=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --list)
                list_flag=true
                shift
                ;;
            --interactive)
                interactive_flag=true
                shift
                ;;
            --no-safety-backup)
                no_safety_backup="--no-safety-backup"
                shift
                ;;
            --stop-app)
                stop_app="--stop-app"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                if [ -z "$backup_file" ]; then
                    backup_file="$1"
                else
                    print_error "Multiple backup files specified"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Handle list mode
    if [ "$list_flag" = true ]; then
        list_backups
        exit 0
    fi
    
    print_status "DevSecureX Database Restore Script"
    print_status "=================================="
    
    # Check prerequisites
    check_container
    
    # Handle interactive mode
    if [ "$interactive_flag" = true ]; then
        backup_file=$(interactive_mode)
    elif [ -z "$backup_file" ]; then
        print_error "No backup file specified"
        show_usage
        exit 1
    else
        backup_file=$(get_backup_file "$backup_file")
    fi
    
    # Confirm the restore operation
    if [ "$interactive_flag" != true ]; then
        local backup_name=$(basename "$backup_file")
        echo ""
        print_warning "You are about to restore from: $backup_name"
        print_warning "This will REPLACE all current data in the database!"
        echo ""
        read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirmation
        
        if [ "$confirmation" != "yes" ]; then
            print_status "Restore cancelled by user"
            exit 0
        fi
    fi
    
    # Execute restore process
    echo ""
    create_safety_backup "$no_safety_backup"
    stop_app_containers "$stop_app"
    
    restore_database "$backup_file"
    verify_restore
    
    start_app_containers "$stop_app"
    
    print_success "Database restore completed successfully!"
}

# Handle script interruption
trap 'print_error "Restore process interrupted!"; exit 1' INT TERM

# Run main function with all arguments
main "$@"