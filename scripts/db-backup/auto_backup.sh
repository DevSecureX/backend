#!/bin/bash

# DevSecureX Automated Backup Script
# This script sets up automated backups using cron and can be run manually for immediate automated backups

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_SCRIPT="${SCRIPT_DIR}/backup_db.sh"
CRON_JOB_COMMENT="# DevSecureX Database Auto Backup"
PROJECT_DIR="$(dirname "$(dirname "${SCRIPT_DIR}")")"

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

# Function to check if backup script exists
check_backup_script() {
    if [ ! -f "${BACKUP_SCRIPT}" ]; then
        print_error "Backup script not found: ${BACKUP_SCRIPT}"
        print_status "Please ensure backup_db.sh exists in the scripts directory"
        exit 1
    fi
    
    if [ ! -x "${BACKUP_SCRIPT}" ]; then
        print_warning "Making backup script executable..."
        chmod +x "${BACKUP_SCRIPT}"
    fi
}

# Function to run immediate backup
run_immediate_backup() {
    print_status "Running immediate backup..."
    "${BACKUP_SCRIPT}" --compress --cleanup
    print_success "Immediate backup completed!"
}

# Function to setup cron job
setup_cron() {
    local schedule="$1"
    local cron_command
    
    # Create the cron command with full paths
    cron_command="cd ${PROJECT_DIR} && ${BACKUP_SCRIPT} --compress --cleanup >> ${PROJECT_DIR}/logs/backup.log 2>&1"
    
    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -q "${BACKUP_SCRIPT}"; then
        print_warning "Cron job already exists. Removing old one..."
        crontab -l 2>/dev/null | grep -v "${BACKUP_SCRIPT}" | crontab -
    fi
    
    # Add new cron job
    print_status "Setting up cron job with schedule: ${schedule}"
    (crontab -l 2>/dev/null; echo "${CRON_JOB_COMMENT}"; echo "${schedule} ${cron_command}") | crontab -
    
    print_success "Cron job setup successfully!"
    print_status "Backup will run automatically according to schedule: ${schedule}"
}

# Function to remove cron job
remove_cron() {
    if crontab -l 2>/dev/null | grep -q "${BACKUP_SCRIPT}"; then
        print_status "Removing existing cron job..."
        crontab -l 2>/dev/null | grep -v -e "${BACKUP_SCRIPT}" -e "${CRON_JOB_COMMENT}" | crontab -
        print_success "Cron job removed successfully!"
    else
        print_warning "No existing cron job found"
    fi
}

# Function to show current cron jobs
show_cron() {
    print_status "Current cron jobs:"
    if crontab -l 2>/dev/null | grep -A1 -B1 "${BACKUP_SCRIPT}"; then
        echo ""
        print_status "DevSecureX backup cron job is active"
    else
        print_warning "No DevSecureX backup cron job found"
    fi
}

# Function to create log directory
setup_logging() {
    local log_dir="${PROJECT_DIR}/logs"
    if [ ! -d "${log_dir}" ]; then
        mkdir -p "${log_dir}"
        print_status "Created log directory: ${log_dir}"
    fi
    
    # Create initial log file
    local log_file="${log_dir}/backup.log"
    if [ ! -f "${log_file}" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - DevSecureX backup log initialized" > "${log_file}"
        print_status "Created log file: ${log_file}"
    fi
}

# Function to show usage
show_usage() {
    echo "DevSecureX Automated Backup Script"
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  setup     Setup automated backups with cron"
    echo "  remove    Remove cron job for automated backups"
    echo "  status    Show current cron job status"
    echo "  run       Run immediate backup"
    echo "  logs      Show recent backup logs"
    echo ""
    echo "Setup Options (use with 'setup' command):"
    echo "  --daily       Daily backup at 2:00 AM (default)"
    echo "  --twice-daily Backup twice a day (2:00 AM and 2:00 PM)"
    echo "  --weekly      Weekly backup (Sunday at 2:00 AM)"
    echo "  --custom CRON Custom cron schedule (e.g., '0 */6 * * *' for every 6 hours)"
    echo ""
    echo "Examples:"
    echo "  $0 setup                              # Daily backup at 2:00 AM"
    echo "  $0 setup --twice-daily               # Backup at 2:00 AM and 2:00 PM"
    echo "  $0 setup --custom '0 */4 * * *'      # Every 4 hours"
    echo "  $0 run                               # Run backup now"
    echo "  $0 status                            # Check cron status"
    echo "  $0 remove                            # Remove automated backup"
    echo "  $0 logs                              # Show backup logs"
}

# Function to show logs
show_logs() {
    local log_file="${PROJECT_DIR}/logs/backup.log"
    if [ -f "${log_file}" ]; then
        print_status "Recent backup logs (last 50 lines):"
        echo ""
        tail -50 "${log_file}"
    else
        print_warning "No backup logs found"
    fi
}

# Main function
main() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 0
    fi
    
    local command="$1"
    shift
    
    case "${command}" in
        "setup")
            print_status "DevSecureX Automated Backup Setup"
            print_status "=================================="
            
            check_backup_script
            setup_logging
            
            # Parse setup options
            local schedule="0 2 * * *"  # Default: daily at 2:00 AM
            
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --daily)
                        schedule="0 2 * * *"
                        print_status "Schedule: Daily at 2:00 AM"
                        shift
                        ;;
                    --twice-daily)
                        schedule="0 2,14 * * *"
                        print_status "Schedule: Twice daily at 2:00 AM and 2:00 PM"
                        shift
                        ;;
                    --weekly)
                        schedule="0 2 * * 0"
                        print_status "Schedule: Weekly on Sunday at 2:00 AM"
                        shift
                        ;;
                    --custom)
                        if [ -n "$2" ]; then
                            schedule="$2"
                            print_status "Schedule: Custom - $2"
                            shift 2
                        else
                            print_error "Custom schedule requires a cron expression"
                            exit 1
                        fi
                        ;;
                    *)
                        print_error "Unknown option: $1"
                        show_usage
                        exit 1
                        ;;
                esac
            done
            
            setup_cron "${schedule}"
            print_status "Logs will be written to: ${PROJECT_DIR}/logs/backup.log"
            ;;
            
        "remove")
            print_status "Removing Automated Backup"
            print_status "=========================="
            remove_cron
            ;;
            
        "status")
            print_status "Automated Backup Status"
            print_status "======================="
            show_cron
            ;;
            
        "run")
            print_status "Running Manual Backup"
            print_status "===================="
            check_backup_script
            run_immediate_backup
            ;;
            
        "logs")
            show_logs
            ;;
            
        "help"|"--help")
            show_usage
            ;;
            
        *)
            print_error "Unknown command: ${command}"
            show_usage
            exit 1
            ;;
    esac
}

# Handle script interruption
trap 'print_error "Script interrupted!"; exit 1' INT TERM

# Run main function with all arguments
main "$@"