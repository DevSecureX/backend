# DevSecureX Database Backup Scripts

This directory contains scripts for backing up and restoring your DevSecureX PostgreSQL database running in Docker.

## Scripts Overview

- **`backup_db.sh`** - Manual backup script
- **`auto_backup.sh`** - Automated backup with cron scheduling
- **`restore_db.sh`** - Database restore script

**Location:** All scripts are located in `scripts/db-backup/` directory.

## Quick Start

### 1. Create a Manual Backup

```bash
# Simple backup
./scripts/db-backup/backup_db.sh

# Compressed backup with cleanup of old backups
./scripts/db-backup/backup_db.sh --compress --cleanup
```

### 2. Setup Automated Backups

```bash
# Daily backup at 2:00 AM (default)
./scripts/db-backup/auto_backup.sh setup

# Twice daily (2:00 AM and 2:00 PM)
./scripts/db-backup/auto_backup.sh setup --twice-daily

# Custom schedule (every 6 hours)
./scripts/db-backup/auto_backup.sh setup --custom "0 */6 * * *"
```

### 3. Restore from Backup

```bash
# Interactive restore (recommended)
./scripts/db-backup/restore_db.sh --interactive

# List available backups
./scripts/db-backup/restore_db.sh --list

# Restore specific backup by number
./scripts/db-backup/restore_db.sh 1
```

## Detailed Usage

### Manual Backup (`backup_db.sh`)

Creates an immediate backup of your database.

**Options:**
- `--compress` - Compress the backup file with gzip
- `--cleanup` - Remove backups older than 7 days
- `--help` - Show help message

**Examples:**
```bash
./scripts/db-backup/backup_db.sh                    # Basic backup
./scripts/db-backup/backup_db.sh --compress         # Compressed backup
./scripts/db-backup/backup_db.sh --compress --cleanup # Compressed + cleanup
```

### Automated Backup (`auto_backup.sh`)

Manages automated backups using cron jobs.

**Commands:**
- `setup` - Setup automated backups
- `remove` - Remove automated backups
- `status` - Show current automation status
- `run` - Run immediate backup
- `logs` - Show recent backup logs

**Setup Options:**
- `--daily` - Daily at 2:00 AM (default)
- `--twice-daily` - 2:00 AM and 2:00 PM
- `--weekly` - Weekly on Sunday at 2:00 AM
- `--custom "CRON"` - Custom cron expression

**Examples:**
```bash
./scripts/db-backup/auto_backup.sh setup                              # Daily backup
./scripts/db-backup/auto_backup.sh setup --twice-daily               # Twice daily
./scripts/db-backup/auto_backup.sh setup --custom "0 */4 * * *"      # Every 4 hours
./scripts/db-backup/auto_backup.sh status                            # Check status
./scripts/db-backup/auto_backup.sh logs                              # View logs
./scripts/db-backup/auto_backup.sh remove                            # Remove automation
```

### Database Restore (`restore_db.sh`)

Restores your database from a backup file.

**Options:**
- `--interactive` - Interactive mode (recommended)
- `--list` - List available backup files
- `--no-safety-backup` - Skip creating safety backup
- `--stop-app` - Stop application containers during restore

**Examples:**
```bash
./scripts/db-backup/restore_db.sh --interactive                      # Interactive restore
./scripts/db-backup/restore_db.sh --list                            # List backups
./scripts/db-backup/restore_db.sh 1                                 # Restore backup #1
./scripts/db-backup/restore_db.sh backup_file.sql.gz                # Restore specific file
```

## Safety Features

### Automatic Safety Backup
Before any restore operation, the script creates a safety backup of your current database (unless `--no-safety-backup` is used).

### Confirmation Prompts
Destructive operations require explicit confirmation to prevent accidental data loss.

### Compression
Backup files can be automatically compressed to save disk space.

### Cleanup
Old backup files (>7 days) can be automatically removed to prevent disk space issues.

## File Locations

- **Backups:** `scripts/db-backup/backups/` directory
- **Logs:** `./logs/backup.log` (for automated backups)
- **Scripts:** `scripts/db-backup/` directory

## Backup File Format

Backup files are named with timestamps:
- `devsecurex_backup_YYYYMMDD_HHMMSS.sql` (uncompressed)
- `devsecurex_backup_YYYYMMDD_HHMMSS.sql.gz` (compressed)

## Troubleshooting

### Container Not Running
If you get "Container not running" error:
```bash
docker-compose up -d
```

### Permission Issues
If scripts are not executable:
```bash
chmod +x scripts/*.sh
```

### Disk Space
Monitor backup directory size and use `--cleanup` option regularly:
```bash
du -sh scripts/db-backup/backups/
```

### Cron Issues
Check if cron service is running:
```bash
# macOS
sudo launchctl list | grep cron

# Linux
sudo service cron status
```

## Configuration

The scripts use these default values (can be modified in script headers):
- **Container:** `devsecurex-db`
- **Database:** `devsecurex_db`
- **User:** `devsecurex_user`
- **Port:** `6544` (mapped to container's 5432)

## Support

If you encounter issues:
1. Check Docker container is running: `docker ps`
2. Verify database connectivity: `docker exec devsecurex-db pg_isready`
3. Check script permissions: `ls -la scripts/`
4. Review backup logs: `tail -f logs/backup.log`