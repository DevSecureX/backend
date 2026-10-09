# 🗄️ Database Backup Scripts

All database backup and restore scripts have been organized in the **`db-backup/`** directory.

## 📂 Location
```
scripts/
└── db-backup/
    ├── backups/          # Backup files directory
    ├── backup_db.sh      # Manual backup script
    ├── auto_backup.sh    # Automated backup setup
    ├── restore_db.sh     # Database restore script
    └── README.md         # Complete documentation
```

## 🚀 Quick Commands

### Create Backup
```bash
./scripts/db-backup/backup_db.sh --compress --cleanup
```

### Setup Daily Automated Backup
```bash
./scripts/db-backup/auto_backup.sh setup
```

### Interactive Restore
```bash
./scripts/db-backup/restore_db.sh --interactive
```

## 📖 Full Documentation
For complete usage instructions, examples, and troubleshooting, see:
**[scripts/db-backup/README.md](./db-backup/README.md)**

---
*DevSecureX Database Backup Solution - Protecting your PostgreSQL data with automated, compressed, and verified backups.*