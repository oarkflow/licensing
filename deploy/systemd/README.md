# systemd Deployment Notes

Install the backup script at the path expected by the unit:

```bash
install -o root -g root -m 0755 scripts/backup_sqlite.sh /usr/local/bin/licensing-backup-sqlite
install -o root -g root -m 0644 deploy/systemd/licensing-backup.service /etc/systemd/system/licensing-backup.service
install -o root -g root -m 0644 deploy/systemd/licensing-backup.timer /etc/systemd/system/licensing-backup.timer
systemctl daemon-reload
systemctl enable --now licensing-backup.timer
```

Adjust `/var/lib/licensing`, `/var/backups/licensing`, user/group, and service names to match the host deployment.
