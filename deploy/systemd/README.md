# systemd templates

`gc` does **not run on its own** — expired sessions, OIDC flows and one-time tokens otherwise
stay in the database. In gateway operation every aborted sign-in attempt leaves a row behind;
that adds up.

```bash
sudo cp tinysesam-gc.service tinysesam-gc.timer /etc/systemd/system/
sudoedit /etc/systemd/system/tinysesam-gc.service     # adjust User, --db AND ReadWritePaths
sudo systemctl daemon-reload
sudo systemctl enable --now tinysesam-gc.timer
systemctl list-timers tinysesam-gc.timer              # check when it runs
```

**`ReadWritePaths` has to be adjusted too.** The unit runs with `ProtectSystem=strict` — the whole
file system is read-only except for the paths named there. Anyone who changes only `--db` and
keeps the database outside `/var/lib/tinysesam` ends up with a service that cannot open it:
SQLite fails on writing (and needs room for `-wal`/`-shm` next to it). If it lies under `/home`,
`ProtectHome=` has to go as well — `yes` hides `/home` completely, `read-only` is not enough either.

A cron job does the same:

```cron
30 3 * * *  tinysesam  /opt/tinysesam/venv/bin/python -m tinysesam gc --db /var/lib/tinysesam/auth.db
```

**What `gc` does not do:** it does not give disk space back to the file system (SQLite keeps the
pages for later rows). After a large cleanup a one-off `VACUUM` helps, with the service
stopped:

```bash
sqlite3 /var/lib/tinysesam/auth.db 'VACUUM;'
```

The **audit log** is deliberately never cleaned up — it is the chronicle, not working memory. It
contains usernames and IP addresses; anyone who needs a retention period (GDPR) sets it
themselves, e.g. monthly:

```bash
sqlite3 /var/lib/tinysesam/auth.db \
  "DELETE FROM audit WHERE ts < strftime('%s','now','-365 days');"
```
