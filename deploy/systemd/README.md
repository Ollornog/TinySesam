# systemd-Vorlagen

`gc` läuft **nicht von selbst** — abgelaufene Sitzungen, OIDC-Flows und Einmal-Token bleiben
sonst in der Datenbank stehen. Im Gateway-Betrieb hinterlässt jeder abgebrochene Anmeldeversuch
eine Zeile; das summiert sich.

```bash
sudo cp tinysesam-gc.service tinysesam-gc.timer /etc/systemd/system/
sudoedit /etc/systemd/system/tinysesam-gc.service     # User, --db UND ReadWritePaths anpassen
sudo systemctl daemon-reload
sudo systemctl enable --now tinysesam-gc.timer
systemctl list-timers tinysesam-gc.timer              # nachsehen, wann er läuft
```

**`ReadWritePaths` gehört mit angepasst.** Die Unit fährt `ProtectSystem=strict` — das ganze
Dateisystem ist schreibgeschützt, bis auf die dort genannten Pfade. Wer nur `--db` umstellt und
die Datenbank ausserhalb von `/var/lib/tinysesam` liegen hat, bekommt einen Dienst, der sie nicht
öffnen kann: SQLite scheitert beim Schreiben (und braucht daneben Platz für `-wal`/`-shm`).
Liegt sie unter `/home`, muss zusätzlich `ProtectHome=` weichen — `yes` blendet `/home` komplett
aus, `read-only` reicht ebenfalls nicht.

Ein Cronjob tut es genauso:

```cron
30 3 * * *  tinysesam  /opt/tinysesam/venv/bin/python -m tinysesam gc --db /var/lib/tinysesam/auth.db
```

**Was `gc` nicht tut:** Es gibt keinen Plattenplatz an das Dateisystem zurück (SQLite behält die
Seiten für spätere Zeilen). Nach einem grossen Aufräumen hilft einmalig ein `VACUUM`, bei
gestopptem Dienst:

```bash
sqlite3 /var/lib/tinysesam/auth.db 'VACUUM;'
```

Das **Audit-Log** wird bewusst nie aufgeräumt — es ist die Chronik, nicht Arbeitsspeicher. Es
enthält Benutzernamen und IP-Adressen; wer eine Aufbewahrungsfrist braucht (DSGVO), setzt sie
selbst, z.B. monatlich:

```bash
sqlite3 /var/lib/tinysesam/auth.db \
  "DELETE FROM audit WHERE ts < strftime('%s','now','-365 days');"
```
