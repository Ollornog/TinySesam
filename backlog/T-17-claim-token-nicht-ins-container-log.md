---
id: T-17
type: Task
title: Das Erst-Admin-Einmal-Token nicht ins Container-Log schreiben
status: erledigt
milestone: M-2
tags: [sicherheit, erst-admin, container, betrieb, log]
created: 2026-09-27
---

# T-17 — Claim-Token: stderr ist im Container das Log

**Fund aus dem Betrieb (2026-09-27, Start im Container ohne Admin):** TinySesam schrieb die
Claim-URL mit dem Einmal-Token auf stderr und direkt danach die Zeile „Der Wert steht bewusst NICHT
im Log“. Im Container IST stderr das Log (`docker logs`, jeder Log-Versand) — der Wert stand also
genau dort, zwei Zeilen über der Beteuerung. `admin_claim_token_file` hätte es verhindert, aber
nichts wies darauf hin, und die Vorgabe traf den häufigsten Betrieb.

**Fertig, wenn:** ohne `admin_claim_token_file` und ohne Konsole (`sys.stderr.isatty()` falsch)
das Token in einer Datei mit `0600` neben der Datenbank steht und stderr/das Log nur den Pfad
nennt; der Text ehrlich sagt, wo das Token steht (auch im Rückfall auf stderr bei `:memory:` oder
einer nicht anlegbaren Datei); dasselbe für die Ausgabe im Moment eines IdP-Entzugs (G6); die
Datei nach dem Einlösen verschwindet bzw. nach dem Verfall ungültig ist; Tests für Konsole und
keine Konsole, Rechte, kein Token im Log-Text; Mutation.

## Erledigt 2026-09-27

- `TinySesam._admin_claim_bekanntgeben`: Konsole → stderr wie bisher; keine Konsole →
  `<db_path>.claim` (0600, ohne `O_TRUNC` geöffnet, Rechte am Deskriptor gesetzt, dann
  abgeschnitten — derselbe Weg wie für `admin_claim_token_file`), im Log nur der Pfad. Rückfall
  auf stderr ohne Datenbank-Datei oder wenn die Datei nicht entsteht, dann mit dem Satz, dass der
  Wert im Log des Dienstes steht. `admin_claim_token_file` geht vor, auch an einer Konsole.
- Aufräumen: `_consume_admin_claim` löscht `<db_path>.claim` nach dem Einlösen; ein Start mit
  Admin räumt einen Rest weg. Nach dem Verfall gilt der Inhalt nicht mehr, der nächste Start
  schreibt ein neues Token. Eine selbst gewählte Datei bleibt stehen (Inhalt ungültig).
- Die Ausgabe nach einem IdP-Entzug (G6) läuft durch dieselbe Methode.
- Tests: `tests/test_betriebsfunde.py` (b) — Konsole und Container (stderr und Sicherheits-Log in
  einem Puffer, wie `docker logs`), Rechte 0600, Einlösen aus der Datei, Aufräumen, Verfall,
  `:memory:`, nicht anlegbare Datei, eigene Datei an der Konsole. Angepasst:
  `tests/test_security_log.py` (Konsole ausdrücklich), `tests/test_t13_entscheide.py` (G6 ohne
  Konsole: Datei). Doku: README EN/DE, `docs/BETRIEB.md` („Erst-Admin-Einmal-Token“),
  `KONFIGURATION.md`, fail2ban-Jail, CHANGELOG.
