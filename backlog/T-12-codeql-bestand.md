---
id: T-12
type: Task
title: CodeQL-Bestand bewerten und die offenen Alerts im Backlog führen
status: erledigt
milestone: M-1
tags: [codeql, ci, hygiene, sicherheit]
created: 2026-09-22
---

# T-12 — CodeQL-Bestand

Auf `main` lagen am 2026-09-22 **61 offene CodeQL-Alerts**, die nie jemand bewertet hatte. Sie
tun nichts — bis ein Pull Request eine ihrer Zeilen berührt: Dann stellt CodeQL jeden als
Review-Thread ein, und `main` verlangt aufgelöste Konversationen. Ein `note`-Alert blockiert den
Merge dann genauso wie ein kritischer (so geschehen in #52).

## Was getan wurde

- **Ein echter Fund:** `examples/showcase.py` setzte den Benutzernamen unescaped ins HTML der
  Demo-Seiten `/app` und `/sensibel` (`py/reflective-xss`). Behoben mit `html.escape`.
- **Neun Fehlalarme mit Begründung in GitHub abgewiesen** — nicht hier gestrichen, sonst kämen
  sie beim nächsten Lauf zurück:
  - `py/url-redirection` (2×, `router.py`): Ziel ist ein fester relativer Pfad, der Token wird
    URL-kodiert eingesetzt. Kein Open Redirect.
  - `py/clear-text-logging-sensitive-data` (4× in `security.py`, `manager.py`, `__main__.py`):
    geloggt werden Proxy-IPs, Hostnamen und „Passwort zu kurz“ ohne den Wert.
  - `py/clear-text-logging-sensitive-data` (2×, `tests/_kit/report.py`): der Test-Reporter
    druckt Prüfnamen.
  - `py/weak-sensitive-data-hashing` (`manager.py`): API-Keys sind zufällige Token mit 256 Bit
    Entropie, kein Passwort — ein schneller Hash ist dort der Standard (wie bei Sitzungs-Token).
  - `py/overly-permissive-file` (`tests/test_sicherheit_befunde.py`): der Test legt absichtlich
    eine 0644-Datei an, um die Warnung davor zu prüfen.
- **Rest mechanisch bereinigt:** nicht geschlossene Dateien in Tests, vier URL-Substring-Prüfungen
  in Tests, ungenutzte Importe und Variablen, leere `except`-Blöcke mit Begründung, gemischte
  Rückgaben, doppelte Importe.
- **`scripts/_codeql_backlog.py`** holt die offene Liste über die API und schreibt sie unten
  zwischen die Marker. Damit landen neue Alerts hier — im Repo, im Diff — statt nur im Postfach.
  Die Mail selbst schaltet nur GitHub ab: Repo → Watch → Custom → „Security alerts“ abwählen.

**Fertig, wenn:** die Tabelle unten leer ist oder jeder verbleibende Eintrag hier eine
Bewertung trägt, und die Suite nach der Bereinigung grün ist.

## Erledigt 2026-09-25

Auf `main` ist kein CodeQL-Alert mehr offen (Tabelle unten, frisch erzeugt). Die übrigen wurden
behoben oder mit Begründung in GitHub abgewiesen (u. a. die Test-Apps in `test_csrf.py` und der
Skript-Zerleger in `test_admin.py`, „used in tests"). Neue Alerts meldet CodeQL an jedem PR als
Review-Thread; `scripts/_codeql_backlog.py` bleibt der Weg, den Stand auf `main` hierher zu holen.

## Offene Alerts (generiert)

<!-- CODEQL:START -->
_Keine offenen Alerts._
<!-- CODEQL:END -->
