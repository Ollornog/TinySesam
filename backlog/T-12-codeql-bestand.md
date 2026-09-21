---
id: T-12
type: Task
title: CodeQL-Bestand bewerten und die offenen Alerts im Backlog führen
status: in-arbeit
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

## Offene Alerts (generiert)

<!-- CODEQL:START -->
**51 offen** (1 error, 19 warning, 31 note).

| # | Schwere | Regel | Stelle |
|---|---|---|---|
| [35](https://github.com/Ollornog/TinySesam/security/code-scanning/35) | error | `py/reflective-xss` | `examples/showcase.py:226` |
| [111](https://github.com/Ollornog/TinySesam/security/code-scanning/111) | warning | `py/implicit-string-concatenation-in-list` | `scripts/_backlog.py:77` |
| [126](https://github.com/Ollornog/TinySesam/security/code-scanning/126) | warning | `py/file-not-closed` | `tests/e2e_stage.py:68` |
| [127](https://github.com/Ollornog/TinySesam/security/code-scanning/127) | warning | `py/file-not-closed` | `tests/e2e_stage.py:270` |
| [28](https://github.com/Ollornog/TinySesam/security/code-scanning/28) | warning | `py/incomplete-url-substring-sanitization` | `tests/test_csp.py:72` |
| [29](https://github.com/Ollornog/TinySesam/security/code-scanning/29) | warning | `py/incomplete-url-substring-sanitization` | `tests/test_forward_auth.py:39` |
| [30](https://github.com/Ollornog/TinySesam/security/code-scanning/30) | warning | `py/incomplete-url-substring-sanitization` | `tests/test_gateway.py:44` |
| [20](https://github.com/Ollornog/TinySesam/security/code-scanning/20) | warning | `py/file-not-closed` | `tests/test_packaging.py:128` |
| [21](https://github.com/Ollornog/TinySesam/security/code-scanning/21) | warning | `py/file-not-closed` | `tests/test_packaging.py:148` |
| [22](https://github.com/Ollornog/TinySesam/security/code-scanning/22) | warning | `py/file-not-closed` | `tests/test_packaging.py:225` |
| [31](https://github.com/Ollornog/TinySesam/security/code-scanning/31) | warning | `py/incomplete-url-substring-sanitization` | `tests/test_repo.py:281` |
| [23](https://github.com/Ollornog/TinySesam/security/code-scanning/23) | warning | `py/file-not-closed` | `tests/test_repo.py:327` |
| [128](https://github.com/Ollornog/TinySesam/security/code-scanning/128) | warning | `py/file-not-closed` | `tests/test_security_log.py:39` |
| [110](https://github.com/Ollornog/TinySesam/security/code-scanning/110) | warning | `py/multiple-definition` | `tests/test_sessions_logout.py:68` |
| [24](https://github.com/Ollornog/TinySesam/security/code-scanning/24) | warning | `py/file-not-closed` | `tests/test_sicherheit_befunde.py:571` |
| [25](https://github.com/Ollornog/TinySesam/security/code-scanning/25) | warning | `py/file-not-closed` | `tests/test_sicherheit_befunde.py:574` |
| [130](https://github.com/Ollornog/TinySesam/security/code-scanning/130) | warning | `py/file-not-closed` | `tests/test_site.py:203` |
| [131](https://github.com/Ollornog/TinySesam/security/code-scanning/131) | warning | `py/file-not-closed` | `tests/test_site.py:205` |
| [129](https://github.com/Ollornog/TinySesam/security/code-scanning/129) | warning | `py/file-not-closed` | `tests/test_site.py:210` |
| [132](https://github.com/Ollornog/TinySesam/security/code-scanning/132) | warning | `py/file-not-closed` | `tests/test_site.py:225` |
| [119](https://github.com/Ollornog/TinySesam/security/code-scanning/119) | note | `py/unused-import` | `examples/showcase.py:32` |
| [120](https://github.com/Ollornog/TinySesam/security/code-scanning/120) | note | `py/unused-import` | `examples/showcase.py:35` |
| [121](https://github.com/Ollornog/TinySesam/security/code-scanning/121) | note | `py/unused-import` | `examples/showcase.py:37` |
| [112](https://github.com/Ollornog/TinySesam/security/code-scanning/112) | note | `py/unnecessary-lambda` | `examples/showcase.py:62` |
| [113](https://github.com/Ollornog/TinySesam/security/code-scanning/113) | note | `py/unnecessary-lambda` | `examples/showcase.py:63` |
| [115](https://github.com/Ollornog/TinySesam/security/code-scanning/115) | note | `py/mixed-returns` | `examples/showcase.py:126` |
| [102](https://github.com/Ollornog/TinySesam/security/code-scanning/102) | note | `py/empty-except` | `tests/e2e_stage.py:71` |
| [117](https://github.com/Ollornog/TinySesam/security/code-scanning/117) | note | `py/import-and-import-from` | `tests/test_api_surface.py:24` |
| [19](https://github.com/Ollornog/TinySesam/security/code-scanning/19) | note | `py/unused-import` | `tests/test_audit_runde2.py:13` |
| [104](https://github.com/Ollornog/TinySesam/security/code-scanning/104) | note | `py/empty-except` | `tests/test_browser.py:135` |
| [105](https://github.com/Ollornog/TinySesam/security/code-scanning/105) | note | `py/empty-except` | `tests/test_browser.py:391` |
| [106](https://github.com/Ollornog/TinySesam/security/code-scanning/106) | note | `py/empty-except` | `tests/test_browser.py:396` |
| [118](https://github.com/Ollornog/TinySesam/security/code-scanning/118) | note | `py/import-and-import-from` | `tests/test_hardening2.py:61` |
| [122](https://github.com/Ollornog/TinySesam/security/code-scanning/122) | note | `py/unused-import` | `tests/test_matrix.py:7` |
| [16](https://github.com/Ollornog/TinySesam/security/code-scanning/16) | note | `py/import-and-import-from` | `tests/test_oidc_jwks.py:49` |
| [17](https://github.com/Ollornog/TinySesam/security/code-scanning/17) | note | `py/import-and-import-from` | `tests/test_oidc_jwks.py:120` |
| [123](https://github.com/Ollornog/TinySesam/security/code-scanning/123) | note | `py/unused-import` | `tests/test_security_log.py:8` |
| [124](https://github.com/Ollornog/TinySesam/security/code-scanning/124) | note | `py/unused-import` | `tests/test_site.py:4` |
| [11](https://github.com/Ollornog/TinySesam/security/code-scanning/11) | note | `py/empty-except` | `tinysesam/__main__.py:182` |
| [114](https://github.com/Ollornog/TinySesam/security/code-scanning/114) | note | `py/mixed-returns` | `tinysesam/gateway.py:79` |
| [18](https://github.com/Ollornog/TinySesam/security/code-scanning/18) | note | `py/unused-import` | `tinysesam/manager.py:25` |
| [125](https://github.com/Ollornog/TinySesam/security/code-scanning/125) | note | `py/repeated-import` | `tinysesam/manager.py:295` |
| [116](https://github.com/Ollornog/TinySesam/security/code-scanning/116) | note | `py/mixed-returns` | `tinysesam/manager.py:1703` |
| [103](https://github.com/Ollornog/TinySesam/security/code-scanning/103) | note | `py/empty-except` | `tinysesam/passwords.py:91` |
| [14](https://github.com/Ollornog/TinySesam/security/code-scanning/14) | note | `py/unused-local-variable` | `tinysesam/store.py:611` |
| [12](https://github.com/Ollornog/TinySesam/security/code-scanning/12) | note | `py/empty-except` | `tinysesam/store.py:623` |
| [15](https://github.com/Ollornog/TinySesam/security/code-scanning/15) | note | `py/unused-local-variable` | `tinysesam/store.py:645` |
| [13](https://github.com/Ollornog/TinySesam/security/code-scanning/13) | note | `py/empty-except` | `tinysesam/store.py:656` |
| [107](https://github.com/Ollornog/TinySesam/security/code-scanning/107) | note | `py/unused-local-variable` | `tinysesam/templates.py:437` |
| [108](https://github.com/Ollornog/TinySesam/security/code-scanning/108) | note | `py/unused-local-variable` | `tinysesam/templates.py:473` |
| [109](https://github.com/Ollornog/TinySesam/security/code-scanning/109) | note | `py/unused-local-variable` | `tinysesam/templates.py:495` |
<!-- CODEQL:END -->
