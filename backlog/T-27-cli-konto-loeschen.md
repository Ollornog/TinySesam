---
id: T-27
type: Task
title: CLI-Befehl zum Löschen eines Kontos (Wartung ohne Admin-Panel)
status: offen
milestone: M-2
tags: [cli, wartung, konten, datenschutz]
created: 2026-10-11
---

# T-27 — `python -m tinysesam delete --db <datei> <benutzer>`

**Anlass (PO 2026-10-11):** Ein Abnahmetest mit einem Testkonto gegen eine produktive Instanz hat dort beim
ersten OIDC-Login ein lokales Konto angelegt (Zeile in `users` plus `oidc_identity`). Die Instanz läuft nur mit
OIDC, ohne Admin-Panel und ohne Konto-Seite. Es gab danach **keinen** unterstützten Weg, das Konto wieder zu
entfernen: Die CLI kennt `passwd`, `backup`, `restore`, `gc`, `audit`, `unlock`, `owner`, `rename` und `gate-key`,
aber kein Löschen. Ein rohes `DELETE` in der Datenbank wäre der falsche Weg (Audit-Anonymisierung,
Anmeldeversuche, Namensbindung — siehe `konto_entfernen`). Das Konto blieb deshalb liegen; anmelden kann es
sich nur nicht mehr, weil der IdP-Client es nicht mehr zulässt.

Die Bibliothek kann es längst (B5-08 aus [T-13](T-13-audit-2026-09-22-runde-3.md): `TinySesam.delete_user` →
`Store.konto_entfernen`). Es fehlt nur der Betreiberweg auf der Kommandozeile, genau wie `unlock`/`rename` für
ihre Fälle.

## Zu tun

- Neues Kommando `delete --db <datei> <benutzer>` in `tinysesam/__main__.py`, das über **denselben** Weg wie das
  Panel löscht (`konto_entfernen`, nicht `Store.delete_user` direkt — ein Test hält fest, dass der Rohbaustein
  keinen weiteren Aufrufer hat).
- Dieselben Schutzregeln wie beim Löschen über das Panel (nachsehen, wie es den Owner behandelt, und das hier
  nicht lockerer machen); unbekannter Benutzer → Exit ≠ 0 mit klarer Meldung.
- Bestätigung: interaktiv nachfragen, `--ja` für Skripte. Ausgabe nennt, was entfernt wurde (Name, Anzahl
  Sitzungen/Identitäten), nie Geheimnisse.
- Hilfe-Text, README-Abschnitt „Wartung“ und CHANGELOG mitziehen.

## Fertig, wenn

- Ein Test legt ein OIDC-Konto mit Sitzung an, löscht es per CLI und prüft: Zeilen in `users`, `oidc_identity`,
  `session` weg, Audit-Eintrag anonymisiert wie beim Löschen über das Panel, zweiter Aufruf → Exit ≠ 0.
- Mutation: Kommando auf `Store.delete_user` umgebogen → der Audit-Test wird rot; Schutzregel entfernt → rot.
