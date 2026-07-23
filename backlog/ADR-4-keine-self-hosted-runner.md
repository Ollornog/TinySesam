---
id: ADR-4
type: Decision
title: CI bleibt auf gehosteten Runnern — self-hosted ausgeschlossen
status: erledigt
tags: [ci, sicherheit]
created: 2026-07-10
---

# ADR-4 — CI bleibt auf gehosteten Runnern

## Kontext

Für private Projekte liegt es nahe, eigene Runner zu betreiben. Für dieses **öffentliche** Repo
wurde geprüft, ob das auch hier sinnvoll wäre.

## Entscheidung

**Ausgeschlossen, nicht aufgeschoben.** Die CI läuft auf `ubuntu-latest`.

## Begründung

Bei einem öffentlichen Repo kann jeder einen Fork-PR öffnen, dessen Workflow dann auf fremder
Hardware liefe. Nicht-ephemere Runner sind damit dauerhaft kompromittierbar — GitHub rät
ausdrücklich davon ab.

**Kosten sind kein Gegenargument:** öffentliche Repos haben unbegrenzte Minuten.

## Konsequenzen

- `runs-on: ubuntu-latest` ist hier eine Sicherheitsentscheidung, keine Beiläufigkeit.
- Die Zeile darf nicht auf `self-hosted` wechseln.
