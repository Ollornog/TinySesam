---
id: T-2
type: Task
title: Browser-Test soll den freien Port nicht selbst suchen
status: offen
milestone: M-1
tags: [testing, browser, flaky]
created: 2026-07-10
---

# T-2 — Freien Port nicht selbst suchen

`tests/test_browser.py: free_port()` bindet einen Port, schließt ihn und gibt die Nummer zurück.
**Dazwischen kann ein anderer Prozess ihn belegen** — eine klassische Race Condition, die den Test
selten und unerklärlich rot macht.

## Lösung

Chrome mit `--remote-debugging-port=0` starten und die tatsächliche Nummer aus `DevToolsActivePort`
im Profilverzeichnis lesen. In einem Schwesterprojekt bewährt.

**Fertig, wenn:** `free_port()` entfällt und die Suite auch bei parallelen Läufen grün bleibt.
