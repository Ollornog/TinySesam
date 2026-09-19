---
id: T-2
type: Task
title: Browser-Test soll den freien Port nicht selbst suchen
status: erledigt
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

## Erledigt (2026-09-19)

Die Chrome-Hälfte war bereits gebaut (`--remote-debugging-port=0` + `DevToolsActivePort`); offen
blieb der **uvicorn-Testserver**, der denselben Fehler hatte.

Gelöst nicht durch besseres Suchen, sondern indem die Lücke verschwindet: Der Socket wird gebunden
und **gebunden gelassen**, dann an `uvicorn.Server.run(sockets=[...])` übergeben. Zwischen „Port
ermittelt" und „Port belegt" gibt es damit keinen Moment mehr, in dem ihn jemand anders nehmen
könnte. `free_port()` ist ersatzlos fort.

Geprüft mit vier parallelen Läufen der Browser-Suite auf demselben Rechner — alle grün. Ein
direkter Negativtest ist nicht sinnvoll konstruierbar: Race Conditions tauchen selten auf, der
Beleg ist das strukturelle Verschwinden des Fensters.
