---
id: M-2
type: Milestone
title: Nach 1.0 — das veröffentlichte Paket gepflegt halten
status: offen
tags: [release, wartung]
created: 2026-09-21
---

# M-2 — Nach 1.0: das veröffentlichte Paket gepflegt halten

**Fertig, wenn:** nichts mehr offen ist, was ein Nutzer des veröffentlichten Pakets merken würde —
weder beim Installieren noch beim Betreiben.

Mit [M-1](M-1-api-stabil-1-0.md) **soll** die Bibliothek auf PyPI gehen
([ADR-6](ADR-6-pypi-veroeffentlichen.md)) — veröffentlicht ist sie noch nicht, und M-1 steht nach
der Reifeprüfung wieder auf `offen`. Ausgeliefert ist 0.18.0 über den gepinnten Git-Tag. Der
Massstab dieses Meilensteins gilt also ab dem Tag der Veröffentlichung: Bis 1.0 heisst er „läuft
im Repo", danach „kommt beim Fremden richtig an". Hier sammeln sich die Punkte, die aus dieser Verschiebung folgen — Fristen des
Bau-Werkzeugs, Lücken, die beim Herrichten für die Veröffentlichung aufgefallen sind, und alles,
was eine Hauptversion kosten würde, wenn es zu spät bemerkt wird.
