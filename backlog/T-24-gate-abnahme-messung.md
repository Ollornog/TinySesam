---
id: T-24
type: Task
title: Abnahme — Messung vorher/nachher und Abnahmetest je App
status: offen
milestone: M-3
tags: [gateway, messung, test]
created: 2026-10-03
---

# T-24 — Abnahme

- Messung mit einer asset-lastigen Beispielseite: Ladezeit und Zahl der TinySesam-Aufrufe mit
  `/auth/forward` gegen Gate-Token. Ergebnis in `docs/BETRIEB.md`.
- Abnahmetest-Muster je App (Skript/Testvorlage): ungeschützter Pfad → Login; Share-Pfad offen;
  Pfad neben dem Share-Präfix zu; Logout `app`/`alle` wie in T-22; Header-Spoofing (`Remote-User`)
  wirkungslos.

**Fertig, wenn:** Messwerte stehen in der Doku, Abnahmemuster liegt unter `deploy/forward-auth/`.
