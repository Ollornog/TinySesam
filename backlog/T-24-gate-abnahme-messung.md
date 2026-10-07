---
id: T-24
type: Task
title: Abnahme — Messung vorher/nachher und Abnahmetest je App
status: erledigt
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

## Erledigt 2026-10-07

- Messung `scripts/gate_messung.py`, Werte in `docs/BETRIEB.md`. Ehrlich: Bei einzelnen Anfragen spart
  das Gate nur rund 0,3 ms; der Gewinn (Faktor 12–13) entsteht unter Gleichzeitigkeit. Der erste Versuch
  mit einem Python-Client ergab das Gegenteil (Gate langsamer) — er mass den Client. Mit `hey` und einer
  statischen Anwendung stimmt das Bild; der Python-Client ist verworfen.
- Abnahmemuster `deploy/forward-auth/abnahme.sh` (bash + curl, `--path-as-is`), im Caddy-Test gegen den
  Testaufbau gefahren, mit Gegenprobe; 3 Mutationen am Skript rot.
- Header-Spoofing lässt sich von aussen nur als „öffnet nichts“ prüfen. Dass die Anwendung keinen
  fremden `Remote-User` sieht, prüft `tests/test_gate_caddy.py` an der Attrappe.
