---
id: T-23
type: Task
title: Konfigurationsprüfung für den Gate-Betrieb
status: offen
milestone: M-3
tags: [gateway, konfiguration]
created: 2026-10-03
---

# T-23 — Konfigurationsprüfung

**Warnungen bzw. Fehler in `konfigpruefung.py`:**
- `login=unsichtbar` + `logout=app` → Warnung: die App ist nach dem nächsten Klick lautlos wieder
  angemeldet, „nur App abmelden“ wirkt praktisch nicht.
- `unsichtbar` bei mehr als einer Anmeldemethode → Fehler.
- Cookie-Domain auf Elterndomain im Gate-Betrieb → Fehler (Sitzung wäre für jede geschützte App lesbar).
- Share-Ausnahme mit Dateiendung statt Präfix → Warnung (wo die Liste in TinySesam bekannt ist).
- Gate-Token-Laufzeit über 15 min → Warnung (Widerrufsverzug).

**Fertig, wenn:** je Regel Test + Mutation.
