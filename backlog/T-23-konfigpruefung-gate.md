---
id: T-23
type: Task
title: Konfigurationsprüfung für den Gate-Betrieb
status: erledigt
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

## Erledigt 2026-10-07

Gegen den gebauten Stand nachgeprüft — drei der geplanten Regeln waren überholt:

- `unsichtbar` + `logout=app` → **keine** Warnung: Die Sperre an der Sitzung (T-22) hält auch mit
  `direct`, die Anwendung zeigt danach die Login-Seite mit „Weiter als …“.
- Cookie-Domain auf der Elterndomain → **kein** Fehler: Das ist das bestehende Forward-Auth-Modell (die
  Vorlagen entfernen die TinySesam-Cookies vor der Anwendung, B-20); der geplante Code-Austausch, für den
  die Regel gedacht war, entfiel mit ADR-9.
- Share-Endungen → entfällt (die Liste steht im Proxy, T-20).
- Schon beim Bau der Funktionen eingebaut (Fehler): `direct` neben anderen Methoden (T-21),
  unbekannte Werte/Schlüssel in `forward_apps` (T-21/T-22), Cookie-Name, Laufzeit, Gate ohne
  Forward-Auth (T-19).

Neu (Warnungen): Laufzeit über 900 s, Gate ohne geschützten Host, `forward_apps` ohne Forward-Auth,
`direct` + Abmelden `all`/`ask` ohne `oidc_rp_logout`. Test `tests/test_konfig_gate.py`, 5 Mutationen rot.
