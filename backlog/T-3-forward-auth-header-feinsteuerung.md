---
id: T-3
type: Task
title: Forward-Auth — welche Remote-Header gesetzt werden, konfigurierbar machen
status: offen
milestone: M-1
tags: [forward-auth, konfiguration]
created: 2026-07-10
---

# T-3 — Feinsteuerung der `Remote-*`-Header

Im Forward-Auth-Modus ([ADR-3](ADR-3-in-app-statt-proxy.md)) setzt `/auth/verify` einen festen
Satz `Remote-*`-Header. Nicht jede nachgelagerte Anwendung will alle davon, und manche erwarten
andere Namen.

**Fertig, wenn:** die Auswahl über die Konfiguration steuerbar ist und der Standard unverändert
bleibt (keine stille Verhaltensänderung für Bestandsnutzer).
