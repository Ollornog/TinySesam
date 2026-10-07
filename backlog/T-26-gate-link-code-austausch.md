---
id: T-26
type: Task
title: Zentrales Gateway mit Code-Austausch — Sitzung bleibt auf dem Gateway, App-Hosts bekommen nur eine eigene Verbindung
status: erledigt
milestone: M-3
tags: [gateway, cookies, sicherheit]
created: 2026-10-07
---

# T-26 — Code-Austausch für ein zentrales Gateway

**Anlass (PO 2026-10-07):** Ein TinySesam soll zentral viele Apps schützen. Mit `cookie_domain` auf der
Elterndomain erreichte das Sitzungs-Cookie jede App darunter — auch über einen Weg am Proxy vorbei (Mesh,
Split-DNS) —, und eine App, der man nicht traut, hätte damit die Tür zu allen anderen. PO-Entscheid: der
sichere Weg, nicht das gemeinsame Cookie. Damit kommt der Code-Austausch aus dem ersten Entwurf von
[ADR-9](ADR-9-gate-token-am-proxy.md) zurück, den T-19 als „nicht nötig“ gestrichen hatte — für ein Gateway
je App-Host stimmte das, für ein zentrales nicht.

## Erledigt 2026-10-07

- `gate_link_enabled`, Tabelle `gate_link` (Schema 14), Wege `/.tinysesam/start`, `/auth/gate/authorize`,
  `/.tinysesam/callback`; `/auth/forward`, Abmelden und „Weiter als …“ lesen die Verbindung.
- Test `tests/test_gate_link.py` mit zwei getrennten Cookie-Speichern je Host (17 Prüfungen), 10 Mutationen
  rot (Host-Bindung der Verbindung, Bindung und Host des Codes, Einmaligkeit, `rd`, „nur hier abgemeldet“,
  überall abmelden, Rotation, Link-Modus der Anmelde-URL, Konfigurationsprüfung).
- Nicht durch einen echten Caddy gefahren: Die neuen Wege liegen unter `/.tinysesam/*`, das die Vorlagen schon
  an TinySesam reichen (dort durch Caddy gemessen); der Ablauf über zwei Hosts folgt beim ersten Ausrollen
  (Abnahme mit `deploy/forward-auth/abnahme.sh`).
