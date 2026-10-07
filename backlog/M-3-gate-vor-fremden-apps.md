---
id: M-3
type: Milestone
title: Gate vor fremden Apps — schnell, einmal anmelden, sauber abmelden
status: erledigt
tags: [gateway, forward-auth, sso]
created: 2026-10-03
---

# M-3 — Gate vor fremden Apps

**Fertig, wenn:** eine fremde App hinter dem Gate ihre Assets ohne TinySesam-Hop lädt, ein Mensch sich
genau einmal anmeldet (beim Provider), wahlweise nur die App oder alles abmeldet, und Share-Pfade ohne
Anmeldung gehen — alles je App einstellbar und mit einem Abnahmetest belegt.

Entscheidung: [ADR-9](ADR-9-gate-token-am-proxy.md). Aufgaben T-19 bis T-24.

## Erledigt 2026-10-07

T-19 bis T-24 und B-2. Offen als Wunsch, ohne Task: ein Icon der Anwendung auf der Login-Seite (T-21),
nginx- und Traefik-Gegenstücke zu `Caddyfile.gate` (ADR-9).
