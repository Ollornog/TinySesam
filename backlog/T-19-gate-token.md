---
id: T-19
type: Task
title: Gate-Token ausstellen — JWKS, Code-Austausch über /.sesam/*, Caddy-Beispiel mit caddy-jwt
status: offen
milestone: M-3
tags: [gateway, jwt, caddy, cookies]
created: 2026-10-03
---

# T-19 — Gate-Token

Kern von [ADR-9](ADR-9-gate-token-am-proxy.md).

**Zu tun:**
- Schlüsselpaar des Gateways (Rotation mit Überlappung), Ausgabe als JWKS.
- `/.sesam/refresh` (auf dem App-Host, vom Proxy an TinySesam geleitet) → Gateway prüft Sitzung,
  Freigabe je App, Rollen → Einmal-Code (kurz, einmal einlösbar, an den Host gebunden) →
  `/.sesam/callback` setzt das Gate-Cookie host-only. Rücksprungziel gegen `trusted_redirect_hosts`.
- Claims: `iss`, `aud` = Host, `sub`, `exp`, Rollen; Laufzeit einstellbar (Vorgabe 5 min).
- `deploy/forward-auth/`: Caddyfile-Beispiel mit `caddy-jwt` (`from_cookies`, Whitelists,
  `handle_errors 401` → 307), Gate-Cookie per `header_up Cookie` entfernen, `Remote-User` vom Client
  immer entfernen, optional aus Claims setzen. Dockerfile-Zeile für `xcaddy --with`.
- `/auth/forward` bleibt unverändert als Weg ohne Plugin.

**Fertig, wenn:** Browser-Test: erste Anfrage → Gateway → zurück mit Cookie; danach N Asset-Requests
ohne einen einzigen Aufruf bei TinySesam (gezählt); abgelaufenes Token → 307 → neues Token, POST
behält den Body; Token für Host A wird auf Host B abgewiesen; die App sieht weder Gate-Cookie noch
TinySesam-Sitzung; Mutation je Prüfung.
