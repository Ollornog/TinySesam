---
id: T-19
type: Task
title: Gate-Token ausstellen und durch einen echten Caddy mit caddy-jwt belegen
status: erledigt
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

## Erledigt 2026-10-07

Der Code-Austausch über `/.sesam/*` ist entfallen: Das Token entsteht auf dem Rückweg in
`/auth/forward` (Begründung in [ADR-9](ADR-9-gate-token-am-proxy.md)). JWKS ebenso — `caddy-jwt`
nimmt bei EdDSA den Schlüssel direkt, eine Rotation mit Überlappung gibt es deshalb nicht.

- `tinysesam/gate.py`: Ableitung (HKDF), Ausstellen, Prüfen wie am Proxy, `zielgruppe()`.
  `_gate_cookie()` in `/auth/forward`; Felder `gate_token_enabled`, `gate_token_ttl_sec`,
  `gate_cookie_name`, Prüfung in `konfigpruefung._gate`; `tinysesam gate-key`; Gateway
  `TINYSESAM_GATE`, `TINYSESAM_GATE_TTL_SEC`.
- `deploy/forward-auth/Caddyfile.gate`, `deploy/forward-auth/caddy-gate/Dockerfile`.
- Tests: `tests/test_gate.py` (Ausstellen, Zielgruppe, Claims, 12 Verfälschungen, fremde
  JOSE-Implementierung, Schlüssel, CLI, Konfigurationsprüfung, Wächter über die Vorlage) und
  `tests/test_gate_caddy.py` (echter Caddy, Vorlage aus dem Repo: 10 Asset-Anfragen ohne Aufruf bei
  TinySesam, POST samt Body auf dem Rückweg, 7 verfälschte Cookies, Widerrufsverzug, Gegenprobe ohne
  Gate). CI-Job `gate-caddy`.
- Mutation: zehn Eingriffe in Code und Vorlage (Token nie ausgestellt, Rollen nicht in der Zielgruppe,
  Token für API-Key, jeder Host, Prüfer ohne alg-Vergleich, Cookie ohne HttpOnly, Remote-Email nicht
  entfernt, kein Set-Cookie auf dem Rückweg, Gate-Cookie erreicht die App, ohne `sign_alg`) — jeder
  macht mindestens eine der beiden Suiten rot.
