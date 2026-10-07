---
id: T-22
type: Task
title: "Logout-Modus je App: app, alle, fragen — Kette über den Provider zurück zum Gate"
status: erledigt
milestone: M-3
tags: [gateway, oidc, logout]
created: 2026-10-03
---

# T-22 — Logout-Modi

Provider-Befund steht in [ADR-9](ADR-9-gate-token-am-proxy.md) (Konsequenzen).

**Zu tun:**
- `/.sesam/logout?scope=app` — Gate-Cookie dieses Hosts löschen, Freigabe dieser App in der Sitzung
  verwerfen; Provider und andere Apps bleiben angemeldet. Die App leitet dafür **direkt** hierher,
  ohne den Provider zu rufen (dessen End-Session beendet immer die Provider-Sitzung).
- `/.sesam/logout?scope=all` — Ziel der Kette App → Provider-End-Session → **Logout Callback URL** →
  hier: **alle** TinySesam-Sitzungen des Benutzers beenden, Gate-Cookie löschen; ruft das Gate selbst
  ab, zusätzlich RP-Logout beim Provider. `state` prüfen, Ziel nur aus `trusted_redirect_hosts`.
- `fragen` — Seite mit „Nur *App X*“ und „Überall abmelden“ (für Apps, die nur eine Logout-URL kennen).
- `oidc_rp_logout=True` als Vorgabe im Gateway-Preset.
- Doku: Checkliste je App (Logout-Ziel in der App, Logout Callback URL beim Provider, Modus im Gate).

**Fertig, wenn:** Browser-Test: `app` → diese App verlangt Login, zweite App bleibt offen; `alle` →
Provider abgemeldet, beide Gates nach ≤ einer Token-Laufzeit zu (eigenes sofort); kein offener
Redirect über `scope`/Ziel; Mutation je Zweig.

## Erledigt 2026-10-07

Werte englisch: `forward_logout = "all" | "app" | "ask"` (Vorgabe `all`), je Host in `forward_apps`.

- `all` beendet **diese** Sitzung (sie trägt jede Anwendung hinter derselben Anmeldung), nicht alle
  Sitzungen des Kontos auf anderen Geräten. „Überall“ heisst hier: in allen Anwendungen dieses
  Browsers. Andere Gate-Cookies dieses Browsers laufen nach `gate_token_ttl_sec` ab.
  *Der Plan nannte „alle TinySesam-Sitzungen des Benutzers“. Das ist ein anderer Schritt („auf allen
  Geräten abmelden“) und bleibt beim Konto-Panel.*
- `app` braucht eine Sperre an der Sitzung (`gate_abgemeldet`, Schema 13). Ohne sie hätte die
  Forward-Auth die Sitzung beim nächsten Klick wieder durchgelassen. Aufgehoben wird sie mit „Weiter
  als …“ (`POST /auth/gate/resume`) oder einer neuen Anmeldung mit Ziel dieser Anwendung. Die
  Forward-Auth schickt dann immer auf die Login-Seite, nie direkt zum Provider (der meldete lautlos
  wieder an).
- **`id_token_hint`:** Ohne ihn beendet PocketID (v2.17.0) seine Sitzung nicht. TinySesam speichert
  das ID-Token verschlüsselt (`oidc_id_token`) und schickt es samt `client_id` des Clients der Anmeldung.
- Wege auf dem App-Host: `/.tinysesam/logout` (GET/POST), `/.tinysesam/after-logout` (Rückweg vom
  Provider, beendet eine noch lebende Sitzung — Kette von der Anwendung aus). Cross-site: erst fragen.
- Doku: Checkliste je Anwendung in `docs/BETRIEB.md`.
- Test: `tests/test_logout_modi.py`, `tests/test_gate_caddy.py` (Abmelden durch Caddy). 9 Mutationen rot.
