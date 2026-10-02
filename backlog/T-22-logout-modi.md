---
id: T-22
type: Task
title: "Logout-Modus je App: app, alle, fragen — Kette über den Provider zurück zum Gate"
status: offen
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
