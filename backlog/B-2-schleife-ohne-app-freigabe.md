---
id: B-2
type: Bug
title: Endlosschleife zwischen Anwendung und Login-Seite, wenn die Freigabe für die Anwendung fehlt
status: erledigt
milestone: M-3
tags: [forward-auth, oidc, mehrere-clients]
created: 2026-10-07
---

# B-2 — Schleife ohne App-Freigabe (mehrere OIDC-Clients)

**Gefunden** beim Bau von [T-21](T-21-login-modi.md), nachgestellt mit dem TestClient.

**Repro.** Eine Installation mit `oidc_clients` für `app-a` und `app-b`. Eine Sitzung mit Freigabe für
`app-a` ruft `app-b` auf:

1. `/auth/forward` (Host `app-b`) → 401, `X-TinySesam-Reason: app-fehlt`, Ziel
   `…/auth/login?next=https://app-b…&app=app-b.example.com`.
2. `/auth/login` sieht die Sitzung → **303 zurück zu `next`**.
3. Weiter bei 1. Ohne Ende.

Dazu verlor der OIDC-Knopf der Login-Seite `app=` (`/auth/oidc/start?next=…`), die Runde begann mit dem
Vorgabe-Client, und die Freigabe für `app-b` entstand auch auf diesem Weg nie.

**Erwartet.** Die Freigabe gibt nur der Provider — also dorthin, mit dem Client von `app-b`.

## Erledigt 2026-10-07

- Die Nachprüfung in `/auth/forward` (`app-fehlt`, `app-veraltet`) führt direkt nach
  `/auth/oidc/start?next=…&app=…`.
- `/auth/login` mit Sitzung, aber ohne gültige Freigabe für ein bekanntes `app` → zum Provider.
- Der Knopf trägt `app=`; `/auth/oidc/start` ohne `app` nimmt den Client zum Host von `next`.
- Test: `tests/test_login_modi.py` (B-2-Abschnitt), Mutation je Teil rot.
