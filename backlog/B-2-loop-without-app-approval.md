---
id: B-2
type: Bug
title: Endless loop between application and login page when the approval for the application is missing
status: erledigt
milestone: M-3
tags: [forward-auth, oidc, mehrere-clients]
created: 2026-10-07
---

# B-2 — Loop without app approval (multiple OIDC clients)

**Found** while building [T-21](T-21-login-modes.md), reproduced with the TestClient.

**Repro.** An installation with `oidc_clients` for `app-a` and `app-b`. A session with approval for
`app-a` calls `app-b`:

1. `/auth/forward` (host `app-b`) → 401, `X-TinySesam-Reason: app-fehlt`, target
   `…/auth/login?next=https://app-b…&app=app-b.example.com`.
2. `/auth/login` sees the session → **303 back to `next`**.
3. Back to 1. Without end.

In addition, the OIDC button of the login page lost `app=` (`/auth/oidc/start?next=…`), the round began with the
default client, and the approval for `app-b` never came about on this path either.

**Expected.** Only the provider grants the approval — so go there, with the client of `app-b`.

## Done 2026-10-07

- The recheck in `/auth/forward` (`app-fehlt`, `app-veraltet`) leads directly to
  `/auth/oidc/start?next=…&app=…`.
- `/auth/login` with a session but without a valid approval for a known `app` → to the provider.
- The button carries `app=`; `/auth/oidc/start` without `app` takes the client for the host of `next`.
- Test: `tests/test_login_modes.py` (B-2 section), mutation turns each part red.
