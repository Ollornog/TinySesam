---
id: T-23
type: Task
title: Configuration check for gate operation
status: erledigt
milestone: M-3
tags: [gateway, configuration]
created: 2026-10-03
---

# T-23 — Configuration check

**Warnings or errors in `config_check.py`:**
- `login=unsichtbar` + `logout=app` → warning: the app is silently signed in again after the next click,
  "sign out of the app only" has practically no effect.
- `unsichtbar` with more than one sign-in method → error.
- Cookie domain on the parent domain in gate operation → error (the session would be readable by every protected app).
- Share exception with a file extension instead of a prefix → warning (where the list is known in TinySesam).
- Gate token lifetime over 15 min → warning (revocation delay).

**Done when:** per rule a test + mutation.

## Done 2026-10-07

Re-checked against the built state — three of the planned rules were obsolete:

- `unsichtbar` + `logout=app` → **no** warning: the lock on the session (T-22) holds even with `direct`,
  the application then shows the login page with "Continue as …".
- Cookie domain on the parent domain → **no** error: that is the existing forward-auth model (the
  templates remove the TinySesam cookies before the application, B-20); the planned code exchange, for which
  the rule was intended, was dropped with ADR-9.
- Share extensions → dropped (the list sits in the proxy, T-20).
- Built in already when building the functions (error): `direct` next to other methods (T-21),
  unknown values/keys in `forward_apps` (T-21/T-22), cookie name, lifetime, gate without
  forward auth (T-19).

New (warnings): lifetime over 900 s, gate without a protected host, `forward_apps` without forward auth,
`direct` + sign-out `all`/`ask` without `oidc_rp_logout`. Test `tests/test_config_gate.py`, 5 mutations red.
