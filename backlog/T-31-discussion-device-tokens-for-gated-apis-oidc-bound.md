---
type: Task
milestone: M-2
title: 'Discussion: device tokens for gated APIs (OIDC-bound, non-browser clients)'
status: offen
id: T-31
created: '2026-11-01'
---
# T-31 — Discussion: device tokens for gated APIs (OIDC-bound, non-browser clients)

**Status: open for discussion — not decided.**

Problem: clients that cannot do a browser login (WebDAV scanner apps, media apps that wrap a web UI) fail at the gate's redirect. Today the only ways out are a private network or removing the gate for that app.

Idea: after an OIDC login in the browser, a user creates a device token in TinySesam (name, allowed path prefixes and methods, expiry, revocable). The gate accepts it instead of redirecting. Disabling the user or removing them from the group at the provider invalidates their tokens.

Ways to carry the token (to be discussed):
1. Token in the path (`/dav/<token>/…`, stripped by the gate before forwarding). Works with any client that only takes a URL; downside: the token appears in logs.
2. App password via Basic Auth, gate sets a trusted user header for backends that support it (REMOTE_USER style). Downside: the client can no longer send the backend's own credentials.
3. Client certificates (mTLS). Strong, but many apps lack support.

Safeguards: path/method allowlist, rate limit and lockout on failures, per-token audit log, expiry after inactivity. Related: existing share keys in the query (key=…).

Open questions: which carrier(s), token storage (hashed), UI in the admin panel, interaction with the forward-auth gateway.
