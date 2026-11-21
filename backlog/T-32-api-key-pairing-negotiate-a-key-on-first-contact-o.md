---
type: Task
title: 'API key pairing: negotiate a key on first contact, optional renew and rotate on login'
status: erledigt
id: T-32
milestone: M-2
tags: [api-keys, crypto, pairing]
created: '2026-11-20'
---
# T-32 — API key pairing: negotiate a key on first contact, optional renew and rotate on login

Wish (PO 2026-11-20). Builds on the existing API keys (hashed, `expires_days`, `apikey_default_days`, kinds `automation`/`human`) — extend them, no second key system.

**1. Pairing instead of copy-paste.** On first contact a client and TinySesam negotiate a key themselves (e.g. a one-time pairing code issued in the account page or admin panel; the client presents it once and both sides derive or agree on the key). After that both sides talk using that key — every request authenticated and its content protected by it, not just a static bearer string that TLS carries.

**2. Expiry stays mandatory, renewal is optional (per key).** Setting `renew_on_login`: each interactive login of the owner pushes the key's expiry out by its configured lifetime. Default off. A disabled account, admin password reset or "end all sessions" still revokes as today.

**3. Rotation is optional (per key).** Setting `rotate_on_login`: each login of the owner rotates the key on **both** sides automatically. Default off.

Open design questions (decide in an ADR before building):
- What "encrypted" adds on top of TLS: request signing (HTTP Message Signatures, RFC 9421) with a negotiated secret or a client key pair (only the public key on the server, nothing to steal from the DB) vs. payload encryption. Prefer a standard over a home-made protocol.
- Rotation needs the client to learn the new key: the client cannot be reached at the owner's login, so the server marks the key "rotate" and the client completes the rotation on its next request (handshake response carries the successor). Overlap window so an in-flight request with the old key does not fail; the old key dies after the first use of the new one.
- How the pairing code is bound: short-lived, single use, rate-limited, shows up in the audit log; which key kind it produces.
- Client side: a small reference client (Python, maybe the Go gate client from T-28) that stores the key and does pairing/rotation by itself, otherwise nobody can use it.

## Closed by T-60 (2026-11-20)

The wish is fulfilled for services by [T-60](T-60-oauth-for-services-client-credentials-private-key-jwt.md),
decision [ADR-13](ADR-13-oauth-for-services-private-key-jwt.md), in a standard way instead of the draft's own
protocol (PR #242 with ADR-10 — closed unmerged, the number ADR-10 stays unused):

1. **Pairing instead of copy-paste** — built: a one-time code from the account page or the admin panel, the client
   creates its key pair, TinySesam keeps only the public key (the draft's code and key pair taken over). "Every
   request protected by the key" became `private_key_jwt` per token request plus a 15-minute token bound to one
   resource, instead of an RFC 9421 signature per request (one check path for people and services, no proxy
   normalisation, no own replay logic per request).
2. **Expiry mandatory, renewal optional** — a service key expires (`oauth_service_key_days`, 90); renewal is the
   rotation below, so `renew_on_login` was not built. For bearer API keys nothing changed.
3. **Rotation** — client-driven: the reference client rotates at half the key lifetime by itself, with an overlap.
   `rotate_on_login` was not built: a service account has no login, and the owner's login cannot reach the client.
4. **Reference client** — `tinysesam-client` (pair, token, request, rotate, info).

Not built, on purpose: `renew_on_login`/`rotate_on_login` for the existing bearer API keys. Whoever needs that should
move the integration to a service (T-60); a new wish gets a new entry.

Done when (original): the ADR is written; pairing, `renew_on_login` and `rotate_on_login` work per key, are settable in the admin panel and the self-service routes, appear in the audit log, are documented in the README section "API keys", and are covered by tests including rotation with a request in flight and the revocation paths.
