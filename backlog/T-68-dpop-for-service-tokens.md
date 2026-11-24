---
id: T-68
type: Task
title: DPoP for service tokens — bind a service's access token to its key (RFC 9449)
status: offen
points: 8
milestone: M-2
blocked_by: [T-60]
tags: [oauth, m2m, dpop]
created: 2026-11-20
---

# T-68 — DPoP for service tokens

Left open by [ADR-13](ADR-13-oauth-for-services-private-key-jwt.md): a service's access token is a bearer token for
its lifetime (15 min) at its resource. DPoP (RFC 9449) would bind it to the service's key — a copied token alone is
useless.

Why not in T-60: the proof is checked at the **resource**, i.e. in `/auth/forward` for every request. That needs
the `DPoP` header passed through the proxy, `htm`/`htu` rebuilt from `X-Forwarded-*` (exactly the normalisation
problem that made ADR-13 drop RFC 9421), a `jti` store per request, and `cnf.jkt` on the token row. Claude Code has
no DPoP either (its tokens stay bearer).

Done when: the token endpoint issues `token_type: DPoP` with `cnf.jkt` to a service that sends a `DPoP` proof;
forward auth refuses such a token without a valid proof (method, URL as the client sent it, `ath`, `iat`, `jti`
single use); the proxy templates pass the header; the reference client signs the proofs; negative tests with
mutations; an ADR amendment says how `htu` is compared behind the proxy.
