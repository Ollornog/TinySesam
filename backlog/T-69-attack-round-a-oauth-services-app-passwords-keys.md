---
id: T-69
type: Task
title: Attack round A (2026-11-21) — OAuth, services, app passwords, keys
status: erledigt
milestone: M-2
tags: [security, audit, oauth, m2m, forward-auth, vault]
created: 2026-11-21
---

# T-69 — attack round A, 2026-11-21

An attack round against the surfaces new since 0.25: the OAuth 2.1 authorization server
([ADR-11](ADR-11-oauth-authorization-server-in-tinysesam.md)), OAuth for services
([ADR-13](ADR-13-oauth-for-services-private-key-jwt.md), [T-60](T-60-oauth-for-services-client-credentials-private-key-jwt.md)),
app passwords ([T-66](T-66-app-passwords-for-webdav-caldav-and-git-at-the-gate.md)) and key management
([ADR-12](ADR-12-key-purposes-keyrings-and-rotation.md)). Verdict: the protocol core (redirect, PKCE, code, refresh
rotation, audience, `private_key_jwt`, `jti`) held against every direct attack; six findings, all fixed here. Each
was first reproduced by a test that failed (`tests/test_attack_round_a.py`), each fix is proven by a mutation.

## Findings

| No | Severity | Finding | Fix |
|---|---|---|---|
| A-1 | medium | "End all sessions", password reset and admin password reset left the account's OAuth grants alive (refresh up to 180 days) | `_keys_revoked` is the one revocation point: API keys, app passwords, services, OAuth grants; `tinysesam passwd` revokes the same offline |
| A-2 | medium | A service key within its rotation overlap could rotate in a key of its own and put the rightful new key on the overlap clock | only the current key may rotate; the same new key again stays a success (crash recovery) |
| A-3 | medium | Every proxy template passed `Authorization` (app password, OAuth token, API key) on to the application | every application upstream in `deploy/` drops `Authorization` and `X-Api-Key`; a scan of all templates, a real Caddy |
| A-4 | low | Open registration counted per /128; one IPv6 /64 filled the global cap for a day | per /64 and per /48; at the cap the longest-unused registration older than ten minutes gives way |
| A-5 | low | `Vault.decrypt` accepted plain text and `v1:` at runtime; a planted plain-text gate seed was published | only the migration reads them; the start refuses leftovers with the way out (`tinysesam keys reencrypt`) and anything but ciphertext in `key_material` |
| A-6 | low | A code reused between consume and grant revoked nothing | a reuse mark on the code, read in the grant's transaction: the first exchange issues nothing |

## Checked across all revocation paths (A-1)

Lock (`set_disabled`), admin password reset, self-service reset, `sessions/revoke` with `scope=all` and the offline
`tinysesam passwd`: all revoke API keys, app passwords, services and OAuth grants now. Deletion removes every
credential through the foreign keys (`ON DELETE CASCADE`, `PRAGMA foreign_keys=ON`). On purpose without revocation:
the own password change and "end others" (they keep automations running and count what stays open), an admin ending
another account's sessions in the panel (sessions only). There is no factor reset by an administrator besides deleting
a passkey, and no LDAP/OIDC deprovisioning path: federated accounts are checked on every sign-in, and forward auth
reads the account on every request.

## Not done here

- Write access to the database stays outside the vault's promise (ADR-12, amended): a session row is stored as a plain
  SHA-256 and gives any account without a key; a pepper for session handles would be its own task — done in
  [T-71](T-71-session-handles-keyed-with-the-pepper.md), the remaining digests in
  [T-72](T-72-pepper-for-the-remaining-token-digests.md).
- nginx and Traefik were checked statically, not through a running proxy.
