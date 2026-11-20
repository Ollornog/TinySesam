---
id: ADR-10
type: Decision
title: Paired API keys sign every request (HTTP Message Signatures, RFC 9421) with a client-held Ed25519 key
status: erledigt
tags: [api-keys, crypto, pairing, signatures]
created: 2026-11-20
---

# ADR-10 — Paired API keys: RFC 9421 signatures with a key pair held by the client

## Context

[T-32](T-32-api-key-pairing-negotiate-a-key-on-first-contact-o.md) (PO wish 2026-11-20): instead of
copying a static `tsk_…` string into a client, the client and TinySesam should negotiate a key on
first contact (a one-time pairing code from the account page or the admin panel), and every later
request should be authenticated *and protected* by that key. Expiry stays mandatory; per key, a
login of the owner may renew it (`renew_on_login`) or rotate it on both sides (`rotate_on_login`).

The existing API keys stay as they are and are the base: one table `api_key`, hashed, with
`expires_days`/`apikey_default_days`, the kinds `automation`/`human`, the role scope, and revocation
on lockout, admin password reset and "end all sessions". A paired key is one more row in that table
— not a second key system.

**What "talking encrypted" can add on top of TLS.** TLS already encrypts and integrity-protects the
connection. A bearer key inside it has three weaknesses TLS does not fix: (1) it is a *transferable*
secret — whoever reads it once (proxy log, debug dump, shell history, a backup of the client config)
can use it from anywhere until it expires; (2) a recorded request can be replayed as long as the key
lives; (3) the server holds something derived from it — a hash is enough to recognise the key,
and a fast hash of a high-entropy key is fine, but the string itself still crosses every hop that
terminates TLS (reverse proxy, load balancer). The real gain is therefore not a second layer of
confidentiality but **binding every request to a key that never leaves the client**, **replay
protection**, and **nothing in the database or in any log that would let someone else sign**.
Confidentiality of the payload beyond TLS is a different requirement; nobody asked for it, and the
option below shows its price.

## Options

1. **RFC 9421 HTTP Message Signatures with a client key pair (Ed25519).** On pairing the client
   generates the key pair and sends only the public key; the server stores only that. Every request
   carries `Signature-Input`/`Signature` over method, target URI and — when there is a body — the
   RFC 9530 `Content-Digest`, plus `created`, a `nonce` and the `keyid`. A stolen database, a proxy log or a
   recorded request yields nothing that signs. Standard, interoperable (curl/other languages can
   implement it), maintained libraries exist.
2. **RFC 9421 with a negotiated HMAC secret (`hmac-sha256`).** Same wire format, but both sides hold
   the same secret. The server must store it *recoverably* (to compute the MAC), i.e. encrypted with
   the installation key, not hashed — a database plus key file leak lets an attacker sign. Pairing
   would need a key agreement (e.g. X25519) or the server would send the secret once, which is the
   copy-paste problem again. Cheaper per request, but strictly weaker than option 1 for no gain we need.
3. **Mutual TLS (client certificates).** Strong binding, but it lives at the TLS terminator, not in
   the app: behind a reverse proxy TinySesam only sees a forwarded header it has to trust, it needs a
   CA, issuing and revocation, and it does not fit "a router inside a foreign FastAPI app". Rotation
   on the owner's login would mean re-issuing certificates through the proxy. Rejected.
4. **Payload encryption (JWE) on top of TLS.** Encrypts bodies end to end past the TLS terminator.
   It does not by itself authenticate the request line or prevent replay (it would still need a
   signature or MAC), it hides payloads from operators' own tooling, and every client needs a JOSE
   stack. It solves a confidentiality problem that TLS already solves for this use. Rejected.
5. **A home-made scheme** (e.g. HMAC over a custom canonical string). Rejected on principle: the
   canonicalisation is exactly where such schemes break, and RFC 9421 exists for this.

## Decision

**Option 1: RFC 9421 HTTP Message Signatures, algorithm `ed25519`, key pair generated and held by the
client; the server stores only the public key.**

- **Library:** [`http-message-signatures`](https://github.com/pyauth/http-message-signatures)
  (pyauth, Apache-2.0, actively maintained, 3.0.0 is the current stable release; it builds on
  `cryptography`, which is already a core dependency, and `http-sf` (MIT) for Structured Fields). It
  implements the signature base, the verification rules (created/expires/max age, required covered
  components, tag selection) and RFC 9530 `Content-Digest`. It is an **optional extra**
  `tinysesam[pairing]` (`http-message-signatures>=3.0.0`), also part of `[all]`; the core install does
  not change. `apikey_pairing_enabled=True` without the extra is refused at construction.
- **Profile (what the server requires):** the signature selected by `tag="tinysesam"`; covered
  components `@method`, `@target-uri` and, whenever the request has a body or a `Content-Digest`
  field, `content-digest` (SHA-256 or SHA-512, checked against the actual body); parameters
  `created` (not older than `apikey_signature_max_age`, default 60 s, and not in the future beyond
  5 s of clock skew), `nonce` (8–128 characters, single use per key while the signature could still
  be accepted), `keyid`; `alg`, if present, must be `ed25519`; nothing else. The target URI is built
  from `base_url` when it is set (scheme and host as the client sees them, behind a proxy too),
  otherwise from the request.
- **Key id:** the RFC 7638 JWK thumbprint of the public key (RFC 8037 `OKP`/`Ed25519`) — a standard
  value the client can compute itself. The row stores it as `key_hash = "ed25519:<thumbprint>"`, so it
  can never collide with the SHA-256 hex of a bearer key, and the bearer path refuses any row that
  carries a public key.
- **Where the check runs:** a small pure-ASGI layer, `auth.install_signatures(app)` (the same pattern
  as `install_https`/`install_error_pages`). It only acts on requests that carry `Signature-Input`; all
  others pass through untouched. It verifies once per request — so a nonce is consumed once even when
  a route asks `current_user()` twice —, reads and checks the body only *after* the header signature
  verified (a stranger cannot make it buffer anything), hands the body on unchanged, and writes the
  result into the ASGI scope. `current_user()` then applies exactly the checks of a bearer key (revoked,
  expired, account disabled, keys dormant at the provider, kind `human` needs a session, kind
  `automation` never carries the admin flag, role scope). A signed request without the layer installed
  authenticates nobody, and the pairing route refuses with a hint, so the mistake shows up at setup.
- **Pairing:** a one-time code `XXXX-XXXX-XXXX-XXXX` (16 characters from a 32-letter alphabet without
  look-alikes, 80 bits), issued from an interactive session — self-service for the own account,
  the admin panel for any account (the same rule as for creating a key: never by a key). The code
  carries the key's settings fixed at issue time: name, kind, role scope (trimmed to the owner's roles
  as for every key), expiry, `renew_on_login`, `rotate_on_login`. It lives `apikey_pairing_minutes`
  (default 10), is stored only as a hash (`magic_token`, purpose `apikey_pairing`), is redeemed once
  (atomic), and is discarded with the owner's other open links on lockout, admin password reset and
  "end all sessions". `POST /auth/apikeys/pair` takes the code and the public key and must itself be
  signed with the new private key (proof of possession, `keyid` = thumbprint of the submitted key).
  The route is rate-limited like other unauthenticated routes; issue, success and every refusal land
  in the audit log (`apikey_pairing_issue`, `apikey_pair`, `apikey_pair_denied`). The event
  `api_key_created` fires as for any new key (detail `paired=True`).
- **Expiry and `renew_on_login`:** a paired key has an expiry like every key (`apikey_default_days`;
  "unlimited" still needs `apikey_allow_unlimited`). With `renew_on_login`, every *completed interactive
  sign-in* of the owner (the single place `_sign_in_complete`, i.e. all methods, after the whole factor
  chain) sets the expiry to `now + lifetime` if that is later. Using the key never renews it. An
  already expired or revoked key is not revived. The option also works for bearer keys; it needs a key
  with an expiry.
- **`rotate_on_login` (paired keys only):** a completed sign-in of the owner marks the key
  `rotate_pending`. The server cannot reach the client then, so it tells it on the next signed response:
  header `TinySesam-Key-Rotate: <path>`. The client generates a new key pair, stores it as *pending*
  first, and calls `POST /auth/apikeys/rotate` with the new public key, signed with the current key. The
  server keeps the old public key as the predecessor and switches to the new one. **Overlap:** the old
  key keeps working until the new key is used for the first time; from that moment it is accepted only
  for signatures created before that moment (requests already in flight, bounded by the signature max
  age), and is dead after that. A repeated rotation call with the same new key (response lost) is
  answered as success. Rotation does not change id, name, kind, scope or expiry of the key, and the
  audit log records it (`apikey_rotate`). Clients may also rotate on their own initiative.
- **Revocation:** unchanged — a paired key is a row in `api_key`, so revoking one key, locking the
  account, the admin password reset and "end all sessions" revoke it like any other key, and open
  pairing codes go with the account's other open links.
- **Reference client:** `tinysesam.client` (needs the extra; standard library HTTP, no further
  dependency) does pairing, signing (nonce, `created`, `Content-Digest`) and rotation by itself and keeps
  its key file at mode 0600. Without a client nobody would use the feature; other languages implement
  the same RFC profile.

## Consequences

- One more optional dependency (`http-message-signatures`, Apache-2.0 — compatible with the MIT
  licence of TinySesam as a dependency), only for those who enable pairing.
- Schema 17 (additive): new columns on `api_key` (`public_key`, `prev_public_key`, `prev_key_hash`,
  `prev_until`, `rotate_pending`, `renew_on_login`, `rotate_on_login`, `lifetime_days`) and a table
  `signature_nonce`. An older version leaves them in place; it cannot verify a paired key (it looks
  keys up by the hash of a bearer string), so paired keys simply do not authenticate there — fail-closed.
- Apps that want paired keys call `auth.install_signatures(app)` once. Bearer keys
  (`Authorization: Bearer tsk_…`, `X-API-Key`) are unchanged and keep working; a paired key is an
  additional kind of credential, not a replacement.
- Clock skew matters: a client whose clock is off by more than the max age plus 5 s gets 401s. That is
  the price of replay protection without a server round trip, and the default (60 s) is generous.
- Rotation is not a defence against an *active* thief of the private key — whoever holds the current
  key can rotate too. It limits how long a *copied* key file stays useful, and a rotation by an attacker
  locks the rightful client out at its next request, which is a visible signal.
- What this does not do: confidentiality of payloads beyond TLS (option 4), and binding to the TLS
  channel (option 3).
