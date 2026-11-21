---
id: ADR-12
type: Decision
title: One key per purpose, each a keyring with key IDs — vault, gate signature, OAuth pepper; rotation without loss
status: erledigt
tags: [security, crypto, gate, oauth, keys]
created: 2026-11-20
---

# ADR-12 — One key per purpose, each a keyring; rotation without loss

## Context

Up to 0.25.x one base key (`TINYSESAM_SECRETS_KEY`, `secrets_key_file` or `<db>.key` beside the database) did
everything: it encrypted the TOTP secrets and the OIDC refresh and ID tokens (AES-256-GCM, `tinysesam/vault.py`), and
by HKDF/HMAC it *was* the Ed25519 gate signing key ([ADR-9](ADR-9-gate-token-at-the-proxy.md)) and the OAuth pepper
([ADR-11](ADR-11-oauth-authorization-server-in-tinysesam.md)). Consequences found in the security review of 2026-11-20
([T-48](T-48-key-rotation-for-secrets-key-and-a-gate-signing-ke.md), finding M5; ASVS 5.0.0 11.1.1, 11.1.2, 11.2.x,
13.3.4):

- whoever could read the data directory (`<db>.key`) could mint a gate token for any account — the proxy trusts
  it without asking TinySesam;
- there was no rotation: after a leak, either every TOTP enrolment was lost or the compromised key stayed;
- the ciphertexts carried no key ID and no binding to their row
  ([T-54](T-54-vault-bind-ciphertexts-to-their-row-aad-with-user.md)): with write access to the database the encrypted
  TOTP secret of one account could be copied into another;
- the gate token said `typ: JWT` ([T-53](T-53-gate-token-explicit-type-and-separate-key-before-t.md)) — nothing told
  it apart from another JWT once TinySesam signs more than one kind.

## Options

1. **Keep one base key, derive per purpose (HKDF labels), add rotation of the base key.** Small, but leaves the
   finding: reading the one key still gives the gate key.
2. **One base key file with several sections (one per purpose).** Rotation per purpose, but one file read still gives
   everything.
3. **Own random material per purpose, each a keyring with key IDs; the vault key outside the database, the gate key and
   the pepper either from their own source or stored in the database encrypted with the vault key.**
4. **An external KMS/HSM (Vault Transit, cloud KMS, PKCS#11).** The right answer at scale; for a single-binary SQLite
   service in a home network a second service to run, secure and back up — the opposite of ADR-3.

## Decision

**Option 3.** Three purposes, each with its own material and key ID:

| purpose | material | source, in this order | kid |
|---|---|---|---|
| `vault` | 32 random bytes, AES-256-GCM | `TINYSESAM_SECRETS_KEY` (+ `_PREVIOUS`), `secrets_key_file`, `<db>.key` | HMAC-SHA-256(key, `tinysesam/kid/vault`), 12 hex |
| `gate` | 32-byte random Ed25519 seed | `TINYSESAM_GATE_KEY` (+ `_PREVIOUS`), `gate_key_file`, table `key_material` | SHA-256(public key), 16 hex (as before) |
| `oauth-pepper` | ≥ 32 random bytes | `TINYSESAM_OAUTH_PEPPER` (+ `_PREVIOUS`), `oauth_pepper_file`, table `key_material` | HMAC-SHA-256(key, `tinysesam/kid/oauth-pepper`), 12 hex |

**The gate key is never derived from the vault key.** Without its own source it is stored in `key_material`, encrypted
with the vault key — so the vault key alone (a leaked environment variable, a stolen key backup) gives no gate key, and
a copy of the database alone gives none either. Both together do; that is the case of `<db>.key` beside the database, which
`config_check` reports when the gate is on, and which `TINYSESAM_GATE_KEY`/`gate_key_file` (or a vault key elsewhere)
closes. The pepper follows the same rule: it guards stored 256-bit token digests, so its loss is less severe, but it
must not change when the vault key is rotated — with a derivation it would have disconnected every program.

**Keyrings.** Every purpose holds an active key and previous ones; the active one encrypts, signs and digests, all of
them decrypt, verify and look up. This is the common pattern:

- Django: `SECRET_KEY` plus `SECRET_KEY_FALLBACKS` (since 4.1) — the first signs, the fallbacks still verify, and the
  documentation asks to remove old values after a while
  (<https://docs.djangoproject.com/en/stable/ref/settings/#secret-key-fallbacks>).
- Rails `ActiveRecord::Encryption`: several keys per `primary_key`, the last encrypts, all are tried for decryption;
  `store_key_references` writes the key reference into the message so it need not try them all
  (<https://guides.rubyonrails.org/active_record_encryption.html#rotating-keys>).
- Tink keysets: one primary key plus enabled keys, the ciphertext prefixed with the key ID (output prefix `TINK`), key
  rotation = add, promote, disable, destroy (<https://developers.google.com/tink/key-management-overview>,
  <https://developers.google.com/tink/design/keysets>).

Taken over: the key ID in every ciphertext (Rails' reference, Tink's prefix), the order "add → make active →
re-encrypt → retire" (Tink), fallbacks only as long as needed (Django). Not taken over: a separate "added but not yet
active" state (Tink) — a TinySesam installation is one database and one process group; instead a running service
re-reads its vault key file when it meets a key ID it has not loaded (a `keys reencrypt` before the restart cannot
break its sign-ins).

**Vault format and associated data (T-54).** `v2:<kid>:<Base64url(nonce ‖ ciphertext ‖ tag)>`; AAD =
`tinysesam/vault/v2 ‖ kid ‖ context`, the context naming table, column and what identifies the row for its whole
life (account for TOTP; client and subject for the refresh token; client and account for the ID token, because the
session handle rotates; the token row for an OAuth successor; purpose and kid for a stored key). JSON-encoded, so no
part can shift into another. `v1:` (0.21–0.25.x) is read only by the migration, with every key of the keyring, and
rewritten at the start (or by `tinysesam keys reencrypt`); every other read takes `v2:` only, and a start that cannot
rewrite what is left stops with that command in its message (amended 2026-11-21 after attack round A, A-5: until then
every read accepted `v1:` and plain text, so whoever could WRITE the database without the vault key planted a
plain-text gate seed in `key_material` and had it published). `key_material` never holds anything but `v2:`; a start
that finds something else refuses instead of encrypting it.

**What the database alone gives — honestly.** A COPY of the database without the vault key gives no reversible secret
and no gate key. WRITE access to the database is not covered by this decision: whoever writes it can add a session row
(its handle is stored as a plain SHA-256), a role or an account and is anyone, without any key; and a plain-text TOTP
secret written there before the next start is encrypted by that start (the migration path from before 0.21, which
cannot tell an old value from a planted one). The vault keeps secrets from a reader of the file, not from a writer.

**Gate token type (T-53).** Header `typ: tinysesam-gate+jwt` (RFC 8725 §3.11; RFC 7515 §4.1.9 lets the
`application/` prefix go) and `kid`; `gate.check` refuses another type. **caddy-jwt cannot check `typ`** — v1.4.0 has
no such option (source `jwt.go`; measured: `JWT` and `at+jwt` signed with the gate key pass alike). A claim-based check
at the proxy would need a matcher on a meta claim in the template; it is not added, because RFC 8725 §3.11 accepts the
other two separations we already have: the gate key signs nothing but gate tokens (rule: any future JWT issuer in
TinySesam gets a purpose and keyring of its own), and `aud` is a bare host (`app.example.com|roles=…`), never equal to
an RFC 8707 audience, which is a URL.

**Gate rotation at the proxy.** `/auth/gate/jwks.json` publishes the active key and every previous one for 3600 s
after it stopped signing (the longest a gate token lives, `gate.TTL_MAX`), as an RFC 7517 set of OKP keys (RFC 8037).
The template switches caddy-jwt to `jwk_url`. Measured with caddy-jwt 1.4.0 and Caddy 2.11.9: `jwk_url` over plain
HTTP to the local upstream works; after a rotation the first one or two requests with the new `kid` take the fallback
path (caddy-jwt refreshes the set asynchronously on an unknown `kid`), then the new key is used; a token signed with the
previous key still passes. `sign_key` remains possible (then the proxy needs the new value after every rotation; until
then every request takes the fallback path — slower, nobody signed out).

**Amended 2026-11-21: the template is back on `sign_key`.** In a rollout, `jwk_url` hung: when the first fetch fails
(TinySesam not up yet when the first token arrives), caddy-jwt 1.4.0 waits for the set without a deadline under its
write lock (`Cache.Register(context.Background(), …)`, jwx/httprc `WaitReady`) and every request with a gate token hangs.
`tests/test_gate_caddy.py` reproduces it. The key set stays published for proxies that fetch keys safely; the template
takes the fixed key, at the price of a manual step after a gate rotation.

**Retirement refuses what would lose something.** `tinysesam keys retire`: vault — while any stored value names the
key (or a `v1:` value exists); gate — within the 3600 s overlap; pepper — while a code or token created before the
rotation is still valid. `--force` exists for gate and pepper only (what it cuts is re-issued or reconnected); never for
the vault (that would be data loss).

**Migration without handwork.** The first start of this version takes the existing base key as version 1 of the
vault keyring (same file, same environment variable, nothing to convert), rewrites `v1:` values as `v2:`, creates a
random gate key and pepper in `key_material`, and keeps the derived ones as previous keys (`note: derived-v1`): the gate
key only if the gate is on and the database has sessions, the pepper only if programs are connected. Old gate tokens
stay valid at a `jwk_url` proxy until they expire; old OAuth tokens stay valid until their natural end. The start warns
while the derived gate key is in the keyring.

**Rollback.** Schema 19 only adds `key_material`, but the values change format; an older version takes `v2:` for plain
text. The way back is `tinysesam keys reencrypt --to v1` with this version, then the older one with that single key
(measured with the code of `bf3aa09`: TOTP and refresh token read correctly). Started without it, the older version
fails TOTP sign-ins and wraps the TOTP values into `v1:` once more; this version unwraps that at its next start
(measured likewise).

## Consequences

- Reading the vault key no longer mints gate tokens; reading the data directory still does when `<db>.key` lies there
  — reported, and closed by putting one of the two keys elsewhere.
- Rotation is three commands per purpose and loses nothing; the audit log records each rotation and retirement.
- Operators updating from 0.25.x with `sign_key` in Caddy must give the proxy the new key (or switch to `jwk_url`);
  until then the gate works on the fallback path. `CHANGELOG` names it under "Changed".
- A lost vault key now also loses the gate key and pepper kept in the database (re-created after `DELETE FROM
  key_material`; OAuth programs reconnect).
- An external KMS stays open for installations that want it ([ADR-3](ADR-3-in-app-instead-of-proxy.md) keeps it out of
  the default); the keyring sources (environment, file) are where it would plug in.
- Sources for the cryptoperiods: NIST SP 800-57 Part 1 Rev. 5 §5.3 (originator-usage vs. recipient-usage period — the
  "previous" state is the recipient-usage period).
