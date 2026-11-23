# Approval confirmation specification

Version 1 (format 1 of `vectors/approval.json`). Status: draft for the first helpers
([T-89](../backlog/T-89-approvals-confirm-one-sensitive-action-with-a-step.md), stage B).

An **approval confirmation** is the proof an application receives after a person confirmed one of its sensitive
actions in TinySesam with a fresh step-up: *this account has just confirmed exactly this action, for this application,
once.* TinySesam does not carry the action out and holds no workflow: whether the action is allowed (only the owner,
the thing still exists) is the application's rule, checked before it asks and again before it acts. This document
fixes how an application asks, how it picks the confirmation up and how it checks it — in any language.

This document is normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in
RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The vectors in
[`vectors/approval.json`](vectors/approval.json) are part of the specification: a helper conforms when it passes every
vector. The Python reference is `tinysesam.approval_token.verify`; the helpers of the other clients follow (Go, Rust,
JS/TS, PHP, [`clients/`](../clients/README.md)). It is an optional part of a client, separate from the gate client
([`gate-client.md`](gate-client.md)), which stays as it is.

## 1. The flow

The operator registers the application's action types in TinySesam's configuration (`apps[<id>].approvals.types`: a
type name that begins with the application's id, a field schema, a fixed title and summary in English and German).
The texts the person reads come from the operator, never from the application, which only sends field values.

1. **Ask** (the application's back end, with an automation key of its service account, `apps[<id>].account`):

   ```http
   POST /auth/api/approvals
   X-Api-Key: tsk_…
   Content-Type: application/json

   {"type": "example.collection.delete_permanently", "subject": "42",
    "fields": {"collection": "c_81f2", "name": "Project Alpha"},
    "return_url": "https://app.example.com/approvals/return", "state": "k3J…"}
   ```

   `subject` is the account that must confirm (a decimal id as a string, for example `Remote-Id` of the request);
   `return_url` and `state` only when the person is already in the application (browser entry, §1.1). The answer is
   `201 {"id": "apv_…", "state": "pending", "match_code": "418 207", "approve_url": "https://auth.example.com/auth/approvals/apv_…", "expires_at": …}`.
   Refusals: `400 invalid_type` (not a registered type), `400 invalid_request` (an unknown, missing or wrongly typed
   field, a value too long, against its pattern or with a control character; a bad `state`), `400 invalid_return_url`
   (not exactly one of the registered addresses), `400 invalid_subject` (not an active person), `403 forbidden_type`
   (a type that does not begin with the application's own id), `403 no_approver` (the key is no automation key of a
   registered service account), `429 too_many_requests` (limits; `Retry-After`).
2. **Show** `approve_url` and `match_code` to the person (a link, an MCP URL elicitation), or redirect the browser to
   `approve_url` (browser entry). The person compares the code, steps up for THIS approval and confirms or rejects.
3. **Pick up** (the back end, the same service account): `GET /auth/api/approvals/{id}?wait=25` (long poll, at most
   25 s). The first read after the confirmation answers `{"state": "consumed", "confirmation": "<JWS>", …}` — exactly
   once. Every later read answers `consumed` without it. `rejected`, `expired`, `withdrawn` carry none;
   `consumed` with `result: "forbidden"` and no confirmation means the application, the type or the person was gone
   when it was confirmed or picked up. A confirmation not picked up within `approval_pickup_sec` (default 300 s)
   expires. `DELETE /auth/api/approvals/{id}` withdraws a pending request.
4. **Check** the confirmation (§4), then carry the action out.

### 1.1 Browser entry

The application creates the request in its back end with `return_url` (exactly one of
`apps[<id>].approvals.return_urls`) and `state` (1–128 printable ASCII characters, random, kept in the person's
session), then redirects the browser to `approve_url` — the pattern of pushed authorization requests (RFC 9126): the
fields never travel through the browser. TinySesam requires that the signed-in account is `subject`, then step-up and
decision, then sends the browser to `return_url?approval=<id>&state=<state>`, with `&result=rejected` or
`&result=expired` when it was not confirmed. The confirmation is **never** in that address. The application compares
`state` with its session, picks the confirmation up in its back end (step 3) and passes `state` as `expect_nonce` to the
check.

## 2. The confirmation

A JWS in Compact Serialization (RFC 7515), signed with Ed25519, issued by TinySesam in
`tinysesam/approval_token.py` (`issue`) at the moment of the pickup.

**Header** — exactly these three members:

| Member | Value |
|---|---|
| `alg` | `EdDSA` (exactly; RFC 8037) |
| `typ` | `tinysesam-approval+jwt` (compared ASCII case-insensitively, without an `application/` prefix) |
| `kid` | 16 lowercase hexadecimal digits: the first 16 hex digits of SHA-256 over the 32 raw public key bytes |

**Payload** — a JSON object:

| Claim | Type | Meaning |
|---|---|---|
| `iss` | string | TinySesam's `base_url` without a trailing slash |
| `aud` | string | the application's id — **one string, never an array** (RFC 7519 §4.1.3 allows an array; a confirmation does not) |
| `sub` | string | the account that confirmed (decimal id) |
| `iat`, `nbf` | integer | the pickup, equal to each other |
| `exp` | integer | `nbf + approval_token_ttl_sec` (30–300 s, default 120) |
| `jti` | string | the approval id (`apv_…`) — handed out once |
| `auth_time` | integer | when the person stepped up for this approval |
| `amr` | array of strings | how (RFC 8176: `pwd`, `otp`, `pin`, `hwk` + `user` for a passkey; `oidc` for a fresh sign-in at the provider) |
| `act` | object | who asked: `{"sub": "app:<application id>"}` (RFC 8693 §4.1) |
| `authorization_details` | array | **exactly one** object: `type` plus the fields, exactly as stored (RFC 9396 §2) |
| `ts_payload_sha256` | string | SHA-256 over the canonical form (§6) of that one object, base64url without padding |
| `nonce` | string | only with a browser entry: the application's `state`, unchanged |

Unknown claims MUST be ignored. A field value is a string, an integer within ±(2^53 − 1) or a boolean — nothing else.
TinySesam refuses control characters (C0, DEL, C1), the bidi controls and the line and paragraph separators in string
values when the application asks, so a confirmation never carries them.

## 3. Keys

The confirmations have a key set of their own, served at `https://<auth host>/auth/approvals/jwks.json` (purpose
`approval`, `tinysesam keys rotate --purpose approval`). It is **never** the gate key set (`/auth/gate/jwks.json`):
the proxy checks gate tokens by the key alone, so only separate keys keep a confirmation out of a gate cookie and a
gate token out of an approval check (RFC 8725 §3.11, §3.12). A helper MUST NOT accept a key of the gate key set for a
confirmation, and a gate client MUST NOT accept an approval key.

The rules for key set entries ([`gate-client.md`](gate-client.md) §4.3) and for fetching the set (§5 there: the
deadline of 5 s, 64 KiB, freshness 60–3600 s, one attempt per 10 s, the order per request) apply word for word, with
this URL. A previous key stays in the set for `keys.APPROVAL_OVERLAP_SEC` (600 s) after a rotation — longer than any
confirmation it signed can live.

## 4. Checking order

The helper checks in this order and reports the class of the **first** failing step. The vectors expect exactly that
class.

1. – 8. **As [`gate-client.md`](gate-client.md) §4.4 steps 1–8**, with `typ` = `tinysesam-approval+jwt` and the
   **approval** key set: size (4096 bytes) and structure → `malformed`; header JSON → `malformed`; a header member
   besides `alg`, `typ`, `kid`, an `alg` other than `EdDSA`, a `typ` other than this one → `header`; `kid` → `kid`;
   signature length and verification → `signature`; no key set → `key_unavailable`; payload JSON → `malformed`, never
   parsed before the signature is verified.
9. **Claims** → `claims`, in this order: every claim of §2 but `nonce` is present; `iss` is a string; `sub` a non-empty
   string without a control character; `iat`, `nbf`, `exp`, `auth_time` integers from 0 to 2^53 − 1; `jti` a non-empty
   string of at most 128 characters without a control character; `amr` a non-empty array of such strings (at most 32
   characters each); `act` an object whose `sub` is such a string; `ts_payload_sha256` a string; `nonce`, if present,
   such a string; `aud` is a string (an array → `claims`); `authorization_details` is an array of exactly one object
   with a string `type` (at most 100 characters) and only string, integer and boolean values; `ts_payload_sha256`
   equals the digest of that object (§6); `iat ≤ nbf` and `auth_time ≤ iat`.
10. **Values**, in this order: `iss` ≠ the configured issuer → `issuer`; `aud` ≠ the application's own id →
    `audience`; `exp ≤ nbf` or `exp − nbf > 300` → `lifetime`; `nbf > now + leeway` → `not_yet_valid`;
    `exp + leeway ≤ now` → `expired`.
11. **Binding to the stored action**, in this order: `authorization_details[0].type` ≠ the action the application is
    about to carry out → `approval_type`; the other members of that object ≠ the fields the application stored when
    it asked — the same names, the same JSON types (`1`, `"1"` and `true` are three different values) and the same
    values → `approval_fields`; `sub` ≠ the account the application acts for → `subject`; when the application kept a
    `state` (browser entry): `nonce` missing or ≠ that state → `nonce`.
12. **Once:** write `jti` atomically into the application's own store (an `INSERT` with a unique key), kept until
    `exp + leeway`. Already there → `replay`. This step comes last, so that a confirmation refused for another reason
    does not use up its id.

Then the application runs its own rules again (still the owner? does the thing still exist?) and carries the action
out. Issuer and the application's id come from configuration, never from the request.

**Clock leeway.** The default is **0**. A helper MAY allow a configured leeway of at most **30 seconds** (a
confirmation lives minutes, not an hour); a larger, a negative or a non-integer value is a configuration error at
start-up. With leeway `L` a confirmation is valid while `nbf ≤ now + L` and `now < exp + L`.

## 5. Errors

| Class | Step | Meaning |
|---|---|---|
| `malformed` | 1–3, 8 | size, structure, base64url, JSON, duplicate members |
| `header` | 4 | a forbidden or unknown header member, wrong `alg`, wrong `typ` (a gate token among them) |
| `kid` | 4, 6 | `kid` missing or malformed, or not in the approval key set (the gate key among them) |
| `signature` | 5, 7 | wrong length or verification failed |
| `key_unavailable` | 6 | no key set could be obtained |
| `claims` | 9 | a missing claim, a wrong type, `aud` as an array, not exactly one entry, the digest, the order of the times |
| `issuer` | 10 | wrong `iss` |
| `audience` | 10 | another application's id |
| `lifetime` | 10 | `exp − nbf` not in (0, 300] |
| `not_yet_valid` | 10 | before `nbf − leeway` |
| `expired` | 10 | at or after `exp + leeway` |
| `approval_type` | 11 | another action |
| `approval_fields` | 11 | other fields: a name, a JSON type or a value |
| `subject` | 11 | another account |
| `nonce` | 11 | another browser session (browser entry) |
| `replay` | 12 | the confirmation was used before |

Every class means the same: **do not carry the action out.** The classes exist for logs and tests. Logs carry the class,
the `kid` and the `jti`, never the confirmation itself.

## 6. The canonical form and the digest

`ts_payload_sha256` is base64url (no padding) of SHA-256 over the UTF-8 bytes of the entry in the JSON
Canonicalization Scheme (RFC 8785). For the values a confirmation can hold this is: the members sorted by name
(ASCII), no whitespace, `"name":value` pairs joined by `,` inside `{}`; strings in UTF-8 with only `"` and `\` escaped
(as `\"` and `\\` — TinySesam refuses the control characters that JCS would escape otherwise); integers in plain
decimal without exponent, sign only when negative; `true` and `false`. A helper SHOULD use a maintained RFC 8785
library; where none exists it MAY implement exactly this subset. The vector `valid-escapes-int-bool` covers quotes, a
backslash, non-ASCII text, a negative integer and a boolean.

## 7. The `jti` store

TinySesam hands a confirmation out once (`approved` → `consumed`), and the application remembers its `jti` until it
expires: a copy taken between pickup and execution is worthless. The store MUST be shared by every process of the
application (a database table with a unique key; not process memory when several workers run) and MAY forget an entry
after `exp + leeway`. The vectors model it with `input.seen`: the ids already in the store before the check.

## 8. The helper

One function per client, named in the client's style:

```text
verify_approval(token, keys, issuer, app_id, expect_type, expect_fields, expect_sub, jti_store,
                expect_nonce = none, now = clock, leeway = 0) → claims | error class
```

`keys` is the approval key set (a fixed set or the JWKS URL of §3); `jti_store(jti, until)` answers true only the first
time. The helper never fetches anything but the configured key set and never logs the token.

## 9. Test vectors

`vectors/approval.json` is generated by `scripts/_approval_vectors.py` from TinySesam's own issuing path (a probe
installation hands the valid confirmations out through `Approvals.pickup` under a fixed clock); never edit it by hand.
`tests/test_approval_vectors.py` checks that it is current, that every attack class below has a vector, that the
Python reference passes all of them, and that every attack vector carries **one defect**: with one rule of the
reference switched off it is accepted — except the few listed there with the reason (a real gate token, which differs
in everything; a signature under a trusted `kid` by another key; a missing claim; an empty entry list). A helper MUST
check `"format": 1`.

| Member | Content |
|---|---|
| `keys` | the test keys: `P` the active approval key of the probe, `Q` the previous one, `A` the **gate** key of `vectors/keys.json`, `X` the attacker's — seeds printed, public test material, never used anywhere else |
| `defaults` | `issuer`, `app_id`, `now`, `max_lifetime` (300), `max_leeway` (30) |
| `vectors[]` | `input`: `jws`, `now`, `leeway`, `issuer`, `app_id`, `jwks` (the approval key set), `expect` (`type`, `fields`, `sub`, optional `nonce`), `seen` (ids already in the `jti` store) → `expected`: `ok: true` with the `claims`, or `ok: false` with the `error` class |

### Attack classes

| Class | What it attacks |
|---|---|
| `typ-wrong` | `typ` of a gate token, no `typ`, the `application/` form |
| `alg-wrong` | another `alg` over an Ed25519 signature |
| `embedded-key` | a key URL in the header (`jku`) |
| `gate-token` | a real gate token presented as a confirmation |
| `gate-key` | a confirmation signed with the gate key (a checker that also trusts the gate key set accepts it) |
| `foreign-key` | the attacker's key under its own or a trusted `kid`, a retired key |
| `bad-signature` | a payload changed after signing |
| `aud-array` | `aud` as an array holding the application's id |
| `details-count` | two entries, none, an object instead of an array |
| `hash-mismatch` | the digest of another entry, the digest over a non-canonical form |
| `claim-types` | a missing `auth_time`, `act` or `jti`, `amr` as a string, a value of an unsupported type, `auth_time` after `iat` |
| `unicode-control` | a line feed in `sub` |
| `issuer` | a trailing slash |
| `audience` | the id of another channel of the same product |
| `lifetime` | more than 300 s |
| `expired` | at `exp`, at the edge of the leeway |
| `not-yet-valid` | before `nbf` |
| `type-mismatch` | another action of the same application |
| `field-mismatch` | another value, a field more or less, an integer for a string, a boolean for an integer |
| `subject` | another account |
| `nonce` | another state, no `nonce` where one is expected |
| `replay` | a `jti` already in the store |

## 10. What a helper MUST NEVER do

- accept a gate token, or take a key from the gate key set (or the gate's `sign_key`) for a confirmation;
- carry the action out before every step of §4 passed — the `jti` written included;
- compare the fields loosely (convert types, trim, case-fold, ignore an extra or a missing field) or accept a second
  entry;
- take the action, its fields, the account or the state from the confirmation instead of from what the application
  stored when it asked;
- read a confirmation from a URL, or put one into a URL, a log line or an error message;
- take the algorithm, the key or a key URL from the token, or parse the payload before verifying the signature.

## 11. References

- [`gate-client.md`](gate-client.md) §4.3, §4.4 steps 1–8 and §5 — taken over word for word with another `typ` and key
  set; [ADR-12](../backlog/ADR-12-key-purposes-keyrings-and-rotation.md) — one purpose per key.
- `tinysesam/approval_token.py` (issuing, reference check), `tinysesam/approvals.py` (requests, page, pickup),
  `SECURITY.md` "Approvals".
- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7519 (JWT), RFC 8037 (Ed25519 in JOSE), RFC 8176 (`amr` values), RFC 8693 §4.1
  (`act`), RFC 8725 (JWT best practices), RFC 8785 (JCS), RFC 9126 (pushed authorization requests), RFC 9396 (rich
  authorization requests).
