# Gate client specification

Version 2 (format 2 of the vectors). Status: draft for the first clients ([T-28](../backlog/T-28-go-variant-small-gate-client.md)).

**Changes from version 1:** the identity carries `account_kind` (`user` or `service`), from the header `Remote-Kind`
or the claim `ts_kind`; both are mandatory, and a request or token without them is refused (§2.2 rules 6–8, §4.4 step
9). The top bar data carries `menu_links` (§8). There is no transition rule: a version 2 client against an older
TinySesam or an older proxy template refuses every request, which is intended — update TinySesam and the proxy first,
then the applications (`SECURITY.md`). A version 1 client keeps working against a version 2 TinySesam: it reads six
headers and ignores unknown claims.

**Additions within version 2 ([T-101](../backlog/T-101-stage-s5-permissions-at-the-server-and-in-the-clients.md)):**
the identity carries `permissions` — the account's permissions for the application, from the header
`Remote-Permissions` or the claim `ts_perms` (§3.4); `account.json` carries `permissions` (§8a); a client offers
`has_permission` and `register_permissions` (§3.4). The member is optional on the wire — missing means "none" — so a
client without it still conforms to every earlier vector; `vectors/permissions.json` holds the new ones.

A **gate client** is a small library inside an application that runs behind TinySesam's gate
([ADR-9](../backlog/ADR-9-gate-token-at-the-proxy.md)). It answers one question per request: *who is this, and may
they do this?* It does not sign anyone in, holds no session and issues nothing. Sign-in, sessions, approvals per
application and the issuing of gate tokens stay in TinySesam.

This document is normative. The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in
RFC 2119 and RFC 8174 when, and only when, they appear in capitals. The test vectors in [`vectors/`](vectors/) are part
of the specification: a client conforms when it passes every vector of the parts it implements. Clients live under
[`clients/`](../clients/README.md) (Go, Rust, JS/TS, PHP), the Python client is the module
`tinysesam.gate_client` in the package itself (WSGI/ASGI, no FastAPI dependency).

## 1. Two operating modes

| | Header mode | Token mode |
|---|---|---|
| The application trusts | the `Remote-*` headers the proxy sets | the signature of the gate token |
| Who checks the token | the proxy (Caddy with caddy-jwt, `deploy/forward-auth/Caddyfile.gate`) or `/auth/forward` | the client |
| Needs | a proxy that fulfils §2.1, and no other way to the application | the public gate key(s), §4 |
| Identity from | `Remote-User`, `-Name`, `-Email`, `-Groups`, `-Id`, `-Auth`, `-Kind`, `-Permissions` | the claims `sub`, `ts_user`, `ts_name`, `ts_email`, `ts_groups`, `ts_id`, `ts_auth`, `ts_kind`, `ts_perms` |

A client MUST implement at least one mode and SHOULD implement both. The mode MUST be chosen explicitly by
configuration; a client MUST NOT fall back from token mode to header mode, nor guess the mode from the request. In token
mode the client MUST ignore every `Remote-*` header for identity and authorization.

Both modes produce the same **identity**:

| Field | Type | Meaning |
|---|---|---|
| `user` | string | the account name (sign-in identifier) |
| `name` | string | the display name, may be empty |
| `email` | string | may be empty |
| `groups` | list of strings | the roles, see §3.3 |
| `id` | string | the account ID, decimal digits; the only value that survives a rename |
| `auth` | string | how the request signed in: `session`, `oauth`, `apikey`, `app-password`, or empty |
| `kind` | `session` or `token` | `session` only when `auth` is exactly `session`, otherwise `token` |
| `account_kind` | `user` or `service` | what the account is: `service` for a service account, otherwise `user`; never empty |
| `permissions` | list of strings | the account's permissions for this application, see §3.4; empty when none is sent |

An application SHOULD key its own records by `id`, never by `user`, `name` or `email`.

`kind` says how the request signed in, `account_kind` what the account is: a paired service acting as a person is
`kind = token` and `account_kind = user`. The field is called `account_kind` because `kind` was taken in version 1;
the header, the claim and TinySesam's `forward_headers` slot are still `Remote-Kind`, `ts_kind` and `kind`.

## 2. Header mode

### 2.1 Duties of the proxy

The client cannot verify where a header came from. Header mode is only safe when the deployment guarantees all of
the following, and a client's documentation MUST state them:

1. The proxy **removes** every `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`, `Remote-Id`,
   `Remote-Auth`, `Remote-Kind` and `Remote-Permissions` the client sent, on **every** path — including public share paths, where it then
   sets none. (A proxy template older than version 2 passes a client's `Remote-Kind` through unchanged; the client
   cannot tell. Hence the order: proxy first, then the applications.)
2. The proxy sets each header only from TinySesam's answer (`/auth/forward`) or from the claims of a gate token it has
   verified itself, and sets a header only when the value is not empty.
3. The application is reachable **only** through that proxy (bound to a loopback or private address, or protected by
   mutual TLS). A second way in — a published port, a sidecar, another virtual host — makes every header forgeable.
4. The proxy removes TinySesam's cookies (`tinysesam_*`, `__Host-tinysesam_*`) and the client's `Authorization` and
   `X-Api-Key` before the application, unless the application checks them itself. A server-side top bar or account
   helper (§8, §8a) needs the session cookie at the application; letting exactly that one through is a deliberate
   exception with a price, described in §8.

A client SHOULD offer a list of trusted peer addresses and refuse header mode for requests from any other peer. It MUST
NOT read identity from any other header (`X-Forwarded-User`, `X-Remote-User`, `X-Auth-Request-*`, …). It MAY let the
header names be configured, because TinySesam's `forward_headers` can rename them; the vectors use the default names.

### 2.2 Reading the headers

Header field names are case-insensitive. For each of the eight headers (`Remote-Permissions` included — missing or
empty is no error, it means no permissions):

1. A field that occurs more than once (also under different spellings) is an error `header`. The client MUST NOT
   join the values or pick one.
2. The value is UTF-8 on the wire: TinySesam always sends the UTF-8 bytes of the value, also for names beyond
   Latin-1. The client MUST decode the octets as strict UTF-8; invalid or overlong sequences are an error `header`.
3. A value containing a C0 control character (U+0000–U+001F, tab included) or DEL (U+007F) is an error `header`. The
   client MUST NOT strip such characters: `boss\x01` stripped would be the name of another account. TinySesam removes
   them before sending, so a well-formed request never has one.
4. A missing or empty `Remote-User` is the error `unauthenticated`.
5. A non-empty `Remote-Id` that is not one or more ASCII digits `0`–`9` is an error `header` (Unicode digits such as
   U+0661 are not digits here).
6. A missing or empty `Remote-Kind` is an error `header` — never taken as `user`. A client SHOULD log it as
   `header: Remote-Kind missing (TinySesam/proxy older than spec v2?)`, without values.
7. A `Remote-Kind` that is not exactly `user` or `service` (case-sensitive, no folding, no trimming inside) is an
   error `header`.
8. `Remote-Kind: service` together with `Remote-Auth: session` is an error `header`: a service account has no session,
   and TinySesam never sends this pair.

The rules apply in this order. Rule 4 comes before rules 5–8: a request without `Remote-User` is `unauthenticated` even
when `Remote-Kind` is missing too — an anonymous request on a public share path must not appear as `header`.

Leading and trailing whitespace of a field value is not part of the value (RFC 9110 §5.5); HTTP libraries remove it.

### 2.3 `Remote-Auth` and the kind of a request

`Remote-Auth` says how the request signed in ([T-75](../backlog/T-75-sign-in-kind-in-forward-auth.md)):

| Value | Kind | Note |
|---|---|---|
| `session` | `session` | a browser session; also every gate token |
| `oauth` | `token` | an OAuth access token |
| `apikey` | `token` | an API key; never carries `admin` |
| `app-password` | `token` | an app password (WebDAV, CalDAV, Git) |
| empty, missing, any other value | `token` | `auth` is reported empty |

The groups of a token request are **incomplete on purpose** (a token never carries `admin`, an OAuth token may carry a
subset). Therefore:

- A request is a session only when `Remote-Auth` is exactly `session` (case-sensitive). An empty or missing value — an
  older TinySesam, a renamed header set, an unknown way in — counts as a token, never as a session.
- A client MUST NOT conclude from a group missing in a token request that the account lacks it (do not revoke, do not
  sync it away). It MAY offer a guard that requires `kind == session`.

### 2.4 Errors in header mode

| Class | When |
|---|---|
| `unauthenticated` | no or empty `Remote-User` |
| `header` | a repeated field, invalid UTF-8, a control character, a malformed `Remote-Id`, a missing or malformed `Remote-Kind`, `service` with `session` |

## 3. Identity rules shared by both modes

### 3.1 Comparison

Names, groups, the issuer and the audience are compared **exactly**, code point by code point: no case folding, no
Unicode normalization, no trimming beyond §3.3, no confusable mapping. `Admin` is not `admin`, and a Cyrillic `а` in
`аdmin` makes another group. A client MUST NOT add any of these conveniences to a guard.

### 3.2 Display

Names may contain any character except C0 controls and DEL — bidirectional overrides (U+202E) and zero-width
characters included. Rendering them safely (escaping in HTML, isolating bidi text) is the application's job; a client
SHOULD say so.

### 3.3 Groups

`Remote-Groups` and the claim `ts_groups` carry the roles as **one string**, joined with `,` (TinySesam joins without
spaces; the admin flag appears as the group `admin`). To read it:

1. Split at every `,`.
2. Remove leading and trailing spaces (U+0020) from each entry. A tab is a control character and has already been
   refused (§2.2, §4.5).
3. Drop empty entries and repeated entries (keep the first occurrence, keep the order).

There is **no escape mechanism**: a backslash, a quote or a percent sign is an ordinary character, and a role name that
contains a comma cannot be represented (TinySesam refuses commas, control characters and surrounding spaces in role
names, [T-85](../backlog/T-85-role-names-without-comma.md)). `has_role(identity, role)` is `role ∈ groups`, exactly.
A client MUST NOT imply other roles from `admin`; whether an admin passes every role check is the application's
decision and not part of the identity.

### 3.4 Permissions

`Remote-Permissions` and the claim `ts_perms` carry the account's permissions for the application of the request's
host ([ADR-17](../backlog/ADR-17-permission-layer-and-admin-levels.md); TinySesam's `apps[id].hosts`) as **one
string**, joined with `,`. They are read exactly like the groups (§3.3): split at every `,`, trim spaces, drop empty
and repeated entries, no escapes. A missing header or claim, or an empty value, is the empty list — never an error and
never "unknown": TinySesam sends nothing for a host of no application and for an account without permissions.

- `has_permission(identity, permission)` is `permission ∈ permissions`, exactly (§3.1). A client MUST NOT imply a
  permission from `admin`, from a role, from a prefix (`docs.*`) or from another application's set.
- A permission name follows `^[a-z][a-z0-9_-]{0,31}(\.[a-z0-9_-]{1,32}){1,3}$`; a client compares what it gets and does
  not refuse a request for an entry outside the rule (TinySesam never sends one; comparing exactly makes it harmless).
- **When a change counts:** in token mode and at the proxy's fast path once the gate token expires
  (`gate_token_ttl_sec`, default 300 s); through `/auth/forward`, in TinySesam's library and through the service path
  (`GET /auth/api/users/{id}/permissions?app=`) at the next request.
- **Registering** (`register_permissions(base_url, app, permissions, api_key)`): the client sends the application's
  whole manifest as `PUT <base_url>/auth/api/apps/<app>/permissions` with the JSON body `{"permissions": [...]}` and the
  automation key of the application's service account in `X-Api-Key` (scope `permissions:register`), straight to
  TinySesam, never through the proxy. Before it sends anything it refuses (error `invalid`): a base URL that is not
  `https` (plain `http` only to a loopback address, §5 rule 1), an application id outside `^[a-z][a-z0-9_]{0,31}$`, a
  manifest that is no list or has more than 200 entries, an entry that is no object or whose `name` breaks the rule
  above, and a name twice. Registering grants nothing; TinySesam answers `added`, `updated`, `returned` and
  `orphaned` (lists of names) and checks labels and descriptions itself. `vectors/permissions.json` (`register`)
  fixes the request and the refusals.

## 4. Token mode

### 4.1 The token

A gate token is a JWS in Compact Serialization (RFC 7515) with three base64url segments `header.payload.signature`,
signed with Ed25519. TinySesam issues it in `tinysesam/gate.py` (`issue`) when `/auth/forward` succeeds for a browser
session with `gate_token_enabled`.

**Header** — exactly these three members, nothing else:

| Member | Value |
|---|---|
| `alg` | `EdDSA` (exactly; RFC 8037) |
| `typ` | `tinysesam-gate+jwt` (compared ASCII case-insensitively, without an `application/` prefix) |
| `kid` | 16 lowercase hexadecimal digits: the first 16 hex digits of SHA-256 over the 32 raw public key bytes |

**Payload** — a JSON object:

| Claim | Type | Meaning |
|---|---|---|
| `iss` | string | the issuer: TinySesam's `base_url` without a trailing slash (`"tinysesam"` without `base_url`) |
| `aud` | string, or array of strings | the audience: the application's host, with required roles `host\|roles=a,b;c` (`gate.audience`) |
| `sub` | string | the account ID |
| `iat`, `nbf` | integer | issuing time, equal to each other (seconds since the epoch) |
| `exp` | integer | expiry: `nbf + gate_token_ttl_sec` (30–3600 s, default 300) |
| `jti` | string | a random identifier |
| `ts_user`, `ts_name`, `ts_email`, `ts_groups`, `ts_id`, `ts_auth`, `ts_perms` | string | the identity; each only when the installation's `forward_headers` include that slot (`ts_perms`: the slot `perms`, §3.4) |
| `ts_kind` | string | **mandatory since version 2:** `user` or `service`, in every token whatever `forward_headers` lists. A gate token is issued only for a session, so in practice it is always `user` |

Unknown claims MUST be ignored. `ts_auth` of a gate token is always `session`; a token without `ts_auth` counts as kind
`token` (§2.3). The identity of a valid token is: `user` = `ts_user`, `name` = `ts_name`, `email` = `ts_email`,
`groups` = §3.3 over `ts_groups`, `id` = `sub`, `auth`/`kind` from `ts_auth` as in §2.3, `account_kind` = `ts_kind`,
`permissions` = §3.4 over `ts_perms`; any other missing claim gives an empty value. A token issued before the update has no `ts_kind` and is refused until it
expires (at most `gate_token_ttl_sec`); the proxy then takes the way back through `/auth/forward`, and the browser gets a
fresh token.

### 4.2 Where the token comes from

The client reads the token from exactly one configured source: the gate cookie (default name `__Host-tinysesam_gate`,
`gate_cookie_name`) or a request header named by configuration. More than one gate cookie in a request is an error
`malformed`. A client MUST NOT take the token from a query parameter, a form field or `Authorization` unless that
source is configured explicitly.

Note on delivery: the proxy template `Caddyfile.gate` removes the gate cookie before the application, and on the way
back through `/auth/forward` the fresh token reaches only the browser. How an application in token mode gets the token
reliably is open ([T-84](../backlog/T-84-token-mode-delivery-to-the-application.md)); this specification fixes how it
is checked.

### 4.3 Keys

The client knows the public keys from its configuration, never from the token:

- **Fixed key:** the output of `tinysesam gate-key --db …` (32 raw bytes, standard Base64 — the proxy's `sign_key`).
  The client computes its `kid` as in §4.1. It MAY accept several fixed keys (before and after a rotation).
- **JWKS:** a URL configured by the operator, normally `https://<auth host>/auth/gate/jwks.json`, fetched as in §5.
  A URL whose path (without trailing slashes) ends in `/approvals/jwks.json` is the approval key set and is refused
  at configuration ([`approval-token.md`](approval-token.md) §3).

Both reduce to a key set `kid → 32-byte Ed25519 public key`. A JWKS entry is usable only when all of these hold;
otherwise it is skipped and the others stay usable:

- `kty` is `OKP` and `crv` is `Ed25519`;
- `x` is strict base64url (§4.4) of exactly 32 bytes;
- `kid` is a string equal to the first 16 hex digits of SHA-256 over those 32 bytes (a `kid` of one's own choosing,
  e.g. in a test fixture, makes the entry unusable: a set with no usable entry is a failed fetch and gives
  `key_unavailable`, §5; with other usable entries the token gets `kid`);
- `alg`, if present, is `EdDSA`; `use`, if present, is `sig`; `key_ops`, if present, is an array containing `verify`;
- it has no `d` (private material), `x5u`, `x5c`, `x5t`, `x5t#S256` or `jku`.

Two entries with the same `kid` make that `kid` unusable. A document that is not an object, has no `keys` array, or has
more than 32 entries is the error `jwks_invalid` (for the fetch: a failed fetch, §5).

### 4.4 Checking order

The client checks in this order and reports the class of the **first** failing step. The vectors expect exactly that
class.

1. **Size.** More than **4096 bytes** → `malformed`. (A cookie value cannot be larger in every browser; the largest
   real token is far below.)
2. **Structure.** Exactly three segments separated by `.`; header and payload not empty; each segment consists only of
   `A–Z a–z 0–9 - _`, carries no padding `=`, no whitespace, no line break, and is **canonical** base64url (re-encoding
   the decoded bytes gives the same text; the unused low bits of the last character are zero). Anything else, the JWS
   JSON Serialization included → `malformed`.
3. **Header JSON.** Strict UTF-8 without a byte order mark, a JSON object, no member name twice, no `NaN`/`Infinity`
   → otherwise `malformed`.
4. **Header members.** Any member besides `alg`, `typ`, `kid` — `crit`, `jwk`, `jku`, `x5u`, `x5c`, `cty`, `zip`, `b64`
   among them — → `header`. `alg` not exactly the string `EdDSA` → `header`. `typ` not `tinysesam-gate+jwt` (ASCII
   case-insensitive) → `header`. `kid` missing, not a string, or not 16 lowercase hex digits → `kid`.
5. **Signature length.** The decoded signature is not exactly 64 bytes (an empty one included) → `signature`.
6. **Key.** The `kid` is not in the key set (after §5 for JWKS) → `kid`; no key set can be obtained → `key_unavailable`.
7. **Signature.** Ed25519 verification of the signature over the ASCII bytes `header-segment.payload-segment` with that
   key fails → `signature`. The algorithm is the client's constant, never the header's value.
8. **Payload JSON.** As step 3 → `malformed`. The payload MUST NOT be parsed before the signature is verified.
9. **Claim types and consistency** → `claims`:
   `iss` and `sub` are strings, `sub` not empty; `aud` is a string or a non-empty array of strings; `iat`, `nbf`,
   `exp` are integers (JSON numbers without fraction; not booleans, not strings) from 0 to 2^53 − 1; `jti`, if present,
   is a string; every `ts_*` identity claim that is present is a string; no identity claim and not `sub` contains a C0
   control character or DEL (§2.2 — refused, not stripped); `ts_id`, if present, equals `sub`; `iat` is not later than
   `nbf`; `ts_kind` is present and exactly `user` or `service`; `ts_kind` is not `service` while `ts_auth` is
   `session`.
10. **Values**, in this order:
    `iss` ≠ the configured issuer → `issuer`;
    the configured audience is not `aud` (string) or not an element of `aud` (array) → `audience`;
    `exp ≤ nbf` or `exp − nbf > 3600` → `lifetime`;
    `nbf > now + leeway` → `not_yet_valid`;
    `exp + leeway ≤ now` → `expired`.

Issuer and audience come from the client's configuration — the audience is the exact string the proxy would name in
`audience_whitelist`, including `|roles=…` when the route requires roles. A client MUST NOT derive them from the
request (`Host`, `X-Forwarded-Host`, the URL).

**Clock leeway.** The default is **0**: TinySesam issues and the proxy checks without tolerance. A client MAY allow a
configured leeway of at most **60 seconds**; a larger value, a negative or a non-integer one is a configuration error
at start-up. With leeway `L` a token is valid while `nbf ≤ now + L` and `now < exp + L`. The vectors carry `leeway`
per vector.

### 4.5 Errors in token mode

| Class | Step | Meaning |
|---|---|---|
| `malformed` | 1–3, 8 | size, structure, base64url, JSON, duplicate members, more than one gate cookie |
| `header` | 4 | a forbidden or unknown header member, wrong `alg`, wrong `typ` |
| `kid` | 4, 6 | `kid` missing or malformed, or not in the key set |
| `signature` | 5, 7 | wrong length or verification failed |
| `key_unavailable` | 6 | no key set could be obtained (§5) |
| `claims` | 9 | wrong type, control character, inconsistency, a missing or malformed `ts_kind` |
| `issuer` | 10 | wrong `iss` |
| `audience` | 10 | wrong `aud` |
| `lifetime` | 10 | `exp − nbf` not in (0, 3600] |
| `not_yet_valid` | 10 | before `nbf − leeway` |
| `expired` | 10 | at or after `exp + leeway` |

Every class means the same to the application: **not authenticated**. The classes exist for logs and tests.

## 5. Fetching the key set (JWKS)

caddy-jwt 1.4.0 waited without a deadline for a key set whose first fetch failed, holding a lock — every later request
hung ([ggicci/caddy-jwt#117](https://github.com/ggicci/caddy-jwt/issues/117), the reason `Caddyfile.gate` used
`sign_key` from 0.26.2 until caddy-jwt 1.5.0 fixed it). A gate client MUST NOT behave like that. The rules, with the values the vectors assume:

1. **The URL** comes from configuration only, `https` (plain `http` only to a loopback address). A client MUST NOT
   follow `jku`, `x5u` or any URL from a token, and SHOULD NOT follow redirects to another host.
2. **Deadline.** One fetch takes at most **5 seconds** in total (connect, TLS, headers, body), and its body at most
   **64 KiB**; beyond either it is a failed fetch. No request ever waits longer than this deadline for keys: while a
   fetch is running, other requests either share its result within the same deadline or proceed with the cached set.
   A client MUST include a test against a server that accepts the connection and never answers.
3. **Freshness.** A successful set is fresh for `max-age` of its `Cache-Control` (default **300 s** when absent or
   unreadable), clamped to **60–3600 s**. `no-cache`/`no-store` do not shorten it below 60 s.
4. **Failed fetch:** a network error, a status other than 200, a body that is no strict JSON, `jwks_invalid`, or a set
   without a single usable entry. A failed fetch never replaces the cached set.
5. **Rate.** At most one fetch attempt per **10 s**, whatever the reason (a stale set, an unknown `kid`, a failure).
6. **Order per request:** if there is no set or it is no longer fresh, fetch (if step 5 allows). Then: no set at all,
   or the set is more than **3600 s** past its freshness → `key_unavailable`. If the token's `kid` is not in the set and
   no fetch happened in this request, fetch once more (if step 5 allows). Still unknown → `kid`.
7. A `kid` that fails step 4 of §4.4 never triggers a fetch.

The scenarios in `vectors/jwks.json` simulate the fetches; the deadline, the body limit and the sharing of a running
fetch need tests of their own in each client.

## 6. Failing closed

- Every error, an exception or a panic inside the client included, means **not authenticated**. A client MUST NOT let a
  request through because a check could not be carried out (no key, a timeout, an unexpected type).
- A guard that fails answers 401 (not authenticated) or 403 (authenticated, role missing); a browser route MAY redirect
  to a sign-in address from configuration. The response MUST NOT contain the token, the claims or the error detail.
- Logs carry the error class and the `kid`, never the token, a claim value or a header value of a credential. (caddy-jwt
  logs parts of rejected candidates as `token_string`; that is the counter-example.)
- Configuration errors (no issuer, no audience, no key, a leeway above 60 s, header mode without opt-in) stop the
  application at start-up instead of failing open later.

## 7. What a client MUST NEVER do

- take the algorithm, the key, a key URL or a certificate from the token (`alg`, `jwk`, `jku`, `x5u`, `x5c`);
- accept `alg: none`, an HMAC algorithm, or any algorithm but `EdDSA`;
- accept a token whose signature it has not verified, or parse the payload before verifying it;
- use the `kid` as a file name, a URL part, a database key or in a log line without the format check of §4.4;
- strip control characters from an identity instead of refusing it, or normalize, case-fold or trim names beyond §3.3;
- derive the issuer or audience from the request;
- trust `Remote-*` headers in token mode, or fall back to header mode when a token is missing;
- block a request for longer than the fetch deadline, retry a fetch on every request, or keep using a key set more than
  3600 s past its freshness;
- mint, refresh or extend a gate token (that is TinySesam's job);
- implement Ed25519, base64url decoding of keys or JSON parsing by hand when a maintained library exists (see
  [`clients/README.md`](../clients/README.md)); the structural pre-checks of §4.4 are the client's own code.

## 8. Top bar data (optional)

An application that draws its own top bar fetches TinySesam's data same-origin at `/.tinysesam/topbar.json` on its own
host (the proxy passes `/.tinysesam/*` to TinySesam) or server-side at `/auth/topbar.json` with the request's cookie
([T-76](../backlog/T-76-top-bar-link-visibility.md)).

**Server-side or in the browser.** A server-side helper forwards TinySesam's cookies of the incoming request (only
names starting with `tinysesam_` or `__Host-tinysesam_`, only to the configured URL). Behind a proxy that keeps
duty 4 of §2.1 they never reach the application, so a server-side fetch always reads *signed out*. Letting them through
hands the application the person's browser session: with the session cookie the application — or whoever takes it
over — acts as that person at TinySesam and at every other application behind the gate until the session ends. The
**recommended** way is therefore the browser's: the page fetches `/.tinysesam/topbar.json` or
`/.tinysesam/account.json` same-origin, the proxy passes them to TinySesam with the browser's cookies, and the
application never holds the session. Server-side only for an application one trusts with the session, and then the
proxy lets through exactly what the fetch needs — the session cookie (`tinysesam_session`, the name of
`session_cookie`, set for `cookie_domain`) and, for a host outside the cookie domain, its connection cookie
`__Host-tinysesam_link` (T-26) — and keeps stripping every other TinySesam cookie (CSRF, gate, unlock, flow).
`deploy/forward-auth/Caddyfile.gate` carries this as a commented variant, measured in `tests/test_gate_caddy.py`.

A helper for it MUST:

- treat anything but a JSON object with `signed_in: true` (the boolean) and a string `name` as signed out;
- render only links whose `href` is an absolute `http`/`https` URL or a path that starts with exactly one `/` (not
  `//`, not `/\`), without whitespace or control characters — `javascript:`, `data:` and protocol-relative targets are
  dropped;
- treat every title and name as text, never as markup;
- not cache the answer across sessions (TinySesam sends `no-store`).

The normalized result has the members `brand`, `signed_in`, `name`, `links` and `menu_links` (each a list of
`title`, `href`; `menu_links` are the entries of the account menu, `[]` when the answer has none or no list),
`account`, `admin_panel` and `logout` (each an `href` or `null`) and `approvals` (below); `vectors/topbar.json` shows it.
The same `href` rule applies to both link lists.

An answer MAY carry further members; a client MUST ignore what it does not know and keep normalizing the rest. With
approvals switched on (T-89) TinySesam adds `approvals`: `{"pending": <count>, "href": <URL of /auth/approvals>}` — the
number of approvals waiting for this account and where to decide them. The normalized `approvals` is
`{"pending", "href"}` when `pending` is a JSON integer from 0 to 2^53 − 1 (not a boolean, not a string, no fraction)
and `href` passes the rule above, otherwise `null` — also when signed out. Whoever shows it shows the number with a
word ("Approvals (2)"), never a coloured dot alone. Every client tolerated the member before it was normalized (the
vector `approvals-pending` passed all five unchanged, T-89 stage B part 2).

## 8a. Account overview data (optional)

An application that shows the person's security state on its own settings page (sign-in methods, sessions, connected
programs) fetches it like the top bar: same-origin at `/.tinysesam/account.json` on its own host, or server-side at
`/.tinysesam/account.json` respectively `/auth/account.json` with only TinySesam's cookies of the request
([T-91](../backlog/T-91-app-frame-and-account-overview.md)) — which reach the application only by the deliberate
exception of §8 ("Server-side or in the browser"); the browser way is the recommended one. It is an optional helper: a client without it is still a
complete gate client. TinySesam answers only for a full browser session — an API key, an OAuth token, an app password
or a half session gets `401` — so the check "a person, by browser" stays with TinySesam and the application needs no
route of its own. Reading only: every change happens on TinySesam's account page, which the links lead to.

A helper for it MUST:

- treat anything but status `200` with a JSON object whose `signed_in` is `true` (the boolean) as signed out — in
  particular `401` (`{"authenticated": false, "signed_in": false}`), `404` (a host the installation does not protect)
  and `429` (60 reads per account and minute, with `Retry-After`);
- keep only `href`s that pass the rule of §8 (an absolute `http`/`https` URL or a path starting with exactly one `/`,
  without whitespace or control characters) and set every other one to `null`;
- treat every name and string as text, never as markup — the answer carries no markup member;
- ignore members it does not know and keep normalizing the rest; read a member of the wrong type as missing;
- not cache the answer across sessions (TinySesam sends `no-store` and `Vary: Cookie`).

The members (TinySesam's answer; `null` means "not offered by this installation", `[]` "offered, empty"):

| Member | Type | Meaning |
|---|---|---|
| `signed_in` | boolean | always `true` in a `200` answer |
| `account` | object | `username` (string), `display_name` (string), `source` (list of strings: `local`, `oidc`, `saml`, `ldap`; two or more = a mixed account) |
| `sign_in.password` | string or null | `"set"`, `"unset"`, `"directory"` (kept in a directory), `null` (passwords off) |
| `sign_in.totp` | object or null | `enabled` (boolean), `recovery_left` (integer or null), `recovery_low` (boolean) |
| `sign_in.passkeys` | object or null | `count` (integer), `items` (list of `name`, `created_at`, `last_used`) |
| `sign_in.pin` | boolean or null | a PIN is set |
| `sessions` | object | `count` (integer), `items` (list of `created_at`, `last_seen`, `method`, `device`, `current`) |
| `programs.oauth` | list or null | connected programs (OAuth): `name`, `created_at`, `last_used` |
| `programs.services` | list or null | paired services: `name`, `created_at`, `last_used` |
| `programs.app_passwords` | list or null | live app passwords: `name`, `created_at`, `last_used`, `expires_at` |
| `programs.api_keys_active` | integer or null | number of active API keys |
| `approvals` | object or null | `pending` (integer) |
| `permissions` | object or null | on an application's host (§3.4): `app` (string, the application id) and `names` (list of strings); `null` on any other host |
| `links` | object | `account`, `sessions`, `totp`, `passkeys`, `devices`, `app_passwords`, `services`, `approvals`: each an `href` or `null` |

Times are Unix seconds (integer) or `null` (never used). `device` is a coarse "browser · system" taken from the
User-Agent, or `null`; `current` is `true` for the session of this request, `false` for the others, `null` when the
answer does not know the request's session. The answer never carries an address, a hash, a secret, a key prefix or the
id of another object. On an application's host the links carry `app=<host>`, so TinySesam's account page opens in that
application's frame; the anchors (`#sessions`, `#totp`, `#passkeys`, `#devices`, `#app-passwords`, `#services`) are
stable.

The normalized result of a helper (`vectors/account.json` shows it):

- **Signed out** — any answer but a `200` with a JSON object whose `signed_in` is `true`: `{"signed_in": false}` with
  `account`, `sign_in`, `sessions`, `programs`, `approvals`, `permissions` and `links` all `null`.
- **Signed in** — every member of the table is present, unknown ones are dropped:
  - a text, a flag or a count of the wrong type reads as `null`; a count or a time is a JSON integer from 0 to
    2^53 − 1 (a negative number, a fraction, a boolean or a string is none);
  - `account`, `sign_in`, `sessions`, `programs` and `links` are always objects: an answer without them, or with
    another type, gives the object with every member `null`;
  - `sign_in.totp` and `sign_in.passkeys` are an object or `null` (not offered); `programs.oauth`, `programs.services`
    and `programs.app_passwords` a list or `null`; `sessions.items` and `sign_in.passkeys.items` always a list (`[]`
    when the answer has none or no list); an entry of a list that is no object is dropped, the members of an entry
    follow the same rules;
  - `approvals` is `{"pending": <count>}` when `pending` is a count, otherwise `null`;
  - `permissions` is `{"app": <text or null>, "names": [<texts>]}` when the answer's member is an object (an entry of
    `names` that is no string is dropped; `names` that is no list reads as `[]`), otherwise `null` — also signed out;
  - every member of `links` is an `href` that passes the rule of §8, or `null`;
  - `sign_in.password` is kept as text — a value besides the three of the table is for the application to ignore;
  - `account.source` is a list of texts or `null`: an entry that is no string is dropped, a value that is no list reads
    as `null`, an unknown text is kept for the application to ignore.

## 8d. Shell component (optional)

An application that shows TinySesam's bar instead of drawing its own loads the shell component
([T-103](../backlog/T-103-stage-s7-shell-on-top-and-at-the-side-one-component-lay.md)) — no client code at all, the
browser does everything. Sections 8b and 8c are kept for the administrator's data and the action pages of milestone
M-2.

```html
<head>
  <script src="/.tinysesam/shell.js" nonce="…"></script>   <!-- library: /auth/shell.js -->
</head>
<body>
  <ts-shell current="/docs"></ts-shell>                      <!-- layout="top" | "side" optional -->
```

- **Where.** `shell.js` and `shell.css` lie beside the data: `/.tinysesam/` on the application's host (the proxy passes
  `/.tinysesam/*` to TinySesam, see §8; only a host TinySesam protects, else `404`) and `/auth/` for an application with
  TinySesam as a library. With `topbar_enabled = false` both answer `404`. They carry `Cache-Control: no-cache` and an
  `ETag`, so a changed configuration shows at once.
- **What the script does.** It restores light/dark before the first paint (the class `dark` on `<html>`, the choice in
  `localStorage.themeMode`), adds `shell.css` to the document (the `--ts-*` tokens and the room for the side bar) with
  its own nonce, and defines `<ts-shell>`. The element fetches `topbar.json` beside the script (same origin, the
  browser's cookies) and draws the bar of TinySesam's own pages in its shadow DOM, with the same CSS. A page with a
  strict CSP needs nothing but the nonce on the `<script>`: every element the component adds carries it, and it uses no
  inline handler, no `style=` attribute and no system dialog.
- **Attributes.** `layout`: `top` (the top bar) or `side` (a 248 px side bar on the left; the `<body>` gives way with
  `padding-left`; below 900 px it folds back into the top bar). Without it the answer's `frame.layout` holds.
  `current`: the path of the page shown; the link to it carries `aria-current="page"`.
- **Differences to TinySesam's own pages, on purpose.** "Sign out" is a link to `logout.href` (TinySesam's sign-out
  page) — a form would need TinySesam's CSRF token, which the application's page does not hold —, and without an app
  frame the name leads to `/` of the page's own origin.

The member `frame` of the answer of §8 (always present; a client that does not draw a shell may ignore it, like every
member it does not know):

| Member | Type | Meaning |
|---|---|---|
| `frame.layout` | `"top"` or `"side"` | `apps[id].layout` of the application whose `hosts` name this host, else `shell_layout` |
| `frame.name` | string or null | the application's name in its app frame (`forward_apps[host]` with `home` or `links`), else `null` |
| `frame.home` | href or null | where "‹ name" leads back to — only for a signed-in person, like the bar of TinySesam's framed pages |
| `frame.links` | list of `title`, `href` | the frame's links the person may see, as addresses on the application's host; `[]` signed out |

In an app frame `account.href` and `approvals.href` carry `app=<host>`, so TinySesam's pages open in that frame.
`/auth/topbar.json?app=<host>` answers the same `frame` for a library; a host without an entry changes nothing in the
answer. Every `href` the component draws passes the rule of §8; titles and names are text, never markup.

A link of `topbar_links`, `topbar_menu_links` or a frame may be limited to the holders of one permission of one
application (`{"permission": "docs.delete", "app": "docs"}`, besides `{"admin": true}` and `{"role": "…"}`): the answer
lists it only for them. Visibility is a convenience, not a protection — the target checks the permission itself.

## 9. Test vectors

Generated by `scripts/_gate_vectors.py` from TinySesam's own issuing path with fixed test keys and a fixed clock;
never edit them by hand. `tests/test_gate_vectors.py` checks that they are current, that every attack class below has
a vector, and that the Python gate client (`tinysesam.gate_client`) passes all of them. Every file carries `"format": 2`;
a client MUST check that number in its tests, so that vectors of another version cannot pass it unseen. Since every
request TinySesam answers carries `Remote-Kind`, the header vectors about other defects carry `Remote-Kind: user`.

| File | Content |
|---|---|
| `keys.json` | the three **test keys** (`A` active, `B` previous, `X` attacker): seed, public JWK, `sign_key_base64` (the proxy's `sign_key` form). Public test material — never use it anywhere else. |
| `token.json` | token mode: `input` (`jws`, `now`, `leeway`, `issuer`, `audience`, `jwks`) → `expected` (`ok` + `claims` + `identity` [+ `has_role`], or `ok: false` + `error`) |
| `headers.json` | header mode: `input.headers` → `expected` (`identity` [+ `has_role`] or `error`). A header value is a string of octets, one code point U+0000–U+00FF per octet (convert with Latin-1); a list means the field occurred more than once |
| `jwks.json` | `sets`: a JWKS document → usable `kids` in order, or `error: jwks_invalid`; `scenarios`: steps with `now`, `jws` and a simulated `fetch` answer (`status`, `cache_control`, `body` or `body_text`, or `error`) → `expect` (`fetched`, `ok`, `error`). A client that fetches where no `fetch` is given fails the step |
| `topbar.json` | §8: `input.topbar` → the normalized `expected.topbar` |
| `account.json` | §8a: `input.account` (the body of a `200` answer) → the normalized `expected.account` |
| `permissions.json` | §3.4: `headers` (as in `headers.json`, `expected.permissions` + `has_permission`, or `error`), `tokens` (as in `token.json`, the same expectations) and `register` (`input` `base_url`, `app`, `permissions` → `expected.request` `method`, `url`, `body`, or `error: invalid`). The identities of `token.json` and `headers.json` do not list `permissions`; this file does |

Every vector has an `id`, a `reason` and an `attack` class (`null` for a plain valid case). Every attack vector carries
**one defect**: with that one check switched off it would be accepted, so a client that lacks the check fails the
vector instead of refusing it with the same class for another reason. The suite measures this for every token and
header vector; the few whose defect cannot occur alone (a malformed `kid` is never in a key set, a token that is not
three segments, a missing claim) are listed there with the reason. Each file names its
`defaults` (`issuer`, `audience`, `now`) — the cache scenarios use them for every step.

### Attack classes

| Class | What it attacks |
|---|---|
| `alg-none` | `alg: none`, with or without a signature, in any spelling |
| `alg-confusion-hs256` | HS256 with the public key (raw bytes or Base64 text) as the HMAC secret |
| `alg-wrong` | another, missing or misspelt `alg` (`ES256`, `Ed25519`, `eddsa`, an array) |
| `typ-wrong` | a plain JWT, no `typ`, the `application/` form |
| `crit` | `crit`, also with `b64: false` (RFC 7797) |
| `embedded-key` | `jwk`, `jku`, `x5u`, `x5c` in the header |
| `header-unknown-member` | `cty`, `zip` and other members |
| `foreign-key` | a key outside the set, under its own or a trusted `kid` |
| `kid-unknown` | a well-formed `kid` that is not (or no longer) in the set |
| `kid-manipulated` | `kid` missing, as a path, as SQL, 1500 characters long, a number, upper case, with NUL |
| `empty-signature` | an empty third segment |
| `bad-signature` | a short, flipped or foreign signature, a changed payload |
| `base64-padding` | `=` padding |
| `base64-alphabet` | the standard alphabet (`+`, `/`), a line break |
| `base64-noncanonical` | non-zero unused bits |
| `segments` | two, four, five segments, an empty segment |
| `oversize` | one step above 4096 bytes (and the largest valid token as its counterpart) |
| `jws-json-serialization` | flattened and general JWS JSON |
| `duplicate-members` | a claim or a header member twice |
| `json-encoding` | invalid UTF-8, a byte order mark, `NaN`, an array instead of an object |
| `claim-types` | a claim of the wrong type, out of range, missing, or inconsistent (`ts_id`, `iat`, `ts_kind`) |
| `unicode-control` | CR/LF (header injection), NUL, DEL, tab in a claim |
| `unicode-homoglyph` | a Cyrillic `а`, a zero-width joiner, a bidi override — valid, but never `admin` |
| `expired` | at `exp`, long after, at the edge of the leeway |
| `not-yet-valid` | before `nbf`, at the edge of the leeway |
| `lifetime` | more than 3600 s, `exp` before `nbf` |
| `issuer` | another issuer, a trailing slash, a prefix |
| `audience` | another host, upper case, missing or different roles, an array without a match |
| `remote-auth` | the kinds of `Remote-Auth`, empty, missing, unknown, wrong case |
| `remote-kind` | `Remote-Kind` missing, empty, in another case, unknown, twice, `service` with `session`; the four valid pairs with `Remote-Auth` |
| `groups-parsing` | commas, spaces, empty and repeated entries, case, no escapes |
| `header-missing-user` | no or empty `Remote-User` |
| `header-duplicate` | a `Remote-*` field twice, also in two spellings |
| `header-injection` | a control character in a header value |
| `header-encoding` | invalid and overlong UTF-8 |
| `id-format` | a `Remote-Id` that is no ASCII number |
| `jwks-entry` | key set entries that must be skipped |
| `jwks-shape` | key set documents that are invalid as a whole |
| `jwks-cache` | the fetch rules of §5 |
| `topbar-href` | `javascript:`, `data:`, protocol-relative and other unsafe links |
| `topbar-types` | an answer of the wrong shape, an `approvals` that is no count |
| `account-href` | unsafe links in the account overview |
| `account-types` | an account overview of the wrong shape, members of the wrong type, unknown and missing members |
| `permissions-parsing` | commas, spaces, empty and repeated entries, case, a prefix, `admin` — exact comparison, nothing implied |
| `permissions-header` | `Remote-Permissions` twice, with a control character, invalid UTF-8; a `ts_perms` of the wrong type or with a control character |
| `register-manifest` | manifests the client refuses before sending: names outside the rule, a name twice, too many entries, an application id outside the rule, a plain `http` base URL |

### Relation to TinySesam's own check

`tinysesam.gate.check` checks a token the way the proxy does: one fixed key, no clock leeway. The vector suite runs it
too: it accepts every valid vector and rejects every vector of the classes `signature`, `issuer`, `audience`,
`not_yet_valid` and `expired`. A client is deliberately stricter in `malformed`, `header`, `kid`, `claims` and
`lifetime` — the proxy (caddy-jwt, Go's JOSE library) and `gate.check` accept some of those tokens, which only a holder
of the private key can mint.

## 10. References

- [ADR-9](../backlog/ADR-9-gate-token-at-the-proxy.md) — gate token at the proxy; [ADR-12](../backlog/ADR-12-key-purposes-keyrings-and-rotation.md) — key purposes, keyrings and rotation.
- `tinysesam/gate.py` (issuing, audience), `TinySesam._forward_values` and `_header_value` (headers),
  `deploy/forward-auth/Caddyfile.gate` (the proxy side).
- RFC 7515 (JWS), RFC 7517 (JWK), RFC 7519 (JWT), RFC 8037 (Ed25519 in JOSE), RFC 8725 (JWT best practices),
  RFC 9110 (HTTP semantics).
