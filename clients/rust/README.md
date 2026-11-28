# tinysesam-gate — gate client for Rust

A small library for applications behind TinySesam's gate. It answers one question per request: *who is this, and
may they do this?* It never signs anyone in, holds no session and issues nothing — sign-in, sessions, approvals and
the issuing of gate tokens stay in TinySesam.

The contract is the [gate client specification](../../spec/gate-client.md); the proof is that this crate passes every
vector in [`spec/vectors/`](../../spec/vectors/) (token, header, key set, cache scenarios, top bar).

**Spec version 2:** the crate requires `Remote-Kind` / `ts_kind` and refuses a request without it — use it with
TinySesam and the proxy templates of the release that brought spec v2 or later (CHANGELOG), and update those first.

Version 0.1.0, independent of TinySesam's version. **Not published** to the Rust crate registry (that needs a
decision of the product owner, see [`clients/README.md`](../README.md#publishing)); use it from this repository.

## Installation

Pin a commit of this repository; Cargo finds the crate in `clients/rust/` by its name:

```toml
[dependencies]
tinysesam-gate = { git = "https://github.com/ollornog/TinySesam", rev = "<full commit SHA>" }
# token mode with a fetched key set (async, tokio + reqwest with rustls):
# tinysesam-gate = { git = "https://github.com/ollornog/TinySesam", rev = "<full commit SHA>", features = ["jwks"] }
```

| Feature | What | Extra dependencies |
|---|---|---|
| *(none, default)* | header mode, token mode with fixed keys, key set parsing, the cache rules, guards, top bar, account overview, approval check with fixed keys | `ed25519-dalek`, `serde_json`, `base64`, `sha2`, `http` — no network, no async runtime |
| `jwks` | `RemoteKeys` / `JwksVerifier`: fetches `/auth/gate/jwks.json` with a deadline and shares a running fetch; `ApprovalJwksVerifier` (the approval key set), `account::AccountFetcher`, `topbar::TopBarFetcher` | `reqwest` (rustls), `tokio` (`sync`, `time`) |

Tested with the current stable Rust (edition 2024). `#![forbid(unsafe_code)]`.

## Which mode

**Header mode is the default and the recommended way.** The proxy in front of the application (Caddy with the
`Caddyfile.gate` template, or `/auth/forward`) checks the sign-in and sets the `Remote-*` headers.

Token mode, where the application verifies the gate token itself, is implemented and passes every vector — but with
today's proxy template it is **not usable yet**: `Caddyfile.gate` removes the gate cookie before the application, and
the fresh token from `/auth/forward` reaches only the browser. How an application gets the token reliably is open
(backlog T-84). Use token mode only when your deployment delivers the token to the application on its own.

The mode is chosen explicitly. The client never falls back from token mode to header mode, and in token mode it never
reads a `Remote-*` header.

## Header mode

```rust
use tinysesam_gate::{HeaderMode, Requirement, authorize};

fn handle(headers: &http::HeaderMap, peer: std::net::IpAddr) -> http::StatusCode {
    let mode = HeaderMode::trust_proxy()                 // the explicit opt-in
        .with_trusted_peers(["127.0.0.1", "::1"])         // only the proxy may set the headers
        .expect("valid peer list");
    let identity = mode.identify(headers, Some(peer)).ok();
    match authorize(identity.as_ref(), &[Requirement::Role("editors")]).status() {
        None => http::StatusCode::OK,                     // allowed
        Some(status) => status,                           // 401 or 403, never why
    }
}
```

`identify` refuses — never repairs — a header that occurs twice (also in two spellings), invalid UTF-8, a control
character (`boss\x01` stripped would be another account's name), a `Remote-Id` that is not ASCII digits, and a
`Remote-Kind` that is missing, empty, not exactly `user` or `service`, or `service` with `Remote-Auth: session` (all
`header`: a missing one means TinySesam or the proxy is older than spec v2 — never guessed as `user`). A missing or
empty `Remote-User` is `unauthenticated` (checked first). Renamed headers (TinySesam's `forward_headers`) go through
`with_names(HeaderNames { … })`. No other header (`X-Forwarded-User`, `X-Remote-User`, …) is ever read.

### Duties of the proxy (spec §2.1)

The client cannot verify where a header came from. Header mode is only safe when **all** of these hold:

1. The proxy **removes** every `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`, `Remote-Id`,
   `Remote-Auth` and `Remote-Kind` the client sent, on **every** path — including public share paths, where it then
   sets none. A proxy template older than spec v2 passes a client's `Remote-Kind` through: update the proxy first.
2. The proxy sets each header only from TinySesam's answer (`/auth/forward`) or from the claims of a gate token it has
   verified itself, and only when the value is not empty.
3. The application is reachable **only** through that proxy: bound to a loopback or private address, or protected by
   mutual TLS. A second way in — a published port, a sidecar, another virtual host — makes every header forgeable.
   `with_trusted_peers` is the second line of defence, not a replacement.
4. The proxy removes TinySesam's cookies (`tinysesam_*`, `__Host-tinysesam_*`) and the client's `Authorization` and
   `X-Api-Key` before the application, unless the application checks them itself.

## Token mode

```rust
use tinysesam_gate::{KeySet, TokenConfig, TokenSource, TokenVerifier};

fn verifier() -> Result<TokenVerifier, tinysesam_gate::ConfigError> {
    let config = TokenConfig::new("https://auth.example.com", "app.example.com")?; // iss and aud, from configuration
    let keys = KeySet::from_sign_keys(["<output of `tinysesam gate-key`>"])?;     // one or more fixed keys
    TokenVerifier::new(config, keys)
}

fn identify(v: &TokenVerifier, headers: &http::HeaderMap) -> Option<tinysesam_gate::Identity> {
    let token = TokenSource::default().extract(headers).ok()?; // the gate cookie `__Host-tinysesam_gate`
    v.verify(&token).ok().map(|verified| verified.identity)
}
```

With the feature `jwks` the keys come from the operator's key set URL instead:

```rust
#[cfg(feature = "jwks")]
mod gate {
    use tinysesam_gate::{ConfigError, Identity, JwksVerifier, TokenConfig, TokenError};

    /// Build once at start-up; clone it freely — the key set cache is shared.
    pub fn verifier() -> Result<JwksVerifier, ConfigError> {
        let config = TokenConfig::new("https://auth.example.com", "app.example.com")?;
        // never /auth/approvals/jwks.json (refused)
        JwksVerifier::from_url(config, "https://auth.example.com/auth/gate/jwks.json")
    }

    pub async fn identify(verifier: &JwksVerifier, token: &str) -> Result<Identity, TokenError> {
        Ok(verifier.verify(token).await?.identity)
    }
}
```

The checks follow spec §4.4 in its order and report the class of the first failing step: size (4096 bytes),
structure and canonical base64url, strict header JSON (no member twice), exactly the header members `alg`, `typ`,
`kid`, `alg` exactly `EdDSA` (a constant of the client, never taken from the token), `typ` `tinysesam-gate+jwt`, a `kid`
of 16 lowercase hex digits, a 64-byte signature, the key, the Ed25519 signature (`verify_strict`), only then the
payload, the claim types, issuer, audience, lifetime (at most 3600 s), `nbf` and `exp`. The audience is the exact
string the proxy names in `audience_whitelist`, including `|roles=…` when the route requires roles.

Key set fetching (spec §5): `https` only (plain `http` only to a loopback IP address), no redirects, at most 5 seconds
and 64 KiB per fetch, fresh for `max-age` clamped to 60–3600 s (300 s without one), at most one attempt per 10 s, a
failed fetch never replaces the cached set, which stays usable up to 3600 s past its freshness. A request never waits
longer than one fetch deadline: concurrent requests share the running fetch. The cache runs on a monotonic clock, so
a jumping wall clock cannot stall or flood it. A custom transport implements `Fetch` (and must keep the deadline).

Every key set entry's `kid` must be the one derived from its key (the first 16 hex digits of SHA-256 over the 32 key
bytes, spec §4.3); an entry with a `kid` of your own choosing (a test fixture with `"kid": "test-key"`) is skipped
silently, and a fetched set without a single usable entry is a failed fetch: every token gets `key_unavailable` (with
other usable entries: `kid`). `KeySet::from_jwks` follows the same rule. `JwksVerifier::from_url` refuses a URL ending
in `/approvals/jwks.json` (the approval key set); `JwksVerifier::new` with `RemoteKeys` of your own leaves that check
to you.

## Identity and guards

Both modes produce the same `Identity`: `user`, `name`, `email`, `groups`, `id`, `auth` (`Session`, `OAuth`, `ApiKey`,
`AppPassword`, `Unspecified`), `kind` (`Session` only when `Remote-Auth`/`ts_auth` is exactly `session`) and
`account_kind` (`AccountKind::User` or `AccountKind::Service`, from `Remote-Kind`/`ts_kind`; `is_service()`). `kind` says
how the request came in, `account_kind` what the account is: a paired service acting as a person is `Token` + `User`.

- Key your own records by `id`, never by `user`, `name` or `email`.
- `has_role` compares exactly: no case folding, no Unicode normalization; `admin` implies no other role.
- `has_permission` (spec §3.4): `identity.permissions` comes from `Remote-Permissions` or `ts_perms` — the account's
  permissions for this application, compared exactly; a missing header means none. `register_request(base, app,
  &manifest)` checks a manifest and builds the `PermissionRequest`; with the feature `jwks`,
  `register_permissions(&client, base, app, &manifest, api_key)` sends it (the automation key of the application's
  service account, scope `permissions:register`; it grants nothing). `account::normalize` carries `permissions`.
- The groups of a token request (`kind == Token`) are incomplete on purpose — never revoke or sync away a role because
  a token request lacks it. `Requirement::Session` guards routes that need the full picture.
- Names may contain bidi overrides and zero-width characters: escape them in HTML and isolate bidi text.

`authorize(identity, &[Requirement::SignedIn | Role(..) | Session | AccountKind(..)])` answers `Allow`, `Unauthorized` (401) or
`Forbidden` (403). A response must not contain the token, the claims or the error detail. Log the error class
(`error.class()`) and at most the format-checked `kid` (`Unverified::kid`), never the token or a claim value.

An axum example with a middleware and a role guard: [`examples/axum_gate.rs`](examples/axum_gate.rs).

## Configuration errors that stop the start

These return a `ConfigError` at construction instead of failing open later: no or an empty issuer or audience, a
clock leeway above 60 seconds, no gate key, a key that is not 32 bytes of standard Base64 or no Ed25519 key, two keys
with one `kid`, an invalid or empty trusted peer list, an invalid or repeated header name, a key set URL that is not
`https` (or `http` to a loopback IP address) or carries credentials, a gate key set URL ending in
`/approvals/jwks.json`, a fetch deadline above 5 seconds. Header mode
itself needs the explicit `HeaderMode::trust_proxy()`.

## Error classes

| Mode | Classes |
|---|---|
| Token | `missing` (no token in the source), `malformed`, `header`, `kid`, `signature`, `key_unavailable`, `claims`, `issuer`, `audience`, `lifetime`, `not_yet_valid`, `expired` |
| Header | `unauthenticated`, `header`, `untrusted_peer` |
| Key set | `jwks_invalid` |

Every class means the same to the application: not authenticated.

## Top bar data

`topbar::normalize_json` reduces TinySesam's `topbar.json` to what an application may render (spec §8): signed out on
any doubt, only links with an absolute `http`/`https` URL or a path starting with exactly one `/` (in `links` and in
`menu_links`, the account menu). Titles and names are
text, never markup; do not cache the answer across sessions. `approvals` is `Some` when TinySesam has approvals
switched on (`pending` of at least 0 and a safe `href`); show the number with a word, never a coloured dot alone.

With the feature `jwks`, `topbar::TopBarFetcher::new(url)?.fetch(cookie_header).await` fetches it server-side with only
TinySesam's cookies (`account::tinysesam_cookies`), 5 seconds and 64 KiB (`with_deadline` shortens the deadline); anything
but a `200`, a failure or a body that is no strict JSON is the signed-out value. The browser way stays the recommendation
(spec §8): behind the proxy templates the session cookie never reaches the application, so a server-side fetch reads
signed out unless you let exactly that cookie through. Never cache the answer across sessions.

## Account overview

`account::normalize_json(body)` normalizes TinySesam's `account.json` (spec §8a) for a settings page of your own:
signed out unless `signed_in` is `true`, every href safe or `None`, a member of the wrong type `None`, unknown members
dropped. With the feature `jwks`, `account::AccountFetcher::new(url)?.fetch(cookie_header).await` fetches it
server-side with only TinySesam's cookies (`account::tinysesam_cookies`), 5 seconds and 64 KiB; anything but a `200`
is signed out. Changes happen on TinySesam's account page, which `links` lead to. Behind the proxy templates these cookies never reach the application (spec §2.1, duty 4), so a server-side fetch reads signed out there: prefer the browser way (the page fetches `/.tinysesam/topbar.json` or `/.tinysesam/account.json` itself), or let exactly the session cookie through with the commented variant in `deploy/forward-auth/Caddyfile.gate` — only for an application you trust with the person's browser session (spec §8, "Server-side or in the browser").

## Approval confirmations

`approval::ApprovalVerifier` checks the signed confirmation of one sensitive action (`spec/approval-token.md`) against
what the application stored when it asked. The `jti` store runs between the two steps, so a synchronous or an
asynchronous database fits; the claims stay locked until `accept`:

```rust
use tinysesam_gate::KeySet;
use tinysesam_gate::approval::{ApprovalConfig, ApprovalExpect, ApprovalVerifier};

fn check(jwks: &serde_json::Value, confirmation: &str, state: &str) -> Result<(), Box<dyn std::error::Error>> {
    // The APPROVAL key set (/auth/approvals/jwks.json) — never the gate key set.
    let verifier = ApprovalVerifier::new(
        ApprovalConfig::new("https://auth.example.com", "example")?,
        KeySet::from_jwks(jwks)?,
    )?;
    let expect = ApprovalExpect::new("example.collection.delete_permanently", "42")
        .field("collection", "c_81f2")
        .field("name", "Project Alpha")
        .nonce(state); // browser entry only
    match verifier.check_at(confirmation, &expect, tinysesam_gate::unix_now()) {
        Ok(checked) => {
            // INSERT INTO approval_jti (jti, until) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING — rows == 1
            let first_use = insert_once(checked.jti(), checked.until());
            let _claims = checked.accept(first_use)?; // `replay` when it was used before
            // run your own rule again, then act
        }
        Err(e) => eprintln!("approval refused: {}", e.class()), // never log the confirmation
    }
    Ok(())
}
# fn insert_once(_: &str, _: i64) -> bool { true }
```

`verify_at(token, &expect, &store, now)` does both steps with a synchronous `JtiStore` (a closure
`Fn(&str, i64) -> Result<bool, StoreFailed>` is one). With the feature `jwks`, `ApprovalJwksVerifier::from_url(config,
"https://auth.example.com/auth/approvals/jwks.json")` fetches the key set by the rules of spec §5 and refuses a
`…/gate/jwks.json`. Errors: `ApprovalError::Token(_)` with the classes of the gate token, then `approval_type`,
`approval_fields`, `subject`, `nonce`, `replay`, and `internal` for a failing store — every class means *do not carry
the action out*. `ApprovalConfig::with_leeway` allows at most 30 seconds.

## Libraries

| Need | Crate | Why |
|---|---|---|
| Ed25519 | `ed25519-dalek` 3 (`verify_strict`) | the maintained pure-Rust implementation of the dalek project; `verify_strict` refuses small-order keys and non-canonical signatures; the advisories of its line (the 1.x signing oracle, a timing issue in an older `curve25519-dalek`) concern versions this crate does not use |
| JSON | `serde_json` with an own visitor | refuses a repeated member name at every depth (every common parser keeps the last one) |
| base64url | `base64` (`URL_SAFE_NO_PAD`) | refuses padding and non-zero trailing bits; the alphabet and canonical checks are spelled out on top |
| HTTP (`jwks`) | `reqwest` with rustls | deadline, no redirects, no decompression, the body read in chunks up to 64 KiB |

No JOSE library: `jsonwebtoken` would still need every pre-check of spec §4.4 and brings a second crypto backend. The
structural checks are this crate's own code; the cryptography, base64 and JSON parsing are not.

## Tests

```sh
cargo test --all-features    # unit tests, every vector, the HTTP tests, property tests, the example builds
cargo clippy --all-features --all-targets -- -D warnings
cargo audit
```

- `tests/vectors.rs` loads every file of `../../spec/vectors/` from this repository (never a copy) and checks every
  vector exactly; a new vector file without a runner turns it red.
- `tests/remote.rs` (feature `jwks`) runs the cache scenarios once more through the async client and adds what the
  vectors cannot carry: a server that accepts and never answers (the request returns after one deadline), a body above
  64 KiB (and exactly 64 KiB as its counterpart), 32 concurrent requests sharing one fetch, no redirects.
- `tests/minted.rs` signs tokens with the public test key A, each with exactly one defect in the payload (invalid
  UTF-8, a byte order mark, a repeated claim, `NaN`, a lone surrogate): the vector `attack-payload-invalid-utf8` also
  repeats a claim, so a client without a UTF-8 check would still pass it.
- `tests/props.rs` (proptest): no input panics a parser; a changed or inserted character never verifies; the group
  rules and the refusal of control characters hold for generated input.
- Mutation proof: relaxing one rule at a time — size, segments, base64, duplicate members, header members, `alg`,
  `typ`, `kid`, signature, claim types, control characters, issuer prefix, audience case, lifetime, `nbf`, `exp`,
  repeated headers, stripping instead of refusing, an empty `Remote-Auth` as session, the key set entry rules, the
  rate limit, the stale limit, sharing, the deadline, the body limit — turns the suite red (63 of 65 hand mutations).
  The two that survive are equivalent: an empty header segment fails as empty JSON with the same class, and a second
  fetch in one request is already stopped by the rate limit. The vectors cannot tell a hex-like but malformed `kid`
  (upper case, wrong length) from an unknown one with fixed keys; `token::tests` pins that format check.

The CI workflow is `.github/workflows/client-rust.yml` (format, clippy, tests with all features, `cargo audit`).
