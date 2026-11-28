# TinySesam gate client for Go

A small library for Go applications behind [TinySesam](../../README.md)'s gate. It answers one question per request:
*who is this, and may they do this?* It never signs anyone in, holds no session and issues no token — that stays in
TinySesam. The contract is the [gate client specification](../../spec/gate-client.md); the test suite passes every
vector in [`spec/vectors/`](../../spec/vectors/), read from this repository.

- Standard library only: `crypto/ed25519` for the signature, `encoding/json` and `encoding/base64` behind the strict
  pre-checks of the specification. No third-party module.
- Go 1.26 or newer (the two supported Go releases).
- `net/http` middleware and guards; the identity travels in the request context.
- **Spec version 2:** it requires `Remote-Kind` / `ts_kind` and refuses a request without it. Use it with TinySesam and
  the proxy templates of the release that brought spec v2 or later (CHANGELOG), and update those first.

## Installation

Every TinySesam release tags this module as `clients/go/vX.Y.Z` on the same commit as `vX.Y.Z` (the release workflow
sets it last, once everything else is green; a module version is never moved). Use the version of the TinySesam
release you run:

```sh
go get github.com/Ollornog/TinySesam/clients/go@v0.32.0
```

The first published version is `v0.29.0`. A commit between releases works as a pseudo-version (`@main`, `@<sha>`).
The package name is `tinysesam`:

```go
import tinysesam "github.com/Ollornog/TinySesam/clients/go"
```

## Header mode (the default)

The proxy asks TinySesam (`/auth/forward`, or caddy-jwt with the gate token) and passes the identity as
`Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`, `Remote-Id`, `Remote-Auth` and `Remote-Kind`. This is the mode the
bundled proxy templates (`deploy/forward-auth/`) support today.

```go
gate, err := tinysesam.New(tinysesam.Config{
	Mode:           tinysesam.HeaderMode,
	TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
})
if err != nil {
	log.Fatal(err) // a configuration error stops the start
}

mux := http.NewServeMux()
mux.Handle("/", tinysesam.RequireAuth(home))
mux.Handle("/reports", tinysesam.RequireRole("editors", reports))
mux.Handle("/settings", tinysesam.RequireSession(settings))
mux.Handle("/profile", tinysesam.RequireAccountKind(tinysesam.AccountUser, profile)) // people only
http.ListenAndServe("127.0.0.1:8080", gate.Middleware(mux))
```

A complete program is in [`examples/basic`](examples/basic/main.go). Example Ex1, [`examples/ex1`](examples/ex1/main.go),
runs behind the TinySesam server with local accounts and uses the account API; its pages show TinySesam's shell on top
(`<ts-shell>`, spec §8d) under a strict CSP; its stack is in `deploy/ex1`.

### Duties of the proxy

The client cannot verify where a header came from. Header mode is only safe when the deployment guarantees all of
this (spec §2.1):

1. The proxy **removes** every `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`, `Remote-Id`,
   `Remote-Auth` and `Remote-Kind` the client sent, on **every** path — public share paths included, where it then
   sets none. A proxy template older than spec v2 passes a client's `Remote-Kind` through: update the proxy first.
2. The proxy sets each header only from TinySesam's answer or from the claims of a gate token it verified itself, and
   only when the value is not empty.
3. The application is reachable **only** through that proxy: bound to a loopback or private address, or protected by
   mutual TLS. A second way in — a published port, a sidecar, another virtual host — makes every header forgeable.
4. The proxy removes TinySesam's cookies and the client's `Authorization` and `X-Api-Key` before the application,
   unless the application checks them itself.

Set `TrustedProxies` to the addresses the proxy connects from: a request from any other peer is refused. The client
reads `RemoteAddr` as it is, so do not put a middleware in front that rewrites it from `X-Forwarded-For`. It never
reads identity from other headers (`X-Forwarded-User`, …). If TinySesam's `forward_headers` renames the headers, set
`HeaderNames`.

## Token mode (for future delivery paths)

The client verifies the gate token itself — an Ed25519-signed JWS — against fixed public keys or a JWKS URL, and
ignores every `Remote-*` header. **With today's proxy template this mode cannot be used:** `Caddyfile.gate` removes
the gate cookie before the application, and how an application receives the token reliably is still open
([T-84](../../backlog/T-84-token-mode-delivery-to-the-application.md)). The checks are complete and tested, so the
mode is ready once a delivery path exists.

```go
gate, err := tinysesam.New(tinysesam.Config{
	Mode:     tinysesam.TokenMode,
	Issuer:   "https://auth.example.com",           // TinySesam's base_url, exactly
	Audience: "app.example.com",                    // as in audience_whitelist, with |roles=… if the route needs roles
	GateKeys: []string{os.Getenv("GATE_KEY")},      // output of `tinysesam gate-key`
	// or: JWKSURL: "https://auth.example.com/auth/gate/jwks.json",
})
```

- The token comes from exactly one source: the gate cookie (`__Host-tinysesam_gate`, or `CookieName`) or the header
  named in `TokenHeader`. Never from a query parameter, a form or `Authorization` unless configured; two gate cookies
  are refused.
- The checks run in the order of spec §4.4 and stop at the first failure: size (4096 bytes), strict base64url
  structure, strict header JSON, the header members (`alg` exactly `EdDSA`, `typ`, a well-formed `kid`, nothing
  else), signature length, key, Ed25519 signature, then — only after the signature — the payload, the claim types,
  issuer, audience, lifetime (at most 3600 s), `nbf` and `exp`. The algorithm is the client's constant; `alg`, `jwk`,
  `jku`, `x5u` and `x5c` in the token are never trusted.
- JWKS: fetched only from the configured URL (`https`, or `http` to a loopback address), within 5 seconds and 64 KiB,
  at most once per 10 seconds, cached for the response's `max-age` (60–3600 s, default 300). A failed fetch keeps the
  previous set; a set more than an hour past its freshness is no longer used. No request waits longer than the
  deadline: concurrent requests share a running fetch. A `JWKSURL` ending in `/approvals/jwks.json` (the approval key
  set) stops the start: a gate token is never checked with an approval key.
- Key set entries (`JWKSURL`, and `ParseJWKS` for `KeySet`): the `kid` of an entry must be the one derived from its key,
  `KeyID(pub)` — the first 16 hex digits of SHA-256 over the 32 key bytes (spec §4.3). An entry with a `kid` of your
  own choosing (a test fixture with `"kid": "test-key"`) is skipped silently. A fetched set without a single usable
  entry is a failed fetch, so every token is refused with `key_unavailable`; with other usable entries the token gets
  `kid`. `ParseJWKS` returns no error for such a set — `NewApprovalVerifier` then stops with "no usable key".
- `LeewaySeconds` allows a clock leeway of up to 60 seconds; the default is 0, as TinySesam and the proxy use.

`Gate.Verify(ctx, jws)` checks a token without a request and returns the identity and the claims.

## The identity

`Identity` holds `User`, `Name`, `Email`, `Groups`, `ID`, `Auth`, `Kind`, `AccountKind` and `Permissions`.

- `HasPermission(name)` (spec §3.4): the account's permissions for this application, from `Remote-Permissions` or
  `ts_perms`, compared exactly — neither `admin` nor a role implies one, a missing header means none. At start
  `RegisterPermissions(ctx, client, "https://auth.example.com", "docs", manifest, apiKey)` registers the manifest
  (`PUT /auth/api/apps/docs/permissions`, the automation key of the application's service account, scope
  `permissions:register`; it grants nothing); `RegisterRequest` checks a manifest without sending it (`ErrManifest`),
  a refusal by TinySesam is a `*RegistrationError`. `ParseAccount` normalizes `Permissions` (`App`, `Names`). Example
  Ex1 (`examples/ex1`) registers at start and guards its routes by permission.

- Key your own records by `ID` — the only value that survives a rename.
- `HasRole(role)` compares exactly: no case folding, no Unicode normalization, and `admin` implies no other role.
  Whether an admin passes every role check is your decision.
- `IsSession()` is true only when `Remote-Auth` (or `ts_auth`) is exactly `session`. An empty, missing or unknown
  value counts as a token. The groups of a token request are incomplete on purpose (a token never carries `admin`):
  never revoke or sync away a role because a token request lacks it. `RequireSession` guards actions a token must
  never perform.
- `AccountKind` is `AccountUser` or `AccountService` (from `Remote-Kind` or `ts_kind`), never empty: a missing value,
  another spelling (`User`), an unknown one, or `service` with `Remote-Auth: session` is the error `header` (token mode:
  `claims`), never a guessed `user` — the detail says `Remote-Kind/ts_kind missing (TinySesam or proxy older than spec
  v2?)` when it is missing. `IsService()` reports a service account; `Kind` (session or token) says how the request
  came in, `AccountKind` what the account is — a paired service acting as a person is `KindToken` with `AccountUser`.
  `HeaderNames.Kind` follows a renamed `forward_headers["kind"]`.
- Names may contain any character except controls, bidirectional overrides and zero-width characters included.
  Escape them for HTML and isolate them as bidi text (`<bdi>`).

## Guards and errors

`Gate.Middleware` identifies every request and stores the identity in the context (`FromContext`); it lets every
request through. `RequireAuth`, `RequireRole`, `RequireSession` and `RequireAccountKind` answer 401 without an
identity and 403 when the role, the session or the account kind is missing, with `Cache-Control: no-store` and without the token, the claims or the reason. A
guard without the middleware in front always answers 401.

`Gate.Identify` returns an `*Error` with a `Class` (`unauthenticated`, `header`, `malformed`, `kid`, `signature`,
`key_unavailable`, `claims`, `issuer`, `audience`, `lifetime`, `not_yet_valid`, `expired`, plus `untrusted_peer` and
`internal`); `errors.Is(err, tinysesam.ErrExpired)` works. Every class means *not authenticated*. With `Logger` set,
each refusal is logged with its class and, if well-formed, the `kid` — never the token, a claim or a header value.
A panic inside the client is caught and refused.

## Configuration errors that stop the start

`New` refuses: no mode; token settings in header mode or header settings in token mode; token mode without
`Issuer`, `Audience` or a key source, or with both `GateKeys` and `JWKSURL`; a gate key that is not 32 bytes of
standard Base64; a `JWKSURL` that is not `https` (plain `http` only to a loopback address) or ends in
`/approvals/jwks.json`; `LeewaySeconds` outside
0–60; both `CookieName` and `TokenHeader`; an invalid or repeated header name.

## Top bar data (optional)

`ParseTopbar(body)` normalizes TinySesam's `/.tinysesam/topbar.json` (spec §8): anything but `signed_in: true` with a
string name is signed out, and links that are not absolute `http(s)` URLs or single-slash paths (`javascript:`,
`data:`, `//host`) are dropped — in `Links` and in `MenuLinks` (the account menu) alike. `FetchTopbar` fetches it server-side with only TinySesam's cookies of the request, a
5-second deadline and a 64 KiB limit. Do not cache the result across sessions. Behind the proxy templates these cookies never reach the application (spec §2.1, duty 4), so a server-side fetch reads signed out there: prefer the browser way (the page fetches `/.tinysesam/topbar.json` or `/.tinysesam/account.json` itself), or let exactly the session cookie through with the commented variant in `deploy/forward-auth/Caddyfile.gate` — only for an application you trust with the person's browser session (spec §8, "Server-side or in the browser"). `Approvals` is set when TinySesam has
approvals switched on (`Pending` of at least 0 and a safe `Href`), otherwise nil; show the number with a word
("Approvals (2)"), never a coloured dot alone. `Frame` (spec §8d) is always set: `Layout` (`"top"` or `"side"`), and on
an application's host with an app frame its `Name`, `Icon` (an image address — draw it as an image), `Home` and `Links`
(the way back and the links only signed in).

## Account overview (optional)

`FetchAccount(ctx, client, accountURL, r)` fetches the person's own security state for a settings page of your own
(spec §8a): `https://<auth host>/auth/account.json` (or `/.tinysesam/account.json` on your host) with only
TinySesam's cookies of `r`, 5 seconds, 64 KiB. TinySesam answers only a full browser session; a 401, 404 or 429 comes
back as the signed-out `Account` plus the error. `ParseAccount(body)` normalizes a body: every href is safe or nil,
every string is text (escape it), a member of the wrong type is nil, unknown members are dropped. Changes happen on
TinySesam's account page — link to `Links.Account`, `Links.Sessions`, … — or on its action pages (spec §8c):
`Actions` holds their addresses, and every session its `Handle` and `End`, the page that ends exactly that session.
`Events` are the account's own events, `Programs.APIKeys` its API keys (name, kind, times), and `Admin` — for a person
who administers accounts inside the application's area — names the administration data: `ParseAdminAccounts(body)`
normalizes that answer (spec §8b; every account with `ID`, names, roles, lock state and the addresses of the
administration action pages in `Actions`, an unsafe href nil).
`ActionURL(href, returnTo, state)` builds the address to send the person to, with the way back to `returnTo` (an
absolute `http(s)` URL of your host) and your `state`; the page comes back with `ts_action`, `ts_result` and `state`.
An unsafe href, another `returnTo` or a bad state is an error wrapping `ErrActionURL`. Back on your page,
`ParseActionReturn(r.URL.RequestURI(), state)` reads that way back: an `*ActionReturn` (`Action`, `Result`) for one of
the register's actions and results with exactly the state you issued (compared in constant time), `nil, nil` for an
ordinary visit, `ErrActionReturnInvalid` or `ErrActionReturnState` for anything else — a hint for a message, never a
proof. Do not cache the result across sessions.

```go
acct, err := tinysesam.FetchAccount(r.Context(), nil, "https://auth.example.com/auth/account.json", r)
if err != nil || !acct.SignedIn {
    // show nothing of TinySesam's state; the gate decided about the request already
}
if t := acct.SignIn.TOTP; t != nil && t.RecoveryLow != nil && *t.RecoveryLow {
    // "Few recovery codes left" with a link to *acct.Links.TOTP
}
for _, s := range acct.Sessions.Items {
    if s.End != nil { // every session but this one: a link "End this session"
        href, _ := tinysesam.ActionURL(*s.End, "https://app.example.com/settings", "s-81f2")
        _ = href
    }
}
```

## Approval confirmations (optional)

A person confirms one sensitive action of your application in TinySesam with a fresh step-up; your back end picks up
one signed confirmation and checks it before acting (`spec/approval-token.md`). Configure the check once:

```go
approvals, err := tinysesam.NewApprovalVerifier(tinysesam.ApprovalConfig{
    Issuer:  "https://auth.example.com",
    AppID:   "example",                                          // apps.example in TinySesam's configuration
    JWKSURL: "https://auth.example.com/auth/approvals/jwks.json", // never /auth/gate/jwks.json (refused)
})
```

Then, after the pickup (`GET /auth/api/approvals/{id}?wait=25` with your service account's key), check the
confirmation against what you stored when you asked — never against what the confirmation says:

```go
claims, err := approvals.Verify(ctx, confirmation, tinysesam.ApprovalExpect{
    Type:    "example.collection.delete_permanently",
    Fields:  map[string]any{"collection": "c_81f2", "name": "Project Alpha"}, // exactly as sent: name, type, value
    Subject: storedRemoteID,                                                 // the account you act for
    Nonce:   storedState,                                                    // browser entry only, else ""
}, jtiStore)
if err != nil {
    log.Printf("approval refused: %s", tinysesam.ClassOf(err)) // never log the confirmation
    return
}
// run your own rule again (still the owner? does the collection still exist?), then act
```

`jtiStore` implements `JTIStore` (`Remember(ctx, jti, until) (bool, error)`): true only the first time, written
atomically and shared by every process — one `INSERT` into a table with a unique key:

```go
store := tinysesam.JTIStoreFunc(func(ctx context.Context, jti string, until int64) (bool, error) {
    res, err := db.ExecContext(ctx,
        `INSERT INTO approval_jti (jti, until) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING`, jti, until)
    if err != nil {
        return false, err // refuses the confirmation (class internal)
    }
    n, err := res.RowsAffected()
    return n == 1, err
})
```

The checks, in the order of the specification: size and structure, header (`typ` `tinysesam-approval+jwt`, never a
gate token), `kid` in the approval key set, the Ed25519 signature, then the claims — `aud` one string equal to `AppID`,
exactly one `authorization_details` entry, its RFC 8785 digest, the order of the times, `iss`, a lifetime of at most
300 s, `nbf`/`exp` with `LeewaySeconds` (0–30) — then type, fields, subject and nonce, and the `jti` last, so a
confirmation refused for another reason does not use up its id. Errors: the classes of the gate token plus
`approval_type`, `approval_fields`, `subject`, `nonce`, `replay` (`ErrApprovalType`, …) and `internal` for a failing
store; every class means *do not carry the action out*. `KeySet` (from `ParseJWKS`) takes a fixed approval key set
instead of `JWKSURL`; each entry's `kid` must be `KeyID(pub)`, see the key set rule under token mode. A complete application with the browser entry: `examples/approvals/app.py` (Python, the same
flow).

`NewApprovalVerifier` refuses: no `Issuer` or `AppID`, no or both key sources, an empty key set, a `JWKSURL` that is
not `https` (plain `http` only to a loopback address) or ends in `/gate/jwks.json`, `LeewaySeconds` outside 0–30.

## Development

```sh
go test -race ./...                                   # vectors, unit tests, JWKS server tests
go test -run='^$' -fuzz='^FuzzVerify$' -fuzztime=1000000x  # one fuzz target at a time (a count: golang/go#75804)
BIN="$(mktemp -d)"; go -C ../../.github/audit build -o "$BIN/" tool  # staticcheck, govulncheck
"$BIN/staticcheck" ./... && "$BIN/govulncheck" ./...
```

The CI workflow `.github/workflows/client-go.yml` runs `go vet`, staticcheck, govulncheck, the race-enabled tests and
a short fuzz run on the current and the previous Go release. The tools are pinned in
[`.github/audit/go.mod`](../../.github/audit/go.mod), apart from the library's own `go.mod`.

## License

MIT, like TinySesam.
