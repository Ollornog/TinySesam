# TinySesam gate client for Go

A small library for Go applications behind [TinySesam](../../README.md)'s gate. It answers one question per request:
*who is this, and may they do this?* It never signs anyone in, holds no session and issues no token — that stays in
TinySesam. The contract is the [gate client specification](../../spec/gate-client.md); the test suite passes every
vector in [`spec/vectors/`](../../spec/vectors/), read from this repository.

- Standard library only: `crypto/ed25519` for the signature, `encoding/json` and `encoding/base64` behind the strict
  pre-checks of the specification. No third-party module.
- Go 1.26 or newer (the two supported Go releases).
- `net/http` middleware and guards; the identity travels in the request context.

## Installation

**Not published yet:** there is no release tag for this module and it is not announced to the Go module proxy (that
needs a decision of the maintainer). Until then use a pseudo-version of a commit on `main`:

```sh
go get github.com/Ollornog/TinySesam/clients/go@main
```

`go` records a pseudo-version such as `v0.0.0-20261122120000-0123456789ab` in your `go.mod`; update it the same way.
The package name is `tinysesam`:

```go
import tinysesam "github.com/Ollornog/TinySesam/clients/go"
```

## Header mode (the default)

The proxy asks TinySesam (`/auth/forward`, or caddy-jwt with the gate token) and passes the identity as
`Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`, `Remote-Id` and `Remote-Auth`. This is the mode the
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
http.ListenAndServe("127.0.0.1:8080", gate.Middleware(mux))
```

A complete program is in [`examples/basic`](examples/basic/main.go).

### Duties of the proxy

The client cannot verify where a header came from. Header mode is only safe when the deployment guarantees all of
this (spec §2.1):

1. The proxy **removes** every `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`, `Remote-Id` and
   `Remote-Auth` the client sent, on **every** path — public share paths included, where it then sets none.
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
  deadline: concurrent requests share a running fetch.
- `LeewaySeconds` allows a clock leeway of up to 60 seconds; the default is 0, as TinySesam and the proxy use.

`Gate.Verify(ctx, jws)` checks a token without a request and returns the identity and the claims.

## The identity

`Identity` holds `User`, `Name`, `Email`, `Groups`, `ID`, `Auth` and `Kind`.

- Key your own records by `ID` — the only value that survives a rename.
- `HasRole(role)` compares exactly: no case folding, no Unicode normalization, and `admin` implies no other role.
  Whether an admin passes every role check is your decision.
- `IsSession()` is true only when `Remote-Auth` (or `ts_auth`) is exactly `session`. An empty, missing or unknown
  value counts as a token. The groups of a token request are incomplete on purpose (a token never carries `admin`):
  never revoke or sync away a role because a token request lacks it. `RequireSession` guards actions a token must
  never perform.
- Names may contain any character except controls, bidirectional overrides and zero-width characters included.
  Escape them for HTML and isolate them as bidi text (`<bdi>`).

## Guards and errors

`Gate.Middleware` identifies every request and stores the identity in the context (`FromContext`); it lets every
request through. `RequireAuth`, `RequireRole` and `RequireSession` answer 401 without an identity and 403 when the
role or the session is missing, with `Cache-Control: no-store` and without the token, the claims or the reason. A
guard without the middleware in front always answers 401.

`Gate.Identify` returns an `*Error` with a `Class` (`unauthenticated`, `header`, `malformed`, `kid`, `signature`,
`key_unavailable`, `claims`, `issuer`, `audience`, `lifetime`, `not_yet_valid`, `expired`, plus `untrusted_peer` and
`internal`); `errors.Is(err, tinysesam.ErrExpired)` works. Every class means *not authenticated*. With `Logger` set,
each refusal is logged with its class and, if well-formed, the `kid` — never the token, a claim or a header value.
A panic inside the client is caught and refused.

## Configuration errors that stop the start

`New` refuses: no mode; token settings in header mode or header settings in token mode; token mode without
`Issuer`, `Audience` or a key source, or with both `GateKeys` and `JWKSURL`; a gate key that is not 32 bytes of
standard Base64; a `JWKSURL` that is not `https` (plain `http` only to a loopback address); `LeewaySeconds` outside
0–60; both `CookieName` and `TokenHeader`; an invalid or repeated header name.

## Top bar data (optional)

`ParseTopbar(body)` normalizes TinySesam's `/.tinysesam/topbar.json` (spec §8): anything but `signed_in: true` with a
string name is signed out, and links that are not absolute `http(s)` URLs or single-slash paths (`javascript:`,
`data:`, `//host`) are dropped. `FetchTopbar` fetches it server-side with only TinySesam's cookies of the request, a
5-second deadline and a 64 KiB limit. Do not cache the result across sessions.

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
