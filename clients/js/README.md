# TinySesam gate client for JavaScript and TypeScript

A small library for applications behind [TinySesam](../../README.md)'s gate. It answers one question per request:
*who is this, and may they do this?* It never signs anyone in, holds no session and issues no token — that stays in
TinySesam. The contract is the [gate client specification](../../spec/gate-client.md); the test suite passes every
vector in [`spec/vectors/`](../../spec/vectors/) (token, header, key set, cache scenarios, top bar), read from this
repository.

- TypeScript, ESM, typed. Version 0.1.0, independent of TinySesam's version.
- **Spec version 2:** it requires `Remote-Kind` / `ts_kind` and refuses a request without it. Use it with TinySesam and
  the proxy templates of the release that brought spec v2 or later (CHANGELOG), and update those first.
- **No runtime dependency.** The core uses web standards only — WebCrypto `Ed25519` for the signature, `fetch`,
  `TextDecoder`, `JSON.parse`, `atob` — so it runs on Node, Deno, Bun and edge runtimes. The Node/Express adapter is
  the separate entry point `@tinysesam/gate/node`; it imports Node's types only.
- Node 22.18 or newer (tested on the current and the previous LTS release); Deno, Bun and edge runtimes need
  WebCrypto `Ed25519`. Without it `createGate` throws a `ConfigError` at start-up instead of failing later.

## Installation

**Not published** to the npm registry (that needs a decision of the product owner, see
[`clients/README.md`](../README.md#publishing)). Use it from this repository, pinned to a commit:

- **pnpm** installs a package from a subdirectory of a Git repository; the package's `prepare` script builds `dist/`
  (a package manager that blocks the scripts of dependencies, such as pnpm 10, must be told to allow it):

  ```sh
  pnpm add "github:ollornog/TinySesam#<full commit SHA>&path:/clients/js"
  ```

- **npm** cannot install from a subdirectory of a Git repository. Vendor the directory (a Git submodule or a copy of
  `clients/js/` at a pinned commit) and depend on it by path; `npm install` runs `prepare`, which builds `dist/`:

  ```json
  { "dependencies": { "@tinysesam/gate": "file:./vendor/tinysesam/clients/js" } }
  ```

- **Deno and Bun** can import the TypeScript source directly: `clients/js/src/index.ts`.

```ts
import { createGate } from '@tinysesam/gate';
import { gateMiddleware, identityOf, requireRole } from '@tinysesam/gate/node';
```

## Which mode

**Header mode is the default and the recommended way.** The proxy in front of the application (Caddy with the
`Caddyfile.gate` template, or `/auth/forward`) checks the sign-in and sets the `Remote-*` headers.

Token mode, where the application verifies the gate token itself, is implemented and passes every vector — but with
today's proxy template it is **not usable yet**: `Caddyfile.gate` removes the gate cookie before the application, and
the fresh token from `/auth/forward` reaches only the browser. How an application gets the token reliably is open
(backlog [T-84](../../backlog/T-84-token-mode-delivery-to-the-application.md)). Use token mode only when your deployment
delivers the token to the application on its own.

The mode is chosen explicitly. The client never falls back from token mode to header mode, and in token mode it never
reads a `Remote-*` header.

## Header mode

```ts
import { createServer } from 'node:http';
import { createGate } from '@tinysesam/gate';
import { gateMiddleware, identityOf } from '@tinysesam/gate/node';

const gate = await createGate({
  mode: 'header',                          // the explicit opt-in
  trustedProxies: ['127.0.0.1', '::1'],    // only the proxy may set the headers (socket address, not X-Forwarded-For)
});

const identify = gateMiddleware(gate);
createServer((req, res) =>
  identify(req, res, () => {
    const identity = identityOf(req);      // Identity or null
    res.end(identity ? `hello ${identity.user}` : 'not signed in');
  }),
).listen(8080, '127.0.0.1');
```

With Express the same functions are ordinary middleware: `app.use(gateMiddleware(gate))`,
`app.get('/admin', requireSession(), requireRole('admin'), handler)`. A complete `node:http` example:
[`examples/node-http.ts`](examples/node-http.ts).

The client refuses — never repairs — a header that occurs twice (also in two spellings), invalid UTF-8, a control
character (`boss\x01` stripped would be another account's name), and a `Remote-Id` that is not ASCII digits. A missing
or empty `Remote-User` is `unauthenticated`. Renamed headers (TinySesam's `forward_headers`) go through
`headerNames: { user: 'X-User', … }`. No other header (`X-Forwarded-User`, `X-Remote-User`, …) is ever read.

Header values are octets (one code unit U+0000–U+00FF per byte), which is what Node's `rawHeaders` and the Fetch
`Headers` API hand out; the client decodes them as strict UTF-8.

**The Fetch adapter cannot see a repeated field:** the Fetch `Headers` API joins repeated fields with `, `. Behind a
proxy that fulfils duty 1 below this never happens; on Node prefer the adapter in `@tinysesam/gate/node`, which reads the
raw field lines and refuses a repetition.

### Duties of the proxy (spec §2.1)

The client cannot verify where a header came from. Header mode is only safe when **all** of these hold:

1. The proxy **removes** every `Remote-User`, `Remote-Name`, `Remote-Email`, `Remote-Groups`, `Remote-Id`,
   `Remote-Auth` and `Remote-Kind` the client sent, on **every** path — including public share paths, where it then
   sets none. A proxy template older than spec v2 passes a client's `Remote-Kind` through: update the proxy first.
2. The proxy sets each header only from TinySesam's answer (`/auth/forward`) or from the claims of a gate token it has
   verified itself, and only when the value is not empty.
3. The application is reachable **only** through that proxy: bound to a loopback or private address, or protected by
   mutual TLS. A second way in — a published port, a sidecar, another virtual host — makes every header forgeable.
   `trustedProxies` is the second line of defence, not a replacement.
4. The proxy removes TinySesam's cookies (`tinysesam_*`, `__Host-tinysesam_*`) and the client's `Authorization` and
   `X-Api-Key` before the application, unless the application checks them itself.

## Token mode

```ts
import { createGate } from '@tinysesam/gate';

const gate = await createGate({
  mode: 'token',
  issuer: 'https://auth.example.com',                      // TinySesam's base_url, exactly
  audience: 'app.example.com',                             // the exact audience_whitelist entry, with |roles=… if any
  gateKeys: ['<output of `tinysesam gate-key`>'],          // one or more fixed keys …
  // jwksUrl: 'https://auth.example.com/auth/gate/jwks.json', // … or the key set URL instead
});
```

The token comes from exactly one source: the gate cookie `__Host-tinysesam_gate` (`cookieName` to rename it) or a
request header (`tokenHeader`). Two gate cookies are `malformed`; a query parameter, a form field or `Authorization`
is never read.

The checks follow spec §4.4 in its order and report the class of the first failing step: size (4096 bytes),
structure and canonical base64url, strict header JSON (no member twice, strict UTF-8, no byte order mark), exactly the
header members `alg`, `typ`, `kid`, `alg` exactly `EdDSA` (a constant of the client, never taken from the token), `typ`
`tinysesam-gate+jwt`, a `kid` of 16 lowercase hex digits, a 64-byte signature, the key, the Ed25519 signature, only
then the payload, the claim types (integers exactly: `1.0` and `1e3` are refused), issuer, audience, lifetime (at most
3600 s), `nbf` and `exp` with the configured leeway (default 0, at most 60 s).

Key set fetching (spec §5): `https` only (plain `http` only to a loopback address), no redirects (a redirect is a failed
fetch), at most 5 seconds (`AbortSignal.timeout`) and 64 KiB per fetch, fresh for `max-age` clamped to 60–3600 s (300 s
without one), at most one attempt per 10 s, a failed fetch never replaces the cached set, which stays usable up to
3600 s past its freshness. A request never waits longer than one fetch deadline: concurrent requests share the running
fetch. The cache runs on a monotonic clock (`performance.now`), so a jumping wall clock cannot stall or flood it.
`fetch` in the configuration replaces the global `fetch` (for a proxy agent, for instance).

Every key set entry's `kid` must be the one derived from its key (the first 16 hex digits of SHA-256 over the 32 key
bytes, spec §4.3); an entry with a `kid` of your own choosing (a test fixture with `"kid": "test-key"`) is skipped
silently, and a fetched set without a single usable entry is a failed fetch: every token gets `key_unavailable` (with
other usable entries: `kid`). A key set URL ending in `/approvals/jwks.json` (the approval key set) stops the start.

### Fetch handlers (Hono, Deno, Bun, edge runtimes)

```ts
import { guardResponse, identifyRequest, withGate } from '@tinysesam/gate';

// a whole handler behind a guard
const editors = withGate(gate, [{ role: 'editors' }], (request, identity) => new Response(`hi ${identity.user}`));

// or by hand, e.g. in a Hono middleware
app.use(async (c, next) => {
  const identity = await identifyRequest(gate, c.req.raw);  // Identity or null
  const denied = guardResponse(identity, ['signed-in']);
  if (denied) return denied;
  c.set('identity', identity);
  await next();
});
```

In header mode with `trustedProxies`, pass the peer address the runtime reports as the third argument of
`identifyRequest` (or `peer` in the options of `withGate`); without it the request is `untrusted_peer`.
Example: [`examples/fetch-handler.ts`](examples/fetch-handler.ts).

## Identity and guards

Both modes produce the same `Identity`: `user`, `name`, `email`, `groups`, `id`, `auth` (`session`, `oauth`, `apikey`,
`app-password` or empty), `kind` (`session` only when `Remote-Auth`/`ts_auth` is exactly `session`) and `accountKind`
(`user` or `service`, from `Remote-Kind`/`ts_kind`; `isService()`; `account_kind` in `toJSON()`). A missing value,
another spelling, an unknown one or `service` with `Remote-Auth: session` is the error `header` (token mode: `claims`),
never a guessed `user`. `kind` says how the request came in, `accountKind` what the account is: a paired service acting
as a person is `token` + `user`. `headerNames.kind` follows a renamed `forward_headers["kind"]`.

- Key your own records by `id`, never by `user`, `name` or `email`.
- `identity.hasRole(role)` compares exactly: no case folding, no Unicode normalization; `admin` implies no other role.
- `identity.hasPermission(name)` (spec §3.4): `identity.permissions` comes from `Remote-Permissions` or `ts_perms` —
  the account's permissions for this application, compared exactly; a missing header means none. At start
  `await registerPermissions('https://auth.example.com', 'docs', manifest, apiKey)` registers the manifest (the
  automation key of the application's service account, scope `permissions:register`; it grants nothing);
  `registerRequest` checks a manifest without sending it (`ConfigError`), a refusal by TinySesam rejects with
  `RegistrationFailed`. `parseAccount` normalizes `permissions` (`app`, `names`).
- The groups of a token request (`identity.isSession()` false) are incomplete on purpose — never revoke or sync away a
  role because a token request lacks it. `requireSession()` / `'session'` guards routes that need the full picture.
- Names may contain bidi overrides and zero-width characters: escape them in HTML and isolate bidi text.

`authorize(identity, ['signed-in' | 'session' | { role } | { accountKind }])` answers `'allow'`, `401` or `403`; the Node guards
(`requireAuth`, `requireRole`, `requireSession`) and the Fetch helpers (`guardResponse`, `withGate`) answer with the
status text and `Cache-Control: no-store` only — never the token, the claims or the reason.

Refusals are `GateError`s with `code` (the class below) and, once format-checked, `kid`; `gate.identifyOrNull()` and the
middleware hand them to the optional `logger`, which receives `{ code, kid }` — never the token or a claim value.

## Configuration errors that stop the start

`createGate` throws a `ConfigError` instead of failing open later: no mode or an unknown one, a setting of the other
mode or an unknown setting (a misspelt `trustedProxies` would otherwise silently trust every peer), no or an empty
issuer or audience, a clock leeway that is not an integer from 0 to 60, no gate key, a key that is not 32 bytes of
standard Base64 or no Ed25519 key, both `gateKeys` and `jwksUrl`, a key set URL that is not `https` (or `http` to a
loopback address), carries credentials or ends in `/approvals/jwks.json`, `fetch` without `jwksUrl`, both `cookieName` and `tokenHeader`, an invalid
or repeated header name, an empty or invalid trusted proxy list, and a runtime without WebCrypto `Ed25519`.

## Error classes

| Mode | Classes |
|---|---|
| Token | `unauthenticated` (no token in the source), `malformed`, `header`, `kid`, `signature`, `key_unavailable`, `claims`, `issuer`, `audience`, `lifetime`, `not_yet_valid`, `expired` |
| Header | `unauthenticated`, `header`, `untrusted_peer` |
| Key set | `jwks_invalid` |
| Both | `internal` (an unexpected failure inside the client — fails closed) |

Every class means the same to the application: not authenticated.

## Top bar data

`parseTopbar(body)` reduces TinySesam's `topbar.json` to what an application may render (spec §8): signed out on any
doubt, only links with an absolute `http`/`https` URL or a path starting with exactly one `/` (in `links` and in
`menu_links`, the account menu). Titles and names are text, never markup — set them with `textContent`. `fetchTopbar(url, cookieHeader)` fetches it server-side with only
TinySesam's cookies, a 5-second deadline and a 64 KiB limit; do not cache the answer across sessions. Behind the proxy templates these cookies never reach the application (spec §2.1, duty 4), so a server-side fetch reads signed out there: prefer the browser way (the page fetches `/.tinysesam/topbar.json` or `/.tinysesam/account.json` itself), or let exactly the session cookie through with the commented variant in `deploy/forward-auth/Caddyfile.gate` — only for an application you trust with the person's browser session (spec §8, "Server-side or in the browser"). `approvals` is
`{ pending, href }` when TinySesam has approvals switched on, otherwise `null`; show the number with a word, never a
coloured dot alone. `frame` (spec §8d) is always present: `layout` (`'top'` or `'side'`), and on an application's host
with an app frame its `name`, `icon` (an image address — set it as an image `src`), `home` and `links` (the way back
and the links only signed in).

## Account overview

`fetchAccount(url, cookieHeader)` fetches TinySesam's `account.json` (spec §8a) server-side for a settings page of
your own — only TinySesam's cookies, 5 seconds, 64 KiB, no redirects; anything but a `200` with `signed_in: true` is
`signedOutAccount()`. `parseAccount(body)` normalizes a body: every href safe or `null`, a member of the wrong type
`null`, unknown members dropped. Every string is text — set it with `textContent`. Changes happen on TinySesam's
account page, which `links` lead to, or on its action pages (spec §8c): `actions` holds their addresses, and every
session its `handle` and `end`, the page that ends exactly that session. `actionUrl(href, returnTo, state)` builds the
address to send the person to, with the way back to `returnTo` (an absolute `http(s)` URL of your host) and your
`state` — `actionUrl(session.end, 'https://app.example.com/settings', 's-81f2')` ends one session; the page comes back
with `ts_action`, `ts_result` and `state`. An unsafe href, another `returnTo` or a bad state throws a `ConfigError`.

## Approval confirmations

`createApprovalVerifier` checks the signed confirmation of one sensitive action (`spec/approval-token.md`) against what
the application stored when it asked:

```ts
import { createApprovalVerifier, errorClassOf } from '@tinysesam/gate';

const approvals = createApprovalVerifier({
  issuer: 'https://auth.example.com',
  appId: 'example',
  jwksUrl: 'https://auth.example.com/auth/approvals/jwks.json', // never /auth/gate/jwks.json (refused)
});

// after GET /auth/api/approvals/{id}?wait=25 with the service account's key:
try {
  await approvals.verify(confirmation, {
    type: 'example.collection.delete_permanently',
    fields: { collection: 'c_81f2', name: 'Project Alpha' }, // exactly as sent: name, type, value
    sub: storedRemoteId,
    nonce: storedState, // browser entry only
  }, async (jti, until) => {
    // INSERT INTO approval_jti (jti, until) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING
    return (await db.query(insertSql, [jti, until])).rowCount === 1;
  });
  // run your own rule again, then act
} catch (err) {
  console.warn('approval refused', errorClassOf(err)); // never log the confirmation
}
```

`keys` (from `parseJwks`, the same `kid` rule as above) takes a fixed approval key set instead of `jwksUrl`; `leewaySeconds` allows at most 30.
Errors: the classes of the gate token plus `approval_type`, `approval_fields`, `subject`, `nonce`, `replay`, and
`internal` for a failing store — every class means *do not carry the action out*. The `jti` is written last, so a
confirmation refused for another reason does not use up its id. Because `JSON.parse` reads `1.0` as `1`, a number
with a fraction or an exponent anywhere in a confirmation's payload refuses it (`claims`); TinySesam writes none.

## Libraries

| Need | Source | Why |
|---|---|---|
| Ed25519 | WebCrypto (`crypto.subtle.verify` with `Ed25519`) | a web standard implemented by the runtime (OpenSSL/BoringSSL in Node, Deno and the edge runtimes); no dependency to audit or update. `jose` (panva) was the alternative: it would still need every pre-check of spec §4.4 — its JWS parser accepts what the specification refuses — and verifies through the same WebCrypto call |
| JSON | `JSON.parse` behind a scan of the accepted text | `JSON.parse` keeps the last of two equal member names, accepts a lone surrogate escape and turns `1.0` into `1`; the scan refuses repeated names and lone surrogates and keeps the source text of the top-level numbers, so integers are checked exactly |
| UTF-8 | `TextDecoder` with `fatal: true` | refuses invalid, overlong and surrogate sequences; the byte order mark is checked before |
| base64url | `atob` with the alphabet and canonical checks spelled out | `atob` skips whitespace and ignores non-zero trailing bits |

The structural checks are this library's own code; the cryptography, base64 and JSON parsing are not.

## Development

```sh
npm ci              # dev tools only: TypeScript, Biome, fast-check, the Node types
npm run lint        # Biome
npm run typecheck   # tsc --noEmit (strict)
npm test            # node --test: every vector, the HTTP tests, property tests
npm run build       # dist/ (what a dependency loads)
```

- `test/vectors.test.ts` loads every file of `../../spec/vectors/` from this repository (never a copy) and checks every
  vector exactly; a new vector file without a runner turns it red.
- `test/jwks-http.test.ts` adds what the vectors cannot carry, against a real HTTP server: a server that accepts and
  never answers (the request returns after the 5-second deadline), one that stalls the body, a body above 64 KiB (and
  exactly 64 KiB as its counterpart), 32 concurrent requests sharing one fetch, no redirects.
- `test/minted.test.ts` signs tokens with the public test key A, each with exactly one defect (invalid UTF-8, a byte
  order mark, a repeated claim, `NaN`, a lone surrogate, a non-integer time, a control character).
- `test/props.test.ts` (fast-check): no input throws past the API, a changed or inserted character never verifies, the
  group and control-character rules hold for generated input.
- `test/gate.test.ts`: configuration errors, token sources, trusted proxies, every header vector through a real Node
  HTTP server and the middleware, guards, logging, the top bar fetch.
- Mutation proof: 104 hand mutations, one rule relaxed at a time and restored from a saved copy with a hash check —
  97 turn the suite red; the other 7 are held by a second guard of the same rule (listed in backlog T-82).

## License

MIT, like TinySesam.
