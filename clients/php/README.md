# TinySesam gate client for PHP

A small library for PHP applications behind [TinySesam](../../README.md)'s gate. It answers one question per request:
*who is this, and may they do this?* It never signs anyone in, holds no session and issues no token — that stays in
TinySesam. The contract is the [gate client specification](../../spec/gate-client.md); the test suite passes every
vector in [`spec/vectors/`](../../spec/vectors/) (token, header, key set, cache scenarios, top bar), read from this
repository.

- Package `tinysesam/gate`, namespace `TinySesam\Gate`. Version 0.1.0, independent of TinySesam's version.
- **Spec version 2:** it requires `Remote-Kind` / `ts_kind` and refuses a request without it. Use it with TinySesam and
  the proxy templates of the release that brought spec v2 or later (CHANGELOG), and update those first.
- **PHP 8.4 or newer** (tested on 8.4, 8.5 and 8.6). 8.4 is the oldest release with active support and the oldest
  that the test tools (PHPUnit 13) run on; ext-sodium, which verifies the signature, is bundled with PHP since 7.2 and
  sets no limit of its own.
- **Runtime dependencies:** ext-sodium, ext-json and ext-pcre (all part of a standard PHP build), and four packages of
  PSR interfaces only: `psr/http-message`, `psr/http-factory`, `psr/http-server-middleware` (with
  `psr/http-server-handler`) for the PSR-15 middleware and `psr/log` for the optional logger. Token mode with a key set
  URL needs ext-curl (or a `Fetcher` of your own).

## Installation

**Not published** on Packagist (that needs a decision of the product owner, see
[`clients/README.md`](../README.md#publishing)). Use it from this repository, pinned to a commit: vendor the directory
(a Git submodule, or a copy of `clients/php/` at a pinned commit) and add it as a path repository:

```json
{
    "repositories": [
        {"type": "path", "url": "vendor-src/tinysesam/clients/php", "options": {"versions": {"tinysesam/gate": "0.1.0"}}}
    ],
    "require": {"tinysesam/gate": "0.1.0"}
}
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

A classic page under PHP-FPM or mod_php ([`examples/plain-php.php`](examples/plain-php.php)):

```php
use TinySesam\Gate\Decision;
use TinySesam\Gate\Gate;
use TinySesam\Gate\GateRequest;
use TinySesam\Gate\Requirement;

$gate = Gate::headerMode(trustedProxies: ['127.0.0.1', '::1']);   // only the proxy may set the headers

$identity = $gate->identifyOrNull(GateRequest::fromGlobals($_SERVER));  // Identity or null
$decision = Decision::of($identity, [Requirement::role('editors')]);    // Allow, Unauthorized (401), Forbidden (403)
```

With a PSR-15 framework (Slim, Mezzio, a RoadRunner worker, ...) the middleware does the same
([`examples/psr15.php`](examples/psr15.php)):

```php
use TinySesam\Gate\Psr15\GateMiddleware;
use TinySesam\Gate\Psr15\RequireMiddleware;

$app->add(new GateMiddleware($gate, $responseFactory));                  // every request: identity or null
$route->add(new RequireMiddleware($responseFactory, [Requirement::session(), Requirement::role('admin')]));
// in a handler:
$identity = GateMiddleware::identityOf($request);
```

`new GateMiddleware($gate, $responseFactory, [/* requirements */])` identifies and guards in one. A refusal answers
401 or 403 with the status text and `Cache-Control: no-store` only — never the token, the claims or the reason.

The client refuses — never repairs — a header that occurs twice (also in two spellings), invalid UTF-8, a control
character (`boss\x01` stripped would be another account's name), and a `Remote-Id` that is not ASCII digits. A missing
or empty `Remote-User` is `unauthenticated`. Renamed headers (TinySesam's `forward_headers`) go through
`headerNames: new HeaderNames(user: 'X-User', ...)`. No other header (`X-Forwarded-User`, `X-Remote-User`, ...) is ever
read. The peer of `trustedProxies` is `REMOTE_ADDR`, never `X-Forwarded-For`.

### What PHP hands over

The gate sees a request the way PHP gives it to the application, and a classic SAPI changes it first. Under PHP-FPM,
mod_php, CGI and PHP's built-in server every header becomes a variable `$_SERVER['HTTP_<NAME>']`:

- **A repeated field arrives joined** (`Remote-User: anna` twice with `boss` becomes `anna, boss`), so the client
  cannot refuse it (spec §2.2 rule 1).
- `Remote-User` and `Remote_User` become **the same variable**; the web server must drop header names with an
  underscore (nginx and Apache do by default).
- PHP's built-in server **cuts a value at a NUL byte** (`user\0` arrives as `user`). The test suite measures both of
  these through the built-in server and pins them.

All three are covered by the proxy's duty 1 below: a client's `Remote-*` field never reaches the application. A
long-running server (RoadRunner, ReactPHP, AMPHP, Swoole) usually keeps the field lines; its PSR-7 request then carries
each line as its own value, and the client refuses a repetition. Read the gate cookie from `GateRequest` too, never
from `$_COOKIE`: PHP keeps only one of two equal cookie names and rewrites dots and spaces in them.

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

```php
use TinySesam\Gate\Gate;
use TinySesam\Gate\Jwks\FileStore;

$gate = Gate::tokenMode(
    issuer: 'https://auth.example.com',            // TinySesam's base_url, exactly
    audience: 'app.example.com',                   // the exact audience_whitelist entry, with |roles=... if any
    gateKeys: ['<output of `tinysesam gate-key`>'], // one or more fixed keys ...
);
$gate = Gate::tokenMode(
    issuer: 'https://auth.example.com',
    audience: 'app.example.com',
    jwksUrl: 'https://auth.example.com/auth/gate/jwks.json',          // ... or the key set URL instead
    store: new FileStore('/var/lib/example/tinysesam-jwks.json'),     // under PHP-FPM, mod_php, CGI
);
```

The token comes from exactly one source: the gate cookie `__Host-tinysesam_gate` (`cookieName` to rename it) or a
request header (`tokenHeader`). Two gate cookies are `malformed`; a query parameter, a form field or `Authorization`
is never read.

The checks follow spec §4.4 in its order and report the class of the first failing step: size (4096 bytes),
structure and canonical base64url, strict header JSON (no member twice, strict UTF-8, no byte order mark), exactly the
header members `alg`, `typ`, `kid`, `alg` exactly `EdDSA` (a constant of the client, never taken from the token), `typ`
`tinysesam-gate+jwt`, a `kid` of 16 lowercase hex digits, a 64-byte signature, the key, the Ed25519 signature
(`sodium_crypto_sign_verify_detached`), only then the payload, the claim types (integers exactly: `1.0` and `1e3` are
refused), issuer, audience, lifetime (at most 3600 s), `nbf` and `exp` with the configured leeway (default 0, at most
60 s).

### Key set fetching (spec §5)

`https` only (plain `http` only to a loopback address), no redirects (a redirect is a failed fetch), at most 5 seconds
for everything (curl's `CURLOPT_TIMEOUT_MS`: DNS, connect, TLS, headers, body) and 64 KiB per fetch (the transfer is
aborted above it), certificate and host name verified, fresh for `max-age` clamped to 60–3600 s (300 s without one),
at most one attempt per 10 s, a failed fetch never replaces the cached set, which stays usable up to 3600 s past its
freshness.

Every key set entry's `kid` must be the one derived from its key (the first 16 hex digits of SHA-256 over the 32 key
bytes, spec §4.3); an entry with a `kid` of your own choosing (a test fixture with `"kid": "test-key"`) is skipped
silently, and a fetched set without a single usable entry is a failed fetch: every token gets `key_unavailable` (with
other usable entries: `kid`). `KeySet::fromJwks` follows the same rule. A `jwksUrl` ending in `/approvals/jwks.json`
(the approval key set) stops the start.

PHP keeps nothing between requests unless something keeps it, so **where the cache lives** is a choice:

- `MemoryStore` (the default) lives as long as the process: right for long-running workers (RoadRunner, FrankenPHP's
  worker mode, Swoole, ReactPHP) and the CLI. It runs on a monotonic clock (`hrtime`).
- `FileStore` is shared by every process of one host, guarded by `flock` on a lock file next to it: **needed under
  PHP-FPM, mod_php and CGI**, where a `MemoryStore` would fetch on every request. One process fetches; the others wait
  for its result at most one deadline and read it from the file. The file holds public material only, but it decides
  which keys the application trusts: give it a directory only the application's user can write, never a shared
  temporary one. Its timestamps are wall-clock seconds; one in the future makes the cache fetch again.

No request waits longer than one fetch deadline for keys. A `Fetcher` of your own replaces curl; it must keep the same
rules, and since PHP cannot interrupt a call that ignores its deadline, the cache can only discard a late answer.

## Identity and guards

Both modes produce the same `Identity` (a readonly object): `user`, `name`, `email`, `groups`, `id`, `auth`
(`session`, `oauth`, `apikey`, `app-password` or empty), `kind` (`Kind::Session` only when `Remote-Auth`/`ts_auth` is
exactly `session`) and `accountKind` (`AccountKind::User` or `AccountKind::Service`, from `Remote-Kind`/`ts_kind`;
`isService()`; `account_kind` in `toArray()`). A missing value, another spelling, an unknown one or `service` with
`Remote-Auth: session` is the error `header` (token mode: `claims`), never a guessed `user`. `kind` says how the request
came in, `accountKind` what the account is: a paired service acting as a person is `token` + `user`.

- Key your own records by `id`, never by `user`, `name` or `email`.
- `$identity->hasRole($role)` compares exactly: no case folding, no Unicode normalization; `admin` implies no other
  role.
- `$identity->hasPermission($name)` (spec section 3.4): `$identity->permissions` comes from `Remote-Permissions` or
  `ts_perms` — the account's permissions for this application, compared exactly; a missing header means none.
  `Permissions::register($base, 'docs', $manifest, $apiKey)` registers the manifest at start (the automation key of the
  application's service account, scope `permissions:register`; it grants nothing); `Permissions::request()` checks a
  manifest without sending it (`ConfigError`), a refusal by TinySesam throws `RegistrationFailed`. `Account::parse`
  carries `permissions`.
- The groups of a token request (`$identity->isSession()` false) are incomplete on purpose — never revoke or sync away
  a role because a token request lacks it. `Requirement::session()` guards routes that need the full picture.
- Names may contain bidi overrides and zero-width characters: escape them (`htmlspecialchars`) and isolate bidi text
  (`<bdi>`).

`Decision::of($identity, [Requirement::signedIn() | session() | role($r) | accountKind($k)])` answers `Allow`,
`Unauthorized` (401) or `Forbidden` (403).

Refusals are `GateError`s with `errorClass` (an `ErrorClass` enum, the classes below) and, once format-checked, `kid`;
the message carries the class and a fixed reason, never a value. `identifyOrNull()` and the middleware hand them to the
optional PSR-3 logger as one `notice` per refusal with the context `class` and `kid` — never the token or a claim
value. The token parameters are `#[\SensitiveParameter]`, so a stack trace does not show them.

## Configuration errors that stop the start

`Gate::headerMode()` and `Gate::tokenMode()` throw a `ConfigError` instead of failing open later: no or an empty
issuer or audience, a clock leeway outside 0 to 60, not exactly one of `gateKeys`, `jwksUrl` and `keySource`, no gate
key, a key that is not 32 bytes of standard Base64, a key set URL that is not `https` (or `http` to a loopback address)
or carries credentials or a fragment, a `jwksUrl` ending in `/approvals/jwks.json`, `fetcher` or `store` without `jwksUrl`, `jwksUrl` without ext-curl and without a
`Fetcher`, both `cookieName` and `tokenHeader`, an invalid cookie or header name, an invalid or repeated header name in
`HeaderNames`, an empty or invalid trusted proxy list, no ext-sodium, and a `FileStore` whose directory is missing or
not writable. Settings are named arguments, so a misspelt one is a PHP error at the call, not a silently ignored key.

## Error classes

| Mode | Classes |
|---|---|
| Token | `unauthenticated` (no token in the source), `malformed`, `header`, `kid`, `signature`, `key_unavailable`, `claims`, `issuer`, `audience`, `lifetime`, `not_yet_valid`, `expired` |
| Header | `unauthenticated`, `header`, `untrusted_peer` |
| Key set | `jwks_invalid` |
| Both | `internal` (an unexpected failure inside the client — fails closed) |

Every class means the same to the application: not authenticated.

## Top bar data

`Topbar::parse($body)` reduces TinySesam's `topbar.json` to what an application may render (spec §8): signed out on any
doubt, only links with an absolute `http`/`https` URL or a path starting with exactly one `/` (in `links` and in
`menuLinks`, the account menu); members it does not know are ignored. Titles and names are text, never markup — escape
them. `Topbar::fetch($url, $_SERVER['HTTP_COOKIE'] ?? '')` fetches it server-side with only TinySesam's cookies, a deadline of
5 seconds, 64 KiB and no redirects (anything but a `200` or a failed transfer is the signed-out value); never cache the
answer across sessions. Behind the proxy templates these cookies never reach the application (spec §2.1, duty 4), so a server-side fetch reads signed out there: prefer the browser way (the page fetches `/.tinysesam/topbar.json` or `/.tinysesam/account.json` itself), or let exactly the session cookie through with the commented variant in `deploy/forward-auth/Caddyfile.gate` — only for an application you trust with the person's browser session (spec §8, "Server-side or in the browser"). `approvals` is `['pending' => …, 'href' => …]` when TinySesam has approvals switched on,
otherwise `null`; show the number with a word, never a coloured dot alone. `frame` (spec §8d) is always set:
`layout` (`'top'` or `'side'`), and on an application's host with an app frame its `name`, `home` and `links` (the way
back and the links only signed in).

## Account overview

`Account::fetch($url, $_SERVER['HTTP_COOKIE'] ?? '')` fetches TinySesam's `account.json` (spec §8a) server-side for a
settings page of your own — only TinySesam's cookies, ext-curl, 5 seconds, 64 KiB, no redirects; anything but a `200`
with `signed_in: true` is `Account::signedOut()`. `Account::parse($body)` normalizes a body into a plain array: every
href safe or `null`, a member of the wrong type `null`, unknown members dropped. Escape every string. Changes happen on
TinySesam's account page, which `links` lead to, or on its action pages (spec §8c): `actions` holds their addresses,
and every session its `handle` and `end`, the page that ends exactly that session. `Account::actionUrl($href,
$returnTo, $state)` builds the address to send the person to, with the way back to `$returnTo` (an absolute `http(s)`
URL of your host) and your `$state` — `Account::actionUrl($session['end'], 'https://app.example.com/settings',
's-81f2')` ends one session; the page comes back with `ts_action`, `ts_result` and `state`. An unsafe href, another
`$returnTo` or a bad state throws a `ConfigError`.

## Approval confirmations

`ApprovalVerifier` checks the signed confirmation of one sensitive action (`spec/approval-token.md`) against what the
application stored when it asked:

```php
use TinySesam\Gate\ApprovalExpect;
use TinySesam\Gate\ApprovalVerifier;
use TinySesam\Gate\GateError;

$approvals = ApprovalVerifier::create(
    'https://auth.example.com',
    'example',
    jwksUrl: 'https://auth.example.com/auth/approvals/jwks.json', // never /auth/gate/jwks.json (refused)
);
try {
    $claims = $approvals->verify($confirmation, new ApprovalExpect(
        'example.collection.delete_permanently',
        ['collection' => 'c_81f2', 'name' => 'Project Alpha'], // exactly as sent: name, type, value
        $storedRemoteId,
        $storedState, // browser entry only, else null
    ), $jtiStore);
    // run your own rule again, then act
} catch (GateError $e) {
    error_log('approval refused: ' . $e->errorClass->value); // never log the confirmation
}
```

`$jtiStore` implements `JtiStore` (or is a callable `fn (string $jti, int $until): bool`): true only the first time,
one `INSERT` into a table with a unique key shared by every worker — the interface's doc block has a PDO example. Under
PHP-FPM give the key set cache a `FileStore` (`store:`), as for the gate. `keys:` (`KeySet::fromJwks`) takes a fixed
approval key set instead of `jwksUrl:`; `leewaySeconds:` allows at most 30. Errors: the classes of the gate token plus
`approval_type`, `approval_fields`, `subject`, `nonce`, `replay`, and `internal` for a failing store — every class
means *do not carry the action out*.

## Libraries

| Need | Source | Why |
|---|---|---|
| Ed25519 | `sodium_crypto_sign_verify_detached` (ext-sodium, bundled with PHP) | libsodium; no dependency to audit. `web-token/jwt-framework` was the alternative: it would still need every pre-check of spec §4.4 and adds a dependency tree |
| JSON | `json_decode` behind a scan of the accepted text | `json_decode` keeps the last of two equal member names; the scan refuses repeated names in any object. Objects are decoded as `\stdClass`, so `{}` and `[]` stay apart, and integers stay `int` (`1.0`, `1e3` are floats and refused as times) |
| UTF-8 | PCRE's UTF-8 check (`preg_match('//u', ...)`) | refuses invalid, overlong and surrogate sequences; the byte order mark is checked before |
| base64url | `base64_decode` in strict mode with the alphabet and canonical checks spelled out | `base64_decode` ignores non-zero trailing bits; `\z`, not `$`, so a trailing line break is refused |
| key set fetch | ext-curl | one deadline over the whole transfer, an abort above the body limit, no redirects |

The structural checks are this library's own code; the cryptography, base64 and JSON parsing are not.

**Limit:** a JSON member name that starts with a NUL character cannot be a property of `\stdClass`; `json_decode`
refuses such a document. A header with such a member is `malformed` instead of `header`, and an unknown claim of that
name refuses the token instead of being ignored — both refusals, and TinySesam never issues either.

## Development

```sh
./ci.sh                 # every check, exactly as the CI workflow client-php runs it (needs PHP 8.4+ and Composer)
ci/in-docker.sh         # the same inside ci/Dockerfile (the newest PHP) for a machine without PHP
composer install        # dev tools only: PHPUnit, PHPStan (+ strict rules), PHP_CodeSniffer, nyholm/psr7
vendor/bin/phpunit      # every vector, the HTTP and process tests, properties
```

`scripts/check.sh` in the repository root runs `ci.sh` too (natively, or through `ci/in-docker.sh`).

- `tests/VectorsTest.php` loads every file of `../../spec/vectors/` from this repository (never a copy), checks that each
  says `"format": 2` and checks every vector exactly; a new vector file without a runner turns it red.
- `tests/JwksHttpTest.php` adds what the vectors cannot carry, against PHP's built-in server: a server that accepts and
  never answers (the request returns after the 5-second deadline, the next one at once), a body above 64 KiB (and
  exactly 64 KiB as its counterpart), no redirects, no status but 200, eight concurrent **processes** sharing one fetch
  through a `FileStore`, a second lookup in a fiber while a fetch runs, a late answer of a fetcher.
- `tests/MintedTest.php` signs tokens with the public test key A, each with exactly one defect (invalid UTF-8 in five
  forms, a byte order mark, a repeated claim — also escaped and nested —, `NaN`, a lone surrogate, non-integer and
  out-of-range times, control characters, a wrong-length signature with an unknown `kid`, a trailing line break in a
  segment).
- `tests/MiddlewareTest.php`: every header vector through the PSR-15 middleware with a real PSR-7 implementation and
  through PHP's built-in server with `$_SERVER` (the limits above are measured there), the guards.
- `tests/GateTest.php`: configuration errors, token sources, trusted proxies, logging, failing closed.
- `tests/PropsTest.php`: generated input with a fixed seed — nothing but a `GateError` escapes, a changed or inserted
  character never verifies, the group, control-character and JSON rules hold.
- Static analysis: PHPStan at the highest level with the strict rules for the library and the examples, level 9 for the
  tests (they walk free-form vector JSON). Code style: PHP_CodeSniffer with PSR-12 (PHP CS Fixer refuses to run on a PHP
  newer than it knows).
- Mutation proof: see backlog [T-83](../../backlog/T-83-gate-client-in-php.md).

## License

MIT, like TinySesam.
