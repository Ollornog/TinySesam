---
id: T-83
type: Task
title: 'Gate client in PHP'
status: erledigt
milestone: M-5
tags: [gate, clients, php]
created: '2026-11-22'
---
# T-83 — gate client in PHP

A small PHP library for applications behind TinySesam's gate, built on the specification and the vectors of
[T-28](T-28-go-variant-small-gate-client.md). It checks; it never issues tokens or signs anyone in.

`sodium_crypto_sign_verify_detached` (ext-sodium); `json_decode` keeps the last duplicate, so a check runs first. A PSR-15 middleware as the first integration.

## Done when

- `clients/php/` follows [`clients/README.md`](../clients/README.md): both modes of
  [`spec/gate-client.md`](../spec/gate-client.md) (header mode; token mode with fixed keys and with JWKS), guards for
  signed in, role and session only.
- Its test suite loads `spec/vectors/*.json` from the repository and passes every token, header, key-set and
  cache-scenario vector; plus the tests the vectors cannot carry (a JWKS server that never answers, a body above
  64 KiB, concurrent requests sharing one fetch).
- Mutation proof: relaxing one rule (algorithm from the header, no duplicate check, stripping instead of refusing)
  turns the vector suite red.
- A workflow `client-php.yml` on `ubuntu-latest` (actions pinned by SHA, `permissions: contents: read`, no path filter),
  the Dependabot entry `composer` for `/clients/php`, a README in English.
- No publication to Packagist without a decision of the product owner.

## Done

- Package `tinysesam/gate` 0.1.0 in [`clients/php/`](../clients/php/README.md) (not on Packagist), spec v2: header mode
  (`Gate::headerMode`, trusted proxies, renamed headers, `GateRequest::fromGlobals($_SERVER)` and `::fromPsr7`), token
  mode with fixed keys or a key set URL, the identity with `accountKind`, guards for signed in, role, session and account
  kind (`Decision`, `Requirement`), a PSR-15 `GateMiddleware`/`RequireMiddleware` as the first integration, the top bar
  helper. PHP 8.4+ (the oldest release with active support, and PHPUnit 13 needs it; ext-sodium sets no limit). Runtime:
  ext-sodium, ext-json, ext-pcre, four PSR interface packages; ext-curl for the key set fetch. No JOSE library
  (`web-token/jwt-framework` would still need every pre-check).
- PHP-specific: `json_decode` into `\stdClass` behind a scan that refuses repeated names (`{}` vs `[]` and `1` vs `1.0`
  stay apart); `\z` instead of `$` in every pattern (a trailing line break); the key set cache in a `Store` —
  `MemoryStore` for workers, `FileStore` (`flock`) for PHP-FPM, where a memory cache would fetch on every request; a
  late answer of a fetcher is discarded (PHP cannot interrupt it). Limit: a JSON member name starting with NUL is refused
  by `json_decode` (a refusal either way).
- Measured SAPI limits (pinned by a test through PHP's built-in server): a repeated field arrives joined, `Remote_User`
  and `Remote-User` are one variable, the built-in server cuts a value at NUL. Proxy duty 1 covers them; README section
  "What PHP hands over".
- Tests (102): every vector — token 120, headers 50 (directly, through `Gate::identify`, through the PSR-15 middleware
  with nyholm/psr7, and through PHP's built-in server with `$_SERVER`), key sets 19, cache scenarios 10 (48 steps), top
  bar 6, the test keys — plus a server that never answers (one deadline, then nothing), a body above 64 KiB and exactly
  64 KiB (curl and the cache), no redirects, no status but 200, eight concurrent processes sharing one fetch through a
  `FileStore`, a fiber lookup during a fetch, minted tokens with one defect each, configuration errors, properties with
  a fixed seed. Green on PHP 8.4, 8.5 (CI) and 8.6.
- Mutation proof: 58 hand mutations, one rule each, restored from a saved copy with a hash check: 52 red. The required
  ones turn the vector suite alone red: `alg` from the header, no duplicate check, stripping instead of refusing (header
  and claim), `service` with `session` accepted, a missing `Remote-Kind`/`ts_kind` taken as `user`, a case-folded kind.
  Equivalent (a second guard holds the rule): the base64url alphabet (the canonical re-encoding), the UTF-8 check of the
  JSON input (`json_decode` refuses invalid UTF-8 itself), trimming all whitespace from groups (every other whitespace
  character is a refused control), the freshness ceiling (clamped twice), curl's write-callback limit
  (`CURLOPT_MAXFILESIZE`), sharing a fetch that ran while waiting (the rate limit gives the same answer). The first run
  left two real gaps green — the cache's own body limit and `identify()` failing closed — both got tests.
- `client-php.yml` (`test` on 8.4/8.5 with setup-php, `image` on 8.6 in `clients/php/ci/Dockerfile`), every job running
  `clients/php/ci.sh`, which `scripts/check.sh` runs too (natively or through `clients/php/ci/in-docker.sh`; neither is
  a failure, not a skip). Dependabot `composer` and `docker` (`/clients/php/ci`); auto-merge with `client-php.yml` among
  the mandatory workflows.
