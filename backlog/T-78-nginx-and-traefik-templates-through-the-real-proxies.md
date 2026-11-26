---
id: T-78
type: Task
title: 'nginx and Traefik templates measured through the real proxies in the CI'
status: erledigt
milestone: M-5
tags: [forward-auth, ci, tests, security]
created: '2026-11-21'
---
# T-78 — nginx and Traefik templates through the real proxies

The Caddy templates were measured against a real Caddy since ADR-9 (`tests/test_gate_caddy.py`); nginx, nginx with
PHP (FastCGI) and Traefik were only read as text. A template is a claim about a proxy — what reaches the application is
decided there.

## Done

- `tests/test_proxies.py` runs `nginx.conf`, `nginx-path.conf` (with a FastCGI stand-in that answers with the
  parameters PHP would see) and `traefik.yml` word for word in the official images, digest-pinned in
  `tests/proxies/Dockerfile` (Dependabot `docker` entry). Required in the CI job `gate-caddy`
  (`TINYSESAM_PROXY_TESTS=1`), skipped without it.
- Probes per proxy:
  - anonymous: the template's answer;
  - a session and an API key (Bearer, `X-Api-Key`): TinySesam's `Remote-*` with `Remote-Auth`;
  - forged `Remote-*` (also the aliases `Remote_User`, `Remote.Groups`), `X-Original-URL` and `X-Forwarded-Host`
    never reach the application, also with `forward_headers` reduced, where TinySesam sends no value;
  - no credential at the application or in the proxy's log;
  - `/.tinysesam/*` reaches TinySesam.

## Found and fixed (CHANGELOG, Security)

- nginx (`nginx.conf`, `nginx-path.conf`), Traefik and the Caddy templates passed a client's `X-Original-URL` on to the
  application; nginx also its `X-Forwarded-Host`.
- Traefik: alias headers (`Remote_User`, `Remote.User`) get past `authResponseHeaders`; a CGI/WSGI/PHP backend reads
  them as `HTTP_REMOTE_USER`. Only Traefik's static configuration can close that (`aliasHeadersStrategy: delete`), so the
  template's header now requires it and the test runs with it.
- nginx and Traefik had no route for `/.tinysesam/*` (sign-out at the application T-22, top bar JSON T-76).

## Measured, not assumed

- Traefik's `authResponseHeaders` deletes a listed header from the request before copying TinySesam's value, also when
  TinySesam's answer does not carry it (Traefik 3.7.19).
- A `fastcgi_param HTTP_REMOTE_*` replaces the client's header of the same name: PHP sees each value once.

## Proof

Mutations, each red: nginx without `proxy_set_header Remote-Auth`, nginx-path without emptying `HTTP_REMOTE_ID` in
the open part, Traefik without `Remote-Auth` in `authResponseHeaders`, Traefik without the strip middleware, Traefik
without `aliasHeadersStrategy`, Caddy without `request_header -X-Original-URL` (in `tests/test_gate_caddy.py`).
