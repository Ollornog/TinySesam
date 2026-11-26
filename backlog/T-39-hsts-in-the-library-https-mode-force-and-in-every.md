---
id: T-39
type: Task
title: 'HSTS in the library (https_mode=force) and in every proxy template'
status: erledigt
milestone: M-5
tags: [security, headers, deploy, asvs]
created: '2026-11-20'
---
# T-39 — HSTS in the library (https_mode=force) and in every proxy template

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M4 — ASVS 3.4.1 (L1).

**Was:** no `Strict-Transport-Security` anywhere — neither in the app nor in `deploy/` (Caddy sets none itself).

## Done (H1)
- `config.hsts` (tier B, default `max-age=31536000`): `install_https` with `https_mode="force"` adds a pure ASGI
  middleware that sets it on every HTTPS response of the app, host routes included, never over HTTP (RFC 6797 §7.2);
  the app's own value wins. Without `includeSubDomains` by default (on a parent domain it binds every subdomain),
  no `preload`. Unparseable values (also with a line break) → `ConfigError`. Gateway: also with its `/healthz` exception.
- Templates: Caddyfile and Caddyfile.gate (both sites), nginx.conf, Traefik (middleware on both routers) with
  `includeSubDomains` (dedicated hosts: it only covers subdomains of that host); nginx-path.conf (parent domain)
  without. Home network (IP): deliberately none, browsers ignore HSTS from an IP (RFC 6797 §8.1.1) — reason in the file.
- `deploy/forward-auth/acceptance.sh`: checks HSTS ≥ 1 year (skipped for an IP address).
- Tests: `tests/test_hsts.py` (library + templates), `tests/test_gateway.py`, `tests/test_gate_caddy.py` (real Caddy:
  header on 200 and on the redirect to the sign-in, both templates).
