---
id: T-37
type: Task
title: 'Home network: template for IP only, with a clear recommendation for a domain'
status: erledigt
milestone: M-5
tags: [deploy, tls, home-network, docs, config-check]
created: '2026-11-20'
---
# T-37 — Home network: template for IP only, with a clear recommendation for a domain

Wish (PO 2026-11-20): a simple template for home networks that want to run on a bare IP address — together with
the recommendation to use a domain. Background: TinySesam's cookies are `Secure`, OAuth clients (Claude Code among
them) require HTTPS for the token endpoint unless it is loopback, and WebAuthn refuses passkeys on an IP address
outright (Web Authentication Level 3, §5.1.3: only the domain form of the host is allowed). Without a domain, HTTPS
needs a certificate with the IP as Subject Alternative Name from a CA of your own that every device trusts once.

## Done

- **Finished service, no own crypto:** Caddy's local CA (`tls internal`). Measured against Caddy 2.11.9 (newest
  stable): it issues a leaf with `IP Address:192.0.2.10` as SAN; root 10 years, intermediate 7 days, leaf 12 hours
  (the documented defaults); the root lies at `/data/caddy/pki/authorities/local/root.crt`. Trap found on the way:
  clients send no SNI for an IP, Caddy then matches by the local address of the connection — inside a Docker bridge
  the container's — and the handshake fails (`tlsv1 alert internal error`). `default_sni` fixes it. Node.js accepts
  the certificate with `NODE_EXTRA_CA_CERTS`, not without.
- `deploy/home-network/`: Caddyfile (TinySesam on :443, an app with forward auth on :8443 — a bare IP has no
  subdomains, cookies are not separated by port) and an override for the reference stack (Caddy pinned by version
  and digest, Dependabot entry). Only documentation addresses (RFC 5737).
- `docs/HOME-NETWORK.md`: domain first (DNS-01 also for names that resolve only at home), then the IP way: start,
  export the root, trust it on every device incl. Claude Code, limits.
- `config_check`: warning for an IP `base_url` (not for loopback/`localhost`).
- Tests: `tests/test_home_network.py` (warning, the override's settings start the gateway, forward auth on the IP
  with a port, only documentation addresses, `tls internal` + `default_sni`); the Caddyfile's forward-auth block runs
  through the template checks of `tests/test_legacy_data.py`. CI step: the override's Caddy completes the handshake
  without SNI on both ports and chains to the exported root.

Done when: the template starts, the guide says when a domain is better and how the IP way works, and the check
warns. ✅
