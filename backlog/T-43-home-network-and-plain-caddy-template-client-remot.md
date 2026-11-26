---
id: T-43
type: Task
title: 'Home-network and plain Caddy template: client Remote-* headers measured'
status: erledigt
milestone: M-5
tags: [deploy, forward-auth, security]
created: '2026-11-20'
---
# T-43 — Home-network and plain Caddy template: client Remote-* headers measured

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), attack candidate 5 (suspicion, not measured): the plain and the home-network Caddyfile do not strip
`Remote-*` up front like `Caddyfile.gate`, and rely on `request_header` in `handle_response`.

## Measured (H1, 2026-11-20)
Caddy 2.11.9 in a throwaway container, both templates, a stand-in for `/auth/forward`, an echo app; the client sends
`Remote-User/-Email/-Groups: forged`:
- TinySesam answers with an EMPTY `Remote-Email` (account without an address): Caddy sets `""` — the client's value
  does not reach the app. **Closed**, no template change needed.
- If the auth response lacks the header entirely (operator renamed `forward_headers` but kept the template lines),
  the app receives the literal placeholder text → T-58.
- nginx 1.31 (`proxy_set_header`): the client's value is removed as well. Traefik deletes before it copies (source).
- Pinned in `tests/test_gate_caddy.py` (real Caddy, plain template and gate way back).
