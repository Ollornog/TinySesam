---
id: B-3
type: Bug
title: 'Gate: paths containing ; or %3B are redirected to /.tinysesam/start'
status: erledigt
milestone: M-2
tags: [gate, forward-auth]
created: 2026-10-23
---

# B-3 — Gate: paths containing `;` or `%3B` are redirected to `/.tinysesam/start`

Finding 2026-10-23: In gate mode the login check redirects every path that contains a semicolon (raw or as `%3B`) to the start page of the login, even with a valid session. The client then receives the login page (HTML, HTTP 200) instead of the file, with no error. Counter-check: `# % & , [ { + = ! @ $ ' (` pass through, only `;` fails. Consequence: downloads of files with `;` in the name silently return wrong content (for example `&amp;` in the file name).

To clarify: where is `;` lost? In the reverse proxy (`forward_auth`: forwarding of the original URI) or in the check (URI parsing, `;` as parameter separator per RFC 3986 / `urllib`)?

Acceptance: a test with `;`, `%3B` and `&amp;` in the path — signed in → the file, signed out → the login; a mutation proves it.

## Done 2026-10-29

**Finding on the question "where is `;` lost?": not in TinySesam, and not in the repository's proxy templates.**
Measured, not read:

- `/auth/forward` with `X-Forwarded-Uri` = `/a;b.pdf`, `/a%3Bb.pdf`, `/Tom&amp;Jerry.pdf`, `/a;b.pdf?k=1;2&m=%3B`:
  signed in (session, API key, link cookie, gate cookie) → 200; signed out → 401 whose login target carries the
  path unchanged (`;` stays, `%3B` becomes `%253B`, `&` becomes `%26`). TinySesam never splits a path (no
  `urlparse`/`.params` anywhere; the repo grep is clean).
- Through a **real Caddy 2.11.7 with caddy-jwt 1.4.0** and `deploy/forward-auth/Caddyfile.gate` word for word, the whole
  code-exchange round trip (request → `/.tinysesam/start` → `/auth/gate/authorize` → `/.tinysesam/callback` → request)
  returns the file for all of these paths, with and without gate cookie. The same holds for a downstream
  copy of the gate macro (rendered, single hop). `tests/test_gate_caddy.py` and `tests/test_gate_link.py`
  now pin this.
- Not reproducible here, therefore **not fixed in this repository**: the production chain has a second hop (edge proxy →
  application proxy) and an application behind it. If the observation recurs, capture the request with `;` at each hop
  (what `X-Forwarded-Uri` carries into `/auth/forward`) — the first hop that shows `/.tinysesam/start` without the
  path, or a 401 from `/auth/forward` in the TinySesam log, is the place. One trap measured on the way: a template
  that builds `X-Forwarded-Uri` from `{http.request.uri.path}` instead of `{uri}` turns `%3B` into `;` (and drops the
  query) — `tests/test_gate_caddy.py` goes red on it.

**The same error class, found and fixed (the login page).** `next` was put into the links of the login page
(`/auth/register?next=…`, `/auth/magic/request?next=…`, OIDC and SAML buttons) and into the passkey script with HTML
escaping only, not as a query value: `&` cut the target off, `+` came back as a space, `%3B` as `;`, and `&amp;` went
through the escaping twice. `templates._next_q` percent-encodes it; the server decodes once and still runs `safe_next`
(test: foreign hosts stay `/`). Test `tests/test_next_in_links.py`; mutation: `_next_q` back to `html.escape` → red.

Mutations of the `;` pins: `_forwarded_url` cutting at `;` → `test_gate_link` and `test_gate_caddy` red;
`X-Forwarded-Uri {http.request.uri.path}` in `Caddyfile.gate` → `test_gate_caddy` red.
