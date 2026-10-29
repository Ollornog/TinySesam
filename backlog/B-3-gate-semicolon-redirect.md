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

Cause (2026-10-29): not the gate and not TinySesam — the **share exception** in the proxy templates (`deploy/forward-auth/Caddyfile`, `Caddyfile.gate`, T-20). Its path filter, a hardening against `/s/..;/admin` (Tomcat/Spring read `..;` as `..`), rejected **every** `;` and `%3B`. Caddy matches the *decoded* path, so `%3B` became `;` and a share download such as `/s/<token>/file_%3B%29.bin` fell out of the exception and ran through the gate: 302 to `/.tinysesam/start`, and the client got the login page instead of the file. Paths without `;` were never affected, which is why the counter-check `# % & , [ { + = ! @ $ ' (` passed. A deployment that does not set `TS_SHARE_PRAEFIX` (the exception is off) is not affected.

Fix: a `;` only counts behind a dot segment. The filter is now `(?i)(^|/)\.\.?(/|;|%3b|$)|[\\\x00]|%(2e|2f|5c|00)` (was `(?i)(^|/)\.\.?(/|$)|[;\\\x00]|%(2e|2f|5c|00|3b)`): `..;`, `.;`, `..;x`, `..%3b` and the doubly encoded `..%253b` stay closed, a `;` or `%3B` anywhere else is an ordinary file-name character. Backslash, NUL, `%2e %2f %5c %00` (doubly encoded forms) and the case rule (`/S/` is not `/s/`) are unchanged. **Operators who copied the template must take over the line** (`@share` block in their own Caddyfile).

Test: `tests/test_gate_caddy.py` runs the share paths against a real Caddy (2.11.7, caddy-jwt 1.4.0) with **both** templates, the gate template and the plain `forward_auth` template (before, only the gate template was covered): 17 open paths (`;`, `%3b`, `%3B`, `%3B%29`, `;)` in the file name, `/public/share/a;b`, literal `%253B`), 30 closed ones (all T-20 path tricks unchanged, plus `.;`, `..;x`, `..%3b`, `..%253b`). `tests/test_gate.py` pins that both templates carry the same filter. Red before the fix on `/s/abc;jsessionid=1`.

Mutations (each run against the real Caddy → red): old rule back in both files, in the plain file only, in the gate file only; dot segment without `;`; dot segment without `%3b`; without backslash; without `%2e|2f|5c|00`; without NUL; case-sensitive.

## Investigation 2026-10-29 (earlier in the day: not reproducible)

Before the cause was found, this was measured and is pinned by tests; it narrowed the search to the share filter:

- `/auth/forward` with `X-Forwarded-Uri` = `/a;b.pdf`, `/a%3Bb.pdf`, `/Tom&amp;Jerry.pdf`, `/a;b.pdf?k=1;2&m=%3B`:
  signed in (session, API key, link cookie, gate cookie) → 200; signed out → 401 whose login target carries the
  path unchanged (`;` stays, `%3B` becomes `%253B`, `&` becomes `%26`). TinySesam never splits a path (no
  `urlparse`/`.params` anywhere; the repo grep is clean).
- Through a real Caddy 2.11.7 with caddy-jwt 1.4.0 and `deploy/forward-auth/Caddyfile.gate`, the whole
  code-exchange round trip (request → `/.tinysesam/start` → `/auth/gate/authorize` → `/.tinysesam/callback` → request)
  returns the file for all of these paths, with and without gate cookie — **outside the share exception**. That is
  why it was not reproducible: the test paths did not start with the share prefix. `tests/test_gate_caddy.py` and
  `tests/test_gate_link.py` pin this.
- A trap measured on the way: a template that builds `X-Forwarded-Uri` from `{http.request.uri.path}` instead of `{uri}`
  turns `%3B` into `;` (and drops the query) — `tests/test_gate_caddy.py` goes red on it.

The same error class, found on the way (login page, `next` not percent-encoded): split out as B-4.

Mutations of the earlier pins: `_forwarded_url` cutting at `;` → `test_gate_link` and `test_gate_caddy` red;
`X-Forwarded-Uri {http.request.uri.path}` in `Caddyfile.gate` → `test_gate_caddy` red.
