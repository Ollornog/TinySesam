---
id: B-4
type: Bug
title: 'Login page: next is HTML-escaped but not percent-encoded in its links'
status: erledigt
milestone: M-2
tags: [gate, login]
created: 2026-10-29
---

# B-4 — Login page: `next` is HTML-escaped but not percent-encoded in its links

Found 2026-10-29 while investigating B-3. `next` was put into the links of the login page (`/auth/register?next=…`, `/auth/magic/request?next=…`, OIDC and SAML buttons) and into the passkey script with HTML escaping only, not as a query value: `&` cut the target off, `+` came back as a space, `%3B` as `;`, and `&amp;` went through the escaping twice. The user landed on a different file than the one requested.

Fixed: `templates._next_q` percent-encodes it; the server decodes once and still runs `safe_next` (foreign hosts, `//` and backslash stay `/`). Test `tests/test_next_in_links.py`; mutations: `_next_q` back to `html.escape`, and the passkey script back to `_e` → red.
