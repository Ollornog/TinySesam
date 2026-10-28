---
id: T-3
type: Task
title: Forward auth — make the remote headers that are set configurable
status: erledigt
milestone: M-1
tags: [forward-auth, konfiguration]
created: 2026-07-10
---

# T-3 — Fine control of the `Remote-*` headers

In forward-auth mode ([ADR-3](ADR-3-in-app-statt-proxy.md)) `/auth/verify` sets a fixed set of
`Remote-*` headers. Not every downstream application wants all of them, and some expect different
names.

**Done when:** the selection can be controlled through configuration and the default stays
unchanged (no silent behaviour change for existing users).

## Done (2026-09-19)

`config.forward_headers` maps **field → header name** (`user` · `name` · `email` · `groups`);
one field may point to several names. Empty keeps the Authelia set `Remote-*`, so nothing changes
for existing users.

The mapping is the **complete** list and not an addition: `{"user": "X-WEBAUTH-USER"}` sends
exactly that one header. One field thus covers both halves of the task — renaming *and* omitting —
instead of needing a second switch for "which ones do I want at all". Anyone who does not want to
give the app the email address leaves out `email`.

Validation happens at startup, not at runtime: an unknown field (`"mail"` instead of `"email"`)
would otherwise silently drop the header, and a name with a line break would be header injection.
Both now raise `ValueError`. The set is built in `auth.forward_response_headers(user)` — the same
seam for custom adaptations.
