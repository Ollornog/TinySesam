---
id: B-3
type: Bug
title: 'Gate: paths containing ; or %3B are redirected to /.tinysesam/start'
status: offen
milestone: M-2
tags: [gate, forward-auth]
created: 2026-10-23
---

# B-3 — Gate: paths containing `;` or `%3B` are redirected to `/.tinysesam/start`

Finding 2026-10-23: In gate mode the login check redirects every path that contains a semicolon (raw or as `%3B`) to the start page of the login, even with a valid session. The client then receives the login page (HTML, HTTP 200) instead of the file, with no error. Counter-check: `# % & , [ { + = ! @ $ ' (` pass through, only `;` fails. Consequence: downloads of files with `;` in the name silently return wrong content (for example `&amp;` in the file name).

To clarify: where is `;` lost? In the reverse proxy (`forward_auth`: forwarding of the original URI) or in the check (URI parsing, `;` as parameter separator per RFC 3986 / `urllib`)?

Acceptance: a test with `;`, `%3B` and `&amp;` in the path — signed in → the file, signed out → the login; a mutation proves it.
