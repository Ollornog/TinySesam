---
id: B-1
type: Bug
title: The admin panel rolls a new CSRF token on every request
status: erledigt
milestone: M-1
tags: [csrf, admin, security]
created: 2026-09-21
---

# B-1 — The admin panel rolls a new CSRF token on every request

Three places set the CSRF cookie: `manager.render_page`, `manager.issue_csrf` and
`admin.py`. For the first two, exactly this bug was fixed once before (commit `b6204bf`):
`render_page` rolled a new token on **every** render and overwrote the cookie — open
forms became invalid and answered with **403 without an error message**. Since then,
`render_page(..., request=request)` adopts an existing cookie.

`admin.py` is the third place. On every `GET` of the panel page it unconditionally sets a fresh
token, without looking at the existing one.

## Reproduced

With an instance that has the login page and admin panel mounted:

1. `GET /auth/login` → cookie `tinysesam_csrf` = **A**. Second request: still **A** (correct).
2. `GET /auth/admin` → the cookie is now **B**.
3. `POST /auth/login` with the token **A** from the still-open form → **403**.

The mechanism still protects against the attacker; it is the user themselves who is hit. In practice:
two tabs open, one of them the panel — the form in the other fails silently.

## Done when

- The panel adopts an existing, valid CSRF cookie instead of replacing it (same
  handling as in `render_page`).
- A suite covers the third setter. `tests/test_cookies.py` already names the gap and
  points to `tests/test_adminmount.py` as the right place. Since 2026-09-21 it lives in
  `tests/test_legacy_data.py` instead: `test_adminmount.py` runs throughout with
  `csrf_enabled=False` — a CSRF check in it would either have switched the whole suite over or
  stood there as a lone foreign body with its own config.
- The regression test checks the **raw** `Set-Cookie` header, not the cookie jar: the jar swallows
  attributes and does not even store Secure cookies over `http://`.

## Done (2026-09-21, with [T-9](T-9-audit-2026-09-21-round-2.md))

Pulled forward from M-2 to M-1: the entry carries `tags: [csrf, admin, security]`, and M-1
has explicitly required *no open security findings* since the maturity review. Putting a
security finding at "after 1.0" while 1.0 requires none open is self-contradictory.

On top of that, the situation had meanwhile become worse than at the time of the report: the security fixes of T-8 put
four more routes and **every** non-reading method of the panel under CSRF — the
token rotation thus hit more paths than before.

`admin.py` now adopts an existing cookie instead of rolling one on every request —
the same handling as in `render_page`. Measured: the login page sets token A, a panel request
sets **no** new cookie any more, and the POST from the other tab answers 200 again
instead of 403.
