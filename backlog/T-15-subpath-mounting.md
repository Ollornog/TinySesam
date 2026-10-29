---
id: T-15
type: Task
title: Make built-in pages mountable under a subpath
status: erledigt
milestone: M-2
tags: [routen, templates, deployment]
created: 2026-09-22
---

# T-15 — Make built-in pages mountable under a subpath

`base_url` carries the subpath, and the **links that are sent** have carried it exactly once since 0.19
(reset, sign-in link, confirmation, invitation; measured in `tests/test_security_findings.py`).
The **built-in pages** do not carry it: form targets and links in `templates.py` are
root-absolute paths (`/auth/register`, `/auth/forgot`, `/auth/magic/request`, `/auth/totp`,
…), and the redirects take `login_path`/`login_redirect`/`logout_redirect` unchanged.

If the app is mounted under `--root-path /sso` behind a proxy that strips `/sso`, each of these paths
points out of the mount: the visitor lands on `https://example.com/auth/login`
instead of `…/sso/auth/login` — 404. The confirmation mail works in that case, the sign-in does not.

**Current state:** The docs say exactly that (README, `i18n/README.de.md`, `CONFIGURATION.md`,
CHANGELOG): the subpath belongs in `base_url` and applies to the links that are sent; the built-in
pages assume that the app sits at the root of its host. A limit that is stated out loud,
instead of a promise that does not hold (finding B-regression-3, third audit round).

**Done when:** the pages derive their targets from **one** source (the request's `root_path` or
a field like `mount_prefix`), a mount under `/sso` without any further setting carries through login,
registration, magic link, reset and account page, and a test measures that on a real mount — not
on a reconstructed URL. Only then may the docs say "carries the subpath" without
qualification.

## Done 2026-09-25

One source: `TinySesam._prefix(request)` takes the path of `base_url`, and without it `scope["root_path"]`
(counter-check: only this way do the guards of a host app outside the mount and a proxy that strips without
`--root-path` come out right). Form checked: only
`/part/part` of A–Z a–z 0–9 . _ ~ -, otherwise empty and a warning — the value ends up unmasked
in attributes and scripts). The built-in pages write `__TS_P__` in front of every path of the app
(forms, links, fetch calls), `render_page` inserts the prefix; a custom template without
the placeholder stays untouched. Redirects to paths of the app go through `auth.pfad(request, p)`;
a `next` target is already a path of the browser and gets no second prefix. `safe_next(next,
request)` gives the fallback `login_redirect` the prefix; the routes have `next=""` instead of `"/"`
as default, so that a missing `next` really leads to `login_redirect` (that is how it already stood in
the configuration). Measured in `tests/test_subpath.py` on a Starlette mount, on a
scope as produced by `uvicorn --root-path` and at the root (unchanged), six mutations red.

**Counter-check (one attacker):** 3 medium (forward-auth URL without prefix, host-app guard,
placeholder replacement via data and custom templates → open redirect in custom templates), 2
low, 3 info — all fixed, 12 mutations red.

**Limit:** `FastAPI(root_path=...)` on the app itself leaves the request path without a prefix —
pages and redirects are right, but `next=` targets from `request.url.path` point out of the mount.
The route is `--root-path` on the server or a mount (README).
