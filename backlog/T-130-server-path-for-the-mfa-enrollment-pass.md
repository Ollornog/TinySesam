---
id: T-130
type: Task
title: "Server path for the MFA enrollment pass (grant and revoke)"
status: erledigt
points: 2
milestone: M-2
tags: [server, parity, admin, mfa]
created: 2026-11-27
---
# T-130 — Server path for the MFA enrollment pass

**Done (2026-11-27):** `POST <admin>/api/users/{uid}/mfa-enrollment` (`minutes` 1–1440, default 60; fresh
confirmation, owner model) and `…/mfa-enrollment/delete` (no confirmation needed to close); the panel's TOTP line
offers "Allow setup for 1 hour" and shows until when it is open; `GET …/totp` names `enrollment_until`. Both parity
entries name the routes. Tests in `tests/test_totp_reset.py`; mutations in the pull request.

**Story points:** 2 · **Estimate:** 3 h · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

Found by the parity test of [T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md): `grant_mfa_enrollment`
and `revoke_mfa_enrollment` (tier B) have no server route. An operator of the server cannot let an account without a
second factor in once to set one up (`mfa_enrollment`), which the library does in Python. Both sit on the parity
list as "library: server path missing — T-130" until then.

## Content
- Panel routes `POST <admin>/api/users/{uid}/mfa-enrollment` (grant, with the validity) and `…/delete` (revoke),
  administrators only, owner model, a fresh confirmation; a line on the panel's account page.
- `server` of both entries in `tests/api_surface.json` names the routes.

## Acceptance
- The parity test lists both with a server route; removing a route turns it red (mutation).
