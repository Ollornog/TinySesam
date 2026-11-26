---
id: T-49
type: Task
title: 'OIDC: max_age / auth_time for re-authentication'
status: erledigt
milestone: M-5
tags: [security, oidc, stepup]
created: '2026-11-20'
---
# T-49 — OIDC: max_age / auth_time for re-authentication

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding N5 — ASVS 6.8.4 (L2).

**Is:** freshness of federated accounts counts from TinySesam's own sign-in; a silent re-login through the running IdP
session counts as fresh (`oidc.py` sends no `prompt`/`max_age`, checks no `auth_time`).

**Proposal:** for step-up send `prompt=login` / `max_age=0` and check `auth_time`. Effort M.

## Done (H4)
- Switch `oidc_reauth_check` (default on). The confirmation page offers "Confirm with <provider>" to an account linked
  to the provider (`/auth/oidc/start?reauth=1`): the request carries `prompt=login` and `max_age=0`, and the callback
  confirms only with an `auth_time` ≥ the request time minus 60 s; otherwise a 401 page, audit `oidc_reauth_stale`,
  nothing refreshed.
- Every other round on a full session (approval for another application, T-14) no longer counts as a step-up
  without a fresh `auth_time` (`stepup_not_counted reason=no_fresh_auth_time`). A new session's `mfa_at` is
  backdated to the provider's `auth_time` (`Store.backdate_confirmation`), so a silent sign-in is as old as the
  provider's real one for `stepup_fresh`/`login_fresh`; `login_fresh` now measures `mfa_at` (the last sign-in on the
  session) and a purely federated account is sent to the confirmation page instead of "sign out".
- Fallback without `auth_time` (ASVS 6.8.4 asks for a documented one): a new session counts from TinySesam's own
  sign-in; the provider button then never confirms. Documented in `SECURITY.md` (en/de).
- Tests: `tests/test_h4_auth_hardening.py` (T-49 block, through the real start/callback with a faked token exchange).
- Open/follow-up: SAML has the same gap (`ForceAuthn` is not sent, no `AuthnInstant` check) — new backlog item if
  wanted. `acr`/`amr` are not evaluated (strength, not recency).
- Sources: ASVS 5.0.0 6.8.4; OpenID Connect Core 1.0 §2 (`auth_time`), §3.1.2.1 (`prompt=login`, `max_age`: "the ID
  Token returned MUST include an auth_time Claim"), §3.1.3.7 item 11 (the client checks `auth_time`); NIST SP
  800-63B-4 §5.2 ("The RP SHALL be authoritative as to whether the reauthentication requirements have been met").
