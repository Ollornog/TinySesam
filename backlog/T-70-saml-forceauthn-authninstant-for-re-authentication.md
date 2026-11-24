---
id: T-70
type: Task
title: 'SAML: ForceAuthn / AuthnInstant for re-authentication (the T-49 gap)'
status: offen
points: 5
milestone: M-4
blocked_by: [T-112]
tags: [security, saml, stepup]
created: '2026-11-21'
---
# T-70 — SAML: ForceAuthn / AuthnInstant for re-authentication

Source: follow-up of [T-49](T-49-oidc-max-age-auth-time-for-re-authentication.md) (sign-in hardening H4), review before
0.26.0 — ASVS 5.0.0 6.8.4 (L2), NIST SP 800-63B-4 §5.2.

**Is:** the SAML path has the gap T-49 closed for OIDC. `saml_.SAMLClient.login_url` sends the `AuthnRequest`
without `ForceAuthn`, and `process` does not read the assertion's `AuthnStatement/@AuthnInstant`. `saml` is in
`TinySesam._STEPUP_SIGN_INS`, so a round through the identity provider's running session — silent, no factor typed —
counts as a fresh confirmation on a full session (`apply_factor` → `rotate_session`, `mfa_at` = now), and a new
session counts as signed in "now" even when the provider's sign-in lies hours back. A stolen, stale session cookie
plus a still running IdP session is enough for new access (`_require_fresh`). The confirmation page offers SAML
accounts nothing of their own: a purely SAML account with nothing to confirm with is told to sign in again
(`_fresh_enough` → `"relogin"`), and the new sign-in is exactly the silent round.

**Why not in the pre-0.26 follow-ups:** not small. It needs (1) `ForceAuthn="true"` on a re-authentication request
(`OneLogin_Saml2_Auth.login(force_authn=True)`) with the request time in the request flow (`put_flow`), (2) reading
`AuthnInstant` from the checked assertion — python3-saml has no public getter, so a parse of the validated response
XML (`get_last_response_xml`, defusedxml) bound to the signed assertion, (3) the step-up rule in `saml_acs`
(`stepup_not_counted reason=no_fresh_authn_instant`, `saml_reauth_stale`), (4) `Store.backdate_confirmation` for a new
session, (5) a "Confirm with <provider>" button on the confirmation page for SAML-linked accounts
(`_confirms_at_provider`), messages en/de, and (6) tests with really signed responses (the H1 helper in
`tests/test_saml.py`) — about the size of T-49.

**Proposal (analogous to `oidc_reauth_check`):** a switch `saml_reauth_check`, default `True`.

- The confirmation page offers SAML-linked accounts "Confirm with <provider>" → `/auth/saml/login?reauth=1`, which
  sends `ForceAuthn="true"`; the ACS confirms only with an `AuthnInstant` at or after the request time (60 s clock
  tolerance), otherwise a 401 page and audit `saml_reauth_stale`.
- Any other SAML round on a full session no longer refreshes the confirmation without a fresh `AuthnInstant`
  (`stepup_not_counted reason=no_fresh_authn_instant`); a new session's `mfa_at` is backdated to `AuthnInstant`.
- Documented fallback (ASVS 6.8.4): an IdP that ignores `ForceAuthn` answers with an old `AuthnInstant` and is caught
  the same way; the attribute is mandatory in `AuthnStatement` (SAML 2.0 Core §2.7.2), so "missing" is a broken
  response. `saml_reauth_check=False` keeps the behaviour up to 0.26.x. Upgrade note: SAML accounts confirm with
  their own factors or the provider button; a silent IdP round no longer makes a session fresh.

**Done when:** the switch exists with the default on; a silent round (old `AuthnInstant`) on a stale full session
does not make it fresh and a forced one does; a new session from an old `AuthnInstant` is not fresh for
`_require_fresh`; the reauth page shows the provider button to a SAML account; tests with signed responses and
mutations; `SECURITY.md` (en/de) drops the "SAML has no such check yet" line and names the fallback.

Sources: SAML 2.0 Core (OASIS, 2005) §3.4.1 (`ForceAuthn`: "the identity provider MUST authenticate the presenter
directly rather than rely on a previous security context"), §2.7.2 (`AuthnStatement`, `AuthnInstant` required);
ASVS 5.0.0 6.8.4; NIST SP 800-63B-4 §5.2.

## Roadmap (2026-11-23)

Moved to [M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md): this is the SAML part of stage S3
([T-99](T-99-stage-s3-every-origin-is-equal-source-step-up-linking-l.md)), the detailed design stays here. It does not
need the server stage and can run as soon as the module cut ([T-112](T-112-modules-split-manager-py-and-store-py-into-one-building.md))
is merged. Estimate: 5 SP, 8–12 h.
