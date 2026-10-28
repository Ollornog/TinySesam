---
id: T-1
type: Task
title: End-to-end test against a real identity provider
status: erledigt
milestone: M-1
tags: [testing, passkey, oidc, saml]
created: 2026-07-10
---

# T-1 — End-to-end test against a real IdP

**The biggest remaining blind spot.** Passkey/WebAuthn, OIDC and SAML have so far only been
**structure-tested**: the ceremony has never run in a real browser on a real HTTPS domain against
a real IdP. A bug there would only show up in production.

## What is missing

- A publicly reachable domain with a valid certificate (WebAuthn requires a real `rp_id` and
  HTTPS)
- An IdP with a registered client
- A passkey-capable browser

## How

The same CDP suite as `tests/test_browser.py`, but with `BASE_URL=https://…` against the deployed
instance — so a **smoke test after deploy**, not a CI test. WebAuthn can be driven over CDP with
`WebAuthn.enable` + `WebAuthn.addVirtualAuthenticator`, without a real security key.

## Why not a CI test

CI has no domain, no certificate and no IdP. A test that fakes them checks the dummy — not the
ceremony.

**Done when:** a run against a real instance plays through all three paths and turns red when it
is deliberately broken.

## Done (2026-09-19)

`tests/e2e_stage.py`, run against a deployed instance with a real domain and a real certificate.
All three paths run through: passkey (registration via the built-in account page, then passwordless
sign-in — virtual authenticator, but real `rp_id`), SAML against a real IdP, OIDC against a real
provider.

Both halves of the criterion verified:

| Run | Exit |
|---|---|
| everything configured correctly | 0 |
| wrong password at the IdP | **1** |
| credential the provider does not know | **1** |
| without configuration (skipped) | 0 — checking nothing is not a failure |

**The run found something immediately**, which is what this entry was for: a rejected SAML
assertion showed the *magic-link* error page and left no log line — the cause (`Invalid issuer`,
because Keycloak's entity ID is not the SSO URL) could only be found by patching the library.
Fixed; the reason is now passed on to `tinysesam.security`.

What the run learned about itself while being built is in the CHANGELOG: wait for states instead of
the clock, clean up after itself, report a rate limit as a rate limit.

**Not part of this entry:** the stage was set up by hand. Making it reproducible (a playbook that
builds the stage from a fresh throwaway CT) is its own task.
