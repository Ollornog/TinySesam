---
id: B-6
type: Bug
title: 'Gate: refresh exchange does not renew the application approval — hourly login once the provider session has ended'
status: erledigt
milestone: M-2
tags: [gateway, oidc, forward-auth]
created: 2026-11-07
---

# B-6 — Gate: refresh exchange does not renew the application approval

## Repro

Gateway with several OIDC clients (`oidc_clients`), `oidc_revalidate_minutes=60` (the `oidc_gateway()` default), a
provider whose own session lasts one hour (PocketID's default "session duration"). Sign in to an application, keep
using it.

**Expected:** no login form while the gateway session lives and the provider keeps confirming the person.
**Actual:** every hour the approval goes stale (`app-stale`), forward auth sends the browser to the provider, whose
session has ended by then — the person has to sign in again (passkey) each hour.

## Cause

Every `oidc_session_refresh_minutes` (15) TinySesam exchanges the refresh token per client and evaluates the groups
(4a). A yes from the provider for client X did not touch the approval of application X (`oidc_grant.checked_at`). So
the approval aged although the provider had just confirmed it, and only the redirect hop could renew it.

## Fix

`_oidc_swap` renews the approval of the exchanged client after a yes (`store.confirm_oidc_grant`):

- only an **existing** approval — one withdrawn by the operator (`drop_oidc_grant`) or never granted stays absent;
- with `allowed_groups` only if the groups claim was in the answer and passed; a missing claim proves nothing, the hop
  still decides;
- time stamp is the moment the provider was asked, not the answer.

Security does not drop: a revocation at the provider now takes effect after at most 15 minutes instead of 60 (the
refresh is refused → session ends, as before); an unreachable provider renews nothing (redirect hop stays as
fallback, `oidc_session_max_unverified_hours` still ends the session). Test: `tests/test_forward_auth.py` (B-6
block, three mutations killed). Operator-side alternative without code: T-31.
