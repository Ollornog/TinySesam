---
id: T-14
type: Task
title: Multiple OIDC clients in one instance — per-app approval lives at the identity provider
status: erledigt
milestone: M-1
tags: [oidc, forward-auth, gateway, authorization, pocketid]
created: 2026-09-21
---

# T-14 — Multiple OIDC clients in one instance

**Operator requirement (2026-09-21, mandatory):** One TinySesam installation protects several
applications (hosts). Who may enter which application is decided **at the identity provider** — in
PocketID through the group approval per OIDC client —, not in TinySesam and not in the proxy. Since this
approval at the IdP applies **per client**, every protected application needs its own client.

Today TinySesam knows exactly one `oidc_client_id`/`oidc_client_secret`. The only solution so far was
one gateway instance per application — three containers, three databases, three audit logs,
three admin panels for the same users. That is the task this entry abolishes.

## What to do

- [x] **`oidc_clients`**: mapping from protected host to client (`client_id`, `client_secret`,
      optional `scopes`, `allowed_groups`, `group_role_map`). The existing single client stays
      as the default ("all hosts") — existing configurations keep running unchanged.
- [x] **One callback URL for all clients** (`base_url` + `oidc_callback_path`): Which client is
      meant is kept in the store within the flow, not in the URL. At the IdP all clients point to the
      same address.
- [x] **The session remembers the approvals**: for each client for which the IdP has signed the user
      in, one entry with a timestamp. Roles from `group_role_map` are kept per client,
      not globally.
- [x] **`/auth/forward` for a host without approval** starts the OIDC round with the client
      of that host (target host from `X-Forwarded-Host`, only from `trusted_redirect_hosts`/
      `protected_hosts`). The IdP still has its session and only checks the approval — a
      redirect, no new passkey. If the IdP refuses, it shows its own refusal; TinySesam
      leaves an audit line with client and reason.
- [x] **Revocation follows the IdP** (requirement from the same conversation, see the PocketID report
      of the third audit): The approval per client expires after `oidc_revalidate_minutes`; the
      next request re-checks with the IdP via refresh token or introspection — if it refuses,
      the approval for this client is gone, the session for the other clients stays. This way a
      group removal in the IdP takes effect within minutes, and a deletion there affects all clients.
- [x] **Gateway environment variables**: `TINYSESAM_OIDC_CLIENTS` as JSON or per host
      `TINYSESAM_OIDC_CLIENT_<HOST>_ID/_SECRET`; `deploy/forward-auth/` gets an example with
      two hosts and two clients.
- [x] **Configuration check**: host without client, client without secret, host not in `protected_hosts`,
      default client missing for hosts without an entry — report everything at startup.
- [x] **Tests**: two hosts, two clients against the OIDC dummy from `tests/test_oidc_jwks.py`;
      approval for A does not apply to B; refusal by the IdP for B leaves A untouched; revocation per client;
      existing configuration with a single client behaves exactly as before (`test_api_surface`).
- [x] **Docs**: README section "Multiple applications, one TinySesam" in both languages,
      `CONFIGURATION.md` (generated), CHANGELOG.

**Done when:** one instance protects three hosts with three IdP clients, the approval per host
comes exclusively from the IdP, a group removal there takes effect within the configured period, and
a configuration with only one client behaves not one byte differently than in 0.18.0.

## Why before 1.0

`oidc_clients` changes the shape of the OIDC configuration. That is more expensive after freezing
the API ([M-1](M-1-api-stable-1-0.md)) than before. The single client stays as a special case of the
mapping, so that the transition is not a break.

## Implemented on 2026-09-22

Built as described above, with two deviations that arose during the build:

- **No `protected_hosts` as a field of its own.** Which hosts are protected is already given by the keys of
  `oidc_clients` and `trusted_redirect_hosts`. A third field would have stated the same
  thing a third time — with the possibility that the three drift apart.
- **The re-check goes through the provider, not through a refresh token.** The silent route
  would have put a usable secret per session into the database. The redirect answers
  the same question, needs none, and the refusal comes from the provider itself — that is, from where
  the approval is maintained.

**Still open:** In-app operation (i.e. without a proxy) does not check the approval per application —
there is no target host there that could be asked. Anyone who mounts several applications in **one**
FastAPI process needs a separate route for that; that is a different case from the one this entry
was written for.
