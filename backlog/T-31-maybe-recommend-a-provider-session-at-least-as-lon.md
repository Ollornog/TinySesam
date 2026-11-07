---
id: T-31
type: Task
title: 'Maybe: recommend a provider session at least as long as the gateway session'
status: offen
milestone: M-2
tags: [gateway, oidc, docs, maybe]
created: 2026-11-07
---

# T-31 — Maybe: recommend a provider session at least as long as the gateway session

**Maybe** — only if B-6 is not enough in practice (e.g. applications without refresh tokens, or a provider that
omits the groups claim on refresh).

Second way out of the hourly login (B-6): raise the provider's own session lifetime (PocketID: "session duration",
default 60 minutes) to the gateway session (`session_ttl_hours`, 7 days by default). Then the redirect hop of
`oidc_revalidate_minutes` stays invisible even where no refresh token renews the approval.

Price: the provider session is the central SSO session — longer for **every** client of the provider, including
applications without the gate in front. A stolen provider cookie lives longer. Revocation is unaffected (the provider
decides on each hop and each refresh).

Done when: the README section "A release follows the provider" names the trade-off and the config check (or
`docs/OPERATIONS.md`) says what to set when the provider session is shorter than `oidc_revalidate_minutes`.
