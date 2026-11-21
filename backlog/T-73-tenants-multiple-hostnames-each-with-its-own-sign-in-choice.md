---
id: T-73
type: Task
title: Tenants — multiple hostnames, each with its own sign-in choice
status: offen
milestone: M-2
tags: [idea, tenants, gate, forward-auth, proposal]
created: '2026-11-21'
---
# T-73 — tenants: multiple hostnames, each with its own sign-in choice

**Status: proposal, an idea.** No decision has been made; the maintainer is still thinking about it. Nothing here is
planned work until it becomes a decision (ADR).

Source: a public Go application that wants to ship TinySesam as its bundled gate — for single users as well as for
hosters who run one instance for many customers. Its own design notes ("tenants and sign-in") would rather put the
tenant topic into TinySesam as a feature than build it twice.

## What it would mean

- **A tenant is found by its hostname** — a subdomain of the hoster, optionally a domain of its own. No paths: a
  hostname keeps cookies and the CSP apart, a path would not.
- **Sign-in choice per tenant:**
  - passkey (the default), password + TOTP, password only;
  - OIDC with the tenant's own provider — the client secret per tenant, encrypted in the vault;
  - registration per tenant on or off, otherwise by invitation.
- **Admins per tenant, and a hoster admin.** Every tenant has its own admins. A hoster admin manages tenants only:
  create, lock, delete, set the account quota. They see no content and no account secrets.
- **Strict separation.** Account, passkey (RP ID = the tenant's hostname), session, audit log and throttle belong to
  the tenant. An account of one tenant never opens another.
- **The tenant in the gate header.** The gate passes the tenant on to the application, signed, like user and groups
  (gate token, ADR-9). The application trusts only this header.
- **Single-tenant mode is the default**, and in it nothing about tenants is visible.

## Open questions

- Data model: a `tenant` column on every table versus one database per tenant.
- Interplay with forward-auth cookies per host, the OAuth authorization server (an issuer per tenant), SAML and LDAP,
  and the rate-limit keys.
- Migration path for existing single-tenant installations.
