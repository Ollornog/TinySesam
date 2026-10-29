---
id: ADR-7
type: Decision
title: TOTP secrets and PINs never come from the identity provider
status: erledigt
tags: [architektur, oidc, mfa, pocketid]
created: 2026-09-22
---

# ADR-7 — TOTP secrets and PINs never come from the identity provider

## Context

During the symbiosis audit with PocketID (2026-09-22) the question arose whether the second factor
can be maintained centrally in the identity provider (IdP): PocketID can give every user arbitrary
**custom claims**, and these claims appear in the ID token. Entering a `totp_secret` or a
`tinysesam_pin` there would at first glance be convenient — one place for all services,
no second enrollment, and switching authenticators would be a change in the IdP panel.

The question is legitimate because TinySesam sits behind PocketID in this installation and
user management lives there. It must nevertheless be answered with no, and for a reason
that has nothing to do with PocketID.

## Options

1. **Custom claim in the ID token.** The IdP carries the TOTP secret (or the PIN) as a claim,
   TinySesam reads it at login and checks the entered code against it.
2. **Retrieval via the IdP API.** TinySesam fetches the secret on demand through an API of the IdP
   instead of transporting it in the token.
3. **Factors stay local.** TinySesam manages TOTP and PIN itself; the IdP supplies
   identity, groups and approval — not secrets.

## Decision

**Option 3.** TOTP secrets and PINs stay in TinySesam's own database.

## Rationale

**A claim goes to every client, not to one.** In PocketID, custom claims attach to the user,
not to the OIDC client. A secret there therefore appears in the ID token of **every** application this user
signs in to — in this installation that is thirteen. The second factor would be known after
a single login to any one of them. What was meant as "one place for all"
is "a leak at every one".

**A second factor that the first one delivers is not one.** The ID token is the result of the
first factor. If the TOTP secret came along in it, whoever completes this sign-in flow
would immediately have the second factor too. Two factors must come from two sources, otherwise
they are one with two input fields.

**Option 2 does not solve this either.** Retrieval via the API narrows the circle of recipients, but the
secret then lies in two systems instead of one, and the question "who owns the factor" is
still unanswered. A TOTP secret is a *verification secret*: it belongs where
verification happens, and nowhere else. The same reasoning rules out mirroring it in the IdP.

**The division of labour stays clean.** The IdP answers: who is this, which groups is the user in,
may the user use this client. TinySesam answers: is that enough for this route, and which
additional proof do I require. That is the separation that ADR-5 (roles in forward auth) and
ADR-3 (in-app instead of proxy) also carry.

## Consequences

- Whoever uses TOTP or PIN sets them up **in TinySesam**. A second enrollment is the price,
  and it is the right one.
- The following still come from the IdP: identity (`sub`), email with `email_verified`, groups, and via the
  client approval the answer to whether this user may use this application at all
  (→ [T-14](T-14-multiple-oidc-clients.md)).
- **Not affected** is the question of whether TinySesam trusts an MFA performed in the IdP: that is
  a different decision (evaluating `amr`/`acr` in the token) and is not up for debate here.
- This ADR only answers where the **secrets** come from. That a user blocked or
  deleted in the IdP must be reflected promptly in TinySesam is a separate point
  (revocation gap, see T-13 and the symbiosis investigation).
