---
id: T-28
type: Task
title: Examine a Go variant — a small gate client instead of a complete rewrite
status: offen
milestone: M-2
tags: [go, gate, gateway]
created: 2026-10-28
---

# T-28 — Examine a Go variant: a small gate client instead of a complete rewrite

A complete rewrite in Go is not worth it: about 26k lines of code, about 40k lines of tests and grown hardening;
TinySesam is a mountable FastAPI module, and Go has no counterpart for that. What does make sense, if there is demand:
a small Go package as a **gate client** (check the token, redirect, cookie) against the existing gateway operating mode,
without a login UI. A complete Go TinySesam only once the majority of the apps that use it are written in Go. Until
then, keep maintaining the Python code unchanged.

## Decision 2026-10-29 — deferred

The item stays `status: offen` in milestone M-2. Decided with the product owner:

- **No permanent parallel Python + Go gateway.** That would be two security-critical implementations of the same
  contract: every fix twice, and the two drift apart (contract drift) because the second one is never the one the
  suites were written against.
- **No complete rewrite now.** The gateway is the FastAPI module run standalone, and the whole login surface lives
  there: login UI, passkey, OIDC, SAML, LDAP, TOTP. The part that runs on **every request** is already Go: the
  per-request check happens in Caddy via caddy-jwt (`deploy/forward-auth/Caddyfile.gate`, ADR-9). Python is only
  involved at sign-in and in the callback. A rewrite would replace the part that is not on the hot path.
- **A Go gate client (library) when Go apps need it.** A small package that checks the gate token, redirects and
  sets the cookie against the existing gateway — without a login UI. Built on demand, not on spec.
- **A complete Go port only once few Python apps remain.** Then as a migration with a time-boxed parallel phase: the
  same database schema, the Go gateway has to pass the existing gate suites unchanged, and the Python gateway is
  deprecated afterwards. Until then the Python code is maintained as it is.
