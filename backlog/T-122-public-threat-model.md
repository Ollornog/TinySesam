---
id: T-122
type: Task
title: "A short public threat model"
status: offen
milestone: M-6
blocked_by: [T-112]
tags: [security, docs]
created: 2026-11-23
---
# T-122 — A short public threat model

**Story points:** 3 · **Estimate:** 4–6 h · **Milestone:** [M-6](M-6-trust-hardening-and-launch.md)

Operators and reviewers need one page that says what TinySesam defends against and what it does not.

## Content
- Attackers (network, a user, a compromised application, a writer to the database file, a malicious identity
  provider, a compromised proxy), trust boundaries (browser, proxy, application, TinySesam, identity provider,
  database, key files), what TinySesam promises and what it explicitly leaves to the operator or the application.
- Built from what exists (`SECURITY.md`, the threat notes of the concept for shell and headless, the ADRs), not new
  claims; every promise links to the test that holds it.
- `docs/threat-model.md` plus a summary in `SECURITY.md`, English and German.

## Acceptance
- Every promise on the page has a test reference; the hygiene test checks the links; until an independent review
  ([T-123](T-123-independent-review-external-penetration-test-or-human.md)) the README says "hardened, not
  independently reviewed".
