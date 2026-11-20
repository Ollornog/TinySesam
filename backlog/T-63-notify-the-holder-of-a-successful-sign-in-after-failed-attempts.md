---
id: T-63
type: Task
title: 'Notify the holder of a successful sign-in after failed attempts'
status: offen
milestone: M-2
tags: [security, notification]
created: '2026-11-20'
---
# T-63 — Notify the holder of a successful sign-in after failed attempts

Source: rest of T-47 (security review 2026-11-20, finding N2 — ASVS 6.3.5/6.3.7 L3). H2 built the events for new
access; this third one was left out of the H2 scope.

**Is:** failed attempts and the later sign-in appear in the account page's "Recent activity", but no event and no
mail says "someone signed in after N failed attempts".

**Proposal:** count the account's failed attempts before `lift_lockout` clears them at a complete sign-in (careful:
`_record_login` already clears those of the same method on success — count before that), event
`signed_in_after_failures` (`failures`, `ip`), mail via `notify_new_access` (or its own switch). Effort S.
