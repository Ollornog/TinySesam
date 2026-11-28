---
type: Task
title: api_keys_active counts expired keys
status: offen
points: 1
id: T-164
milestone: M-5
created: '2026-11-28'
---
# T-164 — api_keys_active counts expired keys

**Story points:** 1

Follow-up of T-106. The account overview's api_keys_active counts keys past expires_at; the list follows it on purpose and an expired key shows by expires_at. Count only keys that are neither revoked nor expired, or rename the field. Acceptance: test with one expired key.
