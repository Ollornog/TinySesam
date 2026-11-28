---
type: Task
title: 'Admin overview: fewer queries and paging'
status: offen
points: 2
id: T-167
milestone: M-5
created: '2026-11-28'
---
# T-167 — Admin overview: fewer queries and paging

**Story points:** 2

Follow-up of T-106. /.tinysesam/admin/accounts.json asks the database about five times per account. Batch the queries and add paging for large instances (spec section 8b). Acceptance: query count independent of the number of accounts; paging vectors.
