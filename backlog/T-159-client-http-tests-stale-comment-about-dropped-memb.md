---
type: Task
title: 'Client HTTP tests: stale comment about dropped members'
status: erledigt
points: 1
id: T-159
milestone: M-5
created: '2026-11-28'
---
# T-159 — Client HTTP tests: stale comment about dropped members

**Story points:** 1

Since T-148 input and expected are equal in the approval HTTP tests of the JS, Rust and PHP clients, so the comment 'members it does not normalize are dropped' is wrong there. Fix the comments the next time these tests are touched.

## Done (sprint S9, 2026-11-28, with T-161)

- The comment in JS `approval.test.ts`, Rust `tests/remote.rs` and PHP `ApprovalTest` now says what holds since T-161:
  input and expected of the vector `signed-in` are equal, the helper normalizes every member.
