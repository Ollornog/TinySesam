---
type: Task
title: Sprint lane runs a client's tests when spec/ or that client changes
status: erledigt
points: 3
id: T-150
milestone: M-2
created: '2026-11-28'
---
# T-150 — Sprint lane runs a client's tests when spec/ or that client changes

**Story points:** 3

In the sprint lane `scripts/_nur_text.sh` reports SPRINT LANE, `classify` sets `nur_text=ja` and every job of client-js, client-rust, client-php and client-go is skipped (their `*-ok` jobs count that as green); the pre-push stages run only rustfmt for Rust, biome for JS and nothing for PHP. The closing PR of sprint S7 was red at the clients' HTTP tests for that reason. Run at least the vector and HTTP tests of a client when `spec/` or `clients/<x>/` changes in a sprint PR. Like T-139 it saves the second round of the closing PR.
