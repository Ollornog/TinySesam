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
