---
id: T-65
type: Task
title: 'AI guide: AGENTS.md for contributors and a skill for app builders'
status: erledigt
milestone: M-5
tags: [docs, ai, onboarding]
created: '2026-11-20'
---
# T-65 — AI guide: AGENTS.md for contributors and a skill for app builders

Source: PO question 2026-11-20 — does a skill in the repo make sense, so that a fresh AI quickly knows how to use the
repo? Yes, for two readers.

**Done:**

- **Contributors** (an agent changes TinySesam): `AGENTS.md` in the root — layout, tests (`scripts/check.sh`, suites,
  browser test, mutation), generated files, backlog, language, the repository's security rules, pitfalls.
  `AGENTS.md` is the cross-tool convention (read by many coding agents); `CLAUDE.md` only imports it (`@AGENTS.md`),
  the way Claude Code's documentation recommends: Claude Code reads `AGENTS.md` on its own only when there is no
  `CLAUDE.md` in the directory or above it, and the import makes it independent of that.
- **App builders** (an agent protects an app with TinySesam): `skills/tinysesam/SKILL.md` in the common Agent Skills
  format (front matter `name`, `description` with the trigger words). A signpost with recipes — FastAPI with mandatory
  TOTP, step-up, admin-created accounts with a sign-in link (T-34/T-33), API keys, forward-auth gate and the quickstart (T-62), app passwords (T-66), OAuth for MCP
  clients (T-36, ADR-11), home network (T-37/T-43), C22 look and the top bar (T-61, T-64) — and pitfalls; details
  stay in README, `CONFIGURATION.md`, `API.md` and `docs/`.
- **Where:** `skills/<name>/SKILL.md` is the plugin layout Claude Code loads by default, and the repo root is a plugin
  marketplace (`.claude-plugin/marketplace.json`, plugin source `./`): `/plugin marketplace add Ollornog/TinySesam`,
  `/plugin install tinysesam@tinysesam`. Other agents read the file directly. Both READMEs have a short section.
- **Against going stale** (`tests/test_repo.py`): every Python block of both files runs as a program (both stages of
  the README example guard, extended; a snippet is not allowed there), every dotted name is checked by the docs guard,
  and a new guard checks every other name in backticks — config fields and package words, `TINYSESAM_*` variables,
  `X-TinySesam-*` headers, routes against the measured HTTP surface, repo paths — plus front matter, the
  `CLAUDE.md` import, the marketplace entry and the install line. Self-probes and mutation anchors in the guard.

**Rebased onto** the Caddy quick start (T-62: recipe 6 starts with `deploy/quickstart/`), app passwords (T-66:
recipe 6a) and the key management (ADR-12: key backup and rotation in the pitfalls).
