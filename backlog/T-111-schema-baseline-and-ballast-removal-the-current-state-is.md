---
id: T-111
type: Task
title: "Schema baseline and ballast removal: the current state is the starting line"
status: erledigt
milestone: M-1
blocked_by: [B-16]
tags: [cleanup, store, migrations, greenfield]
created: 2026-11-23
---
# T-111 — Schema baseline and ballast removal

**Story points:** 8 · **Estimate:** 12–18 h (not measured) · **Milestone:** [M-1](M-1-clean-baseline-and-modules-before-shell-and-headless.md)

**Decision (maintainer, 2026-11-23):** the project is greenfield with next to no users. The current state is the
baseline; everything that only exists for older states goes. No upgrade path from old versions: whoever runs an older
version first updates to the **last release with migrations** (named in the CHANGELOG), then to the baseline release.

## Content

- **Schema baseline.** `Store` creates today's schema (version 26 at the time of writing) in one script. The step-by-step
  `_migrate` chain, `_english_names`, the vocabulary migration and every `if present_beforehand < N` branch are removed.
  A database below the baseline is refused at start with a clear message that names the last release with
  migrations ("update to X first") — never a silent partial upgrade.
- **Read paths for old values.** `_vocabulary.py` (German audit names up to 0.24.x on every read path), the old
  spellings in `recent_audit`, `own_events`, the panel and `tinysesam audit` — gone; the audit and security log keep
  only the English form.
- **Key and vault legacy.** The derived key material up to 0.25.x (`gate.derive_key_name`, `keys.load_stored(...,
  legacy=…)`, `DERIVED_V1`, vault format `v1`, `keys reencrypt --format v1`, the `legacy` source of a keyring). The
  baseline release refuses a database that still holds `v1` values and says which command of the last release with
  migrations re-encrypts them.
- **Tier-C aliases.** `tinysesam/_deprecated.py` and its 38 aliases, the warning filter in `tests/run_all.py`, the
  1.0 guard that waits for them (tier C falls with 1.0 anyway; [M-4](M-4-api-stable-1-0.md)).
- **Session-handle rewrite** of T-71 (`Store.pepper_session_handles`) — with no old rows, the rewrite is only the last
  way in for a writer ([T-72](T-72-pepper-for-the-remaining-token-digests.md)).
- **Old configuration names and switches** that only exist for older states (inventory first: every field, CLI option
  and environment variable whose docstring says "up to 0.x" or "for going back"); the CHANGELOG lists each removal.
- Tests that only prove a migration from an old file (`tests/test_db_names_migration.py` and similar) are removed;
  what they protected that still matters moves into a test against a fresh database.
- The rule for later schema changes is rewritten (`AGENTS.md` pitfalls, `CONTRIBUTING.md`): a change after the
  baseline needs one migration step from the baseline and a test with a baseline database — not from older files.

## Acceptance

- A fresh database is created in one step and equals the schema the last release with migrations reaches (a test
  compares `sqlite_master` of both, generated in CI from the tag).
- A database below the baseline, and one with `v1` vault values, is refused with the message above (test).
- `grep` over `tinysesam/` finds no `_migrate`, `_vocabulary`, `_deprecated`, `DERIVED_V1`, `pepper_session_handles`;
  `tests/api_surface.json` changes only in tier C (the removed aliases).
- Suite green; mutation proof for the refusal rules; CHANGELOG with the last release with migrations and the list of
  removed names; `docs/OPERATIONS.md` "Updating" says the two-step rule.

## Done (2026-11-24)

- `Store` creates schema 26 in one transaction (`SCHEMA`, `Store.INDEXES`, triggers, stamp); `_refuse_below_baseline`
  refuses a TinySesam database below 26 before anything is written and names 0.30.0 (`Store.LAST_MIGRATING_RELEASE`).
- Gone: the migration chain, `_vocabulary.py`, `_deprecated.py` with its 38 aliases and the warning filter of
  `tests/run_all.py`, the derived key material (`gate.derive_key_name`, `oauth.derive_pepper`, `keys.DERIVED_V1`, the
  `legacy` parameters), vault format `v1` (`encrypt_v1`, `reencrypt --to v1`), `Store.pepper_session_handles`.
- Refused at start with the way out: secrets not in `v2` (re-encrypt with 0.30.0), a `derived-v1` gate key or pepper
  (`tinysesam keys retire`, the command is in the message).
- Kept on purpose (not tied to an old version): the trigger comparison, the bucket back-fill of foreign writers, the
  owner catch-up for admins created by own code. Configuration fields whose docs mention an old default were left as
  they are — they are options, not switches for old states.
- `tests/test_schema_baseline.py` compares a fresh database with `tests/fixtures/schema_baseline.json` (generated from
  v0.30.0; regenerated from the tag where the clone has it — the CI checkout is shallow, so there it compares with the
  committed file).
