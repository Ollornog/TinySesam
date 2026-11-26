---
id: M-1
type: Milestone
title: "Clean baseline and modules — before shell and headless continue"
status: offen
rank: 1
tags: [cleanup, modules, greenfield, roadmap]
created: 2026-11-23
---
# M-1 — Clean baseline and modules

**Done when (measured):**

- **Baseline:** a fresh database is created in one step and equals the schema of the last release with migrations
  (test); no migration chain, no vocabulary or key-legacy read path, no `_deprecated.py` left in `tinysesam/`
  ([T-111](T-111-schema-baseline-and-ballast-removal-the-current-state-is.md)).
- **Modules:** `manager.py` and `store.py` each below 1,500 lines, no module in `tinysesam/` above 2,000 lines; a test
  proves for every feature that, switched off, it registers no route and its module is not imported after start and a
  first request ([T-112](T-112-modules-split-manager-py-and-store-py-into-one-building.md)).
- `tests/api_surface.json`: tiers A and B unchanged; only the tier-C aliases are gone.
- The remaining token digests are keyed with the pepper ([T-72](T-72-pepper-for-the-remaining-token-digests.md)).
- `nightly-repeat` green after the last merge.

**Why first (maintainer, 2026-11-23):** greenfield with next to no users — the current state is the baseline, ballast
for older states goes. And modules before [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md): its
first server stage ([T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md)) decides from the
configuration what is loaded; that only works once every feature is a building block of its own.

## Order

[B-16](B-16-the-sql-check-of-test-english-code-goes-blind-afte.md) (the guard must see the new schema script) →
T-111 → T-72 and T-112 (T-72 is small and touches the store; do it before or right after the split) → T-97 (M-2).
[T-96](T-96-stage-s0-documentation-of-the-grid-surfaces-origins-dep.md) (documentation only) can run alongside.

**State 2026-11-26:** B-16, T-111, T-72 and T-112 are done, and recovery codes and the gate code exchange are keyed
with the pepper as well. `nightly-repeat` is green after the last merge. Left: [T-127](T-127-compare-the-schema-baseline-with-the-tag-in-ci.md)
(the baseline test against the tag), then [T-126](T-126-breaking-release-after-the-baseline-with-an-upgrade-list.md)
(one breaking release with the upgrade list). Operators retire their `derived-v1` gate keys on 0.30.x before it.
M-1 is done once that release is out.

## Tasks

| Task | Title | SP | Hours |
|---|---|---|---|
| [B-16](B-16-the-sql-check-of-test-english-code-goes-blind-afte.md) | SQL check blind after an apostrophe | 1 | 2–3 |
| [T-111](T-111-schema-baseline-and-ballast-removal-the-current-state-is.md) | schema baseline and ballast removal | 8 | 12–18 |
| [T-72](T-72-pepper-for-the-remaining-token-digests.md) | pepper for the remaining token digests | 5 | 6–10 |
| [T-112](T-112-modules-split-manager-py-and-store-py-into-one-building.md) | modules: one building block per feature | 21 | 30–40 |
| [T-127](T-127-compare-the-schema-baseline-with-the-tag-in-ci.md) | baseline test against the tag in CI | 1 | 1–2 |
| [T-126](T-126-breaking-release-after-the-baseline-with-an-upgrade-list.md) | breaking release with one upgrade list | 3 | 3–5 |
| **Sum** | | see `dokutool offen` | |

Estimates, not measured (1 SP is about one pull request of 2–3 h).
