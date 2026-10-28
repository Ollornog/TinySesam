---
id: T-11
type: Task
title: zizmor excessive-permissions — already fixed when filed, entry stays as a lesson
status: erledigt
milestone: M-1
tags: [ci, sicherheit, workflows]
created: 2026-09-22
---

# T-11 — zizmor: `excessive-permissions` (moot)

**Filed and withdrawn on the same day.** The entry stays because the mistake is more instructive
than the alleged finding.

## What was claimed

During a cross-repo CI hardening on 2026-09-22 an agent reported that TinySesam was red with the
new gate (`actionlint` + `zizmor` in `ci-local`) — **2× `excessive-permissions`**. This became a
warning to the running session and this backlog item.

## What actually held

The findings were **already fixed** at that point: PR #53 (merged as `230b10e`, 01:40) carries
`pages:write`/`id-token:write` only in the deploy job of `pages.yml`. Re-measured against
`origin/main`:

```
zizmor --persona=regular  →  26 findings, davon 0 high, 0× excessive-permissions
```

The counter-measurement deliberately did **not** run in the working tree (an audit branch was
checked out there), but against the workflow files fetched from `origin/main` into a throwaway
directory.

## The lesson

**A finding ages.** Between measurement and report only a few hours lay here, and in that time the
cause was fixed in another PR. Anyone passing on someone else's finding measures it **against the
state afterwards** that it refers to — not against the one at which it arose. Second part of the
same lesson: the agent measured against a branch, not against `main`.

Same class as the false alarm `REPLACE_ME_TOKEN` on the same day: formally measured correctly,
wrong in substance.

## What remains of it

The second observation of the round is **real and independent of it**:
`~/.local/bin/ci-local` is a **symlink into a checkout-able working tree**. The local gate thus
depends on the currently checked-out state of `ci-infra` — the same commit was green at 01:31 and
red at 01:33. Anyone seeing an unexplained push failure here first checks what `ci-infra` is
currently checked out on. This is tracked in the tower register `context/pipeline-fehler.md`.
