---
id: T-118
type: Task
title: "Grype exception for libc6 expires on 2026-11-28 — rebuild the base images or drop it"
status: erledigt
milestone: M-5
tags: [supply-chain, images, deadline]
created: 2026-11-23
---
# T-118 — Grype exception for libc6 expires on 2026-11-28 — rebuild the base images or drop it

**Story points:** 1 · **Estimate:** 1–2 h · **Deadline:** 2026-11-28 · **Milestone:** [M-5](M-5-after-1-0.md)

`.grype.yaml` accepts CVE-2026-19499 and its sibling in `libc6` until 2026-11-28 (Debian fixed them in
2.41-12+deb13u5; the pinned base images were not rebuilt yet). The rule expires technically: after the date the image
scan turns red.

## Content
- Bump the pinned digests of the Python and distroless bases once rebuilt images carry the fixed `libc6` (an open
  Dependabot pull request may already do it), then remove both rules.
- If the bases are still not rebuilt: a new, dated decision by the maintainer, not a silent extension.

## Acceptance
- Image scan green without the two rules, or a new dated rule with the maintainer's decision in the comment.
