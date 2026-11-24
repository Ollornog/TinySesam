---
id: T-125
type: Task
title: "Attestation retry in the tag jobs of release.yml (image, SBOM)"
status: erledigt
milestone: M-2
tags: [ci, release, supply-chain]
created: 2026-11-23
---
# T-125 — Attestation retry in the tag jobs

**Story points:** 1 · **Estimate:** 1–2 h · **Milestone:** [M-2](M-2-after-1-0.md)

The rehearsal job `rehearsal-attest` retries a failing attestation (three attempts, 20 s and 60 s pause, the last one
hard) since the Sigstore 404s of 2026-11-22; the CHANGELOG says "the tag jobs are unchanged". A Sigstore 404 at a real
tag would mean a rerun of the release run.

## Content
- The same three-attempt shape for the provenance and SBOM attestation of the image and the wheel in the tag jobs;
  the verify step stays unconditional.
- `tests/test_repo.py` pins the shape for the tag jobs as it does for the rehearsal.

## Acceptance
- The shape check covers every attestation step of `release.yml`; a removed retry turns it red (mutation).
