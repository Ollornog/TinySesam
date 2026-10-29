---
id: T-5
type: Task
title: Consider image signature and SBOM
status: erledigt
milestone: M-1
tags: [release, supply-chain, container]
created: 2026-07-10
---

# T-5 — Image signature / SBOM

A digest proves **unchanged**, but not **origin**. `cosign` plus a provenance attestation would
close the gap.

**Only worth it once outsiders run the image in production** — before that it is ceremony without
an audience. Evaluate before 1.0, do not build earlier.

## Done (2026-09-19)

Brought forward on the project owner's decision. The assessment above stands: it was the reason
for waiting, not an argument against — and the effort turned out smaller than thought, because it
works without keys of our own.

Implemented in the release workflow, for **both** kinds of artifact (image as well as
wheel/sdist):

- **Provenance:** `actions/attest-build-provenance` produces an attestation signed via Sigstore.
  Signing uses the workflow's OIDC identity — no key to hand out and none to lose. The image's
  attestation also lands in the registry (`push-to-registry`), so it can be verified even without
  this repo.
- **SBOM:** generated from the **pushed** image (by digest), not from the build directory —
  otherwise it would describe something other than what is delivered. Also attested.
- BuildKit's own provenance stays off: it is **unsigned** and so does not prove exactly what this
  is about.
- Permissions move from the workflow into the individual jobs (`contents: read` globally), so that
  `id-token`/`attestations` apply only where they are needed.

Verified at the next release — until then there is no artifact on which this could be shown.
The command is in both READMEs: `gh attestation verify … --owner Ollornog`.
