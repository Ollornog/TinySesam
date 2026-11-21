---
id: T-55
type: Task
title: 'SLSA Build L3 and an SBOM for wheel and sdist'
status: erledigt
milestone: M-2
tags: [supply-chain, release]
created: '2026-11-20'
---
# T-55 — SLSA Build L3 and an SBOM for wheel and sdist

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), supply-chain table — SLSA v1.1 Build L3; SBOM ⚠️.

**Is:** provenance via Sigstore from the own workflow (Build L2); SBOM only for the image.

**Proposal:** an isolated, reusable builder (`slsa-github-generator` or a reusable workflow) for wheel, sdist and image;
an SBOM for wheel/sdist. Low priority. Effort M.

## Done (2026-11-21)

- Reusable workflow `.github/workflows/build-provenance.yml`, called by `release.yml` (job `provenance`): `rebuild`
  (no write permission) builds wheel and sdist with the same recipe as `build` (tests/test_repo.py compares the blocks),
  checks the bytes against `build`'s `SHA256SUMS`, installs the wheel with its dependencies into an empty directory
  (wheels only) and lets Syft describe it (SPDX, same tool and version as for the images); `attest` (only for a tag,
  no checkout, no pip) attests provenance and SBOM for both files. GitHub's documented path to SLSA v1 Build L3 with
  artifact attestations: the reusable workflow builds and signs, the verifier pins it with `--signer-workflow`.
- `release.yml` `release` no longer attests (only `contents: write`) and attaches `tinysesam-sbom.spdx.json`.
- Image: unchanged (provenance + SBOM via `image-attest`, signer `release.yml`); moving the image build into a
  reusable workflow as well is possible but not needed for the library's L3 claim — left open.
- Verification in README (en/de) and in the header of `release.yml`.
- The reusable workflow lives in the same repository; a separate repository would also take it out of reach of
  whoever can push here — not done (GitHub does not require it for L3).
