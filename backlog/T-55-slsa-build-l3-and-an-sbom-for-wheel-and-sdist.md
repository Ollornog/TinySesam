---
id: T-55
type: Task
title: 'SLSA Build L3 and an SBOM for wheel and sdist'
status: offen
milestone: M-2
tags: [supply-chain, release]
created: '2026-11-20'
---
# T-55 — SLSA Build L3 and an SBOM for wheel and sdist

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), supply-chain table — SLSA v1.1 Build L3; SBOM ⚠️.

**Is:** provenance via Sigstore from the own workflow (Build L2); SBOM only for the image.

**Proposal:** an isolated, reusable builder (`slsa-github-generator` or a reusable workflow) for wheel, sdist and image;
an SBOM for wheel/sdist. Low priority. Effort M.
