---
id: T-5
type: Task
title: Abbild-Signatur und SBOM erwägen
status: offen
milestone: M-1
tags: [release, supply-chain, container]
created: 2026-07-10
---

# T-5 — Abbild-Signatur / SBOM

Ein Digest belegt **Unverändertheit**, aber nicht **Herkunft**. `cosign` plus Provenance-Attestation
würde die Lücke schließen.

**Erst sinnvoll, wenn Fremde das Abbild produktiv einsetzen** — vorher ist es Zeremonie ohne
Publikum. Vor 1.0 bewerten, nicht vorher bauen.
