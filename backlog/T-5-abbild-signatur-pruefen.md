---
id: T-5
type: Task
title: Abbild-Signatur und SBOM erwägen
status: erledigt
milestone: M-1
tags: [release, supply-chain, container]
created: 2026-07-10
---

# T-5 — Abbild-Signatur / SBOM

Ein Digest belegt **Unverändertheit**, aber nicht **Herkunft**. `cosign` plus Provenance-Attestation
würde die Lücke schließen.

**Erst sinnvoll, wenn Fremde das Abbild produktiv einsetzen** — vorher ist es Zeremonie ohne
Publikum. Vor 1.0 bewerten, nicht vorher bauen.

## Erledigt (2026-09-19)

Vorgezogen auf Entscheidung des Projektinhabers. Die Einschätzung oben bleibt stehen: Sie war der
Grund fürs Warten, nicht ein Argument dagegen — und der Aufwand fiel kleiner aus als gedacht, weil
es ohne eigene Schlüssel geht.

Umgesetzt im Release-Workflow, für **beide** Artefaktarten (Abbild wie Wheel/sdist):

- **Herkunft:** `actions/attest-build-provenance` erzeugt eine über Sigstore signierte Attestation.
  Signiert wird mit der OIDC-Identität des Workflows — kein Schlüssel, den man herausgeben, und
  keiner, den man verlieren kann. Die Attestation des Abbilds landet zusätzlich in der Registry
  (`push-to-registry`), ist also auch ohne dieses Repo prüfbar.
- **SBOM:** aus dem **geschobenen** Abbild erzeugt (per Digest), nicht aus dem Bauverzeichnis —
  sonst beschriebe sie etwas anderes als das Ausgelieferte. Ebenfalls beglaubigt.
- BuildKits eigene Provenance bleibt aus: Sie ist **unsigniert** und belegt damit genau das nicht,
  worum es hier geht.
- Die Rechte wandern vom Workflow in die einzelnen Jobs (`contents: read` global), damit
  `id-token`/`attestations` nur dort gelten, wo sie gebraucht werden.

Geprüft wird beim nächsten Release — vorher gibt es kein Artefakt, an dem sich das zeigen liesse.
Der Befehl steht in beiden READMEs: `gh attestation verify … --owner Ollornog`.
