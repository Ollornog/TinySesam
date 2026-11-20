---
id: T-59
type: Task
title: Gateway image on a slimmer or distroless base, with only the dependencies it needs
status: offen
milestone: M-2
tags: [docker, supply-chain, gateway]
created: '2026-11-20'
---
# T-59 — Gateway image on a slimmer or distroless base, with only the dependencies it needs

Goal: less noise in the supply chain. Most CVEs the image scan (Grype, T-42) reports come from the
Debian packages of the base image, not from TinySesam — the current example is the zlib exception
for `python:3.15-slim` in `.grype.yaml`. Each one costs an exception with an expiry date, or a red
`image-probe` on every PR until the base image is rebuilt.

Background: the discussion about a Go rewrite (2026-11-20). Until a real Go migration (T-28) this is
the cheaper lever — it shrinks the attack surface of the running image without touching the code.

## To do

1. **Measure the starting point:** package count, image size and Grype findings (all severities) of
   the current runtime stage.
2. **Compare candidate bases**, each pinned by digest like today, on: Python version matches
   `requires-python` and the CI matrix; glibc vs. musl (wheels for `cryptography`, `argon2-cffi`,
   `pydantic-core` and friends available, no compiler in the runtime stage); who rebuilds the base and
   how fast after a CVE; whether a version can be pinned without a paid plan; licence; whether
   Dependabot can bump it. Candidates, not a preselection: distroless Python, Chainguard/Wolfi Python,
   `python:3.15-alpine`, a slim multi-stage build that copies only the interpreter and the venv onto
   a minimal base.
3. **Check what the core image really needs:** the image installs the `[gateway]` extra (= `[oidc]`
   plus the ASGI server). List every runtime dependency with the reason it is there; drop what the
   gateway path never imports (measure with an import trace of the running gateway, not by reading).
   No change to the extras for library users without a CHANGELOG entry.
4. **No shell or package manager in the runtime stage** if the chosen base allows it. Then
   `HEALTHCHECK`, the documented operator commands (`tinysesam backup`, `unlock`, …) and the
   fail2ban log path must still work — adapt `docs/OPERATIONS.md` and the deploy templates.
5. Keep the existing guarantees: non-root user, reproducible build (`rewrite-timestamp`), SBOM,
   attestation, multi-arch, `image-probe` and `rehearsal` green.

## Done when

The image runs on the new base in the CI jobs `image-probe`, `rehearsal` and `gate-caddy`; the
measurement (before/after: packages, size, Grype findings) is in this entry; the `.grype.yaml`
exceptions that only existed because of the old base are gone; README/OPERATIONS name the new base
and how to get a shell for debugging if the image no longer has one.
