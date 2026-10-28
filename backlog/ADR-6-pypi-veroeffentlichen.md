---
id: ADR-6
type: Decision
title: TinySesam is published on PyPI from 1.0
status: erledigt
supersedes: ADR-1
tags: [release, supply-chain, pypi]
created: 2026-09-21
---

# ADR-6 — TinySesam is published on PyPI from 1.0

## Context

[ADR-1](ADR-1-pypi-vertagt.md) **deferred** publication until 1.0, it did not reject it. With
this release the condition is met. The way here led through installation from Git:

```
tinysesam[oidc] @ git+https://github.com/Ollornog/TinySesam.git@v0.17.0
```

That works, but costs everyone who includes it something: `git` must be on the build machine
(not a given in slim images), resolving second-order dependencies
is awkward, `pip index`/`pip download` do not know the package, and tools that
report updates see no new version. With three of our own applications that was bearable;
as the standard sign-in layer for more of them it is friction that repeats with every
inclusion.

## Options

1. **Stay with Git.** No new distribution channel, no new account, no irrevocable version.
2. **Publish on PyPI, with an API token in the repo.** The usual way, one more secret.
3. **Publish on PyPI, via Trusted Publishing.** PyPI trusts the release workflow through
   its OIDC identity; there is no token.

## Decision

**(3) — publish, via Trusted Publishing, triggered solely by a Git tag.**

## Rationale

- **The concern from ADR-1 has not gone away, it has been answered.** "The API is still moving"
  was an accurate observation in 2026-07, but not a measurable state: two releases in a row broke,
  and both times it was noticed only while writing the CHANGELOG. Since 0.16.0,
  `tests/test_api_surface.py` pins the surface (231 names) and separates **breakage** from
  **extension**. An irrevocable version is justifiable when a breakage can no longer
  happen unnoticed.
- **An auth package remains a supply-chain target — hence no token.** The objection from ADR-1 holds
  unchanged. An API token would be a secret that sits in the repo, has to be rotated and
  can be pulled out of a run by someone. Trusted Publishing has none: PyPI checks the
  workflow's OIDC identity (owner, repo, workflow file, environment) and then issues a
  short-lived token. In addition, every file carries a PEP 740 attestation — whoever pulls the wheel can
  check which commit it was built from.
- **Nothing rolls out automatically.** The upload is triggered by a tag that a human sets. That
  is the same separation as for rollout: delivery, not deployment. The `pypi` environment is
  the place where a second pair of hands can be interposed if needed.
- **The Git route stays.** Whoever pins by tag today does not have to change anything. PyPI is added, it
  replaces nothing.

## Consequences

- Installation: `pip install "tinysesam[all]==X.Y.Z"`. "From 1.0" was the plan; in fact
  every tag goes to PyPI — since **0.19.0** (2026-09-22). The READMEs still said "not on PyPI"
  until 2026-09-27, and a guard in `tests/test_repo.py` enforced that; both are corrected.
- The lock `Private :: Do Not Upload` is removed from `pyproject.toml`; `tests/test_packaging.py`
  makes sure it does not come back — and that wheel and sdist are complete. A wheel
  missing a file installs cleanly and is only noticed by the user.
- **Every published version is final.** A yanked version does not release its number;
  a mistake costs a new number, not a rollback.
- **One-time setup on pypi.org** before the first tag is pushed — the exact fields are in the
  header of [`.github/workflows/release.yml`](../.github/workflows/release.yml), so that they
  sit where someone looks for them at release time: a "pending publisher" for `tinysesam` with owner
  `Ollornog`, repository `TinySesam`, workflow `release.yml`, environment `pypi`, plus an
  environment of the same name in the repo settings.
- The package name `tinysesam` was free on 2026-09-21 (`https://pypi.org/pypi/tinysesam/json` → 404).
  It stays free only until the first upload — by whoever.
