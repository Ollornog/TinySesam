---
id: T-7
type: Task
title: "Switch the license declaration to the SPDX expression (deadline: 2027-02-18)"
status: erledigt
milestone: M-2
tags: [packaging, deadline]
created: 2026-09-21
---

# T-7 — Switch the license declaration to the SPDX expression

**The deadline is fixed:** setuptools reports during the build

> `project.license` as a TOML table is deprecated …
> By 2027-Feb-18, you need to update your project and remove deprecated calls
> or your builds will no longer be supported.

Two places in `pyproject.toml` are affected: `license = { text = "MIT" }` and the classifier
`License :: OSI Approved :: MIT License`. PEP 639 replaces both with

```toml
license = "MIT"
license-files = ["LICENSE"]
```

## Why it did not happen already in 2026-09

The SPDX expression requires **setuptools ≥ 77**. But builds are not only made with the newest:
`tests/test_packaging.py` builds wheel and sdist **offline and without build isolation**, i.e. with
the setuptools that happens to be in the given environment — in the local CI image that is an older
version, which rejects `license` as a string. The switch would break the suite there, and a suite
that is green only on paper would be the worse trade.

The published artifacts are built unaffected by this with the newest setuptools (`python -m
build` builds isolated) — so the metadata in the index is already the current one today
(Metadata 2.4).

## Done 2026-09-25

All environments in which builds are made bring setuptools ≥ 77 (CI image `ci-python-web`: 84,
GitHub jobs install the newest, the release builds isolated). Switched: `license = "MIT"`,
`license-files = ["LICENSE"]`, `build-system.requires = ["setuptools>=77"]`, license classifier
removed. `tests/test_packaging.py` checks `License-Expression` and `License-File`, rejects a
license classifier alongside, and aborts loudly with an older setuptools instead of cryptically.
The build no longer reports a deprecation. Mutations: different expression → red; classifier back →
the build itself rejects.

## Done when

1. The environments in which the suite runs bring setuptools ≥ 77.
2. `pyproject.toml` names `license = "MIT"` + `license-files`, the license classifier is gone.
3. `tests/test_packaging.py` keeps checking the license — now via `License-Expression` instead of
   the classifier — and is green in all environments.
4. The build no longer reports a deprecation.
