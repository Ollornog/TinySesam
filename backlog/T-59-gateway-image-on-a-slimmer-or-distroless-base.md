---
id: T-59
type: Task
title: Gateway image on a slimmer or distroless base, with only the dependencies it needs
status: erledigt
milestone: M-5
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

## Done (2026-11-20)

**Chosen:** runtime stage `gcr.io/distroless/base-debian13:nonroot` (pinned by digest), the Python 3.15 interpreter
from the existing `python:3.15-slim` build stage on top, plus the five Debian libraries the trace needs that the base
lacks — each with its dpkg record (`status.d/<package>` + `.md5sums`), so SBOM and Grype see them. No shell, no package
manager, no coreutils, no pip. uid/gid 1000, `/data`, `HEALTHCHECK` (exec form), entrypoint and security-log path
unchanged. `deploy/gateway/image_setup.py` runs in the runtime stage (exec-form RUN, bind-mounted): account, and red
if a native module does not load, the TLS context has no CAs, or a shell/package manager/pip is on disk.
`image-probe` also checks that the running container cannot start `sh`.

### Before/after (same day, same tools: Syft 1.54.0, Grype 0.120.0, all severities, amd64)

| | before: `python:3.15-slim` runtime | after: distroless runtime |
|---|---|---|
| packages | 114 (Debian 88, Python 25, binary 1) | 41 (Debian 15, Python 25, binary 1) |
| image size | 265.6 MB | 147.6 MB |
| Grype findings (matches) | 236 — high 81, medium 85, low 20, negligible 50 | 67 — high 15, medium 32, low 9, negligible 11 |
| distinct CVEs | 107 | 67 |
| with a fix | 9 — high 1 (zlib, the `.grype.yaml` exception), medium 5, low 2, negligible 1 | 7 — medium 4, low 2, negligible 1 (all the interpreter, "fixed in 3.16") |
| gate (fixable ≥ high) | 1, only green through the exception | 0, no exception |

Left after: libc6 28, libsqlite3-0 14, libssl3t64 10, libgcc-s1 7, python 7, libbz2-1.0 1 — none fixable at high.

### Candidates (bare base images, measured 2026-11-20)

| candidate | Python | libc | packages | size | Grype (crit/high/med/low/negl) | fixable | rebuilt by / pin / licence / Dependabot | verdict |
|---|---|---|---|---|---|---|---|---|
| `python:3.15-slim` (before) | 3.15.2 | glibc | 96 (88 deb) | 182 MB | 236 (0/81/85/20/50) | 9 (1 high) | Docker official images, on Python releases — digest of 2026-11-05 still without the zlib fix of 11-07 / tag + digest / PSF + Debian / yes | the problem |
| `python:3.15-alpine` | 3.15.2 | musl | 41 (33 apk) | 81 MB | 32 (1/12/15/3/1) | 18 (1 crit, 8 high) | same rebuild rhythm, so the same stale-digest problem — here with a fixable critical / tag + digest / yes; musllinux wheels exist for cryptography, cffi, pydantic-core; busybox shell + apk stay unless stripped | rejected |
| `gcr.io/distroless/python3-debian13` | **3.13** (Debian's) | glibc | 38 deb | 91 MB | 324 (4/78/130/31/57, 24 unknown) | 0 | Google, on Debian updates / floating tags only (`latest`, `nonroot`, `debug…`) + digest / Apache-2.0 / digest refresh | rejected: not the newest stable Python, and Debian's python3.13 carries the open findings |
| Chainguard `chainguard/python:latest` | 3.15.x | glibc (Wolfi) | 30 apk | 106 MB | 8 (0/0/4/3/1) | 0 | Chainguard, daily / **free tier: `latest` only** — versioned tags need a paid plan, `latest` jumps minors silently / Apache-2.0 / digest of `latest` | rejected: no version pin without paying |
| Docker Hardened Images (`python`) | — | — | — | — | not measured | — | free (Apache-2.0) since 2025-12, but every pull needs a `docker login` to Docker's hardened-image registry — fork PRs, Dependabot and anyone building the Dockerfile would need credentials | rejected |
| `gcr.io/distroless/cc-debian13` | (none) | glibc | 14 deb | 43 MB | 66 (0/18/28/9/11) | 0 | Google / as above | not needed: brings libstdc++ and libgomp; only libgcc_s is used |
| **`gcr.io/distroless/base-debian13`** + interpreter from slim | 3.15.2 | glibc | 10 deb | 38 MB | 38 (0/10/16/5/7) | 0 | Google, on Debian updates (it already had zlib `+deb13u1`) / floating `nonroot` + digest; Dependabot refreshes the digest (non-version tag: digest-only, cooldown fails open outside Docker Hub — dependabot-core `docker/update_checker.rb`) / Apache-2.0 | **chosen** |

The interpreter still comes from `python:3.15-slim` (build stage): Python CVEs keep arriving with that digest, Debian
library fixes now with the distroless digest.

### What the core image needs (import trace of the running gateway)

Measured with a `sitecustomize` that dumped `sys.modules` and the mapped shared objects at exit: the gateway under
uvicorn through health, sign-in page, a full OIDC round trip against a stand-in provider (discovery, PKCE, token,
JWKS, userinfo), forward-auth with and without session, gate JWKS, OAuth metadata, `/auth/me`, sessions, logout; and
the operator commands `backup`, `unlock`, `keys list`, `audit`, `gc`. Same trace on the new image: identical module
set except `_uuid` (left out on purpose, `uuid` falls back).

Shared objects beyond the base: libsqlite3 (`sqlite3`), libmpdec (`decimal`, via pydantic), libbz2 and liblzma
(`bz2`/`lzma`, imported by `shutil` and `zipfile`), libgcc_s (Rust part of `cryptography`). Not loaded and not shipped:
libffi (`ctypes`; cffi brings its own), ncurses/readline, gdbm/libdb, tk, libuuid.

Python distributions (all from the hashed lock list, `[gateway]` = core + `httpx`, `authlib`, `uvicorn`):

| distribution | why it is there | imported by the gateway |
|---|---|---|
| fastapi, starlette, pydantic, pydantic-core, python-multipart, cryptography, pyotp | core requirements of TinySesam | yes |
| httpx, authlib, uvicorn | the `[gateway]` extra | yes |
| anyio, h11, httpcore, idna, certifi | httpx / uvicorn | yes |
| annotated-doc, opentelemetry-api | fastapi | yes |
| annotated-types, typing-inspection, typing-extensions | pydantic | yes |
| click | uvicorn (imported by `uvicorn.main` on import) | yes |
| cffi | cryptography (`_cffi_backend`) | yes |
| joserfc | authlib (requirement; the gateway uses `authlib.jose`) | **no** |
| pycparser | cffi (only for compiling cdefs) | **no** |
| setuptools | build backend for the own package | uninstalled in the build stage |

23 of 25 are imported. joserfc and pycparser stay: both are declared requirements of packages that are imported,
dropping them would break `pip check` in the build (the guard against #126), a future authlib that imports joserfc
would then only break at the first sign-in — and neither has a finding. No change to the extras.

### Also

- `.grype.yaml`: the zlib exception is gone (the base has the fix). `scripts/_grype_exceptions.py --report` runs after
  both image scans (`if: always()`), prints the findings and fails on an exception that matches nothing in either image.
- `docs/OPERATIONS.md`, "The gateway image: no shell inside": what changes for operators, the debug side-car
  (`docker run --pid/--network/--volumes-from container:<c> busybox sh`), reading the claim token with `python -c`.
- Mutations (all red, all restored): shell-form RUN / slim instead of distroless / ensurepip kept / probe without the
  `sh` check / `sh` not in FORBIDDEN (test_repo); libsqlite3 left out, venv pip kept, busybox as `/bin/sh`, empty CA
  bundle, ensurepip kept, lib-dynload looked up via `platstdlib` (image build); `sh` slipping past the build check
  (image-probe red); orphan check off, missing report counted as clean (test_security_doc).
- arm64 is built by the `image` job (dry run on every PR); no local emulation was available.
