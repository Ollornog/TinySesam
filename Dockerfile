# TinySesam as an OIDC forward-auth gateway.
#
#   docker build -t tinysesam-gateway .
#   docker run --rm -p 8000:8000 -e TINYSESAM_OIDC_ISSUER=… tinysesam-gateway
#
# Ready-made images: ghcr.io/ollornog/tinysesam:<version>  (see .github/workflows/release.yml)
#
# Only the `[gateway]` extra (= `[oidc]` plus ASGI server). `[all]` would pull in `python3-saml` and
# with it the C library `libxmlsec1` — which would have to be compiled under emulation for arm64,
# for an extra the gateway does not use at all. Anyone who wants SAML builds TinySesam as a
# library into an app.
#
# Up to 0.18.0 this had `.[oidc]` plus a hand-appended `uvicorn>=0.30`. That patch was the
# reason why the image ran and a `pip install 'tinysesam[oidc]'` following the instructions did
# not: the server was missing from the extra, not from the image.

# ---------- Build ----------
# Pinned by DIGEST, not by tag: `python:3.15-slim` points here today and elsewhere
# tomorrow — two builds of the same commit would yield different images. To bump:
#   docker manifest inspect python:3.15-slim   (or Dependabot, see dependabot.yml)
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

# Install from the build context, NOT from the network: the image should contain exactly the
# state that lies next to it here — not whatever `main` happens to be right now.
WORKDIR /src
COPY pyproject.toml README.md ./
COPY deploy/gateway/requirements.txt ./requirements.txt
COPY tinysesam ./tinysesam

# The digest above pins only the base image — the other half of the question is what pip
# puts into it. Hence two steps instead of one `pip install ".[gateway]"`:
#   1. the dependencies from the hashed lock list, nothing else (`--require-hashes`); that is
#      also where setuptools sits, the build backend for step 2;
#   2. TinySesam itself without network (`--no-index`), without build isolation (which would
#      otherwise fetch setuptools unchecked from the index) and without dependency resolution.
# No more `pip install --upgrade pip`: that pulled the latest version on every build. The pip
# of the base image is fixed by the digest and is removed at the end anyway.
# `SOURCE_DATE_EPOCH` (set by the release workflow) makes the .pyc files timestamp-free.
#
# `--no-deps` also means: if a transitive dependency is missing from the lock list, pip installs
# anyway without complaint. Until 2026-10-10 Dependabot bumped the list line by line and did not add any new
# dependency (#126: fastapi 0.142 → opentelemetry-api) — an image that would only break at startup with
# ModuleNotFoundError. Since then it regenerates the list entirely (uv ecosystem); the probe stays. `pip check` and the import catch this at BUILD time;
# audit.yml runs the same steps on every PR, so that it does not even get as far as the release.
ARG SOURCE_DATE_EPOCH
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt \
    && /opt/venv/bin/pip install --no-cache-dir --no-deps --no-index --no-build-isolation . \
    && /opt/venv/bin/pip check \
    && /opt/venv/bin/python -c "import tinysesam.gateway" \
    && /opt/venv/bin/pip uninstall --yes setuptools

# What the runtime stage gets from here, collected under /rootfs (T-59). The runtime base has no Python, no shell and
# no package manager, so the interpreter of this stage moves over — and with it exactly the Debian libraries its
# modules need that the runtime base does not already have. Which ones was MEASURED, not read: an import trace of the
# running gateway (sign-in page, OIDC round trip against a stand-in provider, forward-auth, gate JWKS, OAuth metadata,
# logout) and of the operator commands (`backup`, `unlock`, `keys list`, `audit`, `gc`) mapped these shared objects
# beyond glibc, OpenSSL, zlib and zstd (which the base brings): libsqlite3 (sqlite3 — the database), libmpdec (decimal,
# via pydantic), libbz2 and liblzma (bz2/lzma, imported by shutil and zipfile), libgcc_s (the Rust part of
# `cryptography`).
#   * Each library comes WITH its dpkg record (status.d/<package> plus .md5sums, the layout of the base): the SBOM and
#     the Grype scan see every Debian package that is in the image, at its real version. Copying the .so alone would
#     hide them from the scan — fewer findings by looking away, not by having less.
#   * libuuid (util-linux) is left out on purpose: `uuid` has a built-in fallback when `_uuid` cannot load, and the
#     package carries util-linux's findings. Equally the stdlib modules whose library is not shipped — ctypes (libffi;
#     the gateway never imports it, cffi brings its own), curses, readline, dbm, tkinter — go with their .so, so that
#     nothing in the image points at a library that is not there. The runtime stage checks that every native module
#     left still loads (deploy/gateway/image_setup.py).
#   * pip goes, the system one, the bundled wheel (ensurepip) and the venv's own one: whoever can load code here has
#     won — that is why TinySesam has no self-update (CHANGELOG 0.12.0). Paths by pattern, not by series (#74: after
#     3.12 → 3.14 a fixed `python3.12` path no longer applied and pip was back).
# The libraries come from THIS digest-pinned stage, not from the network: same commit, same bytes.
RUN set -eu; \
    R=/rootfs; arch="$(dpkg --print-architecture)"; \
    mkdir -p "$R/usr/local/bin" "$R/usr/local/lib" "$R/var/lib/dpkg/status.d"; \
    cp -a /usr/local/bin/python /usr/local/bin/python3 /usr/local/bin/python3.* "$R/usr/local/bin/"; \
    rm -f "$R"/usr/local/bin/python3.*-config; \
    cp -a /usr/local/lib/libpython3*.so* /usr/local/lib/python3.* "$R/usr/local/lib/"; \
    cd "$R"/usr/local/lib/python3.*; \
    rm -rf site-packages/pip site-packages/pip-*.dist-info ensurepip idlelib tkinter turtledemo turtle.py config-3.*; \
    rm -f lib-dynload/_ctypes.* lib-dynload/_curses.* lib-dynload/_curses_panel.* lib-dynload/_dbm.* \
          lib-dynload/_gdbm.* lib-dynload/_tkinter.* lib-dynload/readline.* lib-dynload/_uuid.*; \
    cd /; \
    for p in libsqlite3-0 libmpdec4 libbz2-1.0 liblzma5 libgcc-s1; do \
        dpkg-query --status "$p" | grep -v '^Status:' > "$R/var/lib/dpkg/status.d/$p"; \
        : > "$R/var/lib/dpkg/status.d/$p.md5sums"; \
        for f in $(dpkg -L "$p" | grep -v '^/usr/share/'); do \
            if [ -f "$f" ] || [ -L "$f" ]; then \
                cp -a --parents "$f" "$R/"; \
                grep " ${f#/}\$" "/var/lib/dpkg/info/$p:$arch.md5sums" >> "$R/var/lib/dpkg/status.d/$p.md5sums" || :; \
            fi; \
        done; \
    done; \
    rm -rf /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.* /opt/venv/bin/activate* /opt/venv/bin/Activate.ps1 \
           /opt/venv/lib/python3.*/site-packages/pip /opt/venv/lib/python3.*/site-packages/pip-*.dist-info

# ---------- Run ----------
# Distroless (Google, Debian 13): glibc, OpenSSL, zlib, zstd, CA certificates, tzdata — no shell, no package manager,
# no coreutils (T-59). Rebuilt by its maintainers whenever Debian ships a fix; the python:*-slim tag above is rebuilt
# only with a Python release, so a fixed zlib waited there for weeks (CVE-2026-85091). The project publishes floating
# tags only (`nonroot`, `latest`, `debug…`); the digest pins one state of `nonroot`, and Dependabot moves the digest
# when the tag moves (dependabot.yml, `docker`).
FROM gcr.io/distroless/base-debian13:nonroot@sha256:83e67481ae9fc8c7a6d211113431fb8085619bed49672e583261111bac184f0d

COPY --from=build /rootfs/ /
COPY --from=build /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TINYSESAM_DB=/data/gateway.db \
    TINYSESAM_HOST=0.0.0.0 \
    TINYSESAM_PORT=8000

# No shell here, so every RUN is in exec form. As root (the base's default user is `nonroot`): the account
# `tinysesam` with uid/gid 1000 as before — existing /data volumes belong to 1000 — and /data; then the checks that
# the image is complete and has no shell, package manager or pip. The script is bind-mounted, not copied: it leaves no
# layer behind.
USER 0
RUN --mount=type=bind,source=deploy/gateway/image_setup.py,target=/run/image_setup.py \
    ["/opt/venv/bin/python", "-I", "-B", "/run/image_setup.py"]

USER tinysesam
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000

# `/healthz` is the only path without sign-in and without HTTPS enforcement — the check talks
# to the process from the inside over HTTP.
#
# Redirects are NOT followed — hence `http.client` and not `urllib.request.urlopen`.
# The latter brings the HTTPRedirectHandler in the default opener, follows a 302 and then
# reports the status of the REDIRECT TARGET. A redirect to /healthz — exactly the case
# `_install_https_except_health` guards against — would pass as "healthy". Until 2026-09-21
# the comment here claimed the opposite of what the code did. (A custom opener is not
# enough for that: `build_opener` omits default handlers only if a SUBCLASS of exactly
# that handler is passed — an HTTPHandler passed along does not replace the redirect handler.)
# `http.client` never redirects on its own.
#
# The timeouts are above `Store.BUSY_TIMEOUT_MS` (10 s): `/healthz` writes (B6-4) and, like every
# sign-in, waits behind a foreign writer (checkpoint, backup, second worker).
# With 4 s the check aborted while sign-ins merely waited and then succeeded; only a lock lasting longer
# than 10 s is an outage — and then the service itself answers with 503.
HEALTHCHECK --interval=30s --timeout=15s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,http.client,sys;\
c=http.client.HTTPConnection('127.0.0.1',int(os.environ.get('TINYSESAM_PORT','8000')),timeout=12);\
c.request('GET','/healthz');\
sys.exit(0 if c.getresponse().status==200 else 1)"]

ENTRYPOINT ["python", "-m", "tinysesam.gateway"]
