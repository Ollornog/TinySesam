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
# Pinned by DIGEST, not by tag: `python:3.14-slim` points here today and elsewhere
# tomorrow — two builds of the same commit would yield different images. To bump:
#   docker manifest inspect python:3.14-slim   (or Dependabot, see dependabot.yml)
FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d AS build

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

# ---------- Run ----------
FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

# `useradd` writes the date of the last password change to /etc/shadow — without this line
# the day of the build, with it the day of the commit (shadow from 4.14 reads SOURCE_DATE_EPOCH).
ARG SOURCE_DATE_EPOCH
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin tinysesam \
    && mkdir -p /data && chown tinysesam:tinysesam /data

COPY --from=build /opt/venv /opt/venv

# No git, no pip in the final image: whoever can load code here has won. That is exactly why
# TinySesam no longer has a self-update (see CHANGELOG 0.12.0).
# The venv brings its OWN pip — deleting the system pip is not enough. A test found
# this after the image was already called "without pip".
# The paths by pattern instead of a fixed Python series: until 2026-09-23 this had `python3.12` —
# after the jump to 3.14 (#74) none of it applied any more, pip was back in the venv.
RUN rm -rf /usr/local/lib/python3.*/site-packages/pip \
           /usr/local/lib/python3.*/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
           /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.* \
           /opt/venv/lib/python3.*/site-packages/pip \
           /opt/venv/lib/python3.*/site-packages/pip-*.dist-info

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TINYSESAM_DB=/data/gateway.db \
    TINYSESAM_HOST=0.0.0.0 \
    TINYSESAM_PORT=8000

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
