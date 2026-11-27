# Your own TinySesam server image WITH SAML (T-134) — a recipe, not a published image.
#
#   docker build -t my-tinysesam-saml \
#       --build-arg TINYSESAM="tinysesam[gateway,saml]==<version>" deploy/saml-server
#   docker run -d -p 127.0.0.1:8000:8000 -v tinysesam-data:/data \
#       -v ./tinysesam.toml:/etc/tinysesam.toml:ro -e TINYSESAM_CONFIG=/etc/tinysesam.toml my-tinysesam-saml
#
# The published image (ghcr.io/ollornog/tinysesam, ../../Dockerfile) stays slim and has no SAML: python3-saml needs
# libxmlsec1, and the distroless runtime there carries no more than the OIDC server needs (decision 2026-11-27 in
# T-97). This image is yours: you own its updates (rebuild when Debian, Python, TinySesam, python3-saml, xmlsec or lxml
# ship a fix) and its scanning. The base is pinned by digest (the repository's copy is kept current by Dependabot; in
# yours, `docker buildx imagetools inspect python:3.15-slim`), TinySesam by version — the build refuses to run without
# `--build-arg TINYSESAM=…==<version>`.
#
# libxmlsec1 and libxml2 come inside the wheels of `xmlsec` and `lxml` (manylinux, amd64 and arm64), built against the
# same libxml2 — mixing a wheel with a library from apt is what breaks `import xmlsec` ("lxml & xmlsec libxml2 library
# version mismatch"). `--only-binary` keeps it that way: on a platform without wheels the build stops with a clear
# error instead of compiling half of it against Debian's libraries. The configuration is the server's TOML file
# (docs/OPERATIONS.md, "A server image with SAML").

# The empty default of the build context `src` (see TINYSESAM below) — first, so the default target stays the last stage.
FROM scratch AS src

# ---------- Build: TinySesam with python3-saml into a venv ----------
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build
# TINYSESAM: what pip installs, e.g. "tinysesam[gateway,saml]==0.32.0". The empty stage `src` above lets the
# repository's test build the same recipe from a checkout (`--build-context src=<checkout>`, TINYSESAM=/src[...]);
# you leave both alone.
ARG TINYSESAM=""
RUN --mount=type=bind,from=src,target=/src,rw \
    test -n "$TINYSESAM" || { echo "set --build-arg TINYSESAM='tinysesam[gateway,saml]==<version>'" >&2; exit 1; }; \
    python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --only-binary=lxml,xmlsec "$TINYSESAM" \
    && /opt/venv/bin/pip check \
    && /opt/venv/bin/python -c "import lxml.etree, xmlsec, onelogin.saml2.auth, tinysesam.gateway"

# ---------- Run ----------
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
RUN groupadd --gid 1000 tinysesam \
    && useradd --uid 1000 --gid 1000 --create-home tinysesam \
    && mkdir /data && chown tinysesam:tinysesam /data
COPY --from=build /opt/venv /opt/venv
# The same imports as at the end of the build, now in the runtime stage: a library missing here fails the build, not
# the first SAML sign-in.
RUN /opt/venv/bin/python -c "import lxml.etree, xmlsec, onelogin.saml2.auth, tinysesam.gateway"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TINYSESAM_DB=/data/tinysesam.db \
    TINYSESAM_HOST=0.0.0.0 \
    TINYSESAM_PORT=8000
USER tinysesam
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=15s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,http.client,sys;\
c=http.client.HTTPConnection('127.0.0.1',int(os.environ.get('TINYSESAM_PORT','8000')),timeout=12);\
c.request('GET','/healthz');\
sys.exit(0 if c.getresponse().status==200 else 1)"]
ENTRYPOINT ["python", "-m", "tinysesam.gateway"]
