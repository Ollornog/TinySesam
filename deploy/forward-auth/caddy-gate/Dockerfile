# Caddy with the caddy-jwt plugin — for deploy/forward-auth/Caddyfile.gate (ADR-9) and deploy/quickstart/.
#
# Published with every release as ghcr.io/ollornog/tinysesam-caddy-gate:vX.Y.Z (multi-arch, SBOM, attested,
# scanned — .github/workflows/release.yml). Building it yourself is only needed for an extra module:
#
#   docker build -t caddy-gate deploy/forward-auth/caddy-gate
#   # with a DNS provider for the DNS-01 challenge (deploy/quickstart, TS_TLS=dns):
#   docker build --build-arg CADDY_EXTRA_MODULES="github.com/caddy-dns/cloudflare" -t caddy-gate-dns \
#     deploy/forward-auth/caddy-gate
#
# Versions: Caddy and caddy-jwt are ordinary Go dependencies in go.mod, their hashes in go.sum — Dependabot bumps
# them (`gomod` entry in .github/dependabot.yml), and the CI job `gate-caddy` checks the image against TinySesam
# (tests/test_gate_caddy.py, tests/test_quickstart.py). Up to 0.25.7 the plugin version was an ARG for xcaddy, which
# Dependabot could not see. Both images below are pinned by version AND digest (Dependabot `docker` entry).
#
# The binary comes from go.mod, not from the final base image: `caddy:<version>-alpine` provides only the
# filesystem layout of the official image (/etc/caddy, /data, /config, CA certificates, mailcap). Its version and
# the one in go.mod are bumped by two Dependabot entries; `caddy version` in the image is always the go.mod one.

# Compiled on the build machine for the target platform (pure Go, no cgo) — no emulation for arm64.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS builder
ARG TARGETOS
ARG TARGETARCH
# Space-separated module paths (optionally `@version`), e.g. a DNS provider. Empty = the published image.
ARG CADDY_EXTRA_MODULES=""
# GOTOOLCHAIN=local: a go.mod that needs a newer Go fails here instead of downloading a toolchain at build time.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum main.go ./
RUN go mod download && go mod verify
# Extra modules are added on top, with their hashes fetched now — only for a build of your own.
RUN if [ -n "$CADDY_EXTRA_MODULES" ]; then \
        { echo 'package main'; echo; for m in $CADDY_EXTRA_MODULES; do echo "import _ \"${m%@*}\""; done; } > extra.go \
        && GOFLAGS=-mod=mod go get $CADDY_EXTRA_MODULES; \
    fi
# Flags as xcaddy uses them: no paths of the build machine, no debug symbols, no VCS stamp (there is no .git here).
RUN GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/caddy .

FROM caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
# Alpine's security fixes now, not when the official image is rebuilt: on 2026-11-20 its digest still carried
# libssl3/libcrypto3 3.5.9-r0 and zlib 1.3.2-r1, all with fixes out (high/critical) — the Grype gate in release.yml
# (`image-probe`) was red on day one. The price is a layer that depends on the day of the build; the gateway
# image keeps its bit-reproducible build (B4-7), this one makes no such promise. The Go dependencies come from
# go.sum, never from here.
RUN apk upgrade --no-cache
COPY --from=builder /out/caddy /usr/bin/caddy
# The build must really contain the plugin — otherwise only `caddy run` fails, on `jwtauth`.
RUN caddy list-modules | grep -qx 'http.authentication.providers.jwt'
LABEL org.opencontainers.image.title="tinysesam-caddy-gate" \
      org.opencontainers.image.description="Caddy with caddy-jwt for TinySesam's forward auth and gate token" \
      org.opencontainers.image.source="https://github.com/Ollornog/TinySesam"
