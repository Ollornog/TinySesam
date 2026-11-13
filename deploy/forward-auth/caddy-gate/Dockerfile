# Caddy with the caddy-jwt plugin — for deploy/forward-auth/Caddyfile.gate (ADR-9).
#
#   docker build -t caddy-gate deploy/forward-auth/caddy-gate
#
# The official image does not ship caddy-jwt; xcaddy builds it in. Both images are pinned by
# version AND digest (Dependabot bumps them, `docker` entry in .github/dependabot.yml).
# The plugin itself is a Go module and invisible to Dependabot: bump CADDY_JWT by hand —
# releases: https://github.com/ggicci/caddy-jwt/releases. Afterwards the CI job `gate-caddy`
# checks exactly this image against TinySesam (tests/test_gate_caddy.py).
FROM caddy:2.11.8-builder-alpine@sha256:e42a64b3bc70aa3a1387bde85b930e507a378fecae5852d5bfde9dcd37d0b999 AS builder
ARG CADDY_JWT=v1.4.0
RUN xcaddy build --with github.com/ggicci/caddy-jwt@${CADDY_JWT}

FROM caddy:2.11.9-alpine@sha256:0bbb055bda6793c999bde78b1b5ce3e89f829fb031af2cf50056ea1246559fee
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
# The build must really contain the plugin — otherwise only `caddy run` fails, on `jwtauth`.
RUN caddy list-modules | grep -qx 'http.authentication.providers.jwt'
