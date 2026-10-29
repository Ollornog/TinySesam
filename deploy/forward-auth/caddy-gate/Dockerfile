# Caddy with the caddy-jwt plugin — for deploy/forward-auth/Caddyfile.gate (ADR-9).
#
#   docker build -t caddy-gate deploy/forward-auth/caddy-gate
#
# The official image does not ship caddy-jwt; xcaddy builds it in. Both images are pinned by
# version AND digest (Dependabot bumps them, `docker` entry in .github/dependabot.yml).
# The plugin itself is a Go module and invisible to Dependabot: bump CADDY_JWT by hand —
# releases: https://github.com/ggicci/caddy-jwt/releases. Afterwards the CI job `gate-caddy`
# checks exactly this image against TinySesam (tests/test_gate_caddy.py).
FROM caddy:2.11.7-builder-alpine@sha256:ef9b65adf9a224770c6d5f6d1ae1bf99bc3caaa78d8c4bae3ea949ee6984f301 AS builder
ARG CADDY_JWT=v1.4.0
RUN xcaddy build --with github.com/ggicci/caddy-jwt@${CADDY_JWT}

FROM caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
# The build must really contain the plugin — otherwise only `caddy run` fails, on `jwtauth`.
RUN caddy list-modules | grep -qx 'http.authentication.providers.jwt'
