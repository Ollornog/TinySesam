# Caddy with the caddy-jwt plugin — for deploy/forward-auth/Caddyfile.gate (ADR-9).
#
#   docker build -t caddy-gate deploy/forward-auth/caddy-gate
#
# The official image does not ship caddy-jwt; xcaddy builds it in. Both images are pinned by
# version AND digest (Dependabot bumps them, `docker` entry in .github/dependabot.yml).
# The plugin itself is a Go module and invisible to Dependabot: bump CADDY_JWT by hand —
# releases: https://github.com/ggicci/caddy-jwt/releases. Afterwards the CI job `gate-caddy`
# checks exactly this image against TinySesam (tests/test_gate_caddy.py).
FROM caddy:2.11.7-builder-alpine@sha256:80331d37e7d4d230f186f2707079e279f32552924f101ee659e8cae9f9877c26 AS bau
ARG CADDY_JWT=v1.4.0
RUN xcaddy build --with github.com/ggicci/caddy-jwt@${CADDY_JWT}

FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
COPY --from=bau /usr/bin/caddy /usr/bin/caddy
# The build must really contain the plugin — otherwise only `caddy run` fails, on `jwtauth`.
RUN caddy list-modules | grep -qx 'http.authentication.providers.jwt'
