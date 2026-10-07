# Caddy mit dem Plugin caddy-jwt — für deploy/forward-auth/Caddyfile.gate (ADR-9).
#
#   docker build -t caddy-gate deploy/forward-auth/caddy-gate
#
# Das offizielle Abbild bringt caddy-jwt nicht mit; xcaddy baut es hinein. Beide Abbilder sind per
# Version UND Digest gepinnt (Dependabot hebt sie, Eintrag `docker` in .github/dependabot.yml).
# Das Plugin selbst ist ein Go-Modul und für Dependabot unsichtbar: CADDY_JWT von Hand heben —
# Releases: https://github.com/ggicci/caddy-jwt/releases. Danach prüft der CI-Job `gate-caddy`
# genau dieses Abbild gegen TinySesam (tests/test_gate_caddy.py).
FROM caddy:2.11.7-builder-alpine@sha256:80331d37e7d4d230f186f2707079e279f32552924f101ee659e8cae9f9877c26 AS bau
ARG CADDY_JWT=v1.4.0
RUN xcaddy build --with github.com/ggicci/caddy-jwt@${CADDY_JWT}

FROM caddy:2.11.7-alpine@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f
COPY --from=bau /usr/bin/caddy /usr/bin/caddy
# Der Bau muss das Plugin wirklich enthalten — sonst scheitert erst `caddy run` an `jwtauth`.
RUN caddy list-modules | grep -qx 'http.authentication.providers.jwt'
