# The proxies tests/test_proxies.py runs the templates with — never built. The suite starts each image as it is and
# reads the reference from the FROM lines; Dependabot (`docker` entry) keeps tag and digest current. Caddy is measured in
# tests/test_gate_caddy.py with the image of deploy/forward-auth/caddy-gate.
#
# nginx stands on the STABLE line (even minor: 1.30.x), not on mainline (odd minor: 1.31.x) — operators run stable, the
# templates are measured against that (T-114). The next stable line (1.32) is a deliberate bump by hand; Dependabot
# ignores the mainline minors (dependabot.yml, `docker` entry).
FROM nginx:1.30.8-alpine@sha256:6437a63b5c529f0e06162b3f593c0154cff6fa2ea0f94fd7c27928cb399e022d AS nginx
FROM traefik:v3.7.19@sha256:a6c0194dda77bcb804824580f36fa7edc56e315b1acfe933366c8b52844a78a4 AS traefik
