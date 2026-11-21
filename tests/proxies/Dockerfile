# The proxies tests/test_proxies.py runs the templates with — never built. The suite starts each image as it is and
# reads the reference from the FROM lines; Dependabot (`docker` entry) keeps tag and digest current. Caddy is measured in
# tests/test_gate_caddy.py with the image of deploy/forward-auth/caddy-gate.
FROM nginx:1.31.8-alpine@sha256:fed7e14be83cbd2661a75cdc5b872d936cf155d46c327084d30b8df19ae88d72 AS nginx
FROM traefik:v3.7.19@sha256:a6c0194dda77bcb804824580f36fa7edc56e315b1acfe933366c8b52844a78a4 AS traefik
