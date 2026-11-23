# The proxies tests/test_proxies.py runs the templates with — never built. The suite starts each image as it is and
# reads the reference from the FROM lines; Dependabot (`docker` entry) keeps tag and digest current. Caddy is measured in
# tests/test_gate_caddy.py with the image of deploy/forward-auth/caddy-gate.
FROM nginx:1.31.9-alpine@sha256:fb4658584bd9a916ffb6f6e365f97c25cfdb2923801f551ea08356e695f14ff7 AS nginx
FROM traefik:v3.7.19@sha256:a6c0194dda77bcb804824580f36fa7edc56e315b1acfe933366c8b52844a78a4 AS traefik
