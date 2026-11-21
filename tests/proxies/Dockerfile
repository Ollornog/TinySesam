# The proxies tests/test_proxies.py runs the templates with — never built. The suite starts each image as it is and
# reads the reference from the FROM lines; Dependabot (`docker` entry) keeps tag and digest current. Caddy is measured in
# tests/test_gate_caddy.py with the image of deploy/forward-auth/caddy-gate.
FROM nginx:1.30.7-alpine@sha256:caf4e1e032a20f9c3c5e28fc7f25ffd768ad8677b4975c54193075997b3a97e3 AS nginx
FROM traefik:v3.7.19@sha256:a6c0194dda77bcb804824580f36fa7edc56e315b1acfe933366c8b52844a78a4 AS traefik
