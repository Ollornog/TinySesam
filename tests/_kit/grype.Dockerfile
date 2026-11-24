# The grype image of the weekly rebuild check (kit 0.64.0) — copied here by `repokit sync`, do not edit by hand.
# Not built: `repokit` renders this reference into the dependabot auto-merge workflow (job `rebuild-check`). It sits in a
# Dockerfile so that Dependabot (docker) raises it in repokit; the target repos get the new pin with the next sync.
FROM anchore/grype:v0.122.1@sha256:661583704a253c0448ed63998b5ea2cd9d5a76ee71eedc4aed439b8ce3e93a1c
