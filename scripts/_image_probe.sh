#!/usr/bin/env bash
# Builds the gateway image for the own platform and checks that it STARTS — not just builds.
#
#   scripts/_image_probe.sh            # builds `tinysesam-probe:local` from the working tree and checks it
#
# Called by the job `image-probe` in .github/workflows/release.yml, on every PR and before every
# push of an image. The build in the Dockerfile already checks `pip check` and the import; that
# does not catch a dependency that can be imported and only breaks at startup (uvicorn,
# Starlette middleware, the own HEALTHCHECK). Here the container really runs:
#   1. without network (`--network none`) and with placeholder values instead of an OIDC provider —
#      the gateway loads the discovery only at the first sign-in;
#   2. until Docker's own HEALTHCHECK from the Dockerfile reports "healthy" (the one every
#      operator sees as well), at most WAIT_S seconds;
#   3. `/healthz` must return 200 and name the version from pyproject.toml — otherwise the
#      image holds a different package than this commit.
# A failure prints the container logs. The container is removed in any case.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${IMAGE:-tinysesam-probe:local}"
WAIT_S="${WAIT_S:-90}"
NAME="tinysesam-probe-$$"

version="$(python3 -c 'import tomllib,pathlib;
print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"

echo "▸ Build image: $IMAGE (version $version)"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
docker build --quiet --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" --tag "$IMAGE" . >/dev/null

cleanup() { docker rm --force "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
    echo "✗ $1" >&2
    echo "── container logs ──" >&2
    docker logs "$NAME" >&2 2>&1 || true
    exit 1
}

# Placeholders, not secrets: the gateway demands the four values at startup, but uses them only
# at a sign-in.
docker run --detach --name "$NAME" --network none \
    -e TINYSESAM_OIDC_ISSUER=https://issuer.example \
    -e TINYSESAM_OIDC_CLIENT_ID=probe \
    -e TINYSESAM_OIDC_CLIENT_SECRET=placeholder-only \
    -e TINYSESAM_BASE_URL=https://auth.example \
    "$IMAGE" >/dev/null

echo "▸ waiting for the image's HEALTHCHECK (at most ${WAIT_S} s)"
state=""
for _ in $(seq 1 "$WAIT_S"); do
    state="$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$NAME")"
    case "$state" in
        "running healthy") break ;;
        "running unhealthy") fail "the HEALTHCHECK reports unhealthy" ;;
        "running no-healthcheck") fail "the image has no HEALTHCHECK any more" ;;
        running*) sleep 1 ;;
        *) fail "the container is not running any more ($state)" ;;
    esac
done
[ "$state" = "running healthy" ] || fail "not healthy after ${WAIT_S} s ($state)"

reply="$(docker exec "$NAME" python -c 'import http.client as h
c = h.HTTPConnection("127.0.0.1", 8000, timeout=10)
c.request("GET", "/healthz")
r = c.getresponse()
print(r.status, r.read().decode())')" || fail "/healthz cannot be fetched"
case "$reply" in
    "200 "*"\"version\":\"$version\""*) ;;
    *) fail "/healthz replied unexpectedly: $reply (expected 200 with version $version)" ;;
esac
echo "✓ image starts, HEALTHCHECK healthy, /healthz 200 with version $version"
