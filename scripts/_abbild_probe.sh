#!/usr/bin/env bash
# Builds the gateway image for the own platform and checks that it STARTS — not just builds.
#
#   scripts/_abbild_probe.sh            # builds `tinysesam-probe:lokal` from the working tree and checks it
#
# Called by the job `abbild-probe` in .github/workflows/release.yml, on every PR and before every
# push of an image. The build in the Dockerfile already checks `pip check` and the import; that
# does not catch a dependency that can be imported and only breaks at startup (uvicorn,
# Starlette middleware, the own HEALTHCHECK). Here the container really runs:
#   1. without network (`--network none`) and with placeholder values instead of an OIDC provider —
#      the gateway loads the discovery only at the first sign-in;
#   2. until Docker's own HEALTHCHECK from the Dockerfile reports "healthy" (the one every
#      operator sees as well), at most WARTEN_S seconds;
#   3. `/healthz` must return 200 and name the version from pyproject.toml — otherwise the
#      image holds a different package than this commit.
# A failure prints the container logs. The container is removed in any case.
set -euo pipefail
cd "$(dirname "$0")/.."

ABBILD="${ABBILD:-tinysesam-probe:lokal}"
WARTEN_S="${WARTEN_S:-90}"
NAME="tinysesam-probe-$$"

version="$(python3 -c 'import tomllib,pathlib;
print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"

echo "▸ Abbild bauen: $ABBILD (Version $version)"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
docker build --quiet --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" --tag "$ABBILD" . >/dev/null

aufraeumen() { docker rm --force "$NAME" >/dev/null 2>&1 || true; }
trap aufraeumen EXIT

scheitern() {
    echo "✗ $1" >&2
    echo "── Container-Logs ──" >&2
    docker logs "$NAME" >&2 2>&1 || true
    exit 1
}

# Placeholders, not secrets: the gateway demands the four values at startup, but uses them only
# at a sign-in.
docker run --detach --name "$NAME" --network none \
    -e TINYSESAM_OIDC_ISSUER=https://issuer.example \
    -e TINYSESAM_OIDC_CLIENT_ID=probe \
    -e TINYSESAM_OIDC_CLIENT_SECRET=nur-platzhalter \
    -e TINYSESAM_BASE_URL=https://auth.example \
    "$ABBILD" >/dev/null

echo "▸ warten auf den HEALTHCHECK des Abbilds (höchstens ${WARTEN_S} s)"
zustand=""
for _ in $(seq 1 "$WARTEN_S"); do
    zustand="$(docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}ohne-healthcheck{{end}}' "$NAME")"
    case "$zustand" in
        "running healthy") break ;;
        "running unhealthy") scheitern "der HEALTHCHECK meldet unhealthy" ;;
        "running ohne-healthcheck") scheitern "das Abbild hat keinen HEALTHCHECK mehr" ;;
        running*) sleep 1 ;;
        *) scheitern "der Container läuft nicht mehr ($zustand)" ;;
    esac
done
[ "$zustand" = "running healthy" ] || scheitern "nach ${WARTEN_S} s nicht healthy ($zustand)"

antwort="$(docker exec "$NAME" python -c 'import http.client as h
c = h.HTTPConnection("127.0.0.1", 8000, timeout=10)
c.request("GET", "/healthz")
r = c.getresponse()
print(r.status, r.read().decode())')" || scheitern "/healthz nicht abrufbar"
case "$antwort" in
    "200 "*"\"version\":\"$version\""*) ;;
    *) scheitern "/healthz antwortet unerwartet: $antwort (erwartet 200 mit Version $version)" ;;
esac
echo "✓ Abbild startet, HEALTHCHECK healthy, /healthz 200 mit Version $version"
