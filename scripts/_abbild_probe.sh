#!/usr/bin/env bash
# Baut das Gateway-Abbild für die eigene Plattform und prüft, dass es STARTET — nicht nur baut.
#
#   scripts/_abbild_probe.sh            # baut `tinysesam-probe:lokal` aus dem Arbeitsbaum und prüft
#
# Aufgerufen vom Job `abbild-probe` in .github/workflows/release.yml, auf jedem PR und vor jedem
# Schieben eines Abbilds. Der Bau im Dockerfile prüft schon `pip check` und den Import; das
# fängt keine Abhängigkeit, die sich importieren lässt und erst beim Start bricht (uvicorn,
# Starlette-Middleware, der eigene HEALTHCHECK). Hier läuft der Container wirklich:
#   1. ohne Netz (`--network none`) und mit Platzhalter-Werten statt eines OIDC-Anbieters —
#      das Gateway lädt die Discovery erst bei der ersten Anmeldung;
#   2. bis Dockers eigener HEALTHCHECK aus dem Dockerfile „healthy“ meldet (der, den auch jeder
#      Betreiber sieht), höchstens WARTEN_S Sekunden;
#   3. `/healthz` muss 200 liefern und die Version aus pyproject.toml nennen — sonst steckt im
#      Abbild ein anderes Paket als in diesem Commit.
# Ein Fehlschlag gibt die Container-Logs aus. Der Container wird in jedem Fall entfernt.
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

# Platzhalter, keine Geheimnisse: Das Gateway verlangt die vier Werte beim Start, benutzt sie aber
# erst bei einer Anmeldung.
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
