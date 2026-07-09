#!/usr/bin/env bash
# Holt das CI-Ergebnis für HEAD ab. Ohne diesen Schritt gilt ein Push als NICHT verifiziert.
#
#   scripts/ci-status.sh          # wartet auf den Lauf; Exit 0 = grün, 1 = rot, 2 = unbekannt
#   scripts/ci-status.sh --log    # bei Rot zusätzlich die Fehlerausgabe (braucht gh)
#
# Bevorzugt `gh` (angemeldet). Fehlt es, fragt das Skript die öffentliche GitHub-API per curl —
# TinySesam ist ein öffentliches Repo, dafür braucht es kein Token.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="Ollornog/TinySesam"
SHA=$(git rev-parse HEAD)
SHORT=${SHA:0:7}

if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
    echo "warte auf CI für $SHORT (gh) …"
    for _ in $(seq 1 30); do
        id=$(gh run list --commit "$SHA" --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
        [[ -n "${id:-}" ]] && break
        sleep 4
    done
    [[ -z "${id:-}" ]] && { echo "kein CI-Lauf für $SHORT gefunden" >&2; exit 2; }
    if gh run watch "$id" --exit-status; then echo "CI grün."; exit 0; fi
    echo "CI ROT." >&2
    [[ "${1:-}" == "--log" ]] && gh run view "$id" --log-failed
    exit 1
fi

command -v curl >/dev/null || { echo "weder gh noch curl — lokal prüfen: scripts/check.sh" >&2; exit 2; }
echo "gh fehlt oder ist nicht angemeldet → öffentliche GitHub-API für $SHORT"
exec python3 scripts/ci_status.py "$REPO" "$SHA"
