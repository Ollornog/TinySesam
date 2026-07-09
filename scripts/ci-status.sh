#!/usr/bin/env bash
# Holt das CI-Ergebnis für HEAD ab. Ohne diesen Schritt gilt ein Push als nicht verifiziert.
#
#   scripts/ci-status.sh          # wartet auf den Lauf, Exit != 0 wenn rot
#   scripts/ci-status.sh --log    # bei Rot zusätzlich die Fehlerausgabe
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v gh >/dev/null; then
    echo "gh fehlt → die lokale Suite IST die CI: scripts/check.sh" >&2
    exit 2
fi
if ! gh auth status >/dev/null 2>&1; then
    echo "gh nicht angemeldet (gh auth login) → lokal prüfen: scripts/check.sh" >&2
    exit 2
fi

sha=$(git rev-parse HEAD)
echo "warte auf CI für ${sha:0:7} …"
for _ in $(seq 1 30); do
    id=$(gh run list --commit "$sha" --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)
    [[ -n "${id:-}" ]] && break
    sleep 4
done
[[ -z "${id:-}" ]] && { echo "kein CI-Lauf für diesen Commit gefunden" >&2; exit 2; }

if gh run watch "$id" --exit-status; then
    echo "CI grün."
else
    echo "CI ROT." >&2
    [[ "${1:-}" == "--log" ]] && gh run view "$id" --log-failed
    exit 1
fi
