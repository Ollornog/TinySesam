#!/usr/bin/env bash
# Das Tor vor jedem Push: Fachtests + Browser-Test + Hygiene + Website-Build.
#
#   scripts/check.sh            # alles
#   scripts/check.sh --fast     # ohne Browser-Test (nur wenn es wirklich eilt)
#
# Der pre-push-Hook (.githooks/pre-push) ruft dieses Skript. Einmalig pro Klon:
#   git config core.hooksPath .githooks
set -euo pipefail

cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

if [[ $FAST -eq 1 ]]; then
    step "Suiten ohne Browser-Test (--fast)"
    "$PY" tests/run_all.py --no-browser || fail "Testsuite"
else
    step "Alle Suiten — Browser- und Hygiene-Test inklusive"
    "$PY" tests/run_all.py || fail "Testsuite"
fi

step "Website bauen — genau das, was die Pages-Action ausliefert"
"$PY" -m web.build _site >/dev/null || fail "web.build"
for f in index.html flows.html legal.html theme.css wizard.png; do
    test -f "_site/$f" || fail "_site/$f fehlt"
done
rm -rf _site
echo "  index.html · flows.html · legal.html · Beilagen"

if [[ $FAST -eq 1 ]]; then
    printf '\n\033[33m! Browser-Test übersprungen. Vor dem Push einmal ohne --fast laufen lassen.\033[0m\n'
fi
printf '\n\033[32m✓ alles grün\033[0m\n'
