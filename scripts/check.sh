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
FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

# Einen Interpreter suchen, der TinySesam auch importieren kann. Ohne das melden 32 Suiten
# „FAIL", obwohl bloß FastAPI im System-Python fehlt — der Hook blockt dann aus dem falschen Grund.
usable() { [[ -x "$1" ]] && "$1" -c "import fastapi" 2>/dev/null; }
PY=""
for cand in "${PYTHON:-}" .venv/bin/python "$(command -v python3 || true)"; do
    [[ -n "$cand" ]] && usable "$cand" && { PY="$cand"; break; }
done

if [[ -z "$PY" ]]; then
    command -v uv >/dev/null || fail "Kein Python mit FastAPI und kein uv. → pip install -e '.[all]'"
    step "Kein Python mit FastAPI gefunden — lege .venv an (einmalig)"
    uv venv .venv >/dev/null || fail "uv venv"
    VIRTUAL_ENV=".venv" uv pip install -q -e ".[all]" uvicorn websockets httpx || fail "uv pip install"
    PY=".venv/bin/python"
fi
step "Interpreter: $("$PY" -c 'import sys;print(sys.executable)')"

if [[ $FAST -eq 1 ]]; then
    step "Suiten ohne Browser-Test (--fast)"
    "$PY" tests/run_all.py --no-browser || fail "Testsuite"
else
    step "Alle Suiten — Browser- und Hygiene-Test inklusive"
    "$PY" tests/run_all.py || fail "Testsuite"
fi

step "Website bauen — genau das, was die Pages-Action ausliefert"
"$PY" -m web.build _site >/dev/null || fail "web.build"
for f in index.html demo.html flows.html legal.html theme.css wizard.png \
         demo/login.en.html demo/account.de.html demo/admin.html demo/adminapi/api/users; do
    test -f "_site/$f" || fail "_site/$f fehlt"
done
rm -rf _site
echo "  index.html · demo.html (+ Vorschau-Panels) · flows.html · legal.html · Beilagen"

if [[ $FAST -eq 1 ]]; then
    printf '\n\033[33m! Browser-Test übersprungen. Vor dem Push einmal ohne --fast laufen lassen.\033[0m\n'
fi
printf '\n\033[32m✓ alles grün\033[0m\n'
