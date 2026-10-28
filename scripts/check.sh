#!/usr/bin/env bash
# The gate before every push: functional tests + browser test + hygiene + website build.
#
#   scripts/check.sh            # everything
#   scripts/check.sh --fast     # without the browser test (only when really in a hurry)
#
# The pre-push hook (.githooks/pre-push) calls this script. Once per clone:
#   git config core.hooksPath .githooks
set -euo pipefail

cd "$(dirname "$0")/.."
FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

# Look for an interpreter that can also import TinySesam. Without it 32 suites report
# "FAIL" just because FastAPI is missing in the system Python — the hook then blocks for the wrong reason.
usable() { [[ -x "$1" ]] && "$1" -c "import fastapi" 2>/dev/null; }
PY=""
for cand in "${PYTHON:-}" .venv/bin/python "$(command -v python3 || true)"; do
    [[ -n "$cand" ]] && usable "$cand" && { PY="$cand"; break; }
done

if [[ -z "$PY" ]]; then
    command -v uv >/dev/null || fail "Kein Python mit FastAPI und kein uv. → pip install -e '.[all]'"
    step "Kein Python mit FastAPI gefunden — lege .venv an (einmalig)"
    uv venv .venv >/dev/null || fail "uv venv"
    # setuptools/wheel: tests/test_packaging.py BUILDS the package (offline, without isolation).
    # A uv venv brings neither, and without a build backend the suite would check nothing.
    # mypy belongs here too: `Typing :: Typed` is a promise to every user, and without the checker
    # tests/test_typen.py skips itself — then nobody measures it (see "a skip is not a green").
    VIRTUAL_ENV=".venv" uv pip install -q -e ".[all]" uvicorn websockets httpx setuptools wheel mypy \
        || fail "uv pip install"
    PY=".venv/bin/python"
fi
# This line is the EVIDENCE for `ci-local --matrix`: the runner reads it back and
# compares the version number with the requested leg. Until 2026-09-22 this held
# only `sys.executable` — a path like /opt/venvs/py313/bin/python names no version,
# and so the matrix NEVER passed in this repo ("unproven", exit 1). The
# version therefore comes first, the path stays next to it (it reveals the venv).
step "Interpreter: $("$PY" -c 'import sys; print(sys.version.split()[0], "@", sys.executable)')"

# Text fast path (repokit 0.35.0, PO 2026-10-15): If the state differs from the default branch only in text from the
# kit's allowlist (*.md in the root, docs/, backlog/, changelog.d/), only the text's own check runs —
# tests/test_repo.py: hygiene, links, anchors, frontmatter — and it ends. The required checks still run and
# report green. Decision and list: scripts/_nur_text.sh (from the kit); narrow it: scripts/nur-text-verengung.txt.
if grund="$(scripts/_nur_text.sh)"; then
    step "$grund"
    "$PY" tests/test_repo.py || fail "Repo-Hygiene"
    printf '\n\033[32m✓ Nur Text — Hygiene grün\033[0m\n'
    exit 0
fi
step "$grund"

if [[ $FAST -eq 1 ]]; then
    step "Suiten ohne Browser-Test (--fast)"
    "$PY" tests/run_all.py --no-browser || fail "Testsuite"
else
    step "Alle Suiten — Browser- und Hygiene-Test inklusive"
    "$PY" tests/run_all.py || fail "Testsuite"
fi

step "Website bauen — genau das, was die Pages-Action ausliefert"
# Into a throwaway directory, not into `_site/` in the tree: there the build sat silently next to a
# `_site/` of its own (and deleted it afterwards), and two runs in the same tree cleaned each other away.
SITE="$(mktemp -d)"
trap 'rm -rf "$SITE"' EXIT
"$PY" -m web.build "$SITE" >/dev/null || fail "web.build"
for f in index.html demo.html flows.html legal.html theme.css wizard.png \
         demo/login.en.html demo/account.de.html demo/admin.de.html demo/adminapi/api/users; do
    test -f "$SITE/$f" || fail "_site/$f fehlt"
done
echo "  index.html · demo.html (+ Vorschau-Panels) · flows.html · legal.html · Beilagen"

if [[ $FAST -eq 1 ]]; then
    printf '\n\033[33m! Browser-Test übersprungen. Vor dem Push einmal ohne --fast laufen lassen.\033[0m\n'
fi
printf '\n\033[32m✓ alles grün\033[0m\n'
