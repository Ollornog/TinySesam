#!/usr/bin/env bash
# The gate before every push: functional tests + browser test + hygiene + website build.
#
#   scripts/check.sh            # everything
#   scripts/check.sh --fast     # without the browser test and the Rust and JS clients (only when really in a hurry)
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
    command -v uv >/dev/null || fail "No Python with FastAPI and no uv. → pip install -e '.[all]'"
    step "No Python with FastAPI found — creating .venv (once)"
    uv venv .venv >/dev/null || fail "uv venv"
    # setuptools/wheel: tests/test_packaging.py BUILDS the package (offline, without isolation).
    # A uv venv brings neither, and without a build backend the suite would check nothing.
    # mypy belongs here too: `Typing :: Typed` is a promise to every user, and without the checker
    # tests/test_types.py skips itself — then nobody measures it (see "a skip is not a green").
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
# report green. Decision and list: `scripts/_nur_text.sh` (from the kit); narrow it: `scripts/nur-text-verengung.txt`.
if reason="$(scripts/_nur_text.sh)"; then
    step "$reason"
    "$PY" tests/test_repo.py || fail "repo hygiene"
    printf '\n\033[32m✓ text only — hygiene green\033[0m\n'
    exit 0
fi
step "$reason"

if [[ $FAST -eq 1 ]]; then
    step "Suites without the browser test (--fast)"
    "$PY" tests/run_all.py --no-browser || fail "test suite"
else
    step "All suites — browser and hygiene test included"
    "$PY" tests/run_all.py || fail "test suite"
fi

# The Go gate client (clients/go): vet and the tests with every vector of spec/vectors. Without a Go toolchain this
# step skips with its reason — a skip is not a green: the CI workflow client-go runs it in any case, with staticcheck,
# govulncheck, the race detector and a fuzz run on top.
if command -v go >/dev/null; then
    step "Go gate client (clients/go): go vet + go test"
    (cd clients/go && go vet ./... && go test -count=1 ./...) || fail "Go gate client"
else
    step "Go gate client SKIPPED — no Go toolchain here (the CI workflow client-go runs it)"
fi

# The Rust gate client (clients/rust, T-81): its own toolchain, its own CI workflow (client-rust.yml, mandatory there).
# Here it runs in the full gate when a working cargo is installed; otherwise the step says why it did not run — the CI
# job is the gate that never skips. `--fast` leaves it out like the browser test (a cold build takes minutes, and
# tests/test_runner.py runs this script with `--fast` under a two-minute limit). "Working" is measured, not assumed:
# a GitHub runner has rustup's `cargo` without a default toolchain. The build directory lies outside the tree (a suite
# must not write into it) and survives between runs.
CARGO="$(command -v cargo || echo "$HOME/.cargo/bin/cargo")"
if [[ $FAST -eq 1 ]]; then
    RUST_SKIP="--fast"
elif ! "$CARGO" --version >/dev/null 2>&1; then
    RUST_SKIP="no working cargo"
else
    RUST_SKIP=""
fi
if [[ -z "$RUST_SKIP" ]]; then
    step "Rust gate client (clients/rust)"
    (cd clients/rust && CARGO_TARGET_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/tinysesam-client-rust" \
        "$CARGO" test --locked --all-features --quiet) || fail "Rust gate client"
else
    printf '\n\033[33m! Rust gate client not tested here (%s) — the CI job client-rust runs it\033[0m\n' "$RUST_SKIP"
fi

# The JS/TS gate client (clients/js, T-82): its own CI workflow (client-js.yml, mandatory there, on two Node LTS
# releases with npm audit and the build). Here it runs in the full gate when Node runs TypeScript directly (22.18,
# 23.6, 24 and later); otherwise the step says why it did not run. `--fast` leaves it out like the Rust client. The dev
# tools go into clients/js/node_modules — an ignored setup directory like .venv — from the lock file and without
# lifecycle scripts, so `prepare` builds nothing into the tree (the build runs in CI only).
if [[ $FAST -eq 1 ]]; then
    JS_SKIP="--fast"
elif ! command -v node >/dev/null || ! command -v npm >/dev/null; then
    JS_SKIP="no node and npm"
elif ! node -e 'const [a, b] = process.versions.node.split(".").map(Number);
                process.exit(a >= 24 || (a === 23 && b >= 6) || (a === 22 && b >= 18) ? 0 : 1)'; then
    JS_SKIP="node $(node --version) cannot run TypeScript directly (needs 22.18, 23.6 or 24+)"
elif ! (cd clients/js && timeout 30 npm ping --loglevel=silent >/dev/null 2>&1); then
    # Measured, not assumed: ci-local runs this script with `--network none`, where `npm ci` cannot fetch the dev
    # tools. Without the probe that container run went red on EAI_AGAIN although nothing of the client was wrong.
    JS_SKIP="the npm registry is not reachable (offline container?)"
else
    JS_SKIP=""
fi
if [[ -z "$JS_SKIP" ]]; then
    step "JS/TS gate client (clients/js): Biome, tsc, tests"
    (cd clients/js && npm ci --ignore-scripts --no-audit --no-fund --prefer-offline --loglevel=error \
        && npm run --silent lint && npm run --silent typecheck && npm test --silent) || fail "JS/TS gate client"
else
    printf '\n\033[33m! JS/TS gate client not tested here (%s) — the CI job client-js runs it\033[0m\n' "$JS_SKIP"
fi

step "Build the website — exactly what the Pages action ships"
# Into a throwaway directory, not into `_site/` in the tree: there the build sat silently next to a
# `_site/` of its own (and deleted it afterwards), and two runs in the same tree cleaned each other away.
SITE="$(mktemp -d)"
trap 'rm -rf "$SITE"' EXIT
"$PY" -m web.build "$SITE" >/dev/null || fail "web.build"
for f in index.html demo.html flows.html legal.html theme.css wizard.png \
         demo/login.en.html demo/account.de.html demo/admin.de.html demo/adminapi/api/users; do
    test -f "$SITE/$f" || fail "_site/$f is missing"
done
echo "  index.html · demo.html (+ preview panels) · flows.html · legal.html · attachments"

if [[ $FAST -eq 1 ]]; then
    printf '\n\033[33m! Browser test skipped. Run once without --fast before the push.\033[0m\n'
fi
printf '\n\033[32m✓ all green\033[0m\n'
