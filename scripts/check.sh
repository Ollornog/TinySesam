#!/usr/bin/env bash
# The gate before every push: functional tests + browser test + hygiene + website build.
#
#   scripts/check.sh            # everything
#   scripts/check.sh --fast     # without the browser test and the Rust, JS and PHP clients (only when in a hurry)
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

# The Go gate client (clients/go): the same steps as the CI workflow client-go, except the fuzz run and the second Go
# release (those stay CI): gofmt (must list nothing), go vet, staticcheck and govulncheck from the tools pinned in
# .github/audit/go.mod, and the tests with the race detector. Without a Go toolchain this step prints a `skip` line —
# ci-local counts exactly that shape (`skip <name> (<reason>)`) as a gap: a skip is not a green. The same holds for the
# parts that need something this machine lacks (a C compiler for -race; the module cache or the network for the tools).
if command -v go >/dev/null; then
    step "Go gate client (clients/go): gofmt, go vet, staticcheck, govulncheck, go test -race"
    GO_UNFORMATTED="$(cd clients/go && gofmt -l .)"
    [[ -z "$GO_UNFORMATTED" ]] || fail "Go gate client: not gofmt-formatted:
$GO_UNFORMATTED"
    (cd clients/go && go vet ./...) || fail "Go gate client: go vet"
    GO_TOOLS="${XDG_CACHE_HOME:-$HOME/.cache}/tinysesam-client-go/tools"
    mkdir -p "$GO_TOOLS"
    if [[ $FAST -eq 1 ]]; then
        # --fast: format, vet and the plain tests only; staticcheck, govulncheck and -race belong to the full gate.
        (cd clients/go && go test -count=1 ./...) || fail "Go gate client: go test"
    elif (cd .github/audit && go build -o "$GO_TOOLS/" tool) >/dev/null 2>&1; then
        (cd clients/go && "$GO_TOOLS/staticcheck" ./...) || fail "Go gate client: staticcheck"
        # govulncheck fetches its vulnerability database: offline (ci-local's container) that is a gap, not a finding.
        if GO_VULN="$(cd clients/go && "$GO_TOOLS/govulncheck" ./... 2>&1)"; then
            :
        elif grep -qiE 'dial tcp|no such host|network is unreachable|i/o timeout|connection refused' <<<"$GO_VULN"; then
            printf '\n\033[33mskip go-govulncheck (the vulnerability database is not reachable) — the CI job client-go runs it\033[0m\n'
        else
            printf '%s\n' "$GO_VULN" >&2
            fail "Go gate client: govulncheck"
        fi
    else
        printf '\n\033[33mskip go-staticcheck (the pinned tools in .github/audit do not build here: no module cache or network) — the CI job client-go runs staticcheck and govulncheck\033[0m\n'
    fi
    if [[ $FAST -eq 1 ]]; then
        :
    elif [[ "$(cd clients/go && go env CGO_ENABLED)" == "1" ]] && command -v gcc >/dev/null; then
        (cd clients/go && go test -race -count=1 ./...) || fail "Go gate client: go test -race"
    else
        (cd clients/go && go test -count=1 ./...) || fail "Go gate client: go test"
        printf '\n\033[33mskip go-race (no C compiler here: the race detector needs cgo) — the CI job client-go runs it\033[0m\n'
    fi
else
    printf '\n\033[33mskip go-gate-client (no Go toolchain here) — the CI job client-go runs it\033[0m\n'
fi

# The Rust gate client (clients/rust, T-81): its own toolchain, its own CI workflow (client-rust.yml, mandatory there).
# Here it runs in the full gate when a working cargo is installed; otherwise the step says why it did not run — the CI
# job is the gate that never skips. `--fast` leaves it out like the browser test (a cold build takes minutes, and
# tests/test_runner.py runs this script with `--fast` under a two-minute limit). "Working" is measured, not assumed:
# a GitHub runner has rustup's `cargo` without a default toolchain. The build directory lies outside the tree (a suite
# must not write into it) and survives between runs — one per checkout: cargo keys a workspace member's build by its
# sources' modification times, not by its path, so a shared directory handed one working tree the test binaries of
# another (built later, `CARGO_MANIFEST_DIR` baked in) — red with the other tree's path, or green against its code.
# Build directories of Rust checkouts that are gone (about 1 GB each): every one carries a `.checkout` file with the
# path of the checkout it belongs to. A directory whose path no longer exists is removed; one without the file (left by
# an older check.sh) is only reported — nothing here guesses what it belonged to. Only names of 16 hex digits count.
RUST_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/tinysesam-client-rust"
rust_cache_sweep() {
    local dir name path legacy=0
    [[ -d "$RUST_CACHE" ]] || return 0
    for dir in "$RUST_CACHE"/*/; do
        dir="${dir%/}"; name="${dir##*/}"
        [[ "$name" =~ ^[0-9a-f]{16}$ ]] || continue
        if [[ -f "$dir/.checkout" ]]; then
            path="$(head -n1 "$dir/.checkout")"
            if [[ -n "$path" && ! -e "$path" ]]; then
                printf '  removing the Rust build directory of a vanished checkout: %s\n' "$path"
                rm -rf "$RUST_CACHE/$name"
            fi
        else
            legacy=$((legacy + 1))
        fi
    done
    [[ $legacy -eq 0 ]] || printf '  note: %d Rust build director%s in %s without a .checkout file (older check.sh) — not removed\n' \
        "$legacy" "$([[ $legacy -eq 1 ]] && echo y || echo ies)" "$RUST_CACHE"
}

rust_cache_sweep
CARGO="$(command -v cargo || echo "$HOME/.cargo/bin/cargo")"
if [[ $FAST -eq 1 ]]; then
    RUST_SKIP="--fast"
elif ! "$CARGO" --version >/dev/null 2>&1; then
    RUST_SKIP="no working cargo"
else
    RUST_SKIP=""
fi
if [[ -z "$RUST_SKIP" ]]; then
    step "Rust gate client (clients/rust): fmt, clippy, tests without and with all features"
    RUST_TARGET="$RUST_CACHE/$(pwd -P | sha256sum | cut -c1-16)"
    mkdir -p "$RUST_TARGET"
    pwd -P >"$RUST_TARGET/.checkout"   # lets the next run find out that this checkout is gone (see rust_cache_sweep)
    # The flags of client-rust.yml; `cargo doc` and `cargo audit` stay in the CI.
    (cd clients/rust && export CARGO_TARGET_DIR="$RUST_TARGET" \
        && "$CARGO" fmt --check \
        && "$CARGO" clippy --locked --all-features --all-targets --quiet -- -D warnings \
        && "$CARGO" test --locked --quiet \
        && "$CARGO" test --locked --all-features --quiet) || fail "Rust gate client"
else
    # `skip <name> (<reason>)`: the shape ci-local counts as a gap (a "! … not tested" line it never saw).
    printf '\n\033[33mskip rust-gate-client (%s) — the CI job client-rust runs it\033[0m\n' "$RUST_SKIP"
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
    # The built package too (test/dist-smoke.mjs, the same check as the CI workflow's last step), built into a throwaway
    # directory: until 2026-11-22 that check stood inline in client-js.yml only, and a request without Remote-Kind
    # reached the CI first.
    step "JS/TS gate client (clients/js): Biome, tsc, tests, the built package"
    (cd clients/js && npm ci --ignore-scripts --no-audit --no-fund --prefer-offline --loglevel=error \
        && npm run --silent lint && npm run --silent typecheck && npm test --silent \
        && JS_DIST="$(mktemp -d)" && trap 'rm -rf "$JS_DIST"' EXIT \
        && npx --no-install tsc -p tsconfig.build.json --outDir "$JS_DIST" \
        && node test/dist-smoke.mjs "$JS_DIST") || fail "JS/TS gate client"
else
    printf '\n\033[33mskip js-gate-client (%s) — the CI job client-js runs it\033[0m\n' "$JS_SKIP"
fi

# The PHP gate client (clients/php, T-83): clients/php/ci.sh holds every check of the CI workflow client-php (Composer
# validate and audit, PHP_CodeSniffer, PHPStan, PHPUnit with every vector, the installed package) — one list, so nothing
# reaches the CI first. A local PHP 8.4+ with ext-sodium, ext-curl, ext-mbstring and Composer runs it directly; without
# one, clients/php/ci/in-docker.sh runs it in clients/php/ci/Dockerfile (the newest PHP, by digest). Neither there is a
# failure, not a skip — except inside ci-local's offline container, which has neither by design: that line says `skip`,
# and ci-local counts it as a gap. `--fast` leaves it out like the Rust and JS clients.
php_fits() {
    command -v php >/dev/null && command -v composer >/dev/null \
        && php -r 'exit(PHP_VERSION_ID >= 80400 && extension_loaded("sodium") && extension_loaded("curl")
                         && extension_loaded("mbstring") ? 0 : 1);' 2>/dev/null
}
if [[ $FAST -eq 1 ]]; then
    printf '\n\033[33mskip php-gate-client (--fast) — the CI job client-php runs it\033[0m\n'
elif php_fits; then
    step "PHP gate client (clients/php): clients/php/ci.sh with the local PHP"
    clients/php/ci.sh || fail "PHP gate client"
elif command -v docker >/dev/null && docker info >/dev/null 2>&1; then
    step "PHP gate client (clients/php): clients/php/ci.sh in clients/php/ci/Dockerfile (no fitting local PHP)"
    clients/php/ci/in-docker.sh || fail "PHP gate client (in Docker)"
elif [[ "${CI_LOCAL_INSIDE:-}" == "1" ]]; then
    printf '\n\033[33mskip php-gate-client (ci-local container: no PHP, no Docker) — CI job client-php runs it\033[0m\n'
else
    fail "PHP gate client: no PHP 8.4+ with ext-sodium, ext-curl, ext-mbstring and Composer, and no Docker for
  clients/php/ci/Dockerfile — install one of them (a skip is not a green)"
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
