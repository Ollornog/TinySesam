#!/usr/bin/env bash
# _client_scope.sh <workflow> — does this pull request touch the gate client a workflow checks? (T-150) Also the
# scope `browser`: the browser suites of ci.yml (job `browser`, its own classifier `classify-browser`).
#
# The one place for the scope of the client workflows (client-go, client-js, client-php, client-rust): the client's
# folder, the specification spec/ (its text and vectors concern every client) and the workflow itself; for Go also the
# pinned tools in .github/audit. Two callers:
#   * the job `classify` (the same in every workflow, tests/test_ci_aggregate.py): in the shared kit's sprint lane
#     (scripts/_nur_text.sh answers "SPRINT LANE") it answers `nur_text=ja` only when this script says no — a sprint
#     pull request that changes a client or spec/ runs that client's jobs, any other skips them as before;
#   * the scope step of each client job: an ordinary pull request that touches nothing of the client ends it green.
# Compares HEAD^1 (the first parent of GitHub's merge commit: the base) with HEAD.
#   exit 0  the pull request touches the client — or doubt (no first parent, unreadable diff): the tests run
#   exit 1  it does not, or <workflow> checks no gate client
#   stdout  one line: the reason
set -uo pipefail
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." || { echo "repository not found: the client's tests run"; exit 0; }

case "${1:-}" in
    client-go) pattern='^(clients/go/|spec/|\.github/audit/go\.(mod|sum)$|\.github/workflows/client-go\.yml$)' ;;
    client-js) pattern='^(clients/js/|spec/|\.github/workflows/client-js\.yml$)' ;;
    client-php) pattern='^(clients/php/|spec/|\.github/workflows/client-php\.yml$)' ;;
    client-rust) pattern='^(clients/rust/|spec/|\.github/workflows/client-rust\.yml$)' ;;
    # The browser suites drive TinySesam's pages and the examples behind a proxy: the library, the examples and their
    # deployments, the suites and their helpers, the workflow. (The sprint lane missed it for T-149: #451 was red.)
    browser) pattern='^(tinysesam/|examples/|clients/js/examples/|deploy/ex[0-9]+/|tests/test_[a-z_]*browser\.py$|tests/_browser_stack\.py$|tests/_test_idp\.py$|tests/_cdp\.py$|tests/voraussetzung\.py$|\.github/workflows/ci\.yml$)' ;;
    *)
        echo "workflow ${1:-<none>} has no scope here"
        exit 1
        ;;
esac
if ! changed="$(git diff --name-only --no-renames HEAD^1 HEAD 2>/dev/null)"; then
    echo "$1: the change of the pull request is not readable (no first parent of HEAD) — the client's tests run"
    exit 0
fi
hit="$(grep -m1 -E -e "$pattern" <<<"$changed")"
if [[ -n "$hit" ]]; then
    echo "$1: the pull request changes $hit — its tests run"
    exit 0
fi
echo "$1: nothing in its scope changed"
exit 1
