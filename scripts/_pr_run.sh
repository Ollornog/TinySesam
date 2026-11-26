#!/usr/bin/env bash
# Take over a green PR run (kit 0.67.0) — copied here by `repokit sync`, do not edit by hand.
#
# WHY (PO 2026-11-23 "merge by fast-forward instead of squash, so main does not repeat the PR run"): after a
# fast-forward merge (pr-mergen, or the kit auto-merge with the app) the default branch carries EXACTLY the commit whose
# PR run was green. The push run of that SHA has nothing new to check. This script is the step `pr` of FleetCommander's
# job `art` (ci.yml), as a kit building block: it finds that green PR run, and the expensive jobs skip.
# A squash commit never had a PR run of its own — it is not found, and the main run stays full. That is the whole
# "fast-forward or squash" decision on the main side; no merge way is guessed from a commit message.
#
# Use as a step of the job that classifies the change (needs `actions: read`), after the checkout:
#
#       - name: Green PR run for exactly this SHA?
#         id: pr
#         env:
#           GH_TOKEN: ${{ github.token }}
#         run: scripts/_pr_run.sh
#
#   job output:   pr_run: ${{ steps.pr.outputs.run }}
#   expensive job: if: ${{ !cancelled() && needs.<job>.outputs.pr_run == '' }}
#
# The `if:` form matters: an empty output means "full run", so a failed or skipped classifier job runs everything.
#
# Counted only — all of it, else nothing is written and the run stays full:
#   - the event is `push` or `workflow_dispatch` (the follow-up of an auto-merge without app), on the default branch
#     (from the event file); a PR run, a schedule (nightly-repeat) or another branch is never taken over;
#   - GITHUB_SHA is a full SHA;
#   - a run of THIS workflow file (from GITHUB_WORKFLOW_REF, or PR_RUN_WORKFLOW) in THIS repo (never a fork), event
#     pull_request, head SHA equal, status completed, conclusion success.
# Why the PR run checked the same tree: a PR run tests the merge of its head into the base of that moment. The base only
# moves forward, so when the default branch later IS that head, the base of that moment is an ancestor of the head, and
# the merge is the head itself. (A force-pushed default branch breaks this — the kit never forces.)
#
# Output: `run=<id>` in $GITHUB_OUTPUT and one line in the job summary when found; one log line either way.
# Exit code: always 0 — every read is guarded; this step must never fail the classifier job.
set -uo pipefail

full() { echo "pr-run: $1 — full run"; exit 0; }

case "${GITHUB_EVENT_NAME:-}" in
  push|workflow_dispatch) ;;
  *) full "event ${GITHUB_EVENT_NAME:-unknown} is not a push to the default branch" ;;
esac
default_branch=""
if [ -n "${GITHUB_EVENT_PATH:-}" ] && [ -r "$GITHUB_EVENT_PATH" ]; then
  default_branch="$(jq -r '.repository.default_branch // empty' "$GITHUB_EVENT_PATH" 2>/dev/null)" || default_branch=""
fi
[ -n "$default_branch" ] || full "default branch not readable from the event"
[ "${GITHUB_REF:-}" = "refs/heads/$default_branch" ] || full "${GITHUB_REF:-no ref} is not the default branch $default_branch"
sha="${GITHUB_SHA:-}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || full "no full SHA (${sha:-empty})"
repo="${GITHUB_REPOSITORY:-}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || full "repository not readable (${repo:-empty})"
file="${PR_RUN_WORKFLOW:-}"
if [ -z "$file" ]; then
  file="${GITHUB_WORKFLOW_REF:-}"; file="${file%%@*}"; file="${file##*/}"
fi
[[ "$file" =~ ^[A-Za-z0-9._-]+\.ya?ml$ ]] || full "workflow file not readable (${file:-empty})"

if ! runs="$(gh api "repos/$repo/actions/workflows/$file/runs?head_sha=$sha&event=pull_request&status=success&per_page=100" \
      --jq '.workflow_runs[] | "\(.id) \(.head_sha) \(.head_repository.full_name) \(.event) \(.status) \(.conclusion)"' 2>&1)"; then
  full "PR runs of $sha not readable (${runs:0:120})"
fi
while read -r id head origin event st conclusion; do
  if [[ "$id" =~ ^[0-9]+$ && "$head" == "$sha" && "$origin" == "$repo" && "$event" == pull_request \
        && "$st" == completed && "$conclusion" == success ]]; then
    if [ -n "${GITHUB_OUTPUT:-}" ] && echo "run=$id" >> "$GITHUB_OUTPUT"; then
      echo "pr-run: green PR run $id of $file for $sha taken over"
      if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
        echo "### Green PR run $id for \`$sha\` taken over — the expensive jobs skip" >> "$GITHUB_STEP_SUMMARY" \
          || echo "::warning::job summary not writable"
      fi
      exit 0
    fi
    full "GITHUB_OUTPUT not writable"
  fi
done <<<"$runs"
full "no green PR run of $repo/$file for $sha"
