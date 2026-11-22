#!/usr/bin/env bash
# Runs clients/php/ci.sh inside the image of clients/php/ci/Dockerfile (the newest stable PHP, pinned by digest) — for a
# machine without a fitting PHP. scripts/check.sh calls it, and the CI workflow client-php runs it as its `image` job, so
# the image that check.sh relies on is itself checked on every pull request.
#
#   clients/php/ci/in-docker.sh      # needs a working `docker` (on a machine with the group not yet active: sg docker)
#
# The Composer cache lives outside the tree (XDG cache); the container runs as the calling user, so clients/php/vendor/
# belongs to that user and not to root.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd -P)"
repo="$(cd "$here/../../.." && pwd -P)"
cache="${XDG_CACHE_HOME:-$HOME/.cache}/tinysesam-client-php/composer"
mkdir -p "$cache"

docker build --quiet --tag tinysesam-client-php:check --label runner.kind=check "$here" >/dev/null
docker run --rm --label runner.kind=check \
    --user "$(id -u):$(id -g)" -e HOME=/tmp -e COMPOSER_HOME=/composer \
    -v "$cache:/composer" -v "$repo:/repo" -w /repo/clients/php \
    tinysesam-client-php:check ./ci.sh
