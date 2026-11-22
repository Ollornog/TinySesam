#!/usr/bin/env bash
# Every check of the PHP gate client, in one place: the CI workflow client-php runs this script (on two PHP releases and
# inside clients/php/ci/Dockerfile), and scripts/check.sh runs it too — natively or in that image. A check that lives
# only in the workflow reaches the CI first; that is why there is no other list.
#
#   clients/php/ci.sh        # needs php (8.4+, ext-sodium, ext-curl, ext-mbstring for PHPUnit) and composer on PATH
#
# Writes only clients/php/vendor/ (ignored, and allowed in .ci-allow-dirty) and throwaway directories.
set -euo pipefail

cd "$(dirname "$0")"
step() { printf '\n\033[1m▸ php client: %s\033[0m\n' "$1"; }

step "PHP $(php -r 'echo PHP_VERSION;'), $(composer --version --no-ansi 2>/dev/null | head -n1)"
php -r 'exit(PHP_VERSION_ID >= 80400 && extension_loaded("sodium") && extension_loaded("curl") ? 0 : 1);' \
    || { echo "needs PHP 8.4 or newer with ext-sodium and ext-curl" >&2; exit 1; }

step "composer validate (strict, lock file current)"
composer validate --strict --no-interaction --no-ansi

step "install the dev tools from the lock file"
composer install --no-interaction --no-progress --no-ansi --prefer-dist

step "composer audit (advisories and abandoned packages, every dependency)"
composer audit --locked --no-interaction --no-ansi

step "code style (PHP_CodeSniffer, PSR-12)"
vendor/bin/phpcs -q --no-colors

step "static analysis (PHPStan: library and examples at max, tests at 9)"
vendor/bin/phpstan analyse --no-progress --no-ansi --memory-limit=1G
vendor/bin/phpstan analyse --no-progress --no-ansi --memory-limit=1G -c phpstan.tests.neon

step "tests (every vector of spec/vectors, HTTP, processes, properties)"
vendor/bin/phpunit --no-progress --colors=never

# The package as an application gets it: installed by path without the dev tools, then loaded through the
# application's autoloader. Proves the autoload map, the runtime dependencies and that no dev class is needed.
step "the installed package (path repository, --no-dev) identifies a request"
smoke="$(mktemp -d)"
trap 'rm -rf "$smoke"' EXIT
here="$(pwd -P)"
cat > "$smoke/composer.json" <<EOF
{
    "repositories": [{"type": "path", "url": "$here", "options": {"versions": {"tinysesam/gate": "0.1.0"}}}],
    "require": {"tinysesam/gate": "0.1.0"},
    "config": {"allow-plugins": false}
}
EOF
composer install --working-dir="$smoke" --no-dev --no-interaction --no-progress --no-ansi --quiet
php tests/package-smoke.php "$smoke/vendor/autoload.php"
