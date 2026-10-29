#!/usr/bin/env bash
# Acceptance test of a gate in front of an application (T-24) — against the real deployment, from outside.
#
#   APP=https://app.example.com ./acceptance.sh
#   APP=https://app.example.com SHARE=/s/abc123 SESSION='__Host-tinysesam_session=…' ./acceptance.sh
#
#   APP       Required. The application behind the gate (scheme + host, no path).
#   SHARE     Optional. A public path (share link) that must work without sign-in.
#   SESSION   Optional. The session cookie of a TEST ACCOUNT (`name=value`, taken from the
#             developer tools). This also enables the checks with sign-in. Note: the last step
#             signs the account out of THIS application ("only here") — go back through the
#             login page, "Continue as …".
#   CURL_EXTRA Optional. Additional curl arguments (e.g. --resolve for a test setup).
#
# Checks the behaviour that is visible from outside. The headers the application receives INSIDE
# are not visible to this script — tests/test_gate_caddy.py checks those against the template.
# Exit 0 = all passed, 1 = at least one check failed, 2 = called incorrectly.
set -u

: "${APP:?APP is missing, e.g. APP=https://app.example.com}"
SHARE="${SHARE:-}"
SESSION="${SESSION:-}"
# shellcheck disable=SC2206  # Intentional: CURL_EXTRA may carry several arguments
EXTRA=(${CURL_EXTRA:-})
command -v curl >/dev/null || { echo "curl is missing" >&2; exit 2; }

rot=0
pruefe() {  # pruefe <name> <condition as return value>
    if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; rot=1; fi
}
# Status and headers of a request; the path goes onto the wire unchanged (--path-as-is).
holen() {  # holen <path> [curl arguments …] → writes status to $code, headers to $kopf
    local pfad="$1"; shift
    kopf="$(curl -s -o /dev/null -D - --path-as-is --max-time 15 "${EXTRA[@]}" "$@" "$APP$pfad")"
    code="$(printf '%s' "$kopf" | awk 'NR==1 {print $2}')"
}
zur_anmeldung() { [ "$code" = 302 ] || [ "$code" = 303 ] || [ "$code" = 401 ]; }

echo "Acceptance: $APP"

# --- without sign-in ---
holen /
zur_anmeldung; pruefe "without sign-in: / leads to the sign-in ($code)" $?
holen / -H "Remote-User: admin" -H "Remote-Groups: admin"
zur_anmeldung; pruefe "a self-sent Remote-User opens nothing ($code)" $?
holen /.tinysesam/after-logout
[ "$code" = 200 ]; pruefe "/.tinysesam/* reaches TinySesam past the gate ($code)" $?

# --- share exception ---
if [ -n "$SHARE" ]; then
    holen "$SHARE"
    ! zur_anmeldung; pruefe "Share path $SHARE is open ($code)" $?
    praefix="${SHARE%/*}"
    for trick in "$praefix/..;/" "$praefix/%2e%2e;/" "$praefix/..%5c" "/x/..$SHARE" "${SHARE^^}"; do
        holen "$trick"
        zur_anmeldung; pruefe "Path trick $trick stays closed ($code)" $?
    done
fi

# --- with sign-in (test account) ---
if [ -n "$SESSION" ]; then
    holen / -H "Cookie: $SESSION"
    [ "$code" = 200 ]; pruefe "with session: / is open ($code)" $?
    gate="$(printf '%s' "$kopf" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(__Host-tinysesam_gate=[^;]*\).*/\1/p' | head -1)"
    if [ -n "$gate" ]; then
        echo "  ok   gate token issued"
        holen / -H "Cookie: $gate"
        [ "$code" = 200 ]; pruefe "with the gate token only: / is open ($code)" $?
        holen / -H "Cookie: ${gate%.*}.AAAA"      # header and payload genuine, signature not
        zur_anmeldung; pruefe "a forged gate token opens nothing ($code)" $?
    else
        echo "  –    no gate token (gate_token_enabled off?) — related checks skipped"
    fi
    holen "/.tinysesam/logout?scope=app" -H "Cookie: $SESSION"
    [ "$code" = 303 ] && printf '%s' "$kopf" | grep -qi '^set-cookie: __Host-tinysesam_gate=;'
    pruefe "sign out here only: 303 and the gate cookie is deleted ($code)" $?
    holen / -H "Cookie: $SESSION"
    zur_anmeldung; pruefe "afterwards / leads to the sign-in again ($code)" $?
fi

[ "$rot" -eq 0 ] && echo "passed" || echo "FAILED"
exit "$rot"
