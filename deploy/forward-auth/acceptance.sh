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
#   ECHO      Optional. 1 = the application reflects the request headers it receives in its response body (a
#             whoami/echo application such as traefik/whoami in deploy/quickstart). Then the script also checks that a
#             Remote-Kind the client forges never arrives — with a session and on the share path.
#
# Checks the behaviour that is visible from outside. The headers the application receives INSIDE
# are not visible to this script unless ECHO=1 — tests/test_gate_caddy.py checks those against the template.
# Exit 0 = all passed, 1 = at least one check failed, 2 = called incorrectly.
set -u

: "${APP:?APP is missing, e.g. APP=https://app.example.com}"
SHARE="${SHARE:-}"
SESSION="${SESSION:-}"
# shellcheck disable=SC2206  # Intentional: CURL_EXTRA may carry several arguments
EXTRA=(${CURL_EXTRA:-})
command -v curl >/dev/null || { echo "curl is missing" >&2; exit 2; }

failed=0
check() {  # check <name> <condition as return value>
    if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  FAIL $1"; failed=1; fi
}
# Status and headers of a request; the path goes onto the wire unchanged (--path-as-is).
fetch() {  # fetch <path> [curl arguments …] → writes status to $code, headers to $head
    local path="$1"; shift
    head="$(curl -s -o /dev/null -D - --path-as-is --max-time 15 "${EXTRA[@]}" "$@" "$APP$path")"
    code="$(printf '%s' "$head" | awk 'NR==1 {print $2}')"
}
to_sign_in() { [ "$code" = 302 ] || [ "$code" = 303 ] || [ "$code" = 401 ]; }
# The response body of a request (for ECHO=1): writes it to $body and the status to $code.
fetch_body() {  # fetch_body <path> [curl arguments …]
    local path="$1"; shift
    body="$(curl -s -w '\n%{http_code}' --path-as-is --max-time 15 "${EXTRA[@]}" "$@" "$APP$path")"
    code="${body##*$'\n'}"; body="${body%$'\n'*}"
}
# A value no TinySesam ever sends: if it shows up in the echo, the proxy passed the client's Remote-Kind on.
FORGED_KIND="tinysesam-forged-kind-probe"

echo "Acceptance: $APP"

# --- without sign-in ---
fetch /
to_sign_in; check "without sign-in: / leads to the sign-in ($code)" $?
# HSTS (ASVS 3.4.1), set by the proxy templates. Browsers ignore it from an IP address (RFC 6797, section 8.1.1) —
# the home-network template therefore has none, and the check is skipped there.
host="${APP#*://}"; host="${host%%/*}"; host="${host%:*}"
if [[ "$host" =~ ^[0-9.]+$ || "$host" == \[* ]]; then
    echo "  –    HSTS not checked: $host is an IP address"
else
    hsts="$(printf '%s' "$head" | tr -d '\r' | sed -n 's/^[Ss]trict-[Tt]ransport-[Ss]ecurity: *max-age=\([0-9]*\).*/\1/p' | head -1)"
    [ "${hsts:-0}" -ge 31536000 ]; check "HSTS on the sign-in redirect, max-age at least one year (${hsts:-none})" $?
fi
fetch / -H "Remote-User: admin" -H "Remote-Groups: admin"
to_sign_in; check "a self-sent Remote-User opens nothing ($code)" $?
fetch / -H "Remote-User: admin" -H "Remote-Kind: service"
to_sign_in; check "a self-sent Remote-User with Remote-Kind: service opens nothing ($code)" $?
fetch /.tinysesam/after-logout
[ "$code" = 200 ]; check "/.tinysesam/* reaches TinySesam past the gate ($code)" $?

# --- share exception ---
if [ -n "$SHARE" ]; then
    fetch "$SHARE"
    ! to_sign_in; check "Share path $SHARE is open ($code)" $?
    prefix="${SHARE%/*}"
    for trick in "$prefix/..;/" "$prefix/%2e%2e;/" "$prefix/..%5c" "/x/..$SHARE" "${SHARE^^}"; do
        fetch "$trick"
        to_sign_in; check "Path trick $trick stays closed ($code)" $?
    done
    if [ "${ECHO:-}" = 1 ]; then
        fetch_body "$SHARE" -H "Remote-Kind: $FORGED_KIND" -H "Remote-User: admin"
        [ "$code" = 200 ] && ! printf '%s' "$body" | grep -q "$FORGED_KIND"
        check "a forged Remote-Kind does not reach the application on the share path ($code)" $?
    fi
fi

# --- with sign-in (test account) ---
if [ -n "$SESSION" ]; then
    fetch / -H "Cookie: $SESSION"
    [ "$code" = 200 ]; check "with session: / is open ($code)" $?
    if [ "${ECHO:-}" = 1 ]; then
        fetch_body / -H "Cookie: $SESSION" -H "Remote-Kind: $FORGED_KIND"
        [ "$code" = 200 ] && ! printf '%s' "$body" | grep -q "$FORGED_KIND" \
            && printf '%s' "$body" | grep -qiE 'remote-kind"?: *"?(user|service)'
        check "with session: the application gets TinySesam's Remote-Kind, never a forged one ($code)" $?
    fi
    gate="$(printf '%s' "$head" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(__Host-tinysesam_gate=[^;]*\).*/\1/p' | head -1)"
    if [ -n "$gate" ]; then
        echo "  ok   gate token issued"
        fetch / -H "Cookie: $gate"
        [ "$code" = 200 ]; check "with the gate token only: / is open ($code)" $?
        fetch / -H "Cookie: ${gate%.*}.AAAA"      # header and payload genuine, signature not
        to_sign_in; check "a forged gate token opens nothing ($code)" $?
    else
        echo "  –    no gate token (gate_token_enabled off?) — related checks skipped"
    fi
    fetch "/.tinysesam/logout?scope=app" -H "Cookie: $SESSION"
    [ "$code" = 303 ] && printf '%s' "$head" | grep -qi '^set-cookie: __Host-tinysesam_gate=;'
    check "sign out here only: 303 and the gate cookie is deleted ($code)" $?
    fetch / -H "Cookie: $SESSION"
    to_sign_in; check "afterwards / leads to the sign-in again ($code)" $?
fi

[ "$failed" -eq 0 ] && echo "passed" || echo "FAILED"
exit "$failed"
