#!/usr/bin/env bash
# Acceptance test of a gate in front of an application (T-24) — against the real deployment, from outside.
#
#   APP=https://app.example.com ./abnahme.sh
#   APP=https://app.example.com SHARE=/s/abc123 SESSION='__Host-tinysesam_session=…' ./abnahme.sh
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

: "${APP:?APP fehlt, z. B. APP=https://app.example.com}"
SHARE="${SHARE:-}"
SESSION="${SESSION:-}"
# shellcheck disable=SC2206  # Intentional: CURL_EXTRA may carry several arguments
EXTRA=(${CURL_EXTRA:-})
command -v curl >/dev/null || { echo "curl fehlt" >&2; exit 2; }

rot=0
pruefe() {  # pruefe <name> <condition as return value>
    if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  ROT  $1"; rot=1; fi
}
# Status and headers of a request; the path goes onto the wire unchanged (--path-as-is).
holen() {  # holen <path> [curl arguments …] → writes status to $code, headers to $kopf
    local pfad="$1"; shift
    kopf="$(curl -s -o /dev/null -D - --path-as-is --max-time 15 "${EXTRA[@]}" "$@" "$APP$pfad")"
    code="$(printf '%s' "$kopf" | awk 'NR==1 {print $2}')"
}
zur_anmeldung() { [ "$code" = 302 ] || [ "$code" = 303 ] || [ "$code" = 401 ]; }

echo "Abnahme: $APP"

# --- without sign-in ---
holen /
zur_anmeldung; pruefe "ohne Anmeldung: / führt zur Anmeldung ($code)" $?
holen / -H "Remote-User: admin" -H "Remote-Groups: admin"
zur_anmeldung; pruefe "ein selbst mitgeschickter Remote-User öffnet nichts ($code)" $?
holen /.tinysesam/after-logout
[ "$code" = 200 ]; pruefe "/.tinysesam/* erreicht TinySesam am Gate vorbei ($code)" $?

# --- share exception ---
if [ -n "$SHARE" ]; then
    holen "$SHARE"
    ! zur_anmeldung; pruefe "Share-Pfad $SHARE ist offen ($code)" $?
    praefix="${SHARE%/*}"
    for trick in "$praefix/..;/" "$praefix/%2e%2e;/" "$praefix/..%5c" "/x/..$SHARE" "${SHARE^^}"; do
        holen "$trick"
        zur_anmeldung; pruefe "Pfad-Trick $trick bleibt zu ($code)" $?
    done
fi

# --- with sign-in (test account) ---
if [ -n "$SESSION" ]; then
    holen / -H "Cookie: $SESSION"
    [ "$code" = 200 ]; pruefe "mit Sitzung: / ist offen ($code)" $?
    gate="$(printf '%s' "$kopf" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(__Host-tinysesam_gate=[^;]*\).*/\1/p' | head -1)"
    if [ -n "$gate" ]; then
        echo "  ok   Gate-Token ausgestellt"
        holen / -H "Cookie: $gate"
        [ "$code" = 200 ]; pruefe "nur mit dem Gate-Token: / ist offen ($code)" $?
        holen / -H "Cookie: ${gate%.*}.AAAA"      # header and payload genuine, signature not
        zur_anmeldung; pruefe "ein verfälschtes Gate-Token öffnet nichts ($code)" $?
    else
        echo "  –    kein Gate-Token (gate_token_enabled aus?) — Prüfungen dazu übersprungen"
    fi
    holen "/.tinysesam/logout?scope=app" -H "Cookie: $SESSION"
    [ "$code" = 303 ] && printf '%s' "$kopf" | grep -qi '^set-cookie: __Host-tinysesam_gate=;'
    pruefe "Abmelden nur hier: 303 und das Gate-Cookie wird gelöscht ($code)" $?
    holen / -H "Cookie: $SESSION"
    zur_anmeldung; pruefe "danach führt / wieder zur Anmeldung ($code)" $?
fi

[ "$rot" -eq 0 ] && echo "bestanden" || echo "NICHT bestanden"
exit "$rot"
