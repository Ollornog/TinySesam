#!/usr/bin/env bash
# Abnahme eines Gates vor einer Anwendung (T-24) — gegen das echte Deployment, von aussen.
#
#   APP=https://app.example.com ./abnahme.sh
#   APP=https://app.example.com SHARE=/s/abc123 SESSION='__Host-tinysesam_session=…' ./abnahme.sh
#
#   APP       Pflicht. Die Anwendung hinter dem Gate (Schema + Host, ohne Pfad).
#   SHARE     Optional. Ein öffentlicher Pfad (Share-Link), der ohne Anmeldung gehen muss.
#   SESSION   Optional. Das Sitzungs-Cookie eines TESTKONTOS (`name=wert`, aus den
#             Entwicklerwerkzeugen). Damit laufen auch die Prüfungen mit Anmeldung. Achtung: Der
#             letzte Schritt meldet das Konto von DIESER Anwendung ab („nur hier“) — zurück über
#             die Login-Seite, „Weiter als …“.
#   CURL_EXTRA Optional. Zusätzliche curl-Argumente (z. B. --resolve für einen Testaufbau).
#
# Prüft das Verhalten, das man von aussen sehen kann. Was die Anwendung DRINNEN an Headern
# bekommt, sieht dieses Skript nicht — das prüft tests/test_gate_caddy.py gegen die Vorlage.
# Exit 0 = alles bestanden, 1 = mindestens eine Prüfung rot, 2 = falsch aufgerufen.
set -u

: "${APP:?APP fehlt, z. B. APP=https://app.example.com}"
SHARE="${SHARE:-}"
SESSION="${SESSION:-}"
# shellcheck disable=SC2206  # Absicht: CURL_EXTRA darf mehrere Argumente tragen
EXTRA=(${CURL_EXTRA:-})
command -v curl >/dev/null || { echo "curl fehlt" >&2; exit 2; }

rot=0
pruefe() {  # pruefe <name> <bedingung als Rückgabewert>
    if [ "$2" -eq 0 ]; then echo "  ok   $1"; else echo "  ROT  $1"; rot=1; fi
}
# Status und Header einer Anfrage; der Pfad geht unverändert auf die Leitung (--path-as-is).
holen() {  # holen <pfad> [curl-argumente …] → schreibt Status in $code, Header in $kopf
    local pfad="$1"; shift
    kopf="$(curl -s -o /dev/null -D - --path-as-is --max-time 15 "${EXTRA[@]}" "$@" "$APP$pfad")"
    code="$(printf '%s' "$kopf" | awk 'NR==1 {print $2}')"
}
zur_anmeldung() { [ "$code" = 302 ] || [ "$code" = 303 ] || [ "$code" = 401 ]; }

echo "Abnahme: $APP"

# --- ohne Anmeldung ---
holen /
zur_anmeldung; pruefe "ohne Anmeldung: / führt zur Anmeldung ($code)" $?
holen / -H "Remote-User: admin" -H "Remote-Groups: admin"
zur_anmeldung; pruefe "ein selbst mitgeschickter Remote-User öffnet nichts ($code)" $?
holen /.tinysesam/after-logout
[ "$code" = 200 ]; pruefe "/.tinysesam/* erreicht TinySesam am Gate vorbei ($code)" $?

# --- Share-Ausnahme ---
if [ -n "$SHARE" ]; then
    holen "$SHARE"
    ! zur_anmeldung; pruefe "Share-Pfad $SHARE ist offen ($code)" $?
    praefix="${SHARE%/*}"
    for trick in "$praefix/..;/" "$praefix/%2e%2e;/" "$praefix/..%5c" "/x/..$SHARE" "${SHARE^^}"; do
        holen "$trick"
        zur_anmeldung; pruefe "Pfad-Trick $trick bleibt zu ($code)" $?
    done
fi

# --- mit Anmeldung (Testkonto) ---
if [ -n "$SESSION" ]; then
    holen / -H "Cookie: $SESSION"
    [ "$code" = 200 ]; pruefe "mit Sitzung: / ist offen ($code)" $?
    gate="$(printf '%s' "$kopf" | tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(__Host-tinysesam_gate=[^;]*\).*/\1/p' | head -1)"
    if [ -n "$gate" ]; then
        echo "  ok   Gate-Token ausgestellt"
        holen / -H "Cookie: $gate"
        [ "$code" = 200 ]; pruefe "nur mit dem Gate-Token: / ist offen ($code)" $?
        holen / -H "Cookie: ${gate%.*}.AAAA"      # Kopf und Inhalt echt, Signatur nicht
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
