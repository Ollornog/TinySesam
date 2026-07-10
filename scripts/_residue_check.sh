#!/usr/bin/env bash
# Rückstands-Check — die EINE Implementierung.
#
# Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.
#
# WARUM: Ein Testlauf darf den Arbeitsbaum nicht verändern. Ein Test, der schreibt, ist
# beim zweiten Lauf nicht mehr wiederholbar. Dieser Check hat als einziger den Fehler
# gefunden, bei dem ein versioniertes `egg-info/` sechs grüne Läufe überlebte — keine
# Testsuite fand ihn.
#
# WARUM EIN SKRIPT: Er existierte fünffach (ci-local, zwei pre-push-Hooks, zwei ci.yml),
# und die beiden `ci.yml`-Fassungen ignorierten `.ci-allow-dirty` — das verbindliche Gate
# widersprach damit dem lokalen Netz. Jetzt fahren Hook, check.sh und CI dieselbe Datei.
#
# NUTZUNG
#   scripts/_residue_check.sh snapshot > vorher.txt   # Zustand VOR dem Lauf festhalten
#   scripts/_residue_check.sh check --seit vorher.txt # danach: was hat der Lauf hinterlassen?
#   scripts/_residue_check.sh check                   # ohne --seit: Baum muss ganz sauber sein
#                                                     # (CI: pristiner Checkout)
#
# Ausnahmen: eine Zeile je Pfadmuster in `.ci-allow-dirty` im Repo-Root (Globs, '#' = Kommentar).
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"

snapshot() {
    git -C "$ROOT" status --porcelain || true
}

# Liest die erlaubten Muster. Fehlt die Datei, ist die Liste leer — fail-closed.
lies_ausnahmen() {
    local datei="$ROOT/.ci-allow-dirty" pat
    [[ -r "$datei" ]] || return 0
    while IFS= read -r pat; do
        [[ -z "$pat" || "$pat" == \#* ]] && continue
        printf '%s\n' "$pat"
    done < "$datei"
}

check() {
    local vorher_datei="" vorher="" nachher line path pat skip
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --seit) vorher_datei="${2:-}"; shift 2 ;;
            *) echo "unbekannte Option: $1" >&2; exit 2 ;;
        esac
    done

    # Ohne --seit gilt der pristine Checkout als Ausgangspunkt (so läuft die CI).
    if [[ -n "$vorher_datei" ]]; then
        [[ -r "$vorher_datei" ]] || { echo "Snapshot nicht lesbar: $vorher_datei" >&2; exit 2; }
        vorher="$(cat "$vorher_datei")"
    fi

    nachher="$(snapshot)"

    local ausnahmen=() rueckstaende=()
    while IFS= read -r pat; do
        [[ -n "$pat" ]] && ausnahmen+=("$pat")
    done < <(lies_ausnahmen)

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Schon vor dem Lauf da? Dann kein Rückstand DIESES Laufs.
        if [[ -n "$vorher" ]] && grep -qxF -- "$line" <<<"$vorher"; then
            continue
        fi
        path="${line:3}"
        skip=0
        for pat in ${ausnahmen[@]+"${ausnahmen[@]}"}; do
            # Glob-Vergleich ist hier gewollt (Muster aus .ci-allow-dirty).
            # shellcheck disable=SC2053
            [[ "$path" == $pat ]] && { skip=1; break; }
        done
        [[ $skip -eq 0 ]] && rueckstaende+=("$line")
    done <<<"$nachher"

    if [[ ${#rueckstaende[@]} -gt 0 ]]; then
        {
            echo
            echo "Rückstands-Check: ABGEBROCHEN — die Suite hat Rückstände hinterlassen:"
            printf '  %s\n' "${rueckstaende[@]}"
            echo
            echo "Ein Test, der schreibt, ist beim zweiten Lauf nicht mehr wiederholbar."
            echo "Erlaubte Ausnahmen: eine Zeile je Pfadmuster in .ci-allow-dirty"
        } >&2
        return 1
    fi
    # Ein Check, dessen Lauf man nie sieht, verdient kein Vertrauen.
    echo "Rückstands-Check: Baum sauber."
    return 0
}

case "${1:-check}" in
    snapshot) snapshot ;;
    check)    shift || true; check "$@" ;;
    *) echo "Nutzung: $0 {snapshot|check [--seit DATEI]}" >&2; exit 2 ;;
esac
