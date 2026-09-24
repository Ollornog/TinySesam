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
        if [[ -z "$vorher_datei" ]]; then
            # In der CI IST es entscheidbar, auch ohne Snapshot: der Checkout ist frisch,
            # also stammt jede veränderte Datei aus dem Lauf.
            #
            # ⚠️ KORREKTUR 2026-09-24 (gemeldet aus einer fremden Session, Register
            # `pipeline-fehler.md`): Bis hierher behauptete die Meldung „In der CI tritt
            # das nie auf" — und genau dort wurde sie gerufen: vier Repos rufen
            # `_residue_check.sh check` OHNE `--seit` nach der Suite. Ein echter
            # Rückstand kam dort als „nicht entscheidbar … kein Vorwurf" heraus. Der Job
            # wurde weiter rot (Exit ≠ 0), das Gate hielt — aber die Aussage war falsch.
            if [[ -n "${CI:-}${GITHUB_ACTIONS:-}" ]]; then
                {
                    echo
                    echo "Rückstands-Check: ABGEBROCHEN — in diesem Lauf sind Rückstände"
                    echo "entstanden (CI erkannt, Checkout frisch, also stammen sie aus dem Lauf)."
                    echo "WELCHER Schritt sie hinterlassen hat, sagt dieser Aufruf NICHT: ohne"
                    echo "Snapshot ist ein Vorbereitungsschritt (z.B. ein editable install, der"
                    echo "egg-info erzeugt) von der Suite nicht zu unterscheiden."
                    printf '  %s\n' "${rueckstaende[@]}"
                    echo
                    echo "Besser als diese Herleitung ist der Snapshot-Weg — VOR der Suite:"
                    echo "    scripts/_residue_check.sh snapshot > \"\$RUNNER_TEMP/vorher.txt\""
                    echo "und danach:"
                    echo "    scripts/_residue_check.sh check --seit \"\$RUNNER_TEMP/vorher.txt\""
                } >&2
                return 1
            fi
            # Ohne Vorher-Stand ist NICHT entscheidbar, ob das der Lauf war. Exit 2 statt 1:
            # es ist kein Freispruch, aber auch kein Vorwurf, den dieses Skript belegen kann.
            {
                echo
                echo "Rückstands-Check: NICHT ENTSCHEIDBAR — der Baum ist verändert, aber es"
                echo "gibt keinen Vorher-Stand. Ob das der Lauf war oder schon vorher da lag,"
                echo "kann dieses Skript nicht wissen:"
                printf '  %s\n' "${rueckstaende[@]}"
                echo
                echo "Im Arbeitsbaum ist das der Normalfall. Unter ci-local und in der CI"
                echo "wird stattdessen Exit 1 gemeldet — dort ist der Baum vor dem Lauf"
                echo "per Konstruktion sauber."
                echo
                echo "Damit es überall entscheidbar wird, VOR der Suite einmal:"
                echo "    scripts/_residue_check.sh snapshot > \"\$TMPDIR/vorher.txt\""
                echo "und danach:"
                echo "    scripts/_residue_check.sh check --seit \"\$TMPDIR/vorher.txt\""
            } >&2
            return 2
        fi
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
    echo "Rückstands-Check: Baum sauber.${vorher_datei:+ (gegen Vorher-Stand)}"
    return 0
}

case "${1:-check}" in
    snapshot) snapshot ;;
    check)    shift || true; check "$@" ;;
    *) echo "Nutzung: $0 {snapshot|check [--seit DATEI]}" >&2; exit 2 ;;
esac
