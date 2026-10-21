#!/usr/bin/env bash
# _nur_text.sh — Ist die Änderung gegenüber dem Standardzweig reiner Text? (repokit, seit Kit 0.35.0)
#
# Regel (PO 2026-10-15, Tower-Kontext ci-policy „Text- und Doku-Änderungen: nur ihr eigener Test“): Ändert ein Commit
# bzw. PR nur Text, fährt die Pipeline nur die Prüfungen, die Text betreffen. Anlass: Ein reiner BACKLOG.md-PR kostete
# ~25 min ci-local im pre-push und ~1 h CI. Diese Datei ist die EINE Stelle, an der das entschieden wird — für den
# pre-push-Hook (check.sh nativ), für ci-local (reicht CI_AENDERUNGEN herein) und für die Jobs der Workflows (check.sh im
# ersten Schritt). Pflicht-Checks laufen weiter und melden grün; ein Pfadfilter im Workflow (paths-ignore) ist verboten,
# ein übersprungener Pflicht-Check blockiert den Merge dauerhaft.
#
#   Exit 0  nur Text → check.sh fährt nur tests/test_repo.py (Hygiene samt Textprüfung) und endet
#   Exit 1  volle Suite — auch bei jedem Zweifel: keine Basis, keine Änderung, eine Datei außerhalb der Liste
#   stdout  EINE Zeile Begründung. Ausgeben! Niemand soll einen Hygiene-Lauf für die volle Suite halten.
#
# Verdrahtung in scripts/check.sh (das Kit verlangt sie, `hygiene.pruefe_nur_text`):
#     if grund="$(scripts/_nur_text.sh)"; then echo "$grund"; "$PY" tests/test_repo.py || fail "Repo-Hygiene"; exit 0; fi
#     echo "$grund"
#
# Woher die Liste der geänderten Dateien kommt:
#   * GitHub Actions, Ereignis pull_request: HEAD muss GITHUB_SHA sein, der Merge-Commit, den GitHub gebaut hat; Basis
#     ist sein erster Elternteil (aus dem rohen Objekt — ein flacher Klon zeigt sonst keine Eltern). Fehlt er (actions/checkout holt nur Tiefe 1), wird genau dieser Commit nachgeholt. Scheitert das
#     (privates Repo ohne Zugangsdaten, kein Netz): volle Suite.
#   * CI_AENDERUNGEN gesetzt, nur mit CI_LOCAL_INSIDE=1 und nie in GitHub Actions → eine Datei je Zeile. (Ein
#     vergessener `export` in einer gewöhnlichen Shell zählt so nicht.) ci-local erzeugt sie auf dem
#     Host, wo der Standardzweig bekannt ist; im Prüfcontainer gibt es nur ein Mini-Repo ohne Historie. Leer gesetzt =
#     volle Suite. In Actions zählt sie nicht: Dort darf keine Umgebungsvariable die Liste ersetzen.
#   * sonst selbst: Basis = merge-base von HEAD mit dem Standardzweig (origin/$GITHUB_BASE_REF, origin/HEAD, origin/main,
#     origin/master — der erste, den es gibt), Unterschied zum ARBEITSBAUM (gestagt und ungestagt) plus neue ungetrackte
#     Dateien. `--no-renames`: ein Umzug roles/x.md → docs/x.md zeigte sonst nur den neuen Namen.
#     Kein Standardzweig, merge-base scheitert → volle Suite. Ein veralteter Standardzweig vergrößert die Liste nur.
#   * Keine Änderung (Push auf den Standardzweig selbst) → volle Suite. Der Standardzweig wird immer voll geprüft.
#
# STANDARD-ERLAUBNISLISTE (eine für alle Repos, nur hier): Markdown, das kein Programm liest, rendert oder ausliefert —
#     *.md in der Wurzel · docs/**.md · backlog/**.md · changelog.d/**.md
#   Nichts sonst, auch kein .md unter roles/, templates/, playbooks/, src/, tests/, scripts/, .github/ … und kein Pfad mit
#   Leerzeichen oder Steuerzeichen. Zusätzlich muss jede Datei eine gewöhnliche, nicht ausführbare Datei sein (kein
#   Symlink, kein +x — ein ausführbares „.md“ ist ein Skript), und
#   KEIN PROGRAMM DARF SIE BEIM NAMEN NENNEN: Steht ihr Dateiname (als Wort) in einer getrackten Datei, die selbst kein
#   Text von der Liste ist, fährt die volle Suite — pyproject `readme = "README.md"`, ein Generator, der API.md schreibt,
#   ein Release-Workflow, der CHANGELOG.md liest. Ausgenommen sind nur die Leser, die im Text-Modus ohnehin laufen:
#   tests/test_repo.py und die Kit-Dateien, einzeln genannt (tests/_kit/, scripts/_nur_text.sh, _residue_check.sh,
#   _backlog.py, .githooks/pre-push). Eine Markdown-Datei, die ihn nennt (auch außerhalb der Liste, etwa i18n/), ist
#   kein Leser — außer das Repo führt Markdown aus (Signatur doctest-glob, doctest.testfile, mktestdocs …) und ein
#   Programm nennt diese Markdown-Datei (zweite Stufe: voller Pfad, oder der Name aus ihrem eigenen Ordnerbaum). Ist die Datei über einen getrackten Symlink außerhalb der Liste erreichbar,
#   fährt ebenfalls die volle Suite. Submodule zählen immer (`--ignore-submodules=none`).
#   Grenze (benannt): Ein Programm, das Text per Glob liest (`docs/*.md`), nennt keinen Namen — das Repo verengt dann.
#
# VERENGEN, nie erweitern: scripts/nur-text-verengung.txt im Repo, je Zeile
#     aus <ERE-Muster>   # Begründung      → eine passende Datei löst die volle Suite aus
#     aus alles          # Begründung      → dieses Repo fährt immer voll (z. B. Doku ist Teil des Produkts)
#   Muster sind POSIX-ERE (bash `=~`), keine Python-Regex: ein ungültiges Muster ergibt die volle Suite.
#   Eine andere Form gibt es nicht; das Kit (pruefe_nur_text) lehnt jede Zeile ohne Begründung oder mit anderem
#   Schlüssel ab. Eine kaputte Datei hier: volle Suite.
set -uo pipefail
cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." || { echo "volle Suite: Repo nicht gefunden"; exit 1; }

VERENGUNG="scripts/nur-text-verengung.txt"

erlaubt() {
    [[ "$1" =~ ^[^/[:space:][:cntrl:]]+\.md$ ]] && return 0
    [[ "$1" =~ ^(docs|backlog|changelog\.d)/[^[:space:][:cntrl:]]+\.md$ ]]
}

# Verengung lesen: Muster, die die volle Suite erzwingen. Jede unlesbare Zeile → volle Suite (nie stillschweigend weiter).
verengt=()
if [[ -e "$VERENGUNG" ]]; then
    while IFS= read -r zeile || [[ -n "$zeile" ]]; do
        [[ "$zeile" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ "$zeile" =~ ^aus[[:space:]]+([^[:space:]]+)[[:space:]]+#[[:space:]]*[^[:space:]] ]]; then
            muster="${BASH_REMATCH[1]}"
            # Das Muster ist POSIX-ERE (bash `=~`), nicht Python: `(?i)` ist ungültig (rc 2), `\d` trifft nichts.
            # Ein ungültiges Muster hieße still „trifft nie“ — also volle Suite (Angriffsrunde 2026-10-21, Fund 1).
            [[ "" =~ $muster ]]
            if [[ $? -eq 2 ]]; then
                echo "volle Suite: $VERENGUNG: Muster $muster ist kein gültiger ERE-Ausdruck"
                exit 1
            fi
            verengt+=("$muster")
        else
            echo "volle Suite: $VERENGUNG hat eine Zeile, die keine Verengung ist: $zeile"
            exit 1
        fi
    done < "$VERENGUNG"
fi
for m in "${verengt[@]}"; do
    if [[ "$m" == alles ]]; then
        echo "volle Suite: dieses Repo verzichtet auf den Text-Schnellweg ($VERENGUNG)"
        exit 1
    fi
done

if [[ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" != true ]]; then
    echo "volle Suite: kein git-Arbeitsbaum"
    exit 1
fi

# Liste der geänderten Dateien, NUL-getrennt (Umlaute bleiben lesbar, ein Zeilenumbruch im Namen bleibt erkennbar).
dateien=()
if [[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_EVENT_NAME:-}" == pull_request ]]; then
    # Die Eltern aus dem ROHEN Commit-Objekt: In einem flachen Klon (Tiefe 1) zeigt `git log --format=%P` keine — der
    # Klon „pfropft“ HEAD als elternlos. Gefunden im Selbsttest, bevor es die CI gefunden hätte.
    # Nur der Merge-Commit, den GitHub für DIESEN Lauf gebaut hat: Checkt ein Workflow den PR-Kopf aus und ist der
    # ein „Update branch“-Merge, wäre Elternteil 1 eigener Code, nicht die Basis (Angriffsrunde, Fund 6).
    if [[ -z "${GITHUB_SHA:-}" || "$(git rev-parse -q --verify HEAD 2>/dev/null)" != "$GITHUB_SHA" ]]; then
        echo "volle Suite: pull_request, aber HEAD ist nicht GITHUB_SHA (der Merge-Commit von GitHub)"
        exit 1
    fi
    mapfile -t eltern < <(git cat-file commit HEAD 2>/dev/null | sed -n '/^$/q; s/^parent //p')
    if [[ ${#eltern[@]} -ne 2 ]]; then
        echo "volle Suite: pull_request, aber HEAD ist kein Merge-Commit (${#eltern[@]} Elternteil(e))"
        exit 1
    fi
    basis="${eltern[0]}"
    if ! git cat-file -e "$basis^{commit}" 2>/dev/null \
            && ! git fetch -q --no-tags --depth=1 origin "$basis" 2>/dev/null; then
        echo "volle Suite: Basis ${basis:0:7} des PR nicht abrufbar"
        exit 1
    fi
    git diff --quiet --no-renames --ignore-submodules=none "$basis" HEAD 2>/dev/null; rc=$?
    if [[ $rc -gt 1 ]]; then
        echo "volle Suite: Unterschied zu ${basis:0:7} nicht lesbar"
        exit 1
    fi
    mapfile -d '' -t dateien < <(git diff -z --name-only --no-renames --ignore-submodules=none "$basis" HEAD 2>/dev/null)
    woher="PR, Basis ${basis:0:7}"
elif [[ -n "${CI_AENDERUNGEN+x}" && "${GITHUB_ACTIONS:-}" != true && "${CI_LOCAL_INSIDE:-}" == 1 ]]; then
    mapfile -t dateien < <(printf '%s\n' "$CI_AENDERUNGEN" | sed '/^[[:space:]]*$/d')
    woher="Liste von ci-local, Basis ${CI_AENDERUNGEN_BASIS:-?}"
else
    standard=""
    for k in ${GITHUB_BASE_REF:+"origin/$GITHUB_BASE_REF"} \
             "$(git symbolic-ref -q --short refs/remotes/origin/HEAD 2>/dev/null)" origin/main origin/master; do
        [[ -n "$k" ]] || continue
        if git rev-parse -q --verify "$k^{commit}" >/dev/null 2>&1; then standard="$k"; break; fi
    done
    if [[ -z "$standard" ]] || ! basis="$(git merge-base HEAD "$standard" 2>/dev/null)" || [[ -z "$basis" ]]; then
        echo "volle Suite: keine Basis (kein Standardzweig bekannt oder merge-base scheitert)"
        exit 1
    fi
    git diff --quiet --no-renames --ignore-submodules=none "$basis" -- 2>/dev/null; rc=$?
    if [[ $rc -gt 1 ]]; then
        echo "volle Suite: Unterschied zu ${basis:0:7} nicht lesbar"
        exit 1
    fi
    mapfile -d '' -t dateien < <(git diff -z --name-only --no-renames --ignore-submodules=none "$basis" -- 2>/dev/null
                                 git ls-files -z --others --exclude-standard 2>/dev/null)
    woher="Basis merge-base mit $standard ${basis:0:7}"
fi

# Doppelte heraus (gestagt + ungetrackt kann dieselbe Datei zweimal nennen), Reihenfolge stabil.
declare -A gesehen=()
eindeutig=()
for f in "${dateien[@]}"; do
    [[ -z "$f" || -n "${gesehen[$f]+x}" ]] && continue
    gesehen[$f]=1
    eindeutig+=("$f")
done
dateien=("${eindeutig[@]}")
if [[ ${#dateien[@]} -eq 0 ]]; then
    echo "volle Suite: keine Änderung gegenüber dem Standardzweig ($woher) — der Standardzweig wird immer voll geprüft"
    exit 1
fi

# Leser, die im Text-Modus ohnehin laufen — ihre Nennung eines Dateinamens ist kein Grund für die volle Suite.
# Einzeln genannt, kein Glob: `scripts/_*.sh` traf eigene Skripte der Repos (_abbild_probe.sh) und, weil `*` im
# Pathspec auch `/` überspringt, scripts/_lib/… (Angriffsrunde, Fund 2).
text_leser=(':!tests/test_repo.py' ':(glob,exclude)tests/_kit/**' ':!scripts/_nur_text.sh' ':!scripts/_residue_check.sh'
            ':!scripts/_backlog.py' ':!.githooks/pre-push')

# Getrackte Symlinks außerhalb der Liste, aufgelöst: Ein Programm kann einen Text unter anderem Namen lesen (Fund 5).
symlink_ziele=()
while IFS= read -r -d '' eintrag; do
    [[ "$eintrag" == 120000\ * ]] || continue
    l="${eintrag#*$'\t'}"
    erlaubt "$l" && continue
    symlink_ziele+=("$(readlink -m -- "$l")")
done < <(git ls-files -s -z 2>/dev/null)

# Wer nennt den Namen? 0 = ein Programm (stdout: wer), 1 = niemand, 2 = Suche gescheitert. $2 = auch über Texte der
# Liste weitersuchen (eine Stufe): Ein Text, der selbst ausgeführt wird (Doctest in der README), ist ein Leser, wenn
# ihn ein Programm beim Namen nennt (Fund 4).
genannt_von() {  # genannt_von <Name> <ja|nein> <eigener Pfad> [<Ordner>: nur Leser darin zählen den blossen Namen]
    local name="$1" weiter="$2" selbst="$3" ordner="${4:-}" treffer voll l rc
    treffer="$(git -c core.quotePath=false grep -l -F -w -e "$name" -- . "${text_leser[@]}" 2>/dev/null)"; rc=$?
    [[ $rc -gt 1 ]] && return 2
    if [[ -n "$ordner" ]]; then
        # Zweite Stufe: der blosse Name nur aus dem eigenen Ordnerbaum (eine Rolle nennt ihre README relativ), sonst
        # nur der volle Pfad — `readme = "README.md"` in pyproject meint die Wurzel, nicht backlog/README.md.
        voll="$(git -c core.quotePath=false grep -l -F -w -e "$selbst" -- . "${text_leser[@]}" 2>/dev/null)"; rc=$?
        [[ $rc -gt 1 ]] && return 2
        treffer="$(printf '%s\n' "$voll"; while IFS= read -r l; do [[ "$l" == "$ordner"/* ]] && printf '%s\n' "$l"; done <<<"$treffer")"
    fi
    while IFS= read -r l; do
        [[ -z "$l" || "$l" == "$selbst" ]] && continue       # eine Datei, die ihren eigenen Namen nennt, liest sich nicht
        # Markdown liest nichts. Ein .md als „Leser“ (Verweis in einer Übersetzung, einem Index, einer Rollen-Doku) zählt
        # nur, wenn seinerseits ein Programm IHN beim Namen nennt — Doctest in der README, Vorlage einer Rolle. Bis
        # 0.36.0 galt jedes .md außerhalb der Liste als Programm; in zweisprachigen Repos (i18n/README.de.md verlinkt
        # backlog/README.md) sprang der Schnellweg so nie an (gefunden beim Rollout, 2026-10-21).
        if [[ "$l" == *.md ]]; then
            [[ "$weiter" == ja ]] || continue
            local wer
            # Zweite Stufe eng (gefunden beim Rollout 0.36.1, 2026-10-21): Mit dem blossen Namen hiesse
            # `readme = "README.md"` in pyproject, dass auch backlog/README.md gelesen wird.
            local o="${l%/*}"; [[ "$o" == "$l" ]] && o=""
            if [[ -z "$o" ]]; then
                wer="$(genannt_von "${l##*/}" nein "$l")"; rc=$?
            else
                wer="$(genannt_von "${l##*/}" nein "$l" "$o")"; rc=$?
            fi
            if [[ $rc -eq 0 ]]; then echo "$l (genannt von $wer)"; return 0; fi
            [[ $rc -eq 2 ]] && return 2
            continue
        fi
        echo "$l"; return 0
    done <<<"$treffer"
    return 1
}

# Führt ein Programm Markdown aus (Doctest über *.md, mktestdocs …)? Nur dann zählt ein Text, der den geänderten nennt,
# als Leser, sobald ein Programm IHN nennt (zweite Stufe). Ohne diese Signatur wäre jede Seite, die die README verlinkt,
# „gelesen“ — pyproject nennt die README immer —, und der Schnellweg spränge nie an (gemessen beim Rollout 2026-10-21).
md_laeuft=nein
git -c core.quotePath=false grep -q -E -e 'doctest-glob|doctest\.testfile|mktestdocs|markdown-docs|pytest-markdown|phmdoctest' \
    -- . ':(exclude)*.md' "${text_leser[@]}" 2>/dev/null; rc=$?
if [[ $rc -eq 0 ]]; then md_laeuft=ja; elif [[ $rc -gt 1 ]]; then
    echo "volle Suite: Suche nach ausgeführtem Markdown gescheitert (git grep Exit $rc)"; exit 1
fi

for f in "${dateien[@]}"; do
    if ! erlaubt "$f"; then
        echo "volle Suite: $f ist kein reiner Text ($woher, ${#dateien[@]} Datei(en))"
        exit 1
    fi
    for m in "${verengt[@]}"; do
        [[ "$f" =~ $m ]]; rc=$?
        if [[ $rc -ne 1 ]]; then
            echo "volle Suite: $f fällt unter die Verengung $m ($VERENGUNG)"
            exit 1
        fi
    done
    if [[ -L "$f" ]] || { [[ -e "$f" ]] && { [[ ! -f "$f" ]] || [[ -x "$f" ]]; }; }; then
        echo "volle Suite: $f ist keine gewöhnliche Textdatei (Symlink, Verzeichnis oder ausführbar)"
        exit 1
    fi
    voll="$(readlink -m -- "$f")"
    for z in "${symlink_ziele[@]}"; do
        if [[ "$z" == "$voll" || "$voll" == "$z"/* ]]; then
            echo "volle Suite: $f ist über einen Symlink erreichbar ($z)"
            exit 1
        fi
    done
    leser="$(genannt_von "${f##*/}" "$md_laeuft" "$f")"; rc=$?
    if [[ $rc -eq 2 ]]; then
        echo "volle Suite: Suche nach Lesern von $f gescheitert (git grep)"
        exit 1
    fi
    if [[ -n "$leser" ]]; then
        echo "volle Suite: $f wird von $leser beim Namen genannt — ein Programm liest es"
        exit 1
    fi
done
mehr=""
[[ ${#dateien[@]} -gt 5 ]] && mehr=" …"
echo "NUR TEXT — Hygiene statt voller Suite: ${#dateien[@]} Datei(en) in der Erlaubnisliste ($woher): ${dateien[*]:0:5}$mehr"
exit 0
