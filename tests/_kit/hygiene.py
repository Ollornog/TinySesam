"""Geteilte Hygiene-Prüfungen. Eine Quelle für alle Repos.

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.
Die Regeln selbst stehen daneben in `hygiene_policy.json` (reine Daten, kein Code).

**Kein Netz, keine Abhängigkeiten.** Nur stdlib. Die Datei ist eingecheckt und liegt
darum in jedem `git clone`, jedem GitHub-ZIP und jedem Release-Tarball.

**Jede Prüfung gibt eine Liste von Verstößen zurück, sie wirft nicht.** Das ist Absicht:
so passt derselbe Code in ein `assert not pruefe_...(...)` wie in ein sammelndes
`r.check(name, not pruefe_...(...))`. Kein Repo muss sein Test-Idiom aufgeben.
"""
from __future__ import annotations

import ast
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

HIER = os.path.dirname(os.path.abspath(__file__))

# TLD-Liste bewusst ENG: jede weitere TLD ist auch ein moeglicher Attributname oder
# eine Dateiendung (`.sh`, `.py`, `.io` sind alle drei zugleich echte TLDs).
_HOST_RE = re.compile(
    r"(?<![\w.@/:-])[a-z0-9][a-z0-9-]{1,40}(?:\.[a-z0-9-]{2,40})*"
    r"\.(?:com|net|org|de|at|ch|eu|io|ai|dev|app|info|co|me|tv|xyz)(?![\w-])",
    re.IGNORECASE)


# ---------------------------------------------------------------------------
# Laden und Einlesen
# ---------------------------------------------------------------------------
def lade_policy(pfad: str | None = None) -> dict:
    with open(pfad or os.path.join(HIER, "hygiene_policy.json"), encoding="utf-8") as fh:
        return json.load(fh)


def getrackte_dateien(root: str) -> list[str]:
    """Nur versionierte Dateien; alles andere geht das Repo nichts an."""
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root,
                         capture_output=True, check=True)
    return [n for n in out.stdout.decode("utf-8").split("\0") if n]


def _lies(root: str, rel: str) -> str | None:
    """Textinhalt oder None, wenn die Datei binär/unlesbar ist."""
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as fh:
            return fh.read()
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        return None


def _texte(root: str, dateien: list[str], policy: dict, mit_selbst: bool = False):
    """(pfad, inhalt) je lesbarer Datei. Nimmt die Musterträger selbst aus."""
    binaer = tuple(policy["binaer_endungen"])
    selbst = set() if mit_selbst else set(policy["selbst_ausnahmen"])
    for rel in dateien:
        if rel in selbst or rel.endswith(binaer):
            continue
        inhalt = _lies(root, rel)
        if inhalt is not None:
            yield rel, inhalt


# ---------------------------------------------------------------------------
# Die Prüfungen
# ---------------------------------------------------------------------------
def pruefe_artefakte(dateien: list[str], policy: dict) -> list[str]:
    """Generierte Artefakte gehören nicht ins Repo.

    `pip install -e .` schreibt `<paket>.egg-info/` bei jedem Lauf neu. Versioniert macht
    das die Suite unwiederholbar — und zwar unsichtbar: `PKG-INFO` ändert sich nur, wenn
    sich Metadaten ändern. Der Baum bleibt zufällig sauber, bis die Version steigt.
    Genau so überlebte der Fehler einmal sechs grüne Läufe. Keine Testsuite fand ihn,
    nur der Rückstands-Check. Die `.gitignore` schützt nur, was noch nicht eingecheckt ist.
    """
    teile = tuple(policy["artefakt_teile"])
    verzeichnisse = set(policy["artefakt_verzeichnisse"])
    endungen = tuple(policy["artefakt_endungen"])
    treffer = []
    for rel in dateien:
        segmente = rel.split("/")
        if (any(t in rel for t in teile)
                or any(s in verzeichnisse for s in segmente[:-1])
                or rel.endswith(endungen)):
            treffer.append(rel)
    return treffer


def pruefe_private_infrastruktur(root: str, dateien: list[str], policy: dict,
                                 projekte: list[str],
                                 eigener_name_sha256: str | list[str] | None = None) -> list[str]:
    """Keine private Infrastruktur im öffentlichen Repo.

    Die Trennlinie ist **Identität gegen Infrastruktur**, nicht „mein Name kommt vor".
    Erlaubt und teils rechtlich nötig: Autor, Impressumsadresse, Lizenz, Repo-URL,
    Projektname. Verboten ist, was jemandem hilft, die Systeme dahinter zu finden.

    `projekte` sind die eigenen Projektnamen, deren Repo-URLs erlaubt bleiben.

    `eigener_name_sha256` nimmt den EIGENEN Namen eines Repos aus der Namensliste —
    als Prüfsumme, nicht als Klartext, damit die Aufrufstelle den Namen nicht trägt.

    WARUM ES DAS BRAUCHT (2026-09-22): Steht der Name eines Projekts selbst auf der
    Liste der geschützten Namen, meldet die Prüfung IN DESSEN EIGENEM REPO jeden
    Vorkommensort — Projektname, Datenbankname, Klassennamen, Abbildname. Gemessen:
    **1605 Befunde** in einem Repo, jeder einzelne formal richtig und trotzdem wertlos.

    Beide Sichtweisen stimmen, und genau das ist der Punkt: Von aussen ist der Name
    **Kundenname** und gehört in kein fremdes Repo. Von innen ist er der **Projektname**
    und steht zu Recht überall. `erlaubte_identitaet` löst das nicht — sie erlaubt ihn
    nur in Repo-URLs, nicht in `DB_DATABASE=<name>`.

    Die Ausnahme gilt bewusst nur für den EINEN eigenen Namen. Alle anderen geschützten
    Namen bleiben auch hier verboten: ein Kundenprojekt darf seinen eigenen Namen nennen,
    aber nicht den des nächsten Kunden.
    """
    muster = [re.compile(m, re.IGNORECASE) for m in policy["private_muster"]]
    # Der Domain-Anker seit 0.17.0: eine Subdomain ist nur dann ein Ausschnitt UNSERER
    # Karte, wenn sie unter EINER UNSERER Domains liegt. Das alte Muster fragte "dreiteilig?"
    # und traf damit jede fremde Website (135 Fehlalarme in einem Repo mit Normen-Katalog).
    eigene = frozenset(policy.get("eigene_domains_sha256_16", []))
    unter_eigener = re.compile(
        r"(?<![\w.@-])(?:[a-z0-9-]+\.)+([a-z0-9-]+)\.[a-z]{2,6}(?![\w-])", re.IGNORECASE)
    eigen = eigener_name_sha256 or []
    if isinstance(eigen, str):
        eigen = [eigen]
    namen = frozenset(policy["private_namen_sha256_16"]) - {h.lower() for h in eigen}
    erlaubt = re.compile(
        policy["erlaubte_identitaet"].format(projekte="|".join(re.escape(p) for p in projekte)),
        re.IGNORECASE)
    wort = re.compile(r"[a-z][a-z0-9-]{3,}")

    treffer = []
    for rel, inhalt in _texte(root, dateien, policy):
        for n, zeile in enumerate(zeilen_wie_grep(inhalt), 1):
            sauber = erlaubt.sub("", zeile)
            for pat in muster:
                if pat.search(sauber):
                    treffer.append(f"{rel}:{n}: {zeile.strip()[:60]}")
            # Auch die BESTANDTEILE einer Zusammensetzung pruefen.
            #
            # WARUM (2026-09-23, am eigenen Fehler gemessen): `wort` nimmt den Bindestrich
            # INS Wort (`[a-z][a-z0-9-]{3,}`). Ein Kundenname in einer Zusammensetzung —
            # `<kunde>-Session`, `<kunde>-deploy`, `<kunde>-stack` — ist damit ein anderes
            # Wort, dessen Hash nicht in der Liste steht, und rutscht durch.
            #
            # Belegt an meinem eigenen Fehler: Ich habe an einem Abend sechsmal einen
            # Kundennamen in der Form `<Kunde>-Session` in `hygiene_policy.json` geschrieben
            # — eine Datei, die `repokit sync` in SECHS oeffentliche Repos kopiert. Der Zaun
            # schwieg jedes Mal. Der blanke Name allein loeste aus, die Zusammensetzung nie.
            #
            # *Ein Zaun, der nur den Normalfall kennt, faengt den Fall nicht, in dem der Name
            # beilaeufig vorkommt — und beilaeufig ist er meistens.*
            kandidaten = set()
            for w in wort.findall(sauber.lower()):
                kandidaten.add(w)
                kandidaten.update(t for t in w.split("-") if len(t) >= 4)
            for w in sorted(kandidaten):
                if hashlib.sha256(w.encode()).hexdigest()[:16] in namen:
                    treffer.append(f"{rel}:{n}: verbotener Name")
            for m in unter_eigener.finditer(sauber):
                eltern = m.group(1).lower()
                # `www.<eigene>` ist der Alias der Website, kein Dienst.
                if _ist_eigene_identitaet(m.group(0), policy):
                    continue
                if hashlib.sha256(eltern.encode()).hexdigest()[:16] in eigene:
                    treffer.append(f"{rel}:{n}: Dienst-Subdomain unter eigener Domain")
    return treffer


def _geheimnis_regeln(policy: dict):
    """(Formate, Zuweisungsmuster, Platzhalter) — einmal kompiliert.

    Die Gross-/Kleinschreibung ist je Liste ANDERS und das ist Absicht:

    * **Formate** case-SENSITIV. `ghp_`, `AKIA`, `-----BEGIN … PRIVATE KEY` sehen genau so
      aus und nicht anders. Mit `IGNORECASE` wuerde `AKIA[0-9A-Z]{16}` mitten in einem
      Base64-Block anschlagen — ein Fehlalarm, den niemand nachvollziehen kann.
    * **Zuweisung** case-INSENSITIV. Der Name heisst mal `PAPERLESS_TOKEN`, mal
      `client_secret`, mal `Api-Key`.
    * **Platzhalter** case-SENSITIV. Die erste Regel ist „NUR Grossbuchstaben" — mit
      `IGNORECASE` wuerde sie auf jeden Kleinbuchstaben-Wert passen und den Waechter
      lautlos abschalten.
    """
    formate = [re.compile(m) for m in policy["geheimnis_formate"]]
    zuweisung = re.compile(policy["geheimnis_zuweisung"], re.IGNORECASE)
    platzhalter = [re.compile(m) for m in policy["geheimnis_platzhalter"]]
    return formate, zuweisung, platzhalter


def ist_platzhalter(wert: str, platzhalter: list) -> bool:
    """Ist der zugewiesene Wert ein Platzhalter und damit kein Geheimnis?

    Belegter Anlass (2026-09-22): `REPLACE_ME_TOKEN` und `REPLACE_ME_NETBIRD_SETUP_KEY`
    aus einem Backup wurden von einem laengenbasierten Muster als Geheimnisse gemeldet,
    und der Fehlalarm wanderte zweimal bis zum PO. Ein Waechter, dem man nicht glaubt,
    wird abgeschaltet — Fehlalarme kosten genauso viel wie uebersehene Luecken.
    """
    return any(p.match(wert) for p in platzhalter)


def _wert_ist_aufruf(zeile: str, treffer) -> bool:
    """Steht rechts ein AUFRUF statt eines Literals? — dann wird der Wert zur Laufzeit erzeugt.

    WARUM (2026-09-22, an einem PHP-Repo gemessen):

        $token = DefectReporterContact::generateStatusToken();

    Hier steht kein Geheimnis, sondern ein **Klassenname** vor einem statischen Aufruf —
    lang genug, um das Zuweisungsmuster auszuloesen. Gleiche Familie wie der Enum-Fall.

    ⚠️ Bewusst ueber den KONTEXT geloest, nicht ueber eine Platzhalter-Regel. Der erste
    Versuch war `^[A-Za-z_][A-Za-z0-9_]*$` als Platzhalter — und liess prompt JWT, Passwort
    und ein Zeichen-Gemisch durch, weil eine Regel, die nur den WERT sieht, einen Bezeichner
    nicht von einem Geheimnis ohne Sonderzeichen unterscheiden kann. Die Negativtests haben
    das gefangen; ohne sie waere ein Loch in den Geheimnis-Zaun gerissen worden.

    Entscheidend ist, was dem Wert FOLGT: `::`, `->` oder `(` sind Code, nie Teil eines
    abgelegten Geheimnisses.
    """
    rest = zeile[treffer.end("wert"):treffer.end("wert") + 4]
    return rest.startswith(("::", "->", "(", "()"))


def zeilen_wie_grep(inhalt: str) -> list[str]:
    """Zeilen so schneiden, wie Editor, `grep` und der Mensch sie zaehlen: nur an ``\n``.

    WARUM NICHT ``splitlines()`` (Register 2026-09-23, behoben 2026-09-24):
    ``str.splitlines()`` trennt auch an U+2028 (LINE SEPARATOR), U+2029, U+0085, ``\v``,
    ``\f`` und U+001C-1E. Steht eines davon irgendwo VOR einem Treffer, meldet der Waechter
    eine Zeilennummer, die es im Editor nicht gibt — gemessen an
    ``tests/test_audit_runde2.py``: gemeldet ``:1610``, gemeint war 1606. Der Befund war
    richtig, nur der Ort verschoben, und man sucht an der falschen Stelle. Ein Waechter, der
    den Fundort falsch nennt, kostet genau das Vertrauen, das er aufbauen soll.

    ``rstrip("\r")`` haelt CRLF-Dateien sauber: ohne das truege jede Zeile ein ``\r`` am
    Ende und ein Muster mit ``$`` wuerde nicht mehr passen.
    """
    return [z.rstrip("\r") for z in inhalt.split("\n")]


def geheimnis_zeilen(inhalt: str, policy: dict) -> list[tuple[int, str]]:
    """(Zeilennummer, Art) je verdaechtiger Zeile. **Nie der Wert.**

    Der Rueckgabewert nennt bewusst nur die Art des Treffers. Wer den Fund weiterreicht
    — Bericht, Mail, Log — reicht damit kein Geheimnis weiter. Genau daran ist es am
    2026-09-21 schon einmal gescheitert: ein unzureichend maskierter Fund landete im
    Sitzungsprotokoll und der Wert galt ab da als verbrannt.
    """
    formate, zuweisung, platzhalter = _geheimnis_regeln(policy)
    treffer = []
    for n, zeile in enumerate(zeilen_wie_grep(inhalt), 1):
        for pat in formate:
            if pat.search(zeile):
                treffer.append((n, "Format"))
                break
        else:
            m = zuweisung.search(zeile)
            if m and not ist_platzhalter(m.group("wert"), platzhalter) \
                  and not _wert_ist_aufruf(zeile, m):
                treffer.append((n, "Zuweisung"))
    return treffer


def pruefe_geheimnisse(root: str, dateien: list[str], policy: dict) -> list[str]:
    """Keine Tokens, Schluessel oder Passwoerter im Klartext.

    Vereinigt zwei Ansaetze: Credential-**Formate** (`ghp_`, `gho_`, `github_pat_`, PEM,
    `AKIA`, `sk-…`, `PVEAPIToken=`) fangen einen versehentlich eingecheckten Schluessel
    auch ohne Zuweisung; das **Zuweisungsmuster** faengt `token = "…"` — seit 2026-09-22
    auch ohne Anfuehrungszeichen (`PAPERLESS_TOKEN: 23f9…`), weil genau diese Form in den
    47 dokumentierten Fundstellen ueberwog und durch JEDEN der fuenf Waechter fiel.

    Gescannt wird jede lesbare Datei, nicht nur bekannte Endungen — ein `.pem` fiele sonst
    schon durch die Dateiauswahl.

    Der Befund nennt Datei, Zeile und Art. **Nie den Wert.**
    """
    treffer = []
    for rel, inhalt in _texte(root, dateien, policy):
        for n, art in geheimnis_zeilen(inhalt, policy):
            treffer.append(f"{rel}:{n}: {art}")
    return treffer


# ---------------------------------------------------------------------------
# Adapter: dieselbe Policy fuer die Nicht-Python-Repos
# ---------------------------------------------------------------------------
def _ere(muster: str, ignoriere_gross_klein: bool = False) -> str:
    """Python-Regex -> POSIX-ERE, wie `grep -E` es versteht.

    WARUM ES DEN ADAPTER GIBT (2026-09-22): Es gab fuenf unabhaengige Fassungen derselben
    Pruefung, und ihre Luecken waren komplementaer — `ci-infra` kannte `gho_` und
    `github_pat_`, aber kein PEM-Muster; ausgerechnet das Repo mit den Runner-Bauanleitungen
    haette einen eingecheckten SSH-Schluessel nicht gesehen. `ansible-deploy` kannte
    `PVEAPIToken`, aber keinen GitHub-Token. Seither ist `hygiene_policy.json` die eine
    Quelle, und die Shell-Repos bekommen ihre Musterdatei daraus erzeugt.

    Drei Uebersetzungen, mehr braucht es nicht:

    * `(?:` und `(?P<name>` -> `(` — ERE kennt keine nicht-fangenden und keine benannten
      Gruppen. Die Gruppen selbst bleiben, sie aendern das Treffverhalten nicht.
    * `\t` -> ein echtes Tabulatorzeichen. In einer ERE-Klammerklasse bedeutet `\t`
      **Backslash oder t**, nicht Tabulator — `[ \t]*` haette also klaglos auf jedes `t`
      gepasst.
    * Buchstaben -> `[aA]`, wenn das Muster in Python mit `IGNORECASE` laeuft. `grep -i`
      waere der bequeme Weg, wuerde aber ALLE Muster einer Datei aufweichen; `AKIA`
      duerfte das nicht.

    Zeichenklassen bleiben unangetastet (sie sind bereits vollstaendig geschrieben),
    Escape-Sequenzen ebenso.
    """
    aus = []
    i, in_klasse = 0, False
    while i < len(muster):
        c = muster[i]
        if c == "\\" and i + 1 < len(muster):
            aus.append("\t" if muster[i + 1] == "t" else muster[i:i + 2])
            i += 2
            continue
        if in_klasse:
            if c == "]":
                in_klasse = False
            aus.append(c)
            i += 1
            continue
        if c == "[":
            in_klasse = True
            aus.append(c)
            i += 1
            continue
        if muster.startswith("(?:", i):
            aus.append("(")
            i += 3
            continue
        if muster.startswith("(?P<", i):
            aus.append("(")
            i = muster.index(">", i) + 1
            continue
        if ignoriere_gross_klein and c.isalpha() and c.isascii():
            aus.append(f"[{c.lower()}{c.upper()}]")
            i += 1
            continue
        aus.append(c)
        i += 1
    return "".join(aus)


def grep_muster(policy: dict) -> list[str]:
    """Die Suchmuster fuer `grep -nIE -f` — Formate und Zuweisung, aus derselben Policy."""
    return [_ere(m) for m in policy["geheimnis_formate"]] + \
           [_ere(policy["geheimnis_zuweisung"], ignoriere_gross_klein=True)]


def grep_ausnahmen(policy: dict) -> list[str]:
    """Die Gegenliste fuer `grep -vE -f`: Zuweisungen, deren Wert ein Platzhalter ist.

    ⚠️ **Die Ausnahme muss den NAMEN mitnehmen, nicht nur den Wert** — sonst schaltet sie
    den Waechter ab. Erster Entwurf am 2026-09-22 nahm nur das Wertmuster und liess es auf
    die ganze Zeile los: `[A-Z][A-Z0-9_]*` passt dann auf `PAPERLESS_TOKEN` selbst, und
    ausgerechnet die Zeile mit dem echten Token waere als „Platzhalter" verworfen worden.
    Darum steht hier der komplette Zuweisungskopf aus der Policy davor und das Wertmuster
    direkt dahinter.

    Der Unterschied zur Python-Fassung bleibt und ist ehrlich zu benennen: `grep`
    entscheidet je ZEILE, Python je WERT. Eine Zeile mit einem echten Geheimnis *und*
    einem Platzhalter faellt in der Shell-Fassung durch. Die Python-Repos haben die
    genaue Fassung.
    """
    kopf = policy["geheimnis_zuweisung"].split("(?P<wert>")[0]
    schwanz = "([^A-Za-z0-9/+_.=~-]|$)"
    aus = []
    for m in policy["geheimnis_platzhalter"]:
        kern = m[1:] if m.startswith("^") else m
        kern = kern[:-1] if kern.endswith("$") else kern
        aus.append(_ere(kopf, ignoriere_gross_klein=True) + _ere(kern) + schwanz)
    return aus


def _ist_generiert(rel: str, policy: dict) -> bool:
    """Schreibt ein WERKZEUG diese Datei? — dann sind fremde Adressen darin unvermeidlich.

    Lock-Dateien und IDE-Helfer tragen Adressen Dritter (packagist.org, tools.ietf.org …).
    Wer sie "neutral macht", bricht die Datei. Gemessen 2026-09-23: ~1400 Adress-Treffer in
    einem PHP-Repo, fast alle aus `composer.lock` und `_ide_helper.php`.

    ⚠️ Gilt NUR fuer Adressen. `pruefe_geheimnisse` nimmt diese Dateien ausdruecklich NICHT
    aus: ein Token in einer Lock-Datei ist trotzdem ein Token — und dort schaut niemand hin.
    """
    return any(re.search(m, rel) for m in policy.get("generierte_dateien", []))


def _ist_belegstelle(rel: str, belegstellen: list[str] | None) -> bool:
    """Verzeichnis, das NUR Fundstellen enthaelt — Normen, Gesetze, Quellenverzeichnisse.

    Wie `_ist_generiert`, andere Begruendung: der Inhalt kommt von Dritten, und wer eine
    Gesetzesfundstelle anonymisiert, zerstoert den Beleg.

    ⚠️ Gilt NUR fuer Adressen, nicht fuer `pruefe_geheimnisse`. Und ein Muster ist so eng wie
    moeglich — `pruefe_belegstellen_eng` prueft das, weil ein zu weites Muster den naechsten
    echten Befund mit derselben Bewegung verdeckt, mit der es die Fehlalarme entfernt.
    """
    return any(re.search(m, rel) for m in (belegstellen or []))


def _ist_eigene_identitaet(host: str, policy: dict) -> bool:
    r"""Die NACKTE eigene Domain (und ihr `www`) ist Identitaet, keine Karte.

    WARUM (2026-09-23, gemeldet aus einem Kundenrepo): `eigene_domains_sha256_16` las bis
    dahin nur `pruefe_private_infrastruktur`. Die Adresspruefungen kannten die Liste nicht und
    meldeten die eigene Produktdomain als fremden Host — 8 von 96 verbliebenen Treffern in einem
    Kundenrepo.

    Die beiden Pruefungen brauchen die Liste in ENTGEGENGESETZTER Richtung, und genau das macht
    sie wertvoll:

    | | eigene Domain | fremde Domain |
    |---|---|---|
    | `pruefe_private_infrastruktur` | Subdomain darunter = ROT | egal wie viele Punkte = gruen |
    | `pruefe_adressen` | nackte Form = GRUEN (Identitaet) | je nach Kontext |

    ⚠️ **Warum NICHT `erlaubte_hosts`:** Diese Liste ist eine Subdomain-Wildcard
    (`(?:^|\.)…$`) — ein Eintrag dort haette `test.<eigene-domain>` still mitfreigegeben, also
    genau den Fund, fuer den der Domain-Anker gebaut wurde. Die falsche Tuer, mit demselben
    Ergebnis wie die alte `erlaubte_hosts`-Verdeckungsfalle.

    **`www` gilt mit, und das ist eine KEHRTWENDE gegenueber 0.17.0**, wo `www.<eigene>` bewusst
    rot war. Die Begruendung damals: "seit dem Domain-Anker ist `www` genauso eine Subdomain wie
    jede andere". Das war formal richtig und sachlich falsch. Die Hausregel trennt nicht nach der
    Form, sondern nach der Sache: erlaubt ist, was zur **Identitaet** gehoert (Autor,
    Impressums-Mail, Repo-URL, Projektname), verboten ist, was einen **Dienst** verraet. `www` ist
    kein Dienst, sondern der kanonische Alias der Website selbst — meist ein Redirect auf die
    nackte Domain, und die steht im Impressum. `paperless.<eigene>` verraet, wo ein Paperless
    laeuft; `www` verraet nichts, was das Impressum nicht schon sagt.

    (Nicht zu verwechseln mit dem `www`-Behelf aus 0.16.0: der stand fuer FREMDE Domains und
    existierte nur, weil das Muster Namensteile zaehlte. Der ist mit 0.17.0 entfallen und kommt
    nicht zurueck. Hier geht es um EIGENE Domains und um die Sache, nicht um die Punktzahl.)
    """
    eigene = frozenset(policy.get("eigene_domains_sha256_16", []))
    if not eigene:
        return False
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return False
    if hashlib.sha256(labels[-2].encode()).hexdigest()[:16] not in eigene:
        return False
    # Nackt (`domain.tld`) oder genau `www.domain.tld` — jede andere Subdomain ist ein Dienst.
    return labels[:-2] in ([], ["www"])


# Ladende Elemente: was der Browser VON SICH AUS holt, weil es im Markup steht.
# Ein `href` gilt NUR bei `<link>` — bei `<a>` nie. Siehe Docstring unten, warum das
# der ganze Trick ist.
_FREMD_MUSTER: list[tuple[str, re.Pattern[str]]] = [
    ("src=", re.compile(r"""\bsrc(?:set)?\s*=\s*["']\s*(https?:)?//([a-z0-9.-]+)""", re.I)),
    ("<link href=", re.compile(
        r"""<link\b(?:[^>]*?\s)?href\s*=\s*["']\s*(https?:)?//([a-z0-9.-]+)""", re.I | re.S)),
    ("css url()", re.compile(r"""url\(\s*["']?\s*(https?:)?//([a-z0-9.-]+)""", re.I)),
    ("@import", re.compile(r"""@import\s+(?:url\()?\s*["']\s*(https?:)?//([a-z0-9.-]+)""", re.I)),
    ("fetch()/import()", re.compile(
        r"""(?:\bfetch|\bimport)\s*\(\s*["'`]\s*(https?:)?//([a-z0-9.-]+)""", re.I)),
    ("<iframe src=", re.compile(r"""<iframe\b[^>]*?\bsrc\s*=\s*["']\s*(https?:)?//([a-z0-9.-]+)""",
                               re.I | re.S)),
]

# XML-Namensraeume sind keine Ressourcenabrufe — der Browser laedt sie nie.
_NAMENSRAUM = re.compile(r"w3\.org/(?:2000/svg|1999/xhtml|1999/xlink|XML/1998/namespace)", re.I)


def pruefe_keine_fremdressourcen(root: str, dateien: list[str], policy: dict,
                                 ausgenommen: dict[str, str] | None = None) -> list[str]:
    """Holt der Browser eines Besuchers etwas von Dritten, weil es in UNSEREM Markup steht?

    WARUM (PO-Regel 2026-09-23, `context/fremdressourcen.md`): Eine Fremdanforderung uebertraegt
    die IP eines Besuchers an einen Dritten, den er nicht kennt und nicht gefragt wurde — allein
    durch den Seitenaufruf, ohne Klick. Das LG Muenchen I hat dafuer Schadensersatz zugesprochen
    (20.01.2022, 3 O 17493/20, dynamisch nachgeladene Schriften), und die Begruendung war: ein
    berechtigtes Interesse scheidet aus, **weil die lokale Einbindung moeglich ist**.

    Dazu zwei Gruende, die ohne Recht auskommen: der Dritte kann ausfallen, umziehen oder die Datei
    stillschweigend austauschen — und was fremd eingebunden ist, steht in keiner Lock-Datei, also
    sieht es kein Dependabot, keine Integritaetspruefung, kein CHANGELOG.

    ⚠️ **DER GANZE TRICK IST DIE TRENNLINIE, und sie entscheidet, ob die Pruefung ueberlebt.**

        Ein Link ist eine Tuer. Ein `src` ist ein Bote, den wir ungefragt losschicken.

    Beanstandet wird nur, wer den Abruf **von sich aus** ausloest: `src`/`srcset`, `<link href>`,
    `url()`, `@import`, `fetch()`/`import()`, `<iframe src>`. **Ein `<a href>` NIE** — Impressum,
    Quellenangaben, Norm-Fundstellen und Badges sind erlaubt und teils rechtlich geboten. Eine
    Pruefung, die Impressumslinks anmeckert, wird nach dem dritten Fehlalarm abgeschaltet, und dann
    schuetzt sie gar nichts mehr. Deshalb prueft `_FREMD_MUSTER` `href` ausdruecklich nur innerhalb
    von `<link …>`.

    **Markdown ist ausgenommen**, und zwar begruendet, nicht aus Bequemlichkeit: eine `README.md`
    wird nicht von uns ausgeliefert, sondern von der Plattform gerendert, die Bilder ohnehin ueber
    ihren eigenen Proxy holt — und die Regel nennt Badges im README ausdruecklich erlaubt.

    `ausgenommen` ist ein dict `{"<pfad>:<host>": "Grund (Ablaufdatum)"}`. Ein Grund ist Pflicht.
    ⚠️ Es gibt Dinge, die man nicht selbst ausliefern KANN (Zahlungs-Widget, Captcha, Kartendienst
    mit Schluessel) — dafuer ist das dict da. Es ist NICHT dafuer da, einen Hotlink zu dulden, der
    sich herunterladen liesse: *eine Freigabe fuer eine Stelle, die man beseitigen koennte, ist
    keine Ausnahme, sondern eine Billigung, und sie deckt jeden weiteren Hotlink mit ab.*
    Solche Freigaben fallen **mit** der Ursache, nicht nach ihr — im selben Commit.

    **Was diese Pruefung NICHT sieht** (benannte Grenze, damit niemand sie fuer vollstaendig haelt):
    Adressen, die JavaScript zur Laufzeit zusammenbaut. Der Quelltext sieht nicht, was der Browser
    am Ende anfordert. Dafuer braucht es den zweiten Blickwinkel — die laufende Seite mit einem
    CDP-Netzwerkprotokoll, jede tatsaechlich angeforderte Herkunft gegen eine Liste. Das gehoert in
    die Browser-Tests, nicht hierher. Beide Blickwinkel sind noetig, keiner ersetzt den anderen.
    """
    ausgenommen = ausgenommen or {}
    treffer = []
    for schluessel, grund in sorted(ausgenommen.items()):
        if not str(grund).strip():
            treffer.append(f"Ausnahme {schluessel!r} ohne Begruendung — ein Grund ist Pflicht")

    eigene = frozenset(policy.get("eigene_domains_sha256_16", []))
    endungen = (".html", ".htm", ".css", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".vue",
                ".php", ".j2", ".jinja", ".jinja2", ".twig", ".erb", ".hbs", ".svg")
    benutzt = set()
    for rel, inhalt in _texte(root, dateien, policy):
        if not rel.endswith(endungen) or _ist_generiert(rel, policy):
            continue
        for art, pat in _FREMD_MUSTER:
            for m in pat.finditer(inhalt):
                host = m.group(2).lower()
                umfeld = inhalt[max(0, m.start() - 60):m.end() + 60]
                if _NAMENSRAUM.search(umfeld):
                    continue
                # Eigener Ursprung ist kein Dritter.
                if _ist_eigene_identitaet(host, policy) or host in ("localhost", "127.0.0.1"):
                    continue
                labels = host.split(".")
                if len(labels) >= 2 and hashlib.sha256(
                        labels[-2].encode()).hexdigest()[:16] in eigene:
                    continue
                schluessel = f"{rel}:{host}"
                if schluessel in ausgenommen:
                    benutzt.add(schluessel)
                    continue
                zeile = inhalt[:m.start()].count("\n") + 1
                treffer.append(
                    f"{rel}:{zeile}: {art} laedt von {host} — der Browser des Besuchers "
                    f"holt das von sich aus und uebertraegt dabei seine IP an einen Dritten. "
                    f"Selbst ausliefern (Lizenz pruefen, Nachweis daneben) oder nicht verwenden")

    for schluessel in sorted(set(ausgenommen) - benutzt):
        treffer.append(f"Ausnahme {schluessel!r} trifft nichts mehr — die Stelle ist weg. "
                       f"Eintrag entfernen, sonst deckt er den naechsten Fall ab")
    return sorted(set(treffer))


def pruefe_adressen(root: str, dateien: list[str], policy: dict,
                    zusaetzliche_hosts: list[str] | None = None,
                    belegstellen: list[str] | None = None) -> list[str]:
    """Nur neutrale Beispieladressen (RFC 2606) in Doku und Code."""
    hosts = list(policy["erlaubte_hosts"]) + list(zusaetzliche_hosts or [])
    erlaubt = re.compile(r"(?:^|\.)(?:" + "|".join(hosts) + r")$", re.IGNORECASE)
    url = re.compile(r"https?://([a-z0-9.-]+)", re.IGNORECASE)
    treffer = []
    for rel, inhalt in _texte(root, dateien, policy):
        if _ist_generiert(rel, policy) or _ist_belegstelle(rel, belegstellen):
            continue
        for host in url.findall(inhalt):
            # Regex-Literale im Frontend enthalten "https?://" ohne echten Host.
            if "." not in host or not re.search(r"[a-z]", host, re.IGNORECASE):
                continue
            if _ist_eigene_identitaet(host, policy):
                continue
            if not erlaubt.search(host):
                treffer.append(f"{rel}: {host}")
    return treffer


def ohne_yaml_kommentar(zeile: str) -> str:
    """Schneidet den YAML-Kommentar ab und gibt nur den Code-Teil zurück.

    Ein `#` beginnt einen Kommentar nur, wenn ihm Zeilenanfang oder Leerraum vorausgeht
    und er nicht in Anführungszeichen steht (`run: echo "a # b"` ist kein Kommentar).
    """
    quote = ""
    for i, c in enumerate(zeile):
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "#" and (i == 0 or zeile[i - 1] in " \t"):
            return zeile[:i]
    return zeile


def pruefe_kein_self_hosted_runner(root: str, dateien: list[str]) -> list[str]:
    """Öffentliche Repos laufen auf `ubuntu-latest`.

    Ein self-hosted Runner führt bei einem Fork-PR fremden Code auf eigener Hardware aus,
    und die Runner sind nicht ephemer. GitHub rät ausdrücklich ab.

    Geprüft wird der **Code** jeder Zeile, der Kommentar dahinter nicht: sonst schlug
    `runs-on: ubuntu-latest  # niemals self-hosted (Fork-PRs)` an — eine Zeile, die die
    Regel *befolgt* und *begründet* (Fehlalarm, gefunden 2026-09-19). Der Kommentar ist
    die **einzige** Ausnahme; das Label bleibt überall sonst verboten, auch in Listenform
    (`runs-on: [self-hosted, linux]`), als mehrzeilige Liste und in einer Matrix, aus der
    `runs-on` sich bedient. Ein Wert soll nie erlaubt werden, nur weil er woanders steht.
    """
    treffer = []
    for rel in dateien:
        if not rel.startswith(".github/workflows/"):
            continue
        inhalt = _lies(root, rel) or ""
        for n, zeile in enumerate(zeilen_wie_grep(inhalt), 1):
            if "self-hosted" in ohne_yaml_kommentar(zeile):
                treffer.append(f"{rel}:{n}")
    return treffer


def pruefe_versionsgleichstand(root: str, weitere: dict[str, str] | None = None) -> list[str]:
    """`pyproject.toml`, CHANGELOG und optionale weitere Quellen nennen dieselbe Version.

    `weitere` bildet Datei -> Regex mit genau einer Gruppe ab, z.B.
    {"tinysesam/__init__.py": r'^__version__ = "([^"]+)"'}
    """
    fehler = []
    pyproject = _lies(root, "pyproject.toml") or ""
    treffer = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if not treffer:
        return ["pyproject.toml nennt keine version"]
    version = treffer.group(1)

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        fehler.append(f"Version ist kein SemVer: {version}")

    changelog = _lies(root, "CHANGELOG.md") or ""
    if f"[{version}]" not in changelog and f"## {version}" not in changelog:
        fehler.append(f"CHANGELOG kennt Version {version} nicht")

    for datei, regex in (weitere or {}).items():
        inhalt = _lies(root, datei)
        if inhalt is None:
            fehler.append(f"{datei} fehlt")
            continue
        m = re.search(regex, inhalt, re.M)
        if not m:
            fehler.append(f"{datei} nennt keine Version")
        elif m.group(1) != version:
            fehler.append(f"{datei}={m.group(1)} aber pyproject={version}")
    return fehler


def pruefe_run_all_sammelt_automatisch(root: str) -> list[str]:
    """Eine Suite, die niemand aufruft, prüft nichts."""
    runner = _lies(root, "tests/run_all.py")
    if runner is None:
        return ["tests/run_all.py fehlt"]
    if "glob(" not in runner and "glob.glob" not in runner and "iterdir" not in runner:
        return ["run_all.py sammelt die Suiten nicht automatisch"]
    return []


def pruefe_ausfuehrbar(root: str, pfade: list[str]) -> list[str]:
    treffer = []
    for rel in pfade:
        voll = os.path.join(root, rel)
        if not os.path.exists(voll):
            treffer.append(f"{rel} fehlt")
        elif not os.stat(voll).st_mode & 0o111:
            treffer.append(f"{rel} ist nicht ausführbar")
    return treffer


def pruefe_pflichtdateien(root: str, namen: list[str]) -> list[str]:
    return [n for n in namen if not os.path.exists(os.path.join(root, n))]


# ---------------------------------------------------------------------------
# Belegte Standards, hier maschinell erzwungen. Quellen: context/repo-standards.md
# ---------------------------------------------------------------------------
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")


def pruefe_actions_sha_gepinnt(root: str, dateien: list[str]) -> list[str]:
    """Fremde Actions müssen auf einen vollen Commit-SHA gepinnt sein, nicht auf einen Tag.

    GitHub: „Pinning an action to a full-length commit SHA is currently the only way to use
    an action as an immutable release." Ein Tag lässt sich verschieben — wer Zugriff auf das
    Action-Repo erlangt, zieht unbemerkt fremden Code in jeden Workflow.

    Ausgenommen: lokale Actions (`./…`) und `docker://`-Referenzen.
    """
    treffer = []
    for rel in dateien:
        if not rel.startswith(".github/workflows/") or not rel.endswith((".yml", ".yaml")):
            continue
        inhalt = _lies(root, rel) or ""
        for n, zeile in enumerate(zeilen_wie_grep(inhalt), 1):
            m = _USES.match(zeile)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            if "@" not in ref:
                treffer.append(f"{rel}:{n}: {ref} — ohne Ref")
                continue
            pin = ref.rsplit("@", 1)[1]
            if not _SHA40.match(pin):
                treffer.append(f"{rel}:{n}: {ref} — Tag statt Commit-SHA")
    return treffer


def pruefe_workflow_permissions(root: str, dateien: list[str]) -> list[str]:
    """Jeder Workflow setzt `permissions:` — mindestens auf oberster Ebene.

    Es gibt keinen sicheren Default: die Ausgangsberechtigung des GITHUB_TOKEN kommt aus der
    Repo-Einstellung. Sobald EINE Berechtigung explizit gesetzt ist, fallen alle übrigen auf
    `none`. Ein Workflow ohne `permissions:` erbt also, was auch immer eingestellt ist.
    """
    treffer = []
    for rel in dateien:
        if not rel.startswith(".github/workflows/") or not rel.endswith((".yml", ".yaml")):
            continue
        inhalt = _lies(root, rel) or ""
        # Auf oberster Ebene = ohne Einrückung.
        if not re.search(r"^permissions:", inhalt, re.M):
            treffer.append(f"{rel}: kein `permissions:` auf oberster Ebene")
    return treffer


def pruefe_kein_abbruch_auf_default_branch(root: str, dateien: list[str],
                                           default_branch: str = "main") -> list[str]:
    """`cancel-in-progress` darf auf dem Default-Branch nicht unbedingt `true` sein.

    Auf einem Feature-Branch ist der Abbruch richtig — dort zählt nur der letzte Stand.
    Auf dem Default-Branch hängt am Lauf aber das Abbild oder ein Required Status Check:
    ein abgebrochener Commit hat hinterher keines, und das fällt erst auf, wenn jemand
    genau diesen Commit ausrollen oder nachvollziehen will.

    Der Schaden ist belegt, nicht theoretisch: paperlaiss verlor am 2026-09-21 vier
    main-Läufe innerhalb von 33 Sekunden, DashMyBoard drei am 2026-07-10.

    Richtig ist der Ausdruck, nicht ein pauschales `false`:

        cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}

    Geprüft wird nur, wo es zählt: ein Workflow, der gar nicht auf den Default-Branch
    pusht (reine `pull_request`-Workflows), darf unbedingt abbrechen.
    """
    treffer = []
    for rel in dateien:
        if not rel.startswith(".github/workflows/") or not rel.endswith((".yml", ".yaml")):
            continue
        inhalt = _lies(root, rel) or ""
        m = re.search(r"^\s*cancel-in-progress:\s*(.+?)\s*$", inhalt, re.M)
        if not m:
            continue
        wert = ohne_yaml_kommentar(m.group(1)).strip().strip("'\"")
        if wert.lower() != "true":
            continue          # `false` oder ein Ausdruck -> die Entscheidung ist getroffen
        # Läuft der Workflow überhaupt AUF dem Default-Branch? Ein `branches:` unter
        # `pull_request:` meint PRs GEGEN den Branch, nicht Läufe auf ihm — deshalb wird
        # der push-Block gesucht und nicht bloß der Branch-Name irgendwo im Text.
        push = re.search(r"^\s{2,}push:\s*$(.*?)(?=^\s{2,}\w+:\s*$|^\w)", inhalt,
                         re.M | re.S)
        laeuft_auf_default = bool(push and re.search(rf"\b{re.escape(default_branch)}\b",
                                                     push.group(1)))
        if laeuft_auf_default:
            treffer.append(
                f"{rel}: `cancel-in-progress: true` gilt auch auf {default_branch} — "
                f"nimm ${{{{ github.ref != 'refs/heads/{default_branch}' }}}}")
    return treffer


# ---------------------------------------------------------------------------
# Die Python-Matrix — eine Quelle, drei Prüfungen (2026-09-22)
#
# Bis heute stand die Matrix an drei Stellen gleichzeitig: im Abbild
# (`/opt/ci-matrix`), in jeder `ci.yml` und implizit in `requires-python`. Gemessen am
# 2026-09-21 waren alle drei verschieden — das Abbild fuhr 3.10/3.12/3.14, die ci.yml
# 3.10/3.12/3.13, `requires-python` sagte `>=3.10`. Jede Stelle fuer sich sah richtig
# aus; zusammen war die Zusage "wir testen, was wir versprechen" unbelegt.
#
# `python_matrix.json` ist die Quelle fuer alles, was in einem FREMDEN Klon und auf
# `ubuntu-latest` gelten muss. Das Abbild fuehrt dieselbe Matrix in `/opt/ci-matrix`;
# das ist Absicht und keine Dublette — eine Datei im Abbild ist zur Testzeit eines
# oeffentlichen Repos nicht erreichbar, und ein Kit, das zur Laufzeit ins Netz greift,
# waere genau das Leck, das dieses Repo verhindern soll.
# ---------------------------------------------------------------------------
_MATRIX_SCHLUESSEL = ("python", "python-version", "python_version")


def lade_python_matrix(pfad: str | None = None) -> dict:
    with open(pfad or os.path.join(HIER, "python_matrix.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _als_zahlen(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _matrix_listen(inhalt: str) -> list[tuple[int, str, list[str]]]:
    """Alle Versionslisten unter einem `matrix:`-Block. -> (zeile, schluessel, werte)

    Ohne YAML-Parser (stdlib-only, und PyYAML fehlt auf mehr als einem Runner), dafuer
    eng gefuehrt: gesucht wird nur INNERHALB eines `matrix:`-Blocks, erkannt an der
    Einrueckung. Sonst faenge das Muster auch `python-version: ${{ matrix.python }}`
    in den Schritten — also genau die Zeile, die die Matrix korrekt benutzt.
    """
    treffer: list[tuple[int, str, list[str]]] = []
    zeilen = zeilen_wie_grep(inhalt)
    block_tiefe: int | None = None
    i = 0
    while i < len(zeilen):
        zeile = zeilen[i]
        nackt = zeile.strip()
        tiefe = len(zeile) - len(zeile.lstrip(" "))
        if nackt and not nackt.startswith("#"):
            if block_tiefe is not None and tiefe <= block_tiefe:
                block_tiefe = None
            if re.match(r"^matrix:\s*(#.*)?$", nackt):
                block_tiefe = tiefe
                i += 1
                continue
        if block_tiefe is not None:
            m = re.match(r"^(%s):\s*(.*)$" % "|".join(_MATRIX_SCHLUESSEL), nackt)
            if m:
                schluessel, rest = m.group(1), ohne_yaml_kommentar(m.group(2)).strip()
                if rest.startswith("["):
                    werte = re.findall(r"['\"]?(\d+\.\d+)['\"]?", rest)
                    treffer.append((i + 1, schluessel, werte))
                elif not rest:
                    # Blockform:  python:\n  - "3.12"
                    werte, j = [], i + 1
                    while j < len(zeilen):
                        eintrag = re.match(r"^\s*-\s*['\"]?(\d+\.\d+)['\"]?\s*(#.*)?$", zeilen[j])
                        if not eintrag:
                            break
                        werte.append(eintrag.group(1))
                        j += 1
                    if werte:
                        treffer.append((i + 1, schluessel, werte))
                        i = j
                        continue
        i += 1
    return treffer


def _setzt(inhalt: str, schluessel: str) -> bool:
    """Steht `<schluessel>: true` wirklich als Einstellung da — nicht bloss im Kommentar?

    TinySesams `ci.yml` erwaehnt `continue-on-error` in einem erklaerenden Kommentar;
    eine Textsuche haette den Gate-Workflow fuer einen Prerelease-Job gehalten und die
    ganze Matrix-Pruefung dort abgeschaltet. Dieselbe Klasse Fehler wie beim
    self-hosted-Waechter (Register 2026-09-19).
    """
    return bool(re.search(rf"^\s*{re.escape(schluessel)}:\s*true\s*(#.*)?$", inhalt, re.M))


def pruefe_python_matrix(root: str, dateien: list[str], quelle: dict | None = None) -> list[str]:
    """Die `python:`-Matrix jeder Workflow-Datei muss der gefuehrten Matrix entsprechen.

    Ein Repo, dessen Workflow eine andere Matrix faehrt als das Abbild, testet lokal
    etwas anderes als im Gate — und meldet beides gruen. Ein Workflow OHNE Matrix ist
    kein Verstoss: nicht jedes Repo ist ein Python-Repo, und ein Job, der bewusst auf
    genau einem Interpreter laeuft (Browser-Job, Release-Job), gehoert nicht in die
    Matrix.

    AUSNAHME PRERELEASE — und warum sie keine Hintertuer ist: Die Obergrenze wandert
    nur, wenn jemand die neue Version vorher fahren konnte. Dafuer gibt es den
    nightly-Job (`allow-prereleases: true`, `continue-on-error: true`). Er darf eine
    Version fahren, die nicht in der Matrix steht — aber NUR eine, die ueber der
    Obergrenze liegt, und nur, wenn er tatsaechlich nicht rot werden kann. Sonst waere
    das Muster genau der Weg, ein Gate-Bein in einem Job verschwinden zu lassen, der
    nie rot wird: die Zelle stuende weiter im Bericht, ihr Ausfall haette aber keine
    Folge mehr.
    """
    q = quelle or lade_python_matrix()
    soll, ober = q["matrix"], q["obergrenze"]["version"]
    treffer = []
    for rel in dateien:
        if not rel.startswith(".github/workflows/") or not rel.endswith((".yml", ".yaml")):
            continue
        inhalt = _lies(root, rel) or ""
        listen = _matrix_listen(inhalt)
        if not listen:
            continue
        if _setzt(inhalt, "allow-prereleases"):
            if not _setzt(inhalt, "continue-on-error"):
                treffer.append(f"{rel}: faehrt ein Prerelease, aber ohne "
                               f"`continue-on-error: true` — ein RC-Bug blockiert damit jeden Push")
            for n, schluessel, ist in listen:
                zu_tief = [v for v in ist if _als_zahlen(v) <= _als_zahlen(ober)]
                if zu_tief:
                    treffer.append(f"{rel}:{n}: {schluessel}: {zu_tief} liegt nicht ueber der "
                                   f"Obergrenze {ober} — ein Gate-Bein gehoert nicht in einen "
                                   f"Job, der nicht rot werden kann")
            continue
        for n, schluessel, ist in listen:
            if sorted(ist, key=_als_zahlen) != sorted(soll, key=_als_zahlen):
                treffer.append(f"{rel}:{n}: {schluessel}: {ist} — gefuehrt ist {soll} "
                               f"(tests/_kit/python_matrix.json)")
    return treffer


def pruefe_requires_python(root: str, quelle: dict | None = None,
                           datei: str = "pyproject.toml") -> list[str]:
    """`requires-python` muss die Untergrenze der Matrix nennen — nicht eine aeltere.

    Ein `>=3.10` bei einer Matrix ab 3.12 ist eine Zusage an jeden Installierenden,
    die nichts einloest: pip laesst das Paket auf 3.10 zu, geprueft hat es dort seit
    dem Matrix-Umbau niemand mehr.
    """
    pfad = os.path.join(root, datei)
    if not os.path.exists(pfad):
        return []
    soll = min((quelle or lade_python_matrix())["matrix"], key=_als_zahlen)
    with open(pfad, encoding="utf-8") as fh:
        inhalt = fh.read()
    m = re.search(r"^requires-python\s*=\s*['\"]([^'\"]+)['\"]", inhalt, re.M)
    if not m:
        return []
    ist = m.group(1).replace(" ", "")
    if ist != f">={soll}":
        return [f"{datei}: requires-python = \"{m.group(1)}\" — die Matrix beginnt bei "
                f"{soll}, also muss dort \">={soll}\" stehen"]
    return []


# ---------------------------------------------------------------------------
# Die Rolling-Regel: ein WAECHTER, keine Automatik (3.5)
#
# Die Regel lautet "die letzten drei stable Minors". Sie als Automatik zu bauen waere
# ein Fehler: am 01.10.2026 erscheint 3.15, und die Matrix zoege ungefragt nach — in
# ein Gate, an dem jeder Push haengt, mit Wheels, die es fuer cp315 noch nicht gibt.
# Deshalb meldet diese Pruefung nur.
#
# Die Daten stehen als gepflegte Liste in `python_matrix.json`. `endoflife.date` zur
# Testzeit abzufragen haette den Wolf zum Hueter gemacht: eine Suite, die Netz braucht,
# ist in einem fremden Klon nicht mehr lauffaehig — und ein Wert, der ueber das Netz
# kommt, laesst sich umhaengen.
#
# WARUM DIE FREIGABE EIN DATUM TRAEGT: Ohne Frist waere "3.15 ist da" eine Zeile, die
# niemand liest. Mit Frist wird die Suite rot, sobald ueber der Freigabe eine stabile
# Version steht UND das Pruefdatum verstrichen ist. Der Ausweg ist immer ein Satz in
# der JSON — Obergrenze heben ODER das Datum mit Begruendung verschieben. Was nicht
# geht, ist: nichts tun.
# ---------------------------------------------------------------------------
def _heute(heute: str | None) -> str:
    if heute:
        return heute
    import datetime
    return datetime.date.today().isoformat()


def pruefe_python_matrix_regel(quelle: dict | None = None,
                               heute: str | None = None) -> list[str]:
    """Widerspricht die gefuehrte Matrix der Rolling-Regel? (rot)"""
    q = quelle or lade_python_matrix()
    tag = _heute(heute)
    rel = q["releases"]
    matrix = q["matrix"]
    ober = q["obergrenze"]["version"]

    treffer = []
    if ober not in rel:
        return [f"obergrenze {ober} steht in keiner Release-Zeile"]

    # Die Liste selbst muss gepflegt sein: kennt sie keine Version, die noch NICHT
    # erschienen ist, dann ist sie hinter der Wirklichkeit — und jede Rechnung
    # darauf haette ein stilles Loch nach oben.
    if not any(d["erschienen"] > tag for d in rel.values()):
        treffer.append(f"die Release-Liste kennt am {tag} keine kuenftige Version mehr "
                       f"— sie ist ungepflegt (letzte: {max(rel, key=_als_zahlen)})")

    kaputt = False
    for v in matrix:
        if v not in rel:
            treffer.append(f"{v} steht in der Matrix, aber in keiner Release-Zeile")
            kaputt = True
        elif rel[v]["erschienen"] > tag:
            treffer.append(f"{v} steht in der Matrix, erscheint aber erst am "
                           f"{rel[v]['erschienen']}")
            kaputt = True
        elif rel[v]["eol"] <= tag:
            treffer.append(f"{v} steht in der Matrix, ist aber seit {rel[v]['eol']} EOL")
            kaputt = True

    stabil = sorted((v for v, d in rel.items() if d["erschienen"] <= tag < d["eol"]),
                    key=_als_zahlen)
    freigegeben = [v for v in stabil if _als_zahlen(v) <= _als_zahlen(ober)]
    soll = freigegeben[-3:]
    if not kaputt and sorted(matrix, key=_als_zahlen) != soll:
        treffer.append(f"gefuehrt ist {matrix}, die Regel ergibt am {tag} aber {soll} "
                       f"(letzte drei stable Minors bis Obergrenze {ober})")

    frist = q["obergrenze"].get("naechste_pruefung")
    darueber = [v for v in stabil if _als_zahlen(v) > _als_zahlen(ober)]
    if darueber and frist and tag > frist:
        treffer.append(
            f"{', '.join(darueber)} ist stable und steht ueber der Obergrenze {ober}; "
            f"die Freigabe war bis {frist} zu pruefen. Entweder die Obergrenze heben "
            f"oder 'naechste_pruefung' mit Begruendung verschieben.")
    return treffer


def melde_python_matrix_nachschub(quelle: dict | None = None,
                                  heute: str | None = None) -> list[str]:
    """Steht ueber der Obergrenze schon eine stabile Version? (Hinweis, nicht rot)

    Bewusst getrennt von `pruefe_python_matrix_regel`: die Nachricht "es gibt etwas
    Neues" ist kein Defekt. Erst wenn die Frist verstreicht, wird daraus einer.
    """
    q = quelle or lade_python_matrix()
    tag = _heute(heute)
    rel, ober = q["releases"], q["obergrenze"]["version"]
    frist = q["obergrenze"].get("naechste_pruefung", "—")
    return [f"{v} ist seit {rel[v]['erschienen']} stable und steht ueber der Obergrenze "
            f"{ober} — zu pruefen bis {frist}"
            for v, d in sorted(rel.items(), key=lambda kv: _als_zahlen(kv[0]))
            if d["erschienen"] <= tag < d["eol"] and _als_zahlen(v) > _als_zahlen(ober)]


def pruefe_changelog_kategorien(root: str, policy: dict, datei: str = "CHANGELOG.md") -> list[str]:
    """Keep a Changelog 1.1.0: fester Satz Kategorien, innerhalb eines Repos eine Sprache.

    Eine Überschrift darf einen erklärenden Zusatz tragen — nach Gedankenstrich
    („### Behoben — der Hook riet …") oder in Klammern („### Geändert (Website)").
    Geprüft wird nur der Kategoriename davor.
    """
    inhalt = _lies(root, datei)
    if inhalt is None:
        return [f"{datei} fehlt"]

    erlaubt = policy["changelog_kategorien"]
    treffer, gesehen = [], set()
    innerhalb_code = False
    for n, zeile in enumerate(zeilen_wie_grep(inhalt), 1):
        if zeile.lstrip().startswith("```"):
            innerhalb_code = not innerhalb_code
            continue
        if innerhalb_code:
            continue
        m = re.match(r"^###\s+(.+)", zeile)
        if not m:
            continue
        # "Behoben — der Hook …" -> "Behoben";  "Geändert (Website)" -> "Geändert"
        kopf = re.split(r"\s+[—–-]\s+|\s*\(", m.group(1).strip(), maxsplit=1)[0].strip()
        sprachen = [s for s, worte in erlaubt.items() if kopf in worte]
        if not sprachen:
            gueltig = sorted({w for worte in erlaubt.values() for w in worte})
            treffer.append(f"{datei}:{n}: unbekannte Kategorie {kopf!r} (erlaubt: {', '.join(gueltig)})")
        else:
            gesehen.update(sprachen)

    if len(gesehen) > 1:
        treffer.append(f"{datei}: Kategorien mischen die Sprachen {sorted(gesehen)}")
    return treffer


def _ueberschriften(text: str) -> list[tuple[int, str]]:
    """(Ebene, Titel) je Überschrift. Code-Blöcke bleiben außen vor — `# ...` darin ist ein Kommentar."""
    aus, innerhalb_code = [], False
    for zeile in zeilen_wie_grep(text):
        if zeile.lstrip().startswith("```"):
            innerhalb_code = not innerhalb_code
            continue
        if innerhalb_code:
            continue
        m = re.match(r"^(#{1,6})\s+(.*)", zeile)
        if m:
            aus.append((len(m.group(1)), m.group(2).strip()))
    return aus


def pruefe_uebersetzungs_struktur(root: str, paare: list[tuple[str, str]]) -> list[str]:
    """Übersetzung und Original haben dieselbe Überschriften-Struktur.

    Für mehrsprachige Doku gibt es keinen Standard, und GitHub wählt die README nach **Ort**
    aus, nicht nach Sprache — eine Übersetzung veraltet also still. Verglichen wird die Folge
    der Überschriften-EBENEN, nicht ihr Text: fügt jemand im Original einen Abschnitt hinzu und
    vergisst die Übersetzung, weichen die Folgen ab.

    Bewusst kein Vergleich der Commit-Historie: `actions/checkout` holt standardmäßig genau
    einen Commit, und `ci-local` committet den tmp-Baum neu. Ein Historien-Check wäre dort
    immer grün — also wertlos.
    """
    treffer = []
    for original, uebersetzung in paare:
        o, u = _lies(root, original), _lies(root, uebersetzung)
        if o is None:
            treffer.append(f"{original} fehlt")
            continue
        if u is None:
            treffer.append(f"{uebersetzung} fehlt")
            continue
        oh, uh = _ueberschriften(o), _ueberschriften(u)
        if [e for e, _ in oh] == [e for e, _ in uh]:
            continue
        for i, (a, b) in enumerate(zip(oh, uh)):
            if a[0] != b[0]:
                treffer.append(f"{uebersetzung}: Struktur weicht ab bei Überschrift {i + 1} "
                               f"(Original H{a[0]} {a[1]!r}, Übersetzung H{b[0]} {b[1]!r})")
                break
        else:
            fehlt = [t for _, t in oh[len(uh):]] or [t for _, t in uh[len(oh):]]
            wo = uebersetzung if len(oh) > len(uh) else original
            treffer.append(f"{wo}: {abs(len(oh) - len(uh))} Überschrift(en) fehlen — {fehlt[:3]}")
    return treffer


def pruefe_testdateien_gerufen(root: str, testverzeichnis: str = "tests",
                               laeufer: list[str] | None = None,
                               ausgenommen: dict[str, str] | None = None) -> list[str]:
    """Wird jede `tests/test_*`-Datei von irgendetwas AUFGERUFEN?

    WARUM (2026-09-23, gemeldet aus einem Kundenrepo an einem echten Repo): Dort wurde
    `tests/test_hygiene.py` von **nichts** gerufen — weder von `scripts/check.sh` noch von
    einem Workflow. Die 16 Kit-Pruefungen darin hatten am Vortag 1060 Treffer auf null
    gebracht und liefen seitdem in **keinem** Lauf mit.

    ⚠️ **WARUM `pruefe_kit_prueffunktionen_gerufen` DAS NICHT SEHEN KANN — und nie koennte.**
    Jene Pruefung belegt, dass die Kit-Funktionen **in** der Testdatei gerufen werden. Sie
    laeuft aber selbst nur, wenn die Datei laeuft:

        Ein nicht verkabelter Hygiene-Test besteht seine eigene Aufruf-Pruefung dadurch,
        dass er schweigt.

    Deshalb muss diese Frage von AUSSEN gestellt werden — aus der Datei heraus geht es
    prinzipiell nicht. Das ist derselbe Gedanke wie „eine Pruefung, die null Faelle gesehen
    hat, ist rot": *ein Pruefer, der nichts findet, meldet gruen — ob das „nichts da" oder
    „nichts gesehen" heisst, steht in keiner Ausgabe.*

    Gesucht wird der Dateiname in den **Laeufern**: `scripts/check.sh`, `scripts/run_all.py`
    und allem unter `.github/workflows/`. Wer einen eigenen Laeufer hat, reicht ihn herein.

    `ausgenommen` ist ein dict `{"<dateiname>": "Grund"}` — ein leerer Grund zaehlt nicht.
    ⚠️ Eine Testdatei, die absichtlich nicht laeuft, ist fast immer eine, die geloescht
    gehoert. Der Eintrag hier ist die Ausnahme fuer den seltenen Fall (z.B. ein Test, den nur
    ein Mensch von Hand fuehrt), nicht der bequeme Weg an einer unverkabelten Datei vorbei.
    """
    import glob as _glob

    ausgenommen = ausgenommen or {}
    treffer = []
    for name, grund in sorted(ausgenommen.items()):
        if not str(grund).strip():
            treffer.append(f"Ausnahme {name!r} ohne Begruendung — ein Grund ist Pflicht")

    # ⚠️ ZUERST: sammelt irgendein Laeufer AUTOMATISCH? Dann ist jede Datei abgedeckt, und
    # ein Namensvergleich waere ein reiner Fehlalarm.
    #
    # Beim ersten Lauf ueber acht Repos meldete diese Pruefung **54 Befunde in sechs Repos** —
    # und keiner war echt: fuenf Repos rufen `tests/run_all.py`, das per `glob("test_*.py")`
    # sammelt. Dort steht naturgemaess kein Dateiname.
    # *Sechs gleichzeitige Fehlalarme sind ein Befund ueber die Pruefung, nicht ueber die
    # Repos* — dieselbe Lehre wie beim Sammelfunktions-Fall in 0.17.1, und beide Male hat sie
    # eine Messung VOR dem Scharfschalten aufgedeckt.
    #
    # Der Waechter bleibt trotzdem noetig: repokits `check.sh` zaehlt namentlich auf, und
    # genau dort lagen zwei Testdateien im Baum, ohne je zu laufen. Und in einem Kundenrepo
    # wurde `test_hygiene.py` von gar nichts gerufen — weder namentlich noch per Sammler.
    if laeufer is None:
        # `tox.ini` und `pyproject.toml` dazu: gemeldet von einer Kunden-Session, die
        # beim Belegen ihres Befunds BEIDE Einstiegspunkte greppen musste (check.sh und
        # die Workflows). Ein Waechter, der nur check.sh liest, mahnt ein Repo an, das
        # seine Tests woanders ruft — und ein Fehlalarm schaltet ihn ab.
        laeufer = ["scripts/check.sh", "scripts/run_all.py", "run_all.py", "Makefile",
                   "tox.ini", "pyproject.toml", "noxfile.py", "justfile"]
        laeufer += sorted(_glob.glob(os.path.join(root, ".github", "workflows", "*.yml")))
        laeufer += sorted(_glob.glob(os.path.join(root, ".github", "workflows", "*.yaml")))
    quelle = []
    for rel in laeufer:
        pfad = rel if os.path.isabs(rel) else os.path.join(root, rel)
        try:
            with open(pfad, encoding="utf-8") as fh:
                quelle.append(fh.read())
        except (OSError, UnicodeDecodeError):
            continue
    text = "\n".join(quelle)
    if not text.strip():
        # Kein Laeufer gefunden -> die Pruefung haette nichts gemessen. Das ist der Fall,
        # gegen den sie gebaut ist; sie darf ihn nicht selbst begehen.
        return treffer + [f"kein Laeufer gefunden (gesucht: {', '.join(laeufer[:3])}…) — "
                          f"diese Pruefung haette nichts gemessen und waere aus dem falschen "
                          f"Grund gruen"]

    # AUTODISCOVERY — aber erst, nachdem die Laeufer gelesen sind.
    #
    # ⚠️ KORREKTUR 0.21.2 (gemeldet aus einer fremden Session, per Mutation belegt, Register
    # `pipeline-fehler.md`): Bis 0.21.1 stand diese Abkuerzung VOR dem Laeuferblock und
    # fragte nur, ob ein Sammler EXISTIERT. Wer alle Aufrufe von `tests/run_all.py` aus
    # check.sh und den Workflows entfernte, bekam trotzdem `[]` zurueck:
    #
    #     Ein nicht verkabelter Sammler bestand die Pruefung dadurch, dass es ihn gibt.
    #
    # Das ist exakt der Fall, gegen den diese Pruefung gebaut ist — eine Ebene hoeher. Die
    # Abkuerzung verlangt jetzt beides: der Sammler sammelt automatisch UND er wird selbst
    # von einem Laeufer gerufen.
    for _sammler in ("tests/run_all.py", "run_all.py", "scripts/run_all.py"):
        _inhalt = _lies(root, _sammler)
        if not _inhalt:
            continue
        if not ("glob(" in _inhalt or "glob.glob" in _inhalt or "iterdir" in _inhalt
                or "discover" in _inhalt):
            continue
        _name = os.path.basename(_sammler)
        if re.search(rf"(^|[\s\"'/]){re.escape(_name)}\b", text, re.M):
            return treffer
        treffer.append(
            f"{_sammler} sammelt automatisch, wird aber selbst von keinem Laeufer "
            f"gerufen — dann laeuft KEINE Testdatei, und diese Pruefung waere ohne "
            f"diese Zeile gruen")
        return treffer
    # `pytest tests/` bzw. `unittest discover` in check.sh: check.sh IST ein Laeufer, hier
    # stellt sich die Frage nach der Verkabelung nicht.
    _check = _lies(root, "scripts/check.sh") or ""
    if re.search(r"pytest\s+(-[^\s]+\s+)*tests?\b|unittest\s+discover", _check):
        return treffer

    muster = os.path.join(root, testverzeichnis, "test_*")
    dateien = sorted(d for d in _glob.glob(muster)
                     if os.path.isfile(d) and not d.endswith((".pyc", ".orig")))
    if not dateien:
        # ⚠️ NICHT SCHWEIGEN. Gemeldet von derselben Kunden-Session, die den Anlass-Befund
        # lieferte — und sie hatte den Fehler am selben Abend im eigenen Werkzeug:
        #
        #     „Meiner tat es beim ersten Lauf — er fand null Dateien und meldete gruen."
        #
        # Genau das ist die Stufe, gegen die diese Pruefung gebaut ist (M-1 Stufe 3: *hat sie
        # etwas gesehen?*). Sie darf sie nicht selbst offen lassen: ein Waechter, der keine
        # Testdateien findet und daraufhin gruen meldet, sieht aus wie ein sauberes Repo.
        #
        # Wer legitim keine `tests/test_*` hat (ein reines Doku- oder Datenrepo), traegt eine
        # Ausnahme mit Grund ein — dann steht es wenigstens da.
        if "__keine_testdateien__" in ausgenommen:
            return treffer
        return treffer + [
            f"in {testverzeichnis}/ liegt keine einzige `test_*`-Datei — diese Pruefung hat "
            f"nichts gemessen und waere aus dem falschen Grund gruen. Wenn das Repo bewusst "
            f"keine hat: ausgenommen={{'__keine_testdateien__': '<Grund>'}}"]

    for pfad in dateien:
        name = os.path.basename(pfad)
        if name in ausgenommen:
            continue
        if not re.search(rf"(^|[\s\"'/]){re.escape(name)}\b", text, re.M):
            treffer.append(f"{testverzeichnis}/{name} liegt im Baum, wird aber von keinem "
                           f"Laeufer aufgerufen (check.sh, run_all, Workflows) — er laeuft "
                           f"in KEINEM Lauf mit und meldet deshalb nie etwas")

    unbekannt = set(ausgenommen) - {os.path.basename(d) for d in dateien}
    for name in sorted(unbekannt):
        treffer.append(f"Ausnahme {name!r} nennt keine vorhandene Testdatei — Tippfehler "
                       f"oder geloescht?")
    return treffer


def pruefe_kit_prueffunktionen_gerufen(root: str, ausgenommen: dict[str, str] | None = None,
                                       testverzeichnis: str = "tests") -> list[str]:
    """Wird jede `pruefe_*` des Kits im Repo auch AUFGERUFEN?

    WARUM ES DIESE PRÜFUNG GIBT (2026-09-22, dritter Fall derselben Sorte): Das Kit
    liefert geprüfte Funktionen aus, `repokit sync` kopiert sie in jedes Repo, und
    repokits Eigentests belegen, dass sie richtig rechnen. Nur belegt **nichts**, dass
    ein Repo sie danach ruft. Gemessen am 2026-09-22:

    - `pruefe_python_matrix`, `pruefe_requires_python`, `pruefe_python_matrix_regel`
      lagen in sieben Repos und wurden in **keinem** gerufen (seit 2026-09-21).
    - `pruefe_kein_abbruch_auf_default_branch` wurde in **keinem** Repo gerufen.
    - `endpoint-check` trug das ganze `hygiene.py` samt Policy im Baum und rief
      daraus **keine einzige** Prüfung.

    Jedes Mal sah die Suite grün aus, und jedes Mal war die Zusage, die das Kit gibt,
    unbelegt. Dieselbe Lehre steht seit dem Manifest-Vendoring in `manifest.py`:
    *eine Prüfung, die niemand ruft, ist keine.* Sie hat sich dreimal wiederholt, weil
    niemand sie gemessen hat — das tut jetzt diese Funktion.

    Ausnehmen ist erlaubt, aber nur **mit Grund** — deshalb ein dict, keine Liste:

        ausgenommen={"pruefe_python_matrix": "Go-Repo, ci.yml hat keine Python-Matrix"}

    So steht die Begründung im Repo und nicht im Kopf dessen, der sie weggelassen hat.
    Ein leerer Grund zählt nicht als Begründung und wird gemeldet.
    """
    import inspect

    ausgenommen = ausgenommen or {}
    treffer = []

    for name, grund in sorted(ausgenommen.items()):
        if not str(grund).strip():
            treffer.append(f"Ausnahme {name!r} ohne Begründung — ein Grund ist Pflicht")

    angeboten = {n for n, _ in inspect.getmembers(sys.modules[__name__], inspect.isfunction)
                 if n.startswith("pruefe_")}
    angeboten.discard("pruefe_kit_prueffunktionen_gerufen")  # sich selbst nicht fordern
    # Pruefungen ANDERER Kit-Module — die Introspektion oben sieht sie nicht. Sie war der
    # blinde Fleck: `manifest.pruefe` scheiterte an beidem, Modul UND Namenspraefix.
    #
    # NUR wenn das Modul im Repo auch LIEGT. `repokit sync` verteilt heute alle Module in
    # jedes Repo, aber der Plan kann sich aendern, und ein Repo, das ein Modul nicht hat,
    # kann dessen Pruefung nicht rufen — eine Forderung waere dort ein Fehlalarm, und ein
    # Fehlalarm ist der Anfang jeder Ausnahmeliste, die spaeter etwas Echtes verdeckt.
    for modul, funktion in AUSGELIEFERTE_PRUEFUNGEN:
        if os.path.exists(os.path.join(root, testverzeichnis, "_kit", f"{modul}.py")):
            angeboten.add(f"{modul}.{funktion}")

    # KIT_WERKZEUGE gilt HIER genauso wie in `pruefe_tabelle_vollstaendig`.
    #
    # ⚠️ GEFUNDEN BEIM ROLLOUT VON 0.21.2, und es ist ein Befund ueber die Pruefungen,
    # nicht ueber die Repos: `pruefe_fixture_deckt_muster` stand in KIT_WERKZEUGE (mit
    # Grund: sie prueft das KIT gegen seine eigene Fixture, nicht ein Repo) — und
    # **sechs Repos wurden gleichzeitig rot**, weil DIESE Pruefung die Tabelle nicht
    # las. Dieselbe Liste galt in zwei Pruefungen gegenlaeufig.
    #
    # Dass es die `headers`-Eintraege nicht traf, war Zufall: sie liegen in einem
    # ANDEREN Modul, und die Introspektion oben sieht nur dieses hier.
    #
    # Warum repokits eigener Lauf es nicht fand: repokit RUFT die Funktion in seinem
    # check.sh. Ein Dogfooding-Lauf kann eine Forderung nicht pruefen, die nur fremde
    # Repos trifft — dafuer gibt es `repokit status`/den Rollout, und beim naechsten Mal
    # frueher: vor dem Scharfschalten ueber ALLE Repos messen.
    for _modul, _funktion, _grund in KIT_WERKZEUGE:
        if not str(_grund).strip():
            treffer.append(f"KIT_WERKZEUGE-Eintrag {_modul}.{_funktion} ohne Begruendung "
                           "— ein Grund ist Pflicht, sonst ist die Liste ein Ablagefach")
            continue
        angeboten.discard(_funktion)
        angeboten.discard(f"{_modul}.{_funktion}")

    quelle = []
    wurzel = os.path.join(root, testverzeichnis)
    for pfad, verzeichnisse, dateien in os.walk(wurzel):
        verzeichnisse[:] = [v for v in verzeichnisse if v not in ("_kit", "__pycache__")]
        for d in dateien:
            if d.endswith(".py"):
                try:
                    with open(os.path.join(pfad, d), encoding="utf-8") as fh:
                        quelle.append(fh.read())
                except OSError:
                    continue
    text = "\n".join(quelle)

    for name in sorted(angeboten):
        if name in ausgenommen:
            continue
        # Der Aufruf, nicht die blosse Erwähnung in einem Kommentar.
        # `modul.funktion` wird als `manifest.pruefe(` ODER `pruefe(` nach einem
        # `from _kit import manifest` gerufen — beide Formen gelten.
        kurz = name.split(".")[-1]
        if not re.search(rf"(?:\b{re.escape(name)}|\b{re.escape(kurz)})\s*\(", text):
            treffer.append(f"{name} liegt im Kit, wird aber nirgends aufgerufen "
                           f"(rufen oder mit Grund in `ausgenommen` eintragen)")

    unbekannt = set(ausgenommen) - angeboten
    for name in sorted(unbekannt):
        treffer.append(f"Ausnahme {name!r} nennt keine Prüfung des Kits — Tippfehler "
                       f"oder aus dem Kit entfernt?")

    return treffer


def pruefe_dateiliste_plausibel(dateien: list[str], mindestens: int = 5,
                                root: str | None = None) -> list[str]:
    """Ist die Dateiliste vollständig? — sonst prüft jede Prüfung danach zu wenig.

    WARUM (2026-09-22, gemeldet aus einem Kundenrepo): `pruefe_geheimnisse([], …)`
    und `pruefe_private_infrastruktur([], …)` geben beide **grün** zurück. Eine leere
    Liste ist damit von „alles sauber" nicht zu unterscheiden.

    ⚠️ DER ECHTE FALL WAR ABER NICHT „LEER". Bei `ci-local` fehlten über `git archive`
    **6 von 1326** Dateien — das ganze `.github/`, weil `.gitattributes` es per
    `export-ignore` ausschliesst. Genau die Workflows also, die `pruefe_actions_sha_gepinnt`
    und `pruefe_workflow_permissions` prüfen sollen. Eine Null-Prüfung hätte das
    durchgewinkt; deshalb zählt diese Funktion mit `root` gegen `git ls-tree -r HEAD`
    und nennt die fehlenden Pfade, statt nur eine Zahl zu vergleichen.

    `mindestens` bleibt als Notnagel für den Fall, dass kein git erreichbar ist.
    """
    treffer = []
    if len(dateien) < mindestens:
        treffer.append(f"nur {len(dateien)} getrackte Datei(en) gefunden (erwartet: "
                       f"mindestens {mindestens}) — die Hygiene-Prüfungen hätten nichts "
                       f"zu prüfen und wären trotzdem grün. Richtiges Verzeichnis?")
        return treffer

    if root is None:
        return treffer

    try:
        # `-z` UND `core.quotePath=false` sind beide noetig, nicht eines von beiden:
        # ohne sie escaped git Nicht-ASCII OKTAL und setzt Anfuehrungszeichen — eine Datei
        # `Änderungen.pdf` kommt dann als `"\303\204nderungen.pdf"` zurueck. Die Aufrufstelle
        # liest ihre Liste mit `ls-files -z` und bekommt den Umlaut richtig; verglichen wurden
        # damit zwei verschieden KODIERTE Fassungen desselben Pfads, und die Pruefung meldete
        # eine vorhandene Datei als fehlend (gemessen 2026-09-23 an einem Repo mit Umlaut-PDF).
        # `-z` allein genuegt nicht — quotePath wirkt unabhaengig davon.
        lauf = subprocess.run(["git", "-C", root, "-c", "core.quotePath=false",
                               "ls-tree", "-r", "-z", "--name-only", "HEAD"],
                              capture_output=True, text=True, check=False)
    except OSError:
        return treffer
    if lauf.returncode != 0:
        return treffer

    im_baum = {z for z in lauf.stdout.split("\0") if z.strip()}
    fehlend = sorted(im_baum - set(dateien))
    if fehlend:
        treffer.append(f"{len(fehlend)} von {len(im_baum)} Dateien fehlen in der "
                       f"geprüften Liste — die Prüfungen sehen sie nie an. "
                       f"Erste: {', '.join(fehlend[:5])}"
                       + (" …" if len(fehlend) > 5 else ""))
    return treffer

def pruefe_persist_credentials(root: str, dateien: list[str],
                               ausgenommen: dict[str, str] | None = None) -> list[str]:
    """Jeder `actions/checkout`-Schritt setzt `persist-credentials: false`.

    EBENE DIESER REGEL — bitte nicht hochstufen: Das ist **eigene Härtung**, kein
    belegter Standard. GitHub empfiehlt `persist-credentials: false` nirgends
    ausdrücklich (geprüft am 2026-09-22 an der Secure-Use-Doku und am README von
    `actions/checkout`). Wer das weitergibt, nennt die Ebene mit.

    WAS ES BRINGT, GENAU: Mit der Vorgabe (`true`) legt checkout das Token so ab, dass
    **jeder spätere Schritt im selben Job** es lesen kann. Seit v6 liegt es unter
    `$RUNNER_TEMP` statt in `.git/config` — das Risiko ist damit kleiner als die oft
    zitierte `.git/config`-Begründung nahelegt, aber es verschwindet nicht. Es zählt
    dort, wo nach dem Checkout **fremder Code** läuft: `pip install -e`, ein
    Build-Skript, eine Action eines Dritten. Der `tj-actions/changed-files`-Vorfall ist
    der bekannte Fall.

    WO ES FALSCH WÄRE: Ein Job, der danach selbst pusht (`git push`, `peaceiris/…`,
    ein Tag-Schubser), braucht das Token im Job. Dort gehört eine Ausnahme **mit Grund**
    hin — dict, keine Liste, damit die Begründung im Repo steht:

        ausgenommen={"release.yml:deploy": "pusht den Tag selbst"}

    Der Schlüssel ist `<workflow-datei>:<job>`, beides ohne Pfad.
    """
    ausgenommen = ausgenommen or {}
    treffer = []

    for name, grund in sorted(ausgenommen.items()):
        if not str(grund).strip():
            treffer.append(f"Ausnahme {name!r} ohne Begründung — ein Grund ist Pflicht")

    for rel in dateien:
        if not rel.startswith(".github/workflows/") or not rel.endswith((".yml", ".yaml")):
            continue
        inhalt = _lies(root, rel)
        if inhalt is None:
            continue
        datei = os.path.basename(rel)
        job = "?"
        for i, zeile in enumerate(zeilen_wie_grep(inhalt)):
            ohne_kommentar = zeile.split("#", 1)[0]
            # Jobnamen stehen auf Einrückungstiefe 2 unter `jobs:`.
            m = re.match(r"^  ([A-Za-z_][\w-]*):\s*$", ohne_kommentar)
            if m:
                job = m.group(1)
            if not re.search(r"uses:\s*actions/checkout@", ohne_kommentar):
                continue
            schluessel = f"{datei}:{job}"
            if schluessel in ausgenommen:
                continue
            # `with:` gehört zum Schritt; der Schritt endet beim nächsten `- ` auf
            # derselben oder geringerer Einrückung. 12 Zeilen reichen dafür weit.
            block = "\n".join(zeilen_wie_grep(inhalt)[i:i + 12])
            naechster = re.search(r"\n\s*- ", block)
            if naechster:
                block = block[:naechster.start()]
            if not re.search(r"persist-credentials:\s*false", block):
                treffer.append(f"{rel}:{i + 1} (Job {job}): actions/checkout ohne "
                               f"`persist-credentials: false` — setzen oder als "
                               f"'{schluessel}' mit Grund ausnehmen")

    unbekannt = {k for k in ausgenommen if ":" not in k}
    for k in sorted(unbekannt):
        treffer.append(f"Ausnahme {k!r} hat nicht die Form '<workflow.yml>:<job>'")

    return treffer


def _ist_code_kette(text: str, treffer) -> bool:
    """Steht der Treffer in einer Attribut-/Methodenkette statt als Hostname?

    Der verräterische Teil steht DAHINTER, nicht davor: `merkmale.de.forEach(fn)`
    beginnt mit `merkmale`, dem also kein Punkt vorausgeht — erst `.forEach(` macht
    die Kette erkennbar. Ein Hostname wird nie mit `.name(` fortgesetzt.
    """
    davor = text[max(0, treffer.start() - 1):treffer.start()]
    if davor == ".":
        return True

    wert = treffer.group(0)
    # GROSSBUCHSTABEN = Code- oder Dateikonvention, kein Hostname. Belegt an
    # `log.Info(` / `entry.Info(` (Go, FlyingCerts) und `README.de in sync.`
    # (Prosa in C22s CLAUDE.md) — drei Fehlalarme aus einem Lauf.
    # ⚠️ GRENZE, bewusst in Kauf genommen: ein Host, der GEMISCHT geschrieben steht
    # (`Auer.AT`), faellt damit durch. Der echte Fund, der diese Pruefung ausgeloest
    # hat, stand klein, und so stehen Hostnamen praktisch immer. Ein
    # Fehlalarm erzieht dazu, die Pruefung zu umgehen; diese Luecke tut das nicht.
    if wert != wert.lower():
        return True

    rest = text[treffer.end():treffer.end() + 40]
    # `log.info(` ist ein Aufruf, kein Host — auch ganz klein geschrieben.
    if rest.startswith("("):
        return True
    return bool(re.match(r"\.[A-Za-z_]\w*\s*[(=]", rest))


def _host_kandidaten(inhalt: str, ist_python: bool) -> set[str]:
    """Hostnamen-Kandidaten aus einem Dateiinhalt — Code-Konstrukte bleiben draussen.

    ZWEI SCHRITTE, nicht einer. Der AST grenzt bei Python die **Menge** ein (nur
    String-Literale und Kommentare, kein Bezeichner-Rauschen). Die **Form** jedes
    Kandidaten wird danach trotzdem geprüft — denn eingebetteter JavaScript-Code steht
    in einem Python-String und ist für den AST ein ganz normales Literal.

    Belegt an C22s `gallery/build.py`: `merkmale.de.forEach(…)` liegt dort in einem
    Python-String. Der erste Entwurf verliess sich allein auf den AST und meldete es
    als Host — die Fassung ohne Formprüfung war also genau so falsch wie eine ohne AST.
    """
    def aus_text(text: str) -> set[str]:
        return {m.group(0) for m in _HOST_RE.finditer(text)
                if not _ist_code_kette(text, m)}

    if ist_python:
        try:
            baum = ast.parse(inhalt)
        except SyntaxError:
            return aus_text(inhalt)
        # dict-SCHLUESSEL sind Nachschlage-Zeichen, keine Werte — und nie ein Hostname.
        # Gemeldet 2026-09-23: `{"admin.app": "App"}` in einem Uebersetzungskatalog. Der AST
        # sieht ein String-Literal, also genau die Menge, die man extrahieren will; die
        # STELLE unterscheidet es.
        # ⚠️ Nur die Schluessel, nicht das ganze dict: der echte Fund, der diese Pruefung
        # ausgeloest hat, war ein dict-WERT (`{"domains": "<kunde>.at"}`). Wer dict-Literale
        # pauschal ueberspringt, verdeckt genau den Fall, fuer den sie gebaut wurde.
        schluessel = set()
        for k in ast.walk(baum):
            if isinstance(k, ast.Dict):
                for kk in k.keys:
                    if isinstance(kk, ast.Constant) and isinstance(kk.value, str):
                        schluessel.add(kk.value)
        roh: set[str] = set()
        for k in ast.walk(baum):
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                if k.value in schluessel:
                    continue
                roh |= aus_text(k.value)
        for zeile in zeilen_wie_grep(inhalt):
            if "#" in zeile:
                roh |= aus_text(zeile.split("#", 1)[1])
        return roh
    return aus_text(inhalt)

def pruefe_blanke_adressen(root: str, dateien: list[str], policy: dict,
                           zusaetzliche_hosts: list[str] | None = None,
                           grundstock: list[str] | None = None,
                           belegstellen: list[str] | None = None) -> list[str]:
    """Fremde Hostnamen OHNE `https://` davor — die Lücke, durch die ein Kundenname fiel.

    WARUM (2026-09-22): In einem **öffentlichen** Repo standen ein realer Firmenname
    und zwei real registrierte `.at`-Domains als Test-Fixtures. Gemeldet hat es nichts:
    `pruefe_adressen` sucht nur URLs **mit Schema**, und das Muster in
    `pruefe_private_infrastruktur` verlangt **drei** Namensteile (`sub.domain.tld`) —
    eine blanke Second-Level-Domain fällt durch beide.

    `grundstock` ist die vom Menschen **einmal durchgesehene** Liste der Hosts, die im
    Repo bereits stehen und in Ordnung sind. Ab dann ist jede NEUE Adresse rot.
    ⚠️ Er darf nicht automatisch erzeugt und committet werden — genau so segnet man den
    nächsten echten Kundennamen ab (dieselbe Falle wie bei einer Baseline, die wächst,
    weil niemand hinsieht).

    VIER FALLEN, alle an echten Stellen gemessen — die Tests halten sie fest:
    1. Dateinamen mit Sprachkürzel: `login.de.html` liefert `login.de`. Der Treffer
       sitzt am **Anfang** des Namens, wo ein Endungs-Filter nicht hinsieht.
    2. JavaScript in einem Python-String — s. `_host_kandidaten`.
    3. Kurze Attributnamen, die TLDs sind (`obj.it`). Gegenprobe: `self.cfg.base_url`,
       `d.get`, `sys.exit` lösen NICHT aus, weil `url`/`get`/`exit` keine TLDs sind.
    4. Angreifer-Platzhalter der Form `evil.<tld>` / `attacker.<tld>` sind **real
       registrierte** Domains. Sie gehören auf `.example`/`.invalid`/`.test`, NICHT
       auf eine Erlaubnisliste. (Hier bewusst ohne die echte Endung geschrieben:
       diese Datei wird nach `repokit sync` in öffentliche Repos kopiert, und ein
       Negativbeispiel im Klartext wäre dort dasselbe Problem, das es beschreibt.)
    """
    erlaubt_liste = list(policy["erlaubte_hosts"]) + list(zusaetzliche_hosts or [])
    erlaubt = re.compile(r"(?:^|\.)(?:" + "|".join(erlaubt_liste) + r")$", re.IGNORECASE)
    gesegnet = {h.lower() for h in (grundstock or [])}

    treffer = []
    for rel, inhalt in _texte(root, dateien, policy):
        if _ist_generiert(rel, policy) or _ist_belegstelle(rel, belegstellen):
            continue
        for host in sorted(_host_kandidaten(inhalt, rel.endswith(".py"))):
            klein = host.lower()
            if klein in gesegnet or erlaubt.search(host):
                continue
            if _ist_eigene_identitaet(host, policy):
                continue
            # Falle 1: der Treffer ist ein PRAEFIX eines Dateinamens (`login.de.html`).
            if re.search(rf"{re.escape(host)}\.[a-z0-9]{{1,5}}\b", inhalt, re.IGNORECASE):
                continue
            # Pfadbestandteil (`scripts/check.sh`) oder Dateiendung am Wortende.
            if re.search(rf"[\w./-]/{re.escape(host)}\b", inhalt):
                continue
            treffer.append(f"{rel}: {host} — fremder Hostname ohne Schema. Neutral machen "
                           f"(RFC 2606: .example/.invalid/.test) oder, wenn er dort "
                           f"hingehoert, nach Durchsicht in den Grundstock aufnehmen")
    return sorted(set(treffer))


def pruefe_belegstellen_eng(root: str, dateien: list[str],
                            belegstellen: list[str] | None = None) -> list[str]:
    """Trifft ein Belegstellen-Muster auch Code oder Konfiguration?

    WARUM (2026-09-23): Eine Belegstelle nimmt Verzeichnisse von den Adresspruefungen aus.
    Das ist richtig — und es ist die naechste Verdeckungsfalle. Belegt an einem Kundenrepo:
    67 Adress-Treffer lagen in `docs/claude`, **alle in derselben Datei**, die den einzigen
    echten Infrastruktur-Befund trug. Ein pauschales `docs/**` haette ihn mit derselben
    Bewegung verdeckt, mit der es die Fehlalarme entfernt.

    *Die Verdeckungsfalle wechselt nur das Gewand: erst `erlaubte_hosts`, dann `belegstellen`.*

    ⚠️ **WAS DIESE PRUEFUNG NICHT KANN — und warum sie es nicht versucht.** Der erste Entwurf
    hatte zusaetzlich eine ANTEILS-Schwelle: ein Muster, das mehr als ein Viertel der Dateien
    abdeckt, sei zu weit. Beim ersten Lauf meldete sie `docs/research/` — ein Verzeichnis, das
    genau eine korrekte Belegstelle IST. In dem Kundenrepo deckt es 659 von 1331 Dateien ab,
    also 49%; bei einem dokumentationslastigen Produkt ist ein hoher Anteil **normal**. Die
    Schwelle haette also die richtige Belegstelle verboten und die falsche nicht gefunden.
    Sie ist ersatzlos entfallen.

    **Ob ein Verzeichnis NUR Fundstellen enthaelt, ist mechanisch nicht entscheidbar.** Die
    Datei, die den echten Befund trug, war eine `.md` wie alle anderen darin. Deshalb bleibt
    genau ein Kriterium, und das ist ein strukturelles: **ein Muster, das Code oder
    Konfiguration trifft, ist zu weit** — dort steht eine Adresse als Einstellung, nicht als
    Beleg. Der Rest ist Sichtung durch einen Menschen, und die Liste gehoert entsprechend eng.
    """
    treffer = []
    if not belegstellen:
        return treffer
    code = (".py", ".sh", ".yml", ".yaml", ".go", ".php", ".js", ".ts", ".toml",
            ".cfg", ".ini", ".env", ".sql", ".tf", ".j2")
    for muster in belegstellen:
        try:
            pat = re.compile(muster)
        except re.error as fehler:
            treffer.append(f"Belegstelle {muster!r} ist kein gueltiger Ausdruck: {fehler}")
            continue
        getroffen = [d for d in dateien if pat.search(d)]
        if not getroffen:
            treffer.append(f"Belegstelle {muster!r} trifft keine einzige Datei — "
                           f"veraltet oder Tippfehler? Eine Ausnahme ohne Wirkung "
                           f"taeuscht Sorgfalt vor.")
            continue
        mit_code = sorted(d for d in getroffen
                          if d.endswith(code)
                          or os.path.basename(d) in ("Dockerfile", "Makefile"))
        if mit_code:
            treffer.append(
                f"Belegstelle {muster!r} trifft auch Code/Konfiguration "
                f"({', '.join(mit_code[:3])}{' …' if len(mit_code) > 3 else ''}) — dort steht "
                f"eine Adresse als Einstellung, nicht als Beleg, und die Ausnahme wuerde sie "
                f"verdecken. Enger fassen.")
    return treffer



# Die ausgelieferten Pruefungen — AUSDRUECKLICH, nicht per Introspektion.
#
# WARUM DIESE TABELLE (2026-09-23): `pruefe_kit_prueffunktionen_gerufen` sammelte seine
# Soll-Liste ueber `inspect.getmembers(sys.modules[__name__])` und filterte auf den Praefix
# `pruefe_`. Damit sah er nur Funktionen DIESES Moduls mit DIESEM Namen — und uebersah
# `manifest.pruefe` vollstaendig: anderes Modul, und sie heisst `pruefe`, nicht `pruefe_…`.
#
# Folge, gemessen: Ein Repo trug die Manifest-Pruefung im Baum und rief sie **nie**. Genau die
# Leiche, gegen die der Waechter gebaut ist — er hat sie nicht gemeldet. Der Satz aus seinem
# eigenen Docstring ("eine Pruefung, die niemand ruft, ist keine") galt fuer ihn selbst nicht.
#
# Die Lehre ist allgemeiner als der Fall: **wer "was als Pruefung zaehlt" implizit ueber eine
# Namenskonvention definiert, baut die Blindheit mit ein.** Deshalb steht es hier als Liste.
# Wer eine Pruefung hinzufuegt, traegt sie ein — und `pruefe_tabelle_vollstaendig` unten
# vergleicht die Tabelle gegen das Modul, damit auch das nicht am Vorsatz haengt.
AUSGELIEFERTE_PRUEFUNGEN: list[tuple[str, str]] = [
    ("manifest", "pruefe"),
    # Gefordert, weil sie nichts braucht als das Repo — und weil ihr Zuschnitt ueber ALLE acht
    # Repos gemessen ist (2026-09-24): 7 sauber, einer rot, und der Rote ist ein echter,
    # dokumentierter Befund. Die naheliegende weite Fassung ("jeder Job mit write-Rechten haengt
    # am Tag") haette 7 von 9 heissen Jobs falsch gemeldet — Pages-Deploy, CI-Abbild, Cleanup.
    ("hygiene", "pruefe_veroeffentlichen_am_tag"),
    # Die SAMMELFUNKTION, nicht ihre Teile — sie ist die ausgelieferte Schnittstelle.
    #
    # ⚠️ KORREKTUR 0.17.1, und die Lehre ist bitter, weil sie meine eigene ist: 0.17.0
    # trug hier `pruefe_backlog` und `pruefe_keine_zyklen` einzeln ein, mit der Begruendung
    # "ueber sieben Repos gemessen, in KEINEM gerufen". Die Messung war ein grep nach
    # `pruefe_backlog\s*\(` — und `backlog.alle_pruefungen()` ruft beide auf. ALLE sieben
    # Repos riefen sie also, ueber genau die Schnittstelle, die dafuer gebaut ist.
    #
    # Die Zahl war ein Werkzeug-Artefakt, kein Befund. Und es ist DERSELBE Fehler, gegen
    # den dieser ganze Waechter gebaut ist — "Funktion ist nicht Aufrufer" — nur einmal
    # um die Ecke: wer nach dem Namen der Funktion sucht, findet den Aufruf nicht, der
    # ueber eine Sammelfunktion laeuft. Beim Rollout fiel es sofort auf, weil sechs Repos
    # gleichzeitig rot wurden. *Sechs gleichzeitige Fehlalarme sind ein Befund ueber die
    # Pruefung, nicht ueber die Repos.*
    ("backlog", "alle_pruefungen"),
]

# Angeboten, aber NICHT gefordert — und jedes mit dem Grund, warum nicht.
#
# Die Unterscheidung ist noetig, weil "ausgeliefert" zwei verschiedene Dinge heisst.
# Eine Hygiene- oder Backlog-Pruefung braucht nichts als das Repo; wer sie nicht ruft,
# laesst sie einfach liegen. Ein Header-Pruefer braucht eine **HTTP-Antwort** — ein Repo
# ohne Web-Dienst kann ihn nicht rufen, und ihn dort zu fordern erzwaenge in jedem Repo
# fuenf Ausnahmen mit Begruendung. Eine Ausnahmeliste, die in jedem Repo fuenf Zeilen
# lang ist, ist wieder genau die Verdeckungsfalle, gegen die der Waechter gebaut ist.
#
# ⚠️ Diese Liste ist KEIN Ablagefach fuer Unbequemes. Der Grund muss die Form der
# Funktion betreffen ("braucht eine Antwort, die nur eine laufende App liefert"),
# nicht die Bequemlichkeit des Repos ("haben wir noch nicht eingebaut") — das Zweite
# gehoert als Ausnahme MIT Grund ins jeweilige Repo, wo es sichtbar bleibt.
KIT_WERKZEUGE: list[tuple[str, str, str]] = [
    ("hygiene", "pruefe_dateien_geschlossen",
     ("prueft den Kit-Quelltext selbst, nicht das aufrufende Repo — sie gehoert in repokits "
      "eigene Suite, und dort laeuft sie")),
    ("hygiene", "pruefe_zeilennummern_wie_grep",
     ("prueft den Kit-Quelltext selbst, nicht das aufrufende Repo — sie gehoert in repokits "
      "eigene Suite, und dort laeuft sie")),
    ("headers", "pruefe_cookie_flags",
     "braucht geparste Set-Cookie-Koepfe einer echten Antwort"),
    ("headers", "pruefe_security_header",
     "braucht die Antwort-Koepfe eines laufenden Dienstes"),
    ("headers", "pruefe_csp", "braucht einen CSP-Wert aus einer Antwort"),
    ("headers", "pruefe_hsts",
     "gehoert auf die Proxy-/Deploy-Ebene, nicht in eine App-Suite (s. Docstring)"),
    ("headers", "pruefe_kein_versions_leak",
     "braucht die Antwort-Koepfe eines laufenden Dienstes"),
    ("hygiene", "pruefe_fixture_deckt_muster",
     ("prueft das KIT gegen seine eigene Fixture, nicht ein Repo — sie laeuft in "
      "repokits check.sh; die Repos erben das Ergebnis ueber `repokit muster`")),
]


def pruefe_policy_schluessel_gelesen(policy: dict,
                                     kit_verzeichnis: str | None = None) -> list[str]:
    """Traegt die Policy einen Schluessel, den KEIN Kit-Modul liest?

    WARUM (2026-09-23, gefunden im eigenen 0.17.0): Die Policy bekam den Schluessel
    `belegstellen` mit leerem Vorgabewert — und **nichts las ihn**. Die Belegstellen gehen
    als Parameter in den Aufruf (`pruefe_blanke_adressen(..., belegstellen=[...])`), genau
    wie `grundstock`, weil die Policy-Datei vom Manifest bewacht wird: ein Repo, das dort
    eintraegt, bricht seine eigene Manifest-Pruefung.

    Der tote Schluessel war also nicht bloss nutzlos, er war eine **falsche Einladung** —
    er zeigte auf den einen Ort, an dem ein Repo seine Belegstellen NICHT eintragen kann.

    Dieselbe Sorte Befund wie "ausgeliefert ist nicht gerufen", nur fuer **Daten** statt
    Funktionen: *ein Konfigurationswert, den niemand liest, ist keine Konfiguration — er ist
    eine Zusage, die nichts einloest.*

    Geprueft wird per Textsuche nach `policy["<name>"]` und `policy.get("<name>")` ueber alle
    Kit-Module. Schluessel, die mit `_` beginnen, sind Kommentare und zaehlen nicht.
    """
    treffer = []
    wurzel = kit_verzeichnis or HIER
    quellen = []
    for datei in sorted(glob.glob(os.path.join(wurzel, "*.py"))):
        try:
            with open(datei, encoding="utf-8") as fh:
                quellen.append(fh.read())
        except OSError as fehler:
            treffer.append(f"Kit-Modul {os.path.basename(datei)} nicht lesbar: {fehler}")
    quelle = "\n".join(quellen)
    if not quelle:
        treffer.append("Kein Kit-Modul gefunden — die Pruefung haette nichts gemessen "
                       "und waere aus dem falschen Grund gruen")
        return treffer

    for name in sorted(k for k in policy if not str(k).startswith("_")):
        muster = (rf'\[\s*["\']{re.escape(name)}["\']\s*\]'
                  rf'|\.get\(\s*["\']{re.escape(name)}["\']')
        if not re.search(muster, quelle):
            treffer.append(
                f"Policy-Schluessel {name!r} wird von keinem Kit-Modul gelesen — entfernen "
                f"oder verdrahten. Ein Wert, den niemand liest, ist eine Zusage, die nichts "
                f"einloest; steht er an einer Stelle, die ein Repo nicht aendern DARF "
                f"(Manifest), ist er ausserdem eine falsche Einladung.")
    return treffer


def pruefe_zeilennummern_wie_grep(kit_verzeichnis: str | None = None) -> list[str]:
    """Keine Kit-Pruefung darf `splitlines()` benutzen, wo sie Zeilen zaehlt.

    WARUM (Register 2026-09-23, behoben 2026-09-24): `splitlines()` trennt auch an U+2028,
    U+2029, U+0085, ``\v``, ``\f`` und U+001C-1E. Ein einziges solches Zeichen in einer
    Datei verschiebt JEDE danach gemeldete Zeilennummer — gemessen: gemeldet ``:1610``,
    gemeint 1606. Zwoelf Stellen in diesem Modul waren betroffen, nicht eine; deshalb gibt
    es [`zeilen_wie_grep`](#) und deshalb wird es hier erzwungen statt erinnert.

    *Ein Waechter, der den Fundort falsch nennt, kostet genau das Vertrauen, das er
    aufbauen soll — und man sucht an der falschen Stelle.*

    Geprueft wird per **AST**, nicht im Zeilentext: ein `splitlines` im Docstring (dort
    steht die Begruendung) ist kein Aufruf. Genau dieser Unterschied hat schon einmal einen
    Fehlalarm erzeugt.
    """
    import ast as _ast
    verz = kit_verzeichnis or os.path.dirname(os.path.abspath(__file__))
    treffer: list[str] = []
    for name in sorted(os.listdir(verz)):
        if not name.endswith(".py") or name == "__init__.py":
            continue
        pfad = os.path.join(verz, name)
        try:
            # `with`, nicht `open(...).read()`: CodeQL meldet sonst `py/file-not-closed`,
            # und zwar in JEDEM Repo, das diese Kopie traegt — gemeldet aus der
            # TinySesam-Session am Tag der Auslieferung. Der Fix gehoert in die Quelle,
            # nicht in sieben abgewiesene Alerts.
            with open(pfad, encoding="utf-8") as fh:
                baum = _ast.parse(fh.read())
        except (OSError, SyntaxError) as fehler:
            treffer.append(f"{name}: nicht lesbar ({fehler}) — nicht geprueft")
            continue
        for knoten in _ast.walk(baum):
            if isinstance(knoten, _ast.Call) and isinstance(knoten.func, _ast.Attribute) \
                    and knoten.func.attr == "splitlines":
                treffer.append(f"{name}:{knoten.lineno}: splitlines() — "
                               "zeilen_wie_grep() nehmen (U+2028 verschiebt die Nummer)")
    return treffer


# Was VEROEFFENTLICHT in einem Workflow? Erkannt an der HANDLUNG, nicht am Namen.
#
# Die Falle stammt aus der TinySesam-Session (2026-09-24): ihre erste Fassung erkannte den
# PyPI-Job an `name: pypi` — und schlug bei `name: pypi-dist` an, einem ARTEFAKTNAMEN im
# Bau-Job. *Ein Waechter, der am Namen erkennt, trifft alles, was aehnlich heisst.*
_VEROEFFENTLICHT: list[tuple[str, str]] = [
    (r"gh\s+release\s+create", "gh release create"),
    (r"docker/login-action", "docker/login-action"),
    (r"pypa/gh-action-pypi-publish", "pypi-publish"),
    (r"actions/attest", "actions/attest*"),
    (r"twine\s+upload", "twine upload"),
    (r"docker/build-push-action", "build-push-action"),
]
_AM_TAG = re.compile(r"ref_type\s*==\s*'tag'|startsWith\(github\.ref,\s*'refs/tags")


def _workflow_bloecke(inhalt: str) -> tuple[bool, list[dict]]:
    """(ist_tag_workflow_mit_knopf, [{name, if, steps:[{text, if}]}]) — OHNE PyYAML.

    Bewusst textuell: `yaml` liegt nur in `ci-ansible` und `ci-runner-tools`, NICHT in
    `ci-python-web`, `ci-go` und `ci-php` (nachgemessen 2026-09-24). Eine Pruefung, die dort
    mit ImportError endet oder sich ueberspringt, ist keine — "Skip ist kein Gruen".
    """
    zeilen = zeilen_wie_grep(inhalt)
    tiefe = lambda z: len(z) - len(z.lstrip(" "))          # noqa: E731 — lokal, einzeilig

    # --- on: … tags: + workflow_dispatch?
    in_on = False
    hat_tags = hat_knopf = False
    for z in zeilen:
        if re.match(r"^on:", z):
            in_on = True
            continue
        if in_on:
            if z.strip() and tiefe(z) == 0:
                in_on = False
            else:
                if re.match(r"^\s+tags:", z):
                    hat_tags = True
                if re.match(r"^\s+workflow_dispatch:", z):
                    hat_knopf = True
    # Kurzform `on: [push]` traegt keine tags — dann greift die Pruefung nicht.

    # --- jobs:
    jobs: list[dict] = []
    in_jobs = False
    job: dict | None = None
    job_tiefe = None
    schritt: dict | None = None
    for z in zeilen:
        if re.match(r"^jobs:", z):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if z.strip() and tiefe(z) == 0:                    # naechster Top-Level-Schluessel
            break
        m = re.match(r"^(\s+)([A-Za-z_][\w-]*):\s*$", z)
        if m and (job_tiefe is None or len(m.group(1)) == job_tiefe):
            job_tiefe = len(m.group(1))
            job = {"name": m.group(2), "if": "", "steps": []}
            jobs.append(job)
            schritt = None
            continue
        if job is None:
            continue
        # Schritt-Anfang: "- " tiefer als der Jobname
        if re.match(r"^\s+-\s", z) and tiefe(z) > job_tiefe:
            schritt = {"text": z, "if": ""}
            job["steps"].append(schritt)
            continue
        mif = re.match(r"^\s+if:\s*(.*)$", z)
        if mif:
            if schritt is not None:
                schritt["if"] += " " + mif.group(1)
            else:
                job["if"] += " " + mif.group(1)
            continue
        if schritt is not None:
            schritt["text"] += "\n" + z
        else:
            job["if"] += ""                                 # andere Job-Schluessel: uninteressant
            if re.match(r"^\s+environment:", z):
                job["environment"] = z.split(":", 1)[1].strip() or "?"
    return (bool(hat_tags and hat_knopf), jobs)


def pruefe_veroeffentlichen_am_tag(root: str, dateien: list[str] | None = None) -> list[str]:
    """In einem tag-getriggerten Workflow MIT `workflow_dispatch`: nichts veroeffentlicht ohne Tag.

    WARUM (Register 2026-09-23/24, Muster aus der TinySesam-Session): Ein Workflow mit
    `on: push: tags` wird von der normalen CI nie beruehrt — er sieht gepflegt aus, weil das Repo
    gruen ist, aber das Gruen kommt von einem anderen Workflow. Der Ausweg ist ein
    `workflow_dispatch`-Trockenlauf. Genau dort lag die Falle: fuenf von sechs Repos hatten den
    Knopf, keines hatte ihn je gedrueckt — und ein Druck haette **aus einem Branch heraus
    veroeffentlicht** (`gh release create`, `docker push` nach ghcr), weil nur `--verify-tag` davor
    stand. *Ein Notausgang, der beim Oeffnen klemmt oder ins Freie fuehrt, ist keiner.*

    **Der Zuschnitt ist gemessen, nicht geraten** (ueber alle acht Repos der Flotte, 2026-09-24):
    Die naheliegende Regel „jeder Job mit `write`-Rechten haengt am Tag" haette **7 von 9** heissen
    Jobs falsch gemeldet — der Pages-Deploy (`pages`/`id-token: write`, veroeffentlicht bei JEDEM
    Push auf main und soll das), das CI-Abbild eines Kundenrepos und ein Registry-Cleanup
    (`packages: write`, beides gewollt). Deshalb: geprueft wird **nur in tag-getriggerten Workflows
    mit Knopf**, und dort **die Handlung** (Release anlegen, Registry-Anmeldung, schiebender Bau,
    PyPI, Beglaubigung) — nicht das Recht und nicht der Name.

    Gedeckt ist eine Handlung, wenn der **Job** oder der **Schritt** ein `if` mit
    `github.ref_type == 'tag'` bzw. `startsWith(github.ref, 'refs/tags…')` traegt.
    """
    treffer: list[str] = []
    verz = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(verz):
        return treffer
    for name in sorted(os.listdir(verz)):
        if not name.endswith((".yml", ".yaml")):
            continue
        inhalt = _lies(root, os.path.join(".github", "workflows", name))
        if inhalt is None:
            continue
        tag_workflow, jobs = _workflow_bloecke(inhalt)
        if not tag_workflow:
            continue
        for job in jobs:
            job_am_tag = bool(_AM_TAG.search(job.get("if", "")))
            if job.get("environment") and not job_am_tag:
                treffer.append(f".github/workflows/{name}:{job['name']}: `environment: "
                               f"{job['environment']}` ohne Tag-Bedingung am Job")
            for s in job["steps"]:
                if job_am_tag or _AM_TAG.search(s.get("if", "")):
                    continue
                for muster, bezeichnung in _VEROEFFENTLICHT:
                    if not re.search(muster, s["text"]):
                        continue
                    if bezeichnung == "build-push-action":
                        # Ein Bau, der NICHT schiebt, veroeffentlicht nichts. `push:` mit einem
                        # Ausdruck (`${{ github.ref_type == 'tag' }}`) ist genau die Loesung und
                        # darf nicht als Befund gelten.
                        # Die GANZE Zeile nach `push:` lesen, nicht das erste Wort: bei
                        # `push: ${{ github.ref_type == 'tag' }}` faengt `\S+` nur `${{` und
                        # meldete DashMyBoard falsch (aufgefallen, weil eine zweite,
                        # unabhaengige Messung mit PyYAML widersprach — zwei Implementierungen,
                        # die sich uneinig sind, sind billiger als ein Fehlalarm im Gate).
                        mp = re.search(r"push:\s*(.*)$", s["text"], re.M)
                        wert = (mp.group(1) if mp else "").strip().strip("\"'")
                        if wert.lower() in ("false", "") or "ref_type" in wert or "refs/tags" in wert:
                            continue
                    treffer.append(f".github/workflows/{name}:{job['name']}: "
                                   f"`{bezeichnung}` ohne Tag-Bedingung — ein Trockenlauf "
                                   f"wuerde damit VEROEFFENTLICHEN")
                    break
    return treffer


def pruefe_dateien_geschlossen(kit_verzeichnis: str | None = None) -> list[str]:
    """Kein `open()` im Kit ausserhalb eines `with` — die Datei bliebe offen.

    WARUM (2026-09-24, am Tag der Auslieferung von 0.21.6 gemeldet): `open(pfad).read()` in
    einer frisch gebauten Pruefung liess CodeQL in TinySesam `py/file-not-closed` melden — und
    weil das Kit als **Kopie** in jedes Repo wandert, haette derselbe Alert in jedem Repo mit
    CodeQL aufgeschlagen. Sieben abgewiesene Alerts sind kein Fix; der Fix gehoert in die Quelle.

    *Was das Kit ausliefert, vervielfaeltigt jeden Fehler — und jeden Fix.*

    Geprueft wird per AST (ein `open(` im Docstring oder in einem Kommentar ist kein Aufruf).
    CodeQL laeuft nur in den Repos, die es eingerichtet haben; diese Pruefung laeuft ueberall,
    auch offline in `ci-local`.
    """
    import ast as _ast
    verz = kit_verzeichnis or os.path.dirname(os.path.abspath(__file__))
    treffer: list[str] = []
    for name in sorted(os.listdir(verz)):
        if not name.endswith(".py") or name == "__init__.py":
            continue
        pfad = os.path.join(verz, name)
        try:
            with open(pfad, encoding="utf-8") as fh:
                baum = _ast.parse(fh.read())
        except (OSError, SyntaxError) as fehler:
            treffer.append(f"{name}: nicht lesbar ({fehler}) — nicht geprueft")
            continue
        im_with = set()
        for knoten in _ast.walk(baum):
            if isinstance(knoten, _ast.With):
                for eintrag in knoten.items:
                    for x in _ast.walk(eintrag.context_expr):
                        im_with.add(id(x))
        for knoten in _ast.walk(baum):
            if isinstance(knoten, _ast.Call) and getattr(knoten.func, "id", None) == "open" \
                    and id(knoten) not in im_with:
                treffer.append(f"{name}:{knoten.lineno}: open() ohne `with` — die Datei bleibt "
                               "offen (CodeQL: py/file-not-closed)")
    return treffer


def pruefe_tabelle_vollstaendig(kit_verzeichnis: str | None = None) -> list[str]:
    """Kennt die Tabelle JEDE Pruefung der anderen Kit-Module?

    WARUM (2026-09-23): `AUSGELIEFERTE_PRUEFUNGEN` schliesst die Luecke, die die
    Introspektion liess — aber als **handgefuehrte Liste**. Wer morgen eine Pruefung in
    `backlog.py` hinzufuegt und die Zeile hier vergisst, hat die alte Blindheit zurueck,
    nur eine Ebene hoeher. Genau so entstand der erste Fall: der Waechter wurde gebaut,
    `manifest.pruefe` stand nicht drin, und niemand merkte es, weil nichts es prueft.

    *Wer eine Liste einfuehrt, um eine Konvention zu ersetzen, muss die Liste pruefen —
    sonst hat er die Konvention nur umbenannt.*

    Deshalb vergleicht diese Funktion die Tabelle gegen den Quellbaum: jede oberste
    `pruefe*`-Funktion eines Kit-Moduls ausser `hygiene` selbst muss in **genau einer**
    der beiden Listen stehen. Sie liest per AST, importiert also nichts.
    """
    treffer = []
    wurzel = kit_verzeichnis or HIER
    gefordert = {(m, f) for m, f in AUSGELIEFERTE_PRUEFUNGEN}
    werkzeug = {(m, f) for m, f, _ in KIT_WERKZEUGE}

    for m, f, grund in KIT_WERKZEUGE:
        if not str(grund).strip():
            treffer.append(f"{m}.{f} steht als Werkzeug ohne Grund — ein Grund ist Pflicht")
    for doppelt in sorted(gefordert & werkzeug):
        treffer.append(f"{doppelt[0]}.{doppelt[1]} steht in BEIDEN Listen — gefordert "
                       f"oder angeboten, nicht beides")

    # ZWEI Mengen, und die Trennung ist der Kern: `alle` beantwortet "existiert die
    # Tabellenzeile noch?" und darf am Namen NICHT haengen — sonst meldet die Pruefung
    # `alle_pruefungen` als verschwunden, weil der Name nicht `pruefe` vorne hat. Genau
    # der Praefix-Filter, dessen Blindheit dieser ganze Umbau behebt; er kroch beim ersten
    # Versuch sofort wieder herein.
    #
    # `gefunden` beantwortet die andere Richtung — "gibt es eine Pruefung, die in keiner
    # Liste steht?" — und DA ist der Praefix eine Heuristik mit **benannter Grenze**: eine
    # neue `pruefe_*` faellt auf, eine neue `bewerte_*` nicht. Mechanisch ist "was ist eine
    # Pruefung?" nicht entscheidbar; deshalb steht die Grenze hier, statt so zu tun, als
    # gaebe es sie nicht.
    alle: set[tuple[str, str]] = set()
    gefunden = set()
    # Was eine eingetragene Funktion SELBST ruft, gilt als abgedeckt — sonst meldet die
    # Pruefung die Teile einer Sammelfunktion als "nicht eingetragen" und treibt genau
    # die Einzel-Eintraege herbei, die in 0.17.0 sechs Repos rot machten (s. oben).
    ueber_sammler: set[tuple[str, str]] = set()
    for datei in sorted(glob.glob(os.path.join(wurzel, "*.py"))):
        modul = os.path.splitext(os.path.basename(datei))[0]
        if modul in ("hygiene", "__init__"):
            continue
        try:
            with open(datei, encoding="utf-8") as fh:
                baum = ast.parse(fh.read())
        except (OSError, SyntaxError) as fehler:
            treffer.append(f"Kit-Modul {modul} nicht lesbar: {fehler}")
            continue
        for knoten in baum.body:
            if not isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            alle.add((modul, knoten.name))
            if knoten.name.startswith("pruefe"):
                gefunden.add((modul, knoten.name))
            if (modul, knoten.name) in gefordert or (modul, knoten.name) in werkzeug:
                for inner in ast.walk(knoten):
                    if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
                        ueber_sammler.add((modul, inner.func.id))

    for m, f in sorted(gefunden - gefordert - werkzeug - ueber_sammler):
        treffer.append(f"{m}.{f} ist eine Pruefung des Kits, steht aber in KEINER Liste — "
                       f"in AUSGELIEFERTE_PRUEFUNGEN eintragen (dann muss jedes Repo sie "
                       f"rufen) oder mit Grund in KIT_WERKZEUGE")
    for m, f in sorted((gefordert | werkzeug) - alle):
        if m == "hygiene":
            continue
        treffer.append(f"{m}.{f} steht in der Tabelle, existiert im Kit aber nicht "
                       f"(umbenannt oder entfernt?)")
    return treffer


FIXTURE_SCHMUTZIG = "fixture_geheimnis_schmutzig.txt"
FIXTURE_SAUBER = "fixture_geheimnis_sauber.txt"


def _fixture_zeilen(kit_verzeichnis: str, name: str) -> list[str]:
    pfad = os.path.join(kit_verzeichnis, name)
    with open(pfad, encoding="utf-8") as fh:
        return [z for z in zeilen_wie_grep(fh.read()) if z and not z.startswith("#")]


def pruefe_fixture_deckt_muster(policy: dict,
                                kit_verzeichnis: str | None = None) -> list[str]:
    """Jede Musterzeile braucht einen Fall in der Fixture — und die Fixture keinen Fehlalarm.

    WARUM (2026-09-24): Die Fixture behauptete in ihrem eigenen Kopf „JEDE Zeile der
    Musterliste hat hier einen Fall". Als die Liste um `nbp_` (NetBird-PAT) und `pat=`
    wuchs, wuchs die Fixture NICHT mit — und der Selbsttest blieb gruen, weil er nur
    gegen eine harte Zahl (13) prueft. Eine Zusage, die niemand nachmisst, ist keine
    Zusage: das neue Muster war ab dem Tag seiner Aufnahme ungeprueft.

    GRENZE, die diese Pruefung NICHT schliesst: sie deckt MUSTERZEILEN ab, nicht die
    Alternativen INNERHALB einer Zeile. Das Zuweisungsmuster ist eine einzige Zeile mit
    einem Dutzend Schluesselwoertern (`token`, `secret`, `pat`, …); faellt eines davon
    weg, bleibt die Zeile getroffen und diese Pruefung schweigt. Wer ein Schluesselwort
    ergaenzt, ergaenzt die Fixture von Hand — hier steht nur, dass es kein Muster OHNE
    jeden Fall geben kann.
    """
    kit_verzeichnis = kit_verzeichnis or os.path.dirname(os.path.abspath(__file__))
    befunde: list[str] = []
    try:
        schmutzig = _fixture_zeilen(kit_verzeichnis, FIXTURE_SCHMUTZIG)
        sauber = _fixture_zeilen(kit_verzeichnis, FIXTURE_SAUBER)
    except OSError as e:
        return [f"Fixture nicht lesbar: {e} — der Selbsttest der Muster ist nicht messbar"]
    if not schmutzig:
        return [f"{FIXTURE_SCHMUTZIG} enthaelt keinen Fall — ein leerer Selbsttest ist gruen und wertlos"]

    muster = grep_muster(policy)
    ausnahmen = [re.compile(a) for a in grep_ausnahmen(policy)]

    def trifft(regex, zeilen: list[str]) -> list[str]:
        r = re.compile(regex)
        return [z for z in zeilen
                if r.search(z) and not any(a.search(z) for a in ausnahmen)]

    for m in muster:
        if not trifft(m, schmutzig):
            befunde.append(
                f"kein Fall in {FIXTURE_SCHMUTZIG} fuer das Muster {m[:48]}… — "
                "es koennte geloescht werden, ohne dass der Selbsttest rot wird")

    for m in muster:
        for z in trifft(m, sauber):
            befunde.append(
                f"{FIXTURE_SAUBER}: Fehlalarm auf einem Platzhalter ({z[:40]}…) — "
                "ein Waechter, dem man nicht glaubt, wird abgeschaltet")
    return befunde
