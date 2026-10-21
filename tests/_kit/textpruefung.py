#!/usr/bin/env python3
"""Textprüfung — tote Links, tote Anker, optional Frontmatter in Markdown (repokit T-16, Kit 0.35.0).

    python3 tests/_kit/textpruefung.py [--wurzel DIR] [--frontmatter SCHLUESSEL,…] [DATEI …]
    python3 tests/_kit/textpruefung.py --selbsttest

Ohne DATEI: alle *.md unter der Wurzel (ohne .git, node_modules, .venv*). Exit 0 sauber · 1 Befunde · 2 nichts geprüft
(eine Prüfung über null Dateien ist kein Grün).

WARUM (PO 2026-10-15): Text- und Doku-Änderungen fahren nur noch ihre eigene Prüfung statt der ganzen Pipeline. Das
Kit prüfte Texte bis dahin nur mit hygiene.py (Infrastruktur, Geheimnisse, Fremdressourcen); tote Links und Anker sah
niemand. Dieser Baustein ist der Kern des Text-Schnellwegs (`scripts/_nur_text.sh`): Im Text-Modus laufen hygiene.py
und er, sonst nichts. Er weiß nichts über eine Infrastruktur und braucht kein Repo — Wurzel und Pfadliste kommen als
Argumente, damit auch ein Wiki-Werkzeug (dokutool lint) ihn rufen kann. Nur stdlib.

Was geprüft wird, je Markdown-Datei (Code — eingezäunt, eingerückt, inline — zählt nicht; ein zitiertes Beispiel ist
kein Verweis):
  * relative Links `[x](pfad)` und Bilder `![x](pfad)`: das Ziel existiert und liegt innerhalb der Wurzel. Externe
    Ziele (`http:`, `mailto:` …) prüft er nicht — kein Netz.
  * Anker `#frag` und `datei.md#frag`: die Zielseite hat die Überschrift (GitHub-Slug, doppelte mit -1, -2 …) oder ein
    `<a id|name="frag">`.
  * Frontmatter: steht eine am Anfang (`---`), muss sie geschlossen sein, jede oberste Zeile `schluessel: wert`, und ein
    unquotierter Wert mit `: ` ist ein Befund (YAML liest ihn als Abbildung). Mit --frontmatter muss jede Datei eine
    tragen, mit genau diesen Pflichtschlüsseln.
Nicht geprüft (bewusst): Referenz-Links `[x][ref]`, HTML-`href`, Wikilinks.

Herkunft: Code-Ausblendung, Slug und Anker aus dokutool (LinuxTools, `bin/dokutool.py`, Stand 2026-10-15) übernommen,
damit Wiki und Repos dieselbe Antwort geben.
"""
from __future__ import annotations

import os
import re
import sys
import urllib.parse

FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})(.*)$")
INLINE_CODE_RE = re.compile(r"(`+)(.+?)\1")
LISTENPUNKT_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
MD_LINK_RE = re.compile(r"\[([^\]]*)\]\(\s*<?([^)\s>]+?)>?(?:\s+\"[^\"]*\")?\s*\)")
HEADING_RE = re.compile(r"^ {0,3}(#{1,6})[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$")
ANKER_TAG_RE = re.compile(r"<a\s[^>]*?\b(?:id|name)\s*=\s*[\"']([^\"']+)[\"']", re.I)
SCHEMA_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
AUSLASSEN = {".git", "node_modules", "__pycache__"}


def zeilen_ohne_code(text: str):
    """(zeile, ist_code) je Zeile: eingezäunter Code (``` / ~~~, auch eingerückt) und eingerückter Code (4 Leerzeichen
    nach einer Leerzeile, außerhalb einer Liste)."""
    in_fence, zeichen, laenge = False, "", 0
    nach_leer, in_liste = True, False
    for zeile in text.split("\n"):
        m = FENCE_RE.match(zeile)
        if in_fence:
            if m and m.group(2)[0] == zeichen and len(m.group(2)) >= laenge and not m.group(3).strip():
                in_fence = False
            yield zeile, True
            continue
        if m:
            in_fence, zeichen, laenge = True, m.group(2)[0], len(m.group(2))
            yield zeile, True
            continue
        if not zeile.strip():
            nach_leer = True
            yield zeile, False
            continue
        breit = zeile.expandtabs(4)
        einzug = len(breit) - len(breit.lstrip())
        if LISTENPUNKT_RE.match(zeile):
            in_liste = True
        elif einzug == 0:
            in_liste = False
        ist_code = einzug >= 4 and nach_leer and not in_liste
        nach_leer = False
        yield zeile, ist_code


def ohne_code(text: str) -> str:
    return "\n".join("" if code else INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), z)
                     for z, code in zeilen_ohne_code(text))


def github_slug(titel: str) -> str:
    """Überschrift → Anker wie bei GitHub: Markup raus, klein, nur Buchstaben/Ziffern/_/-/Leerzeichen, Leerzeichen → -."""
    t = re.sub(r"<[^>]+>", "", titel)
    t = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"[`*]", "", t).strip().lower()
    return re.sub(r"[^\w\- ]", "", t).replace(" ", "-")


def anker_von(text: str) -> set[str]:
    aus: set[str] = set()
    gesehen: dict[str, int] = {}
    for zeile, code in zeilen_ohne_code(text):
        if code:
            continue
        ist_titel = HEADING_RE.match(zeile)
        zeile = INLINE_CODE_RE.sub(lambda m: m.group(2), zeile) if ist_titel else INLINE_CODE_RE.sub("", zeile)
        m = HEADING_RE.match(zeile)
        if m:
            sl = github_slug(m.group(2))
            n = gesehen.get(sl, 0)
            gesehen[sl] = n + 1
            aus.add(sl if n == 0 else f"{sl}-{n}")
        for a in ANKER_TAG_RE.findall(zeile):
            aus.add(a.strip().lower())
    return aus


def frontmatter_befunde(rel: str, text: str, pflicht: list[str] | None) -> list[str]:
    zeilen = text.split("\n")
    if not zeilen or zeilen[0].strip() != "---":
        return [f"{rel}: keine Frontmatter (Pflicht: {', '.join(pflicht)})"] if pflicht else []
    try:
        ende = next(i for i in range(1, len(zeilen)) if zeilen[i].strip() in ("---", "..."))
    except StopIteration:
        return [f"{rel}: Frontmatter nicht geschlossen (fehlendes `---`)"]
    befunde, schluessel = [], set()
    for n, z in enumerate(zeilen[1:ende], 2):
        if not z.strip() or z.lstrip().startswith("#") or z[0] in " \t-":
            continue
        m = re.match(r"^([A-Za-z_][\w-]*):(?:\s+(.*))?$", z)
        if not m:
            befunde.append(f"{rel}:{n}: Frontmatter-Zeile ist kein `schluessel: wert`")
            continue
        schluessel.add(m[1])
        wert = (m[2] or "").strip()
        if wert and wert[0] not in "\"'[{|>" and ": " in wert:
            befunde.append(f"{rel}:{n}: Wert von `{m[1]}` enthält `: ` ohne Anführungszeichen (YAML liest eine Abbildung)")
    for p in pflicht or []:
        if p not in schluessel:
            befunde.append(f"{rel}: Frontmatter ohne Pflichtschlüssel `{p}`")
    return befunde


def alle_md(wurzel: str) -> list[str]:
    aus = []
    for verz, unter, namen in os.walk(wurzel):
        unter[:] = sorted(u for u in unter if u not in AUSLASSEN and not u.startswith(".venv"))
        aus += [os.path.relpath(os.path.join(verz, n), wurzel) for n in sorted(namen) if n.endswith(".md")]
    return aus


def pruefe(wurzel: str, dateien: list[str] | None = None, frontmatter: list[str] | None = None) -> tuple[list[str], int]:
    """(Befunde, Zahl der geprüften Markdown-Dateien). `dateien` relativ zur Wurzel oder absolut; nur *.md zählen."""
    wurzel = os.path.realpath(wurzel)
    rels = [os.path.relpath(os.path.realpath(d) if os.path.isabs(d) else os.path.join(wurzel, d), wurzel)
            for d in (alle_md(wurzel) if dateien is None else dateien)]
    rels = sorted({r for r in rels if r.endswith(".md") and os.path.isfile(os.path.join(wurzel, r))})
    befunde: list[str] = []
    ankercache: dict[str, set[str]] = {}

    def lies(pfad: str) -> str | None:
        try:
            with open(pfad, encoding="utf-8") as fh:
                return fh.read()
        except (OSError, UnicodeDecodeError):
            return None

    def anker(pfad: str) -> set[str] | None:
        if pfad not in ankercache:
            t = lies(pfad)
            if t is None:
                return None
            ankercache[pfad] = anker_von(t)
        return ankercache[pfad]

    for rel in rels:
        quelle = os.path.join(wurzel, rel)
        text = lies(quelle)
        if text is None:
            befunde.append(f"{rel}: nicht lesbar (UTF-8?)")
            continue
        befunde += frontmatter_befunde(rel, text, frontmatter)
        for n, zeile in enumerate(ohne_code(text).split("\n"), 1):
            for _titel, ziel in MD_LINK_RE.findall(zeile):
                if SCHEMA_RE.match(ziel) or ziel.startswith("//"):
                    continue                         # extern: kein Netz
                pfad, _, frag = ziel.partition("#")
                pfad = urllib.parse.unquote(pfad.split("?", 1)[0])
                frag = urllib.parse.unquote(frag).strip().lower()
                if pfad:
                    basis = wurzel if pfad.startswith("/") else os.path.dirname(quelle)
                    abs_ziel = os.path.realpath(os.path.join(basis, pfad.lstrip("/")))
                    if abs_ziel != wurzel and not abs_ziel.startswith(wurzel + os.sep):
                        befunde.append(f"{rel}:{n}: Link {ziel} zeigt aus der Wurzel hinaus")
                        continue
                    if not os.path.exists(abs_ziel):
                        befunde.append(f"{rel}:{n}: toter Link {ziel}")
                        continue
                else:
                    abs_ziel = quelle
                if frag and not frag.startswith(":~:") and abs_ziel.endswith(".md") and os.path.isfile(abs_ziel):
                    a = anker(abs_ziel)
                    if a is not None and frag not in a:
                        befunde.append(f"{rel}:{n}: toter Anker {ziel} (Überschrift bzw. <a id> fehlt im Ziel)")
    return befunde, len(rels)


def selbsttest() -> int:
    import tempfile
    rot = []
    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "docs"))

        def schreib(rel: str, inhalt: str) -> None:
            with open(os.path.join(t, rel), "w", encoding="utf-8") as fh:
                fh.write(inhalt)
        schreib("README.md", "---\ntitle: Start\n---\n# Start\n\n## Größe & Maß\n\n<a id=\"fest\"></a>\n"
                "[doku](docs/a.md) · [abschnitt](docs/a.md#zweiter-teil) · [hier](#größe--maß) · [fest](#fest)\n"
                "[extern](https://example.com/x) · ![bild](docs/bild.png)\n\n```\n[im code](gibt-es-nicht.md)\n```\n"
                "und `[inline](auch-nicht.md)`\n")
        schreib("docs/a.md", "# A\n\n## Zweiter Teil\n\n[zurück](../README.md#start)\n")
        schreib("docs/bild.png", "png")
        befunde, n = pruefe(t)
        if befunde or n != 2:
            rot.append(f"sauberer Baum: {befunde} ({n} Dateien)")
        faelle = [
            ("toter Link", "docs/a.md", "# A\n\n## Zweiter Teil\n\n[weg](../fehlt.md)\n", "toter Link"),
            ("toter Anker", "docs/a.md", "# A\n\n## Anders\n\n[zurück](../README.md#start)\n", "toter Anker"),
            ("Link aus der Wurzel hinaus", "docs/a.md", "# A\n\n## Zweiter Teil\n\n[raus](../../x.md)\n",
             "aus der Wurzel"),
            ("Frontmatter mit `: ` im Wert", "docs/a.md",
             "---\ndescription: Wann: immer\n---\n# A\n\n## Zweiter Teil\n", "ohne Anführungszeichen"),
            ("Frontmatter nicht geschlossen", "docs/a.md", "---\ntitle: A\n# A\n\n## Zweiter Teil\n", "nicht geschlossen"),
        ]
        for name, rel, inhalt, muster in faelle:
            with open(os.path.join(t, rel), encoding="utf-8") as fh:
                alt = fh.read()
            schreib(rel, inhalt)
            befunde, _ = pruefe(t)
            if not any(muster in b for b in befunde):
                rot.append(f"{name}: nicht erkannt ({befunde})")
            schreib(rel, alt)
        befunde, _ = pruefe(t, frontmatter=["title", "type"])
        if not any("Pflichtschlüssel `type`" in b for b in befunde) or not any("keine Frontmatter" in b for b in befunde):
            rot.append(f"--frontmatter: Pflicht nicht durchgesetzt ({befunde})")
        befunde, n = pruefe(t, dateien=["docs/bild.png"])
        if n != 0:
            rot.append("eine Nicht-Markdown-Datei wurde als geprüft gezählt")
    for r in rot:
        print(f"  ✗ textpruefung-Selbsttest: {r}", file=sys.stderr)
    if rot:
        return 1
    print("  ✓ textpruefung: Selbsttest (sauber, toter Link, toter Anker, aus der Wurzel, Frontmatter)")
    return 0


def main(argv: list[str]) -> int:
    if "--selbsttest" in argv:
        return selbsttest()
    wurzel, pflicht, dateien = ".", None, []
    it = iter(argv)
    for a in it:
        if a == "--wurzel":
            wurzel = next(it, ".")
        elif a == "--frontmatter":
            pflicht = [p for p in next(it, "").split(",") if p]
        elif a.startswith("-"):
            print(f"textpruefung: unbekannte Option {a}", file=sys.stderr)
            return 2
        else:
            dateien.append(a)
    befunde, n = pruefe(wurzel, dateien or None, pflicht)
    for b in befunde:
        print(f"  ✗ {b}", file=sys.stderr)
    if n == 0:
        print("textpruefung: keine Markdown-Datei geprüft — NICHTS geprüft (kein Grün)", file=sys.stderr)
        return 2
    if befunde:
        return 1
    print(f"  ✓ textpruefung: {n} Markdown-Datei(en), Links und Anker stimmen")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
