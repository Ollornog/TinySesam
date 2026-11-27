#!/usr/bin/env python3
"""Release-Automatik eigener Abbilder — Patch-Release nach einem Dependabot-Merge und Pin-PR im Ziel-Repo.

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.

WARUM (PO 2026-11-15, „ja, für alle“): Ein Dependabot-Merge, der das Abbild einer App ändert (Basisabbild, Sperrliste,
go.mod), landete auf `main`, aber niemand schnitt ein Release, und der Pin im Ziel-Repo (Compose der Flotte) wartete auf
Hand. Sicherheitsfixes erreichten den Betrieb so nie von selbst. Die Kette:

    Dependabot-Merge (Auto-Merge sieht: Pfade des Abbilds berührt)
      → release.yml per workflow_dispatch, `automatik=vorbereiten`: dieses Skript hebt die Patch-Version und den
        CHANGELOG und öffnet mit dem App-Token den PR `release/v<version>`
      → Pflicht-Checks grün → Auto-Merge (Autor die App, nur die Dateien aus `RELEASE_DATEIEN`)
      → release.yml per workflow_dispatch, `automatik=taggen`: dieses Skript prüft den Stand und setzt den Tag
      → Tag-Lauf von release.yml baut das Abbild, danach `fc-pin`: Pin-PR `pin/<repo>` im Ziel-Repo (EINER je Quell-Repo,
        fortgeschrieben; mit PIN_ANHAENGE `pin/<repo>-<tag>`, ältere werden geschlossen — seit 0.58.0)
      → dort Startprobe und Auto-Merge (nur Pin-Zeilen), danach der Converge der Flotte.

Warum ein Release-PR statt eines direkten Commits: Öffentliche Repos verlangen Pflicht-Checks auf `main`; ein direkter
Push der Versionsänderung wäre abgewiesen. Der PR nimmt dieselben Checks ab wie jeder andere.

Konfiguration je Repo: `.github/release-automatik.json`

    {
      "schema": "semver" | "datum",            # v1.2.3 → v1.2.4 | vJJJJ.MM.TT (Europe/Berlin), am selben Tag .1, .2 …
      "versionsdateien": [{"datei": "pyproject.toml", "muster": "^version = \\"(?P<v>[^\\"]+)\\"$"}],   # nur semver;
                                               # "alle": true = jeder Treffer (mind. einer, alle gleich) wird gehoben
      "changelog": {"datei": "CHANGELOG.md", "form": "keepachangelog" | "datum", "sprache": "de" | "en",
                    "kopf": "## [{version}] - {datum}",   # kopf optional, Vorgaben siehe KOPF
                    "erlaubt": ["Fixed", "Security", "Dependencies"]} | null,   # erlaubt optional, siehe unten
      "versionsbefehl": ["scripts/_release.py", "{version}"],   # optional: eigenes Werkzeug des Repos setzt die Version
      "pruefbefehl": ["scripts/_release.py", "--check"],        # optional: vor dem Tag, rc != 0 → kein Tag
      "abbilder": ["<registry>/<owner>/<name>"],  # was der Tag-Lauf veröffentlicht; fc-pin hebt genau diese Pins
      "dockerfiles": {"<registry>/<owner>/<name>": "app/Dockerfile"}   # optional (0.64.0): Dockerfile je Abbild
    }

Schutz vor falschen Patch-Releases (seit 0.55.0): `vorbereiten` schneidet nur einen Patch. Steht unter [Unreleased] aber
Neues (`### Added`, `### Changed` …) oder Text ohne Kategorie, verweigert es (rc 1, Meldung samt Job-Summary): Das ist ein
Minor und gehört einem Menschen. Erlaubt sind die Kategorien aus `changelog.erlaubt` (Namen ohne Beachtung der
Groß-/Kleinschreibung; ein Zusatz nach ` — ` an der Überschrift zählt nicht); Vorgabe je Sprache: en Fixed, Security,
Dependencies · de Behoben, Sicherheit, Abhängigkeiten. `["*"]` schaltet die Prüfung ab. Gilt für `keepachangelog`.

Aufrufe (GH_TOKEN = App-Token; GITHUB_REPOSITORY wie in Actions):

    _release_automatik.py vorbereiten                       # Version + CHANGELOG, PR release/v<version>
    _release_automatik.py taggen --version X                # Stand von main prüfen, Tag v<X> setzen
    _release_automatik.py fc-pin --tag vX --ziel OWNER/REPO # Digests auflösen, Pin-PR im Ziel-Repo
    _release_automatik.py naechste                          # nur ausgeben, was `vorbereiten` schneiden würde
    _release_automatik.py neubau                            # weekly rebuild check (kit 0.64.0), see below

Release-Anhänge im Pin-PR (seit 0.48.0, PO 2026-11-15): Liefert ein Release neben dem Abbild Dateien, die das Ziel-Repo
neben der Compose hält (paperlaiss: Skripte und Knöpfe samt SHA256SUMS), nimmt `fc-pin` sie mit, wenn die Repo-Variable
`PIN_ANHAENGE` (Umgebung des Tag-Laufs) sie nennt — Leerzeichen-getrennt `<ordner>:<datei>` oder `<ordner>:*` (alle
Dateien der SHA256SUMS und sie selbst). Der Ordner muss im Ziel schon bestehen. `fc-pin` lädt SHA256SUMS und Anhänge vom
Release des Tags, prüft jeden Hash und schreibt nur, was sich unterscheidet (Dateimodus bleibt). Der Auto-Merge des
Ziels (`PIN_ANHAENGE` im Block je Repo) prüft dasselbe gegen das Release. Ohne die Variable bleibt alles wie vorher.
Gelesen wird das Release mit `QUELLE_TOKEN` (Workflow-Token des App-Repos), sonst mit GH_TOKEN.

Weekly rebuild (kit 0.64.0, PO 2026-11-23): the dependabot auto-merge workflow (template) runs `neubau` once a week on a
clone of the default branch, read-only. Reasons for a patch release, per image in `abbilder`, against the image of the
last release tag: (a) no external FROM of the image's Dockerfile is the base of the released image any more (its layers
are no prefix of the released image's layers — the base tag moved, or a base bump was merged without a release), or
(b) grype (pinned image, GRYPE_IMAGE) finds a fixable finding of severity High or above (`.grype.yaml` exceptions count).
With a reason it writes `reason=…` to GITHUB_OUTPUT and the workflow dispatches `vorbereiten`; without one nothing
happens. The Dockerfile: `dockerfiles` in the config (image → path), else `Dockerfile` in the root, else the only one.

stdlib-only. Nach außen nur `git`, `gh` und `docker buildx imagetools inspect` (fc-pin); `neubau` liest Abbilder nur über
grype (Funde und Schichten aus seinem JSON) und holt grype per `gh release download` — kein Docker-Daemon, kein
Registry-Name in dieser Datei.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

KONFIG = ".github/release-automatik.json"
# Login des App-Bots, der die PRs öffnet. Der Auto-Merge prüft genau ihn (Vorlage, APP_LOGIN).
APP_LOGIN = "ollornog-auto-merge[bot]"
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
DATUM = re.compile(r"^(20\d\d)\.([01]\d)\.([0-3]\d)(?:\.(\d+))?$")
UNVEROEFFENTLICHT = re.compile(r"^## \[(Unreleased|Unveröffentlicht)\][ \t]*$", re.M)
# Pin-Zeile einer Compose: `image: <abbild>:<tag>@sha256:<64 hex>` — nur so gepinnte Abbilder hebt fc-pin.
PIN = r"^(?P<vor>\s*image:\s*)(?P<abbild>{abbild}):(?P<tag>[A-Za-z0-9._-]+)@(?P<digest>sha256:[0-9a-f]{{64}})(?P<nach>\s*(?:#.*)?)$"


class Fehler(Exception):
    """Ein Zustand, in dem die Automatik nichts tun darf (Meldung für Menschen, Lauf rot)."""


class Halt(Fehler):
    """By design nothing to do, a human decides (since 0.65.0): a notice and a summary, the run stays green.

    WHY: [Unreleased] with Added/Changed is a minor — no patch release, the release is cut by a human. Up to 0.64 that
    ended red after every Dependabot merge in such a repo, and ci-wache reported "main red — release" for a state that is
    intended (TinySesam, UnderDoc, paperlaiss, PWM-Control, DashMyBoard). Not silent either: the notice names what waits.
    """


# ── reine Funktionen (getestet in repokit tests/test_release_automatik.py) ────────────────────────────────────────────────────

def lade_konfig(root: str) -> dict:
    try:
        with open(os.path.join(root, KONFIG), encoding="utf-8") as fh:
            k = json.load(fh)
    except OSError as e:
        raise Fehler(f"{KONFIG} fehlt — ohne sie gibt es keine Release-Automatik") from e
    if k.get("schema") not in ("semver", "datum"):
        raise Fehler(f"{KONFIG}: schema muss semver oder datum sein")
    if k["schema"] == "semver" and not k.get("versionsdateien"):
        raise Fehler(f"{KONFIG}: semver braucht versionsdateien")
    for a in k.get("abbilder") or []:
        if not re.fullmatch(r"[a-z0-9.-]+/[a-z0-9._-]+/[a-z0-9._/-]+", a):
            raise Fehler(f"{KONFIG}: Abbild {a!r} nicht in der Form registry/owner/name")
    df = k.get("dockerfiles")
    if df is not None and (not isinstance(df, dict) or any(
            a not in (k.get("abbilder") or []) or not isinstance(p, str) or not p or p.startswith("/") or ".." in p.split("/")
            for a, p in df.items())):
        raise Fehler(f"{KONFIG}: dockerfiles muss Abbild (aus abbilder) → relativer Pfad sein")
    return k


def version_in(text: str, muster: str, alle: bool = False) -> str:
    """Die Version, die `muster` (Gruppe `v`) trifft — genau einmal, oder mit `alle` mindestens einmal und überall gleich
    (Beispiel-Pins in README und Compose, die die Suite des Repos an die aktuelle Version bindet)."""
    treffer = list(re.finditer(muster, text, re.M))
    if not treffer or (len(treffer) != 1 and not alle):
        raise Fehler(f"Muster {muster!r} trifft {len(treffer)}-mal statt " + ("mindestens einmal" if alle else "genau einmal"))
    werte = {t.group("v") for t in treffer}
    if len(werte) != 1:
        raise Fehler(f"Muster {muster!r} trifft verschiedene Versionen {sorted(werte)}")
    return werte.pop()


def setze_version(text: str, muster: str, neu: str, alle: bool = False) -> str:
    version_in(text, muster, alle)
    for m in reversed(list(re.finditer(muster, text, re.M))):
        a, b = m.span("v")
        text = text[:a] + neu + text[b:]
    return text


def _sv(v: str) -> tuple[int, int, int]:
    m = SEMVER.match(v)
    if not m:
        raise Fehler(f"{v!r} ist keine Version X.Y.Z")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def naechste_version(schema: str, quelltext: str | None, tags: list[str], heute: datetime.date) -> str:
    """Die Version des nächsten Patch-Release (ohne `v`).

    semver: Patch +1 auf den letzten Tag. Steht im Quelltext schon eine NEUERE Version als der letzte Tag, ist ein Release
    in Vorbereitung — dann setzt die Automatik aus (sie würde es sonst überholen). Ohne jeden Tag ebenso: das erste
    Release schneidet ein Mensch.
    datum: vJJJJ.MM.TT, gibt es den Tag schon, .1, .2 …
    """
    if schema == "datum":
        basis = heute.strftime("%Y.%m.%d")
        if f"v{basis}" not in tags:
            return basis
        n = 1
        while f"v{basis}.{n}" in tags:
            n += 1
        return f"{basis}.{n}"
    versionen = sorted((_sv(t[1:]) for t in tags if t.startswith("v") and SEMVER.match(t[1:])), reverse=True)
    if not versionen:
        raise Fehler("kein Release-Tag v<X.Y.Z> — das erste Release schneidet ein Mensch")
    letzte = versionen[0]
    if quelltext is not None and _sv(quelltext) > letzte:
        raise Fehler(f"Version im Quelltext {quelltext} ist neuer als der letzte Tag v{'.'.join(map(str, letzte))} — "
                     "ein Release ist in Vorbereitung, die Automatik setzt aus")
    return f"{letzte[0]}.{letzte[1]}.{letzte[2] + 1}"


_TEXTE = {
    # titel: Überschrift der Form datum; kategorie: Abschnitt in keepachangelog — eine Kategorie, die Keep-a-Changelog-
    # Prüfungen der Repos kennen (DashMyBoard verlangt sie), nicht frei erfunden.
    "de": {"titel": "Abhängigkeiten", "kategorie": "Geändert", "kopf": "Patch-Release der Release-Automatik nach Dependabot-Merges:",
           "leer": "Patch-Release der Release-Automatik (Abbild neu gebaut)."},
    "en": {"titel": "Dependencies", "kategorie": "Changed", "kopf": "Patch release cut by the release automation after Dependabot merges:",
           "leer": "Patch release cut by the release automation (image rebuilt)."},
}


# Kopfzeile des neuen Abschnitts je Form (überschreibbar mit changelog.kopf; Platzhalter {version} {datum} {titel}).
KOPF = {"keepachangelog": "## [{version}] — {datum}", "datum": "## {datum} — {titel} (v{version})"}


ERLAUBT = {"de": ["Behoben", "Sicherheit", "Abhängigkeiten"], "en": ["Fixed", "Security", "Dependencies"]}


def unreleased_unerlaubt(text: str, erlaubt: list[str]) -> list[str]:
    """Kategorien unter [Unreleased], die kein Patch-Release tragen dürfen (leer = alles in Ordnung). Text ohne
    Kategorie-Überschrift zählt als `(ohne Kategorie)`. `*` in `erlaubt` schaltet die Prüfung ab."""
    if "*" in erlaubt:
        return []
    m = UNVEROEFFENTLICHT.search(text)
    if not m:
        return []
    rest = text[m.end():]
    n = re.search(r"^## ", rest, re.M)
    block = rest[:n.start()] if n else rest
    ok = {e.casefold() for e in erlaubt}
    schlecht: list[str] = []
    lose = False
    in_kategorie = False
    for zeile in block.splitlines():
        h = re.match(r"^### (.+?)\s*$", zeile)
        if h:
            in_kategorie = True
            name = re.split(r"\s+[—–-]\s+", h.group(1), maxsplit=1)[0].strip()
            if name.casefold() not in ok and name not in schlecht:
                schlecht.append(name)
        elif zeile.strip() and not in_kategorie:
            lose = True
    return (["(ohne Kategorie)"] if lose else []) + schlecht


def changelog_eintragen(text: str, form: str, sprache: str, version: str, datum: str, eintraege: list[str],
                        kopf: str | None = None) -> str:
    """Den Abschnitt des neuen Release in den CHANGELOG setzen.

    keepachangelog: Was unter [Unreleased]/[Unveröffentlicht] steht, gehört zu diesem Release (es liegt auf main) — es
    wandert unter die neue Version, darüber bleibt ein leeres [Unreleased]. Ohne diesen Kopf kommt der Abschnitt vor die
    erste Version. datum: ein Abschnitt `## JJJJ-MM-TT — …` vor dem ersten `## `.
    """
    t = _TEXTE.get(sprache)
    if t is None:
        raise Fehler(f"sprache {sprache!r}: de oder en")
    liste = "".join(f"- {e}\n" for e in eintraege)
    rumpf = f"{t['kopf']}\n\n{liste}" if eintraege else f"{t['leer']}\n"
    if form not in KOPF:
        raise Fehler(f"changelog.form {form!r}: keepachangelog oder datum")
    zeile = (kopf or KOPF[form]).format(version=version, datum=datum, titel=t["titel"])
    if not zeile.startswith("## ") or "\n" in zeile:
        raise Fehler(f"changelog.kopf {kopf!r}: eine Zeile, beginnt mit `## `")
    if form == "keepachangelog":
        # Hat das Werkzeug des Repos den Abschnitt schon geschlossen ([Unreleased] → [version]), kommt der Eintrag dort hinein.
        da = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n", text, re.M)
        if da:
            neu = text[:da.end()] + f"\n### {t['kategorie']}\n\n{rumpf}" + text[da.end():]
            if not UNVEROEFFENTLICHT.search(neu):
                # Das Werkzeug hat [Unreleased] umbenannt statt ein leeres zu lassen: ohne den Kopf landen spätere
                # Einträge im veröffentlichten Abschnitt (TinySesam v0.26.3/v0.27.1). Ein leeres kommt darüber.
                label = "Unveröffentlicht" if sprache == "de" else "Unreleased"
                neu = neu[:da.start()] + f"## [{label}]\n\n" + neu[da.start():]
            return neu
        m = UNVEROEFFENTLICHT.search(text)
        neu_kopf = f"{zeile}\n\n"
        if m:
            rest = text[m.end():]
            n = re.search(r"^## ", rest, re.M)
            offen = (rest[:n.start()] if n else rest).strip("\n")
            danach = rest[n.start():] if n else ""
            abschnitt = neu_kopf + (offen + "\n\n" if offen else "") + f"### {t['kategorie']}\n\n{rumpf}\n"
            return text[:m.end()] + "\n\n" + abschnitt + danach
        n = re.search(r"^## ", text, re.M)
        if not n:
            raise Fehler("CHANGELOG ohne Abschnitt `## ` — wohin der Eintrag gehört, ist unklar")
        return text[:n.start()] + neu_kopf + f"### {t['kategorie']}\n\n{rumpf}\n" + text[n.start():]
    n = re.search(r"^## ", text, re.M)
    if not n:
        raise Fehler("CHANGELOG ohne Abschnitt `## ` — wohin der Eintrag gehört, ist unklar")
    return text[:n.start()] + f"{zeile}\n\n{rumpf}\n" + text[n.start():]


def pin_ersetzen(text: str, abbild: str, tag: str, digest: str) -> tuple[str, int]:
    """Jede gepinnte Zeile von `abbild` auf `tag@digest` heben. Gibt (Text, Zahl der geänderten Zeilen)."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise Fehler(f"Digest {digest!r} nicht in der Form sha256:<64 hex>")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", tag):
        raise Fehler(f"Tag {tag!r} unzulässig")
    muster = re.compile(PIN.format(abbild=re.escape(abbild)))
    zeilen, n = text.split("\n"), 0
    for i, z in enumerate(zeilen):
        m = muster.match(z)
        if m and (m.group("tag"), m.group("digest")) != (tag, digest):
            zeilen[i] = f"{m.group('vor')}{abbild}:{tag}@{digest}{m.group('nach')}"
            n += 1
    return "\n".join(zeilen), n


def zweigname(art: str, *teile: str) -> str:
    name = "-".join(teile)
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise Fehler(f"Zweigname {art}/{name} unzulässig")
    return f"{art}/{name}"


NAME = re.compile(r"[A-Za-z0-9._-]+")
# Jeder Teil beginnt mit Buchstabe, Ziffer, _ oder - — „.“, „..“ und „.git“ gehen so nicht.
ORDNER = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*")
SUMMEN = "SHA256SUMS"


def anhang_regeln(text: str) -> list[tuple[str, str]]:
    """`PIN_ANHAENGE` lesen: Leerzeichen-getrennt `<ordner>:<datei>` oder `<ordner>:*`. Leer heißt keine Anhänge."""
    regeln = []
    for teil in (text or "").split():
        ordner, _, datei = teil.rpartition(":")
        if not ORDNER.fullmatch(ordner) or not (datei == "*" or NAME.fullmatch(datei)):
            raise Fehler(f"PIN_ANHAENGE: {teil!r} nicht in der Form <ordner>:<datei> oder <ordner>:*")
        regeln.append((ordner, datei))
    return regeln


def summen_lesen(text: str) -> dict[str, str]:
    """SHA256SUMS (`<64 hex>  <name>`, Binärmarke `*` erlaubt) → {name: hash}. Nur flache Namen, keiner doppelt."""
    aus: dict[str, str] = {}
    for z in text.splitlines():
        if not z.strip():
            continue
        m = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)", z)
        if not m or m.group(2) in aus or m.group(2) == SUMMEN:
            raise Fehler(f"{SUMMEN}: Zeile {z!r} unzulässig")
        aus[m.group(2)] = m.group(1)
    if not aus:
        raise Fehler(f"{SUMMEN} ist leer")
    return aus


def anhang_soll(regeln: list[tuple[str, str]], summen: dict[str, str], summen_hash: str) -> dict[str, tuple[str, str]]:
    """Ziel-Pfad → (Name im Release, Soll-Hash). `*` heißt alle Dateien der SHA256SUMS und sie selbst."""
    soll: dict[str, tuple[str, str]] = {}
    for ordner, datei in regeln:
        if datei == "*":
            namen = sorted(summen) + [SUMMEN]
        elif datei == SUMMEN or datei in summen:
            namen = [datei]
        else:
            raise Fehler(f"PIN_ANHAENGE: {datei} steht nicht in der {SUMMEN} des Release")
        for n in namen:
            soll[f"{ordner}/{n}"] = (n, summen_hash if n == SUMMEN else summen[n])
    return soll


def git_blob_sha(inhalt: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(inhalt) + inhalt).hexdigest()


# ── weekly rebuild (kit 0.64.0) — pure functions ───────────────────────────────────────────────────────────────────────
# PO 2026-11-23: an app image is rebuilt once a week only when there is a reason: (a) the base image of the Dockerfile is
# no longer the base of the last released image, or (b) grype finds a fixable finding of severity High or above in the
# released image. Without a reason nothing happens — every release opens a pin PR in the fleet repo.

SCHWERE = ["Negligible", "Low", "Medium", "High", "Critical"]


def _datum_schluessel(v: str) -> tuple[int, int, int, int]:
    m = DATUM.match(v)
    if not m:
        raise Fehler(f"{v!r} ist keine Datumsversion")
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0)


def letzter_release_tag(schema: str, tags: list[str]) -> str | None:
    """The newest release tag `v…` of the schema (semver: highest X.Y.Z; datum: latest date and suffix), or None."""
    passend = [t for t in tags if t.startswith("v") and (SEMVER if schema == "semver" else DATUM).match(t[1:])]
    if not passend:
        return None
    return max(passend, key=lambda t: _sv(t[1:]) if schema == "semver" else _datum_schluessel(t[1:]))


def basis_kandidaten(dockerfile: str) -> tuple[list[str], str | None]:
    """External images named by FROM lines (deduplicated, in order) and the base of the final stage.

    The final base is the last FROM, followed through stage names to an external image; "scratch" if it ends there.
    `--platform=…` is dropped; `$NAME`/`${NAME}` is replaced by an `ARG NAME=default` before the first FROM. A reference
    that still holds a `$` cannot be resolved and is left out (the final base is then None).
    """
    args: dict[str, str] = {}
    stufen: dict[str, str] = {}
    extern: list[str] = []
    letzte: str | None = None
    erster_from = False
    text = re.sub(r"\\\n", " ", dockerfile)
    for zeile in text.split("\n"):
        z = zeile.strip()
        if not erster_from:
            a = re.match(r"(?i)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)\s*$", z)
            if a:
                args[a.group(1)] = a.group(2).strip("\"'")
                continue
        m = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", z)
        if not m:
            continue
        erster_from = True
        bild = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda x: args.get(x.group(1), x.group(0)), m.group(1))
        if "$" in bild:
            ziel = None
        elif bild.lower() in stufen:
            ziel = stufen[bild.lower()]
        elif bild.lower() == "scratch":
            ziel = "scratch"
        else:
            ziel = bild
            if bild not in extern:
                extern.append(bild)
        if m.group(2):
            stufen[m.group(2).lower()] = ziel
        letzte = ziel
    return extern, letzte


def basis_unveraendert(release_schichten: list[str], kandidaten: dict[str, list[str]]) -> str | None:
    """The candidate whose layers (rootfs diff_ids) are a non-empty prefix of the released image's — that image is still
    the base. None: no FROM of the Dockerfile is the base of the released image any more."""
    for ref, schichten in kandidaten.items():
        if schichten and release_schichten[:len(schichten)] == schichten:
            return ref
    return None


def behebbare_treffer(grype_json: str, schwelle: str = "High") -> list[str]:
    """Findings of a grype JSON report with a fix (fix.state "fixed" and a version) at `schwelle` or above, one line each
    (`<id> <severity> <package> <version> → <fix>`), sorted and without duplicates. Ignored matches (`.grype.yaml`) are
    not in `matches` and do not count."""
    try:
        bericht = json.loads(grype_json)
    except ValueError as e:
        raise Fehler(f"grype: keine JSON-Ausgabe ({e})") from e
    if not isinstance(bericht, dict) or not isinstance(bericht.get("matches"), list):
        raise Fehler("grype: Bericht ohne `matches` — Format unbekannt, kein Urteil")
    return sorted({f["zeile"] for f in _behebbare(bericht, schwelle)})


def behebbare_funde(grype_json: str, schwelle: str = "High") -> list[dict]:
    """Like `behebbare_treffer`, one dict per finding: id, schwere, paket, version, fix, pfade (locations in the image),
    zeile (the line of `behebbare_treffer`). For the image audit (kit 0.72.0), whose exceptions name a path prefix."""
    try:
        bericht = json.loads(grype_json)
    except ValueError as e:
        raise Fehler(f"grype: keine JSON-Ausgabe ({e})") from e
    if not isinstance(bericht, dict) or not isinstance(bericht.get("matches"), list):
        raise Fehler("grype: Bericht ohne `matches` — Format unbekannt, kein Urteil")
    return _behebbare(bericht, schwelle)


def _behebbare(bericht: dict, schwelle: str) -> list[dict]:
    grenze = SCHWERE.index(schwelle)
    aus: list[dict] = []
    for t in bericht["matches"]:
        v = t.get("vulnerability") or {}
        fix = v.get("fix") or {}
        schwere = v.get("severity", "")
        if schwere not in SCHWERE or SCHWERE.index(schwere) < grenze:
            continue
        if fix.get("state") != "fixed" or not fix.get("versions"):
            continue
        a = t.get("artifact") or {}
        pfade = sorted({str(o.get("path")) for o in a.get("locations") or [] if isinstance(o, dict) and o.get("path")})
        zeile = f"{v.get('id', '?')} {schwere} {a.get('name', '?')} {a.get('version', '?')} → {', '.join(fix['versions'])}"
        aus.append({"id": str(v.get("id", "?")), "schwere": schwere, "paket": a.get("name", "?"),
                    "version": a.get("version", "?"), "fix": list(fix["versions"]), "pfade": pfade, "zeile": zeile})
    return aus


def dockerfile_fuer(abbild: str, konfig: dict, dateien: list[str]) -> str | None:
    """The Dockerfile of `abbild`: `dockerfiles` in the config (image → path), else `Dockerfile` in the root, else the
    only tracked file named `Dockerfile`. None if that is not clear."""
    nach_konfig = (konfig.get("dockerfiles") or {}).get(abbild)
    if nach_konfig:
        return nach_konfig
    if "Dockerfile" in dateien:
        return "Dockerfile"
    alle = [d for d in dateien if d.rsplit("/", 1)[-1] == "Dockerfile"]
    return alle[0] if len(alle) == 1 else None


# ── nach außen: git, gh, docker ─────────────────────────────────────────────────────────────────────────────────────

def _lauf(argv: list[str], eingabe: str | None = None, cwd: str | None = None, env: dict[str, str] | None = None) -> str:
    r = subprocess.run(argv, input=eingabe, capture_output=True, text=True, check=False, cwd=cwd, env=env)
    if r.returncode != 0:
        raise Fehler(f"{' '.join(argv[:4])} … rc={r.returncode}: {r.stderr.strip()[:500]}")
    return r.stdout


def _quelle_env() -> dict[str, str]:
    env = dict(os.environ)
    if env.get("QUELLE_TOKEN"):
        env["GH_TOKEN"] = env["QUELLE_TOKEN"]
    return env


def gh_quelle(pfad: str) -> object:
    """Lesen im eigenen Repo (Release) mit QUELLE_TOKEN — das App-Token des Tag-Laufs gilt nur fürs Ziel."""
    r = subprocess.run(["gh", "api", "-X", "GET", pfad], capture_output=True, text=True, check=False, env=_quelle_env())
    if r.returncode != 0:
        raise Fehler(f"gh api GET {pfad} … rc={r.returncode}: {r.stderr.strip()[:500]}")
    return json.loads(r.stdout)


def gh_roh(pfad: str) -> bytes:
    """Ein Release-Anhang als Bytes (Accept: application/octet-stream)."""
    r = subprocess.run(["gh", "api", "-X", "GET", pfad, "-H", "Accept: application/octet-stream"], capture_output=True,
                       check=False, env=_quelle_env())
    if r.returncode != 0:
        raise Fehler(f"gh api GET {pfad} … rc={r.returncode}: {r.stderr.decode(errors='replace').strip()[:500]}")
    return r.stdout


def gh(pfad: str, methode: str = "GET", daten: dict | None = None) -> object:
    argv = ["gh", "api", "-X", methode, pfad]
    if daten is not None:
        argv += ["--input", "-"]
    aus = _lauf(argv, json.dumps(daten) if daten is not None else None)
    return json.loads(aus) if aus.strip() else None


def _baum_mit(repo: str, kopf: str, dateien: dict[str, str | bytes], modi: dict[str, str] | None) -> str:
    """Neuer Baum: der Baum von `kopf` plus `dateien` (Text als utf-8-Blob, Bytes als base64). Gibt die Baum-SHA."""
    baum = gh(f"repos/{repo}/git/commits/{kopf}")["tree"]["sha"]
    eintraege = []
    for pfad, inhalt in sorted(dateien.items()):
        if isinstance(inhalt, bytes):
            daten = {"content": base64.b64encode(inhalt).decode("ascii"), "encoding": "base64"}
        else:
            daten = {"content": inhalt, "encoding": "utf-8"}
        blob = gh(f"repos/{repo}/git/blobs", "POST", daten)["sha"]
        eintraege.append({"path": pfad, "mode": (modi or {}).get(pfad, "100644"), "type": "blob", "sha": blob})
    return gh(f"repos/{repo}/git/trees", "POST", {"base_tree": baum, "tree": eintraege})["sha"]


def pr_oeffnen(repo: str, basis: str, zweig: str, dateien: dict[str, str | bytes], titel: str, text: str,
               modi: dict[str, str] | None = None) -> str:
    """Ein Commit mit `dateien` (Pfad → Inhalt) auf `basis`, als Zweig `zweig`, und ein PR. Gibt die PR-URL.

    Text geht als utf-8-Blob, Bytes (Release-Anhänge) als base64; `modi` hält den Dateimodus (Vorgabe 100644).

    Über die Git-Data-API: Autor und Committer ist das Token (die App), der Commit ist von GitHub signiert. Der Auto-Merge
    prüft genau das (alle Commits vom App-Bot). Gibt es den Zweig schon mit offenem PR, bleibt es dabei (Wiederholung).
    """
    offen = gh(f"repos/{repo}/pulls?state=open&head={repo.split('/')[0]}:{zweig}")
    if offen:
        return offen[0]["html_url"]
    kopf = gh(f"repos/{repo}/git/ref/heads/{basis}")["object"]["sha"]
    neu_baum = _baum_mit(repo, kopf, dateien, modi)
    commit = gh(f"repos/{repo}/git/commits", "POST", {"message": titel, "tree": neu_baum, "parents": [kopf]})["sha"]
    try:
        gh(f"repos/{repo}/git/refs", "POST", {"ref": f"refs/heads/{zweig}", "sha": commit})
    except Fehler:
        # Zweig von einem abgebrochenen Lauf ohne PR: auf den neuen Commit setzen (er gehört der Automatik).
        gh(f"repos/{repo}/git/refs/heads/{zweig}", "PATCH", {"sha": commit, "force": True})
    pr = gh(f"repos/{repo}/pulls", "POST", {"title": titel, "head": zweig, "base": basis, "body": text})
    return pr["html_url"]


def alter_pin_zweig(ref: str, name: str, aktuell: str) -> bool:
    """Ist `ref` ein anderer Pin-Zweig desselben Quell-Repos — der feste `pin/<name>` oder einer nach dem Muster bis
    0.57.0, `pin/<name>-<tag>` mit Tag `v…` oder `main-…`? `pin/app-agg` ist kein Zweig von `app` (kein Tag-Anfang)."""
    if ref == aktuell:
        return False
    return ref == f"pin/{name}" or bool(re.fullmatch(rf"pin/{re.escape(name)}-(?:v|main-)[A-Za-z0-9._-]+", ref))


def gh_seiten(pfad: str) -> list[dict]:
    """All pages of a list endpoint (100 per page)."""
    aus: list[dict] = []
    seite = 1
    trenner = "&" if "?" in pfad else "?"
    while True:
        teil = gh(f"{pfad}{trenner}per_page=100&page={seite}") or []
        aus += teil
        if len(teil) < 100:
            return aus
        seite += 1


def _offene_prs(repo: str) -> list[dict]:
    return gh_seiten(f"repos/{repo}/pulls?state=open")


def pin_pr_fortschreiben(repo: str, basis: str, zweig: str, name: str, dateien: dict[str, str | bytes], titel: str,
                         text: str, modi: dict[str, str] | None = None) -> str:
    """Der eine Pin-PR eines Quell-Repos (seit 0.58.0): `zweig` wird bei jedem Lauf neu auf den Kopf von `basis` gebaut
    (ein Commit, immer auf main-Stand — das braucht ein Fast-Forward-Merge im Ziel), ein offener PR dafür bekommt Titel
    und Text des neuen Stands, sonst wird einer geöffnet. Danach schließt es die anderen offenen Pin-PRs desselben
    Quell-Repos (siehe `alter_pin_zweig`) mit Verweis und löscht ihre Zweige. Gibt die PR-URL.

    Force-with-lease über die API, die keinen Vergleich beim Schreiben kennt: Der Zweig wird nur überschrieben, wenn
    (1) alle seine Commits seit `basis` von der App stammen — ein Mensch, der etwas daraufgelegt hat, verliert es nicht
    still —, (2) ein offener PR auf genau den gelesenen Kopf zeigt und (3) der Zweig unmittelbar vor dem Schreiben
    noch dort steht. Sonst Fehler (Lauf rot, nichts überschrieben). Das Restfenster zwischen (3) und dem Schreiben ist
    eine API-Runde.
    """
    eigner = repo.split("/")[0]
    offen = (gh(f"repos/{repo}/pulls?state=open&head={eigner}:{zweig}") or [None])[0]
    kopf = gh(f"repos/{repo}/git/ref/heads/{basis}")["object"]["sha"]
    try:
        gelesen = gh(f"repos/{repo}/git/ref/heads/{zweig}")["object"]["sha"]
    except Fehler:
        gelesen = None   # Zweig gibt es nicht (404): neu anlegen; legt ihn jemand dazwischen an, scheitert POST laut.
    neu_baum = _baum_mit(repo, kopf, dateien, modi)
    if gelesen is None:
        if offen:
            raise Fehler(f"{zweig}: offener PR #{offen.get('number')}, aber der Zweig fehlt — nichts überschrieben")
        commit = gh(f"repos/{repo}/git/commits", "POST", {"message": titel, "tree": neu_baum, "parents": [kopf]})["sha"]
        gh(f"repos/{repo}/git/refs", "POST", {"ref": f"refs/heads/{zweig}", "sha": commit})
    else:
        if offen and offen["head"]["sha"] != gelesen:
            raise Fehler(f"{zweig}: PR #{offen.get('number')} zeigt auf {offen['head']['sha'][:12]}, der Zweig auf "
                         f"{gelesen[:12]} — fremd bewegt, nichts überschrieben")
        fremde = sorted({(c.get("author") or {}).get("login") or "(unbekannt)"
                         for c in gh(f"repos/{repo}/compare/{basis}...{gelesen}").get("commits") or []} - {APP_LOGIN})
        if fremde:
            raise Fehler(f"{zweig}: Commits von {', '.join(fremde)} auf dem Zweig — fremd bewegt, nichts überschrieben. "
                         "Den PR prüfen und schließen (oder den Zweig löschen); der nächste Lauf baut ihn neu.")
        alt = gh(f"repos/{repo}/git/commits/{gelesen}")
        if alt["tree"]["sha"] == neu_baum and [p["sha"] for p in alt.get("parents") or []] == [kopf]:
            print(f"{zweig} steht schon auf diesem Stand — Zweig unverändert")
        else:
            commit = gh(f"repos/{repo}/git/commits", "POST", {"message": titel, "tree": neu_baum, "parents": [kopf]})["sha"]
            jetzt = gh(f"repos/{repo}/git/ref/heads/{zweig}")["object"]["sha"]
            if jetzt != gelesen:
                raise Fehler(f"{zweig}: während des Laufs von {gelesen[:12]} auf {jetzt[:12]} bewegt — nichts überschrieben")
            gh(f"repos/{repo}/git/refs/heads/{zweig}", "PATCH", {"sha": commit, "force": True})
    if offen:
        gh(f"repos/{repo}/pulls/{offen['number']}", "PATCH", {"title": titel, "body": text})
        url = offen["html_url"]
    else:
        url = gh(f"repos/{repo}/pulls", "POST", {"title": titel, "head": zweig, "base": basis, "body": text})["html_url"]
    for pr in _offene_prs(repo):
        ref = pr["head"]["ref"]
        if ((pr.get("user") or {}).get("login") != APP_LOGIN or pr["head"].get("repo", {}).get("full_name") != repo
                or not alter_pin_zweig(ref, name, zweig) or not pr.get("title", "").startswith(f"{name}: pin ")):
            continue
        gh(f"repos/{repo}/issues/{pr['number']}/comments", "POST", {"body":
           f"Superseded by {url}: the release automation now keeps one rolling pin PR per source repo "
           f"(branch `{zweig}`), rebuilt on `{basis}` for each new state. Closing this one."})
        gh(f"repos/{repo}/pulls/{pr['number']}", "PATCH", {"state": "closed"})
        try:
            gh(f"repos/{repo}/git/refs/heads/{ref}", "DELETE")
        except Fehler as e:
            print(f"::warning::PR #{pr['number']} geschlossen, Zweig {ref} nicht gelöscht: {e}")
        print(f"Alter Pin-PR #{pr['number']} ({ref}) geschlossen")
    return url


def _tags(root: str) -> list[str]:
    return [t for t in _lauf(["git", "-C", root, "tag", "--list", "v*"]).split() if t]


def _heute() -> datetime.date:
    from zoneinfo import ZoneInfo
    return datetime.datetime.now(ZoneInfo("Europe/Berlin")).date()


def _dependabot_seit(root: str, tag: str | None) -> list[str]:
    bereich = f"{tag}..HEAD" if tag else "HEAD"
    aus = _lauf(["git", "-C", root, "log", bereich, "--no-merges", "--author=dependabot", "--format=%s"])
    return [z.strip().replace("`", "'") for z in aus.splitlines() if z.strip()]


def _letzter_tag(root: str) -> str | None:
    aus = _lauf(["git", "-C", root, "describe", "--tags", "--abbrev=0", "--match", "v*"]) if _tags(root) else ""
    return aus.strip() or None


def vorbereiten(root: str, repo: str, basis: str, trocken: bool = False) -> str:
    k = lade_konfig(root)
    dateien: dict[str, str] = {}
    quelltext = None
    if k["schema"] == "semver":
        vd = k["versionsdateien"][0]
        with open(os.path.join(root, vd["datei"]), encoding="utf-8") as fh:
            quelltext = version_in(fh.read(), vd["muster"], vd.get("alle", False))
    version = naechste_version(k["schema"], quelltext, _tags(root), _heute())
    if trocken:
        return version
    cl0 = k.get("changelog")
    if cl0 and cl0.get("form") == "keepachangelog":
        with open(os.path.join(root, cl0["datei"]), encoding="utf-8") as fh:
            erlaubt = cl0.get("erlaubt") or ERLAUBT.get(cl0.get("sprache", "en"), ERLAUBT["en"])
            schlecht = unreleased_unerlaubt(fh.read(), erlaubt)
        if schlecht:
            raise Halt(f"{cl0['datei']}: unter [Unreleased] steht {', '.join(schlecht)} — das ist kein Patch-Release "
                         f"(erlaubt: {', '.join(erlaubt)}; changelog.erlaubt). Kein Release-PR; das Release schneidet ein Mensch.")
    if k.get("versionsbefehl"):
        # Das Repo hat ein eigenes Werkzeug, das die Version überall setzt (TinySesam: scripts/_release.py) — es wird
        # benutzt, statt seine Stellen hier nachzubauen. Was es ändert, kommt in den PR (die Diff-Prüfung des Auto-Merge
        # hält das auf RELEASE_DATEIEN).
        argv = [a.replace("{version}", version) for a in k["versionsbefehl"]]
        if argv and argv[0].endswith(".py"):
            argv = [sys.executable] + argv
        _lauf(argv, cwd=root)
        for zeile in _lauf(["git", "-C", root, "status", "--porcelain", "--untracked-files=no"]).splitlines():
            pfad = zeile[3:].strip()
            with open(os.path.join(root, pfad), encoding="utf-8") as fh:
                dateien[pfad] = fh.read()
    if k["schema"] == "semver":
        for vd in k["versionsdateien"]:
            # Mehrere Muster für dieselbe Datei bauen aufeinander auf (README: Git-Tag und Abbild-Tag).
            if vd["datei"] not in dateien:
                with open(os.path.join(root, vd["datei"]), encoding="utf-8") as fh:
                    dateien[vd["datei"]] = fh.read()
            dateien[vd["datei"]] = setze_version(dateien[vd["datei"]], vd["muster"], version, vd.get("alle", False))
    cl = k.get("changelog")
    if cl:
        alt = dateien.get(cl["datei"])
        if alt is None:
            with open(os.path.join(root, cl["datei"]), encoding="utf-8") as fh:
                alt = fh.read()
        dateien[cl["datei"]] = changelog_eintragen(alt, cl["form"], cl.get("sprache", "en"), version,
                                                   _heute().isoformat(), _dependabot_seit(root, _letzter_tag(root)),
                                                   cl.get("kopf"))
    if not dateien:
        raise Fehler("nichts zu ändern (weder Versionsdatei noch CHANGELOG) — ein Release-PR wäre leer")
    url = pr_oeffnen(repo, basis, zweigname("release", f"v{version}"), dateien, f"Release v{version}",
                     f"Patch release v{version}, cut by the release automation after a Dependabot merge that changes the "
                     "image. Only version files and the changelog change; the auto-merge checks that. After the merge "
                     "the tag follows, and the tag run publishes the image.")
    print(f"Release-PR v{version}: {url}")
    return version


def taggen(root: str, repo: str, version: str) -> None:
    """Tag v<version> auf den Kopf von main — nur, wenn er der Merge genau dieses Release-PR der App ist."""
    k = lade_konfig(root)
    kopf = _lauf(["git", "-C", root, "rev-parse", "HEAD"]).strip()
    if not version:
        # Von Hand ausgelöst (workflow_dispatch ohne Version): die Version steht im Zweig des Release-PR, dessen Merge der
        # Kopf ist. Kein solcher PR → laut scheitern, nie raten.
        prs = gh(f"repos/{repo}/commits/{kopf}/pulls")
        zweige = sorted({p["head"]["ref"][len("release/v"):] for p in prs or []
                         if p.get("merged_at") and p["head"]["ref"].startswith("release/v") and p["user"]["login"] == APP_LOGIN})
        if not zweige:
            print(f"Keine Version angegeben, und der Kopf {kopf[:12]} ist kein Merge eines Release-PR der App — nichts zu tun")
            return
        if len(zweige) != 1:
            raise Fehler(f"Keine Version angegeben, und der Kopf {kopf[:12]} ist der Merge mehrerer Release-PR: {', '.join(zweige)}")
        version = zweige[0]
    if not (SEMVER.match(version) if k["schema"] == "semver" else DATUM.match(version)):
        raise Fehler(f"Version {version!r} passt nicht zum Schema {k['schema']}")
    tag = f"v{version}"
    if tag in _tags(root):
        print(f"Tag {tag} gibt es schon — nichts zu tun")
        return
    prs = gh(f"repos/{repo}/commits/{kopf}/pulls")
    passend = [p for p in prs or [] if p.get("merged_at") and p["head"]["ref"] == f"release/{tag}"
               and p["user"]["login"] == APP_LOGIN]
    if not passend:
        raise Fehler(f"Kopf {kopf[:12]} ist nicht der Merge des Release-PR release/{tag} der App — kein Tag")
    for vd in k.get("versionsdateien") or []:
        with open(os.path.join(root, vd["datei"]), encoding="utf-8") as fh:
            if version_in(fh.read(), vd["muster"], vd.get("alle", False)) != version:
                raise Fehler(f"{vd['datei']} trägt nicht {version} — kein Tag")
    if k.get("pruefbefehl"):
        argv = list(k["pruefbefehl"])
        if argv and argv[0].endswith(".py"):
            argv = [sys.executable] + argv
        _lauf(argv, cwd=root)   # rc != 0 → Fehler, kein Tag
    gh(f"repos/{repo}/git/refs", "POST", {"ref": f"refs/tags/{tag}", "sha": kopf})
    print(f"Tag {tag} auf {kopf[:12]} gesetzt")


def digest_von(abbild: str, tag: str) -> str:
    aus = _lauf(["docker", "buildx", "imagetools", "inspect", f"{abbild}:{tag}", "--format", "{{json .Manifest}}"])
    d = json.loads(aus).get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", d):
        raise Fehler(f"{abbild}:{tag}: kein Digest aus der Registry ({d!r})")
    return d


PLATTFORM = "linux/amd64"
GRYPE_PIN = re.compile(r"anchore/grype:v([0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}")


def grype_holen(bild: str, ziel: str) -> str:
    """The grype program of the pinned version (GRYPE_IMAGE `anchore/grype:v<version>@sha256:…`, raised by Dependabot in
    repokit) from anchore's GitHub release of that version, checked against the release's checksums file. Through `gh`
    (no Docker daemon, no registry host in this file). Returns the path."""
    import platform
    import tarfile
    m = GRYPE_PIN.fullmatch(bild)
    if not m:
        raise Fehler(f"GRYPE_IMAGE {bild!r}: anchore/grype:v<version>@sha256:<digest> erwartet")
    version = m.group(1)
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if arch is None:
        raise Fehler(f"grype: keine Fassung für {platform.machine()}")
    archiv, summen = f"grype_{version}_linux_{arch}.tar.gz", f"grype_{version}_checksums.txt"
    _lauf(["gh", "release", "download", f"v{version}", "--repo", "anchore/grype", "--dir", ziel,
           "--pattern", archiv, "--pattern", summen])
    with open(os.path.join(ziel, summen), encoding="utf-8") as fh:
        soll = [z.split()[0] for z in fh if z.split()[1:] == [archiv]]
    with open(os.path.join(ziel, archiv), "rb") as fh:
        ist = hashlib.sha256(fh.read()).hexdigest()
    if len(soll) != 1 or soll[0] != ist:
        raise Fehler(f"grype {version}: {archiv} passt nicht zu {summen}")
    pfad = os.path.join(ziel, "grype")
    with tarfile.open(os.path.join(ziel, archiv), "r:gz") as tar:
        eintrag = tar.getmember("grype")
        if not eintrag.isfile():
            raise Fehler(f"grype {version}: kein Programm im Archiv")
        # Owner only (0o700, CodeQL py/overly-permissive-file): the runner user runs it, nobody else needs to read or
        # run the program. Created with that mode (no window with umask rights) and set again (umask cannot widen it).
        fd = os.open(pfad, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
        with tar.extractfile(eintrag) as quelle, os.fdopen(fd, "wb") as aus:
            aus.write(quelle.read())
            os.fchmod(aus.fileno(), 0o700)
    return pfad


def schichten_aus(grype_json: str) -> list[str]:
    """The rootfs diff_ids of the scanned image from a grype JSON report (source.target.config, else its layers)."""
    try:
        ziel = json.loads(grype_json)["source"]["target"]
        if ziel.get("config"):
            return list(json.loads(base64.b64decode(ziel["config"]))["rootfs"]["diff_ids"])
        return [s["digest"] for s in ziel["layers"]]
    except (ValueError, KeyError, TypeError) as e:
        raise Fehler(f"grype: Bericht ohne Schichten des Abbilds ({e})") from e


def _grype(ref: str, root: str, grype: str, eigene: set[str]) -> str:
    """grype over `ref` in the registry (linux/amd64), JSON on stdout. For the registries of the repo's own images
    (`eigene`) grype gets REGISTRY_TOKEN in its environment (GRYPE_REGISTRY_AUTH_* — the value never stands on a command
    line); every other registry is read anonymously. The repo's `.grype.yaml` (exceptions) counts."""
    env = dict(os.environ)
    host = ref.split("/", 1)[0]
    if env.get("REGISTRY_TOKEN") and host in eigene:
        env.update(GRYPE_REGISTRY_AUTH_AUTHORITY=host, GRYPE_REGISTRY_AUTH_PASSWORD=env["REGISTRY_TOKEN"],
                   GRYPE_REGISTRY_AUTH_USERNAME=env.get("REGISTRY_USER") or "token")
    argv = [grype, f"registry:{ref}", "--platform", PLATTFORM, "-o", "json"]
    if os.path.exists(os.path.join(root, ".grype.yaml")):
        argv += ["-c", os.path.join(root, ".grype.yaml")]
    return _lauf(argv, env=env)


def _getrackt(root: str) -> list[str]:
    return [z for z in _lauf(["git", "-C", root, "ls-files"]).split("\n") if z]


def _ausgabe(schluessel: str, wert: str) -> None:
    pfad = os.environ.get("GITHUB_OUTPUT")
    if pfad:
        with open(pfad, "a", encoding="utf-8") as fh:
            fh.write(f"{schluessel}={wert}\n")


def _zusammenfassung(text: str) -> None:
    """Append to the job summary. A summary that cannot be written is a warning, never silent and never the verdict."""
    pfad = os.environ.get("GITHUB_STEP_SUMMARY")
    if pfad:
        try:
            with open(pfad, "a", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as e:
            print(f"::warning::job summary not written ({pfad}): {e}", file=sys.stderr)


def neubau(root: str, repo: str) -> list[str]:
    """Weekly rebuild check: the reasons for a patch release of the own image(s), empty = nothing to do.

    Writes `reason=<short>` to GITHUB_OUTPUT only when there is a reason (the workflow then dispatches `vorbereiten`) and
    a section to the job summary in every case. Red (Fehler) when the released image or grype cannot be read: a check
    that saw nothing is no "no reason".
    """
    k = lade_konfig(root)
    abbilder = k.get("abbilder") or []
    if not abbilder:
        _zusammenfassung("### Weekly rebuild\n\nNo own image (`abbilder` in .github/release-automatik.json is empty).\n")
        return []
    offen = [p["head"]["ref"] for p in _offene_prs(repo)
             if p.get("user", {}).get("login") == APP_LOGIN and p["head"]["ref"].startswith("release/")]
    if offen:
        _zusammenfassung(f"### Weekly rebuild\n\nA release PR of the automation is open ({', '.join(offen)}): nothing to do.\n")
        return []
    tags = [t["name"] for t in gh_seiten(f"repos/{repo}/tags")]
    tag = letzter_release_tag(k["schema"], tags)
    if tag is None:
        _zusammenfassung("### Weekly rebuild\n\nNo release tag yet: the first release is cut by a human.\n")
        return []
    dateien = _getrackt(root)
    werkbank = tempfile.mkdtemp(prefix="neubau-")
    try:
        return _neubau_pruefen(root, k, tag, abbilder, dateien, werkbank)
    finally:
        shutil.rmtree(werkbank, ignore_errors=True)


def _neubau_pruefen(root: str, k: dict, tag: str, abbilder: list[str], dateien: list[str], werkbank: str) -> list[str]:
    zeilen: list[str] = []
    gruende: list[str] = []
    grype = os.environ.get("GRYPE_BIN") or grype_holen(os.environ.get("GRYPE_IMAGE", ""), werkbank)
    eigene = {a.split("/", 1)[0] for a in abbilder}
    for abbild in abbilder:
        ref = f"{abbild}:{tag}"
        bericht = _grype(ref, root, grype, eigene)
        release = schichten_aus(bericht)
        if not release:
            raise Fehler(f"{ref}: keine Schichten — das veröffentlichte Abbild ist nicht lesbar")
        df = dockerfile_fuer(abbild, k, dateien)
        if df is None:
            zeilen.append(f"- `{ref}` base: not checked — no single Dockerfile; name it in `dockerfiles` of the config")
        else:
            with open(os.path.join(root, df), encoding="utf-8") as fh:
                extern, final = basis_kandidaten(fh.read())
            kandidaten: dict[str, list[str]] = {}
            for kand in extern:
                try:
                    kandidaten[kand] = schichten_aus(_grype(kand, root, grype, eigene))
                except Fehler as e:
                    zeilen.append(f"- `{kand}` ({df}) not readable: {e}")
            treffer = basis_unveraendert(release, kandidaten)
            if treffer:
                zeilen.append(f"- `{ref}` base unchanged: `{treffer}` ({df})")
            elif final == "scratch":
                zeilen.append(f"- `{ref}` base: final stage is `FROM scratch` — nothing to compare")
            elif final is None:
                zeilen.append(f"- `{ref}` base: final FROM of {df} not resolvable — not checked")
            else:
                g = f"{abbild}: base image changed (`{final}` in {df} is not the base of `{ref}`)"
                gruende.append(g)
                zeilen.append(f"- {g}")
        funde = behebbare_treffer(bericht)
        if funde:
            g = f"{abbild}: grype finds {len(funde)} fixable High/Critical in `{ref}`"
            gruende.append(g)
            zeilen.append(f"- {g}:")
            zeilen += [f"  - {f}" for f in funde[:20]] + ([f"  - … {len(funde) - 20} more"] if len(funde) > 20 else [])
        else:
            zeilen.append(f"- `{ref}`: grype finds nothing fixable at High or above")
    urteil = ("**Reason for a patch release** — `vorbereiten` follows." if gruende
              else "**No reason** — no release, no pin PR.")
    _zusammenfassung(f"### Weekly rebuild (last release {tag})\n\n{urteil}\n\n" + "\n".join(zeilen) + "\n")
    print("\n".join(zeilen))
    if gruende:
        _ausgabe("reason", "; ".join(gruende).replace("\n", " ")[:900])
    return gruende


# ── image audit in the PR CI (kit 0.72.0) ─────────────────────────────────────────────────────────────────────────────
# Todo @8fc1e1 (S2 2026-11-27, PO "only dependencies that are used, checked at build time"): the weekly rebuild sees a
# finding only in a released image; a Dependabot PR on a base image or a new package reached main unchecked. Taken over
# from a private repo's job `image-probe` (scripts/abbild-audit.sh, since 2026-10-15): after the build in the PR CI grype
# scans the fresh image. Red: a finding WITH a fix at High or above that no valid exception covers. Exceptions live in
# a text file with reason and expiry (grype's own `.grype.yaml` has no expiry; it still counts, as in `neubau`):
#
#     <vulnerability id>  <path prefix in the image>  <valid until YYYY-MM-DD>  <reason>
#
# A line without reason, with a bad date, expired or more than 90 days ahead is red; an exception that covers no
# finding any more is a notice (remove it). Warning, never red: the final stage is not slim (distroless, static,
# alpine, slim, scratch, chainguard, wolfi, busybox) and the Dockerfile gives no reason (`# runtime-base: <reason>`).

AUSNAHME_TAGE = 90
# grype source schemes; anything else is a local docker image (`name:tag`, whose `:` is no scheme).
GRYPE_QUELLE = re.compile(r"^(docker|docker-archive|oci-archive|oci-dir|registry|podman|dir|file|sbom):")
SCHLANK = re.compile(r"(?i)(distroless|/static|static-debian|alpine|-slim|slim-|:slim|scratch|chainguard|wolfi|busybox)")
SCHLANK_GRUND = re.compile(r"(?im)^\s*#\s*runtime-base:\s*\S")


def ausnahmen_lesen(text: str, heute: datetime.date) -> tuple[list[dict], list[str]]:
    """Exception lines of the image audit: (rules, errors). Comment and empty lines are skipped. A rule is
    {id, praefix, bis, grund, zeile}; every broken line is an error (red), never silently skipped."""
    regeln: list[dict] = []
    fehler: list[str] = []
    for nr, roh in enumerate(text.splitlines(), 1):
        z = roh.strip()
        if not z or z.startswith("#"):
            continue
        teile = z.split(None, 3)
        if len(teile) < 4 or not teile[3].strip():
            fehler.append(f"line {nr}: expected `<id> <path prefix> <YYYY-MM-DD> <reason>`: {z}")
            continue
        vid, praefix, datum, grund = teile
        try:
            bis = datetime.date.fromisoformat(datum) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", datum) else None
        except ValueError:
            bis = None
        if bis is None:
            fehler.append(f"line {nr}: {datum!r} is no date YYYY-MM-DD")
            continue
        if bis < heute:
            fehler.append(f"line {nr}: exception for {vid} expired on {bis} — fix it or give a new reason")
            continue
        if bis > heute + datetime.timedelta(days=AUSNAHME_TAGE):
            fehler.append(f"line {nr}: exception for {vid} runs until {bis}, more than {AUSNAHME_TAGE} days ahead")
            continue
        if not praefix.startswith("/"):
            fehler.append(f"line {nr}: path prefix {praefix!r} must start with /")
            continue
        regeln.append({"id": vid, "praefix": praefix, "bis": bis, "grund": grund.strip(), "zeile": nr})
    return regeln, fehler


def abbild_urteil(funde: list[dict], regeln: list[dict]) -> tuple[list[dict], set[int]]:
    """(findings no rule covers, line numbers of the rules that covered something). A rule covers a finding when the id
    matches and EVERY location of the finding starts with its prefix (a finding without location is never covered)."""
    offen: list[dict] = []
    genutzt: set[int] = set()
    for f in funde:
        treffer = [r for r in regeln
                   if r["id"] == f["id"] and f["pfade"] and all(p.startswith(r["praefix"]) for p in f["pfade"])]
        if treffer:
            genutzt.update(r["zeile"] for r in treffer)
        else:
            offen.append(f)
    return offen, genutzt


def laufzeit_schlank(dockerfile: str) -> tuple[bool, str]:
    """Is the final stage slim, or does the Dockerfile give a reason? (ok, description)."""
    _extern, final = basis_kandidaten(dockerfile)
    if SCHLANK_GRUND.search(dockerfile):
        return True, f"final base `{final}`, reason given (`# runtime-base:`)"
    if final is None:
        return False, "final FROM not resolvable"
    if final == "scratch" or SCHLANK.search(final):
        return True, f"final base `{final}` is slim"
    return False, f"final base `{final}` is not slim (distroless/static/alpine/slim) and no `# runtime-base: <reason>`"


def grype_pin_aus_kit(root: str) -> str:
    """The pinned grype image of the kit (tests/_kit/grype.Dockerfile, raised by Dependabot in repokit), "" if absent."""
    for rel in ("tests/_kit/grype.Dockerfile", "kit/tests/_kit/grype.Dockerfile"):
        pfad = os.path.join(root, rel)
        if os.path.exists(pfad):
            with open(pfad, encoding="utf-8") as fh:
                for zeile in fh:
                    m = re.match(r"^FROM\s+(\S+)\s*$", zeile.strip())
                    if m:
                        return m.group(1)
    return ""


def abbild_pruefen(root: str, quellen: list[str], schwelle: str, ausnahmen: str, dockerfiles: list[str],
                   heute: datetime.date | None = None) -> int:
    """The image audit: 0 = nothing open, 1 = open findings or broken exceptions. Fehler (rc 1 in main) when grype or a
    report cannot be read — a scan that saw nothing is no "0 findings"."""
    heute = heute or _heute()
    zeilen: list[str] = []
    rot = False
    regeln: list[dict] = []
    pfad = os.path.join(root, ausnahmen)
    if os.path.exists(pfad):
        with open(pfad, encoding="utf-8") as fh:
            regeln, kaputt = ausnahmen_lesen(fh.read(), heute)
        for k in kaputt:
            print(f"::error file={ausnahmen}::{k}", file=sys.stderr)
            zeilen.append(f"- exceptions {ausnahmen}: {k}")
        rot = rot or bool(kaputt)
    for df in dockerfiles:
        with open(os.path.join(root, df), encoding="utf-8") as fh:
            ok, text = laufzeit_schlank(fh.read())
        zeilen.append(f"- runtime {df}: {text}")
        if not ok:
            print(f"::warning file={df}::{text}")
    werkbank = tempfile.mkdtemp(prefix="abbild-")
    genutzt: set[int] = set()
    try:
        grype = os.environ.get("GRYPE_BIN") or grype_holen(os.environ.get("GRYPE_IMAGE") or grype_pin_aus_kit(root),
                                                           werkbank)
        for quelle in quellen:
            ref = quelle if GRYPE_QUELLE.match(quelle) else f"docker:{quelle}"
            argv = [grype, ref, "-o", "json"]
            if os.path.exists(os.path.join(root, ".grype.yaml")):
                argv += ["-c", os.path.join(root, ".grype.yaml")]
            funde = behebbare_funde(_lauf(argv), schwelle)
            offen, g = abbild_urteil(funde, regeln)
            genutzt |= g
            if offen:
                rot = True
                zeilen.append(f"- `{quelle}`: {len(offen)} fixable finding(s) at {schwelle} or above without exception:")
                for f in sorted(offen, key=lambda x: x["zeile"])[:30]:
                    zeilen.append(f"  - {f['zeile']} ({', '.join(f['pfade']) or 'no location'})")
                    print(f"::error::{quelle}: {f['zeile']}", file=sys.stderr)
            else:
                zeilen.append(f"- `{quelle}`: nothing fixable at {schwelle} or above"
                              + (f" ({len(funde)} covered by exceptions)" if funde else ""))
    finally:
        shutil.rmtree(werkbank, ignore_errors=True)
    for r in regeln:
        if r["zeile"] not in genutzt:
            zeilen.append(f"- exception line {r['zeile']} ({r['id']} {r['praefix']}) covers no finding — remove it")
            print(f"::notice file={ausnahmen}::exception line {r['zeile']} ({r['id']}) covers no finding — remove it")
    urteil = "**Red** — fix the image or add a dated exception." if rot else "**Green**"
    _zusammenfassung(f"### Image audit (grype)\n\n{urteil}\n\n" + "\n".join(zeilen) + "\n")
    print("\n".join(zeilen))
    return 1 if rot else 0


def anhaenge(repo: str, tag: str, ziel: str, basis: str, regeln: list[tuple[str, str]]) -> tuple[dict[str, bytes], dict[str, str]]:
    """Release-Anhänge für den Pin-PR: (Pfad → Bytes nur für abweichende Dateien, Pfad → Modus der bestehenden Datei).

    Jeder Anhang muss den Hash aus der SHA256SUMS des Release tragen, sonst Fehler (kein PR). Jeder Ordner muss im Ziel
    bestehen — ein Tippfehler in PIN_ANHAENGE soll laut scheitern, nicht still einen neuen Ordner anlegen.
    """
    if not tag.startswith("v"):
        raise Fehler(f"PIN_ANHAENGE: Anhänge gibt es nur zu einem Release-Tag v…, nicht zu {tag}")
    release = gh_quelle(f"repos/{repo}/releases/tags/{tag}")
    if release.get("draft") or release.get("tag_name") != tag:
        raise Fehler(f"Release {tag} von {repo} fehlt oder ist ein Entwurf")
    ids = {a["name"]: a["id"] for a in release.get("assets") or []}
    if SUMMEN not in ids:
        raise Fehler(f"Release {tag} von {repo} hat keine {SUMMEN}")
    summen_roh = gh_roh(f"repos/{repo}/releases/assets/{ids[SUMMEN]}")
    summen = summen_lesen(summen_roh.decode("utf-8"))
    soll = anhang_soll(regeln, summen, hashlib.sha256(summen_roh).hexdigest())
    baum = gh(f"repos/{ziel}/git/trees/{basis}?recursive=1")
    if baum.get("truncated"):
        raise Fehler(f"Baum von {ziel} abgeschnitten — Anhänge nicht sicher abgleichbar")
    im_ziel = {e["path"]: e for e in baum.get("tree") or [] if e.get("type") == "blob"}
    ordner_da = {e["path"] for e in baum.get("tree") or [] if e.get("type") == "tree"}
    for ordner, _ in regeln:
        if ordner not in ordner_da:
            raise Fehler(f"PIN_ANHAENGE: Ordner {ordner} fehlt in {ziel}")
    inhalte: dict[str, bytes] = {}
    for name in sorted({n for n, _ in soll.values()}):
        if name == SUMMEN:
            inhalte[name] = summen_roh
            continue
        if name not in ids:
            raise Fehler(f"Release {tag}: {name} steht in der {SUMMEN}, ist aber kein Anhang")
        inhalte[name] = gh_roh(f"repos/{repo}/releases/assets/{ids[name]}")
        if hashlib.sha256(inhalte[name]).hexdigest() != summen[name]:
            raise Fehler(f"Release {tag}: {name} passt nicht zur {SUMMEN} — kein Pin-PR")
    neu: dict[str, bytes] = {}
    modi: dict[str, str] = {}
    for pfad, (name, _) in sorted(soll.items()):
        alt = im_ziel.get(pfad)
        if alt and alt.get("sha") == git_blob_sha(inhalte[name]):
            continue
        neu[pfad] = inhalte[name]
        if alt:
            modi[pfad] = alt.get("mode", "100644")
    return neu, modi


def fc_pin(root: str, repo: str, tag: str, ziel: str, digests: dict[str, str] | None = None,
           anhang_text: str | None = None) -> str | None:
    """Pin-PR im Ziel-Repo: jede Compose unter stacks/*/compose.yaml, die ein Abbild dieses Release pinnt — und, mit
    PIN_ANHAENGE, die Release-Anhänge, die sich im Ziel unterscheiden."""
    k = lade_konfig(root)
    regeln = anhang_regeln(os.environ.get("PIN_ANHAENGE", "") if anhang_text is None else anhang_text)
    abbilder = k.get("abbilder") or []
    if not abbilder:
        raise Fehler(f"{KONFIG}: keine abbilder — fc-pin weiß nicht, was es heben soll")
    digests = digests or {a: digest_von(a, tag) for a in abbilder}
    basis = gh(f"repos/{ziel}")["default_branch"]
    geaendert: dict[str, str] = {}
    for eintrag in gh(f"repos/{ziel}/contents/stacks?ref={basis}") or []:
        if eintrag.get("type") != "dir":
            continue
        pfad = f"stacks/{eintrag['name']}/compose.yaml"
        try:
            datei = gh(f"repos/{ziel}/contents/{pfad}?ref={basis}")
        except Fehler:
            continue
        text = base64.b64decode(datei["content"]).decode("utf-8")
        neu, summe = text, 0
        for a in abbilder:
            neu, n = pin_ersetzen(neu, a, tag, digests[a])
            summe += n
        if summe:
            geaendert[pfad] = neu
    if not geaendert:
        print(f"Kein Stack in {ziel} pinnt {', '.join(abbilder)} anders als {tag} — kein Pin-PR")
        return None
    modi: dict[str, str] = {}
    anhang_dateien: dict[str, bytes] = {}
    if regeln:
        anhang_dateien, modi = anhaenge(repo, tag, ziel, basis, regeln)
    name = repo.split("/")[-1].lower()
    zeilen = "\n".join(f"- `{a}:{tag}@{digests[a]}`" for a in abbilder)
    hinweis = "Only pin lines change; the auto-merge checks that."
    if regeln:
        hinweis = (f"Release assets: {', '.join(sorted(anhang_dateien)) or 'unchanged'} — each checked against the "
                   f"{SUMMEN} of release {tag}; the auto-merge checks pin lines and assets against that release.")
    # Ein fester Zweig je Quell-Repo (seit 0.58.0). Mit Anhängen bleibt der Tag im Namen: der Auto-Merge des Ziels liest
    # Quelle und Release der Anhänge aus `pin/<repo>-<tag>` (Vorlage, anhang_quelle) — auch dann bleibt es EIN offener PR.
    zweig = zweigname("pin", name, tag) if regeln else zweigname("pin", name)
    url = pin_pr_fortschreiben(ziel, basis, zweig, name, {**geaendert, **anhang_dateien}, f"{name}: pin {tag}",
                               f"Pin from the release run of {repo} {tag} (release automation):\n\n{zeilen}\n\n"
                               f"Files: {', '.join(sorted(geaendert))}. {hinweis}\n\n"
                               f"Rolling PR: each new state of {repo} rebuilds `{zweig}` on `{basis}` and updates this PR.",
                               modi)
    print(f"Pin-PR: {url}")
    return url


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="_release_automatik.py")
    p.add_argument("schritt", choices=["vorbereiten", "taggen", "fc-pin", "naechste", "neubau", "abbild-pruefen"])
    # abbild-pruefen (kit 0.72.0): grype sources of freshly built images (`name:tag` = local docker image).
    p.add_argument("quellen", nargs="*")
    p.add_argument("--schwelle", "--threshold", dest="schwelle", choices=["High", "Critical"], default="High")
    p.add_argument("--ausnahmen", "--exceptions", dest="ausnahmen", default=".github/abbild-ausnahmen.txt")
    p.add_argument("--dockerfile", action="append", default=[])
    p.add_argument("--version", default="")
    p.add_argument("--tag", default="")
    # --target: dieselbe Option englisch — Repos mit Englisch-Wächter über ihre Workflows (TinySesam) rufen sie so.
    p.add_argument("--ziel", "--target", dest="ziel", default="")
    p.add_argument("--root", default=os.getcwd())
    p.add_argument("--basis", default="main")
    a = p.parse_intermixed_args(argv)   # images may stand after the options (abbild-pruefen)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    try:
        if a.schritt == "abbild-pruefen":
            if not a.quellen:
                raise Fehler("abbild-pruefen: no image given")
            return abbild_pruefen(a.root, a.quellen, a.schwelle, a.ausnahmen, a.dockerfile)
        if a.quellen:
            raise Fehler(f"{a.schritt}: unexpected arguments {a.quellen}")
        if a.schritt == "naechste":
            print(vorbereiten(a.root, repo, a.basis, trocken=True))
            return 0
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise Fehler("GITHUB_REPOSITORY fehlt oder ist unzulässig")
        if a.schritt == "vorbereiten":
            vorbereiten(a.root, repo, a.basis)
        elif a.schritt == "taggen":
            taggen(a.root, repo, a.version)
        elif a.schritt == "neubau":
            neubau(a.root, repo)
        else:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", a.ziel):
                raise Fehler("--ziel OWNER/REPO fehlt oder ist unzulässig")
            # Ein Release-Tag (v…) oder der Tag eines Abbilds je Stand auf main (UnderDoc: main-<sha>, seit 0.47.2).
            if not re.fullmatch(r"(v|main-)[A-Za-z0-9._-]+", a.tag):
                raise Fehler("--tag v… oder main-… fehlt oder ist unzulässig")
            fc_pin(a.root, repo, a.tag, a.ziel)
    except Halt as e:
        print(f"::notice::{e}")
        _zusammenfassung(f"### Release automation skipped (a human cuts this release)\n\n{e}\n")
        return 0
    except Fehler as e:
        print(f"::error::{e}", file=sys.stderr)
        _zusammenfassung(f"### Release automation stopped\n\n{e}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
