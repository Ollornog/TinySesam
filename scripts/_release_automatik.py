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
      → Tag-Lauf von release.yml baut das Abbild, danach `fc-pin`: Pin-PR `pin/<repo>-<tag>` im Ziel-Repo
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
      "abbilder": ["<registry>/<owner>/<name>"]   # was der Tag-Lauf veröffentlicht; fc-pin hebt genau diese Pins
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

Release-Anhänge im Pin-PR (seit 0.48.0, PO 2026-11-15): Liefert ein Release neben dem Abbild Dateien, die das Ziel-Repo
neben der Compose hält (paperlaiss: Skripte und Knöpfe samt SHA256SUMS), nimmt `fc-pin` sie mit, wenn die Repo-Variable
`PIN_ANHAENGE` (Umgebung des Tag-Laufs) sie nennt — Leerzeichen-getrennt `<ordner>:<datei>` oder `<ordner>:*` (alle
Dateien der SHA256SUMS und sie selbst). Der Ordner muss im Ziel schon bestehen. `fc-pin` lädt SHA256SUMS und Anhänge vom
Release des Tags, prüft jeden Hash und schreibt nur, was sich unterscheidet (Dateimodus bleibt). Der Auto-Merge des
Ziels (`PIN_ANHAENGE` im Block je Repo) prüft dasselbe gegen das Release. Ohne die Variable bleibt alles wie vorher.
Gelesen wird das Release mit `QUELLE_TOKEN` (Workflow-Token des App-Repos), sonst mit GH_TOKEN.

stdlib-only. Nach außen nur `git`, `gh api` und `docker buildx imagetools inspect`.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

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


# ── nach außen: git, gh, docker ─────────────────────────────────────────────────────────────────────────────────────

def _lauf(argv: list[str], eingabe: str | None = None, cwd: str | None = None) -> str:
    r = subprocess.run(argv, input=eingabe, capture_output=True, text=True, check=False, cwd=cwd)
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
    baum = gh(f"repos/{repo}/git/commits/{kopf}")["tree"]["sha"]
    eintraege = []
    for pfad, inhalt in sorted(dateien.items()):
        if isinstance(inhalt, bytes):
            daten = {"content": base64.b64encode(inhalt).decode("ascii"), "encoding": "base64"}
        else:
            daten = {"content": inhalt, "encoding": "utf-8"}
        blob = gh(f"repos/{repo}/git/blobs", "POST", daten)["sha"]
        eintraege.append({"path": pfad, "mode": (modi or {}).get(pfad, "100644"), "type": "blob", "sha": blob})
    neu_baum = gh(f"repos/{repo}/git/trees", "POST", {"base_tree": baum, "tree": eintraege})["sha"]
    commit = gh(f"repos/{repo}/git/commits", "POST", {"message": titel, "tree": neu_baum, "parents": [kopf]})["sha"]
    try:
        gh(f"repos/{repo}/git/refs", "POST", {"ref": f"refs/heads/{zweig}", "sha": commit})
    except Fehler:
        # Zweig von einem abgebrochenen Lauf ohne PR: auf den neuen Commit setzen (er gehört der Automatik).
        gh(f"repos/{repo}/git/refs/heads/{zweig}", "PATCH", {"sha": commit, "force": True})
    pr = gh(f"repos/{repo}/pulls", "POST", {"title": titel, "head": zweig, "base": basis, "body": text})
    return pr["html_url"]


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
            raise Fehler(f"{cl0['datei']}: unter [Unreleased] steht {', '.join(schlecht)} — das ist kein Patch-Release "
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
    url = pr_oeffnen(ziel, basis, zweigname("pin", name, tag), {**geaendert, **anhang_dateien}, f"{name}: pin {tag}",
                     f"Pin from the release run of {repo} {tag} (release automation):\n\n{zeilen}\n\n"
                     f"Files: {', '.join(sorted(geaendert))}. {hinweis}", modi)
    print(f"Pin-PR: {url}")
    return url


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="_release_automatik.py")
    p.add_argument("schritt", choices=["vorbereiten", "taggen", "fc-pin", "naechste"])
    p.add_argument("--version", default="")
    p.add_argument("--tag", default="")
    # --target: dieselbe Option englisch — Repos mit Englisch-Wächter über ihre Workflows (TinySesam) rufen sie so.
    p.add_argument("--ziel", "--target", dest="ziel", default="")
    p.add_argument("--root", default=os.getcwd())
    p.add_argument("--basis", default="main")
    a = p.parse_args(argv)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    try:
        if a.schritt == "naechste":
            print(vorbereiten(a.root, repo, a.basis, trocken=True))
            return 0
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise Fehler("GITHUB_REPOSITORY fehlt oder ist unzulässig")
        if a.schritt == "vorbereiten":
            vorbereiten(a.root, repo, a.basis)
        elif a.schritt == "taggen":
            taggen(a.root, repo, a.version)
        else:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", a.ziel):
                raise Fehler("--ziel OWNER/REPO fehlt oder ist unzulässig")
            # Ein Release-Tag (v…) oder der Tag eines Abbilds je Stand auf main (UnderDoc: main-<sha>, seit 0.47.2).
            if not re.fullmatch(r"(v|main-)[A-Za-z0-9._-]+", a.tag):
                raise Fehler("--tag v… oder main-… fehlt oder ist unzulässig")
            fc_pin(a.root, repo, a.tag, a.ziel)
    except Fehler as e:
        print(f"::error::{e}", file=sys.stderr)
        zusammenfassung = os.environ.get("GITHUB_STEP_SUMMARY")
        if zusammenfassung:
            try:
                with open(zusammenfassung, "a", encoding="utf-8") as fh:
                    fh.write(f"### Release automation stopped\n\n{e}\n")
            except OSError:
                pass
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
