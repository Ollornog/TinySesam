#!/usr/bin/env python3
"""Unused dependencies — the kit's check per language (kit 0.73.0). Copied here by `repokit sync`, do not edit by hand.

WHY (PO 2026-11-27): an own app carries only the dependencies it uses, and the build checks it. Measured on all own repos
on 2026-11-27 (todo @9e585b): few real findings, many false alarms of a naive run (server binaries started by the CMD,
FastAPI's implicit python-multipart, security floors for transitive packages, the vendored kit `_kit`, extras used as
test groups). So the check knows those defaults, and everything else a repo keeps goes into an allow list WITH reason.

What it runs (tools pinned here; network only for fetching them, so it belongs in a CI job, not in the offline hygiene):

    Go      every tracked go.mod (also .github/audit/go.mod): `go mod tidy -diff` must be empty
    Rust    every top Cargo.toml: cargo-machete (no build, works for firmware targets)
    Python  every manifest (pyproject.toml with [project] dependencies; requirements.in, else a requirements*.txt
            without hashes): deptry in a throwaway environment that has the manifest installed (module names come from
            the installed metadata). Counted: DEP002 (declared, never imported). DEP001/DEP003 (imported but not
            declared / only transitive) are warnings.
    JS/TS   only package dirs with a knip config (knip.json, .knip.json, knip.jsonc): knip, dependencies only. Without a
            config: a note (vendor builds that copy out of node_modules are invisible to knip, measured 2026-11-27).
    PHP     composer.json: a note — composer-unused needs vendor/ and runs in the repo's own PHP job.

Configuration: `.github/abhaengigkeiten.json` (optional):

    {
      "allow": {"<manifest path>": {"<package>": "<reason>"}},   # reason required; an entry that matches nothing is red
      "warn_until": "YYYY-MM-DD",   # switch per repo: findings are warnings until that day (at most 60 days ahead),
                                    # afterwards red. Without it: red at once.
      "off": {"<language>": "<reason>"}   # go | rust | python | js — a language not checked here, with reason
    }

Exit 0: nothing open (or only warnings, or inside `warn_until`). Exit 1: findings, a broken configuration or a tool that
could not run — a check that saw nothing is no green. stdout: one line per finding; GitHub annotations in Actions.

    python3 scripts/_abhaengigkeiten.py [--root DIR] [--nur go,rust,python,js]

stdlib only.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

DEPTRY = "deptry==0.25.1"
CARGO_MACHETE = "0.10.1"
KNIP = "knip@6.48.0"
KONFIG = ".github/abhaengigkeiten.json"
WARN_TAGE = 60
SPRACHEN = ("go", "rust", "python", "js")
# Extras that are test/dev groups, not runtime (deptry --pep621-dev-dependency-groups).
DEV_EXTRAS = ("test", "tests", "dev", "lint", "docs", "typing", "e2e", "browser", "ci")
# Packages that are used without an import (measured 2026-11-27): the server the CMD starts, its speedups, the form
# parser FastAPI loads itself, the template engine Starlette loads, build backends.
OHNE_IMPORT = {
    "uvicorn": "server started by the image's CMD, not imported",
    "gunicorn": "server started by the image's CMD, not imported",
    "httptools": "uvicorn picks it up by itself (--http auto)",
    "uvloop": "uvicorn picks it up by itself (--loop auto)",
    "websockets": "uvicorn picks it up by itself for WebSocket routes",
    "python-multipart": "FastAPI/Starlette import it themselves for forms",
    "jinja2": "Starlette's Jinja2Templates imports it",
    "setuptools": "build backend",
    "wheel": "build backend",
}


class Fehler(Exception):
    pass


def _in_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _lauf(argv: list[str], cwd: str, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, env=env, timeout=1800)
    except FileNotFoundError as e:
        raise Fehler(f"{argv[0]} not found — the check cannot run here (install it or run the CI job)") from e
    except subprocess.TimeoutExpired as e:
        raise Fehler(f"{argv[0]} took longer than 30 min") from e


def getrackt(root: str) -> list[str]:
    r = _lauf(["git", "-C", root, "ls-files", "-z"], root)
    if r.returncode != 0:
        raise Fehler(f"git ls-files failed: {r.stderr.strip()[:200]}")
    return [p for p in r.stdout.split("\0") if p]


def konfig_lesen(root: str, heute: datetime.date) -> tuple[dict, list[str]]:
    """The repo configuration and its errors (every error is red)."""
    pfad = os.path.join(root, KONFIG)
    if not os.path.exists(pfad):
        return {"allow": {}, "off": {}, "warn_until": None}, []
    fehler: list[str] = []
    try:
        with open(pfad, encoding="utf-8") as fh:
            roh = json.load(fh)
    except (OSError, ValueError) as e:
        return {"allow": {}, "off": {}, "warn_until": None}, [f"{KONFIG} unreadable: {e}"]
    if not isinstance(roh, dict):
        return {"allow": {}, "off": {}, "warn_until": None}, [f"{KONFIG}: expected an object"]
    for k in sorted(set(roh) - {"allow", "warn_until", "off", "_comment"}):
        fehler.append(f"{KONFIG}: unknown key {k!r}")
    allow: dict[str, dict[str, str]] = {}
    for manifest, pakete in (roh.get("allow") or {}).items():
        if not isinstance(pakete, dict):
            fehler.append(f"{KONFIG}: allow[{manifest!r}] must map package → reason")
            continue
        for paket, grund in pakete.items():
            if not isinstance(grund, str) or not grund.strip():
                fehler.append(f"{KONFIG}: allow[{manifest!r}][{paket!r}] has no reason")
                continue
            allow.setdefault(manifest, {})[_norm(paket)] = grund.strip()
    off: dict[str, str] = {}
    for sprache, grund in (roh.get("off") or {}).items():
        if sprache not in SPRACHEN:
            fehler.append(f"{KONFIG}: off[{sprache!r}] is no language ({', '.join(SPRACHEN)})")
        elif not isinstance(grund, str) or not grund.strip():
            fehler.append(f"{KONFIG}: off[{sprache!r}] has no reason")
        else:
            off[sprache] = grund.strip()
    warn = roh.get("warn_until")
    bis = None
    if warn is not None:
        try:
            bis = datetime.date.fromisoformat(warn) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(warn)) else None
        except ValueError:
            bis = None
        if bis is None:
            fehler.append(f"{KONFIG}: warn_until {warn!r} is no date YYYY-MM-DD")
        elif bis > heute + datetime.timedelta(days=WARN_TAGE):
            fehler.append(f"{KONFIG}: warn_until {bis} is more than {WARN_TAGE} days ahead")
            bis = None
    return {"allow": allow, "off": off, "warn_until": bis}, fehler


def _norm(paket: str) -> str:
    """Package names compare like PyPI does (case, `_`/`.`/`-`)."""
    return re.sub(r"[-_.]+", "-", paket).lower()


# ── Go ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def go_pruefen(root: str, dateien: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    """(findings as (manifest, text), warnings)."""
    funde: list[tuple[str, str]] = []
    for gomod in sorted(d for d in dateien if os.path.basename(d) == "go.mod"):
        ordner = os.path.join(root, os.path.dirname(gomod))
        r = _lauf(["go", "mod", "tidy", "-diff"], ordner)
        if r.returncode == 0:
            continue
        diff = [z for z in r.stdout.splitlines() if z[:1] in "+-" and not z.startswith(("+++", "---"))]
        if not diff:
            raise Fehler(f"{gomod}: go mod tidy -diff failed: {(r.stderr or r.stdout).strip()[:300]}")
        weg = sorted({z[1:].split()[0] for z in diff if z.startswith("-") and _modulzeile(z)})
        neu = sorted({z[1:].split()[0] for z in diff if z.startswith("+") and _modulzeile(z)})
        teile = []
        if weg:
            teile.append("not needed: " + ", ".join(weg))
        if neu:
            teile.append("missing: " + ", ".join(neu))
        funde.append((gomod, f"go mod tidy -diff is not empty ({'; '.join(teile) or 'go.sum differs'})"))
    return funde, []


def _modulzeile(z: str) -> bool:
    teile = z[1:].split()
    # A require line of go.mod (`example.invalid/mod v0.41.0`, with a tab in a require block) or a go.sum line; not the
    # directives `module`, `go`, `toolchain`, `require (` …
    return (len(teile) >= 2 and "." in teile[0] and teile[1].startswith("v")
            and teile[0] not in ("module", "go", "toolchain", "require", "replace", "exclude", "tool"))


# ── Rust ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
def machete_programm() -> str:
    """cargo-machete: CARGO_MACHETE, else on PATH, else the pinned version installed once with cargo into a cache."""
    if os.environ.get("CARGO_MACHETE"):
        return os.environ["CARGO_MACHETE"]
    if shutil.which("cargo-machete"):
        return "cargo-machete"
    cache = os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "repokit",
                         f"cargo-machete-{CARGO_MACHETE}")
    prog = os.path.join(cache, "bin", "cargo-machete")
    if not os.path.exists(prog):
        r = _lauf(["cargo", "install", "--locked", "--quiet", "--version", CARGO_MACHETE, "--root", cache,
                   "cargo-machete"], os.getcwd())
        if r.returncode != 0 or not os.path.exists(prog):
            raise Fehler(f"cargo-machete {CARGO_MACHETE} could not be installed: {r.stderr.strip()[-300:]}")
    return prog


def rust_pruefen(root: str, dateien: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    cargos = sorted(d for d in dateien if os.path.basename(d) == "Cargo.toml")
    oben = [c for c in cargos if not any(c != o and c.startswith(os.path.dirname(o) + "/") and os.path.dirname(o)
                                          for o in cargos)]
    funde: list[tuple[str, str]] = []
    for c in oben:
        ordner = os.path.join(root, os.path.dirname(c)) if os.path.dirname(c) else root
        r = _lauf([machete_programm(), ordner], root)
        if r.returncode not in (0, 1):
            raise Fehler(f"{c}: cargo-machete failed: {(r.stderr or r.stdout).strip()[:300]}")
        manifest = None
        for z in r.stdout.splitlines():
            m = re.match(r"^\S+ -- (.+Cargo\.toml):$", z)
            if m:
                manifest = os.path.relpath(m.group(1), root)
            elif z.startswith("\t") and manifest and z.strip():
                funde.append((manifest, f"unused: {z.strip()}"))
        if r.returncode == 1 and not any(f[0].startswith(os.path.dirname(c)) for f in funde):
            raise Fehler(f"{c}: cargo-machete reports findings this check cannot read: {r.stdout.strip()[:300]}")
    return funde, []


# ── Python ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def python_manifeste(root: str, dateien: list[str]) -> list[str]:
    """pyproject.toml with [project] dependencies; per folder requirements.in, else requirements*.txt without hashes.
    Tool pins (.github/…) and the vendored kit are no app manifests."""
    aus: list[str] = []
    ordner: dict[str, list[str]] = {}
    for d in dateien:
        if d.startswith((".github/", "tests/_kit/")):
            continue
        b = os.path.basename(d)
        if b == "pyproject.toml":
            with open(os.path.join(root, d), encoding="utf-8") as fh:
                text = fh.read()
            if re.search(r"(?m)^\[project\]", text) and re.search(r"(?m)^dependencies\s*=", text):
                aus.append(d)
        elif re.fullmatch(r"requirements(-[\w.]+)?\.(in|txt)", b):
            ordner.setdefault(os.path.dirname(d), []).append(d)
    for o, liste in sorted(ordner.items()):
        if os.path.join(o, "pyproject.toml").lstrip("/") in aus:
            continue
        ins = [d for d in liste if d.endswith("requirements.in")]
        if ins:
            aus.append(ins[0])
            continue
        txt = os.path.join(o, "requirements.txt").lstrip("/")
        if txt in liste:
            with open(os.path.join(root, txt), encoding="utf-8") as fh:
                if "--hash" not in fh.read():
                    aus.append(txt)
    return sorted(aus)


def pyproject_anforderungen(pfad: str) -> list[str]:
    """[project] dependencies and every optional dependency of a pyproject.toml (extras count: deptry needs them
    installed to map them; test/dev extras are dev groups). A self reference `name[extra]` is resolved, not installed."""
    import tomllib
    with open(pfad, "rb") as fh:
        projekt = tomllib.load(fh).get("project") or {}
    name = _norm(str(projekt.get("name", "")))
    alle = list(projekt.get("dependencies") or [])
    for werte in (projekt.get("optional-dependencies") or {}).values():
        alle += list(werte or [])
    aus: list[str] = []
    for a in alle:
        kopf = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", a)
        if kopf and _norm(kopf.group(1)) == name:
            continue
        if a not in aus:
            aus.append(a)
    return aus


def python_pruefen(root: str, dateien: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    funde: list[tuple[str, str]] = []
    warnungen: list[str] = []
    for manifest in python_manifeste(root, dateien):
        ordner = os.path.dirname(manifest)
        with tempfile.TemporaryDirectory(prefix="deptry-") as tmp:
            ausgabe = os.path.join(tmp, "deptry.json")
            # A throwaway environment with the manifest installed (all extras): deptry maps packages to modules from the
            # installed metadata; without it, it guesses from the name (PyYAML → yaml fails).
            venv = os.path.join(tmp, "venv")
            vpy = os.path.join(venv, "bin", "python")
            wo = os.path.join(root, ordner) if ordner else root
            liste = os.path.basename(manifest)
            if manifest.endswith("pyproject.toml"):
                liste = os.path.join(tmp, "pyproject-requirements.txt")
                with open(liste, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(pyproject_anforderungen(os.path.join(root, manifest))) + "\n")
            # The interpreter of the CI job (its Python version is the app's), uv when there is one, else venv + pip.
            py = os.environ.get("ABH_PYTHON") or sys.executable
            if shutil.which("uv"):
                schritte = [["uv", "venv", "-q", "--python", py, venv],
                            ["uv", "pip", "install", "-q", "--python", vpy, "-r", liste],
                            ["uv", "pip", "install", "-q", "--python", vpy, DEPTRY]]
            else:
                schritte = [[py, "-m", "venv", venv],
                            [vpy, "-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", liste],
                            [vpy, "-m", "pip", "install", "-q", "--disable-pip-version-check", DEPTRY]]
            for schritt in schritte:
                r = _lauf(schritt, wo)
                if r.returncode != 0:
                    raise Fehler(f"{manifest}: {' '.join(schritt[:3])} failed: {(r.stderr or r.stdout).strip()[-300:]}")
            argv = [os.path.join(venv, "bin", "deptry"), ".", "--json-output", ausgabe, "--known-first-party", "_kit",
                    "--pep621-dev-dependency-groups", ",".join(DEV_EXTRAS)]
            if not manifest.endswith("pyproject.toml"):
                argv += ["--requirements-files", os.path.basename(manifest)]
                dev = [os.path.basename(d) for d in dateien
                       if os.path.dirname(d) == ordner and re.fullmatch(r"requirements-dev\.(in|txt)", os.path.basename(d))]
                if dev:
                    argv += ["--requirements-files-dev", ",".join(dev)]
            r = _lauf(argv, wo, env={**os.environ, "VIRTUAL_ENV": venv})
            try:
                with open(ausgabe, encoding="utf-8") as fh:
                    bericht = json.load(fh)
            except (OSError, ValueError) as e:
                raise Fehler(f"{manifest}: deptry gave no report (rc {r.returncode}): "
                             f"{(r.stderr or r.stdout).strip()[-300:]}") from e
        if not isinstance(bericht, list):
            raise Fehler(f"{manifest}: deptry report has an unknown format")
        for v in bericht:
            code = (v.get("error") or {}).get("code")
            modul = v.get("module", "?")
            if code == "DEP002":
                funde.append((manifest, modul))
            elif code in ("DEP001", "DEP003", "DEP004"):
                ort = (v.get("location") or {}).get("file", "?")
                art = {"DEP001": "imported but not declared", "DEP003": "imported, only transitive",
                       "DEP004": "dev dependency imported in app code"}[code]
                warnungen.append(f"{manifest}: {modul} — {art} ({os.path.join(ordner, ort) if ordner else ort})")
    return funde, warnungen


# ── JS / TS ──────────────────────────────────────────────────────────────────────────────────────────────────────────
KNIP_KONFIG = ("knip.json", ".knip.json", "knip.jsonc", ".knip.jsonc")


def js_pruefen(root: str, dateien: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
    funde: list[tuple[str, str]] = []
    warnungen: list[str] = []
    for pj in sorted(d for d in dateien if os.path.basename(d) == "package.json" and "node_modules/" not in d):
        ordner = os.path.dirname(pj)
        if not any(os.path.join(ordner, k).lstrip("/") in dateien for k in KNIP_KONFIG):
            warnungen.append(f"{pj}: NOT checked — no knip config (knip.json with the entry files), knip would guess")
            continue
        r = _lauf(["npx", "--yes", KNIP, "--include", "dependencies", "--reporter", "json", "--no-progress"],
                  os.path.join(root, ordner) if ordner else root)
        try:
            bericht = json.loads(r.stdout)
        except ValueError as e:
            raise Fehler(f"{pj}: knip gave no JSON (rc {r.returncode}): {(r.stderr or r.stdout).strip()[-300:]}") from e
        for eintrag in bericht.get("issues") or []:
            for art in ("dependencies", "devDependencies", "optionalPeerDependencies"):
                for d in eintrag.get(art) or []:
                    funde.append((pj, d.get("name", "?") if isinstance(d, dict) else str(d)))
    return funde, warnungen


PRUEFER = {"go": go_pruefen, "rust": rust_pruefen, "python": python_pruefen, "js": js_pruefen}
KENNZEICHEN = {"go": "go.mod", "rust": "Cargo.toml", "js": "package.json"}


def pruefen(root: str, sprachen: tuple[str, ...], heute: datetime.date) -> int:
    konfig, fehler = konfig_lesen(root, heute)
    dateien = getrackt(root)
    roh: list[tuple[str, str, str]] = []   # (language, manifest, package/text)
    warnungen: list[str] = []
    for sprache in sprachen:
        if sprache in konfig["off"]:
            print(f"  {sprache}: off — {konfig['off'][sprache]}")
            continue
        try:
            funde, w = PRUEFER[sprache](root, dateien)
        except Fehler as e:
            fehler.append(f"{sprache}: {e}")
            continue
        roh += [(sprache, m, p) for m, p in funde]
        warnungen += w
    for d in dateien:
        if os.path.basename(d) == "composer.json" and not d.startswith(("vendor/", "tests/_kit/")):
            warnungen.append(f"{d}: NOT checked here — composer-unused needs vendor/ and runs in the repo's PHP job")
    offen: list[str] = []
    genutzt: set[tuple[str, str]] = set()
    for sprache, manifest, paket in roh:
        name = _norm(paket.split(":", 1)[-1].strip()) if sprache != "go" else paket
        erlaubt = konfig["allow"].get(manifest, {})
        if sprache != "go" and name in erlaubt:
            genutzt.add((manifest, name))
            continue
        if sprache == "python" and name in OHNE_IMPORT:
            continue
        offen.append(f"{manifest}: {paket}" if sprache == "go" else f"{manifest}: {paket} — declared, never used")
    for manifest, pakete in konfig["allow"].items():
        for paket in pakete:
            if (manifest, paket) not in genutzt:
                fehler.append(f"{KONFIG}: allow[{manifest!r}][{paket!r}] matches no finding — remove it")
    for w in dict.fromkeys(warnungen):   # one line per finding, in order (deptry names every import site)
        print(f"::warning::{w}" if _in_actions() else f"  note: {w}")
    bis = konfig["warn_until"]
    warnmodus = bis is not None and heute <= bis
    for o in offen:
        if warnmodus:
            print(f"::warning::{o} (warning until {bis})" if _in_actions() else f"  WARNING (until {bis}): {o}")
        else:
            print(f"::error::{o}" if _in_actions() else f"  ✗ {o}", file=sys.stderr)
    for f in fehler:
        print(f"::error::{f}" if _in_actions() else f"  ✗ {f}", file=sys.stderr)
    if bis is not None and heute > bis and offen:
        print(f"  warn_until {bis} has passed: the findings are red now", file=sys.stderr)
    if fehler or (offen and not warnmodus):
        return 1
    print(f"  unused dependencies: {len(offen)} open" + (f" (warnings until {bis})" if offen else ", clean"))
    return 0


def _heute() -> datetime.date:
    from zoneinfo import ZoneInfo
    return datetime.datetime.now(ZoneInfo("Europe/Berlin")).date()


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="_abhaengigkeiten.py")
    p.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    p.add_argument("--nur", "--only", dest="nur", default="")
    a = p.parse_args(argv)
    sprachen = tuple(s for s in (a.nur.split(",") if a.nur else SPRACHEN) if s)
    falsch = [s for s in sprachen if s not in SPRACHEN]
    if falsch:
        print(f"unknown language(s): {', '.join(falsch)}", file=sys.stderr)
        return 2
    return pruefen(os.path.abspath(a.root), sprachen, _heute())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
