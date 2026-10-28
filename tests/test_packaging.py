"""The package as it reaches the user — not the intent in `pyproject.toml`.

Since 0.19.0 PyPI is the installation route ([ADR-6](../backlog/ADR-6-pypi-veroeffentlichen.md)).
So what counts is no longer what lies in the repo but what ends up in the wheel and the sdist — and the
two are built from different rules. A wheel missing a file installs
cleanly and only crashes at the user; a version that is on PyPI cannot be
taken back. Both show up here, before a tag is set.

That is why it really **builds**, instead of reading `pyproject.toml`: the
versioned tree (`git ls-files`) is built in a copy outside the repo — offline, without
build isolation, so nothing has to be downloaded and the working tree stays untouched
(CI afterwards checks that it is).

On its very first run this test found what it was meant for: the sdist contained
`tests/test_*.py`, but neither `tests/run_all.py` nor `tests/_kit/` — a suite that cannot
be started. See `MANIFEST.in`.
"""

# This suite reads the repo state via git. Without git it is not meaningful —
# a missing precondition, not a failure.
import re as _re_pkg
import shutil  # noqa: E402
from voraussetzung import braucht  # noqa: E402
import pathlib  # noqa: E402

braucht(shutil.which("git"), "git fehlt")
# git on the PATH is not enough: measuring is done against `git ls-files`, and that needs a
# repo. The unpacked sdist has none — decline there instead of turning red.
braucht((pathlib.Path(__file__).resolve().parent.parent / ".git").exists(),
        "kein Git-Repo (z.B. ausgepacktes sdist) — der Paket-Test vergleicht gegen `git ls-files`")
import email.parser
import re
import shutil
import os
import sys
import tarfile
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _kit import hygiene  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import _artefakte_normalisieren  # noqa: E402

# Without setuptools nothing can be built — and without a build this test checks nothing. A
# silent "skipped" would be the worst answer here: it would look green and be empty.
try:
    import setuptools
    from setuptools import build_meta
except ImportError:  # pragma: no cover
    print("  setuptools is missing — without a build backend this suite is not meaningful.")
    print("  → pip install setuptools wheel")
    sys.exit(1)
# The SPDX license expression (PEP 639, T-7) needs setuptools >= 77. With an older one the
# build below fails with a message about `project.license` that nobody relates to the version —
# hence loud here and with the reason.
if int(setuptools.__version__.split(".")[0]) < 77:  # pragma: no cover
    print(f"  setuptools {setuptools.__version__} is too old — the license expression needs >= 77.")
    print("  → pip install -U setuptools")
    sys.exit(1)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def ok(name):
    print(f"  ✓ {name}")


# Fixed build time for the reproducibility comparison below. The value is arbitrary — what counts
# is that both builds see the same one, like the commit timestamp in the release workflow.
BAUZEIT = 1700000000
GEGRAFTET = ("tests", "examples", "deploy")   # the `graft` trees from MANIFEST.in


def attrappen_aus_gitignore() -> list[str]:
    """For each pattern from .gitignore one dummy in every grafted tree (B4-13)."""
    pfade = []
    for zeile in pathlib.Path(ROOT, ".gitignore").read_text(encoding="utf-8").splitlines():
        muster = zeile.strip()
        if not muster or muster.startswith(("#", "!")) or muster.startswith("/"):
            continue
        name = muster.rstrip("/").replace("*", "attrappe")
        for baum in GEGRAFTET:
            pfade.append(f"{baum}/{name}/attrappe.txt" if muster.endswith("/") else f"{baum}/{name}")
    return pfade


def baue(verschiebung: float = 0.0, attrappen: tuple[str, ...] = (),
         gruppe_schreibt: bool = False) -> tuple[str, str, str]:
    """(directory, wheel, sdist) — from a copy of the versioned files.

    `verschiebung` shifts the file timestamps of the copy by that many seconds — this is what
    a second checkout of the same commit looks like. `gruppe_schreibt` gives every file g+w, as a
    checkout under umask 0002 (Ubuntu/Mint) creates it. `attrappen` adds untracked files,
    as they lie in a used working tree.
    """
    arbeit = tempfile.mkdtemp(prefix="tinysesam-pack-")
    quelle, ziel = os.path.join(arbeit, "src"), os.path.join(arbeit, "dist")
    os.makedirs(quelle)
    os.makedirs(ziel)
    for rel in list(hygiene.getrackte_dateien(ROOT)) + list(attrappen):
        pfad = os.path.join(quelle, rel)
        os.makedirs(os.path.dirname(pfad), exist_ok=True)
        if rel in attrappen:
            pathlib.Path(pfad).write_text("gehört nicht ins sdist\n", encoding="utf-8")
        else:
            shutil.copy2(os.path.join(ROOT, rel), pfad)
        if verschiebung:
            stempel = os.stat(pfad).st_mtime + verschiebung
            os.utime(pfad, (stempel, stempel))
        # Set the permissions in BOTH directions: the source itself already sits at
        # 0664 or 0644 depending on umask — only "add g+w" would make no difference on a 0002 machine.
        modus = os.stat(pfad).st_mode
        os.chmod(pfad, (modus | 0o020) if gruppe_schreibt else (modus & ~0o022))

    vorher, sde = os.getcwd(), os.environ.get("SOURCE_DATE_EPOCH")
    try:
        os.chdir(quelle)
        os.environ["SOURCE_DATE_EPOCH"] = str(BAUZEIT)
        whl = build_meta.build_wheel(ziel)
        sdist = build_meta.build_sdist(ziel)
    finally:
        os.chdir(vorher)
        if sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = sde
    # The same step as in the release workflow — without it the sdist would depend on timestamps and
    # permissions of the checkout, the wheel on its permissions (umask).
    _artefakte_normalisieren.sdist_normalisieren(os.path.join(ziel, sdist), BAUZEIT)
    _artefakte_normalisieren.wheel_normalisieren(os.path.join(ziel, whl))
    return arbeit, os.path.join(ziel, whl), os.path.join(ziel, sdist)


def kopf(text: bytes):
    return email.parser.BytesParser().parsebytes(text)


ATTRAPPEN = tuple(attrappen_aus_gitignore())
ARBEIT, WHEEL, SDIST = baue(attrappen=ATTRAPPEN)
ZWEITER = None
try:
    with zipfile.ZipFile(WHEEL) as z:
        wheel_dateien = set(z.namelist())
        metadata_name = next(n for n in wheel_dateien if n.endswith(".dist-info/METADATA"))
        META = kopf(z.read(metadata_name))
    with tarfile.open(SDIST) as t:
        sdist_roh = t.getnames()
        praefix = os.path.basename(SDIST)[: -len(".tar.gz")] + "/"
        sdist_dateien = {n[len(praefix):] for n in sdist_roh if n.startswith(praefix)}
        pkg_info = next(n for n in sdist_roh if n.endswith(praefix + "PKG-INFO"))
        PKG = kopf(t.extractfile(pkg_info).read())

    VERSION = META["Version"]
    KLASSEN = META.get_all("Classifier") or []

    # ---------- Wheel: what is needed at runtime is also in it ----------
    # The actual reason for this suite. Today the package consists only of `.py` and
    # `py.typed`; as soon as someone adds a template, an image or a translation file,
    # it is missing without an entry in `[tool.setuptools.package-data]` — visible in the repo, not in the wheel,
    # and the error occurs on somebody else's machine.
    paketdateien = [f for f in hygiene.getrackte_dateien(ROOT) if f.startswith("tinysesam/")]
    assert paketdateien, "no versioned files found under tinysesam/"
    fehlend = [f for f in paketdateien if f not in wheel_dateien]
    assert not fehlend, ("these versioned files are missing from the wheel — without an entry under "
                         f"[tool.setuptools.package-data] they are not packed: {fehlend}")
    nicht_py = [f for f in paketdateien if not f.endswith(".py")]
    ok(f"Wheel complete: {len(paketdateien)} files, of which {len(nicht_py)} without .py "
       f"({', '.join(os.path.basename(f) for f in nicht_py)})")

    assert f"tinysesam-{VERSION}.dist-info/entry_points.txt" in wheel_dateien, \
        "the console command `tinysesam` is missing from the wheel"
    # Since T-7 (setuptools >= 77, PEP 639) the license lies under `dist-info/licenses/`, and the
    # metadata names it as `License-File`. Until then it lay directly in `dist-info`, depending on the build tool
    # — the test knew both places because an older setuptools was building locally.
    lizenzen = [n for n in wheel_dateien if ".dist-info/licenses/" in n and "LICENSE" in n.upper()]
    assert lizenzen, "the license is not in the wheel — expected under <name>.dist-info/licenses/LICENSE"
    assert "LICENSE" in (META.get_all("License-File") or []), \
        f"the metadata does not name the license file (License-File: {META.get_all('License-File')})"
    ok(f"Wheel contains console command and license ({lizenzen[0].split('.dist-info/')[1]})")

    # ---------- Version: one number, the same everywhere ----------
    modul = re.search(r'^__version__ = "([^"]+)"',
                      pathlib.Path(ROOT, "tinysesam/__init__.py").read_text(encoding="utf-8"),
                      re.M).group(1)
    assert VERSION == modul == PKG["Version"], (VERSION, modul, PKG["Version"])
    ok(f"Version {VERSION}: wheel = sdist = tinysesam.__version__")

    # ---------- The upload lock is gone, and it must not come back ----------
    # `Private :: Do Not Upload` made PyPI reject every upload — right, as long as nothing was
    # published. Since 1.0 it would be a release that only fails at the index.
    privat = [k for k in KLASSEN if k.startswith("Private ::")]
    assert not privat, f"upload lock still in the package: {privat}"

    # Maturity is not a feeling: from 1.0 the package says "stable", before that "Beta".
    haupt = int(VERSION.split(".")[0])
    erwartet = ("Development Status :: 5 - Production/Stable" if haupt >= 1
                else "Development Status :: 4 - Beta")
    assert erwartet in KLASSEN, f"for version {VERSION} '{erwartet}' belongs in the classifiers"
    ok(f"no upload lock; maturity matches the version ({erwartet.split(' :: ')[1]})")

    # ---------- Python versions: the promise and the test run are the same thing ----------
    # A classifier is a promise. One that CI does not run is a guess.
    ci = pathlib.Path(ROOT, ".github/workflows/ci.yml").read_text(encoding="utf-8")
    matrix = re.search(r"python-version:\s*\[([^\]]+)\]", ci)
    assert matrix, "ci.yml has no python-version matrix any more — then nobody checks here any more"
    gefahren = re.findall(r'"(\d+\.\d+)"', matrix.group(1))
    genannt = [k.rsplit(" :: ", 1)[1] for k in KLASSEN
               if re.fullmatch(r"Programming Language :: Python :: \d+\.\d+", k)]
    ungedeckt = [v for v in gefahren if v not in genannt]
    assert not ungedeckt, f"CI runs {ungedeckt}, the package does not name them as a classifier"

    untergrenze = re.search(r">=\s*(\d+)\.(\d+)", META["Requires-Python"])
    assert untergrenze, f"Requires-Python without lower bound: {META['Requires-Python']!r}"
    kleinste = min(tuple(int(x) for x in v.split(".")) for v in genannt)
    assert kleinste == (int(untergrenze.group(1)), int(untergrenze.group(2))), (
        f"Requires-Python says {META['Requires-Python']}, the smallest classifier names "
        f"{'.'.join(str(x) for x in kleinste)}")
    ok(f"Python {META['Requires-Python']}: classifiers {genannt[0]}–{genannt[-1]}, "
       f"CI runs {', '.join(gefahren)}")

    # ---------- Lower bounds: the floor is measured, not guessed ----------
    # A `>=` without a cap is a promise to everyone who pins a version (lockfile,
    # constraints, distribution package): "supported from here". If the floor lay below a
    # security fix, the promise was false — and nobody noticed, because a fresh install
    # pulls the newest anyway. Up to 0.18.0 the lowest allowed resolution resolved to
    # authlib 1.3.0, python-multipart 0.0.9 and (via FastAPI) starlette 0.36.3, all three
    # with open advisories (B4-1 from T-13).
    #
    # Measured against a table, not against the network: a test that queries OSV is
    # neither runnable offline nor identical across two runs. The table is rebuilt in every
    # dependency round (`uv pip compile --resolution=lowest-direct` + OSV batch) and is frozen
    # here. So this test does NOT keep the world up to date — it makes sure that the
    # once-measured floor does not slip again.
    GEMESSENER_BODEN = {          # as of 2026-09-22, authlib 2026-10-28; source OSV.dev
        "fastapi": (0, 133, 0),        # only from here on is starlette >= 1.3.1 allowed
        "python-multipart": (0, 0, 31),
        # 1.6.12: GHSA-5357-c2jx-v7qh et al. (algorithm confusion). 1.9.1: CVE-2026-96760,
        # CVE-2026-114614 to -114618 and -114620 (fixes in 1.8.0, 1.9.0 and 1.9.1).
        "authlib": (1, 9, 1),
    }

    def _zahlen(text: str) -> tuple:
        return tuple(int(x) for x in _re_pkg.findall(r"\d+", text))

    gemessen = []
    for zeile in (META.get_all("Requires-Dist") or []):
        # "authlib>=1.6.12; extra == \"oidc\"" → name, lower bound
        anforderung = zeile.split(";", 1)[0].strip()
        treffer = _re_pkg.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*>=\s*([0-9.]+)", anforderung)
        if not treffer:
            continue
        name = treffer.group(1).lower().replace("_", "-")
        if name not in GEMESSENER_BODEN:
            continue
        ist, soll = _zahlen(treffer.group(2)), GEMESSENER_BODEN[name]
        assert ist >= soll, (
            f"{name}>={treffer.group(2)} is below the measured gap-free floor "
            f"{'.'.join(str(x) for x in soll)} — an installation that pins the lower bound "
            "gets a version with a known gap")
        gemessen.append(name)
    fehlend = sorted(set(GEMESSENER_BODEN) - set(gemessen))
    assert not fehlend, (f"for {fehlend} there is no `>=` lower bound in the package — without a floor "
                         "the user installs whatever they happen to pin")
    # An upper bound does NOT belong here: a cap in a library blocks exactly
    # the update that brings the next security fix, and is inherited by every app.
    deckel = [z for z in (META.get_all("Requires-Dist") or []) if "<" in z.split(";", 1)[0]]
    assert not deckel, f"upper bounds in the package: {deckel} — a library does not cap"
    ok(f"Lower bounds above the measured floor ({', '.join(sorted(set(gemessen)))}), no upper bound")

    # ---------- The project page on the index ----------
    urls = dict(z.split(", ", 1) for z in (META.get_all("Project-URL") or []))
    for pflicht in ("Homepage", "Documentation", "Repository", "Changelog", "Issues"):
        assert pflicht in urls, f"[project.urls] without '{pflicht}' — the sidebar on the index stays empty"
        assert urls[pflicht].startswith("https://"), f"{pflicht} does not point to https"
    assert META["Summary"] and len(META["Summary"]) > 20, "short description missing or too short"
    # The license is in the metadata as an SPDX expression (PEP 639) — and NOT additionally as a
    # classifier: PEP 639 rejects both side by side, and the index would otherwise show two sources.
    assert META["License-Expression"] == "MIT", f"License-Expression is {META['License-Expression']!r}"
    assert not [k for k in KLASSEN if k.startswith("License ::")], "license classifier next to the SPDX expression"
    ok(f"Project page complete: {', '.join(sorted(urls))}")

    # ---------- The long description is rendered, not dumped as text ----------
    # Without `Description-Content-Type` PyPI shows the README as raw text — with all the markup.
    assert (META["Description-Content-Type"] or "").startswith("text/markdown"), \
        f"Description-Content-Type is {META['Description-Content-Type']!r}"
    beschreibung = META.get_payload() or ""
    assert len(beschreibung) > 2000, f"the README did not make it into the package ({len(beschreibung)} characters)"
    assert float((META["Metadata-Version"] or "0")) >= 2.1, META["Metadata-Version"]
    ok(f"README as Markdown in the package ({len(beschreibung) // 1000} kB), "
       f"Metadata {META['Metadata-Version']}")

    # ---------- sdist: the library source, complete or not at all ----------
    for pflicht in ("pyproject.toml", "README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md",
                    "i18n/README.de.md", "i18n/SECURITY.de.md"):
        assert pflicht in sdist_dateien, f"{pflicht} is missing from the sdist"
    fehlend = [f for f in paketdateien if f not in sdist_dateien]
    assert not fehlend, f"these package files are missing from the sdist: {fehlend}"

    # The test suite is in the sdist — COMPLETE or not at all. By an old heuristic setuptools
    # pulls in only `tests/test_*.py`, without `run_all.py`, without `_kit/`, without
    # `api_surface.json`: half a suite is worse than none, because it claims one
    # can test the source package, and fails at the import. `MANIFEST.in` therefore takes `graft
    # tests`. Whoever repackages TinySesam should be able to verify the build — that is the point of a
    # source package; the repo-bound suites decline there on their own (exit 77).
    tests_drin = {f for f in sdist_dateien if f.startswith("tests/")}
    assert tests_drin, "the sdist contains no test suite — check `graft tests` in MANIFEST.in"
    for pflicht in ("tests/run_all.py", "tests/_starter.py", "tests/voraussetzung.py",
                    "tests/api_surface.json", "tests/_kit/report.py", "tests/_kit/hygiene.py"):
        assert pflicht in tests_drin, (f"{pflicht} is missing from the sdist — without this file the "
                                       "suite does not start there, and half a suite is worse than none")
    # Every suite the collective run knows in the repo must also be in the source package.
    im_repo = {f"tests/{n}" for n in os.listdir(os.path.join(str(ROOT), "tests"))
              if n.startswith("test_") and n.endswith(".py")}
    fehlende_suiten = sorted(im_repo - tests_drin)
    assert not fehlende_suiten, f"these suites are missing from the sdist: {fehlende_suiten}"
    ok(f"sdist carries the complete suite ({len(tests_drin)} files, {len(im_repo)} suites)")

    # What the README links to should also be in the source package — a dead link is more annoying in a
    # tarball than on the web, where there is no GitHub next to it.
    for pflicht in ("examples/showcase.py", "deploy/forward-auth/docker-compose.yml",
                    "deploy/fail2ban/tinysesam-jail.conf"):
        assert pflicht in sdist_dateien, f"{pflicht} is missing from the sdist (linked in the README)"
    muell = sorted(f for f in sdist_dateien | wheel_dateien
                   if "__pycache__" in f or f.endswith((".pyc", ".pyo")))
    assert not muell, f"build artifacts in the package: {muell[:3]}"
    ok(f"sdist: {len(sdist_dateien)} files, license/CHANGELOG/SECURITY included, "
       "no half test suite, no bytecode")

    # ---------- What .gitignore excludes stays out (B4-13) ----------
    # Above, the build was done WITH a dummy per .gitignore pattern in every grafted tree — this is how
    # a used working tree looks (an `examples/app.db`, a `deploy/…/.env`). The
    # release builds from a fresh checkout; whoever packages themselves does not.
    assert len(ATTRAPPEN) >= 3 * len(GEGRAFTET), f"too few dummies from .gitignore: {ATTRAPPEN}"
    durchgerutscht = sorted(a for a in ATTRAPPEN if a in sdist_dateien or a in wheel_dateien)
    assert not durchgerutscht, ("gitignored files in the package — adjust the pattern in MANIFEST.in: "
                                f"{durchgerutscht[:6]}")
    ok(f"none of the {len(ATTRAPPEN)} gitignored dummies in the sdist or wheel")

    # ---------- Bit-reproducible: second checkout, same checksums (B4-8) ----------
    # A second build with different file timestamps and g+w permissions — this is how two
    # checkouts of the same commit differ (different time, different umask). With the same
    # `SOURCE_DATE_EPOCH` wheel and sdist must be byte-for-byte identical, otherwise nobody can reproduce the
    # published checksum. Until the re-check (A-3) the second build copied the
    # permissions along — the 0644/0664 difference in the wheel thus never showed up.
    import hashlib  # noqa: E402
    ZWEITER, WHEEL2, SDIST2 = baue(verschiebung=86400.0, attrappen=ATTRAPPEN, gruppe_schreibt=True)

    def _sha(pfad: str) -> str:
        return hashlib.sha256(pathlib.Path(pfad).read_bytes()).hexdigest()

    assert _sha(WHEEL) == _sha(WHEEL2), ("wheel not reproducible (SOURCE_DATE_EPOCH or "
                                         "the permission normalization has no effect)")
    assert _sha(SDIST) == _sha(SDIST2), ("sdist not reproducible — "
                                         "scripts/_artefakte_normalisieren.py has no effect")
    # The release workflow does the same, in this order and in the same step: export time,
    # build without isolation, normalize both artifacts. A mere "appears somewhere"
    # (until the re-check, A-6) pinned down neither the order nor `--no-isolation`.
    rel_zeilen = [hygiene.ohne_yaml_kommentar(z).strip() for z in
                  pathlib.Path(ROOT, ".github/workflows/release.yml").read_text(encoding="utf-8").splitlines()]
    bau = next((i for i, z in enumerate(rel_zeilen) if re.search(r"-m\s+build\b", z)), None)
    assert bau is not None, "release.yml does not build with `-m build`"
    assert "--no-isolation" in rel_zeilen[bau], f"release.yml builds with isolation: {rel_zeilen[bau]}"
    anfang = max(i for i in range(bau) if re.match(r"^(- )?(name|run|uses):", rel_zeilen[i]))
    ende = next((i for i in range(bau + 1, len(rel_zeilen))
                 if re.match(r"^- (name|uses|run):", rel_zeilen[i])), len(rel_zeilen))
    davor, danach = rel_zeilen[anfang:bau], rel_zeilen[bau + 1:ende]
    assert "export SOURCE_DATE_EPOCH" in davor, "release.yml: SOURCE_DATE_EPOCH not exported before the build"
    assert any(re.match(r"^SOURCE_DATE_EPOCH=\"\$\(git log -1 --format=%ct\)\"$", z) for z in davor), \
        "release.yml: SOURCE_DATE_EPOCH not from the commit timestamp"
    assert any("scripts/_artefakte_normalisieren.py" in z and "dist/*.whl" in z and "dist/*.tar.gz" in z
               for z in danach), "release.yml: wheel and sdist are not normalized after the build"
    ok(f"Wheel and sdist bit-reproducible (sha256 {_sha(SDIST)[:12]}…), release builds the same way")

    # ---------- Publishing happens without a secret ----------
    # Trusted Publishing (OIDC) instead of an API token: no value in the repo, none that has to be
    # rotated, and none that a fork PR could grab.
    zeilen = pathlib.Path(ROOT, ".github/workflows/release.yml").read_text(encoding="utf-8").splitlines()
    rel = "\n".join(zeilen)
    assert 'tags: ["v*"]' in rel, "it would publish without a tag — a human presses the button"
    assert "id-token: write" in rel, "without the id-token permission there is no OIDC identity"
    assert "name: pypi" in rel, ("the upload lacks the environment `pypi` — it is the name "
                                "the publisher names on pypi.org, and the place for a "
                                "second pair of hands before publishing")

    # Look at the step itself, not the whole file: a `password:` is legitimate here
    # — when logging in to the container registry. Only the PyPI step may not have one.
    i = next((n for n, z in enumerate(zeilen) if "pypa/gh-action-pypi-publish" in z), None)
    assert i is not None, "the release does not publish to PyPI"

    # The WHOLE file is checked, not just "the block under the uses line".
    #
    # The first version cut the step off at the indentation of the `uses:` line. If a `name:`
    # precedes it, as is usual, `uses:` moves one level deeper — and everything below it,
    # including a `password: ${{ secrets.PYPI_API_TOKEN }}`, counted as "no longer in the
    # step". The most ordinary YAML restructuring thus silently switched the check off. Before a
    # first publication that is the most expensive conceivable false alarm in reverse: it reports
    # green while a token sits in the workflow.
    #
    # A token belongs nowhere in this file, so the delimitation is not needed at all.
    for verboten in ("PYPI_API_TOKEN", "TWINE_", "TWINE_PASSWORD", "twine upload"):
        treffer = [f"Zeile {n + 1}: {z.strip()}" for n, z in enumerate(zeilen) if verboten in z]
        assert not treffer, (f"'{verboten}' in the release workflow: {treffer} — Trusted Publishing "
                             "needs no secret")
    # `password:` appears in comments (the file explains why there is none) — hence
    # only real YAML assignments. Excepted is `secrets.GITHUB_TOKEN`: it is generated by GitHub
    # per run, is not a maintained secret and logs the image in to GHCR here.
    # Also excepted is the throwaway value of the dress rehearsal (`password: generalprobe`, since 2026-10-11):
    # it only logs in at the local registry and the local package server on the runner — exactly
    # this word, no expression, no secret. The real upload (job `pypi`) stays without a password.
    pw_zeilen = [f"Zeile {n + 1}: {z.strip()}" for n, z in enumerate(zeilen)
                 if _re_pkg.match(r"^\s*password\s*:", z) and "secrets.GITHUB_TOKEN" not in z
                 and z.strip() != "password: generalprobe"]
    assert not pw_zeilen, (f"`password:` in the release workflow: {pw_zeilen} — Trusted Publishing "
                           "needs no secret")
    ok("Release publishes via Trusted Publishing, only on a tag, without a secret")

finally:
    shutil.rmtree(ARBEIT, ignore_errors=True)
    if ZWEITER:
        shutil.rmtree(ZWEITER, ignore_errors=True)

print("OK test_packaging")
