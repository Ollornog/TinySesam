"""The package as it reaches the user — not the intent in `pyproject.toml`.

Since 0.19.0 PyPI is the installation route ([ADR-6](../backlog/ADR-6-publish-to-pypi.md)).
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

braucht(shutil.which("git"), "git missing")
# git on the PATH is not enough: measuring is done against `git ls-files`, and that needs a
# repo. The unpacked sdist has none — decline there instead of turning red.
braucht((pathlib.Path(__file__).resolve().parent.parent / ".git").exists(),
        "no Git repo (e.g. unpacked sdist) — the package test compares against `git ls-files`")
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
import _normalize_artifacts  # noqa: E402

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
BUILD_TIME = 1700000000
GRAFTED = ("tests", "examples", "deploy")   # the `graft` trees from MANIFEST.in


def stubs_from_gitignore() -> list[str]:
    """For each pattern from .gitignore one dummy in every grafted tree (B4-13)."""
    paths = []
    for line in pathlib.Path(ROOT, ".gitignore").read_text(encoding="utf-8").splitlines():
        pattern = line.strip()
        if not pattern or pattern.startswith(("#", "!")) or pattern.startswith("/"):
            continue
        name = pattern.rstrip("/").replace("*", "dummy")
        for tree in GRAFTED:
            paths.append(f"{tree}/{name}/dummy.txt" if pattern.endswith("/") else f"{tree}/{name}")
    return paths


def make(shift: float = 0.0, stubs: tuple[str, ...] = (),
         group_writes: bool = False) -> tuple[str, str, str]:
    """(directory, wheel, sdist) — from a copy of the versioned files.

    `shift` shifts the file timestamps of the copy by that many seconds — this is what
    a second checkout of the same commit looks like. `group_writes` gives every file g+w, as a
    checkout under umask 0002 (Ubuntu/Mint) creates it. `stubs` adds untracked files,
    as they lie in a used working tree.
    """
    work = tempfile.mkdtemp(prefix="tinysesam-pack-")
    source, destination = os.path.join(work, "src"), os.path.join(work, "dist")
    os.makedirs(source)
    os.makedirs(destination)
    for rel in list(hygiene.getrackte_dateien(ROOT)) + list(stubs):
        path = os.path.join(source, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if rel in stubs:
            pathlib.Path(path).write_text("does not belong in the sdist\n", encoding="utf-8")
        else:
            shutil.copy2(os.path.join(ROOT, rel), path)
        if shift:
            stamp = os.stat(path).st_mtime + shift
            os.utime(path, (stamp, stamp))
        # Set the permissions in BOTH directions: the source itself already sits at
        # 0664 or 0644 depending on umask — only "add g+w" would make no difference on a 0002 machine.
        mode = os.stat(path).st_mode
        os.chmod(path, (mode | 0o020) if group_writes else (mode & ~0o022))

    before, sde = os.getcwd(), os.environ.get("SOURCE_DATE_EPOCH")
    try:
        os.chdir(source)
        os.environ["SOURCE_DATE_EPOCH"] = str(BUILD_TIME)
        whl = build_meta.build_wheel(destination)
        sdist = build_meta.build_sdist(destination)
    finally:
        os.chdir(before)
        if sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = sde
    # The same step as in the release workflow — without it the sdist would depend on timestamps and
    # permissions of the checkout, the wheel on its permissions (umask).
    _normalize_artifacts.normalize_sdist(os.path.join(destination, sdist), BUILD_TIME)
    _normalize_artifacts.normalize_wheel(os.path.join(destination, whl))
    return work, os.path.join(destination, whl), os.path.join(destination, sdist)


def head(text: bytes):
    return email.parser.BytesParser().parsebytes(text)


STUBS = tuple(stubs_from_gitignore())
WORK, WHEEL, SDIST = make(stubs=STUBS)
SECOND = None
try:
    with zipfile.ZipFile(WHEEL) as z:
        wheel_files = set(z.namelist())
        metadata_name = next(n for n in wheel_files if n.endswith(".dist-info/METADATA"))
        META = head(z.read(metadata_name))
    with tarfile.open(SDIST) as t:
        sdist_raw = t.getnames()
        prefix = os.path.basename(SDIST)[: -len(".tar.gz")] + "/"
        sdist_files = {n[len(prefix):] for n in sdist_raw if n.startswith(prefix)}
        pkg_info = next(n for n in sdist_raw if n.endswith(prefix + "PKG-INFO"))
        PKG = head(t.extractfile(pkg_info).read())

    VERSION = META["Version"]
    CLASSES = META.get_all("Classifier") or []

    # ---------- Wheel: what is needed at runtime is also in it ----------
    # The actual reason for this suite. Today the package consists only of `.py` and
    # `py.typed`; as soon as someone adds a template, an image or a translation file,
    # it is missing without an entry in `[tool.setuptools.package-data]` — visible in the repo, not in the wheel,
    # and the error occurs on somebody else's machine.
    package_files = [f for f in hygiene.getrackte_dateien(ROOT) if f.startswith("tinysesam/")]
    assert package_files, "no versioned files found under tinysesam/"
    absent = [f for f in package_files if f not in wheel_files]
    assert not absent, ("these versioned files are missing from the wheel — without an entry under "
                         f"[tool.setuptools.package-data] they are not packed: {absent}")
    not_py = [f for f in package_files if not f.endswith(".py")]
    ok(f"Wheel complete: {len(package_files)} files, of which {len(not_py)} without .py "
       f"({', '.join(os.path.basename(f) for f in not_py)})")

    assert f"tinysesam-{VERSION}.dist-info/entry_points.txt" in wheel_files, \
        "the console command `tinysesam` is missing from the wheel"
    # Since T-7 (setuptools >= 77, PEP 639) the license lies under `dist-info/licenses/`, and the
    # metadata names it as `License-File`. Until then it lay directly in `dist-info`, depending on the build tool
    # — the test knew both places because an older setuptools was building locally.
    licenses = [n for n in wheel_files if ".dist-info/licenses/" in n and "LICENSE" in n.upper()]
    assert licenses, "the license is not in the wheel — expected under <name>.dist-info/licenses/LICENSE"
    assert "LICENSE" in (META.get_all("License-File") or []), \
        f"the metadata does not name the license file (License-File: {META.get_all('License-File')})"
    ok(f"Wheel contains console command and license ({licenses[0].split('.dist-info/')[1]})")

    # ---------- Version: one number, the same everywhere ----------
    module = re.search(r'^__version__ = "([^"]+)"',
                      pathlib.Path(ROOT, "tinysesam/__init__.py").read_text(encoding="utf-8"),
                      re.M).group(1)
    assert VERSION == module == PKG["Version"], (VERSION, module, PKG["Version"])
    ok(f"Version {VERSION}: wheel = sdist = tinysesam.__version__")

    # ---------- The upload lock is gone, and it must not come back ----------
    # `Private :: Do Not Upload` made PyPI reject every upload — right, as long as nothing was
    # published. Since 1.0 it would be a release that only fails at the index.
    private = [k for k in CLASSES if k.startswith("Private ::")]
    assert not private, f"upload lock still in the package: {private}"

    # Maturity is not a feeling: from 1.0 the package says "stable", before that "Beta".
    main = int(VERSION.split(".")[0])
    expected = ("Development Status :: 5 - Production/Stable" if main >= 1
                else "Development Status :: 4 - Beta")
    assert expected in CLASSES, f"for version {VERSION} '{expected}' belongs in the classifiers"
    ok(f"no upload lock; maturity matches the version ({expected.split(' :: ')[1]})")

    # ---------- Python versions: the promise and the test run are the same thing ----------
    # A classifier is a promise. One that CI does not run is a guess.
    ci = pathlib.Path(ROOT, ".github/workflows/ci.yml").read_text(encoding="utf-8")
    matrix = re.search(r"python-version:\s*\[([^\]]+)\]", ci)
    assert matrix, "ci.yml has no python-version matrix any more — then nobody checks here any more"
    driven = re.findall(r'"(\d+\.\d+)"', matrix.group(1))
    named = [k.rsplit(" :: ", 1)[1] for k in CLASSES
               if re.fullmatch(r"Programming Language :: Python :: \d+\.\d+", k)]
    uncovered = [v for v in driven if v not in named]
    assert not uncovered, f"CI runs {uncovered}, the package does not name them as a classifier"

    lower_limit = re.search(r">=\s*(\d+)\.(\d+)", META["Requires-Python"])
    assert lower_limit, f"Requires-Python without lower bound: {META['Requires-Python']!r}"
    smallest = min(tuple(int(x) for x in v.split(".")) for v in named)
    assert smallest == (int(lower_limit.group(1)), int(lower_limit.group(2))), (
        f"Requires-Python says {META['Requires-Python']}, the smallest classifier names "
        f"{'.'.join(str(x) for x in smallest)}")
    ok(f"Python {META['Requires-Python']}: classifiers {named[0]}–{named[-1]}, "
       f"CI runs {', '.join(driven)}")

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
    MEASURED_FLOOR = {          # as of 2026-09-22, authlib 2026-10-28; source OSV.dev
        "fastapi": (0, 133, 0),        # only from here on is starlette >= 1.3.1 allowed
        "python-multipart": (0, 0, 31),
        # 1.6.12: GHSA-5357-c2jx-v7qh et al. (algorithm confusion). 1.9.1: CVE-2026-96760,
        # CVE-2026-114614 to -114618 and -114620 (fixes in 1.8.0, 1.9.0 and 1.9.1).
        "authlib": (1, 9, 1),
    }

    def _numbers(text: str) -> tuple:
        return tuple(int(x) for x in _re_pkg.findall(r"\d+", text))

    measured = []
    for line in (META.get_all("Requires-Dist") or []):
        # "authlib>=1.6.12; extra == \"oidc\"" → name, lower bound
        request = line.split(";", 1)[0].strip()
        hit = _re_pkg.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*>=\s*([0-9.]+)", request)
        if not hit:
            continue
        name = hit.group(1).lower().replace("_", "-")
        if name not in MEASURED_FLOOR:
            continue
        is_, should = _numbers(hit.group(2)), MEASURED_FLOOR[name]
        assert is_ >= should, (
            f"{name}>={hit.group(2)} is below the measured gap-free floor "
            f"{'.'.join(str(x) for x in should)} — an installation that pins the lower bound "
            "gets a version with a known gap")
        measured.append(name)
    absent = sorted(set(MEASURED_FLOOR) - set(measured))
    assert not absent, (f"for {absent} there is no `>=` lower bound in the package — without a floor "
                         "the user installs whatever they happen to pin")
    # An upper bound does NOT belong here: a cap in a library blocks exactly
    # the update that brings the next security fix, and is inherited by every app.
    lid = [z for z in (META.get_all("Requires-Dist") or []) if "<" in z.split(";", 1)[0]]
    assert not lid, f"upper bounds in the package: {lid} — a library does not cap"
    ok(f"Lower bounds above the measured floor ({', '.join(sorted(set(measured)))}), no upper bound")

    # ---------- The project page on the index ----------
    urls = dict(z.split(", ", 1) for z in (META.get_all("Project-URL") or []))
    for required in ("Homepage", "Documentation", "Repository", "Changelog", "Issues"):
        assert required in urls, f"[project.urls] without '{required}' — the sidebar on the index stays empty"
        assert urls[required].startswith("https://"), f"{required} does not point to https"
    assert META["Summary"] and len(META["Summary"]) > 20, "short description missing or too short"
    # The license is in the metadata as an SPDX expression (PEP 639) — and NOT additionally as a
    # classifier: PEP 639 rejects both side by side, and the index would otherwise show two sources.
    assert META["License-Expression"] == "MIT", f"License-Expression is {META['License-Expression']!r}"
    assert not [k for k in CLASSES if k.startswith("License ::")], "license classifier next to the SPDX expression"
    ok(f"Project page complete: {', '.join(sorted(urls))}")

    # ---------- The long description is rendered, not dumped as text ----------
    # Without `Description-Content-Type` PyPI shows the README as raw text — with all the markup.
    assert (META["Description-Content-Type"] or "").startswith("text/markdown"), \
        f"Description-Content-Type is {META['Description-Content-Type']!r}"
    description = META.get_payload() or ""
    assert len(description) > 2000, f"the README did not make it into the package ({len(description)} characters)"
    assert float((META["Metadata-Version"] or "0")) >= 2.1, META["Metadata-Version"]
    ok(f"README as Markdown in the package ({len(description) // 1000} kB), "
       f"Metadata {META['Metadata-Version']}")

    # ---------- sdist: the library source, complete or not at all ----------
    for required in ("pyproject.toml", "README.md", "LICENSE", "CHANGELOG.md", "SECURITY.md",
                    "i18n/README.de.md", "i18n/SECURITY.de.md"):
        assert required in sdist_files, f"{required} is missing from the sdist"
    absent = [f for f in package_files if f not in sdist_files]
    assert not absent, f"these package files are missing from the sdist: {absent}"

    # The test suite is in the sdist — COMPLETE or not at all. By an old heuristic setuptools
    # pulls in only `tests/test_*.py`, without `run_all.py`, without `_kit/`, without
    # `api_surface.json`: half a suite is worse than none, because it claims one
    # can test the source package, and fails at the import. `MANIFEST.in` therefore takes `graft
    # tests`. Whoever repackages TinySesam should be able to verify the build — that is the point of a
    # source package; the repo-bound suites decline there on their own (exit 77).
    tests_inside = {f for f in sdist_files if f.startswith("tests/")}
    assert tests_inside, "the sdist contains no test suite — check `graft tests` in MANIFEST.in"
    for required in ("tests/run_all.py", "tests/_starter.py", "tests/voraussetzung.py",
                    "tests/api_surface.json", "tests/_kit/report.py", "tests/_kit/hygiene.py"):
        assert required in tests_inside, (f"{required} is missing from the sdist — without this file the "
                                       "suite does not start there, and half a suite is worse than none")
    # Every suite the collective run knows in the repo must also be in the source package.
    in_repo = {f"tests/{n}" for n in os.listdir(os.path.join(str(ROOT), "tests"))
              if n.startswith("test_") and n.endswith(".py")}
    missing_suites = sorted(in_repo - tests_inside)
    assert not missing_suites, f"these suites are missing from the sdist: {missing_suites}"
    ok(f"sdist carries the complete suite ({len(tests_inside)} files, {len(in_repo)} suites)")

    # What the README links to should also be in the source package — a dead link is more annoying in a
    # tarball than on the web, where there is no GitHub next to it.
    for required in ("examples/showcase.py", "deploy/forward-auth/docker-compose.yml",
                    "deploy/fail2ban/tinysesam-jail.conf"):
        assert required in sdist_files, f"{required} is missing from the sdist (linked in the README)"
    trash = sorted(f for f in sdist_files | wheel_files
                   if "__pycache__" in f or f.endswith((".pyc", ".pyo")))
    assert not trash, f"build artifacts in the package: {trash[:3]}"
    ok(f"sdist: {len(sdist_files)} files, license/CHANGELOG/SECURITY included, "
       "no half test suite, no bytecode")

    # ---------- What .gitignore excludes stays out (B4-13) ----------
    # Above, the build was done WITH a dummy per .gitignore pattern in every grafted tree — this is how
    # a used working tree looks (an `examples/app.db`, a `deploy/…/.env`). The
    # release builds from a fresh checkout; whoever packages themselves does not.
    assert len(STUBS) >= 3 * len(GRAFTED), f"too few dummies from .gitignore: {STUBS}"
    slipped_through = sorted(a for a in STUBS if a in sdist_files or a in wheel_files)
    assert not slipped_through, ("gitignored files in the package — adjust the pattern in MANIFEST.in: "
                                f"{slipped_through[:6]}")
    ok(f"none of the {len(STUBS)} gitignored dummies in the sdist or wheel")

    # ---------- Bit-reproducible: second checkout, same checksums (B4-8) ----------
    # A second build with different file timestamps and g+w permissions — this is how two
    # checkouts of the same commit differ (different time, different umask). With the same
    # `SOURCE_DATE_EPOCH` wheel and sdist must be byte-for-byte identical, otherwise nobody can reproduce the
    # published checksum. Until the re-check (A-3) the second build copied the
    # permissions along — the 0644/0664 difference in the wheel thus never showed up.
    import hashlib  # noqa: E402
    SECOND, WHEEL2, SDIST2 = make(shift=86400.0, stubs=STUBS, group_writes=True)

    def _sha(path: str) -> str:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

    assert _sha(WHEEL) == _sha(WHEEL2), ("wheel not reproducible (SOURCE_DATE_EPOCH or "
                                         "the permission normalization has no effect)")
    assert _sha(SDIST) == _sha(SDIST2), ("sdist not reproducible — "
                                         "scripts/_normalize_artifacts.py has no effect")
    # The release workflow does the same, in this order and in the same step: export time,
    # build without isolation, normalize both artifacts. A mere "appears somewhere"
    # (until the re-check, A-6) pinned down neither the order nor `--no-isolation`.
    rel_lines = [hygiene.ohne_yaml_kommentar(z).strip() for z in
                  pathlib.Path(ROOT, ".github/workflows/release.yml").read_text(encoding="utf-8").splitlines()]
    build = next((i for i, z in enumerate(rel_lines) if re.search(r"-m\s+build\b", z)), None)
    assert build is not None, "release.yml does not build with `-m build`"
    assert "--no-isolation" in rel_lines[build], f"release.yml builds with isolation: {rel_lines[build]}"
    start = max(i for i in range(build) if re.match(r"^(- )?(name|run|uses):", rel_lines[i]))
    end = next((i for i in range(build + 1, len(rel_lines))
                 if re.match(r"^- (name|uses|run):", rel_lines[i])), len(rel_lines))
    before, afterwards = rel_lines[start:build], rel_lines[build + 1:end]
    assert "export SOURCE_DATE_EPOCH" in before, "release.yml: SOURCE_DATE_EPOCH not exported before the build"
    assert any(re.match(r"^SOURCE_DATE_EPOCH=\"\$\(git log -1 --format=%ct\)\"$", z) for z in before), \
        "release.yml: SOURCE_DATE_EPOCH not from the commit timestamp"
    assert any("scripts/_normalize_artifacts.py" in z and "dist/*.whl" in z and "dist/*.tar.gz" in z
               for z in afterwards), "release.yml: wheel and sdist are not normalized after the build"
    ok(f"Wheel and sdist bit-reproducible (sha256 {_sha(SDIST)[:12]}…), release builds the same way")

    # ---------- Publishing happens without a secret ----------
    # Trusted Publishing (OIDC) instead of an API token: no value in the repo, none that has to be
    # rotated, and none that a fork PR could grab.
    lines = pathlib.Path(ROOT, ".github/workflows/release.yml").read_text(encoding="utf-8").splitlines()
    rel = "\n".join(lines)
    assert 'tags: ["v*"]' in rel, "it would publish without a tag — a human presses the button"
    assert "id-token: write" in rel, "without the id-token permission there is no OIDC identity"
    assert "name: pypi" in rel, ("the upload lacks the environment `pypi` — it is the name "
                                "the publisher names on pypi.org, and the place for a "
                                "second pair of hands before publishing")

    # Look at the step itself, not the whole file: a `password:` is legitimate here
    # — when logging in to the container registry. Only the PyPI step may not have one.
    i = next((n for n, z in enumerate(lines) if "pypa/gh-action-pypi-publish" in z), None)
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
    for forbidden in ("PYPI_API_TOKEN", "TWINE_", "TWINE_PASSWORD", "twine upload"):
        hit = [f"Line {n + 1}: {z.strip()}" for n, z in enumerate(lines) if forbidden in z]
        assert not hit, (f"'{forbidden}' in the release workflow: {hit} — Trusted Publishing "
                             "needs no secret")
    # `password:` appears in comments (the file explains why there is none) — hence
    # only real YAML assignments. Excepted is `secrets.GITHUB_TOKEN`: it is generated by GitHub
    # per run, is not a maintained secret and logs the image in to GHCR here.
    # Also excepted is the throwaway value of the dress rehearsal (`password: rehearsal`, since 2026-10-11):
    # it only logs in at the local registry and the local package server on the runner — exactly
    # this word, no expression, no secret. The real upload (job `pypi`) stays without a password.
    pw_lines = [f"Line {n + 1}: {z.strip()}" for n, z in enumerate(lines)
                 if _re_pkg.match(r"^\s*password\s*:", z) and "secrets.GITHUB_TOKEN" not in z
                 and z.strip() != "password: rehearsal"]
    assert not pw_lines, (f"`password:` in the release workflow: {pw_lines} — Trusted Publishing "
                           "needs no secret")
    ok("Release publishes via Trusted Publishing, only on a tag, without a secret")

finally:
    shutil.rmtree(WORK, ignore_errors=True)
    if SECOND:
        shutil.rmtree(SECOND, ignore_errors=True)

print("OK test_packaging")
