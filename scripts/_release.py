#!/usr/bin/env python3
"""release — do the manual steps before a release and check them. stdlib-only.

    python3 scripts/_release.py 0.17.0          set the version, close the CHANGELOG
    python3 scripts/_release.py --check       check only, change nothing

The version appears in eight places (package, module, two READMEs several times, two compose files, the `go get` of
the Go client README) and in the CHANGELOG. By hand this has worked so far because a test enforces it — but "works because
a test complains" is not a procedure, it is a loop of error and correction. Milestone 1.0
explicitly requires that a release runs through without manual steps
(`backlog/M-4-api-stable-1-0.md`).

What this script deliberately does NOT do: tag and push. A human presses the button — the same
separation as for rollout (delivery, not deployment). It prepares and says what follows. The Go module tag
`clients/go/vX.Y.Z` is not a second button: release.yml sets it from the release tag (scripts/_go_module_tag.py).
"""
from __future__ import annotations

import datetime as dt
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _go_module_tag  # noqa: E402 — sibling script, stdlib-only

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Everywhere a version appears. The READMEs name it several times (git ref, wheel URL, image tag,
# verification commands) — so we replace, rather than patch a fixed line number.
FILES = ["pyproject.toml", "tinysesam/__init__.py", "README.md", "i18n/README.de.md",
           "deploy/forward-auth/docker-compose.yml", "deploy/quickstart/docker-compose.yml", "clients/go/README.md"]
CHANGELOG = ROOT / "CHANGELOG.md"
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def current_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


def check() -> int:
    """Does everything match? Returns the number of complaints."""
    version = current_version()
    error = []

    module = (ROOT / "tinysesam/__init__.py").read_text(encoding="utf-8")
    if f'__version__ = "{version}"' not in module:
        error.append(f"tinysesam/__init__.py does not name {version}")

    for name in FILES[2:]:
        text = (ROOT / name).read_text(encoding="utf-8")
        # An older version in an example is not a cosmetic flaw: it sends users to a state
        # that this release is just replacing.
        # `tinysesam-caddy-gate:v…` too: the quickstart pins both own images (since 2026-11-20).
        # `clients/go@v…`: the `go get` of the Go module (tag `clients/go/vX.Y.Z`, set by release.yml).
        old = {v for v in re.findall(r"(?:tinysesam(?:-caddy-gate)?[:@/-]|clients/go@)v?(\d+\.\d+\.\d+)", text)} - {version}
        if old:
            error.append(f"{name} still refers to {', '.join(sorted(old))}")

    # release.yml tags the Go module as `clients/go/vX.Y.Z` (job `go-module-plan` checks the same at the tag commit):
    # a module path that no longer matches the directory would publish a version nobody can `go get`.
    go_mod = (ROOT / _go_module_tag.MODULE_DIR / "go.mod").read_text(encoding="utf-8")
    if _go_module_tag.module_path(go_mod) != _go_module_tag.MODULE_PATH:
        error.append(f"{_go_module_tag.MODULE_DIR}/go.mod does not name module {_go_module_tag.MODULE_PATH}")

    text = CHANGELOG.read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\] — \d{{4}}-\d{{2}}-\d{{2}}", text, re.M):
        error.append(f"CHANGELOG has no closed section [{version}] — <date>")

    for f in error:
        print(f"  ✗ {f}")
    if not error:
        print(f"  ✓ everything on {version}: package, module, both READMEs, both compose files, Go client README, CHANGELOG, "
              "Go module path")
    return len(error)


def replace_pins(text: str, old: str, new: str) -> tuple[str, int]:
    """Replace the version only where it is a **pin** — not in narrative text.

    Up to 0.20.0 the script replaced every occurrence of the string `old` in the READMEs. That
    turned "0.19.0 upgraded the database to schema 8" into a false "0.20.0 upgraded …" and
    "up to 0.19.0 you ended up in the same account" into a statement about the new version. A pin
    is recognised by what precedes it: `@v`, `:v`, `/v` (git ref, image tag, release path),
    `tinysesam-` (wheel and sdist), `==` (PyPI), and in `pyproject.toml`/`__init__.py` by the assignment.

    What follows the version decides too: no digit and no dot (`v0.19.01` stays whole), except the `.tar.gz` of the
    sdist — up to 0.26.0 the dot after the version kept `tinysesam-X.Y.Z.tar.gz` from being replaced."""
    pattern = re.compile(r'(?:(?<=@v)|(?<=:v)|(?<=/v)|(?<=tinysesam-)|(?<===)|(?<=version = ")'
                        r'|(?<=__version__ = "))' + re.escape(old) + r"(?!\d)(?!\.(?!tar\.gz\b))")
    return pattern.subn(new, text)


#: How the docs name a feature that is merged but not yet released: "from the release after X". Once that release
#: exists it is "since <new>". A plain "since X" is history and never changes.
#: Per language of the READMEs (`README.md`, `i18n/README.de.md`).
FORWARD = {"en": ("from the release after ", "since "), "de": ("ab dem Release nach ", "seit ")}


def replace_forward(text: str, old: str, new: str) -> tuple[str, int]:
    """Turn "from the release after <old>" (and the German "ab dem Release nach <old>") into "since <new>"."""
    total = 0
    for before, after in FORWARD.values():
        text, count = re.subn(re.escape(before) + re.escape(old) + r"(?!\d)(?!\.\d)", after + new, text)
        total += count
    return text, total


def close_changelog(text: str, new: str, today: str) -> str | None:
    """`## [Unreleased]` becomes `## [new] — today`, and a fresh, empty `## [Unreleased]` stays above it.

    Up to 0.27.1 the heading was only renamed. Then no open section existed until someone wrote one, and the next
    entry went into the top section — the one just released (0.27.1: the entry of #317 landed in the published section
    and #313 had to move it). `None` when there is no open section."""
    opened = "## [Unreleased]"
    if opened not in text:
        return None
    return text.replace(opened, f"{opened}\n\n## [{new}] — {today}", 1)


def set_value(new: str) -> int:
    old = current_version()
    if old == new:
        print(f"  Version is already {new} — nothing to do.")
        return 0
    print(f"  {old} → {new}")

    for name in FILES:
        p = ROOT / name
        text, count = replace_pins(p.read_text(encoding="utf-8"), old, new)
        text, forward = replace_forward(text, old, new)
        count += forward
        if count:
            p.write_text(text, encoding="utf-8")
            print(f"    {name}: {count} occurrence(s)")

    text = CHANGELOG.read_text(encoding="utf-8")
    today = dt.date.today().isoformat()
    # The CHANGELOG is English (since T-29; before, German with "[Unveröffentlicht]") and names the open section
    # "[Unreleased]".
    closed = close_changelog(text, new, today)
    if closed is not None:
        CHANGELOG.write_text(closed, encoding="utf-8")
        print(f"    CHANGELOG: [Unreleased] → [{new}] — {today}, empty [Unreleased] above it")
    else:
        print("    CHANGELOG: no [Unreleased] section found — please check by hand")

    print("\n  What is still missing (and a human should decide):")
    print("    1. Summarise at the top of the CHANGELOG section WHO needs this release.")
    print("       For a breaking change, the warning belongs in the first line.")
    print("    2. Run the suite, open the release PR against main, merge it.")
    print(f"    3. Set the tag: git tag -a v{new} -m \"…\" && git push origin v{new}")
    print(f"       Only this one: release.yml sets the Go module tag {_go_module_tag.TAG_PREFIX}v{new} on the same")
    print("       commit by itself, last, once everything else is green (jobs go-module-*). Do not tag it by hand.")
    print("    4. Then check the artifacts yourself — not the traffic light:")
    print("       gh release view · manifest (both architectures, no latest) ·")
    print(f"       gh attestation verify · go list -m {_go_module_tag.MODULE_PATH}@v{new}")
    return 0


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--check":
        return 1 if check() else 0
    if not SEMVER.match(argv[0]):
        print(f"  '{argv[0]}' is not a version of the form X.Y.Z")
        return 2
    return set_value(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
