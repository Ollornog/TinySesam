#!/usr/bin/env python3
"""release — do the manual steps before a release and check them. stdlib-only.

    python3 scripts/_release.py 0.17.0          set the version, close the CHANGELOG
    python3 scripts/_release.py --check       check only, change nothing
    python3 scripts/_release.py --automation 0.17.1   as the first, but refuses when [Unreleased] holds more than a
                                              patch release may carry (the release automation calls it this way)

The version appears in seven places (package, module, two READMEs several times, two compose files) and
in the CHANGELOG. By hand this has worked so far because a test enforces it — but "works because
a test complains" is not a procedure, it is a loop of error and correction. Milestone 1.0
explicitly requires that a release runs through without manual steps
(`backlog/M-1-api-stable-1-0.md`).

What this script deliberately does NOT do: tag and push. A human presses the button — the same
separation as for rollout (delivery, not deployment). It prepares and says what follows.
"""
from __future__ import annotations

import datetime as dt
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Everywhere a version appears. The READMEs name it several times (git ref, wheel URL, image tag,
# verification commands) — so we replace, rather than patch a fixed line number.
FILES = ["pyproject.toml", "tinysesam/__init__.py", "README.md", "i18n/README.de.md",
           "deploy/forward-auth/docker-compose.yml", "deploy/quickstart/docker-compose.yml"]
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
        old = {v for v in re.findall(r"tinysesam(?:-caddy-gate)?[:@/-]v?(\d+\.\d+\.\d+)", text)} - {version}
        if old:
            error.append(f"{name} still refers to {', '.join(sorted(old))}")

    text = CHANGELOG.read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(version)}\] — \d{{4}}-\d{{2}}-\d{{2}}", text, re.M):
        error.append(f"CHANGELOG has no closed section [{version}] — <date>")

    for f in error:
        print(f"  ✗ {f}")
    if not error:
        print(f"  ✓ everything on {version}: package, module, both READMEs, both compose files, CHANGELOG")
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


#: What a patch release may carry, the way the CHANGELOG names it (`### Fixed`, `### Security — …`, `### Dependencies`).
#: Anything else (Added, Changed, Removed, Deprecated, …) is a feature or a change: a minor release, and a human cuts it.
PATCH_CATEGORIES = frozenset({"fixed", "security", "dependencies"})


def unfit_for_patch(text: str) -> list[str]:
    """What in `[Unreleased]` keeps the release automation from cutting a patch release (empty list: it may).

    The automation (kit `_release_automatik.py`, after a Dependabot merge that changes the image) takes the whole open
    section with it. Cut as 0.27.1 it published new API (T-83, T-88) in a patch release. A category outside
    `PATCH_CATEGORIES` and text outside every category (it cannot be classified) both count; an empty or missing
    section is fine (then the release carries the Dependabot entries only)."""
    start = re.search(r"^## \[Unreleased\][ \t]*$", text, re.M)
    if not start:
        return []
    rest = text[start.end():]
    end = re.search(r"^## ", rest, re.M)
    section = rest[:end.start()] if end else rest
    found: list[str] = []
    parts = re.split(r"^### ", section, flags=re.M)
    if parts[0].strip():
        found.append("text outside a `###` category")
    for part in parts[1:]:
        heading = part.split("\n", 1)[0].strip()
        category = re.split(r"\s+[—–-]\s+|[:\s]", heading, maxsplit=1)[0].lower()
        if category not in PATCH_CATEGORIES:
            found.append(f"### {heading}")
    return found


def automation_check() -> int:
    """For the release automation: refuse (rc 1) when `[Unreleased]` holds more than a patch release may carry."""
    unfit = unfit_for_patch(CHANGELOG.read_text(encoding="utf-8"))
    if not unfit:
        return 0
    message = ("no automatic patch release: [Unreleased] holds entries for a minor release (" + "; ".join(unfit) +
               "). A human decides: run `scripts/_release.py <version>` and merge the release PR.")
    print(f"::error title=Release automation stopped::{message}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### Release automation stopped\n\n{message}\n\nNothing was changed, no release PR was opened.\n")
    print(f"  ✗ {message}", file=sys.stderr)
    return 1


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
    print("    4. Then check the artifacts yourself — not the traffic light:")
    print("       gh release view · manifest (both architectures, no latest) ·")
    print("       gh attestation verify")
    return 0


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--check":
        return 1 if check() else 0
    automated = argv[0] == "--automation"
    if automated:
        argv = argv[1:]
    if len(argv) != 1 or not SEMVER.match(argv[0]):
        print(f"  {' '.join(argv)!r} is not a version of the form X.Y.Z")
        return 2
    if automated and automation_check():
        return 1
    return set_value(argv[0])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
