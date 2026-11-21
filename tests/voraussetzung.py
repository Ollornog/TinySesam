"""A suite says itself when a prerequisite is missing.

Deliberately lives NEXT TO `_kit/` and not inside it: `_kit/` is the shared test base from repokit
and is overwritten by `repokit sync` — a file of our own there would be gone at the next sync.

Why the runner does not decide this: it would only see an ImportError on stderr and could not tell
two completely different cases apart — "this TEST lacks an extra" (skipping is right) and "the
LIBRARY crashes without an extra" (that is a bug). This is exactly why it stayed invisible for
months that `pip install tinysesam` with the default configuration does not start at all.

Usage, at the very top of the suite:

    from voraussetzung import braucht_modul, braucht
    braucht_modul("onelogin", extra="saml")
    braucht(shutil.which("chrome"), "kein Chrome gefunden")

Both end the process with exit 77; `run_all.py` counts that as "skipped" and names the reason.
If the prerequisite is there, nothing happens.
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

SKIP_EXIT = 77


def braucht(bedingung, grund):
    """Bail out if `bedingung` is false — with a reason the runner displays."""
    if not bedingung:
        print(f"uebersprungen: {grund}")
        sys.exit(SKIP_EXIT)


def braucht_modul(name, extra=None):
    """Bail out if a module is not installed.

    Checks via `find_spec` instead of a real import: an import could fail itself (missing system
    library, broken installation), and THAT would be a bug, not a reason to skip. All that
    matters here is "is it there".
    """
    try:
        da = importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        da = False
    hinweis = f"Modul '{name}' fehlt"
    if extra:
        hinweis += f" — pip install 'tinysesam[{extra}]'"
    braucht(da, hinweis)


def pflicht_werkzeug(name, zweck):
    """The path of a tool without which PART of a suite checks nothing — or goes red.

    Unlike `braucht()`: the suite keeps running, only this part depends on the tool. Until
    2026-09-24 such places had `if shutil.which("node"):` — if node was missing, the probe was
    silently dropped and the suite reported green. That is exactly how `ci-local` (image without
    node) checked less than the gate on GitHub (`ubuntu-latest` ships node), and nobody noticed: a
    mutation in the panel JS stayed green locally. If the tool is missing, that is now an error.

    Whoever deliberately works without it sets `TINYSESAM_OHNE_<NAME>=1` (e.g.
    `TINYSESAM_OHNE_NODE=1`): then the suite keeps running, and the line states explicitly that
    this part did NOT check. CI never sets it.
    """
    pfad = shutil.which(name)
    if pfad:
        return pfad
    schalter = f"TINYSESAM_OHNE_{name.upper()}"
    if os.environ.get(schalter) == "1":
        print(f"  ⚠ {zweck}: `{name}` is missing, allowed via {schalter}=1 — this part did NOT check")
        return None
    raise AssertionError(f"`{name}` fehlt — ohne es prüft „{zweck}“ nichts und wäre stumm grün. "
                         f"Installieren, oder bewusst {schalter}=1 setzen (dann steht es als ungeprüft da).")


def find_chrome():
    """The Chrome the browser suites run, or None if there is none.

    `CHROME` (a path or a name on PATH) wins. CI sets it to the Chrome that `setup-chrome` just unpacked
    (`steps.<id>.outputs.chrome-path`): by name lookup the runner image's preinstalled `google-chrome` came first, whose
    ~400 MB nobody had read yet on that machine; Chrome then faulted its binary in page by page from the cold image
    disk and wrote no DevTools port within 30 s (B-13, main process in state D, `wchan=folio_wait_bit_common`). A wrong
    `CHROME` stops the suite instead of falling back silently to that cold Chrome."""
    env = os.environ.get("CHROME", "").strip()
    if env:
        found = shutil.which(env)
        if not found:
            raise SystemExit(f"CHROME={env!r} is not an executable")
        return found
    # `setup-chrome` installs the binary as `chrome`, Debian as `chromium`.
    return next((found for name in ("google-chrome", "chrome", "chromium", "chromium-browser")
                 if (found := shutil.which(name))), None)


def chrome_files(chrome):
    """The files a Chrome start reads first: the real binary, its siblings (paks, ICU data, V8 snapshot, bundled
    libraries; not the subdirectories) and the shared libraries it links.

    Siblings only for the `chrome` layout of Google Chrome and Chrome for Testing: a distribution `chromium` is often a
    shell wrapper in /usr/bin, and its directory is not Chrome's."""
    real = Path(chrome).resolve()
    binary = real.parent / "chrome" if (real.parent / "chrome").is_file() else real
    files = [binary]                        # first: callers name it
    if binary.name == "chrome":
        files += sorted(p for p in binary.parent.iterdir() if p.is_file() and p != binary)
    try:
        out = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        out = ""
    libs = {Path(m).resolve() for m in re.findall(r"=> (/\S+)", out)}
    return files + sorted(p for p in libs if p.is_file() and p not in files)


def prewarm_chrome(chrome):
    """Read Chrome's files once, untimed, before the timed start. Returns (binary, files, bytes, seconds).

    On a fresh CI runner the first reads of Chrome's ~400 MB from the image disk are slow. Reading them here, outside the
    start timeout, shows the disk's own time instead of hiding it in the 30 s that stay the measure for a hung Chrome."""
    files = chrome_files(chrome)
    start = time.monotonic()
    count = total = 0
    buf = bytearray(1 << 20)
    for path in files:
        try:
            with path.open("rb", buffering=0) as fh:
                while n := fh.readinto(buf):
                    total += n
            count += 1
        except OSError:
            pass
    return files[0], count, total, time.monotonic() - start
