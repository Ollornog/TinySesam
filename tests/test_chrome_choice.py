"""Which Chrome the browser suites run, and that it is read before the timed start (B-13).

Cause of the rare "Chrome wrote no DevTools port (after 30s)": the suites found the runner image's preinstalled
`google-chrome` before the Chrome that `setup-chrome` had just unpacked, and its ~400 MB were still cold on the image
disk of a fresh runner. Two guards, each proven by a mutation:

  (a) `CHROME` wins over the name lookup, and a wrong path stops the suite instead of falling back silently
  (b) the untimed read covers the binary the start executes, not only a wrapper script in front of it

Mutations: `find_chrome` without the `CHROME` branch -> (a) red; `chrome_files` returning the wrapper only -> (b) red.
"""
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from voraussetzung import find_chrome, prewarm_chrome  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


saved = os.environ.get("CHROME")
tmp = Path(tempfile.mkdtemp(prefix="chrome-choice-"))
try:
    # (a) CHROME goes first, whatever else is on PATH
    os.environ["CHROME"] = sys.executable
    assert find_chrome() == shutil.which(sys.executable), find_chrome()
    ok("CHROME is taken before the name lookup")
    os.environ["CHROME"] = str(tmp / "no-such-chrome")
    try:
        find_chrome()
    except SystemExit as exc:
        assert "no-such-chrome" in str(exc), exc
        ok("a wrong CHROME stops the suite, no silent fallback")
    else:
        raise AssertionError("a wrong CHROME path did not stop the suite")
    os.environ.pop("CHROME")

    # (b) the layout of Google Chrome: a 1 KB wrapper script next to the real `chrome` binary and its data files
    wrapper, binary, data = tmp / "google-chrome", tmp / "chrome", tmp / "icudtl.dat"
    wrapper.write_text("#!/bin/sh\nexec \"$(dirname \"$0\")/chrome\" \"$@\"\n")
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    binary.write_bytes(os.urandom(3 << 20))
    data.write_bytes(os.urandom(1 << 20))
    link = tmp / "bin"
    link.mkdir()
    (link / "google-chrome").symlink_to(wrapper)           # reached through a symlink, like /usr/bin/google-chrome
    got, count, total, _ = prewarm_chrome(str(link / "google-chrome"))
    assert got == binary, f"read starts at {got}, the start executes {binary}"
    assert total >= binary.stat().st_size + data.stat().st_size, f"only {total} bytes read"
    ok("the read covers the executed binary and its siblings, not only the wrapper")
finally:
    if saved is None:
        os.environ.pop("CHROME", None)
    else:
        os.environ["CHROME"] = saved
    shutil.rmtree(tmp, ignore_errors=True)
print("OK")
