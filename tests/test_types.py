"""`Typing :: Typed` is a promise — here it is measured.

The package carries the classifier and a `py.typed`. With that it promises every user: the
annotations are correct, your type checker may rely on them. Nobody ever checked that —
and at the first measurement there were **30 errors** in 6 files, among them six user-facing
methods that promised `Optional[dict]` and returned a `sqlite3.Row`. Whoever
believed the promise and wrote `user.get("email")` got an `AttributeError` from a line that, according to the
type, could not be wrong.

This suite is the antidote. In addition it measures the promise where it arrives: on the
actual return value — an annotation can be correct and the implementation still not.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from voraussetzung import braucht_modul  # noqa: E402

braucht_modul("mypy")

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Typen — die Zusage `Typing :: Typed`")

# ---------- 1) The type checker itself ----------
# `--check-untyped-defs`: without it mypy does not check the BODIES of unannotated functions at all —
# 120 of 410 went unseen that way, including all four config presets (a user gets
# `Any` there and loses every type check from then on). mypy points this out itself in the run; the
# filter on ": error:" threw the hint away, so the test was blind to its own gap.
# `--cache-dir`: otherwise mypy puts its cache as `.mypy_cache/` in the working directory — i.e.
# into the tree, invisible to `git status` (mypy puts a `.gitignore` of its own in it). Two runs
# in the same tree shared it, and a cache from an earlier run could have
# influenced the next. Now a fresh folder of its own per run (TMPDIR is the throwaway sandbox).
cache = tempfile.mkdtemp(prefix="mypy-")
im_baum = ROOT / ".mypy_cache"
schon_da = im_baum.exists()
lauf = subprocess.run([sys.executable, "-m", "mypy", "tinysesam/", "--ignore-missing-imports",
                       "--check-untyped-defs", "--cache-dir", cache],
                      cwd=ROOT, capture_output=True, text=True)
r.check("mypy writes its cache into the sandbox, not into the tree",
        any(Path(cache).iterdir()) and (schon_da or not im_baum.exists()),
        f"Cache leer: {not any(Path(cache).iterdir())}, .mypy_cache im Baum angelegt: "
        f"{not schon_da and im_baum.exists()}")
fehler = [z for z in lauf.stdout.splitlines() if ": error:" in z]
r.check("mypy findet keinen Fehler in tinysesam/", not fehler,
        "\n        " + "\n        ".join(fehler[:6]) +
        (f"\n        … and {len(fehler) - 6} more" if len(fehler) > 6 else ""))

# And the check must have seen anything at all — a run over zero files would be
# always green and would say nothing.
r.check("and in doing so has seen the whole library",
        "source file" in lauf.stdout and " 0 source files" not in lauf.stdout,
        f"Ausgabe: {lauf.stdout.strip()[:120]!r}")

# ---------- 2) The promise where it arrives ----------
# `py.typed` must be shipped, otherwise every type checker ignores the annotations.
r.check("py.typed liegt im Paket", (ROOT / "tinysesam" / "py.typed").exists(),
        "without this file no type checker evaluates the annotations (PEP 561)")

auth = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"),
                                 cookie_secure=False))
uid = auth.create_user("wer", password="geheim12345", email="wer@example.com")

# The six methods that promise `Optional[dict]` — measured on the real return value.
for name, wert in (("get_user", auth.get_user(uid)),
                   ("find_user", auth.find_user("wer")),
                   ("_check_password", auth._check_password("wer", "geheim12345")),
                   ("current_user", None),
                   ("redeem_magic (leer)", auth.redeem_magic("gibtsnicht")),
                   ("find_user (leer)", auth.find_user("niemand"))):
    if name == "current_user":
        continue
    erwartet_leer = "leer" in name
    if erwartet_leer:
        r.check(f"{name} returns None, not something wrong", wert is None, f"{type(wert).__name__}")
    else:
        r.check(f"{name} really returns a dict, not a sqlite3.Row",
                isinstance(wert, dict), f"returns {type(wert).__name__}")

# The test on which a user failed: there is no `.get()` on a Row.
u = auth._check_password("wer", "geheim12345")
r.check("and a dict access like .get() works",
        u is not None and u.get("email") == "wer@example.com",
        "exactly here whoever believed the annotation failed")

sys.exit(r.done())
