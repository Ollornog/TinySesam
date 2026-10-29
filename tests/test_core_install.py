"""What `pip install tinysesam` must be able to do WITHOUT extras.

Why this suite exists: until 2026-09-21 `passkey_enabled` defaulted to `True`, although
`webauthn` is not in the core but in the extra `[passkey]`. That crashed the very first step
of every new user — `TinySesam(TinySesamConfig(db_path=…)).router()` ended with
`ModuleNotFoundError: webauthn`. Nobody saw it because `run_all.py` booked real failures as
"skipped".

The checks here deliberately run WITHOUT importing the extras: they measure the defaults,
not the environment. So they also trigger in the full run in which all extras are installed —
exactly where the error would otherwise stay invisible.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tinysesam import TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Core install — what must work without extras")

# Which switch needs which extra — from the CODE, not as a copy. A table here
# would silently go stale with the next new method and the test would be green without checking it.
from tinysesam.manager import SWITCH_REQUIRES_EXTRA  # noqa: E402

r.check("the switch→extra table is not empty", bool(SWITCH_REQUIRES_EXTRA),
        "empty — then the loop below checks nothing")

# Every switch must also exist: a typo in the table would otherwise never match and
# nobody would notice.
default = TinySesamConfig(db_path=":memory:")
unknown = [k for k in SWITCH_REQUIRES_EXTRA if not hasattr(default, k)]
r.check("every switch from the table exists in the config", not unknown, f"{unknown}")

# And every named extra must be in the pyproject.
_raw_beforehand = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
missing_extras = [e for _, e in SWITCH_REQUIRES_EXTRA.values()
                   if f"\n{e} = [" not in _raw_beforehand]
r.check("every named extra exists in the pyproject", not missing_extras, f"{missing_extras}")

for switch, (module, extra) in sorted(SWITCH_REQUIRES_EXTRA.items()):
    an = bool(getattr(default, switch, False))
    r.check(f"{switch} is OFF by default (needs {module} from [{extra}])", not an,
            f"is set to True — `pip install tinysesam` without [{extra}] crashes at router build")

# The core dependencies are what `pip install tinysesam` really brings along.
# What is on by default may only draw from them.
# `pyproject.toml` is read — the file from which the package is built.
#
# For a while this went through `importlib.metadata.requires()`, with the argument "measures closer to
# the subject: what is really there after `pip install tinysesam`". That was true and still
# wrong: the metadata of a `pip install -e .` installation is written ONCE. In the
# CI image there is such an installation, the working state is mounted next to it — so the test
# measured the state of the day before yesterday and reported an extra as missing that has been
# in the pyproject for an hour. For the question "what does the package promise" the source file is right.
#
# (Read by hand instead of parsed with `tomllib`: that was necessary while 3.10 was promised
# — there `tomllib` does not exist yet. Since the lower bound 3.12 (2026-09-22) it would be
# possible; but for two lists the rework is not worth it, and without a parser the test
# also stays runnable in a clone that someone opens with an older interpreter.)
import re as _re  # noqa: E402

_raw = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _items(name: str, source: str = "") -> list:
    """The content of a `name = [...]` assignment as a list of strings."""
    hit = _re.search(rf"^{_re.escape(name)}\s*=\s*\[(.*?)\]", source or _raw, _re.S | _re.M)
    return _re.findall(r'"([^"]+)"', hit.group(1)) if hit else []


requests = _items("dependencies")
r.check("the core dependencies are readable at all", bool(requests),
        "pyproject.toml yielded no `dependencies` list — then the rest checks nothing")

_extras_block = _raw[_raw.index("[project.optional-dependencies]"):]
_extras_block = _extras_block[:_extras_block.index("\n[", 1)]

# `dependencies` is by definition the core — extras are in a section of their own.
core = {_d.split(";")[0].split(">")[0].split("=")[0].split("[")[0].strip().lower()
        for _d in requests}
r.check("fastapi belongs to the core", "fastapi" in core)
r.check("webauthn does NOT belong to the core (otherwise the switch above would be harmless)",
        "webauthn" not in core)

# An enabled switch without its extra must give a READABLE message, not a
# ModuleNotFoundError from inside the library.
# The BEHAVIOUR is measured, not whether two words appear in the source file. The earlier
# version checked `"tinysesam[passkey]" in router_py` — whoever removed the protection and left the words
# as a comment got away with it, while the real call raised a bare
# ModuleNotFoundError raises.
import importlib  # noqa: E402


class _Blocked:
    def __init__(self, name):
        self.name = name

    def find_spec(self, fullname, path=None, destination=None):
        if fullname == self.name or fullname.startswith(self.name + "."):
            raise ModuleNotFoundError(f"No module named '{fullname}'", name=fullname)
        return None


def _without(name, fn):
    blocker = _Blocked(name)
    sys.meta_path.insert(0, blocker)
    away = {n: m for n, m in list(sys.modules.items()) if n == name or n.startswith(name + ".")}
    for n in away:
        del sys.modules[n]
    try:
        return fn()
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(away)
        importlib.invalidate_caches()


import tempfile  # noqa: E402

from tinysesam import MissingExtra, TinySesam  # noqa: E402


def _with_passkey():
    # The router build is the place where the passkey routes come into being — the
    # missing extra shows up there. The constructor only warns (a client could be replaced).
    path = str(Path(tempfile.mkdtemp()) / "t.db")
    auth = TinySesam(TinySesamConfig(db_path=path, cookie_secure=False, passkey_enabled=True))
    return auth.router()


try:
    _without("webauthn", _with_passkey)
    error = None
except Exception as e:
    error = e
r.check("passkey without the extra reports itself understandably instead of with ModuleNotFoundError",
        isinstance(error, MissingExtra),
        f"{type(error).__name__}: {str(error)[:70]}")
r.check("...and names the extra machine-readably", getattr(error, "extra", None) == "passkey",
        f"extra={getattr(error, 'extra', None)!r}")

# And the runner must no longer guess "skipped".
runner = (ROOT / "tests" / "run_all.py").read_text(encoding="utf-8")
r.check("run_all counts only the agreed exit code as skipped",
        "SKIP_EXIT = 77" in runner and "r.returncode == SKIP_EXIT" in runner)
r.check("run_all no longer guesses at stderr",
        'ModuleNotFoundError" in r.stderr' not in runner,
        "the old heuristic is back — it cannot tell 'test needs extra' from "
        "'library crashes'")


# ── The gateway did not start following its own instructions ──────────────────
# The README named `pip install 'tinysesam[oidc]'` and `python -m tinysesam.gateway` in one
# breath. But `[oidc]` brings no ASGI server: the start command ended in a
# ModuleNotFoundError for uvicorn, which looked like a defect instead of a missing line in the
# install command. The Docker image ran because it installed `uvicorn` by hand on the side — the
# patch hid the gap in the extra.
gateway_extra = _items("gateway", _extras_block)
r.check("there is an extra [gateway]", bool(gateway_extra),
        "only [oidc] — then the documented line does not start")
r.check("and it contains an ASGI server",
        any("uvicorn" in d for d in gateway_extra), f"{gateway_extra}")

# The instructions must point to this extra, no longer to [oidc]. What is searched is the
# gateway section itself (the heading with "gateway"/"Gateway"), not a wording —
# the German and the English text are built differently.
import re as _re2  # noqa: E402

for file in ("README.md", "i18n/README.de.md"):
    text = (ROOT / file).read_text(encoding="utf-8")
    sections = _re2.split(r"^## ", text, flags=_re2.M)
    matching = [a for a in sections if _re2.search(r"[Gg]ateway", a.splitlines()[0] if a else "")]
    r.check(f"{file} has a gateway section", bool(matching),
            "not found — then the test below checks nothing")
    together = "\n".join(matching)
    r.check(f"{file} names the extra [gateway] for the gateway",
            "tinysesam[gateway]" in together, "still refers to [oidc]")
    r.check(f"{file} no longer names [oidc] there as the installation path",
            "pip install 'tinysesam[oidc]'" not in together,
            "the old, non-startable line is still there")

# `--help` is a question, not a start command: before, the server ran on 0.0.0.0:8000.
import subprocess  # noqa: E402

execution = subprocess.run([sys.executable, "-m", "tinysesam.gateway", "--help"],
                      cwd=ROOT, capture_output=True, text=True, timeout=30)
r.check("`python -m tinysesam.gateway --help` exits with 0", execution.returncode == 0,
        f"Exit {execution.returncode}: {(execution.stderr or execution.stdout)[:100]}")
r.check("...and prints help instead of starting a server",
        "TINYSESAM_OIDC_ISSUER" in execution.stdout and "0.0.0.0" not in execution.stdout.split("bind address")[0],
        f"Output: {execution.stdout[:120]!r}")

fail = subprocess.run([sys.executable, "-m", "tinysesam.gateway", "--nonsense"],
                      cwd=ROOT, capture_output=True, text=True, timeout=30)
r.check("an unknown argument ends with 2, not with a running server",
        fail.returncode == 2, f"Exit {fail.returncode}")

sys.exit(r.done())
