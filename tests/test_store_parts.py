"""The core in parts (T-112): `Store` keeps its core in `store.py`; every other method lives in a part
`tinysesam/_store_<part>.py`, loaded on its first use through the index `store._PART_METHODS`.

Pinned here:

  (a) the index and the parts agree: every function of a part is indexed under that part, every indexed name exists
      there, no name is both in the core class and in a part, and no part is missing from the index
  (b) a part loads only when one of its methods is used — importing the store and creating a database load no
      OAuth, approval or app-password queries — and a method reached through a store or through the class is the same
      function, bound like a method of the class (static methods stay static)
  (d) the same for TinySesam's building blocks `_manager_<part>.py` (index `manager._PART_METHODS`), and `dir()` lists
      every method
  (e) a feature that is off loads nothing: with every feature of the registry `tinysesam/_features.py` off, none of
      its building blocks is imported and none of its routes exists after start and a first request; switched on, a
      feature loads its blocks and registers its routes (counter-probe)
  (f) size: no module in `tinysesam/` has 2,000 lines or more, `manager.py` and `store.py` stay below 1,500 (M-1)

    python tests/run_all.py test_store_parts.py
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tinysesam import store as S  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Store parts (T-112)")
PKG = ROOT / "tinysesam"

# ---------------------------------------------------------------- (a) index and parts agree
parts = {p.stem[len("_store_"):]: p for p in sorted(PKG.glob("_store_*.py")) if p.stem != "_store_schema"}
defined, mismatch = {}, []
for part, path in parts.items():
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined[node.name] = part
store_class = next(c for c in ast.walk(ast.parse((PKG / "store.py").read_text(encoding="utf-8")))
                   if isinstance(c, ast.ClassDef) and c.name == "Store")
core = {f.name for f in store_class.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))}
for name, part in defined.items():
    if S._PARTS.get(name) != part:
        mismatch.append(f"{name}: defined in _store_{part}.py, indexed under {S._PARTS.get(name)!r}")
for name, part in S._PARTS.items():
    if defined.get(name) != part:
        mismatch.append(f"{name}: indexed under {part!r}, not defined there")
r.check("(a) every function of a part is indexed under its part, every indexed name exists there",
        not mismatch and len(defined) >= 250, "; ".join(mismatch[:6]) or f"only {len(defined)} functions")
r.check("(a) no method is both in the core class and in a part", not core & set(defined), sorted(core & set(defined)))
r.check("(a) every part file has an index entry and every index entry a file",
        set(S._PART_METHODS) == set(parts), sorted(set(S._PART_METHODS) ^ set(parts)))

# ---------------------------------------------------------------- (b) loaded on first use
probe = r"""
import os, sys, tempfile
from tinysesam.store import Store
loaded = lambda: sorted(m.split("._store_")[1] for m in sys.modules if m.startswith("tinysesam._store_"))
at_import = loaded()
st = Store(os.path.join(tempfile.mkdtemp(), "p.db"))
at_open = loaded()
st.oauth_services()
print(at_import, at_open, loaded(), sep="|")
"""
out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=120, cwd=str(ROOT),
                     env={**os.environ, "PYTHONPATH": str(ROOT)})
at_import, at_open, after = (eval(x) for x in out.stdout.strip().split("|")) if out.returncode == 0 else ([], [], [])
r.check("(b) importing the store loads no part but the schema; opening a database loads no OAuth, approval or API-key "
        "part; the first OAuth query loads exactly that part",
        out.returncode == 0 and at_import == ["schema"] and not {"oauth", "approvals", "apikeys"} & set(at_open)
        and "oauth" in after and set(after) - set(at_open) == {"oauth"},
        (out.stdout + out.stderr)[-400:])
st = S.Store(os.path.join(tempfile.mkdtemp(), "b.db"))
bound = st.list_api_keys
r.check("(b) a part method on a store is bound like a class method; through the class it is the plain function; a "
        "static method stays static",
        bound.__self__ is st and bound.__func__ is S.Store.list_api_keys
        and S.Store._token_digest(b"p" * 32, "apikey", "x") == st._token_digest(b"p" * 32, "apikey", "x"))
try:
    st.no_such_method
    unknown = False
except AttributeError:
    unknown = True
r.check("(b) an unknown name is still an AttributeError (hasattr stays honest)",
        unknown and not hasattr(S.Store, "no_such_method"))
st.close()

# ---------------------------------------------------------------- (d) TinySesam's building blocks agree with the index
from tinysesam import _features as F  # noqa: E402
from tinysesam import manager as M  # noqa: E402

blocks = {p.stem[len("_manager_"):]: p for p in sorted(PKG.glob("_manager_*.py"))}
block_defined, block_mismatch = {}, []
for part, path in blocks.items():
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            block_defined[node.name] = part
manager_class = next(c for c in ast.walk(ast.parse((PKG / "manager.py").read_text(encoding="utf-8")))
                     if isinstance(c, ast.ClassDef) and c.name == "TinySesam")
manager_core = {f.name for f in manager_class.body if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))}
for name, part in block_defined.items():
    if M._PARTS.get(name) != part:
        block_mismatch.append(f"{name}: defined in _manager_{part}.py, indexed under {M._PARTS.get(name)!r}")
for name, part in M._PARTS.items():
    if block_defined.get(name) != part:
        block_mismatch.append(f"{name}: indexed under {part!r}, not defined there")
r.check("(d) every function of a TinySesam building block is indexed under its block, every indexed name exists there; "
        "none is also in the class; every block has an index entry",
        not block_mismatch and len(block_defined) >= 300 and not manager_core & set(block_defined)
        and set(M._PART_METHODS) == set(blocks),
        "; ".join(block_mismatch[:6]) or sorted(manager_core & set(block_defined))[:6])
r.check("(d) introspection sees the whole class: every indexed method is in dir(TinySesam)",
        set(M._PARTS) <= set(dir(M.TinySesam)))

# ---------------------------------------------------------------- (e) a feature that is off loads nothing
# Each probe starts an application in a fresh interpreter, serves a first page and a sign-in attempt, then reports the
# package modules and heavy libraries that are loaded and every route path. With the default configuration every
# feature of the registry is off: none of its modules may be loaded, none of its routes may exist. The counter-probe
# switches a feature on and must find its building blocks and routes — a probe that cannot see a feature proves nothing.
# (Mutation probes: an unconditional `from . import _manager_qr` in router.py; the forward-auth routes registered
# without their switch → red.)
FEATURE_PROBE = r"""
import json, os, sys, tempfile
from tinysesam import TinySesam, TinySesamConfig
from fastapi import FastAPI
from fastapi.testclient import TestClient
over = json.loads(sys.argv[1])
cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "p.db"), lang="en", cookie_secure=False, **over)
auth = TinySesam(cfg)
app = FastAPI()
app.include_router(auth.router())
client = TestClient(app, base_url="https://auth.example.com")
client.get("/auth/login")
client.post("/auth/login", data={"username": "nobody", "password": "not the password"})

print(json.dumps({"modules": sorted(m for m in sys.modules if m.startswith("tinysesam.")
                                    or m.split(".")[0] in ("ldap3", "onelogin", "authlib", "webauthn", "qrcode", "PIL")),
                  # as FastAPI itself lists them (the routers are included lazily in newer FastAPI versions)
                  "paths": sorted(app.openapi()["paths"])}))
"""
HEAVY = ("ldap3", "onelogin", "authlib", "webauthn", "qrcode", "PIL")


def feature_probe(**over):
    out = subprocess.run([sys.executable, "-c", FEATURE_PROBE, json.dumps(over)], capture_output=True, text=True,
                         timeout=180, cwd=str(ROOT), env={**os.environ, "PYTHONPATH": str(ROOT)})
    if out.returncode != 0:
        return None, out.stderr[-600:]
    data = json.loads(out.stdout.strip().splitlines()[-1])
    return data, ""


def leaks(data, feature):
    _, modules, prefixes = F.FEATURES[feature]
    loaded = {m.split(".", 1)[1] for m in data["modules"] if m.startswith("tinysesam.")}
    return ([m for m in modules if m in loaded], [p for p in data["paths"] for x in prefixes if p.startswith(x)])


base, error = feature_probe()
off_leaks = {} if base is None else {f: leaks(base, f) for f in F.FEATURES if any(leaks(base, f))}
heavy = [] if base is None else sorted({m.split(".")[0] for m in base["modules"]} & set(HEAVY))
r.check(f"(e) every feature of the registry off ({len(F.FEATURES)}): none of its building blocks loaded, none of its "
        "routes registered, after start, a page and a sign-in attempt; no heavy optional library loaded",
        base is not None and not off_leaks and not heavy,
        error or f"leaks: {off_leaks}, heavy: {heavy}")
ON = {"forward_auth": dict(forward_auth_enabled=True, base_url="https://auth.example.com",
                           trusted_redirect_hosts=["app.example.com"]),
      "qr_login": dict(qr_login_enabled=True, base_url="https://auth.example.com"),
      "resource_locks": dict(resource_locks_enabled=True),
      "magic_links": dict(magiclink_enabled=True, magiclink_self_request=False, base_url="https://auth.example.com")}
seen = {}
for feature, over in ON.items():
    data, error = feature_probe(**over)
    if data is None:
        seen[feature] = f"did not start: {error}"
        continue
    modules, paths = leaks(data, feature)
    expected = [m for m in F.FEATURES[feature][1] if m.startswith(F.PRELOAD_PREFIXES)]
    if sorted(modules) != sorted(expected) or (F.FEATURES[feature][2] and not paths):
        seen[feature] = f"modules {modules} (expected {expected}), routes {paths[:3]}"
r.check(f"(e) counter-probe: switched on, {', '.join(ON)} load their building blocks and register their routes",
        not seen, str(seen))
r.check("(e) the registry names real switches and real modules",
        all(hasattr(M.TinySesamConfig, switch) or switch in M.TinySesamConfig.__dataclass_fields__
            for switch, _, _ in F.FEATURES.values())
        and all((PKG / f"{m}.py").exists() for _, mods, _ in F.FEATURES.values() for m in mods))

# ---------------------------------------------------------------- (f) size of every module (the M-1 limits)
all_sizes = {str(p.relative_to(PKG)): len(p.read_text(encoding="utf-8").splitlines()) for p in sorted(PKG.rglob("*.py"))}
too_big = {k: v for k, v in all_sizes.items() if v >= 2000}
r.check("(f) no module in tinysesam/ has 2,000 lines or more; manager.py and store.py stay below 1,500",
        not too_big and all_sizes["manager.py"] < 1500 and all_sizes["store.py"] < 1500 and len(all_sizes) >= 60,
        f"too big: {too_big}, manager.py {all_sizes['manager.py']}, store.py {all_sizes['store.py']}")

sys.exit(r.done())
