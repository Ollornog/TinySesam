"""The store in parts (T-112): `Store` keeps its core in `store.py`; every other method lives in a part
`tinysesam/_store_<part>.py`, loaded on its first use through the index `store._PART_METHODS`.

Pinned here:

  (a) the index and the parts agree: every function of a part is indexed under that part, every indexed name exists
      there, no name is both in the core class and in a part, and no part is missing from the index
  (b) a part loads only when one of its methods is used — importing the store and creating a database load no
      OAuth, approval or app-password queries — and a method reached through a store or through the class is the same
      function, bound like a method of the class (static methods stay static)
  (c) size: `store.py` stays below 1,500 lines, a part below 2,000 (the M-5 limits)

    python tests/run_all.py test_store_parts.py
"""
import ast
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

# ---------------------------------------------------------------- (c) size
sizes = {p.name: len(p.read_text(encoding="utf-8").splitlines()) for p in [PKG / "store.py", *parts.values()]}
r.check("(c) store.py below 1,500 lines, every part below 2,000",
        sizes["store.py"] < 1500 and all(n < 2000 for n in sizes.values()), sizes)

sys.exit(r.done())
