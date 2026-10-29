"""Batch A: session invalidation on password change, auth.gc(), dummy-verify timing, py.typed."""
import os
import tempfile, os, time
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False))
auth.ensure_admin("admin", "geheim123-lang-genug")
uid = auth.store.get_user_by_name("admin")["id"]
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def secret_text(u=Depends(auth.require_user)):
    return {"u": u["username"]}


# ---------- Self-service password change ends OTHER sessions, keeps the current one ----------
c1 = TestClient(app)   # session A (changes the password)
c2 = TestClient(app)   # session B (is supposed to get kicked out)
for c in (c1, c2):
    c.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "next": "/"}, follow_redirects=False)
assert c1.get("/geheim").status_code == 200 and c2.get("/geheim").status_code == 200
c1.post("/auth/password", json={"current": "geheim123-lang-genug", "new": "neuespasswort-lang"})
assert c1.get("/geheim").status_code == 200, "own session stays"
assert c2.get("/geheim").status_code == 401, "other session ended"
ok("self-service password change: other sessions ended, current one stays")

# ---------- auth.gc() removes expired items + returns counters ----------
# create an expired session + an expired magic token + an old login attempt
auth.store.create_session(uid, -10, True, "password")               # expired immediately
auth.store._exec("INSERT INTO login_attempt(ts,username,ip,success,method) VALUES (?,?,?,?,?)",
                 (int(time.time()) - 999999, "x", "1.2.3.4", 0, "password"))
auth.store.add_magic_token("deadhash", "login", int(time.time()) - 10, user_id=uid)
res = auth.gc(attempts_older_than_sec=86400)
assert res["sessions"] >= 1 and res["login_attempts"] >= 1 and res["magic_tokens"] >= 1, res
ok(f"auth.gc() cleans up + counts: {res}")

# ---------- Dummy verify: unknown user ~ as slow as a real failed attempt ----------
from tinysesam import TinySesamConfig as _C  # noqa
def took(username):
    t = time.perf_counter()
    auth._check_password(username, "irgendwas")
    return time.perf_counter() - t
t_known = took("admin")          # exists, wrong password -> real hash verify
t_unknown = took("gibtsnicht")   # does not exist -> dummy verify
# both should do noticeable work; rough bound (no instant return for unknown)
assert t_unknown > t_known * 0.3, (t_known, t_unknown)
ok(f"dummy verify: unknown user not instant (known={t_known*1000:.1f}ms, unknown={t_unknown*1000:.1f}ms)")

# ---------- py.typed present ----------
import importlib.util as _ilu, os.path as osp
assert osp.exists(osp.join(osp.dirname(_ilu.find_spec("tinysesam").origin), "py.typed"))
ok("py.typed shipped")

# ---------- A failed write leaves no transaction open ----------
# Python's sqlite3 silently opens a BEGIN before every INSERT/UPDATE/DELETE. If the write failed
# (a foreign writer holds the lock longer than busy_timeout, volume full, read-only), that
# transaction stayed open on the shared connection. `reserve_attempt` starts with an explicit
# `BEGIN IMMEDIATE` and failed on it with "cannot start a transaction within a transaction" —
# every sign-in ended with 500 until some other write happened to commit the leftovers.
# The write probe of /healthz, reachable without sign-in, was enough as a trigger.
# (Mutation probe: in `Store._exec` replace `with self._writing():` by
# `with self._lock:` -> "_exec (audit_log)" red; the same in `write_probe` ->
# "schreibprobe" red, in `delete_user` -> "delete_user" red; in `reserve_attempt` remove the
# cleanup before `BEGIN IMMEDIATE` -> the sign-in attempt over a leftover transaction
# raises -> red.)
import sqlite3                                                                  # noqa: E402

db_s = os.path.join(tempfile.mkdtemp(), "t.db")
auth_s = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_s, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False))
uid_s = auth_s.create_user("sven", "Sven-Passwort-2026")
app_s = FastAPI()
app_s.include_router(auth_s.router())
auth_s.store.db.execute("PRAGMA busy_timeout=200")      # do not wait ten seconds per failure


def _write_probe():
    auth_s.store._written = None                    # otherwise a read access is enough for it
    auth_s.store.write_probe()


writer = {
    "schreibprobe": _write_probe,
    "_exec (audit_log)": lambda: auth_s.store.audit_log("probe", "sven", None, None),
    "record_attempt": lambda: auth_s.store.record_attempt("sven", "198.51.100.9", False, "password"),
    "add_recovery_codes": lambda: auth_s.store.add_recovery_codes(uid_s, ["a" * 64]),
    "consume_recovery_code": lambda: auth_s.store.consume_recovery_code(uid_s, "b" * 64),
    "use_magic_token": lambda: auth_s.store.use_magic_token("c" * 64),
    "delete_user": lambda: auth_s.store.delete_user(uid_s + 1000),
}
foreign = sqlite3.connect(db_s, isolation_level=None)
foreign.execute("BEGIN IMMEDIATE")
try:
    for name, write in writer.items():
        try:
            write()
        except sqlite3.OperationalError:
            pass
        else:
            raise AssertionError(f"{name}: precondition missed — the foreign writer does not lock")
        assert not auth_s.store.db.in_transaction, \
            f"{name} leaves a transaction open on the shared connection after the failure"
finally:
    foreign.execute("ROLLBACK")
    foreign.close()
auth_s.store.db.execute(f"PRAGMA busy_timeout={auth_s.store.BUSY_TIMEOUT_MS}")
codes = [TestClient(app_s, raise_server_exceptions=False).post(
    "/auth/login", data={"username": "sven", "password": "Sven-Passwort-2026"},
    follow_redirects=False).status_code for _ in range(3)]
assert codes == [303, 303, 303], f"sign-in after failed writes: {codes}"
ok(f"failed writes roll back ({len(writer)} paths), sign-in stays intact")

# Second lock: if a transaction is lying around anyway (a future writer without
# rollback), `reserve_attempt` clears it instead of letting every sign-in fail.
auth_s.store.db.execute("INSERT INTO setting(key, value) VALUES ('probe_liegengeblieben', '1')")
assert auth_s.store.db.in_transaction, "precondition: an open transaction is lying around"
attempt_s = auth_s._begin_attempt("sven", "198.51.100.9", "password")
assert attempt_s is not None, "the sign-in attempt was rejected"
assert not auth_s.store.db.in_transaction
assert auth_s.store.get_setting("probe_liegengeblieben") is None, \
    "the leftovers of a failed writer were committed along instead of discarded"
ok("reserve_attempt discards a leftover transaction instead of failing on it")
auth_s.store.db.close()
os.remove(db_s)

# Guard over the list above: it names today's write paths. A new writer with
# `with self._lock: ... self.db.commit()` would escape it. Hence via AST: every commit in the
# store sits in a `_writing()` block — or, in a function that runs its transaction
# itself, in the `try` of a block whose `except` catches every failure and rolls back, or
# whose `finally` rolls back. Until the fix, for the self-managed functions the guard only
# checked whether `rollback()` appeared ANYWHERE in them: `rotate_session` has one in the
# `rowcount != 1` branch, and without the rollback in the `except` the guard stayed green although
# a failed INSERT left the transaction open.
#
# "Catches every failure" means: `except` without a type, with `Exception` or with `BaseException`
# (also as `builtins.…`, also in a tuple) — the FULL name is compared. Until the final
# round any last component `Error`, `DatabaseError` or `OperationalError` counted:
# `except sqlite3.OperationalError:` in `reserve_attempt` stayed green, and a binding error after
# `BEGIN IMMEDIATE` (ProgrammingError) left the transaction open (final finding sperren-0).
# `sqlite3.Error` is not enough either: `OverflowError` (a number above 2**63 as a parameter) is
# not a sqlite3.Error and ends the same way. `_clock_record` therefore caught too narrowly until then.
# Limits the syntax tree does not see: whether the rollback in the handler is actually EXECUTED
# (an `if False:` in front of it), and a `builtins.Exception` that someone rebinds from outside
# at runtime. Rebinding IN store.py (`Exception = KeyError`, an import under that name) is caught
# by `_shadowed` below. (Mutation probes: in `delete_user` put `with self._lock:` back -> red, with
# function name; in `_catches_everything` accept any last component `Error`/`DatabaseError`/
# `OperationalError` again -> the self-test below turns red; in `_clock_record` `except sqlite3.Error:`
# again -> red, `_clock_record:<line>`; in store.py narrow `reserve_attempt` to
# `except sqlite3.OperationalError:` or `rotate_session` to `except sqlite3.DatabaseError:`
# -> red with function name; `_is_commit` again only `commit()`/`execute("COMMIT")`, without
# `END`, without `executemany` or case-sensitive -> red.)
import ast                                                                      # noqa: E402
import re                                                                       # noqa: E402
import copy                                                                     # noqa: E402
from pathlib import Path                                                        # noqa: E402

ITSELF_KEPT = {"__init__", "_migrate", "rotate_session", "reserve_attempt", "_clock_record"}
STORE_SOURCE = (Path(__file__).resolve().parent.parent / "tinysesam" / "store.py").read_text("utf-8")
_WIDE = {"Exception", "BaseException"}


#: SQL that closes a transaction — whatever the spelling (`END`, `COMMIT TRANSACTION`,
#: `commit;`; `RELEASE` does it for the outermost savepoint).
_COMMIT_SQL = re.compile(r"(?i)(?:^|;)\s*(?:commit|end|release)\b")


def _is_commit(k):
    """Does this call close a transaction? `commit()`, any `executescript()` (it commits an open
    transaction before running its script), `execute`/`executemany` with COMMIT/END/RELEASE.
    Limit: SQL that only arises at runtime (a variable) is not seen by the syntax tree."""
    if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)):
        return False
    if k.func.attr in ("commit", "executescript"):
        return True
    return (k.func.attr in ("execute", "executemany") and bool(k.args) and isinstance(k.args[0], ast.Constant)
            and isinstance(k.args[0].value, str) and bool(_COMMIT_SQL.search(k.args[0].value)))


def _rolls_back(node):
    """Does the block contain a rollback — `rollback()`, `execute("ROLLBACK")`, `_discard()`?"""
    for k in ast.walk(node):
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute):
            if k.func.attr in ("rollback", "_discard"):
                return True
            if (k.func.attr == "execute" and k.args and isinstance(k.args[0], ast.Constant)
                    and str(k.args[0].value).strip().upper() == "ROLLBACK"):
                return True
    return False


def _catches_everything(handler):
    """Does this `except` catch EVERY failure of a write — without a type, `Exception`,
    `BaseException` (also `builtins.…`, also in a tuple)? The full name is compared, not
    the last component: `sqlite3.Error`, `x.Exception` or `OperationalError` catch a special case."""
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    for t in types:
        if isinstance(t, ast.Name) and t.id in _WIDE:
            return True
        if (isinstance(t, ast.Attribute) and t.attr in _WIDE
                and isinstance(t.value, ast.Name) and t.value.id == "builtins"):
            return True
    return False


def _shadowed(tree):
    """The broad names the module rebinds itself (assignment, import, def, parameter …) —
    then `except Exception:` would mean something else there."""
    bound = set()
    for k in ast.walk(tree):
        if isinstance(k, ast.Name) and isinstance(k.ctx, (ast.Store, ast.Del)):
            bound.add(k.id)
        elif isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(k.name)
        elif isinstance(k, ast.arg):
            bound.add(k.arg)
        elif isinstance(k, ast.alias):
            bound.add(k.asname or k.name.split(".")[0])
        elif isinstance(k, ast.ExceptHandler) and k.name:
            bound.add(k.name)
        elif isinstance(k, (ast.Global, ast.Nonlocal)):
            bound.update(k.names)
    return bound & _WIDE


def _protected(fn, with_try=True):
    """The nodes whose failure is rolled back: in a `with self._writing():` block
    or (with `with_try`) in the `try` part of a block whose broad `except` or `finally` rolls back."""
    inside = set()
    for w in ast.walk(fn):
        if isinstance(w, ast.With) and any(
                isinstance(i.context_expr, ast.Call) and isinstance(i.context_expr.func, ast.Attribute)
                and i.context_expr.func.attr == "_writing" for i in w.items):
            inside.update(id(k) for k in ast.walk(w))
        elif with_try and isinstance(w, ast.Try) and (
                any(_catches_everything(h) and _rolls_back(h) for h in w.handlers)
                or any(_rolls_back(f) for f in w.finalbody)):
            for part in w.body:
                inside.update(id(k) for k in ast.walk(part))
    return inside


def _store_class(tree):
    return next(k for k in tree.body if isinstance(k, ast.ClassDef) and k.name == "Store")


def _check_commits(tree):
    """(Commits outside `_writing()`, commits of self-managed transactions without
    rollback on failure) — each as `function:line`. `tree`: source text or syntax tree."""
    klass = _store_class(ast.parse(tree) if isinstance(tree, str) else tree)
    without_writing, without_rollback = [], []
    for fn in klass.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        commits = [k for k in ast.walk(fn) if _is_commit(k)]
        if not commits or fn.name == "__init__":     # construction: if it fails, there is no store
            continue
        inside = _protected(fn)
        unclosed = [f"{fn.name}:{k.lineno}" for k in commits if id(k) not in inside]
        (without_rollback if fn.name in ITSELF_KEPT else without_writing).extend(unclosed)
    return without_writing, without_rollback


_STORE_TREE = ast.parse(STORE_SOURCE)
assert not _shadowed(_STORE_TREE), \
    f"store.py rebinds {_shadowed(_STORE_TREE)} — `except` there would mean something else"
unprotected, without_rollback = _check_commits(_STORE_TREE)
assert not unprotected, f"commit outside _schreibend() (no rollback on failure): {unprotected}"
assert not without_rollback, f"runs the transaction itself but does not roll back on failure: {without_rollback}"

# Self-test of the guard — on the syntax tree, without a text anchor: if it turns red, that is due to
# the guard, not to a source-text comparison that trips on every rewording. Every function is
# checked whose commit depends ALONE on its own `try` (not on `_writing`),
# derived rather than enumerated: a new self-managed function joins automatically. In each one
# the rolling-back `except` is narrowed — to every spelling of a special case, including those
# that got through until the final round — or replaced by a `finally` without rollback.
_only_try = sorted(
    f.name for f in _store_class(_STORE_TREE).body
    if isinstance(f, ast.FunctionDef) and f.name != "__init__"
    and any(id(k) not in _protected(f, with_try=False) for k in ast.walk(f) if _is_commit(k)))
# The function from the finding must be included — otherwise the probe might run over nothing.
assert "reserve_attempt" in _only_try, f"self-test hits nothing: {_only_try}"


def _replace_except(fn_name, type_name):
    """Copy of the store tree in which `fn_name` catches every rolling-back `except` with `type_name`
    (`typ=None`: no `except`, `finally: pass`)."""
    tree = copy.deepcopy(_STORE_TREE)
    fn = next(f for f in _store_class(tree).body if isinstance(f, ast.FunctionDef) and f.name == fn_name)
    tries = [t for t in ast.walk(fn) if isinstance(t, ast.Try) and (
        any(_catches_everything(h) and _rolls_back(h) for h in t.handlers)
        or any(_rolls_back(x) for x in t.finalbody))]
    assert tries, f"self-test: {fn_name} no longer has a rolling-back except"
    for t in tries:
        if type_name is None:
            t.handlers, t.finalbody = [], [ast.Pass()]
            continue
        for h in t.handlers:
            h.type = None if type_name == "" else ast.parse(type_name, mode="eval").body
        t.finalbody = [x for x in t.finalbody if not _rolls_back(x)]
    return tree


for _fn_name in _only_try:
    for _type_name in ("KeyError", "OverflowError", "binascii.Error", "sqlite3.Error", "sqlite3.DatabaseError",
                 "sqlite3.OperationalError", "sqlite3.ProgrammingError", "OperationalError",
                 "(KeyError, sqlite3.OperationalError)", "irgendwas.Exception", "irgendwas.BaseException",
                 None):
        _, _mutated = _check_commits(_replace_except(_fn_name, _type_name))
        assert any(f.startswith(_fn_name + ":") for f in _mutated), \
            f"the guard accepts a too narrow catch in {_fn_name}: {_type_name or 'finally: pass'} → {_mutated}"
    # Control: the broad spellings stay allowed — otherwise the probe above would only check
    # that the guard complains about everything.
    for _type_name in ("", "Exception", "BaseException", "builtins.Exception", "(KeyError, Exception)"):
        _, _mutated = _check_commits(_replace_except(_fn_name, _type_name))
        assert not _mutated, f"the guard complains about a broad catch: {_fn_name} {_type_name or 'without type'} → {_mutated}"
# And the other half: what IS a commit? SQLite also ends a transaction with `END`,
# `COMMIT TRANSACTION`, `commit;` — and `executescript()` commits an open transaction before
# it runs its script. Each of these spellings in a new unprotected writer gets noticed.
for _commit in ('self.db.execute("END")', 'self.db.execute("commit;")', 'self.db.execute("COMMIT TRANSACTION")',
                'self.db.execute("  End Transaction")', 'self.db.executemany("COMMIT", [()])',
                'self.db.executescript("DELETE FROM setting; COMMIT;")', 'self.db.execute("RELEASE sp")'):
    _m = copy.deepcopy(_STORE_TREE)
    _store_class(_m).body.append(ast.parse(
        "def _probe_schreiber(self):\n    with self._lock:\n"
        f"        self.db.execute('DELETE FROM setting')\n        {_commit}\n").body[0])
    _without, _ = _check_commits(_m)
    assert any(f.startswith("_probe_schreiber:") for f in _without), f"commit not recognised as a commit: {_commit}"
for _rebind in ("Exception = KeyError\n", "from sqlite3 import OperationalError as BaseException\n",
                  "def f(Exception):\n    pass\n"):
    assert _shadowed(ast.parse(_rebind)), f"rebinding missed: {_rebind!r}"
ok("every commit in the store rolls back on failure (AST over store.py)")

os.remove(db)
print("\nHARDENING-2 OK ✅")
