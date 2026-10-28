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
def geheim(u=Depends(auth.require_user)):
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
# (Mutation probe: in `Store._exec` replace `with self._schreibend():` by
# `with self._lock:` -> "_exec (audit_log)" red; the same in `schreibprobe` ->
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


def _schreibprobe():
    auth_s.store._geschrieben = None                    # otherwise a read access is enough for it
    auth_s.store.schreibprobe()


schreiber = {
    "schreibprobe": _schreibprobe,
    "_exec (audit_log)": lambda: auth_s.store.audit_log("probe", "sven", None, None),
    "record_attempt": lambda: auth_s.store.record_attempt("sven", "198.51.100.9", False, "password"),
    "add_recovery_codes": lambda: auth_s.store.add_recovery_codes(uid_s, ["a" * 64]),
    "consume_recovery_code": lambda: auth_s.store.consume_recovery_code(uid_s, "b" * 64),
    "use_magic_token": lambda: auth_s.store.use_magic_token("c" * 64),
    "delete_user": lambda: auth_s.store.delete_user(uid_s + 1000),
}
fremd = sqlite3.connect(db_s, isolation_level=None)
fremd.execute("BEGIN IMMEDIATE")
try:
    for name, schreiben in schreiber.items():
        try:
            schreiben()
        except sqlite3.OperationalError:
            pass
        else:
            raise AssertionError(f"{name}: Vorbedingung verfehlt — der fremde Schreiber sperrt nicht")
        assert not auth_s.store.db.in_transaction, \
            f"{name} leaves a transaction open on the shared connection after the failure"
finally:
    fremd.execute("ROLLBACK")
    fremd.close()
auth_s.store.db.execute(f"PRAGMA busy_timeout={auth_s.store.BUSY_TIMEOUT_MS}")
codes = [TestClient(app_s, raise_server_exceptions=False).post(
    "/auth/login", data={"username": "sven", "password": "Sven-Passwort-2026"},
    follow_redirects=False).status_code for _ in range(3)]
assert codes == [303, 303, 303], f"sign-in after failed writes: {codes}"
ok(f"failed writes roll back ({len(schreiber)} paths), sign-in stays intact")

# Second lock: if a transaction is lying around anyway (a future writer without
# rollback), `reserve_attempt` clears it instead of letting every sign-in fail.
auth_s.store.db.execute("INSERT INTO setting(key, value) VALUES ('probe_liegengeblieben', '1')")
assert auth_s.store.db.in_transaction, "precondition: an open transaction is lying around"
versuch_s = auth_s._versuch_beginnen("sven", "198.51.100.9", "password")
assert versuch_s is not None, "the sign-in attempt was rejected"
assert not auth_s.store.db.in_transaction
assert auth_s.store.get_setting("probe_liegengeblieben") is None, \
    "the leftovers of a failed writer were committed along instead of discarded"
ok("reserve_attempt discards a leftover transaction instead of failing on it")
auth_s.store.db.close()
os.remove(db_s)

# Guard over the list above: it names today's write paths. A new writer with
# `with self._lock: ... self.db.commit()` would escape it. Hence via AST: every commit in the
# store sits in a `_schreibend()` block — or, in a function that runs its transaction
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
# not a sqlite3.Error and ends the same way. `_uhr_mitschreiben` therefore caught too narrowly until then.
# Limits the syntax tree does not see: whether the rollback in the handler is actually EXECUTED
# (an `if False:` in front of it), and a `builtins.Exception` that someone rebinds from outside
# at runtime. Rebinding IN store.py (`Exception = KeyError`, an import under that name) is caught
# by `_ueberschattet` below. (Mutation probes: in `delete_user` put `with self._lock:` back -> red, with
# function name; in `_faengt_alles` accept any last component `Error`/`DatabaseError`/
# `OperationalError` again -> the self-test below turns red; in `_uhr_mitschreiben` `except sqlite3.Error:`
# again -> red, `_uhr_mitschreiben:<line>`; in store.py narrow `reserve_attempt` to
# `except sqlite3.OperationalError:` or `rotate_session` to `except sqlite3.DatabaseError:`
# -> red with function name; `_ist_commit` again only `commit()`/`execute("COMMIT")`, without
# `END`, without `executemany` or case-sensitive -> red.)
import ast                                                                      # noqa: E402
import re                                                                       # noqa: E402
import copy                                                                     # noqa: E402
from pathlib import Path                                                        # noqa: E402

SELBST_GEFUEHRT = {"__init__", "_migrate", "rotate_session", "reserve_attempt", "_uhr_mitschreiben"}
STORE_QUELLE = (Path(__file__).resolve().parent.parent / "tinysesam" / "store.py").read_text("utf-8")
_BREIT = {"Exception", "BaseException"}


#: SQL that closes a transaction — whatever the spelling (`END`, `COMMIT TRANSACTION`,
#: `commit;`; `RELEASE` does it for the outermost savepoint).
_COMMIT_SQL = re.compile(r"(?i)(?:^|;)\s*(?:commit|end|release)\b")


def _ist_commit(k):
    """Does this call close a transaction? `commit()`, any `executescript()` (it commits an open
    transaction before running its script), `execute`/`executemany` with COMMIT/END/RELEASE.
    Limit: SQL that only arises at runtime (a variable) is not seen by the syntax tree."""
    if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)):
        return False
    if k.func.attr in ("commit", "executescript"):
        return True
    return (k.func.attr in ("execute", "executemany") and bool(k.args) and isinstance(k.args[0], ast.Constant)
            and isinstance(k.args[0].value, str) and bool(_COMMIT_SQL.search(k.args[0].value)))


def _rollt_zurueck(knoten):
    """Does the block contain a rollback — `rollback()`, `execute("ROLLBACK")`, `_verwerfen()`?"""
    for k in ast.walk(knoten):
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute):
            if k.func.attr in ("rollback", "_verwerfen"):
                return True
            if (k.func.attr == "execute" and k.args and isinstance(k.args[0], ast.Constant)
                    and str(k.args[0].value).strip().upper() == "ROLLBACK"):
                return True
    return False


def _faengt_alles(handler):
    """Does this `except` catch EVERY failure of a write — without a type, `Exception`,
    `BaseException` (also `builtins.…`, also in a tuple)? The full name is compared, not
    the last component: `sqlite3.Error`, `x.Exception` or `OperationalError` catch a special case."""
    if handler.type is None:
        return True
    typen = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    for t in typen:
        if isinstance(t, ast.Name) and t.id in _BREIT:
            return True
        if (isinstance(t, ast.Attribute) and t.attr in _BREIT
                and isinstance(t.value, ast.Name) and t.value.id == "builtins"):
            return True
    return False


def _ueberschattet(baum):
    """The broad names the module rebinds itself (assignment, import, def, parameter …) —
    then `except Exception:` would mean something else there."""
    gebunden = set()
    for k in ast.walk(baum):
        if isinstance(k, ast.Name) and isinstance(k.ctx, (ast.Store, ast.Del)):
            gebunden.add(k.id)
        elif isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            gebunden.add(k.name)
        elif isinstance(k, ast.arg):
            gebunden.add(k.arg)
        elif isinstance(k, ast.alias):
            gebunden.add(k.asname or k.name.split(".")[0])
        elif isinstance(k, ast.ExceptHandler) and k.name:
            gebunden.add(k.name)
        elif isinstance(k, (ast.Global, ast.Nonlocal)):
            gebunden.update(k.names)
    return gebunden & _BREIT


def _geschuetzt(fn, mit_try=True):
    """The nodes whose failure is rolled back: in a `with self._schreibend():` block
    or (with `mit_try`) in the `try` part of a block whose broad `except` or `finally` rolls back."""
    drin = set()
    for w in ast.walk(fn):
        if isinstance(w, ast.With) and any(
                isinstance(i.context_expr, ast.Call) and isinstance(i.context_expr.func, ast.Attribute)
                and i.context_expr.func.attr == "_schreibend" for i in w.items):
            drin.update(id(k) for k in ast.walk(w))
        elif mit_try and isinstance(w, ast.Try) and (
                any(_faengt_alles(h) and _rollt_zurueck(h) for h in w.handlers)
                or any(_rollt_zurueck(f) for f in w.finalbody)):
            for teil in w.body:
                drin.update(id(k) for k in ast.walk(teil))
    return drin


def _store_klasse(baum):
    return next(k for k in baum.body if isinstance(k, ast.ClassDef) and k.name == "Store")


def _commits_pruefen(baum):
    """(Commits outside `_schreibend()`, commits of self-managed transactions without
    rollback on failure) — each as `function:line`. `baum`: source text or syntax tree."""
    klasse = _store_klasse(ast.parse(baum) if isinstance(baum, str) else baum)
    ohne_schreibend, ohne_rollback = [], []
    for fn in klasse.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        commits = [k for k in ast.walk(fn) if _ist_commit(k)]
        if not commits or fn.name == "__init__":     # construction: if it fails, there is no store
            continue
        drin = _geschuetzt(fn)
        offen = [f"{fn.name}:{k.lineno}" for k in commits if id(k) not in drin]
        (ohne_rollback if fn.name in SELBST_GEFUEHRT else ohne_schreibend).extend(offen)
    return ohne_schreibend, ohne_rollback


_STORE_BAUM = ast.parse(STORE_QUELLE)
assert not _ueberschattet(_STORE_BAUM), \
    f"store.py rebinds {_ueberschattet(_STORE_BAUM)} — `except` there would mean something else"
ungeschuetzt, ohne_rollback = _commits_pruefen(_STORE_BAUM)
assert not ungeschuetzt, f"commit outside _schreibend() (no rollback on failure): {ungeschuetzt}"
assert not ohne_rollback, f"runs the transaction itself but does not roll back on failure: {ohne_rollback}"

# Self-test of the guard — on the syntax tree, without a text anchor: if it turns red, that is due to
# the guard, not to a source-text comparison that trips on every rewording. Every function is
# checked whose commit depends ALONE on its own `try` (not on `_schreibend`),
# derived rather than enumerated: a new self-managed function joins automatically. In each one
# the rolling-back `except` is narrowed — to every spelling of a special case, including those
# that got through until the final round — or replaced by a `finally` without rollback.
_nur_try = sorted(
    f.name for f in _store_klasse(_STORE_BAUM).body
    if isinstance(f, ast.FunctionDef) and f.name != "__init__"
    and any(id(k) not in _geschuetzt(f, mit_try=False) for k in ast.walk(f) if _ist_commit(k)))
# The function from the finding must be included — otherwise the probe might run over nothing.
assert "reserve_attempt" in _nur_try, f"self-test hits nothing: {_nur_try}"


def _except_ersetzen(fn_name, typ):
    """Copy of the store tree in which `fn_name` catches every rolling-back `except` with `typ`
    (`typ=None`: no `except`, `finally: pass`)."""
    baum = copy.deepcopy(_STORE_BAUM)
    fn = next(f for f in _store_klasse(baum).body if isinstance(f, ast.FunctionDef) and f.name == fn_name)
    tries = [t for t in ast.walk(fn) if isinstance(t, ast.Try) and (
        any(_faengt_alles(h) and _rollt_zurueck(h) for h in t.handlers)
        or any(_rollt_zurueck(x) for x in t.finalbody))]
    assert tries, f"self-test: {fn_name} no longer has a rolling-back except"
    for t in tries:
        if typ is None:
            t.handlers, t.finalbody = [], [ast.Pass()]
            continue
        for h in t.handlers:
            h.type = None if typ == "" else ast.parse(typ, mode="eval").body
        t.finalbody = [x for x in t.finalbody if not _rollt_zurueck(x)]
    return baum


for _fn_name in _nur_try:
    for _typ in ("KeyError", "OverflowError", "binascii.Error", "sqlite3.Error", "sqlite3.DatabaseError",
                 "sqlite3.OperationalError", "sqlite3.ProgrammingError", "OperationalError",
                 "(KeyError, sqlite3.OperationalError)", "irgendwas.Exception", "irgendwas.BaseException",
                 None):
        _, _mutiert = _commits_pruefen(_except_ersetzen(_fn_name, _typ))
        assert any(f.startswith(_fn_name + ":") for f in _mutiert), \
            f"the guard accepts a too narrow catch in {_fn_name}: {_typ or 'finally: pass'} → {_mutiert}"
    # Control: the broad spellings stay allowed — otherwise the probe above would only check
    # that the guard complains about everything.
    for _typ in ("", "Exception", "BaseException", "builtins.Exception", "(KeyError, Exception)"):
        _, _mutiert = _commits_pruefen(_except_ersetzen(_fn_name, _typ))
        assert not _mutiert, f"the guard complains about a broad catch: {_fn_name} {_typ or 'without type'} → {_mutiert}"
# And the other half: what IS a commit? SQLite also ends a transaction with `END`,
# `COMMIT TRANSACTION`, `commit;` — and `executescript()` commits an open transaction before
# it runs its script. Each of these spellings in a new unprotected writer gets noticed.
for _commit in ('self.db.execute("END")', 'self.db.execute("commit;")', 'self.db.execute("COMMIT TRANSACTION")',
                'self.db.execute("  End Transaction")', 'self.db.executemany("COMMIT", [()])',
                'self.db.executescript("DELETE FROM setting; COMMIT;")', 'self.db.execute("RELEASE sp")'):
    _m = copy.deepcopy(_STORE_BAUM)
    _store_klasse(_m).body.append(ast.parse(
        "def _probe_schreiber(self):\n    with self._lock:\n"
        f"        self.db.execute('DELETE FROM setting')\n        {_commit}\n").body[0])
    _ohne, _ = _commits_pruefen(_m)
    assert any(f.startswith("_probe_schreiber:") for f in _ohne), f"commit not recognised as a commit: {_commit}"
for _umbinden in ("Exception = KeyError\n", "from sqlite3 import OperationalError as BaseException\n",
                  "def f(Exception):\n    pass\n"):
    assert _ueberschattet(ast.parse(_umbinden)), f"rebinding missed: {_umbinden!r}"
ok("every commit in the store rolls back on failure (AST over store.py)")

os.remove(db)
print("\nHARDENING-2 OK ✅")
