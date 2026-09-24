"""Batch A: Session-Invalidierung bei PW-Wechsel, auth.gc(), Dummy-Verify-Timing, py.typed."""
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


# ---------- Selbst-PW-Änderung beendet ANDERE Sitzungen, behält die aktuelle ----------
c1 = TestClient(app)   # Sitzung A (ändert das Passwort)
c2 = TestClient(app)   # Sitzung B (soll rausfliegen)
for c in (c1, c2):
    c.post("/auth/login", data={"username": "admin", "password": "geheim123-lang-genug", "next": "/"}, follow_redirects=False)
assert c1.get("/geheim").status_code == 200 and c2.get("/geheim").status_code == 200
c1.post("/auth/password", json={"current": "geheim123-lang-genug", "new": "neuespasswort-lang"})
assert c1.get("/geheim").status_code == 200, "eigene Sitzung bleibt"
assert c2.get("/geheim").status_code == 401, "andere Sitzung beendet"
ok("Selbst-PW-Änderung: andere Sitzungen beendet, aktuelle bleibt")

# ---------- auth.gc() räumt abgelaufenes weg + liefert Zähler ----------
# abgelaufene Session + abgelaufenen Magic-Token + alten Login-Versuch anlegen
auth.store.create_session(uid, -10, True, "password")               # sofort abgelaufen
auth.store._exec("INSERT INTO login_attempt(ts,username,ip,success,method) VALUES (?,?,?,?,?)",
                 (int(time.time()) - 999999, "x", "1.2.3.4", 0, "password"))
auth.store.add_magic_token("deadhash", "login", int(time.time()) - 10, user_id=uid)
res = auth.gc(attempts_older_than_sec=86400)
assert res["sessions"] >= 1 and res["login_attempts"] >= 1 and res["magic_tokens"] >= 1, res
ok(f"auth.gc() räumt auf + zählt: {res}")

# ---------- Dummy-Verify: unbekannter User ~ gleich langsam wie echter Fehlversuch ----------
from tinysesam import TinySesamConfig as _C  # noqa
def took(username):
    t = time.perf_counter()
    auth.check_password(username, "irgendwas")
    return time.perf_counter() - t
t_known = took("admin")          # existiert, falsches PW → echter Hash-Verify
t_unknown = took("gibtsnicht")   # existiert nicht → Dummy-Verify
# beide sollten spürbar Arbeit leisten; grobe Schranke (kein instant-return bei unbekannt)
assert t_unknown > t_known * 0.3, (t_known, t_unknown)
ok(f"Dummy-Verify: unbekannter User nicht instant (known={t_known*1000:.1f}ms, unknown={t_unknown*1000:.1f}ms)")

# ---------- py.typed vorhanden ----------
import importlib.util as _ilu, os.path as osp
assert osp.exists(osp.join(osp.dirname(_ilu.find_spec("tinysesam").origin), "py.typed"))
ok("py.typed ausgeliefert")

# ---------- Ein gescheiterter Schreibzugriff lässt keine Transaktion offen ----------
# Pythons sqlite3 öffnet vor jedem INSERT/UPDATE/DELETE still ein BEGIN. Scheiterte der
# Schreibzugriff (fremder Schreiber hält die Sperre länger als busy_timeout, Volume voll, nur
# lesbar), blieb diese Transaktion auf der geteilten Verbindung offen. `reserve_attempt` beginnt
# mit einem ausdrücklichen `BEGIN IMMEDIATE` und scheiterte daran mit „cannot start a transaction
# within a transaction" — jede Anmeldung endete mit 500, bis irgendein anderer Schreibzugriff die
# Reste zufällig mitcommittete. Auslöser genügte die Schreibprobe von /healthz, ohne Anmeldung
# erreichbar. (Mutationsprobe: in `Store._exec` `with self._schreibend():` durch
# `with self._lock:` ersetzen → „_exec (audit_log)" rot; dasselbe in `schreibprobe` →
# „schreibprobe" rot, in `delete_user` → „delete_user" rot; in `reserve_attempt` das Aufräumen
# vor `BEGIN IMMEDIATE` streichen → der Anmeldeversuch über einer liegengebliebenen Transaktion
# wirft → rot.)
import sqlite3                                                                  # noqa: E402

db_s = os.path.join(tempfile.mkdtemp(), "t.db")
auth_s = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_s, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False))
uid_s = auth_s.create_user("sven", "Sven-Passwort-2026")
app_s = FastAPI()
app_s.include_router(auth_s.router())
auth_s.store.db.execute("PRAGMA busy_timeout=200")      # nicht zehn Sekunden je Fehlschlag warten


def _schreibprobe():
    auth_s.store._geschrieben = None                    # sonst genügt ihr ein Lesezugriff
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
            f"{name} lässt nach dem Fehlschlag eine Transaktion auf der geteilten Verbindung offen"
finally:
    fremd.execute("ROLLBACK")
    fremd.close()
auth_s.store.db.execute(f"PRAGMA busy_timeout={auth_s.store.BUSY_TIMEOUT_MS}")
codes = [TestClient(app_s, raise_server_exceptions=False).post(
    "/auth/login", data={"username": "sven", "password": "Sven-Passwort-2026"},
    follow_redirects=False).status_code for _ in range(3)]
assert codes == [303, 303, 303], f"Anmeldung nach gescheiterten Schreibzugriffen: {codes}"
ok(f"gescheiterte Schreibzugriffe rollen zurück ({len(schreiber)} Wege), die Anmeldung bleibt heil")

# Zweites Schloss: Liegt trotzdem eine Transaktion herum (ein künftiger Schreiber ohne
# Zurückrollen), räumt `reserve_attempt` sie weg, statt jede Anmeldung scheitern zu lassen.
auth_s.store.db.execute("INSERT INTO setting(key, value) VALUES ('probe_liegengeblieben', '1')")
assert auth_s.store.db.in_transaction, "Vorbedingung: eine offene Transaktion liegt herum"
versuch_s = auth_s.versuch_beginnen("sven", "198.51.100.9", "password")
assert versuch_s is not None, "der Anmeldeversuch wurde abgewiesen"
assert not auth_s.store.db.in_transaction
assert auth_s.store.get_setting("probe_liegengeblieben") is None, \
    "die Reste eines gescheiterten Schreibers wurden mitcommittet statt verworfen"
ok("reserve_attempt verwirft eine liegengebliebene Transaktion, statt an ihr zu scheitern")
auth_s.store.db.close()
os.remove(db_s)

# Wächter über die Liste oben: Sie nennt die Schreibwege von heute. Ein neuer Schreiber mit
# `with self._lock: … self.db.commit()` fiele ihr nicht auf. Deshalb per AST: Jeder Commit im
# Store steht in einem `_schreibend()`-Block — oder, in einer Funktion, die ihre Transaktion
# selbst führt, im `try` eines Blocks, dessen `except` jeden Fehlschlag fängt und zurückrollt bzw.
# dessen `finally` zurückrollt. Bis zur Nachbesserung prüfte der Wächter bei den selbst geführten
# Funktionen nur, ob IRGENDWO in ihnen `rollback()` stand: `rotate_session` hat eines im Zweig
# `rowcount != 1`, und ohne das Zurückrollen im `except` blieb der Wächter grün, obwohl ein
# gescheitertes INSERT die Transaktion offen liess.
#
# „Fängt jeden Fehlschlag“ heisst: `except` ohne Typ, mit `Exception` oder mit `BaseException`
# (auch als `builtins.…`, auch in einem Tupel) — verglichen wird der VOLLE Name. Bis zur
# Schlussrunde galt jedes letzte Glied `Error`, `DatabaseError` oder `OperationalError`:
# `except sqlite3.OperationalError:` in `reserve_attempt` blieb grün, und ein Bindefehler nach
# `BEGIN IMMEDIATE` (ProgrammingError) liess die Transaktion offen (Schlussfund sperren-0).
# Auch `sqlite3.Error` reicht nicht: `OverflowError` (eine Zahl über 2**63 als Parameter) ist
# kein sqlite3.Error und endet genauso. `_uhr_mitschreiben` fing deshalb bis dahin zu eng.
# Grenzen, die der Syntaxbaum nicht sieht: ob das Zurückrollen im Handler auch AUSGEFÜHRT wird
# (ein `if False:` davor), und ein `builtins.Exception`, das jemand zur Laufzeit von aussen
# umbiegt. Ein Umbinden IN store.py (`Exception = KeyError`, ein Import unter diesem Namen) fängt
# `_ueberschattet` unten. (Mutationsproben: in `delete_user` wieder `with self._lock:` → rot, mit
# Funktionsname; in `_faengt_alles` wieder jedes letzte Glied `Error`/`DatabaseError`/
# `OperationalError` annehmen → die Selbstprobe unten wird rot; in `_uhr_mitschreiben` wieder
# `except sqlite3.Error:` → rot, `_uhr_mitschreiben:<Zeile>`; in store.py `reserve_attempt` auf
# `except sqlite3.OperationalError:` oder `rotate_session` auf `except sqlite3.DatabaseError:`
# verengen → rot mit Funktionsname; `_ist_commit` wieder nur `commit()`/`execute("COMMIT")`, ohne
# `END`, ohne `executemany` oder case-sensitiv → rot.)
import ast                                                                      # noqa: E402
import re                                                                       # noqa: E402
import copy                                                                     # noqa: E402
from pathlib import Path                                                        # noqa: E402

SELBST_GEFUEHRT = {"__init__", "_migrate", "rotate_session", "reserve_attempt", "_uhr_mitschreiben"}
STORE_QUELLE = (Path(__file__).resolve().parent.parent / "tinysesam" / "store.py").read_text("utf-8")
_BREIT = {"Exception", "BaseException"}


#: SQL, das eine Transaktion abschliesst — gleich in welcher Schreibung (`END`, `COMMIT TRANSACTION`,
#: `commit;`; `RELEASE` tut es für den äussersten Sicherungspunkt).
_COMMIT_SQL = re.compile(r"(?i)(?:^|;)\s*(?:commit|end|release)\b")


def _ist_commit(k):
    """Schliesst dieser Aufruf eine Transaktion ab? `commit()`, jedes `executescript()` (es committet
    eine offene Transaktion, bevor es sein Skript fährt), `execute`/`executemany` mit COMMIT/END/RELEASE.
    Grenze: SQL, das erst zur Laufzeit entsteht (eine Variable), sieht der Syntaxbaum nicht."""
    if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)):
        return False
    if k.func.attr in ("commit", "executescript"):
        return True
    return (k.func.attr in ("execute", "executemany") and bool(k.args) and isinstance(k.args[0], ast.Constant)
            and isinstance(k.args[0].value, str) and bool(_COMMIT_SQL.search(k.args[0].value)))


def _rollt_zurueck(knoten):
    """Enthält der Block ein Zurückrollen — `rollback()`, `execute("ROLLBACK")`, `_verwerfen()`?"""
    for k in ast.walk(knoten):
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute):
            if k.func.attr in ("rollback", "_verwerfen"):
                return True
            if (k.func.attr == "execute" and k.args and isinstance(k.args[0], ast.Constant)
                    and str(k.args[0].value).strip().upper() == "ROLLBACK"):
                return True
    return False


def _faengt_alles(handler):
    """Fängt dieser `except` JEDEN Fehlschlag eines Schreibzugriffs — ohne Typ, `Exception`,
    `BaseException` (auch `builtins.…`, auch in einem Tupel)? Verglichen wird der volle Name, nicht
    das letzte Glied: `sqlite3.Error`, `x.Exception` oder `OperationalError` fangen einen Sonderfall."""
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
    """Die breiten Namen, die das Modul selbst neu bindet (Zuweisung, Import, def, Parameter …) —
    dann hiesse `except Exception:` dort etwas anderes."""
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
    """Die Knoten, deren Fehlschlag zurückgerollt wird: in einem `with self._schreibend():`-Block
    oder (mit `mit_try`) im `try`-Teil eines Blocks, dessen breiter `except` oder `finally` zurückrollt."""
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
    """(Commits ausserhalb von `_schreibend()`, Commits selbst geführter Transaktionen ohne
    Zurückrollen beim Fehlschlag) — je als `funktion:zeile`. `baum`: Quelltext oder Syntaxbaum."""
    klasse = _store_klasse(ast.parse(baum) if isinstance(baum, str) else baum)
    ohne_schreibend, ohne_rollback = [], []
    for fn in klasse.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        commits = [k for k in ast.walk(fn) if _ist_commit(k)]
        if not commits or fn.name == "__init__":     # Aufbau: scheitert er, gibt es keinen Store
            continue
        drin = _geschuetzt(fn)
        offen = [f"{fn.name}:{k.lineno}" for k in commits if id(k) not in drin]
        (ohne_rollback if fn.name in SELBST_GEFUEHRT else ohne_schreibend).extend(offen)
    return ohne_schreibend, ohne_rollback


_STORE_BAUM = ast.parse(STORE_QUELLE)
assert not _ueberschattet(_STORE_BAUM), \
    f"store.py bindet {_ueberschattet(_STORE_BAUM)} neu — `except` dort hiesse etwas anderes"
ungeschuetzt, ohne_rollback = _commits_pruefen(_STORE_BAUM)
assert not ungeschuetzt, f"Commit ausserhalb von _schreibend() (kein Zurückrollen beim Fehlschlag): {ungeschuetzt}"
assert not ohne_rollback, f"führt die Transaktion selbst, rollt beim Fehlschlag aber nicht zurück: {ohne_rollback}"

# Selbstprobe des Wächters — am Syntaxbaum, ohne Textanker: Dass sie rot wird, liegt dann am
# Wächter, nicht an einem Quelltextvergleich, der bei jeder Umformulierung anschlägt. Geprüft
# wird jede Funktion, deren Commit ALLEIN am eigenen `try` hängt (nicht an `_schreibend`),
# abgeleitet statt aufgezählt: Eine neue selbst geführte Funktion kommt von selbst dazu. In jeder
# wird der zurückrollende `except` verengt — auf jede Schreibweise eines Sonderfalls, auch die,
# die bis zur Schlussrunde durchkamen — oder durch ein `finally` ohne Zurückrollen ersetzt.
_nur_try = sorted(
    f.name for f in _store_klasse(_STORE_BAUM).body
    if isinstance(f, ast.FunctionDef) and f.name != "__init__"
    and any(id(k) not in _geschuetzt(f, mit_try=False) for k in ast.walk(f) if _ist_commit(k)))
# Die Funktion aus dem Fund muss dabei sein — sonst liefe die Probe womöglich über nichts.
assert "reserve_attempt" in _nur_try, f"Selbstprobe greift ins Leere: {_nur_try}"


def _except_ersetzen(fn_name, typ):
    """Kopie des Store-Baums, in der `fn_name` jeden zurückrollenden `except` mit `typ` fängt
    (`typ=None`: kein `except`, `finally: pass`)."""
    baum = copy.deepcopy(_STORE_BAUM)
    fn = next(f for f in _store_klasse(baum).body if isinstance(f, ast.FunctionDef) and f.name == fn_name)
    tries = [t for t in ast.walk(fn) if isinstance(t, ast.Try) and (
        any(_faengt_alles(h) and _rollt_zurueck(h) for h in t.handlers)
        or any(_rollt_zurueck(x) for x in t.finalbody))]
    assert tries, f"Selbstprobe: {fn_name} hat keinen zurückrollenden except mehr"
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
            f"der Wächter lässt in {_fn_name} einen zu engen Fang gelten: {_typ or 'finally: pass'} → {_mutiert}"
    # Gegenprobe: Die breiten Schreibweisen bleiben erlaubt — sonst prüfte die Probe oben nur,
    # dass der Wächter alles anmeckert.
    for _typ in ("", "Exception", "BaseException", "builtins.Exception", "(KeyError, Exception)"):
        _, _mutiert = _commits_pruefen(_except_ersetzen(_fn_name, _typ))
        assert not _mutiert, f"der Wächter meckert einen breiten Fang an: {_fn_name} {_typ or 'ohne Typ'} → {_mutiert}"
# Und die andere Hälfte: Was IST ein Commit? SQLite beendet eine Transaktion auch mit `END`,
# `COMMIT TRANSACTION`, `commit;` — und `executescript()` committet eine offene Transaktion, bevor
# es sein Skript fährt. Jede dieser Schreibweisen in einem neuen Schreiber ohne Schutz fällt auf.
for _commit in ('self.db.execute("END")', 'self.db.execute("commit;")', 'self.db.execute("COMMIT TRANSACTION")',
                'self.db.execute("  End Transaction")', 'self.db.executemany("COMMIT", [()])',
                'self.db.executescript("DELETE FROM setting; COMMIT;")', 'self.db.execute("RELEASE sp")'):
    _m = copy.deepcopy(_STORE_BAUM)
    _store_klasse(_m).body.append(ast.parse(
        "def _probe_schreiber(self):\n    with self._lock:\n"
        f"        self.db.execute('DELETE FROM setting')\n        {_commit}\n").body[0])
    _ohne, _ = _commits_pruefen(_m)
    assert any(f.startswith("_probe_schreiber:") for f in _ohne), f"Commit nicht als Commit erkannt: {_commit}"
for _umbinden in ("Exception = KeyError\n", "from sqlite3 import OperationalError as BaseException\n",
                  "def f(Exception):\n    pass\n"):
    assert _ueberschattet(ast.parse(_umbinden)), f"Umbinden übersehen: {_umbinden!r}"
ok("jeder Commit im Store rollt beim Fehlschlag zurück (AST über store.py)")

os.remove(db)
print("\nHÄRTUNG-2 OK ✅")
