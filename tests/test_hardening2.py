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
auth.ensure_admin("admin", "geheim123")
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
    c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c1.get("/geheim").status_code == 200 and c2.get("/geheim").status_code == 200
c1.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"})
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
# Store steht in einem `_schreibend()`-Block — oder in einer Funktion, die ihre Transaktion
# selbst führt UND sichtbar zurückrollt. (Mutationsprobe: in `delete_user` wieder
# `with self._lock:` → rot, mit Funktionsname.)
import ast                                                                      # noqa: E402
from pathlib import Path                                                        # noqa: E402

SELBST_GEFUEHRT = {"__init__", "_migrate", "rotate_session", "reserve_attempt", "_uhr_mitschreiben"}
baum = ast.parse((Path(__file__).resolve().parent.parent / "tinysesam" / "store.py").read_text("utf-8"))
store_klasse = next(k for k in baum.body if isinstance(k, ast.ClassDef) and k.name == "Store")


def _ist_commit(k):
    if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)):
        return False
    if k.func.attr == "commit":
        return True
    return (k.func.attr == "execute" and k.args and isinstance(k.args[0], ast.Constant)
            and str(k.args[0].value).strip().upper() == "COMMIT")


def _geschuetzt(fn):
    """Die Knoten innerhalb eines `with self._schreibend():`-Blocks."""
    drin = set()
    for w in ast.walk(fn):
        if isinstance(w, ast.With) and any(
                isinstance(i.context_expr, ast.Call) and isinstance(i.context_expr.func, ast.Attribute)
                and i.context_expr.func.attr == "_schreibend" for i in w.items):
            drin.update(id(k) for k in ast.walk(w))
    return drin


ungeschuetzt, ohne_rollback = [], []
for fn in store_klasse.body:
    if not isinstance(fn, ast.FunctionDef):
        continue
    commits = [k for k in ast.walk(fn) if _ist_commit(k)]
    if not commits:
        continue
    if fn.name in SELBST_GEFUEHRT:
        quelle = ast.unparse(fn)
        if fn.name != "__init__" and not any(w in quelle for w in ("rollback()", "'ROLLBACK'", "_verwerfen()")):
            ohne_rollback.append(fn.name)
        continue
    drin = _geschuetzt(fn)
    ungeschuetzt += [f"{fn.name}:{k.lineno}" for k in commits if id(k) not in drin]
assert not ungeschuetzt, f"Commit ausserhalb von _schreibend() (kein Zurückrollen beim Fehlschlag): {ungeschuetzt}"
assert not ohne_rollback, f"führt die Transaktion selbst, rollt aber nie zurück: {ohne_rollback}"
ok("jeder Commit im Store rollt beim Fehlschlag zurück (AST über store.py)")

os.remove(db)
print("\nHÄRTUNG-2 OK ✅")
