"""Batch A: Session-Invalidierung bei PW-Wechsel, auth.gc(), Dummy-Verify-Timing, py.typed."""
import tempfile, os, time
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
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
import tinysesam, os.path as osp
assert osp.exists(osp.join(osp.dirname(tinysesam.__file__), "py.typed"))
ok("py.typed ausgeliefert")

os.remove(db)
print("\nHÄRTUNG-2 OK ✅")
