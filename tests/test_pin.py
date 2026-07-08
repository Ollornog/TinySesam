"""Phase 3: Persönliche PIN pro User — Login, Mindestlänge, eigener Lockout, mit TOTP kombinierbar."""
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 password_enabled=True, pin_enabled=True, pin_min_length=4, cookie_secure=False))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
uid = auth.store.get_user_by_name("admin")["id"]

# Login-Seite zeigt PIN-Form
assert "Mit PIN anmelden" in c.get("/auth/login").text
ok("Login-Seite zeigt PIN-Form (pin_enabled)")

# Mindestlänge
try:
    auth.set_pin(uid, "12")
    assert False, "zu kurze PIN sollte fehlschlagen"
except ValueError:
    ok("set_pin erzwingt Mindestlänge")

auth.set_pin(uid, "2468")
assert auth.has_pin(uid)

# falsche PIN → 401
assert c.post("/auth/pin", data={"username": "admin", "pin": "0000", "next": "/geheim"}).status_code == 401
ok("falsche PIN → 401")

# richtige PIN → eingeloggt
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and "set-cookie" in {k.lower() for k in r.headers}
assert c.get("/geheim").json()["u"] == "admin"
ok("richtige PIN → eingeloggt (PIN ist vollwertiger Faktor)")

# Self-Service: PIN ändern & entfernen
assert c.post("/auth/pin/set", json={"pin": "13579"}).json() == {"ok": True}
assert c.post("/auth/pin/set", json={"pin": "1"}).status_code == 400   # zu kurz
c.get("/auth/logout")
r = c.post("/auth/pin", data={"username": "admin", "pin": "13579", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("PIN self-service ändern")

# eigener PIN-Lockout: 5 Fehlversuche → auch korrekte PIN gesperrt
c.get("/auth/logout")
for _ in range(5):
    c.post("/auth/pin", data={"username": "admin", "pin": "0000", "next": "/"})
r = c.post("/auth/pin", data={"username": "admin", "pin": "13579", "next": "/"})
assert r.status_code == 429, r.status_code
ok("PIN-Lockout greift (auch korrekte PIN gesperrt)")
auth.store.clear_fails(username="admin")

# PIN + TOTP kombiniert: PIN-Login führt in den TOTP-Schritt
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).now())
c2 = TestClient(app)
r = c2.post("/auth/pin", data={"username": "admin", "pin": "13579", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/totp" in r.headers["location"]
assert c2.get("/geheim").status_code == 401   # noch nicht voll
r = c2.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and c2.get("/geheim").json()["u"] == "admin"
ok("PIN + TOTP kombinierbar (PIN → 2. Faktor)")

# entfernen
c3 = TestClient(app)
c3.post("/auth/pin", data={"username": "admin", "pin": "13579"}, follow_redirects=False)
c3.post("/auth/totp", data={"code": pyotp.TOTP(secret).now()}, follow_redirects=False)
assert c3.post("/auth/pin/disable").json() == {"ok": True}
assert not auth.has_pin(uid)
ok("PIN entfernen")

os.remove(db)
print("\nPIN OK ✅")
