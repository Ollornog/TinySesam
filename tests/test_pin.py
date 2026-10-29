"""Phase 3: personal PIN per user — login, minimum length, own lockout, combinable with TOTP."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import time

import pyotp
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 password_enabled=True, pin_enabled=True, pin_min_length=4, cookie_secure=False))
auth.ensure_admin("admin", "dummy123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/secret")
def secret_text(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
uid = auth.store.get_user_by_name("admin")["id"]

# login page shows the PIN form
assert "Mit PIN anmelden" in c.get("/auth/login").text
ok("login page shows the PIN form (pin_enabled)")

# minimum length
try:
    auth.set_pin(uid, "12")
    assert False, "too short PIN should fail"
except ValueError:
    ok("set_pin enforces minimum length")

auth.set_pin(uid, "2468")
assert auth.has_pin(uid)

# wrong PIN → 401
assert c.post("/auth/pin", data={"username": "admin", "pin": "0000", "next": "/secret"}).status_code == 401
ok("wrong PIN → 401")

# correct PIN → signed in
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/secret"}, follow_redirects=False)
assert r.status_code == 303 and "set-cookie" in {k.lower() for k in r.headers}
assert c.get("/secret").json()["u"] == "admin"
ok("correct PIN → logged in (PIN is a full factor)")

# self-service: change & remove PIN
assert c.post("/auth/pin/set", json={"pin": "13579"}).json() == {"ok": True, "other_sessions": 0}
assert c.post("/auth/pin/set", json={"pin": "1"}).status_code == 400   # too short
c.get("/auth/logout")
r = c.post("/auth/pin", data={"username": "admin", "pin": "13579", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("PIN self-service change")

# own PIN lockout: 5 failed attempts → even the correct PIN is locked
c.get("/auth/logout")
for _ in range(5):
    c.post("/auth/pin", data={"username": "admin", "pin": "0000", "next": "/"})
r = c.post("/auth/pin", data={"username": "admin", "pin": "13579", "next": "/"})
assert r.status_code == 429, r.status_code
ok("PIN lockout applies (even the correct PIN locked)")
auth.store.clear_fails(username="admin")

# PIN + TOTP combined: PIN login leads to the TOTP step
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))
c2 = TestClient(app)
r = c2.post("/auth/pin", data={"username": "admin", "pin": "13579", "next": "/secret"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/totp" in r.headers["location"]
assert c2.get("/secret").status_code == 401   # not full yet
r = c2.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/secret"}, follow_redirects=False)
assert r.status_code == 303 and c2.get("/secret").json()["u"] == "admin"
ok("PIN + TOTP combinable (PIN → 2nd factor)")

# remove
c3 = TestClient(app)
c3.post("/auth/pin", data={"username": "admin", "pin": "13579"}, follow_redirects=False)
# A TOTP code has applied exactly ONCE since 0.18.0. The same code was already consumed above —
# so here the next time step (lies within the permitted window).
c3.post("/auth/totp", data={"code": pyotp.TOTP(secret).at(int(time.time()) + 30)},
        follow_redirects=False)
assert c3.post("/auth/pin/disable").json()["ok"] is True
assert not auth.has_pin(uid)
ok("PIN removed")

os.remove(db)
print("\nPIN OK ✅")
