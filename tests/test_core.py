"""End-to-end test of the password + TOTP core via FastAPI TestClient (without browser)."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import time
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False,
                                 oidc_enabled=False, cookie_secure=False))
assert auth.ensure_admin("admin", "dummy123"), "admin should be created"
assert not auth.ensure_admin("x", "y"), "second ensure_admin must do nothing"

app = FastAPI()
app.include_router(auth.router())


@app.get("/secret")
def secret_text(u=Depends(auth.require_user)):
    return {"user": u["username"], "admin": bool(u["is_admin"])}


c = TestClient(app)


def ok(name):
    print(f"  ✓ {name}")


# 1) without login → 401 (JSON client)
assert c.get("/secret").status_code == 401
ok("protected without login → 401")

# 2) login page renders
r = c.get("/auth/login")
assert r.status_code == 200 and "Passwort" in r.text
ok("login page")

# 3) wrong password
assert c.post("/auth/login", data={"username": "admin", "password": "wrong", "next": "/secret"}).status_code == 401
ok("wrong password → 401")

# 4) correct password (no TOTP yet) → 303 + cookie, no MFA
r = c.post("/auth/login", data={"username": "admin", "password": "dummy123", "next": "/secret"}, follow_redirects=False)
assert r.status_code == 303 and "set-cookie" in {k.lower() for k in r.headers}
ok("login without 2FA → logged in")

# 5) protected now reachable
r = c.get("/secret")
assert r.status_code == 200 and r.json()["user"] == "admin"
ok("protected reachable with session")
assert c.get("/auth/me").json()["authenticated"] is True
ok("/auth/me authenticated")

# 6) set up TOTP
uid = auth.store.get_user_by_name("admin")["id"]
secret = auth.totp_begin(uid)["secret"]
assert auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30)) and auth.store.has_confirmed_totp(uid)
ok("TOTP set up")

# 7) logout → login is now MFA-required
c.get("/auth/logout")
r = c.post("/auth/login", data={"username": "admin", "password": "dummy123", "next": "/secret"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/totp" in r.headers["location"]
assert c.get("/secret").status_code == 401, "with 2FA pending not yet fully logged in"
ok("login with TOTP → 2FA step required")

# 8) wrong + correct TOTP code
assert c.post("/auth/totp", data={"code": "000000", "next": "/secret"}).status_code == 401
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/secret"}, follow_redirects=False)
assert r.status_code == 303
assert c.get("/secret").json()["user"] == "admin"
ok("TOTP correct → fully signed in")

# 9) roles (optional)
auth.set_roles(uid, ["editor"])
u = auth.store.get_user(uid)
assert auth.has_role(u, "editor") and auth.has_role(u, "something")  # admin ⇒ all roles
auth.store.set_disabled(uid, False)
ok("roles + admin override")

# ---------- B2-3: the setup code is consumed ----------
# Until T-13 `totp_confirm` did not book the time step: the same code, just typed
# in for the setup, still signed in for up to 90 seconds afterwards. (Mutation probe: in `totp_confirm`
# `_totp.verify(...)` instead of `matching_step` + `consume_totp_step` → red.)
db_b = os.path.join(tempfile.mkdtemp(), "b.db")
auth_b = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_b, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False))
uid_b = auth_b.create_user("berta", "berta-secret-1")
_event = []
auth_b.on_security_event = lambda e, k, d: _event.append(e)
secret_text_b = auth_b.totp_begin(uid_b)["secret"]
code_b = pyotp.TOTP(secret_text_b).now()
assert auth_b.totp_confirm(uid_b, code_b)
assert not auth_b._verify_totp(uid_b, code_b), "the setup code still signs in afterwards"
assert not auth_b.totp_confirm(uid_b, code_b), "…and confirms a second time"
assert _event == ["totp_enabled"], _event
assert any(z["event"] == "totp_enable" for z in auth_b.store.recent_audit(20))
ok("B2-3: the setup code applies exactly once (afterwards not at /auth/totp either)")

# ---------- B2-12 / R3-6: throttle, own bucket and log at the setup confirmation ----------
# (Mutation probe: remove the `is_totp_setup_locked` query in router.totp_setup_confirm → red.)
auth_b.totp_disable(uid_b)
app_b = FastAPI()
app_b.include_router(auth_b.router())
cb = TestClient(app_b)
assert cb.post("/auth/login", data={"username": "berta", "password": "berta-secret-1"},
               follow_redirects=False).status_code == 303
secret_text_b = auth_b.totp_begin(uid_b)["secret"]
limit = auth_b._sec("totp_setup_max_attempts")
responses = [cb.post("/auth/totp/setup", data={"code": "000000"}).json().get("ok") for _ in range(limit)]
assert responses == [False] * limit, responses
r = cb.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret_text_b).now()})
assert r.status_code == 429, f"after {limit} failed attempts the confirmation must lock, was {r.status_code}"
assert not auth_b.store.has_confirmed_totp(uid_b)
fail = [z for z in auth_b.store.recent_audit(50) if z["event"] == "login_fail" and "totp_setup" in (z["detail"] or "")]
assert len(fail) >= limit, "every failed attempt is in the audit log"
# Own bucket: the sign-in of the same account stays open.
assert not auth_b._is_locked("berta", "testclient")
assert TestClient(app_b).post("/auth/login", data={"username": "berta", "password": "berta-secret-1"},
                              follow_redirects=False).status_code == 303
ok("B2-12/R3-6: setup confirmation throttled, locked, logged — login stays open")
os.remove(db_b)

os.remove(db)
print("\nALL TESTS OK ✅")
