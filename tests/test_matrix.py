"""Phase 9: combination matrix — features individually/off/combined, without interfering with each other.

Checks the guideline: every capability works alone, can be switched off (then no route/no
behaviour) and can be combined with the others."""
import os
import tempfile
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pyotp
import time
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def absent(c, path):
    """True if the route does not exist (404). GET, without following redirects."""
    return c.get(path, follow_redirects=False).status_code == 404


# ---------- EVERYTHING OFF: only base routes, no optional ones ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
a = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False,
                              pin_enabled=False, magiclink_enabled=False, allow_signup=False,
                              resource_locks_enabled=False, forward_auth_enabled=False,
                              account_enabled=False, admin_enabled=False, cookie_secure=False))
app = FastAPI(); app.include_router(a.router())
c = TestClient(app, raise_server_exceptions=False)
for path in ("/auth/pin", "/auth/magic/request", "/auth/register", "/auth/resource/x",
             "/auth/forward", "/auth/account"):
    assert absent(c, path), f"{path} should be absent (404)"
assert c.get("/auth/login").status_code == 200
assert c.get("/auth/logout", follow_redirects=False).status_code in (303, 307)
os.remove(db)
ok("all optional features off → associated routes are missing (404), base stays")

# ---------- EVERYTHING ON: routes present, no collision ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
a = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", 
    db_path=db, passkey_enabled=False, oidc_enabled=False,
    pin_enabled=True, magiclink_enabled=True, allow_signup=True, resource_locks_enabled=True,
    forward_auth_enabled=True, account_enabled=True, admin_enabled=True,
    remember_me_enabled=True, cookie_secure=False, base_url="https://auth.example.com"))
a.set_mailer(lambda *x, **k: None)
a.ensure_admin("admin", "dummy123")
uid = a.store.get_user_by_name("admin")["id"]
a.set_pin(uid, "2468")
a.set_resource_secret("z", "1234", kind="pin", label="Z")
app = FastAPI(); app.include_router(a.router())
c = TestClient(app, raise_server_exceptions=False)
JSON = {"Accept": "application/json"}
for path in ("/auth/pin", "/auth/magic/request", "/auth/register", "/auth/resource/z",
             "/auth/forward", "/auth/account", "/auth/reauth"):
    assert not absent(c, path), f"{path} should be present"
assert c.get("/auth/login").status_code == 200
ok("all features on → all routes reachable, no collision")
secret = a.totp_begin(uid)["secret"]
a.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))

# PIN login → TOTP step (classic: PIN identifies, TOTP as 2nd factor)
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/totp" in r.headers["location"]
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
assert r.status_code == 303
# signed in: account page + forward-auth ok
assert "Konto · admin" in c.get("/auth/account").text
assert c.get("/auth/forward", headers={"X-Forwarded-Host": "app", "X-Forwarded-Uri": "/x"}).status_code == 200
# resource PIN independent of the login
c2 = TestClient(app)
assert c2.post("/auth/resource/z", data={"secret": "1234", "next": "/"}, follow_redirects=False).status_code == 303
ok("PIN+TOTP login, account page, forward auth and resource PIN usable at the same time")
os.remove(db)

# ---------- Feature on its own: only magic link (no password) ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
sent = []
a = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, password_enabled=False, passkey_enabled=False,
                              oidc_enabled=False, magiclink_enabled=True, cookie_secure=False,
                              base_url="https://auth.example.com"))   # mail link, see R4-01
a.set_mailer(lambda to, s, t, html=None: sent.append(t))
a.create_user("nurmail", email="m@example.com")
app = FastAPI(); app.include_router(a.router())
c = TestClient(app)
# no password login
assert c.post("/auth/login", data={"username": "nurmail", "password": "x"}).status_code == 404
# Magic link works on its own
c.post("/auth/magic/request", data={"email": "m@example.com", "next": "/"})
import re
tok = re.search(r"/auth/magic/([\w\-]+)", sent[0]).group(1)
assert c.post(f"/auth/magic/{tok}", follow_redirects=False).status_code == 303   # R4-02: POST redeems
os.remove(db)
ok("only magic link (password off): password login 404, magic login works alone")

print("\nKOMBINATIONS-MATRIX OK ✅")
