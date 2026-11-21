"""Attack round B (2026-11-21): the password alone sets up TOTP past an existing PIN.

With alternatives in a chain (T-34), `login_chain=["password", "totp|pin"]`, an account that has a password
and a PIN signs in with both. `totp_enrollment_user()` lets the half session after the password set up TOTP
whenever the chain names `totp` and the account has no confirmed TOTP; it only asks for a passkey the account
already has, not for a PIN. So whoever knows only the password sets up an own TOTP, the confirmation code
completes the chain, and the session is full — the PIN was never asked, and the attacker keeps a second factor
plus recovery codes. Open while self-setup is allowed: `mfa_enrollment="grace"` (days after creation) or
`"first_login"` (an account whose PIN came from the operator or app code before its first full sign-in).

The setup pass after a sign-in link has the right rule (`_setup_owed`: a factor the account HAS for a step is
provided before anything is set up); the mandatory TOTP setup in a chain lacks it.
"""
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

PASSWORD = "a long probe password 4711"
JSON = {"Accept": "application/json"}


def ok(name):
    print(f"  ✓ {name}")


for mode in ("grace", "first_login"):
    auth = TinySesam(TinySesamConfig(
        csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
        oidc_enabled=False, cookie_secure=False, pin_enabled=True, login_chain=["password", "totp|pin"],
        mfa_enrollment=mode))
    uid = auth.create_user("bob", password=PASSWORD)
    auth.set_pin(uid, "735194")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/secret")
    def secret_page(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    c = TestClient(app)
    r = c.post("/auth/login", data={"username": "bob", "password": PASSWORD, "next": "/secret"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/auth/pin"), r.headers.get("location")
    assert c.get("/secret", headers=JSON).status_code == 401
    ok(f"{mode}: after the password the chain asks for the PIN the account has")

    # The attacker does not go to /auth/pin but to the TOTP setup.
    r = c.post("/auth/totp/setup/start", data={"next": "/secret"})
    found = re.search(r"\b([A-Z2-7]{32})\b", r.text) if r.status_code == 200 else None
    if found:
        code = pyotp.TOTP(found.group(1)).at(time.time() - 30)
        c.post("/auth/totp/setup", data={"code": code, "next": "/secret"})
    status = c.get("/secret", headers=JSON).status_code
    assert status == 401 and not auth.store.has_confirmed_totp(uid), (
        f"{mode}: the half session with only the password set up TOTP and got through "
        f"(/secret → {status}, TOTP confirmed: {auth.store.has_confirmed_totp(uid)}) — the PIN was never asked")
    ok(f"{mode}: the half session cannot set up TOTP past the PIN the account already has")

# The same door from the mailbox: a sign-in link gives a half session with `magic` only (no setup pass — the
# account lacks nothing). It must not bind an own TOTP to an account that protected itself with a PIN (the rule
# of ASVS 6.3.6 that `totp_enrollment_user` applies to a passkey).
auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
    oidc_enabled=False, cookie_secure=False, pin_enabled=True, magiclink_enabled=True,
    base_url="https://auth.example.com", login_chain=["password", "totp|pin"], mfa_enrollment="grace"))
uid = auth.create_user("fred", password=PASSWORD)
auth.set_pin(uid, "735194")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)
raw = auth.create_magic_token("login", user_id=uid, payload={"next": "/"})
r = c.post(f"/auth/magic/{raw}", follow_redirects=False)
assert r.status_code == 303 and not r.headers["location"].startswith("/auth/setup"), r.headers.get("location")
r = c.post("/auth/totp/setup/start", data={"next": "/"})
found = re.search(r"\b([A-Z2-7]{32})\b", r.text) if r.status_code == 200 else None
if found:
    c.post("/auth/totp/setup", data={"code": pyotp.TOTP(found.group(1)).at(time.time() - 30), "next": "/"})
assert not auth.store.has_confirmed_totp(uid), (
    "a sign-in link alone (mailbox) bound an own TOTP to an account that has a PIN for that step")
ok("a sign-in link alone cannot bind a TOTP past the account's PIN")
