"""Attack round B (2026-11-21): a sign-in link refreshes a stale full session — step-up without a factor.

`apply_factor()` attaches every factor to a running session of the same account; on a session that is already
full it counts as a step-up (`mfa_at` anew, token rotated). The factor `magic` (sign-in link, admin-issued
link, cross-device approval) is no step-up method — `stepup_options()` never names it, and a link alone does
not even sign in an account with TOTP (`magiclink_require_second_factor`). Redeemed in a browser that holds a
stale session cookie, it still makes the session fresh, and `_require_fresh` (B-12) lets a new API key, passkey,
app password or service pairing through.

Attacker: a stolen session cookie whose confirmation has expired, plus one sign-in link of the account (mailbox
access with `magiclink_self_request`, or a link an admin handed out). Without the cookie the same link stops at
the TOTP step; without the link the cookie gets 403 `stepup`.
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
    oidc_enabled=False, cookie_secure=False, magiclink_enabled=True, apikey_enabled=True,
    base_url="https://auth.example.com", stepup_max_age_sec=900))
uid = auth.create_user("carol", password="a long probe password 4711", email="carol@example.com")
auth.totp_confirm(uid, pyotp.TOTP(auth.totp_begin(uid)["secret"]).at(time.time() - 30))
app = FastAPI()
app.include_router(auth.router())

# Without a session the link stops at the TOTP step.
fresh = TestClient(app)
raw = auth.create_magic_token("login", user_id=uid, payload={"next": "/"})
r = fresh.post(f"/auth/magic/{raw}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp"), r.headers.get("location")
assert fresh.get("/auth/me").status_code == 401
ok("baseline: the link alone does not sign in an account with TOTP")

# The stolen cookie: a full session (password + TOTP), last confirmation two hours ago.
c = TestClient(app)
tok = auth.store.create_session(uid, 86400, True, "password", factors=["password", "totp"])
then = int(time.time()) - 7200
auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                 (then, then, auth.store.session_hash(tok)))
c.cookies.set(auth.session_cookie_name, tok)
assert c.post("/auth/apikeys", json={"name": "x"}).status_code == 403
ok("baseline: the stale session cannot create an API key (step-up demanded)")

raw = auth.create_magic_token("login", user_id=uid, payload={"next": "/"})
c.post(f"/auth/magic/{raw}", follow_redirects=False)
r = c.post("/auth/apikeys", json={"name": "persistence"})
assert r.status_code == 403, (
    f"the sign-in link made the stale session fresh: POST /auth/apikeys → {r.status_code} "
    "(a link is no step-up factor — stepup_options() does not name it)")
ok("a sign-in link redeemed in a stale session is no step-up")
