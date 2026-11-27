"""Follow-ups to attack round B and sign-in hardening H4, before 0.26.0.

* **Invitation lifetime**: an invitation without an own `ttl_min` lives `invite_ttl_min` (24 h), no longer the
  10 minutes of `magiclink_ttl_min`; the reset link keeps the 10 minutes. Both bounded by `signin_link_max_ttl_min`.
* **Recovery code is no step-up**: `login_totp` on a full session takes a TOTP code only — like the confirmation page.
* **Admin panel, new accounts and admin rights**: `POST /api/users` with a password or `is_admin`, and making an
  account admin through `/roles`, want a fresh confirmation also with `admin_require_mfa=False`.
* **`/auth/claim-admin`**: only from a fresh interactive session, never from an API key (a service account's key
  made that account admin and owner, and the first-admin path was closed for good).

Each rule has its mutation in the pull request.
"""
import os
import sys
import tempfile
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, config_check  # noqa: E402

BASE = "https://auth.example.com"
PW = "a long probe password 4711"
JSON = {"Accept": "application/json"}
HTML = {"Accept": "text/html"}
STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
               passkey_enabled=False, oidc_enabled=False, cookie_secure=False, base_url=BASE,
               apikey_enabled=True, stepup_max_age_sec=900)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def session_client(auth, app, uid, *, age=0, method="password", factors=None, full=True):
    """A session for `uid` whose sign-in and last confirmation lie `age` seconds back (`full=False`: a half one)."""
    c = TestClient(app)
    tok = auth.store.create_session(uid, 86400, full, method, factors=factors or [method])
    then = int(time.time()) - age
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def expires_in(auth, raw):
    row = auth.store._one("SELECT expires_at FROM magic_token WHERE token_hash=?",
                          (auth.store.token_digest(raw, "magic"),))
    return row["expires_at"] - time.time()


def errors_of(**over):
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), **over)
    return config_check.check_config(cfg)[0]


# ══ Invitation lifetime ═════════════════════════════════════════════════════════════════════════
auth, app = build(magiclink_enabled=True, allow_signup=True)
assert auth.cfg.invite_ttl_min == 24 * 60 and auth.cfg.magiclink_ttl_min == 10
left = expires_in(auth, auth.create_invite("guest@example.com", BASE)["token"])
assert 24 * 3600 - 10 <= left <= 24 * 3600 + 5, left
assert 3600 - 10 <= expires_in(auth, auth.create_invite(None, BASE, ttl_min=60)["token"]) <= 3600 + 5
for bad in (0, 24 * 60 + 1, "60", 1.5, True):
    try:
        auth.create_invite(None, BASE, ttl_min=bad)
        raise AssertionError(f"ttl_min={bad!r} was accepted")
    except ValueError as e:
        assert "1440" in str(e) or "ttl_min" in str(e), str(e)
# The reset link stays at magiclink_ttl_min (10 minutes, OWASP: short-lived) — it is the account's way back in.
uid = auth.create_user("rita", password=PW, email="rita@example.com")
sent = []
auth._token_mail = lambda raw, *a, **k: sent.append(raw)   # the mail itself is not the point here
assert auth.send_password_reset("rita@example.com", BASE) and len(sent) == 1
assert 600 - 10 <= expires_in(auth, sent[0]) <= 600 + 5, expires_in(auth, sent[0])
ok("invitation: 24 h by default, own ttl_min honoured and bounded (1…signin_link_max_ttl_min); reset link 10 min")

# The panel: the bound is a 400 with the reason, not a 500; without a value the 24 h apply.
auth_p, app_p = build(magiclink_enabled=True, allow_signup=True)
auth_p.ensure_admin("root", PW)
root = auth_p.store.get_user_by_name("root")["id"]
adm = session_client(auth_p, app_p, root, age=5)
for body in ({"ttl_min": 24 * 60 + 1}, {"ttl_min": "abc"}):
    r = adm.post("/auth/admin/api/invite", headers=JSON, json=body)
    assert r.status_code == 400, (body, r.status_code, r.text[:200])
r = adm.post("/auth/admin/api/invite", headers=JSON, json={"email": ""})
assert r.status_code == 200, r.text[:200]
raw = r.json()["url"].rsplit("/", 1)[1]
assert 24 * 3600 - 10 <= expires_in(auth_p, raw) <= 24 * 3600 + 5
ok("panel invitation: 24 h without a value, an out-of-range ttl_min is a 400")

# config_check: a range of its own, and the bound of every hand-over link above it.
assert any("invite_ttl_min" in e for e in errors_of(invite_ttl_min=0))
assert any("invite_ttl_min" in e for e in errors_of(invite_ttl_min=7 * 24 * 60 + 1))
assert any("below invite_ttl_min" in e for e in errors_of(allow_signup=True, signin_link_max_ttl_min=60))
assert not any("below invite_ttl_min" in e for e in errors_of(allow_signup=True))
assert not any("below invite_ttl_min" in e for e in errors_of(signin_link_max_ttl_min=60)), \
    "without self-registration no invitation is redeemed — no reason to refuse the setup"
assert any("invite_ttl_min" in e for e in config_check.check_config(TinySesamConfig(
    db_path=":memory:", allow_signup=True, signin_link_max_ttl_min=60, lang="de"))[0])
ok("config_check: invite_ttl_min 1…10080, and not above signin_link_max_ttl_min with allow_signup (en+de)")


# ══ Recovery code: emergency way in, not a step-up ══════════════════════════════════════════════
auth, app = build(totp_enabled=True, login_chain=["password", "totp"])
tina = auth.create_user("tina", password=PW)
secret = auth.totp_begin(tina)["secret"]
auth.store.confirm_totp(tina)
codes = auth.generate_recovery_codes(tina)
stale = session_client(auth, app, tina, age=STALE, factors=["password", "totp"])
assert not auth.stepup_options(auth.get_user(tina)).count("recovery")
r = stale.post("/auth/totp", data={"code": codes[0], "next": "/"}, headers=JSON, follow_redirects=False)
assert r.status_code == 401, (r.status_code, r.text[:200])
assert auth.recovery_codes_remaining(tina) == len(codes), "the refused code must not be used up"
assert stale.post("/auth/apikeys", headers=JSON, json={"name": "k"}).status_code == 403, "still not fresh"
assert not [a for a in auth.store.recent_audit(100) if a["event"] == "recovery_used"]
# The confirmation page has always refused it — the two agree now.
r = stale.post("/auth/reauth", data={"code": codes[0], "next": "/"}, follow_redirects=False)
assert r.status_code == 401 and auth.recovery_codes_remaining(tina) == len(codes), r.status_code
# A TOTP code still confirms on the same route.
r = stale.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
assert r.status_code == 303, (r.status_code, r.text[:200])
stale.cookies.set(auth.session_cookie_name, r.cookies.get(auth.session_cookie_name) or stale.cookies.get(auth.session_cookie_name))
assert stale.post("/auth/apikeys", headers=JSON, json={"name": "k"}).status_code == 200
ok("recovery code on a full session: refused (401, not used up, not fresh) — like /auth/reauth; a TOTP code confirms")

# The emergency way in stays: a half session after the password completes with a recovery code.
half = session_client(auth, app, tina, factors=["password"], full=False)
r = half.post("/auth/totp", data={"code": codes[1], "next": "/"}, follow_redirects=False)
assert r.status_code == 303, (r.status_code, r.text[:200])
assert auth.recovery_codes_remaining(tina) == len(codes) - 1
half.cookies.set(auth.session_cookie_name, r.cookies.get(auth.session_cookie_name))
assert half.get("/auth/me", headers=JSON).json().get("username") == "tina"
ok("recovery code on a half session: still the way in when the authenticator is gone")


# ══ Admin panel: new accounts with a password or admin rights, promotion to admin ═══════════════
auth, app = build(admin_require_mfa=False)
auth.ensure_admin("root", PW)
root = auth.store.get_user_by_name("root")["id"]
mine = auth.create_user("mallory", password=PW)       # an account the holder of the stolen session controls
ADMIN = "/auth/admin/api"
old_admin = session_client(auth, app, root, age=STALE)
refused = {"account with a password": {"username": "p1", "password": "an admin chosen password 4711"},
           "admin account": {"username": "a1", "is_admin": True}}
for what, body in refused.items():
    r = old_admin.post(f"{ADMIN}/users", headers=JSON, json=body)
    assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth"), (what, r.status_code, r.text[:200])
    assert auth.store.get_user_by_name(body["username"]) is None, what
r = old_admin.post(f"{ADMIN}/users/{mine}/roles", headers=JSON, json={"roles": [], "is_admin": True})
assert r.status_code == 403 and not auth.store.get_user(mine)["is_admin"], (r.status_code, r.text[:200])
# What gives nobody access yet stays open to the stale session: an account without a password, roles only.
assert old_admin.post(f"{ADMIN}/users", headers=JSON, json={"username": "sso1"}).status_code == 200
assert old_admin.post(f"{ADMIN}/users", headers=JSON, json={"username": "svc1", "is_service": True}).status_code == 200
assert old_admin.post(f"{ADMIN}/users/{mine}/roles", headers=JSON, json={"roles": ["editor"]}).status_code == 200
ok("admin_require_mfa=False: a stale admin session creates no account with password or admin rights and promotes nobody")
fresh_admin = session_client(auth, app, root, age=5)
for what, body in refused.items():
    assert fresh_admin.post(f"{ADMIN}/users", headers=JSON, json=body).status_code == 200, what
r = fresh_admin.post(f"{ADMIN}/users/{mine}/roles", headers=JSON, json={"roles": [], "is_admin": True})
assert r.status_code == 200 and auth.store.get_user(mine)["is_admin"], r.text[:200]
# Taking the flag away is no new access — the stale session may (with another admin left).
r = old_admin.post(f"{ADMIN}/users/{mine}/roles", headers=JSON, json={"roles": [], "is_admin": False})
assert r.status_code == 200 and not auth.store.get_user(mine)["is_admin"], r.text[:200]
ok("… a fresh one gets through; revoking admin rights needs no fresh confirmation")


# ══ /auth/claim-admin: session only, fresh only ═════════════════════════════════════════════════
def claim_setup():
    auth, app = build(admin_enabled=True)
    assert not auth.admin_exists()
    return auth, app, auth.admin_claim_token()


auth, app, token = claim_setup()
svc = auth.create_service("ci")
svc_key = auth.create_api_key(svc, name="ci")["key"]
bob = auth.create_user("bob", password=PW)
bob_key = auth.create_api_key(bob, name="cli")["key"]
anon = TestClient(app)
for key in (svc_key, bob_key):
    r = anon.get(f"/auth/claim-admin?token={token}", headers={"X-API-Key": key, **JSON}, follow_redirects=False)
    # Refused as a key ("needs a session"), not only because a key is never fresh: the account is never read
    # from the key in the first place.
    assert r.status_code == 403 and r.json().get("detail") == auth.t("api.needs_session"), (r.status_code, r.text[:200])
assert not auth.admin_exists() and auth.admin_claim_token() == token, "the token must stay unused"
ok("claim-admin: an API key (service account or person) claims nothing — 403, token unused")

stale = session_client(auth, app, bob, age=STALE)
r = stale.get(f"/auth/claim-admin?token={token}", headers=HTML, follow_redirects=False)
target = "/auth/reauth?next=" + quote(f"/auth/claim-admin?token={token}", safe="")
assert r.status_code == 303 and r.headers["location"] == target, (r.status_code, r.headers.get("location"))
assert not auth.admin_exists()
r = stale.post("/auth/reauth", data={"password": PW, "next": f"/auth/claim-admin?token={token}"},
               follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == f"/auth/claim-admin?token={token}", r.headers.get("location")
r = stale.get(f"/auth/claim-admin?token={token}", follow_redirects=False)
assert r.status_code == 303 and auth.store.get_user(bob)["is_admin"] and auth.store.get_user(bob)["is_owner"]
ok("claim-admin: a stale session goes through the confirmation page and back, then becomes admin and owner")

# An account without anything to confirm with (no password, no factor) whose sign-in is old: sign in again.
auth, app, token = claim_setup()
ghost = auth.create_user("ghost")
old = session_client(auth, app, ghost, age=STALE, method="passkey")
r = old.get(f"/auth/claim-admin?token={token}", headers=JSON, follow_redirects=False)
assert r.status_code == 403 and not auth.admin_exists(), (r.status_code, r.text[:200])
assert session_client(auth, app, ghost, age=5, method="passkey").get(
    f"/auth/claim-admin?token={token}", follow_redirects=False).status_code == 303 and auth.admin_exists()
ok("claim-admin: without anything to confirm with, an old sign-in is refused and a fresh one claims")
