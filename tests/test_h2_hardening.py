"""H2 — hardening part 2 (security review 2026-11-20): B-12, T-44, T-45, T-46, T-47.

* **B-12** (ASVS 7.5.1, NIST SP 800-63B-4 §4.1.2.1): a session without a fresh confirmation creates no new
  way into the account — no passkey, no TOTP, no PIN, no API key, no cross-device approval, no OAuth
  consent. The setup pass after a sign-in link and the mandatory TOTP setup in a chain stay possible.
* **T-44** (RFC 10027 §6.1): cross-device approval only with the number from the other screen, only for an
  account with a second factor (switch), only fresh; `/auth/qr/status` throttled; a warning on the page.
* **T-45**: `admin_require_mfa` on by default — an old admin session confirms first; `config_check` warns
  when it is switched off; an account with nothing to confirm with is told to sign in again.
* **T-46** (ASVS 6.4.1): a password the admin set is a start secret — the next password sign-in stays half
  until the holder chose an own one.
* **T-47**: the holder learns of new access — hook, mail (only with a mailer, no link), account page.

Each rule has its mutation in the PR; the guard at the end pins that every route that creates new access
goes through the one bolt (`_require_fresh`).
"""
import ast
import os
import pathlib
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import config_check  # noqa: E402
from tinysesam.messages import MESSAGES  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = "https://auth.example.com"
JSON = {"Accept": "application/json"}
HTML = {"Accept": "text/html"}


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
               passkey_enabled=False, oidc_enabled=False, cookie_secure=False, base_url=BASE,
               apikey_enabled=True, pin_enabled=True, stepup_max_age_sec=900)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/who")
    def who(u=Depends(auth.require_user)):
        return {"u": u["username"]}
    return auth, app


def session_client(auth, app, uid, *, age=0, method="password", factors=None):
    """A FULL session for `uid` whose sign-in and last confirmation lie `age` seconds back."""
    c = TestClient(app)
    tok = auth.store.create_session(uid, 86400, True, method, factors=factors or [method])
    then = int(time.time()) - age
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def who(c):
    r = c.get("/who", headers=JSON)
    return r.json().get("u") if r.status_code == 200 else None


def audit(auth, event):
    return [a for a in auth.store.recent_audit(300) if a["event"] == event]


STALE = 100000

# =====================================================================================
# B-12 — new access only from a fresh confirmation
# =====================================================================================
auth, app = build()
anna = auth.create_user("anna", password="anna-pw-12345", email="anna@example.com")
assert not auth.store.has_confirmed_totp(anna)

# (a) stale session of an account WITH something to confirm with (password): 403 + reauth hint, nothing made
stale = session_client(auth, app, anna, age=STALE)
assert who(stale) == "anna", "the stale session is a valid session — only not fresh"
attempts = {
    "/auth/apikeys": dict(json={"name": "stolen"}),
    "/auth/totp/setup/start": dict(data={}),
    "/auth/totp/setup": dict(data={"code": "000000"}),
    "/auth/pin/set": dict(json={"pin": "48151623"}),
}
for path, kw in attempts.items():
    r = stale.post(path, headers=JSON, **kw)
    assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", \
        (path, r.status_code, r.text[:160])
assert not auth.list_api_keys(anna) and not auth.has_pin(anna) and not auth.store.has_confirmed_totp(anna)
assert auth.store._one("SELECT COUNT(*) AS n FROM totp_cred WHERE user_id=?", (anna,))["n"] == 0, \
    "a stale session must not even get a TOTP secret"
ok("B-12: a stale session creates no API key, no TOTP (not even the secret) and no PIN — 403 + reauth hint")

# The TOTP setup PAGE sends a stale browser session to the reauth page and back (path AND query).
r = stale.get("/auth/totp/setup?next=/who", headers=HTML, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/reauth?next=" + quote("/auth/totp/setup?next=/who", safe=""), \
    r.headers.get("location")
r = stale.post("/auth/reauth", data={"password": "anna-pw-12345", "next": "/auth/totp/setup?next=/who"},
               follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/totp/setup?next=/who", r.headers.get("location")
assert stale.get("/auth/totp/setup?next=/who", headers=HTML, follow_redirects=False).status_code == 200
ok("B-12: the TOTP setup page goes through the reauth page and comes back to itself")

# (b) after the confirmation (and right after a sign-in) the same calls go through
k = stale.post("/auth/apikeys", headers=JSON, json={"name": "ci"})
assert k.status_code == 200 and k.json().get("key"), (k.status_code, k.text[:160])
assert stale.post("/auth/pin/set", headers=JSON, json={"pin": "48151623"}).status_code == 200
start = stale.post("/auth/totp/setup/start", headers=HTML, data={})
assert start.status_code == 200, start.status_code
secret = re.search(r"class=mono>([A-Z2-7]{16,})<", start.text).group(1)
r = stale.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret).now()})
assert r.status_code == 200 and r.json()["ok"] is True, r.text[:200]
fresh = TestClient(app)
assert fresh.post("/auth/login", data={"username": "anna", "password": "anna-pw-12345"},
                  follow_redirects=False).status_code == 303
ok("B-12: after the step-up the API key, the PIN and the TOTP come into being (and a fresh sign-in counts as fresh)")

# (c) an account with NOTHING to confirm with (federated): the age of the sign-in counts, no reauth hint
fed = auth.create_user("fed", password=None)
r = session_client(auth, app, fed, age=STALE, method="oidc").post("/auth/apikeys", headers=JSON, json={"name": "x"})
assert r.status_code == 403 and r.json()["detail"] == auth.t("api.stepup_relogin") \
    and "X-TinySesam-Reauth" not in r.headers, (r.status_code, r.text[:160])
r = session_client(auth, app, fed, age=10, method="oidc").post("/auth/apikeys", headers=JSON, json={"name": "x"})
assert r.status_code == 200, r.text[:160]
ok("B-12: a federated account depends on the age of its sign-in (403 'sign in again', no reauth hint)")

# (d) an API key never creates new access
r = TestClient(app).post("/auth/apikeys", headers={**JSON, "Authorization": f"Bearer {k.json()['key']}"},
                         json={"name": "child"})
assert r.status_code == 403, r.status_code
ok("B-12: an API key mints no API key")

# (e) the mandatory TOTP setup in a chain (half session) stays possible — fresh from the sign-in
auth_c, app_c = build(login_chain=["password", "totp"])
auth_c.create_user("newcomer", password="fresh-pw-123456")
c = TestClient(app_c)
r = c.post("/auth/login", data={"username": "newcomer", "password": "fresh-pw-123456"}, follow_redirects=False)
assert r.headers["location"].startswith("/auth/totp"), r.headers.get("location")
start = c.post("/auth/totp/setup/start", headers=HTML, data={})
assert start.status_code == 200, start.status_code
secret = re.search(r"class=mono>([A-Z2-7]{16,})<", start.text).group(1)
r = c.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret).now()})
assert r.status_code == 200 and r.json()["ok"] is True, r.text[:200]
assert who(c) == "newcomer"
ok("B-12: the mandatory TOTP setup in a chain is not asked again (half session, fresh from the password)")

# (f) OAuth consent: allowing a program is new access too
RESOURCE = "https://app.example.com/mcp"
CB = "http://localhost:43123/callback"
auth_o, app_o = build(forward_auth_enabled=True, oauth_enabled=True, oauth_resources=[RESOURCE],
                      trusted_redirect_hosts=["app.example.com"], csrf_enabled=True)
olga = auth_o.create_user("olga", password="olga-pw-12345")
oc = session_client(auth_o, app_o, olga, age=STALE)
oc.follow_redirects = False
cid = oc.post("/auth/oauth/register", json={
    "client_name": "probe", "redirect_uris": [CB], "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"], "token_endpoint_auth_method": "none"}).json()["client_id"]
params = {"response_type": "code", "client_id": cid, "redirect_uri": CB, "code_challenge": "x" * 43,
          "code_challenge_method": "S256", "state": "s", "scope": "mcp", "resource": RESOURCE}
loc = oc.get("/auth/oauth/authorize", params=params).headers["location"]
txn = parse_qs(urlsplit(loc).query)["txn"][0]
r = oc.get(loc)
assert r.status_code == 303 and r.headers["location"] == "/auth/reauth?next=" + quote(f"/auth/oauth/consent?txn={txn}", safe=""), \
    (r.status_code, r.headers.get("location"))
reauth_page = oc.get(r.headers["location"])                 # sets the CSRF cookie, as a browser would see it
csrf = re.search(r"name=_csrf value='([^']*)'", reauth_page.text).group(1)
r = oc.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": txn, "decision": "allow"})
assert r.status_code == 303 and r.headers["location"].startswith("/auth/reauth?next="), (r.status_code, r.headers.get("location"))
assert not auth_o.store._all("SELECT * FROM oauth_code"), "a stale session must not get an authorization code"
r = oc.post("/auth/reauth", data={"_csrf": csrf, "password": "olga-pw-12345", "next": f"/auth/oauth/consent?txn={txn}"})
assert r.status_code == 303, r.status_code
page = oc.get(f"/auth/oauth/consent?txn={txn}")
assert page.status_code == 200, page.status_code
csrf = re.search(r"name=_csrf value='([^']*)'", page.text).group(1)
r = oc.post("/auth/oauth/consent", data={"_csrf": csrf, "txn": txn, "decision": "allow"})
assert r.status_code == 303 and "code=" in r.headers["location"], r.headers.get("location")
ok("B-12: OAuth consent — stale → reauth (page and answer), no code; after it the consent goes through")

# =====================================================================================
# T-44 — QR approval: number matching, second factor, freshness, throttle
# =====================================================================================
auth, app = build(qr_login_enabled=True)
bob = auth.create_user("bob", password="bob-pw-123456")             # no second factor
tina = auth.create_user("tina", password="tina-pw-12345")           # TOTP
auth.totp_begin(tina)
auth.store.confirm_totp(tina)


def qr_start():
    dev = TestClient(app)
    r = dev.post("/auth/qr/start", data={"next": "/who"})
    code = re.search(r"name=code value='([A-Z0-9]{8})'", r.text).group(1)
    secret = re.search(r"name=secret value='([\w\-]+)'", r.text).group(1)
    match = re.search(r"id=qrmatch>(\d\d)<", r.text).group(1)
    assert auth.t("qr.match_hint") in r.text
    return dev, code, secret, match


def qr_state(dev, code, secret):
    return dev.post("/auth/qr/status", data={"code": code, "secret": secret}).json()["state"]


dev, code, secret, match = qr_start()
# The link carries the short code and nothing else. (Up to here the check was `match not in url` — but the eight
# random characters of the code contain a two-digit number now and then, and the suite went red by chance.)
_approve = urlsplit(auth._qr_links(code)["approve_url"])
assert _approve.path == "/auth/qr/approve" and parse_qs(_approve.query) == {"code": [code]}, _approve
ok("T-44: the new device shows a two-digit number — it is not part of the approval link")

# (a) default: an account without a second factor cannot approve
phone_b = session_client(auth, app, bob, age=5)
r = phone_b.get(f"/auth/qr/approve?code={code}")
assert r.status_code == 403 and auth.t("qr.needs_second_factor") in r.text, r.status_code
r = phone_b.post("/auth/qr/approve", data={"code": code, "match": match})
assert r.status_code == 403 and qr_state(dev, code, secret) == "pending", r.status_code
ok("T-44: qr_login_require_second_factor (default) — an account without TOTP/passkey does not approve")

# (b) the page warns, the number decides — a wrong one voids the request at once
phone_t = session_client(auth, app, tina, age=5, factors=["password", "totp"])
page = phone_t.get(f"/auth/qr/approve?code={code}")
assert page.status_code == 200 and auth.t("qr.warning") in page.text and "name=match" in page.text
wrong = "10" if match != "10" else "11"
r = phone_t.post("/auth/qr/approve", data={"code": code, "match": wrong})
assert r.status_code == 400 and auth.t("qr.mismatch") in r.text, r.status_code
assert qr_state(dev, code, secret) == "invalid", "a wrong number must void the request"
assert phone_t.post("/auth/qr/approve", data={"code": code, "match": match}).status_code == 400
assert audit(auth, "qr_login_mismatch")
r = phone_t.post("/auth/qr/approve", data={"code": qr_start()[1], "match": ""})
assert r.status_code == 400, "no number is a wrong number"
ok("T-44: warning on the page; a wrong (or missing) number voids the request — one guess only")

dev, code, secret, match = qr_start()
r = phone_t.post("/auth/qr/approve", data={"code": code, "match": match})
assert r.status_code == 200 and qr_state(dev, code, secret) == "approved", r.status_code
r = dev.post("/auth/qr/finish", data={"code": code, "secret": secret}, follow_redirects=False)
assert r.headers["location"].startswith("/auth/totp"), "the new device still owes tina's second factor"
ok("T-44: the right number approves; the new device still has to present the second factor")

# (c) freshness on the approving device
dev, code, secret, match = qr_start()
old_t = session_client(auth, app, tina, age=STALE, factors=["password", "totp"])
r = old_t.get(f"/auth/qr/approve?code={code}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/reauth?next=" + quote(f"/auth/qr/approve?code={code}", safe=""), \
    r.headers.get("location")
r = old_t.post("/auth/qr/approve", data={"code": code, "match": match}, headers=JSON)
assert r.status_code == 403 and qr_state(dev, code, secret) == "pending", r.status_code
ok("B-12/T-44: a stale approving session goes to the reauth page first; its POST is refused")

# (d) the status poll has its own throttle
from tinysesam import router as _router  # noqa: E402
from tinysesam import security as _security  # noqa: E402
limit = _router._QR_STATUS_PER_MINUTE
auth.rl = _security.RateLimiter()                    # the polls above count too — start from an empty bucket
codes = [dev.post("/auth/qr/status", data={"code": code, "secret": secret}).status_code for _ in range(limit + 3)]
assert codes[:limit] == [200] * limit and codes[-1] == 429, (codes.count(200), codes[-3:])
ok(f"T-44: /auth/qr/status is throttled ({limit}/min per address, then 429)")

# (e) the switch: accounts without a second factor may approve again — still with the number
auth_s, app_s = build(qr_login_enabled=True, qr_login_require_second_factor=False)
u = auth_s.create_user("solo", password="solo-pw-12345")
d = TestClient(app_s)
r = d.post("/auth/qr/start", data={"next": "/who"})
code = re.search(r"name=code value='([A-Z0-9]{8})'", r.text).group(1)
match = re.search(r"id=qrmatch>(\d\d)<", r.text).group(1)
assert session_client(auth_s, app_s, u, age=5).post("/auth/qr/approve", data={"code": code, "match": match}).status_code == 200
ok("T-44: qr_login_require_second_factor=False lets a single-factor account approve (number still required)")

# =====================================================================================
# T-45 — admin_require_mfa by default
# =====================================================================================
assert TinySesamConfig().admin_require_mfa is True and TinySesamConfig().admin_password_must_change is True
_, warn_off = config_check.check_config(TinySesamConfig(db_path=":memory:", admin_require_mfa=False))
_, warn_on = config_check.check_config(TinySesamConfig(db_path=":memory:"))
assert any("admin_require_mfa=False" in w for w in warn_off) and not any("admin_require_mfa" in w for w in warn_on)
_, warn_de = config_check.check_config(TinySesamConfig(db_path=":memory:", admin_require_mfa=False, lang="de"))
assert any("Admin-Panel" in w for w in warn_de), warn_de
ok("T-45: admin_require_mfa and admin_password_must_change default True; config_check warns when off (de+en)")

auth, app = build()
auth.ensure_admin("root", "root-pw-12345")
root = auth.store.get_user_by_name("root")["id"]
victim = auth.create_user("vic", password="vic-pw-123456")
old_admin = session_client(auth, app, root, age=STALE)
r = old_admin.get("/auth/admin", headers=HTML, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"].startswith("/auth/reauth"), (r.status_code, r.headers.get("location"))
r = old_admin.post(f"/auth/admin/api/users/{victim}/password", headers=JSON, json={"password": "taken-over-123"})
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth"), r.status_code
assert auth._check_password("vic", "vic-pw-123456"), "an old admin session must not set a password"
r = old_admin.post(f"/auth/admin/api/users/{victim}/signin-link", headers=JSON, json={})
assert r.status_code in (403, 404) and not auth.store.open_token(victim, "login")
assert old_admin.post("/auth/reauth", data={"password": "root-pw-12345", "next": "/auth/admin"},
                      follow_redirects=False).status_code == 303
assert old_admin.get("/auth/admin", headers=HTML).status_code == 200
ok("T-45: an old admin session gets panel and API only after the confirmation (password)")

# The panel follows the reauth hint instead of reporting an error.
panel = old_admin.get("/auth/admin", headers=HTML).text
assert 'r.headers.get("X-TinySesam-Reauth")' in panel and "location.href=re+" in panel
ok("T-45: the panel script goes to the reauth page on 403 + X-TinySesam-Reauth")

# An admin with nothing to confirm with (purely federated) is told to sign in again.
fed_admin = auth.create_user("fedadmin", password=None, is_admin=True)
fa = session_client(auth, app, fed_admin, age=STALE, method="oidc")
r = fa.get("/auth/admin", headers=HTML, follow_redirects=False)
assert r.status_code == 307
page = fa.get(r.headers["location"]).text
assert auth.t("err.stepup_relogin") in page and "/auth/logout" in page
assert session_client(auth, app, fed_admin, age=10, method="oidc").get("/auth/admin", headers=HTML).status_code == 200
ok("T-45: a federated admin is not locked out — fresh sign-in works, a stale one is told to sign in again")

# =====================================================================================
# T-46 — the administrator's password is a start secret
# =====================================================================================
fresh_admin = TestClient(app)
fresh_admin.post("/auth/login", data={"username": "root", "password": "root-pw-12345"}, follow_redirects=False)
r = fresh_admin.post("/auth/admin/api/users", headers=JSON,
                     json={"username": "newbie", "password": "start-secret-1", "email": "newbie@example.com"})
assert r.status_code == 200, r.text[:200]
newbie = r.json()["id"]
assert auth.store.password_must_change(newbie)

c = TestClient(app)
r = c.post("/auth/login", data={"username": "newbie", "password": "start-secret-1", "next": "/who"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/setup?next=/who", r.headers.get("location")
assert who(c) is None, "the start secret alone must not sign in fully"
page = c.get("/auth/setup?next=/who")
assert page.status_code == 200 and auth.t("onboard.renew_title") in page.text and "ob_pw1" in page.text
assert c.post("/auth/apikeys", headers=JSON, json={"name": "x"}).status_code in (401, 403)
r = c.post("/auth/password/set", headers=JSON, json={"new": "start-secret-1", "next": "/who"})
assert r.status_code == 400 and r.json()["detail"] == auth.t("api.password_same"), r.text[:200]
r = c.post("/auth/password/set", headers=JSON, json={"new": "short", "next": "/who"})
assert r.status_code == 400 and who(c) is None
r = c.post("/auth/password/set", headers=JSON, json={"new": "my-own-secret-77", "next": "/who"})
assert r.status_code == 200 and r.json()["next"] == "/who", r.text[:200]
assert who(c) == "newbie" and not auth.store.password_must_change(newbie)
assert audit(auth, "password_renewed")
c2 = TestClient(app)
assert c2.post("/auth/login", data={"username": "newbie", "password": "my-own-secret-77", "next": "/who"},
               follow_redirects=False).headers["location"] == "/who"
ok("T-46: new account with an admin password → half session → own password (not the same, by the rule) → in")

# The reset in the panel marks the same; the holder's own change clears it; the half session expires.
assert fresh_admin.post(f"/auth/admin/api/users/{newbie}/password", headers=JSON,
                        json={"password": "reset-secret-22"}).status_code == 200
assert auth.store.password_must_change(newbie)
c3 = TestClient(app)
r = c3.post("/auth/login", data={"username": "newbie", "password": "reset-secret-22"}, follow_redirects=False)
assert r.headers["location"].startswith("/auth/setup"), r.headers.get("location")
auth.store._exec("UPDATE session SET created_at=? WHERE token_hash=?",
                 (int(time.time()) - STALE, auth.store.session_hash(c3.cookies.get(auth.session_cookie_name))))
r = c3.get("/auth/setup", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login"), r.headers.get("location")
assert c3.post("/auth/password/set", headers=JSON, json={"new": "late-secret-333"}).status_code == 401
auth.set_password(newbie, "holder-chosen-44")
assert not auth.store.password_must_change(newbie)
ok("T-46: panel reset marks it too; the half session expires with the step-up window; any own password clears it")

# A sign-in WITHOUT the password (passkey, OIDC, link) is not held — the start secret waits for its use.
auth.store.set_password_must_change(newbie, True)
assert not auth._password_change_owed(newbie, ["oidc"]) and auth._password_change_owed(newbie, ["password"])
ok("T-46: only a sign-in that used the start secret owes the change")

# Switch off: the admin's password stays.
auth_n, app_n = build(admin_password_must_change=False)
auth_n.ensure_admin("root", "root-pw-12345")
an = TestClient(app_n)
an.post("/auth/login", data={"username": "root", "password": "root-pw-12345"}, follow_redirects=False)
uid_n = an.post("/auth/admin/api/users", headers=JSON, json={"username": "keeps", "password": "kept-secret-1"}).json()["id"]
assert not auth_n.store.password_must_change(uid_n)
r = TestClient(app_n).post("/auth/login", data={"username": "keeps", "password": "kept-secret-1", "next": "/who"},
                           follow_redirects=False)
assert r.headers["location"] == "/who"
ok("T-46: admin_password_must_change=False — the admin's password signs in fully as before")

# =====================================================================================
# T-47 — the holder learns of new access
# =====================================================================================
auth, app = build(magiclink_enabled=True, magiclink_self_request=False, qr_login_enabled=True)
mails = []
auth.set_mailer(lambda to, subject, text, html=None: mails.append((to, subject, text)))
events = []
auth.on_security_event = lambda ev, acc, det: events.append((ev, acc["username"], det))
auth.ensure_admin("root", "root-pw-12345")
hold = auth.create_user("holder", password="holder-pw-1234", email="holder@example.com")
auth.store.set_email_verified(hold, True)
adm = TestClient(app)
adm.post("/auth/login", data={"username": "root", "password": "root-pw-12345"}, follow_redirects=False)


def flush():
    auth._notice_outcome.wait()


# (a) admin sets the password, admin issues a link
assert adm.post(f"/auth/admin/api/users/{hold}/password", headers=JSON, json={"password": "admin-set-pw-9"}).status_code == 200
assert adm.post(f"/auth/admin/api/users/{hold}/signin-link", headers=JSON, json={}).status_code == 200
flush()
names = [(e, n) for e, n, _ in events]
assert ("password_changed", "holder") in names and ("signin_link_issued", "holder") in names, names
det = {e: d for e, n, d in events if n == "holder"}
assert det["password_changed"] == {"by_operator": True}, det["password_changed"]
assert det["signin_link_issued"]["by_operator"] is True and det["signin_link_issued"]["ttl_min"] > 0
subjects = [s for to, s, _ in mails if to == "holder@example.com"]
assert auth.t("mail.access.subject", what=auth.t("notice.password_changed")) in subjects, subjects
assert auth.t("mail.access.subject", what=auth.t("notice.signin_link_issued")) in subjects, subjects
ok("T-47: admin password and admin sign-in link → event (by_operator) + mail to the verified address")

# (b) the holder's own password change is no news to them: event yes, mail no
before = len(mails)
auth.rl = _security.RateLimiter()      # the admin's password mail above must not be what keeps this one away
auth.set_password(hold, "holder-own-pw-5")
flush()
assert events[-1] == ("password_changed", "holder", {"by_operator": False}) and len(mails) == before
ok("T-47: the holder's own password change — event with by_operator=False, no mail")

# (c) device signed in by QR approval, new factor, API key — and the throttle
auth.totp_begin(hold)
auth.store.confirm_totp(hold)
phone = session_client(auth, app, hold, age=5, factors=["password", "totp"])
dev = TestClient(app)
r = dev.post("/auth/qr/start", data={"next": "/who"}, headers={"User-Agent": "NewTV/1.0"})
code = re.search(r"name=code value='([A-Z0-9]{8})'", r.text).group(1)
secret = re.search(r"name=secret value='([\w\-]+)'", r.text).group(1)
match = re.search(r"id=qrmatch>(\d\d)<", r.text).group(1)
assert phone.post("/auth/qr/approve", data={"code": code, "match": match}).status_code == 200
dev.post("/auth/qr/finish", data={"code": code, "secret": secret}, follow_redirects=False)
ev = [d for e, n, d in events if e == "device_signed_in"]
assert ev and ev[-1]["method"] == "qr_login" and ev[-1]["agent"] == "NewTV/1.0", ev
before = len(mails)
phone.post("/auth/apikeys", headers=JSON, json={"name": "one"})
phone.post("/auth/apikeys", headers=JSON, json={"name": "two"})
flush()
keymails = [m for m in mails[before:] if m[1] == auth.t("mail.access.subject", what=auth.t("notice.api_key_created"))]
assert len(keymails) == 1, f"two keys within a minute → one mail, got {len(keymails)}"
ok("T-47: device_signed_in (QR) with method and agent; two API keys in a minute → one mail")

# (d) the mails carry no link, in either language; every mailed event has its text
for lang in ("en", "de"):
    m = MESSAGES[lang]
    for event in auth._ACCESS_MAIL_EVENTS:
        assert "notice." + event in m, (lang, event)
        assert "://" not in m["notice." + event]
    assert "://" not in m["mail.access.text"] and "://" not in m["mail.access.subject"]
sent = [text for _, subject, text in mails if subject.startswith("Security notice")]
assert sent and all("://" not in text for text in sent), sent[:1]
ok("T-47: the access mail has no link (de + en), every mailed event has its wording")

# (e) no mail without a verified address, none with the switch off, none without a mailer — the hook always
auth.store.set_email_verified(hold, False)
before = len(mails)
auth._security_event("passkey_added", hold, name="x")
flush()
assert len(mails) == before
auth.store.set_email_verified(hold, True)
auth.cfg.notify_new_access = False
auth._security_event("totp_enabled", hold)
flush()
assert len(mails) == before and events[-1][0] == "totp_enabled"
auth.cfg.notify_new_access = True
ok("T-47: no mail to an unverified address or with notify_new_access=False — the hook still fires")

# (f) the account page shows it — "by an administrator" for the admin's acts
page = TestClient(app)
tok, _ = auth.start_session(hold, "passkey")
page.cookies.set(auth.session_cookie_name, tok)
html = page.get("/auth/account").text
listing = html.split("id=eventlist", 1)[1].split("</ul>", 1)[0]
assert "password_set_by_admin" in listing and "signin_link_issue" in listing and "qr_login" in listing, listing[:500]
assert auth.t("acc.events_by_admin") in listing
ok("T-47: the account page's 'Recent activity' lists the admin's password and link (by an administrator) and the QR sign-in")

# =====================================================================================
# Attack round B — the admin routes that create access want a fresh confirmation even with admin_require_mfa=False
# =====================================================================================
auth, app = build(admin_require_mfa=False, magiclink_enabled=True)
auth.ensure_admin("root", "root-pw-12345")
root = auth.store.get_user_by_name("root")["id"]
victim = auth.create_user("vic", password="vic-pw-123456")
ADMIN = "/auth/admin/api"
calls = {"password reset": (f"{ADMIN}/users/{victim}/password", {"password": "a fresh long password 4711"}),
         "API key": (f"{ADMIN}/users/{victim}/keys", {"name": "k"}),
         "sign-in link": (f"{ADMIN}/users/{victim}/signin-link", {}),
         "invitation": (f"{ADMIN}/invite", {"email": "", "is_admin": True})}
old_admin = session_client(auth, app, root, age=STALE)
assert old_admin.get(f"{ADMIN}/users", headers=JSON).status_code == 200, "the panel itself stays open (no admin MFA)"
for what, (path, body) in calls.items():
    r = old_admin.post(path, json=body, headers=JSON)
    assert r.status_code == 403, (what, r.status_code, r.text[:200])
assert auth.store.get_user(victim) and not auth.list_api_keys(victim)
ok(f"admin_require_mfa=False: {len(calls)} admin routes that create access refuse a stale session (403 step-up)")
fresh_admin = session_client(auth, app, root, age=5)
for what, (path, body) in calls.items():
    r = fresh_admin.post(path, json=body, headers=JSON)
    assert r.status_code == 200, (what, r.status_code, r.text[:200])
ok("… and a fresh one gets through")

# =====================================================================================
# Guard — every route that creates new access goes through the one bolt
# =====================================================================================
#: Route handler (file, function) → why it creates new access. Each must call `_require_fresh`
#: (or, as a page, `_reauth_target`/`_fresh_enough` and its POST `_require_fresh`/`_fresh_enough`).
NEW_ACCESS = {
    ("router.py", "totp_setup"): "TOTP setup page",
    ("router.py", "totp_setup_start"): "TOTP secret",
    ("router.py", "totp_setup_confirm"): "TOTP confirmation",
    ("router.py", "pin_set"): "PIN",
    ("router.py", "apikeys_create"): "API key",
    ("router.py", "qr_approve_page"): "QR approval page",
    ("router.py", "_qr_decide"): "QR approval",
    ("router.py", "_fresh_for_identifier"): "username / address",
    ("webauthn_.py", "reg_begin"): "passkey",
    ("webauthn_.py", "reg_finish"): "passkey",
    ("oauth.py", "consent_page"): "OAuth consent page",
    ("oauth.py", "consent_answer"): "OAuth consent",
    ("admin.py", "user_password"): "password set by an admin",
    ("admin.py", "user_key_create"): "API key by an admin",
    ("admin.py", "service_pairing"): "service pairing",
    ("admin.py", "invite"): "invitation",
    ("admin.py", "user_signin_link"): "sign-in link by an admin",
    ("admin.py", "user_create"): "account with a password or admin rights by an admin",
    # The route `user_roles` hands over to `PanelActions.set_roles` (shared with the approvals, which never send
    # `is_admin`) — the bolt sits there.
    ("admin.py", "set_roles"): "admin rights granted by an admin",
    ("router.py", "claim_admin"): "first admin and owner via the one-time token",
}
_BOLTS = {"_require_fresh", "_reauth_target", "_fresh_enough"}
missing = []
for (file, fn), why in NEW_ACCESS.items():
    tree = ast.parse((ROOT / "tinysesam" / file).read_text(encoding="utf-8"))
    node = next((n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fn), None)
    assert node is not None, f"{file}:{fn} not found — renamed? ({why})"
    calls = {n.func.attr for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    if not calls & _BOLTS:
        missing.append(f"{file}:{fn} ({why})")
assert not missing, f"new access without the freshness bolt: {missing}"
ok(f"guard: all {len(NEW_ACCESS)} routes that create new access call the freshness bolt")
