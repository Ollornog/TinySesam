"""Three setups without email: user+password only, PIN as route factor, PIN as step-up."""
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

HTML = {"accept": "text/html"}


def login(c, u="max", pw="geheim12345-lang-genug"):
    return c.post("/auth/login", data={"username": u, "password": pw, "next": "/"}, follow_redirects=False)


# ---------- 1) Username + password only, no email involved ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, allow_signup=True,
                                                cookie_secure=False))
cfg = auth.cfg
assert cfg.login_identifier == "username" and not cfg.signup_require_email
assert not cfg.magiclink_enabled and not cfg.password_reset_enabled and not cfg.signup_verify_email
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app, headers=HTML)

page = c.get("/auth/register").text
assert "name=username" in page and "name=email" not in page or "required" not in page
r = c.post("/auth/register", data={"username": "max", "password": "geheim12345-lang-genug", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303, r.text[:200]
assert auth.store.get_user_by_name("max")["email"] is None
c.cookies.clear()

lp = c.get("/auth/login").text
assert "Benutzer</label>" in lp, "no combined field"
for gone in ("/auth/magic/request", "/auth/forgot"):
    assert gone not in lp, f"{gone} must not be offered"
assert c.get("/auth/magic/request").status_code == 404
assert c.get("/auth/forgot").status_code == 404
assert login(c).status_code == 303
os.unlink(db)
print("  local_accounts(): user+password, no email routes ok")


# ---------- 2) PIN as additional factor of a route (already signed in) ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                cookie_secure=False))
uid = auth.create_user("max", password="geheim12345-lang-genug")
auth.set_pin(uid, "2468")
app = FastAPI()
app.include_router(auth.router())


@app.get("/tresor")
def vault(user=Depends(auth.require(factors=["password", "pin"]))):
    return {"ok": user["username"]}


c = TestClient(app, headers=HTML)
assert login(c).status_code == 303
# Password alone is not enough — the route sends to the PIN step
r = c.get("/tresor", follow_redirects=False)
assert r.status_code in (303, 307) and r.headers["location"].startswith("/auth/pin"), r.headers
page = c.get("/auth/pin?next=/tresor").text
assert "name=pin" in page and "name=username" not in page, "signed in → no user field"
r = c.post("/auth/pin", data={"pin": "1111", "next": "/tresor"})
assert r.status_code == 401 and "name=username" not in r.text
r = c.post("/auth/pin", data={"pin": "2468", "next": "/tresor"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/tresor"
assert c.get("/tresor", headers={"accept": "application/json"}).json() == {"ok": "max"}
os.unlink(db)
print("  require(factors=[password,pin]): PIN without user field, route open afterwards ok")


# ---------- 3) PIN as step-up for sensitive areas ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                stepup_methods=["pin"], stepup_max_age_sec=1,
                                                cookie_secure=False))
uid = auth.create_user("max", password="geheim12345-lang-genug")
auth.set_pin(uid, "2468")
app = FastAPI()
app.include_router(auth.router())


@app.get("/sensibel")
def sensitive(user=Depends(auth.require(mfa=True))):
    return {"ok": user["username"]}


c = TestClient(app, headers=HTML)
assert login(c).status_code == 303
u = auth.store.get_user_by_name("max")
assert auth.stepup_options(u) == ["pin"], auth.stepup_options(u)

# Let the freshness expire artificially → step-up is required
s = auth.store.list_sessions()[0]
auth.store.set_session_mfa(s["token_hash"], True)
auth.store.db.execute("UPDATE session SET mfa_at=0 WHERE token_hash=?", (s["token_hash"],))
auth.store.db.commit()

r = c.get("/sensibel", follow_redirects=False)
assert r.status_code == 307 and r.headers["location"].startswith("/auth/reauth"), r.headers
page = c.get("/auth/reauth?next=/sensibel").text
assert "name=pin" in page and "PIN zur Bestätigung" in page
assert "name=password" not in page, "stepup_methods=['pin'] → no password field"
r = c.post("/auth/reauth", data={"pin": "9999", "next": "/sensibel"})
assert r.status_code == 401
# Password is NOT accepted if only PIN is allowed. Since 0.22.0 (`confirm_password`)
# that is 403 `method_disabled` and not a failed attempt: a method that is not offered is
# not checked at all — until then 401, and the request counted in the bucket `reauth`.
_before = auth.store.count_fails(0, username="max", method="reauth")
r = c.post("/auth/reauth", data={"password": "geheim12345-lang-genug", "next": "/sensibel"})
assert r.status_code == 403, "password must not pass here"
assert auth.store.count_fails(0, username="max", method="reauth") == _before, "no failed attempt"
assert c.get("/sensibel", follow_redirects=False).status_code == 307, "the session is not fresh"
r = c.post("/auth/reauth", data={"pin": "2468", "next": "/sensibel"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/sensibel"
assert c.get("/sensibel", headers={"accept": "application/json"}).json() == {"ok": "max"}
os.unlink(db)
print("  stepup_methods=['pin']: sensitive area requires PIN despite login ok")


# ---------- 4) Fallback: desired method not set up ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                stepup_methods=["pin"], cookie_secure=False))
uid = auth.create_user("ohnepin", password="geheim12345-lang-genug")   # no PIN set
u = auth.store.get_user(uid)
assert auth.stepup_options(u) == ["password"], "without PIN → password instead of a dead end"
os.unlink(db)
print("  fallback without a set-up PIN → password ok")

# ---------- 5) pin_login=False: PIN is not a first factor ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                pin_login=False, cookie_secure=False))
uid = auth.create_user("max", password="geheim12345-lang-genug")
auth.set_pin(uid, "2468")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
assert "pin" not in auth.cfg.enabled_methods()
lp = c.get("/auth/login").text
assert "name=pin" not in lp, "PIN form must not be on the login page"
# A guest cannot sign in by PIN
r = c.get("/auth/pin", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login")
r = c.post("/auth/pin", data={"username": "max", "pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 404, r.status_code
# signed in may keep confirming the PIN
assert login(c).status_code == 303
assert "name=pin" in c.get("/auth/pin").text
os.unlink(db)
print("  pin_login=False: PIN only as an additional factor ok")



# ---------- 6) Demo mode + first-admin bootstrap ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
kw = dict(db_path=db, csrf_enabled=False, lang="de", passkey_enabled=False,
          cookie_secure=False, pin_enabled=True, demo_mode=True)
auth = TinySesam(TinySesamConfig.local_accounts(**kw))
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
assert auth.store.get_user_by_name("demo") and auth.store.get_user_by_name("demoadmin")["is_admin"]
lp = c.get("/auth/login").text
assert "Demo-Modus" in lp and "demoadmin" in lp and "demo_mode" in lp, "credentials + warning"
assert c.post("/auth/login", data={"username": "demo", "password": "demo1234", "next": "/"},
              follow_redirects=False).status_code == 303
assert "Demo-PIN" in c.get("/auth/pin").text
# switch off → accounts gone
auth2 = TinySesam(TinySesamConfig.local_accounts(**{**kw, "demo_mode": False}))
assert not auth2.store.get_user_by_name("demo") and not auth2.store.get_user_by_name("demoadmin")
os.unlink(db)
print("  demo_mode: accounts + notice, deleted when switched off ok")

# Allowlist: only whoever is on it becomes admin — and only as long as none exists
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, cookie_secure=False,
                                                admin_identifiers=["chef"]))
auth.create_user("fremder", password="geheim12345-lang-genug")
auth.create_user("chef", password="geheim12345-lang-genug")
app = FastAPI(); app.include_router(auth.router()); c = TestClient(app, headers=HTML)
c.post("/auth/login", data={"username": "fremder", "password": "geheim12345-lang-genug", "next": "/"})
assert not auth.store.get_user_by_name("fremder")["is_admin"], "a stranger must not become admin"
c.cookies.clear()
c.post("/auth/login", data={"username": "chef", "password": "geheim12345-lang-genug", "next": "/"})
assert auth.store.get_user_by_name("chef")["is_admin"]
os.unlink(db)

# One-time token: exactly once, afterwards the route is gone
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, cookie_secure=False))
tok = auth.admin_claim_token()
assert tok
auth.create_user("erster", password="geheim12345-lang-genug")
app = FastAPI(); app.include_router(auth.router()); c = TestClient(app, headers=HTML)
r = c.get(f"/auth/claim-admin?token={tok}", follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"], "sign in first without login"
c.post("/auth/login", data={"username": "erster", "password": "geheim12345-lang-genug", "next": "/"})
assert c.get("/auth/claim-admin?token=falsch").status_code == 403
r = c.get(f"/auth/claim-admin?token={tok}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/admin"
assert auth.store.get_user_by_name("erster")["is_admin"]
assert c.get(f"/auth/claim-admin?token={tok}").status_code == 404, "route disappears with the first admin"
assert auth.admin_claim_token() is None
os.unlink(db)
print("  first admin: allowlist + one-time token, no 'first user wins' ok")


# ---------- 7) The FIRST PIN of an account without any factor ----------
# `/auth/pin/set` is not only the way to replace a PIN but the only one to create it.
# Behind `require_mfa()` this was a dead end for a purely federated account (no password,
# no PIN, no TOTP): `stepup_options()` is empty, so there is nothing
# with which this account could perform a step-up, and after `stepup_max_age_sec` had expired
# it never got to the set-up again. Reproduced in `a2_r33_pin_sackgasse.py` (round 3).
# Now: CREATING depends on the age of the sign-in, REPLACING and removing stay behind
# `require_mfa()`. Mutation probe: the case distinction in `pin_set` turned back into a
# bare `require_mfa()` → (a) turns red; `login_fresh` always True → (b) turns red.
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                                 passkey_enabled=False, oidc_enabled=False,
                                 password_enabled=False,      # purely federated account
                                 pin_enabled=True, totp_enabled=True, stepup_max_age_sec=900))
uid = auth.create_user("sso-nutzer")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
J = {"Accept": "application/json"}
assert not auth.store.get_password_hash(uid) and not auth.has_pin(uid)
assert not auth.store.has_confirmed_totp(uid)
assert auth.stepup_options(auth.get_user(uid)) == [], "precondition: nothing to confirm with"

tok, mfa_ok = auth.start_session(uid, "oidc", remember=True)
assert mfa_ok, "the federated login alone makes the session fully valid"
c.cookies.set(auth.cfg.session_cookie, tok)
# The freshness has expired (the window is 15 minutes, the session lasts days) — exactly the
# situation in which the dead end snapped shut. The sign-in itself is still young.
auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                 (int(time.time()) - 100000, auth.store.session_hash(tok)))
assert c.get("/auth/me", headers=J).status_code == 200, "the session must stay valid"
r = c.post("/auth/pin/set", json={"pin": "2468"}, headers=J)
assert r.status_code == 200, (r.status_code, r.text[:120])       # (a)
assert auth._verify_user_pin(uid, "2468"), "the first PIN must arrive"
print("  (a) first PIN without any factor: fresh sign-in suffices ok")

# Now the account HAS a factor → replacing requires a confirmation again, and that
# can be provided via the PIN. The promise "changing a factor requires freshness" stays intact.
r = c.post("/auth/pin/set", json={"pin": "1357"}, headers=J)
assert r.status_code == 403, (r.status_code, r.text[:120])
assert r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", dict(r.headers)
assert auth._verify_user_pin(uid, "2468"), "the old PIN may stay"
page_html = c.get("/auth/reauth").text
assert "name=pin" in page_html, "the reauth page must now have a PIN field"
r = c.post("/auth/reauth", data={"pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
assert c.post("/auth/pin/set", json={"pin": "1357"}, headers=J).status_code == 200
assert auth._verify_user_pin(uid, "1357")
print("  REPLACING the PIN stays behind require_mfa (403 → reauth by PIN → 200) ok")
os.unlink(db)

# And the old sign-in opens nothing any more: if the login is too old as well, it stays at 403 —
# but with the hint that helps (sign in again), and WITHOUT the reference to a reauth page
# that cannot offer this account a field.
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                                 passkey_enabled=False, oidc_enabled=False, password_enabled=False,
                                 pin_enabled=True, totp_enabled=True, stepup_max_age_sec=900))
uid = auth.create_user("sso-nutzer")
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
tok, _ = auth.start_session(uid, "oidc", remember=True)
c.cookies.set(auth.cfg.session_cookie, tok)
auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                 (int(time.time()) - 100000, int(time.time()) - 100000,
                  auth.store.session_hash(tok)))
r = c.post("/auth/pin/set", json={"pin": "2468"}, headers={"Accept": "application/json"})
assert r.status_code == 403, (r.status_code, r.text[:120])       # (b)
assert r.json().get("detail") == auth.t("api.stepup_relogin"), r.text[:160]
assert "X-TinySesam-Reauth" not in r.headers, dict(r.headers)
assert not auth.has_pin(uid), "without a fresh sign-in no PIN may be set"
# The reauth page tells the account the truth, instead of offering a password field that it does
# not have (every attempt would be hopeless — and would count in the same lockout bucket).
page_html = c.get("/auth/reauth")
fields = re.findall(r"<input[^>]*name=[\"\']?(\w+)", page_html.text)
assert fields == [], fields
assert auth.t("err.stepup_none") in page_html.text, page_html.text[:300]
response = c.post("/auth/reauth", data={"password": "geraten", "next": "/"})
assert response.status_code == 403, response.status_code
assert auth.store.count_fails(0, username="sso-nutzer") == 0, "no failed attempt in the lockout bucket"
os.unlink(db)
print("  (b) sign-in too old: 403 'sign in again', reauth page without field ok")


# ---------- 8) The same route for an account WITH a password: the rule, exactly ----------
# The exception from (7) applies narrowly: it is meant for an account that has nothing at all with which
# it could confirm. As soon as `stepup_options()` returns something — and it does for every
# account with a password —, CREATING the first PIN also requires a fresh confirmation.
# That is intentional and not negligence: with `pin_login` a PIN is a full first
# factor, a stolen session cookie would otherwise set up its own access that
# outlasts the theft. A fresh sign-in alone is NOT enough for that.
# Until the second round the CHANGELOG claimed across the board that creating depends on the age of the
# sign-in; the rule was measured by no suite. Now here. (Mutation probe:
# remove `or auth.stepup_options(u)` in `pin_set` → (b) turns red.)
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                                 passkey_enabled=False, oidc_enabled=False, pin_enabled=True,
                                 pin_login=True, stepup_max_age_sec=900))
PW = "Anna-Passwort-2026"
uid = auth.create_user("anna", PW)
app = FastAPI(); app.include_router(auth.router())
c = TestClient(app, headers=HTML)
J = {"Accept": "application/json"}
assert auth.stepup_options(auth.get_user(uid)) == ["password"], "precondition: the account can confirm"
assert c.post("/auth/login", data={"username": "anna", "password": PW, "next": "/"},
              follow_redirects=False).status_code == 303

# (a) Freshly signed in: the first PIN goes through — the sign-in IS the confirmation here.
r = c.post("/auth/pin/set", json={"pin": "2468"}, headers=J)
assert r.status_code == 200, (r.status_code, r.text[:120])
assert auth._verify_user_pin(uid, "2468")
print("  (a) password account, freshly signed in: first PIN goes through ok")

# (b) Confirmation expired, sign-in still young: 403 — and indeed the one that helps.
auth.disable_pin(uid)
_hash = auth.store.session_hash(c.cookies.get(auth.cfg.session_cookie))
auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?", (int(time.time()) - 100000, _hash))
_session = auth.store._one("SELECT created_at, mfa_at FROM session WHERE token_hash=?", (_hash,))
# Precondition, otherwise (b) measures the wrong bolt: the SIGN-IN is still young, only the
# confirmation has expired. Exactly this situation separates `login_fresh()` from `stepup_fresh()`.
assert int(time.time()) - _session["created_at"] < auth.cfg.stepup_max_age_sec, dict(_session)
assert int(time.time()) - _session["mfa_at"] > auth.cfg.stepup_max_age_sec, dict(_session)
r = c.post("/auth/pin/set", json={"pin": "1357"}, headers=J)
assert r.status_code == 403, (r.status_code, r.text[:120])
assert r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", dict(r.headers)
assert not auth.has_pin(uid), "without confirmation no sign-in factor may arise"
print("  (b) password account, confirmation expired: 403 + reference to the reauth page ok")

# (c) And the path the reference points to leads to the goal: confirm password → set PIN.
r = c.post("/auth/reauth", data={"password": PW, "next": "/"}, follow_redirects=False)
assert r.status_code == 303, r.status_code
r = c.post("/auth/pin/set", json={"pin": "1357"}, headers=J)
assert r.status_code == 200, (r.status_code, r.text[:120])
assert auth._verify_user_pin(uid, "1357")
print("  (c) after confirmation on /auth/reauth: first PIN goes through ok")
os.unlink(db)

# ---------- 5) A PIN locked at the PIN sign-in cannot be guessed further on /auth/reauth (C-3) ----------
# The step-up page has its own bucket (`is_reauth_locked`); it must not undermine the PIN lockout
# of the sign-in — otherwise the keyspace supply of an attacker doubles.
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig.local_accounts(db_path=db, csrf_enabled=False, lang="de",
                                                passkey_enabled=False, pin_enabled=True,
                                                stepup_methods=["pin"], stepup_max_age_sec=1,
                                                cookie_secure=False))
uid = auth.create_user("max", password="geheim12345-lang-genug")
auth.set_pin(uid, "2468")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app, headers=HTML)
assert login(c).status_code == 303
for _ in range(int(auth._sec("pin_max_attempts")) + 1):
    c.post("/auth/pin", data={"pin": "0000", "next": "/"})
assert auth._is_pin_locked("max", "testclient"), "precondition: the PIN sign-in is locked"
time.sleep(1.1)
r = c.post("/auth/reauth", data={"pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 429, f"locked PIN is still accepted on /auth/reauth: {r.status_code}"
os.unlink(db)
print("  (C-3) PIN lockout of the sign-in also applies on the step-up page ok")

print("OK test_pin_stepup")
