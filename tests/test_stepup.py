"""Phase 2: step-up / per-route MFA (flag on the guard), reauth freshness, admin_require_mfa."""
import ast
import os
import pathlib
import re
import tempfile, os, time
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import importlib.util
from tinysesam import TinySesam, TinySesamConfig

#: Without the [passkey] extra there are no passkey routes — `build_router` then raises
#: `MissingExtra`. The suite checks step-up and factor removal here, not WebAuthn itself:
#: it therefore also runs in core operation and only skips the passkey route.
HAS_PASSKEY = importlib.util.find_spec("webauthn") is not None


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, stepup_max_age_sec=900,
                                 # F-06 itself (old token dead immediately) — the grace period (A-6)
                                 # has its own checks below.
                                 session_rotation_grace_sec=0))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/normal")
def normal(u=Depends(auth.require_user)):
    return {"u": u["username"]}


@app.get("/sudo")
def sudo(u=Depends(auth.require(mfa=True))):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}
uid = auth.store.get_user_by_name("admin")["id"]


def stale():
    """Artificially age the mfa_at of the current session."""
    tok = c.cookies.get("tinysesam_session")
    auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                     (int(time.time()) - 100000, auth.store.session_hash(tok)))


# ---------- fresh after login → sudo reachable ----------
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c.get("/normal", headers=JSON).status_code == 200
assert c.get("/sudo", headers=JSON).status_code == 200
ok("fresh session: require_user AND require(mfa=True) reachable")

# ---------- Freshness expired → normal ok, sudo blocks (403 + reauth header) ----------
stale()
assert c.get("/normal", headers=JSON).status_code == 200, "normal route stays reachable"
r = c.get("/sudo", headers=JSON)
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", (r.status_code, dict(r.headers))
ok("expired freshness: JSON client → 403 + X-TinySesam-Reauth")

# Browser (Accept: text/html) → redirect to /auth/reauth
r = c.get("/sudo", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"] == "/auth/reauth?next=/sudo", r.headers.get("location")
ok("expired freshness: browser → 307 /auth/reauth?next=/sudo")

# ---------- Reauth via password (user without TOTP) → fresh again ----------
r = c.get("/auth/reauth", follow_redirects=False)
assert r.status_code == 200 and "Passwort" in r.text
assert c.post("/auth/reauth", data={"password": "falsch", "next": "/sudo"}).status_code == 401
r = c.post("/auth/reauth", data={"password": "geheim123", "next": "/sudo"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/sudo"
assert c.get("/sudo", headers=JSON).status_code == 200
ok("reauth via password → sudo reachable again")

# ---------- F-06: the step-up renews the session token ----------
# Whoever has read the old cookie along must not hold a sudo session after the confirmation.
# Lifetime and sign-in time stay — a step-up does not extend the session.
stale()
before = c.cookies.get("tinysesam_session")
line_before = auth.store.get_session(before)
r = c.post("/auth/reauth", data={"password": "geheim123", "next": "/sudo"}, follow_redirects=False)
assert r.status_code == 303 and "tinysesam_session=" in r.headers.get("set-cookie", ""), r.headers
afterwards = c.cookies.get("tinysesam_session")
assert afterwards and afterwards != before, "reauth must issue a new token"
assert auth.store.get_session(before) is None, "the old token must be dead"
line = auth.store.get_session(afterwards)
assert line["created_at"] == line_before["created_at"] and line["expires_at"] == line_before["expires_at"]
assert line["remember"] == line_before["remember"] and line["mfa_ok"] == 1
assert c.get("/sudo", headers=JSON).status_code == 200
thief = TestClient(app)
thief.cookies.set("tinysesam_session", before)
assert thief.get("/normal", headers=JSON).status_code == 401, "old cookie no longer works"
ok("F-06: reauth rotates the token (old one dead, lifetime and created_at unchanged)")

# The same when the step-up runs via a renewed login with a factor (apply_factor on
# an already full session): new token, old session gone, no second one alongside.
before = c.cookies.get("tinysesam_session")
count = len(auth.store.list_sessions(uid))
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303 and c.cookies.get("tinysesam_session") != before
assert auth.store.get_session(before) is None and len(auth.store.list_sessions(uid)) == count
ok("F-06: renewed factor on a full session → token rotated, session count unchanged")

# The third step-up path: POST /auth/totp on a FULL session (route chain with TOTP, or
# someone simply opens the page). `complete_totp` made the session fresh again but only rotated
# the token on the half → full transition — a cookie read beforehand thus got fresh
# sudo rights. Own instance: a TOTP on the admin above would change every login of this suite.
# (Mutation probe: remove the branch `ok and was_ok` → rotate_session in complete_totp → red.)
db_t = os.path.join(tempfile.mkdtemp(), "t.db")
auth_t = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_t, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False, stepup_max_age_sec=900,
                                   session_rotation_grace_sec=0))
uid_t = auth_t.create_user("eva", password="Eva-Geheim-2026")
assert auth_t.totp_confirm(uid_t, pyotp.TOTP(auth_t.totp_begin(uid_t)["secret"]).now())
codes_t = auth_t.generate_recovery_codes(uid_t)   # two codes without waiting for the next TOTP window
app_t = FastAPI()
app_t.include_router(auth_t.router())


@app_t.get("/sudo")
def sudo_t(u=Depends(auth_t.require(mfa=True))):
    return {"u": u["username"]}


c_t = TestClient(app_t)
c_t.post("/auth/login", data={"username": "eva", "password": "Eva-Geheim-2026", "next": "/"},
         follow_redirects=False)
assert c_t.post("/auth/totp", data={"code": codes_t[0], "next": "/"}, follow_redirects=False
                ).status_code == 303
assert c_t.get("/sudo", headers=JSON).status_code == 200, "fully signed in after TOTP"
before = c_t.cookies.get("tinysesam_session")
auth_t.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                   (int(time.time()) - 100000, auth_t.store.session_hash(before)))
assert c_t.get("/sudo", headers=JSON).status_code == 403, "freshness must have expired"
line_before = auth_t.store.get_session(before)
count = len(auth_t.store.list_sessions(uid_t))
r = c_t.post("/auth/totp", data={"code": codes_t[1], "next": "/sudo"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/sudo", (r.status_code, r.headers)
assert any(z.startswith("tinysesam_session=") for z in r.headers.get_list("set-cookie")), \
    "step-up via /auth/totp sets no new session cookie"
afterwards = c_t.cookies.get("tinysesam_session")
assert afterwards and afterwards != before and auth_t.store.get_session(before) is None, "old token still alive"
line = auth_t.store.get_session(afterwards)
assert line["created_at"] == line_before["created_at"] and line["expires_at"] == line_before["expires_at"]
assert len(auth_t.store.list_sessions(uid_t)) == count, "step-up creates a second session"
assert c_t.get("/sudo", headers=JSON).status_code == 200
thief = TestClient(app_t)
thief.cookies.set("tinysesam_session", before)
assert thief.get("/sudo", headers=JSON).status_code == 401, "the cookie read along still works"
ok("F-06: step-up via /auth/totp on a full session rotates the token (old one dead, lifetime unchanged)")

# Own UI (README „Your own login page"): `complete_totp` now returns a new token on step-up,
# and the old one is dead afterwards. Whoever puts the return value into the cookie stays
# signed in — the way the docs must show. (Whoever ignores it has had a dead session in the
# cookie since F-06; at login half → full that was always so.)
# (Mutation probe: remove the branch `ok and was_ok` in complete_totp → red, already in the block
# before; here the old token would stay alive.)
from fastapi import Request as _Req, Response as _Resp   # noqa: E402


@app_t.post("/eigen/stepup")
def own_stepup(request: _Req, code: str = ""):
    response = _Resp()
    tok = request.cookies.get(auth_t.session_cookie_name)
    s = auth_t._session_from_request(request)
    if s and auth_t._verify_recovery_code(s["user_id"], code):
        new = auth_t.complete_totp(tok)
        if new:
            auth_t.set_cookie(response, new)
    return response


before = c_t.cookies.get("tinysesam_session")
auth_t.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                   (int(time.time()) - 100000, auth_t.store.session_hash(before)))
assert c_t.get("/sudo", headers=JSON).status_code == 403
codes_t2 = auth_t.generate_recovery_codes(uid_t)
assert c_t.post("/eigen/stepup", params={"code": codes_t2[0]}).status_code == 200
assert c_t.cookies.get("tinysesam_session") != before and auth_t.store.get_session(before) is None
assert c_t.get("/sudo", headers=JSON).status_code == 200, "own step-up following the docs pattern signs out"
ok("F-06: own step-up route with `neu = complete_totp(tok); set_cookie(resp, neu)` stays signed in")
os.remove(db_t)

# On step-up via /auth/totp TinySesam rotates the session token but not the CSRF token —
# like `/auth/reauth`: a new one would only invalidate the forms in the other open tabs.
# At login (half → full), by contrast, a fresh one (rotate_csrf, cookie injection).
# (Mutation probe: remove the `if not s["mfa_ok"]` before rotate_csrf in router.totp_submit → red.)
db_x = os.path.join(tempfile.mkdtemp(), "t.db")
auth_x = TinySesam(TinySesamConfig(lang="de", db_path=db_x, passkey_enabled=False, oidc_enabled=False,
                                   cookie_secure=False, stepup_max_age_sec=900,
                                   session_rotation_grace_sec=0))
uid_x = auth_x.create_user("eva", password="Eva-Geheim-2026")
assert auth_x.totp_confirm(uid_x, pyotp.TOTP(auth_x.totp_begin(uid_x)["secret"]).now())
codes_x = auth_x.generate_recovery_codes(uid_x)
app_x = FastAPI()
app_x.include_router(auth_x.router())


@app_x.get("/sudo")
def sudo_x(u=Depends(auth_x.require(mfa=True))):
    return {"u": u["username"]}


def _assigned(response):
    return {z.split("=", 1)[0] for z in response.headers.get_list("set-cookie")}


c_x = TestClient(app_x)
_slot = re.search(r"name=_csrf value='([^']+)'", c_x.get("/auth/login").text).group(1)
c_x.post("/auth/login", data={"username": "eva", "password": "Eva-Geheim-2026", "next": "/",
                              "_csrf": _slot}, follow_redirects=False)
r = c_x.post("/auth/totp", data={"code": codes_x[0], "next": "/", "_csrf": c_x.cookies.get("tinysesam_csrf")},
             follow_redirects=False)
assert r.status_code == 303 and {"tinysesam_session", "tinysesam_csrf"} <= _assigned(r), \
    ("at login (half → full) a fresh CSRF token belongs with it", _assigned(r))
csrf_before = c_x.cookies.get("tinysesam_csrf")
tok_x = c_x.cookies.get("tinysesam_session")
auth_x.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                   (int(time.time()) - 100000, auth_x.store.session_hash(tok_x)))
assert c_x.get("/sudo", headers=JSON).status_code == 403
r = c_x.post("/auth/totp", data={"code": codes_x[1], "next": "/sudo", "_csrf": csrf_before},
             follow_redirects=False)
assert r.status_code == 303 and "tinysesam_session" in _assigned(r), (r.status_code, _assigned(r))
assert "tinysesam_csrf" not in _assigned(r), "the step-up rotates the CSRF token (other tabs break)"
assert c_x.cookies.get("tinysesam_csrf") == csrf_before and c_x.get("/sudo", headers=JSON).status_code == 200
ok("F-06: step-up via /auth/totp rotates the session token, not the CSRF token; login rotates both")
os.remove(db_x)

# ---------- API key does NOT satisfy step-up ----------
key = auth.create_api_key(uid, name="k")["key"]
assert c.get("/normal", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 200
# remove fresh session cookies, key only
c2 = TestClient(app)
assert c2.get("/normal", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 200
assert c2.get("/sudo", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 403
ok("API key: require_user ok, require(mfa=True) → 403 (no interactive factor)")

# ---------- admin_require_mfa with TOTP user ----------
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))
auth.cfg.admin_require_mfa = True
c3 = TestClient(app)
# Login → TOTP step → fully logged in (fresh)
c3.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
c3.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
r = c3.get("/auth/admin", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 200, r.status_code
# age → admin panel demands reauth
tok = c3.cookies.get("tinysesam_session")
auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                     (int(time.time()) - 100000, auth.store.session_hash(tok)))
r = c3.get("/auth/admin", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and "/auth/reauth" in r.headers["location"], r.headers.get("location")
# Reauth now demands TOTP (not password)
assert "Authenticator" in c3.get("/auth/reauth").text
# Fresh time step: the code from login is used up (a TOTP code is valid exactly once).
r = c3.post("/auth/reauth", data={"code": pyotp.TOTP(secret).at(int(time.time()) + 30),
                                  "next": "/auth/admin"}, follow_redirects=False)
assert r.status_code == 303
assert c3.get("/auth/admin", headers={"Accept": "text/html"}).status_code == 200
ok("admin_require_mfa: panel ages → reauth via TOTP → free again")

# ---------- R3-3: factor management demands freshness — and fails with an API key ----------
# Attack (finding R3-3, round 3): a taken-over or long-open session got 403 on every
# `require(mfa=True)` guard but could still delete TOTP, issue itself ten fresh
# recovery codes, set/remove the PIN and delete passkeys. The same routes
# hung on `current_user()` — and that also accepts an **API key**: a leaked
# machine credential that never provided an interactive factor silently removed its owner's
# second factor.
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
auth2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, rp_name="Test",
                                  cookie_secure=False, oidc_enabled=False, pin_enabled=True,
                                  apikey_enabled=True, passkey_enabled=HAS_PASSKEY,
                                  stepup_max_age_sec=900))
uid2 = auth2.create_user("opfer", password="geheim123")
sec2 = auth2.totp_begin(uid2)["secret"]
assert auth2.totp_confirm(uid2, pyotp.TOTP(sec2).at(time.time() - 30))
auth2.set_pin(uid2, "2468")
auth2.store.add_webauthn(uid2, "credid-r3-3", "pubkey", 0, ["internal"], "Testschlüssel")
pk2 = auth2.store.list_webauthn(uid2)[0]["id"]
app2 = FastAPI()
app2.include_router(auth2.router())


@app2.get("/normal2")
def normal2(u=Depends(auth2.require_user)):
    return {"u": u["username"]}


@app2.get("/sudo2")
def sudo2(u=Depends(auth2.require(mfa=True))):
    return {"u": u["username"]}


def body(path, pin="9876", pk=None):
    """What the respective route expects as body (the others ignore it)."""
    if path == "/auth/pin/set":
        return {"pin": pin}
    if path == "/auth/passkey/delete":
        return {"id": pk}
    return {}


#: The five routes that remove or replace a sign-in factor.
MANAGEMENT = ("/auth/totp/recovery", "/auth/totp/disable", "/auth/pin/set",
              "/auth/pin/disable") + (("/auth/passkey/delete",) if HAS_PASSKEY else ())


def factors(a, uid):
    """What can this account currently sign in with? (TOTP, PIN, number of passkeys)"""
    return (a.store.has_confirmed_totp(uid), a.has_pin(uid), len(a.store.list_webauthn(uid)))


c4 = TestClient(app2)
c4.post("/auth/login", data={"username": "opfer", "password": "geheim123", "next": "/"},
        follow_redirects=False)
c4.post("/auth/totp", data={"code": pyotp.TOTP(sec2).now(), "next": "/"}, follow_redirects=False)
assert c4.get("/sudo2", headers=JSON).status_code == 200
assert c4.post("/auth/totp/recovery", json={}, headers=JSON).status_code == 200
assert c4.post("/auth/pin/set", json={"pin": "9876"}, headers=JSON).status_code == 200
assert auth2._verify_user_pin(uid2, "9876")
ok("fresh session: recovery codes and PIN change still go through (legitimate path)")

tok2 = c4.cookies.get("tinysesam_session")
auth2.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                  (int(time.time()) - 100000, auth2.store.session_hash(tok2)))
# Precondition — without it the block checked nothing: the session LIVES on, `current_user()`
# returns it, only the freshness is missing. That is exactly what the five routes relied on before; with
# the old `current_user()` lines every one of the following assertions would be red.
assert c4.get("/normal2", headers=JSON).status_code == 200, "the session must stay valid"
assert c4.get("/sudo2", headers=JSON).status_code == 403, "the freshness must really be gone"
before2 = factors(auth2, uid2)
for path in MANAGEMENT:
    response = c4.post(path, json=body(path, pk=pk2), headers=JSON)
    assert response.status_code == 403, (path, response.status_code, response.text[:90])
    assert response.headers.get("X-TinySesam-Reauth") == "/auth/reauth", (path, dict(response.headers))
assert factors(auth2, uid2) == before2, "no factor may change from a stale session"
ok(f"stale session: all {len(MANAGEMENT)} factor routes → 403 + reauth hint, nothing changed")

# Fresh time step: the code from login is used up (a TOTP code is valid exactly once).
r = c4.post("/auth/reauth", data={"code": pyotp.TOTP(sec2).at(int(time.time()) + 30), "next": "/"},
            follow_redirects=False)
assert r.status_code == 303, r.status_code
if HAS_PASSKEY:
    assert c4.post("/auth/passkey/delete", json={"id": pk2}, headers=JSON).status_code == 200
    assert auth2.store.list_webauthn(uid2) == [], "after the step-up the legitimate path must be open"
else:
    assert c4.post("/auth/pin/disable", json={}, headers=JSON).status_code == 200
    assert not auth2.has_pin(uid2), "after the step-up the legitimate path must be open"
ok("after reauth: the same call goes through again (factor removed)")

# ---------- The same attack via API key, with CSRF switched on ----------
# CSRF stays ON here (default): for a real API key `_csrf_dispensable` applies, so the
# CSRF layer does not stop it. What stops it must be the freshness barrier.
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
auth3 = TinySesam(TinySesamConfig(lang="de", db_path=db3, rp_name="Test", cookie_secure=False,
                                  oidc_enabled=False, pin_enabled=True, apikey_enabled=True,
                                  passkey_enabled=HAS_PASSKEY))
uid3 = auth3.create_user("opfer", password="geheim123")
sec3 = auth3.totp_begin(uid3)["secret"]
assert auth3.totp_confirm(uid3, pyotp.TOTP(sec3).at(time.time() - 30))
auth3.set_pin(uid3, "1357")
auth3.store.add_webauthn(uid3, "credid-r3-3-api", "pubkey", 0, ["internal"], "Testschlüssel")
pk3 = auth3.store.list_webauthn(uid3)[0]["id"]
key_name = auth3.create_api_key(uid3, name="ci")["key"]
app3 = FastAPI()
app3.include_router(auth3.router())


@app3.get("/normal3")
def normal3(u=Depends(auth3.require_user)):
    return {"u": u["username"]}


c5 = TestClient(app3)
KEY = {"X-API-Key": key_name, "Accept": "application/json"}
# Precondition: the key is valid and `current_user()` thus returns the account — exactly the
# basis on which the five routes previously allowed factor removal.
assert c5.get("/normal3", headers=KEY).status_code == 200, "the API key must be valid"
before3 = factors(auth3, uid3)
#: Which message the rejection MUST carry. `/auth/pin/set` runs into the session latch
#: (it sits there before the first/further PIN case distinction), the four pure removal routes
#: into the freshness barrier. Both are 403 — what is checked is the reason, not just the number,
#: otherwise a random CSRF 403 would also keep the test green.
REASON = {"/auth/pin/set": "api.needs_session"}
for path in MANAGEMENT:
    response = c5.post(path, json=body(path, pin="1111", pk=pk3), headers=KEY)
    assert response.status_code == 403, (path, response.status_code, response.text[:90])
    expected = auth3.t(REASON.get(path, "api.stepup_session"))
    assert response.json().get("detail") == expected, (path, response.text[:90])
assert factors(auth3, uid3) == before3, "an API key must not remove a factor"
assert auth3._verify_user_pin(uid3, "1357"), "the PIN must not be changeable via API key"
ok(f"API key (CSRF on): all {len(MANAGEMENT)} factor routes → 403, each with its reason")

# ---------- A-umgehung-2: the same latch applies to CREATING a factor ----------
# The R3-3 fix only covered REMOVAL. Creation still hung on `current_user()`, and that
# accepts an API key; the CSRF check is skipped for a real key anyway
# (`_csrf_dispensable`). Two paths were thus open:
#   (1) `GET /auth/totp/setup` returns the secret in plain text, `POST` confirms it →
#       the account then carried a TOTP whose secret the KEY holder knows.
#   (2) A self-registered passkey is a full login → fresh interactive
#       session → and thus the key stood in front of the five removal routes after all.
# Reproduced in `A2b_r3-3_apikey_totp.py` / `A2_r3-3_apikey_passkey.py` (round 3, attack
# against the fixes). Mutation probe: replacing `auth.require_session(...)` in `totp_setup` or
# `reg_begin` by `auth.current_user(request)` again → this block turns red
# (GET 200 with secret or begin 200), the rest of the suite stays green.
db4 = os.path.join(tempfile.mkdtemp(), "t.db")
auth4 = TinySesam(TinySesamConfig(lang="de", db_path=db4, rp_name="Test", cookie_secure=False,
                                  oidc_enabled=False, pin_enabled=True, apikey_enabled=True,
                                  passkey_enabled=HAS_PASSKEY))
uid4 = auth4.create_user("opfer", password="geheim123")      # NO TOTP, NO PIN
app4 = FastAPI()
app4.include_router(auth4.router())
c6 = TestClient(app4)
KEY4 = {"X-API-Key": auth4.create_api_key(uid4, name="ci")["key"], "Accept": "application/json"}

r = c6.get("/auth/totp/setup", headers=KEY4)
assert r.status_code == 403, (r.status_code, r.text[:90])
assert r.json().get("detail") == auth4.t("api.needs_session"), r.text[:120]
assert auth4.store.get_totp(uid4) is None, "the call must not even create a secret"
# Without a secret the key cannot confirm anything either — the route itself is checked anyway.
r = c6.post("/auth/totp/setup", data={"code": "000000"}, headers=KEY4)
assert r.status_code == 403 and r.json().get("detail") == auth4.t("api.needs_session"), r.text[:120]
assert not auth4.store.has_confirmed_totp(uid4), "no TOTP may become active via API key"
# Since N7 the secret is created in its OWN route. It is the path the latch above
# really means — without this line it would have remained bypassable after the rework.
r = c6.post("/auth/totp/setup/start", data={}, headers=KEY4)
assert r.status_code == 403 and r.json().get("detail") == auth4.t("api.needs_session"), r.text[:120]
assert auth4.store.get_totp(uid4) is None, "the new start must not create a secret via key either"
for path in (("/auth/passkey/register/begin", "/auth/passkey/register/finish")
             if HAS_PASSKEY else ()):
    r = c6.post(path, json={}, headers=KEY4)
    assert r.status_code == 403, (path, r.status_code, r.text[:90])
    assert r.json().get("detail") == auth4.t("api.needs_session"), (path, r.text[:120])
    assert "tinysesam_waflow" not in r.cookies, path
assert auth4.store.list_webauthn(uid4) == [], "no passkey may be added via API key"
assert auth4.list_api_keys(uid4), "precondition: the key is issued and valid"
ok("API key: CREATION too (totp/setup" + (", passkey/register" if HAS_PASSKEY else "")
   + ") → 403 'session only'")

# And the legitimate path of the same account keeps working — otherwise the latch would be a dead end.
c7 = TestClient(app4)
c7.get("/auth/login", headers={"Accept": "text/html"})     # fetches the CSRF cookie
assert c7.post("/auth/login", data={"username": "opfer", "password": "geheim123", "next": "/",
                                    "_csrf": c7.cookies.get("tinysesam_csrf") or ""},
               follow_redirects=False).status_code == 303
page_html = c7.get("/auth/totp/setup", headers={"Accept": "text/html"})
assert page_html.status_code == 200, page_html.status_code
# Since N7 the GET only shows the button; the secret is only created in the CSRF-protected POST.
assert "/auth/totp/setup/start" in page_html.text, page_html.text[:200]
page_html = c7.post("/auth/totp/setup/start",
                data={"_csrf": c7.cookies.get("tinysesam_csrf") or ""},
                headers={"Accept": "text/html"})
assert page_html.status_code == 200, page_html.status_code
secret_text = re.search(r"<div class=mono>([A-Z2-7]+)</div>", page_html.text)
assert secret_text, page_html.text[:200]
r = c7.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret_text.group(1)).now()},
            headers={"X-CSRF-Token": c7.cookies.get("tinysesam_csrf") or "", "Accept": "application/json"})
assert r.status_code == 200 and r.json() == {"ok": True, "other_sessions": 0}, r.text[:120]
assert auth4.store.has_confirmed_totp(uid4), "setup from the session must go through"
ok("session of the same account: setting up TOTP works unchanged (secret, confirmation)")

# ---------- Round 2: failed attempts on the reauth page do not lock the SIGN-IN ----------
# `/auth/reauth` recorded its misses as `record_login(…, "reauth")`, and `is_locked`
# counted them: five typos on the step-up confirmation locked the user's
# sign-in for `lockout_window_sec` — even with the correct password. A confirmation is
# not a sign-in, though; whoever performs it is already signed in. Now it has its own
# bucket (`is_reauth_locked`, `reauth_max_attempts`), and that has no IP dimension: guessing
# only hits the own account. (Mutation probe: check `is_locked` in `reauth_submit` again
# and remove "reauth" from `security.OWN_LOCK` → (a) turns red.)
db5 = os.path.join(tempfile.mkdtemp(), "t.db")
auth5 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db5, passkey_enabled=False,
                                  oidc_enabled=False, cookie_secure=False, stepup_max_age_sec=900))
PW_ANNA, PW_PROCESS = "Anna-Passwort-2026", "Bea-Passwort-2026"      # literals: not next to `password=`
auth5.create_user("anna", PW_ANNA)
auth5.create_user("bea", PW_PROCESS)
app5 = FastAPI()
app5.include_router(auth5.router())
c8 = TestClient(app5)
assert c8.post("/auth/login", data={"username": "anna", "password": PW_ANNA, "next": "/"},
               follow_redirects=False).status_code == 303
LIMIT_R = auth5._sec("reauth_max_attempts")
for i in range(LIMIT_R):
    r = c8.post("/auth/reauth", data={"password": f"tippfehler{i}", "next": "/"})
    assert r.status_code == 401, (i, r.status_code)
assert auth5.store.count_fails(0, username="anna", method="reauth") >= LIMIT_R, \
    "the failed attempts were not recorded at all — then the test measures nothing"

# (a) The attack: the sign-in of the same account stays open.
assert not auth5._is_locked("anna", "testclient"), "step-up typos lock the login"
fresh5 = TestClient(app5)
r = fresh5.post("/auth/login", data={"username": "anna", "password": PW_ANNA, "next": "/"},
                 follow_redirects=False)
assert r.status_code == 303, f"login locked after step-up typos: {r.status_code}"
ok("failed attempts on the reauth page do not lock the sign-in (own bucket)")

# (b) It is throttled anyway — where the guessing happened: the next attempt runs into the lock,
# even with the correct password. The threshold is wired up, not merely present.
assert auth5._is_reauth_locked("anna", "testclient"), "no own lockout for the confirmation"
r = c8.post("/auth/reauth", data={"password": PW_ANNA, "next": "/"})
assert r.status_code == 429, f"step-up guessing does not run into the lock: {r.status_code}"
ok("…the confirmation itself is locked after reauth_max_attempts (429)")

# (c) No IP dimension: a second user behind the same address can still confirm.
c9 = TestClient(app5)
assert c9.post("/auth/login", data={"username": "bea", "password": PW_PROCESS, "next": "/"},
               follow_redirects=False).status_code == 303
assert not auth5._is_reauth_locked("bea", "testclient"), \
    "a colleague's failed attempts lock an uninvolved person's confirmation behind NAT"
r = c9.post("/auth/reauth", data={"password": PW_PROCESS, "next": "/"}, follow_redirects=False)
assert r.status_code == 303, f"uninvolved person's confirmation locked: {r.status_code}"
ok("…and it locks per account, not per connection")

# (d) anna's legitimate path is open again after clearing (admin route as with login).
auth5.store.clear_fails(username="anna", method="reauth")
r = c8.post("/auth/reauth", data={"password": PW_ANNA, "next": "/"}, follow_redirects=False)
assert r.status_code == 303, f"confirmation fails after unlocking: {r.status_code}"
ok("…unlockable, afterwards the same account confirms again")
os.remove(db5)


# ---------- H-18 (b): every self-service route is classified and holds its class ----------
# R3-3 bound five routes to step-up freshness — individually. A sixth route that creates or
# removes a factor would escape every test. Hence: every POST route of the router that
# does not belong to the sign-in flow is in exactly one class, and every class is measured.
# A new route without classification turns this check red — that is the purpose.
db6 = os.path.join(tempfile.mkdtemp(), "t.db")
auth6 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db6, rp_name="Test",
                                  passkey_enabled=HAS_PASSKEY, oidc_enabled=False,
                                  cookie_secure=False, stepup_max_age_sec=900, pin_enabled=True,
                                  apikey_enabled=True, account_enabled=True,
                                  resource_locks_enabled=True))
app6 = FastAPI()
router6 = auth6.router()
app6.include_router(router6)
uid6 = auth6.create_user("selbst", password="Geheim12345!")
auth6.set_pin(uid6, "471193")
_sec6 = auth6.totp_begin(uid6)["secret"]
assert auth6.totp_confirm(uid6, pyotp.TOTP(_sec6).now())
key6 = auth6.create_api_key(uid6, "bot")["key"]

#: Sign-in flow: these routes ARE the confirmation, they manage nothing.
SIGN_IN_FLOW = {"/auth/login", "/auth/totp", "/auth/pin", "/auth/magic/request", "/auth/reauth",
                "/auth/forgot", "/auth/reset", "/auth/register", "/auth/resource/{name}",
                "/auth/saml/acs", "/auth/passkey/login/begin", "/auth/passkey/login/finish",
                "/auth/logout",   # sign-out (F-07) only ends the own session, manages nothing
                # Limit d: only for a HALF sign-in, merely records — it ends only once the
                # last factor is confirmed; a full session uses /auth/sessions/revoke.
                "/auth/sessions/revoke-after-login",
                # The link to the new address IS the confirmation (possession of the mailbox), like
                # /auth/reset — the change was requested with step-up (/auth/account/email).
                "/auth/email/{token}"}
#: Demand fresh confirmation (require_mfa): expired session → 403 + X-TinySesam-Reauth.
STEPUP = {"/auth/totp/disable", "/auth/totp/recovery", "/auth/pin/set", "/auth/pin/disable",
          "/auth/passkey/delete", "/auth/sessions/revoke",   # sessions/revoke: F-09
          "/auth/account/username", "/auth/account/email"}   # self-service (2026-09-25)
#: The old password is the confirmation (throttled, locked, logged — R4-10).
PASSWORD = {"/auth/password"}
#: Setting up a factor: only with an interactive session, never with an API key (R3-1/R3-3).
ONLY_SESSION = {"/auth/totp/setup/start", "/auth/totp/setup", "/auth/passkey/register/begin",
               "/auth/passkey/register/finish"}
#: Known open — with justification. If one of them gets bound, it belongs in STEPUP.
OFFEN = {"/auth/apikeys": "key issuance without step-up (reported as H-18)",
         "/auth/apikeys/{key_id}/revoke": "key revocation without step-up (reported as H-18)"}

# From the router itself, not from `app6.routes`: newer FastAPI versions store included
# routers there as an object without a path — the list would be empty and the check silently green.
_post6 = {rt.path for rt in router6.routes
          if "POST" in (getattr(rt, "methods", None) or ())
          and not str(getattr(rt, "path", "")).startswith(auth6.cfg.admin_path)}
_classes = [SIGN_IN_FLOW, STEPUP, PASSWORD, ONLY_SESSION, set(OFFEN)]
_unclassified = sorted(p for p in _post6 if not any(p in k for k in _classes))
assert not _unclassified, f"self-service route without classification: {_unclassified}"
_double = [p for p in _post6 if sum(p in k for k in _classes) > 1]
assert not _double, _double
assert STEPUP & _post6 and ONLY_SESSION & _post6, f"guard without hits: router setup changed? {sorted(_post6)}"
ok(f"H-18: all {len(_post6)} POST routes classified (sign-in flow, step-up, password, session, open)")


def _stale_client():
    """Fully signed in, but sign-in AND last confirmation lie far back."""
    cl = TestClient(app6)
    tok = auth6.store.create_session(uid6, 3600, True, "password")
    old = int(time.time()) - 100000
    auth6.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                      (old, old, auth6.store.session_hash(tok)))
    cl.cookies.set(auth6.session_cookie_name, tok)
    return cl


_payload = {"/auth/pin/set": {"json": {"pin": "999999"}}, "/auth/totp/setup": {"data": {"code": "000000"}},
             "/auth/password": {"json": {"current": "falsch-falsch", "new": "Neu1234567890!"}},
             "/auth/sessions/revoke": {"json": {"scope": "others"}},
             "/auth/apikeys": {"json": {"name": "neu"}},
             "/auth/account/username": {"json": {"username": "anders"}},
             "/auth/account/email": {"json": {"email": "anders@example.com"}}}
for path in sorted(STEPUP & _post6):
    r = _stale_client().post(path, headers=JSON, **_payload.get(path, {}))
    assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth"), \
        f"{path}: expired confirmation got through ({r.status_code}) — step-up missing"
for path in sorted(ONLY_SESSION & _post6):
    r = TestClient(app6).post(path, headers={**JSON, "X-API-Key": key6}, **_payload.get(path, {}))
    assert r.status_code in (401, 403), f"{path}: API key sets up a factor ({r.status_code})"
r = _stale_client().post("/auth/password", headers=JSON, **_payload["/auth/password"])
assert r.status_code == 403 and auth6._check_password("selbst", "Geheim12345!"), \
    f"/auth/password without the old password: {r.status_code}"
for path in sorted(set(OFFEN) & _post6):
    destination = path.replace("{key_id}", str(auth6.list_api_keys(uid6)[0]["id"]))
    r = _stale_client().post(destination, headers=JSON, **_payload.get(path, {}))
    assert r.status_code == 200, (
        f"{path} now demands a confirmation ({r.status_code}) — move from OFFEN to STEPUP "
        f"({OFFEN[path]})")
ok(f"H-18: {len(STEPUP & _post6)} routes demand step-up, {len(ONLY_SESSION & _post6)} only a "
   f"session, {len(set(OFFEN) & _post6)} known open ({', '.join(sorted(set(OFFEN.values())))})")
os.remove(db6)

# ---------- A-2: the step-up keeps the kind of the session cookie ----------
# Since F-06 a step-up rotates the token, and the caller sets the cookie anew. With the
# default `remember=True` a session WITHOUT "stay signed in" got a cookie for
# seven days, which survived closing the browser on a shared computer; conversely
# the PIN route with an empty form field turned a remembered session into a session cookie.
db6 = os.path.join(tempfile.mkdtemp(), "t.db")
auth6 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db6, passkey_enabled=False,
                                  oidc_enabled=False, cookie_secure=False, magiclink_enabled=True,
                                  pin_enabled=True, base_url="https://auth.example.com"))
auth6.set_mailer(lambda *a, **k: None)
auth6.ensure_admin("admin", "geheim123")
uid6 = auth6.store.get_user_by_name("admin")["id"]
auth6.set_pin(uid6, "24680")
app6 = FastAPI()
app6.include_router(auth6.router())


def _session_cookie(response):
    lines = [z for z in response.headers.get_list("set-cookie") if z.startswith("tinysesam_session=")]
    assert len(lines) == 1, response.headers.get_list("set-cookie")
    return lines[0].lower()


for remember in ("", "on"):
    c6 = TestClient(app6)
    r = c6.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                     "remember": remember}, follow_redirects=False)
    assert ("max-age" in _session_cookie(r)) == bool(remember), _session_cookie(r)
    before = c6.cookies.get("tinysesam_session")
    raw = auth6.create_magic_token("login", user_id=uid6, email="x@example.com", ttl_min=15,
                                   payload={"next": "/"})
    r = c6.post(f"/auth/magic/{raw}", follow_redirects=False)   # R4-02: only the POST redeems
    assert c6.cookies.get("tinysesam_session") != before, "step-up must rotate (F-06)"
    assert ("max-age" in _session_cookie(r)) == bool(remember), \
        f"magic step-up (remember={remember!r}) changes the cookie kind: {_session_cookie(r)}"
    # PIN with the OPPOSITE in the form — the session got its kind at the first factor.
    r = c6.post("/auth/pin", data={"username": "admin", "pin": "24680", "next": "/",
                                   "remember": "" if remember else "on"}, follow_redirects=False)
    assert r.status_code == 303, r.status_code
    assert ("max-age" in _session_cookie(r)) == bool(remember), \
        f"PIN step-up (session remember={remember!r}) changes the cookie kind: {_session_cookie(r)}"
    line = auth6.store.get_session(c6.cookies.get("tinysesam_session"))
    assert bool(line["remember"]) == bool(remember)
ok("A-2: step-up via magic link and PIN keeps the cookie kind of the session (remember yes/no)")
os.remove(db6)

# ---------- 0.20.1: /auth/reauth confirms only a session, never an API key ----------
# Attack (0.20.1 follow-up, pre-existing up to 0.20.0): the route checked the factor of the
# account from `current_user()` and then set the session from `session_from_request()` to
# "full". With a HALF session (password yes, TOTP open) `current_user()` falls back to the
# API key — authorization and effect hit two different accounts:
#   (a) half session of the victim + own automation key + own password → the VICTIM's
#       session was fully signed in, its TOTP never asked.
#   (b) the same in the own account: automation key (does not carry the admin flag, R6-5) + password
#       → full admin session without TOTP. Key + password replaced the second factor.
# An API key can never reach step-up freshness anyway (`stepup_fresh`), the route has nothing to
# confirm for it: 403 `api.stepup_session`, before any factor is checked.
# (Mutation probe: remove the latch in `reauth_submit` → (a) and (b) red; the one in
# `reauth_page` → the GET part red. Since the second round the latch is
# `_only_session(request)` with `session_user()`: there `current_user()` again in
# `reauth_submit` → (a) red and the guard below; in `reauth_page` → the GET part red; the 403
# in `_only_session` removed → (a) red.)
db7 = os.path.join(tempfile.mkdtemp(), "t.db")
auth7 = TinySesam(TinySesamConfig(lang="de", db_path=db7, rp_name="Test", cookie_secure=False,
                                  oidc_enabled=False, passkey_enabled=False, apikey_enabled=True))
auth7.ensure_admin("chefin", "Geheim-Admin-1")
uid7_adm = auth7.store.get_user_by_name("chefin")["id"]
uid7_victim = auth7.create_user("opfer", password="Geheim-Opfer-1")
uid7_perpetrator = auth7.create_user("taeter", password="Geheim-Taeter-1")
_secret_text7 = {}
for _u7 in (uid7_adm, uid7_victim):
    _secret_text7[_u7] = auth7.totp_begin(_u7)["secret"]
    assert auth7.totp_confirm(_u7, pyotp.TOTP(_secret_text7[_u7]).at(time.time() - 30))
key7_perpetrator = auth7.create_api_key(uid7_perpetrator, name="ci")["key"]
key7_adm = auth7.create_api_key(uid7_adm, name="ci")["key"]
app7 = FastAPI()
app7.include_router(auth7.router())


def _half_signed_in(name, password):
    """First factor provided, TOTP open — the situation in the middle of the sign-in."""
    cl = TestClient(app7)
    cl.get("/auth/login", headers={"Accept": "text/html"})     # fetches the CSRF cookie
    r = cl.post("/auth/login", data={"username": name, "password": password, "next": "/",
                                     "_csrf": cl.cookies.get("tinysesam_csrf") or ""},
                follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp"), \
        (r.status_code, r.headers.get("location"))
    s = auth7.store.get_session(cl.cookies.get("tinysesam_session"))
    assert s and not s["mfa_ok"], "precondition: the session is half"
    assert cl.get("/auth/me", headers=JSON).status_code == 401, "precondition: half = not signed in"
    return cl


def _reauth_with_key(cl, key, password):
    return cl.post("/auth/reauth", data={"password": password, "next": "/",
                                         "_csrf": cl.cookies.get("tinysesam_csrf") or ""},
                   headers={**JSON, "X-API-Key": key}, follow_redirects=False)


# (a) foreign account
c7 = _half_signed_in("opfer", "Geheim-Opfer-1")
r = _reauth_with_key(c7, key7_perpetrator, "Geheim-Taeter-1")
assert r.status_code == 403 and r.json().get("detail") == auth7.t("api.stepup_session"), \
    (r.status_code, r.text[:120])
s = auth7.store.get_session(c7.cookies.get("tinysesam_session"))
assert s and not s["mfa_ok"], "the victim's half session was made full via a foreign key"
assert c7.get("/auth/me", headers=JSON).status_code == 401, "victim signed in without TOTP"
# (b) own account: key + password do not replace the second factor
c7 = _half_signed_in("chefin", "Geheim-Admin-1")
r = _reauth_with_key(c7, key7_adm, "Geheim-Admin-1")
assert r.status_code == 403 and r.json().get("detail") == auth7.t("api.stepup_session"), \
    (r.status_code, r.text[:120])
s = auth7.store.get_session(c7.cookies.get("tinysesam_session"))
assert s and not s["mfa_ok"], "automation key + password replaced TOTP"
assert c7.get("/auth/admin", headers={"Accept": "text/html"},
              follow_redirects=False).status_code != 200, "admin panel reachable without TOTP"
# GET: a key alone gets no confirmation page (there would be nothing to confirm).
r = TestClient(app7).get("/auth/reauth", headers={**JSON, "X-API-Key": key7_perpetrator},
                         follow_redirects=False)
assert r.status_code == 403 and r.json().get("detail") == auth7.t("api.stepup_session"), \
    (r.status_code, r.text[:120])
ok("0.20.1: /auth/reauth with API key → 403, a half session (foreign or own) stays half")

# The legitimate route stays open: full session, freshness expired, confirmation via TOTP.
c7 = _half_signed_in("opfer", "Geheim-Opfer-1")
_totp7 = pyotp.TOTP(_secret_text7[uid7_victim])
r = c7.post("/auth/totp", data={"code": _totp7.now(), "next": "/",
                                "_csrf": c7.cookies.get("tinysesam_csrf") or ""},
            follow_redirects=False)
assert r.status_code == 303 and c7.get("/auth/me", headers=JSON).status_code == 200, r.status_code
auth7.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                  (int(time.time()) - 100000, auth7.store.session_hash(c7.cookies.get("tinysesam_session"))))
assert c7.get("/auth/reauth", headers={"Accept": "text/html"}).status_code == 200
r = c7.post("/auth/reauth", data={"code": _totp7.at(int(time.time()) + 30), "next": "/",
                                  "_csrf": c7.cookies.get("tinysesam_csrf") or ""},
            follow_redirects=False)
assert r.status_code == 303, (r.status_code, r.text[:120])
s = auth7.store.get_session(c7.cookies.get("tinysesam_session"))
assert s and s["mfa_ok"] and int(time.time()) - s["mfa_at"] < 60, "step-up did not refresh the session"
ok("0.20.1: step-up of a full session via TOTP keeps working")
os.remove(db7)

# ---------- 0.20.1: /auth/pin takes "already signed in" from the session, never from an API key ----------
# Attack (second round against 0.20.1, pre-existing up to 0.20.0), the same class as
# `/auth/reauth` above: `pin_submit` read "already logged in" from `current_user()`. A pure
# API-key request (no cookie) thereby counted as signed in: the latch `pin_login=False` (the
# PIN is no first factor) did not apply, the PIN of the key account was checked, and
# `apply_factor()` created a NEW, full session for lack of one. From the automation key,
# which never carries the admin flag (R6-5), key + PIN thus became an admin session with panel,
# key management and factor setup. With a half foreign session in the cookie the
# same request replaced its cookie with that of the key account.
# (Mutation probe: in `login_pin` again `me = self.current_user(request)` → (a), (b) and
# (d) red, plus the guard below; in `pin_page` → (c) red.)
db8 = os.path.join(tempfile.mkdtemp(), "t.db")
auth8 = TinySesam(TinySesamConfig(lang="de", db_path=db8, rp_name="Test", cookie_secure=False,
                                  oidc_enabled=False, passkey_enabled=False, apikey_enabled=True,
                                  pin_enabled=True, pin_login=False, stepup_max_age_sec=900))
auth8.ensure_admin("chef", "Geheim-Chef-2026")
uid8 = auth8.store.get_user_by_name("chef")["id"]
auth8.set_pin(uid8, "4711")
uid8_victim = auth8.create_user("opfer", password="Geheim-Opfer-8")
_secret_text8 = auth8.totp_begin(uid8_victim)["secret"]
assert auth8.totp_confirm(uid8_victim, pyotp.TOTP(_secret_text8).at(time.time() - 30))
KEY8 = {"X-API-Key": auth8.create_api_key(uid8, name="ci", kind="automation")["key"]}
app8 = FastAPI()
app8.include_router(auth8.router())
r = TestClient(app8).get("/auth/me", headers={**JSON, **KEY8})
assert r.status_code == 200 and r.json()["is_admin"] is False, \
    ("precondition: valid automation key without admin flag", r.status_code, r.text[:120])
_sessions8 = len(auth8.store.list_sessions())

# (a) Key + PIN, no cookie (for a real key the CSRF check is dropped): 404 like any guest.
c8a = TestClient(app8)
r = c8a.post("/auth/pin", data={"pin": "4711", "next": "/"}, headers=KEY8, follow_redirects=False)
assert r.status_code == 404, (r.status_code, r.headers.get("location"), r.text[:120])
assert not c8a.cookies.get("tinysesam_session"), "key + PIN received a session cookie"
assert len(auth8.store.list_sessions()) == _sessions8, "key + PIN created a session"
assert c8a.get("/auth/admin/api/users", headers=JSON).status_code in (401, 403)
# (b) the same with a user field — the key does not turn the guest into a signed-in user.
r = c8a.post("/auth/pin", data={"pin": "4711", "username": "chef", "next": "/"}, headers=KEY8,
             follow_redirects=False)
assert r.status_code == 404, (r.status_code, r.text[:120])
assert len(auth8.store.list_sessions()) == _sessions8
# (c) The GET offers the key no PIN form (it would be a 404 on submit anyway).
r = c8a.get("/auth/pin", headers={**KEY8, "Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login"), \
    (r.status_code, r.headers.get("location"))
ok("0.20.1: /auth/pin with automation key + PIN at pin_login=False → 404, no session, no admin")

# (d) Half session of another in the cookie + own key + own PIN: the cookie stays as it was.
c8d = TestClient(app8)
c8d.get("/auth/login", headers={"Accept": "text/html"})     # fetches the CSRF cookie
r = c8d.post("/auth/login", data={"username": "opfer", "password": "Geheim-Opfer-8", "next": "/",
                                  "_csrf": c8d.cookies.get("tinysesam_csrf") or ""},
             follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp"), r.headers.get("location")
_half8 = c8d.cookies.get("tinysesam_session")
# Since G7 (2026-09-26) a half session in the cookie is no guest anymore IF the PIN is its
# chain step (`_pin_chain_step`). Here there is no chain, the next step of
# "opfer" is TOTP: the half session does not count, the key does not either → 404 like any guest at
# `pin_login=False`. (Between G7 and p2 F1 this was 401 — the half session checked PINs whose
# step was not even open; that fixed the error in place.) What matters here remains: the key
# does not count, cookie and session stay as they were, and nobody gets a new one.
r = c8d.post("/auth/pin", data={"pin": "4711", "next": "/", "_csrf": c8d.cookies.get("tinysesam_csrf")},
             headers=KEY8, follow_redirects=False)
assert r.status_code == 404, (r.status_code, r.text[:120])
assert c8d.cookies.get("tinysesam_session") == _half8, "the cookie of the half session was replaced"
_s8 = auth8.store.get_session(_half8)
assert _s8 and _s8["user_id"] == uid8_victim and not _s8["mfa_ok"], "the half session has changed"
assert not any(z["user_id"] == uid8 for z in auth8.store.list_sessions()), "the key account has a session"
ok("0.20.1: half foreign session (next step TOTP) + key + PIN → 404, cookie and "
   "session unchanged, none for the key account")

# (e) The legitimate route stays: full session, PIN as additional factor at pin_login=False.
c8e = TestClient(app8)
c8e.get("/auth/login", headers={"Accept": "text/html"})
assert c8e.post("/auth/login", data={"username": "chef", "password": "Geheim-Chef-2026", "next": "/",
                                     "_csrf": c8e.cookies.get("tinysesam_csrf") or ""},
                follow_redirects=False).status_code == 303
assert "name=pin" in c8e.get("/auth/pin", headers={"Accept": "text/html"}).text
r = c8e.post("/auth/pin", data={"pin": "4711", "next": "/", "_csrf": c8e.cookies.get("tinysesam_csrf")},
             follow_redirects=False)
assert r.status_code == 303, (r.status_code, r.text[:120])
_s8 = auth8.store.get_session(c8e.cookies.get("tinysesam_session"))
assert _s8 and _s8["user_id"] == uid8 and "pin" in _s8["factors_done"], dict(_s8) if _s8 else None
ok("0.20.1: full session + PIN as additional factor keeps working at pin_login=False")
os.remove(db8)

# ---------- Guard: no spot with session effect takes its account from a key source ----------
# The class behind `/auth/reauth` and `/auth/pin`: a route checks a factor for the account
# from `current_user()` and applies it to the session. Without a full session `current_user()` falls
# back to the API key — the key's account is then checked, and the effect hits
# the cookie or creates a new session. The rule stands in ONE place: whoever
# creates a session, attaches a factor to it, refreshes or ends it, takes the account from
# `session_user()` (or `pending_user()`/`totp_enrollment_user()`, or from the factor itself).
# Every function of the package is checked; local helpers (a bare call like `_only_session(…)`)
# count too, as does a mention without a call (`Depends(auth.current_user)`).
# `require_session`/`require_mfa` are deliberately NOT in the list: they reject a key.
# (Mutation probes, each individually: `current_user` instead of `session_user` in `login_pin`,
# `login_totp`, `totp_setup_confirm`, `_sign_out` → guard red; in `_only_session` → red only
# thanks to the helper tracking (green without it, hence the probe `helper` in the self-test);
# `session_user()` itself bent to `current_user()` → the guard stays green, the
# behaviour blocks above turn red — both layers are needed.)
# Since 0.22.0 the sign-in steps live in `login_password`/`login_pin`/`login_totp`
# (the routes call them): they are sinks themselves — a route that surrounds them with an account from a
# key source is caught here like one that calls `apply_factor`. So is the step-up
# (`confirm_*`, `POST /auth/reauth` calls them) and the password change (`change_password`, ends
# the other sessions of the account). Since these building blocks the guard measures three more forms:
# a sink that is only PASSED (`run_in_threadpool(auth.change_password, …)` in
# `POST /auth/password` — no call on the attribute, invisible until then); helpers called as a
# method (`self._only_with_session(…)` — otherwise it would not check the source of the building blocks,
# only that of the routes); and a function that is itself named like a sink: its body
# has session effect even if it calls no other sink (`change_password` ends sessions
# via the store). (Mutation probe: in `TinySesam._only_with_session` `current_user` instead of
# `session_user` → red at `_confirm`, `confirm_*` and `change_password`; green without the
# method helper.)
LOWER = {"apply_factor", "start_session", "complete_totp", "complete_mfa", "rotate_session",
          "set_session_mfa", "set_session_factors", "logout",
          "login_password", "login_pin", "login_totp",
          "confirm_password", "confirm_pin", "confirm_totp", "change_password"}
KEY_SOURCES = {"current_user", "_determine_current_user", "require_user", "require_role",
               "require_admin", "_enforce"}


def _own_node(fn):
    """The nodes in the body of `fn` — without nested functions, which count for themselves."""
    unclosed = list(ast.iter_child_nodes(fn))
    while unclosed:
        k = unclosed.pop()
        if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield k
        unclosed.extend(ast.iter_child_nodes(k))


def _session_effect(source_text, file="?"):
    """(Names of the functions with session effect, violations) for a module source."""
    fns = [k for k in ast.walk(ast.parse(source_text)) if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef))]
    per_name: dict = {}
    for fn in fns:
        per_name.setdefault(fn.name, []).append(fn)
    direct = {}
    for fn in fns:
        sink, source, helper = False, set(), set()
        for k in _own_node(fn):
            # Called or merely passed (`run_in_threadpool(auth.change_password, …)`).
            if isinstance(k, ast.Attribute) and k.attr in LOWER:
                sink = True
            if isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id in per_name:
                helper.add(k.func.id)
            if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                    and isinstance(k.func.value, ast.Name) and k.func.value.id == "self"
                    and k.func.attr in per_name):
                helper.add(k.func.attr)          # `self._only_with_session(…)`: method of the same module
            name = k.attr if isinstance(k, ast.Attribute) else k.id if isinstance(k, ast.Name) else None
            if name in KEY_SOURCES:
                source.add(name)
        direct[id(fn)] = (sink, source, helper)

    def shell(fn, seen):
        """(Sink reachable?, reachable key sources) via local helpers, cycle-proof."""
        if id(fn) in seen:
            return False, set()
        seen.add(id(fn))
        sink, source, helper = direct[id(fn)]
        source = set(source)
        for h in helper:
            for destination in per_name[h]:
                s2, q2 = shell(destination, seen)
                sink, source = sink or s2, source | q2
        return sink, source

    effective, violations = set(), []
    for fn in fns:
        sink, source = shell(fn, set())
        if sink or fn.name in LOWER:        # a sink itself: its body counts
            effective.add(fn.name)
            if source:
                violations.append(f"{file}:{fn.lineno} {fn.name} ← {sorted(source)}")
    return effective, violations


# Self-test: the guard must see the class in every form it promises — otherwise its
# green says nothing (a switched-off helper tracking would otherwise go unnoticed).
_PROBES = {
    "direkt": ("def r(request):\n    me = auth.current_user(request)\n"
               "    auth.apply_factor(request, me['id'], 'pin')\n", True),
    "helfer": ("def _h(request):\n    return auth.current_user(request)\n"
               "def r(request, resp):\n    u = _h(request)\n    auth.rotate_session(request, resp)\n", True),
    "depends": ("def r(request, u=Depends(auth.require_user)):\n    auth.logout(request, resp)\n", True),
    "sauber": ("def r(request):\n    me = auth.session_user(request)\n"
               "    auth.apply_factor(request, me['id'], 'pin')\n", False),
    "uebergeben": ("async def r(request):\n    auth.current_user(request)\n"
                   "    return await run_in_threadpool(auth.change_password, request, 'a', 'b')\n", True),
    "methode": ("class T:\n    def _h(self, request):\n        return self.current_user(request)\n"
                "    def c(self, request):\n        u = self._h(request)\n"
                "        self.store.rotate_session(u, 1)\n", True),
    "senke_selbst": ("class T:\n    def change_password(self, request):\n"
                     "        u = self.current_user(request)\n        self.store.delete_user_sessions_except(u)\n",
                     True),
    "verschachtelt": ("def aussen():\n    auth.current_user(x)\n"
                      "    def innen(request):\n        auth.complete_totp(t)\n", False),
}
for _probe, (_text, _expected_red) in _PROBES.items():
    assert bool(_session_effect(_text)[1]) == _expected_red, f"guard self-test '{_probe}' wrong"

_package = pathlib.Path(__file__).resolve().parent.parent / "tinysesam"
_effective, _violations = set(), []
for _file in sorted(_package.glob("*.py")):
    _w, _v = _session_effect(_file.read_text(encoding="utf-8"), _file.name)
    _effective |= _w
    _violations += _v
assert not _violations, ("account from a source that accepts an API key, at a spot with "
                         "session effect — use `session_user()`: " + "; ".join(_violations))
# Without hits the guard measures nothing: the known spots must be found.
_expected = {"pin_submit", "reauth_submit", "totp_submit", "totp_setup_confirm", "login_submit",
             "_sign_out", "apply_factor", "login_password", "login_pin", "login_totp",
             "_confirm", "confirm_password", "confirm_pin", "confirm_totp", "change_password",
             "change_own_password"}
assert _expected <= _effective, f"guard no longer finds {sorted(_expected - _effective)} — setup changed?"
ok(f"guard: {len(_effective)} spots with session effect, none takes its account from a key source "
   f"({len(_PROBES)} self-probes)")

# ---------- A-6: grace period of the old token after the step-up (PO decision 2026-09-25) ----------
# A request that was already under way at the moment of the step-up (second tab) still carries the old
# token. `session_rotation_grace_sec` (default 10) keeps applying — but WITHOUT step-up freshness, and
# it ends with the new session.
db_g = os.path.join(tempfile.mkdtemp(), "g.db")
auth_g = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_g, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False, stepup_max_age_sec=900))
assert auth_g.cfg.session_rotation_grace_sec == 10, "default of the grace period is 10 seconds"
uid_g = auth_g.create_user("gina", password="Gin-Geheim-2026")
app_g = FastAPI()
app_g.include_router(auth_g.router())


@app_g.get("/normal")
def normal_g(u=Depends(auth_g.require_user)):
    return {"u": u["username"]}


@app_g.get("/sudo")
def sudo_g(u=Depends(auth_g.require(mfa=True))):
    return {"u": u["username"]}


cg = TestClient(app_g)
cg.post("/auth/login", data={"username": "gina", "password": "Gin-Geheim-2026"}, follow_redirects=False)
old_g = cg.cookies.get("tinysesam_session")
auth_g.store._exec("UPDATE session SET mfa_at=?", (int(time.time()) - 100000,))
cg.post("/auth/reauth", data={"password": "Gin-Geheim-2026", "next": "/sudo"}, follow_redirects=False)
new_g = cg.cookies.get("tinysesam_session")
assert new_g and new_g != old_g and cg.get("/sudo", headers=JSON).status_code == 200
second_tab = TestClient(app_g)
second_tab.cookies.set("tinysesam_session", old_g)
assert second_tab.get("/normal", headers=JSON).status_code == 200, "the request in the second tab fails"
assert second_tab.get("/sudo", headers=JSON).status_code != 200, "the old token has fresh sudo rights"
assert len(auth_g.store.list_sessions(uid_g)) == 1, "the superseded token counts as a session of its own"
ok("A-6: old token keeps working briefly (normal route), without step-up freshness, no second session")
auth_g.store._exec("UPDATE session SET expires_at=? WHERE token_hash=?",
                   (int(time.time()) - 1, auth_g.store.session_hash(old_g)))
assert second_tab.get("/normal", headers=JSON).status_code == 401, "after the period it no longer works"
ok("A-6: after the period has elapsed the old token is dead")
# Signing out the new session takes the superseded token along.
cg.post("/auth/login", data={"username": "gina", "password": "Gin-Geheim-2026"}, follow_redirects=False)
old2 = cg.cookies.get("tinysesam_session")
auth_g.store._exec("UPDATE session SET mfa_at=?", (int(time.time()) - 100000,))
cg.post("/auth/reauth", data={"password": "Gin-Geheim-2026", "next": "/"}, follow_redirects=False)
auth_g.store.delete_session_by_handle(auth_g.store.session_hash(cg.cookies.get("tinysesam_session")))
assert auth_g.store.get_session(old2) is None, "the superseded token survives the sign-out"
ok("A-6: sign-out/revocation of the new session also ends the superseded token")
os.remove(db_g)
# (Mutation probes: `mercy_sec` ignored → first check red; `mfa_at=NULL` omitted → sudo
#  red; the filter in `list_sessions` removed → session count red; `OR nachfolger=?` on deletion removed →
#  sign-out red.)

os.remove(db)
os.remove(db2)
os.remove(db3)
os.remove(db4)
print("\nSTEP-UP OK ✅")
