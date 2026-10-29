"""Phase 4.5: factor chain engine — ordered combinations, global + per route, strict flag."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import time
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def fresh(chain=None, strict=True, **kw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    cfg = TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                          cookie_secure=False, login_chain=chain or [], login_chain_strict=strict,
                          pin_enabled=True, **kw)
    auth = TinySesam(cfg)
    auth.ensure_admin("admin", "geheim123")
    uid = auth.store.get_user_by_name("admin")["id"]
    auth.set_pin(uid, "2468")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def secret_text(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, uid, app


# ---------- Global chain ["pin","password"] strict: order enforced ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=True)


@app.get("/area")
def area(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# First factor PIN -> session incomplete, no access yet
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login"), r.headers.get("location")
assert c.get("/area", headers=JSON).status_code == 401
ok("chain pin->password: after PIN only a redirect to /auth/login, no access yet")

# Second factor password -> chain satisfied -> access
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/area", r.headers.get("location")
assert c.get("/area", headers=JSON).json() == {"u": "admin"}
ok("chain pin->password: fully logged in after the password")
os.remove(db)

# ---------- Strict: wrong order grants NO access ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=True)
c = TestClient(app)
# Password first (wrong order) -> sent to /auth/pin, but never "done"
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/pin")
assert c.get("/geheim", headers=JSON).status_code == 401
ok("strict: password-before-PIN does not satisfy the chain (no access)")
os.remove(db)

# ---------- Non-strict: any order suffices ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=False)
c = TestClient(app)
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert c.get("/geheim", headers=JSON).status_code == 401   # only one factor
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("non-strict: password then PIN (reverse order) suffices")
os.remove(db)

# ---------- Global chain ["password","totp"] with real TOTP ----------
db, auth, uid, app = fresh(chain=["password", "totp"], strict=True)
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))
c = TestClient(app)
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp")
assert c.get("/geheim", headers=JSON).status_code == 401
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("chain password->totp satisfied")
os.remove(db)

# ---------- Per-route override: route additionally demands a specific factor ----------
db, auth, uid, app = fresh(chain=[])   # global classic


@app.get("/pin-area")
def pin_area(u=Depends(auth.require(factors=["password", "pin"]))):
    return {"u": u["username"]}


c = TestClient(app)
# classic password login (complete globally, no TOTP)
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}       # normal route open
r = c.get("/pin-area", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"].startswith("/auth/pin"), r.headers.get("location")
# attach PIN as an additional factor to the running session
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/pin-area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/pin-area"
assert c.get("/pin-area", headers=JSON).json() == {"u": "admin"}
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}       # normal route still open
ok("per-route factors=[password,pin]: PIN as additional factor, session stays valid")
os.remove(db)

# ---------- R3-1: the chain also protects accounts WITHOUT the factor ----------
# `login_chain=["password","totp"]` reads as "nobody gets in without a second factor".
# Up to 0.18.x that was not true: an account without TOTP was allowed to set it up itself at
# exactly this point — so whoever had only the password bound their own authenticator and was
# fully in. The chain protected everyone except those it was meant for.
import time as _when                                                      # noqa: E402
from tinysesam.errors import ConfigError as _ConfigError                  # noqa: E402


def _chain_without_totp(**kw):
    """An app with a password+totp chain and an account that has NO TOTP."""
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test",
                                     passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                     login_chain=["password", "totp"], **kw))
    uid = auth.create_user("neu", password="geheim123")
    app = FastAPI()
    app.include_router(auth.router())
    return db, auth, uid, app


def _until_the_second_factor(app):
    c = TestClient(app)
    c.post("/auth/login", data={"username": "neu", "password": "geheim123", "next": "/"},
           follow_redirects=False)
    return c


# Default "first_login": a fresh account may set itself up — otherwise every new account would be
# a dead end and the operator would have to touch the database.
db_a, auth_a, uid_a, app_a = _chain_without_totp()
assert auth_a.mfa_enrollment_allowed(uid_a) is True
c_a = _until_the_second_factor(app_a)
assert c_a.get("/auth/totp", headers={"Accept": "text/html"}, follow_redirects=False
               ).headers.get("location", "").startswith("/auth/totp/setup")
ok("R3-1: a never-used account sets up the second factor itself (default)")

# A-1: Confirming the mandatory setup also completes the TOTP step. Since the setup code is
# consumed (B2-3), the same code at /auth/totp was a failed attempt — anyone who typed it again
# (as they used to) filled the login lockout including fail2ban lines and, after five attempts,
# locked the account that had just been set up.
# (Mutation probe: remove the enrollment branch in router.totp_setup_confirm -> red.)
import io as _io_e, logging as _logging_e, re as _re                     # noqa: E402
from tinysesam import security as _sec_e                                  # noqa: E402

db_e, auth_e, uid_e, app_e = _chain_without_totp()
c_e = _until_the_second_factor(app_e)
assert "value='/ziel'" in c_e.get("/auth/totp/setup?next=/ziel").text
_page_html = c_e.post("/auth/totp/setup/start", data={"next": "/ziel"}).text
assert "data-next='/ziel'" in _page_html, "the target is lost on the way through the setup"
assert "location.href=j.next" in _page_html, "the page does not follow the target after confirmation"
_secret_text = _re.search(r"class=mono>([A-Z2-7]+)<", _page_html).group(1)
_event_e = []
auth_e.on_security_event = lambda e, k, d: _event_e.append(e)
_code = pyotp.TOTP(_secret_text).now()
_buffer_e = _io_e.StringIO()
_check_e = _logging_e.StreamHandler(_buffer_e)
_sec_e.seclog.addHandler(_check_e)
try:
    _ant = c_e.post("/auth/totp/setup", data={"code": _code, "next": "/ziel"})
    assert _ant.status_code == 200 and _ant.json() == {"ok": True, "next": "/ziel",
                                                       "other_sessions": 0,
                                                       "other_sessions_after": 0}, _ant.text
    _s = auth_e.store.get_session(c_e.cookies.get(auth_e.cfg.session_cookie))
    assert _s and _s["mfa_ok"], "after the mandatory setup the session is still stuck in the MFA step"
    # The old way — the same code at /auth/totp once more — is thereby superfluous: the setup
    # page forwards straight to the target with `next`.
    assert not auth_e._is_locked("neu", "testclient")
    assert c_e.get("/auth/account", follow_redirects=False).status_code == 200, "not fully signed in"
finally:
    _sec_e.seclog.removeHandler(_check_e)
assert "failed login" not in _buffer_e.getvalue(), _buffer_e.getvalue()
assert _event_e == ["totp_enabled"], _event_e
ok("A-1: mandatory setup under the chain signs in with the confirmation (no failed attempt afterwards)")

# A-4: An already active TOTP is not "confirmed once more" — neither via the route (409 like
# GET and /start) nor via the method. Before: 200 {"ok": true}, a wrong `totp_enabled` event
# and a second code verifier for the active factor.
# (Mutation probe: remove `or t["confirmed"]` in totp_confirm OR the 409 guard -> red.)
_sequence = pyotp.TOTP(_secret_text).at(_when.time() + 30)
_ant = c_e.post("/auth/totp/setup", data={"code": _sequence})
assert _ant.status_code == 409, (_ant.status_code, _ant.text)
assert not auth_e.totp_confirm(uid_e, _sequence), "totp_confirm confirms an active TOTP again"
assert _event_e == ["totp_enabled"], _event_e
assert sum(z["event"] == "totp_enable" for z in auth_e.store.recent_audit(50)) == 1
assert auth_e._verify_totp(uid_e, _sequence), "the follow-up code must stay free for sign-in"
ok("A-4: confirmed TOTP -> 409 at /auth/totp/setup, no second totp_enabled")

# B1-7 also in the mandatory setup: the confirmation reports `other_sessions`, measured against
# the NEW session. The case where that matters is "device lost": device A is still fully signed
# in, the operator removes the TOTP and opens an enrollment window, device B sets up anew.
# Without the field the page forwarded immediately without offering to end A. Counted against
# the old cookie it would be 2 here: its half session was just deleted by `complete_totp`, and
# the new one counted as "other".
# (Mutation probe: remove other_sessions in the enrollment branch -> red; count against the old
# cookie, i.e. `count_other_sessions(request, u)` without token -> red, already at A-1 above with 1 instead of 0.)
auth_e.totp_disable(uid_e)
auth_e.grant_mfa_enrollment(uid_e, minutes=30)
c_b = _until_the_second_factor(app_e)
_page_html_b = c_b.post("/auth/totp/setup/start", data={"next": "/ziel"}).text
_secret_text_b = _re.search(r"class=mono>([A-Z2-7]+)<", _page_html_b).group(1)
_ant_b = c_b.post("/auth/totp/setup", data={"code": pyotp.TOTP(_secret_text_b).now(), "next": "/ziel"})
assert _ant_b.status_code == 200, _ant_b.text
assert _ant_b.json() == {"ok": True, "next": "/ziel", "other_sessions": 1, "other_sessions_after": 0}, _ant_b.json()
assert c_e.get("/auth/account", follow_redirects=False).status_code == 200, "device A is still in"
assert c_b.post("/auth/sessions/revoke", json={"scope": "others"}).status_code == 200
assert c_e.get("/auth/account", follow_redirects=False).status_code != 200, "device A stayed signed in"
ok("B1-7: mandatory setup reports the other sessions, counted against the new session")
os.remove(db_e)

# ...but only if the session is full with this confirmation. In a longer chain
# (password -> totp -> pin) it is still half afterwards, and POST /auth/sessions/revoke answers
# a half session with 401. The page still asked "end other sessions?", ending failed silently,
# and the page jumped to the PIN step — the user thought the lost device was signed out.
# No offer is more honest than an offer that does not hold.
# (Mutation probe: remove `if renewed else 0` in the enrollment branch -> red.)
db_k = os.path.join(tempfile.mkdtemp(), "t.db")
auth_k = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_k, rp_name="Test",
                                   passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                   pin_enabled=True, login_chain=["password", "totp", "pin"],
                                   mfa_enrollment="strict"))
uid_k = auth_k.create_user("neu", password="geheim123")
auth_k.set_pin(uid_k, "2468")
_secret_text_k = auth_k.totp_begin(uid_k)["secret"]
assert auth_k.totp_confirm(uid_k, pyotp.TOTP(_secret_text_k).now())
_codes_k = auth_k.generate_recovery_codes(uid_k)
app_k = FastAPI()
app_k.include_router(auth_k.router())
c_ka = _until_the_second_factor(app_k)                       # device A: the whole chain
assert c_ka.post("/auth/totp", data={"code": _codes_k[0], "next": "/"},
                 follow_redirects=False).headers["location"].startswith("/auth/pin")
c_ka.post("/auth/pin", data={"username": "neu", "pin": "2468", "next": "/"}, follow_redirects=False)
assert c_ka.get("/auth/account", follow_redirects=False).status_code == 200
auth_k.totp_disable(uid_k)                                  # device lost
auth_k.grant_mfa_enrollment(uid_k, minutes=30)
c_kb = _until_the_second_factor(app_k)                       # device B sets up anew
_page_html_k = c_kb.post("/auth/totp/setup/start", data={"next": "/ziel"}).text
_secret_text_kb = _re.search(r"class=mono>([A-Z2-7]+)<", _page_html_k).group(1)
_ant_k = c_kb.post("/auth/totp/setup", data={"code": pyotp.TOTP(_secret_text_kb).now(), "next": "/ziel"})
assert _ant_k.status_code == 200, _ant_k.text
_s_k = auth_k.store.get_session(c_kb.cookies.get(auth_k.cfg.session_cookie))
assert _s_k and not _s_k["mfa_ok"], "the session is already full after the TOTP step"
# No offer to redeem IMMEDIATELY (`other_sessions` 0, the half session cannot end anything) —
# but since limit d (2026-09-24) one for the completion: `other_sessions_after` counts device A.
assert _ant_k.json() == {"ok": True, "next": "/auth/pin?next=/ziel", "other_sessions": 0,
                         "other_sessions_after": 1}, \
    f"offer the half session cannot redeem: {_ant_k.json()}"
assert c_kb.post("/auth/sessions/revoke", json={"scope": "others"}).status_code == 401
ok("B1-7 + limit d: in a longer chain no immediate offer, but one for the completion")
os.remove(db_k)

# ...but only until the first complete login. After that the way is shut — exactly the case in
# which someone has the password of an EXISTING account.
auth_a.store.mark_first_login(uid_a, int(_when.time()))
assert auth_a.mfa_enrollment_allowed(uid_a) is False
c_a2 = _until_the_second_factor(app_a)
_destination = c_a2.get("/auth/totp", headers={"Accept": "text/html"}, follow_redirects=False
                 ).headers.get("location", "")
assert not _destination.startswith("/auth/totp/setup"), f"setup stayed open: {_destination!r}"
assert auth_a.store.get_user(uid_a)["first_login_at"] is not None
ok("R3-1: after the first complete login the self-setup is closed")

# And the message about it is NOT a failed attempt: whoever fails here entered their correct
# password. If the line carried the event word of the login jail, fail2ban would lock out exactly
# the person who has just signed in correctly. (Found because CodeQL flagged the line as
# password logging — the false alarm pointed to a real bug next to it.)
import io as _io, logging as _logging                                     # noqa: E402
from tinysesam import security as _security                               # noqa: E402

_buffer = _io.StringIO()
_check = _logging.StreamHandler(_buffer)
_security.seclog.addHandler(_check)
try:
    _until_the_second_factor(app_a).get("/auth/totp", headers={"Accept": "text/html"},
                                       follow_redirects=False)
finally:
    _security.seclog.removeHandler(_check)
_text = _buffer.getvalue()
assert "mfa enrollment denied" in _text, f"no message: {_text[:200]!r}"
assert _security.log_event("totp") not in _text, \
    f"the blocked setup carries the login jail word: {_text[:200]!r}"
ok("R3-1: ...the message about it does not hit the fail2ban jail (it is not a failed attempt)")

# The operator can open a window — the way for "device lost" and for strict.
_until = auth_a.grant_mfa_enrollment(uid_a, minutes=30)
assert _until > int(_when.time())
assert auth_a.mfa_enrollment_allowed(uid_a) is True
assert auth_a.mfa_enrollment_allowed(uid_a, now=_until + 1) is False
auth_a.revoke_mfa_enrollment(uid_a)
assert auth_a.mfa_enrollment_allowed(uid_a) is False
ok("R3-1: an operator enrollment window wins — time-limited and revocable")

# "strict": never on its own, not even the first time.
db_s, auth_s, uid_s, app_s = _chain_without_totp(mfa_enrollment="strict")
assert auth_s.mfa_enrollment_allowed(uid_s) is False
_destination_s = _until_the_second_factor(app_s).get("/auth/totp", headers={"Accept": "text/html"},
                                             follow_redirects=False).headers.get("location", "")
assert not _destination_s.startswith("/auth/totp/setup"), _destination_s
assert auth_s.grant_mfa_enrollment(uid_s, minutes=5) and auth_s.mfa_enrollment_allowed(uid_s) is True
ok("R3-1: mfa_enrollment='strict' refuses even the fresh account — until the operator opens")

# "grace": a period from account creation, closed afterwards.
db_g, auth_g, uid_g, app_g = _chain_without_totp(mfa_enrollment="grace", mfa_enrollment_grace_days=7)
assert auth_g.mfa_enrollment_allowed(uid_g) is True
assert auth_g.mfa_enrollment_allowed(uid_g, now=int(_when.time()) + 8 * 86400) is False
ok("R3-1: mfa_enrollment='grace' expires after the configured number of days")

# Without enforcement everything stays as it was: if the chain demands no second factor, every
# signed-in user sets it up themselves at any time.
db_o = os.path.join(tempfile.mkdtemp(), "t.db")
auth_o = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_o, rp_name="Test",
                                   passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                   mfa_enrollment="strict"))
uid_o = auth_o.create_user("frei", password="geheim123")
app_o = FastAPI()
app_o.include_router(auth_o.router())
c_o = TestClient(app_o)
c_o.post("/auth/login", data={"username": "frei", "password": "geheim123", "next": "/"},
         follow_redirects=False)
assert c_o.get("/auth/totp/setup", headers={"Accept": "text/html"}).status_code == 200, \
    "without chain enforcement a voluntary TOTP must remain possible to set up"
ok("R3-1: if MFA is optional the bolt does not apply — voluntary stays voluntary")

# An unknown mode aborts at construction instead of silently allowing.
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                              passkey_enabled=False, mfa_enrollment="irgendwas"))
    raise AssertionError("unknown mode got through")
except _ConfigError:
    pass
ok("R3-1: a typo in mfa_enrollment aborts construction")

for _d in (db_a, db_s, db_g, db_o):
    os.remove(_d)

print("\nFACTOR CHAINS OK ✅")
