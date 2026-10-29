"""Structure test for OIDC + passkey: load modules, routes respond, passkey options can be generated
(without browser), login page shows all active methods. (Browser/provider path not checkable here.)"""

# This suite deliberately builds an app WITH passkey and OIDC — without the extras there is nothing
# to check. That is a missing precondition of this suite, not a fault of the library:
# exactly this distinction the runner did not make earlier.
from voraussetzung import braucht_modul  # noqa: E402
braucht_modul("webauthn", extra="passkey")
braucht_modul("authlib", extra="oidc")
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", 
    db_path=db, rp_name="Test", rp_id="localhost", origin="http://localhost:8000",
    password_enabled=True, passkey_enabled=True, oidc_enabled=True,
    oidc_name="PocketID", oidc_issuer="https://id.example.invalid",
    oidc_client_id="cid", oidc_client_secret="sec", cookie_secure=False,
    # Required with oidc_enabled: the redirect URI goes to the IdP and must not come from the
    # Host-Header kommen (R4-01).
    base_url="https://auth.example.com"))
assert auth.oidc is not None and auth.webauthn is not None, "OIDC/passkey modules not loaded"

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app, raise_server_exceptions=False)

# routes exist (not 404) + basic behaviour
assert c.get("/auth/login").status_code == 200
assert c.get("/auth/me").status_code == 401
assert c.post("/auth/passkey/register/begin").status_code == 401   # exists, just not logged in
assert c.get("/auth/passkey/list").status_code == 401
print("  ✓ Routen vorhanden + Guards greifen (Passwort/TOTP/OIDC/Passkey)")

# passkey login options can be generated without a browser
r = c.post("/auth/passkey/login/begin")
assert r.status_code == 200, r.text
j = r.json()
assert "challenge" in j and j.get("rpId") == "localhost", j
print("  ✓ Passkey-Login-Options generiert (challenge, rpId=localhost)")

# login page shows all active methods
html = c.get("/auth/login").text
assert "Passwort" in html and "PocketID" in html and "Passkey" in html
print("  ✓ Login-Seite: Passwort-Form + OIDC-Button + Passkey-Button")

# ---------- register/finish binds the passkey to the SIGNED-IN account (N5) ----------
# Promise in the CHANGELOG: “`register/finish` additionally binds the new passkey to the signed-in
# account instead of only to the flow cookie.” Nobody measured it: mutation M15 (the line
# `if flow["user_id"] != u["id"]` removed) ran through green with 46/46, and `grep -rn "wareg:"
# tests/` found no line that plants a FOREIGN flow. The bolt is the answer to
# “whoever can set a cookie via a subdomain” — exactly the sort of protection that silently
# disappears because its absence changes nothing in normal operation.
FLOW = "tinysesam_waflow"
a_id = auth.create_user("konto_a", password="Geheim12345!")
b_id = auth.create_user("konto_b", password="Geheim12345!")


def ok_(name):
    print(f"  ✓ {name}")


def _sitzung(uid):
    cx = TestClient(app, raise_server_exceptions=False)
    cx.cookies.set(auth.cfg.session_cookie, auth.store.create_session(uid, 3600, True, "password"))
    return cx


c_a = _sitzung(a_id)
r_begin = c_a.post("/auth/passkey/register/begin")
assert r_begin.status_code == 200, r_begin.text[:150]
flow_a = c_a.cookies.get(FLOW)
assert flow_a, "register/begin sets no flow cookie — then the attack below plants nothing"

# The attack: B is signed in and brings the flow of A along.
c_b = _sitzung(b_id)
c_b.cookies.set(FLOW, flow_a)
r_fremd = c_b.post("/auth/passkey/register/finish", json={})
assert r_fremd.status_code == 400, (
    f"foreign flow → HTTP {r_fremd.status_code}: {r_fremd.text[:150]!r} — without the bolt "
    "the registration continues and the passkey lands on the wrong account")
assert r_fremd.json().get("detail") == auth.t("api.passkey_reg_expired"), r_fremd.text[:150]
assert auth.store.list_webauthn(a_id) == [], "a passkey was added to A"
assert auth.store.list_webauthn(b_id) == [], "a passkey was added to B"

# Counter-check: with the OWN flow the same (empty) body fails at a different point —
# otherwise “400 for everyone” would be green too and the bolt not measured at all.
c_a2 = _sitzung(a_id)
assert c_a2.post("/auth/passkey/register/begin").status_code == 200
r_eigen = c_a2.post("/auth/passkey/register/finish", json={})
assert not (r_eigen.status_code == 400
            and r_eigen.json().get("detail") == auth.t("api.passkey_reg_expired")), (
    "the own flow is rejected just like the foreign one — then the check above only measures "
    f"that finish() fails with an empty body (HTTP {r_eigen.status_code})")
print("  ✓ register/finish: foreign flow → 400, no passkey on either account")

# ---------- B2-10: a passkey without user verification is not a full login ----------
# A passkey signs in ALONE in TinySesam. Without user verification it proves only possession of the
# key: the unlocked machine, the plugged-in stick, the phone put down briefly.
# Until 0.18.x the request said “preferred” AND the response was not checked —
# an authenticator could thus say no and still count.
import json as _json_b210                                                  # noqa: E402
from tinysesam.errors import ConfigError as _ConfigError                    # noqa: E402

_opt_reg = _json_b210.loads(_sitzung(a_id).post("/auth/passkey/register/begin").text)
assert _opt_reg["authenticatorSelection"]["userVerification"] == "required", _opt_reg["authenticatorSelection"]
_opt_log = _json_b210.loads(c.post("/auth/passkey/login/begin").text)
assert _opt_log["userVerification"] == "required", _opt_log
ok_("B2-10: registration and login require user verification (default)")

# Can be switched off, but not silently: the build says so, and the configuration check warns.
_db_p = os.path.join(tempfile.mkdtemp(), "t.db")
_auth_p = TinySesam(TinySesamConfig(db_path=_db_p, csrf_enabled=False, cookie_secure=False,
                                    passkey_enabled=True, rp_id="localhost",
                                    origin="http://localhost:8000",
                                    passkey_user_verification="preferred"))
_app_p = FastAPI()
_app_p.include_router(_auth_p.router())
_opt_p = _json_b210.loads(TestClient(_app_p).post("/auth/passkey/login/begin").text)
assert _opt_p["userVerification"] == "preferred", _opt_p
from tinysesam.config_check import check_config as _check_config                      # noqa: E402
_f, _w = _check_config(_auth_p.cfg)
assert any("passkey_user_verification" in x for x in _w), _w
ok_("B2-10: 'preferred' is possible but reports itself at startup and in the config check")

# A typo aborts instead of silently switching the check off.
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                              passkey_enabled=True, rp_id="localhost",
                              origin="http://localhost:8000",
                              passkey_user_verification="egal"))
    raise AssertionError("unbekannter Wert kam durch")
except _ConfigError:
    pass
ok_("B2-10: an unknown value for passkey_user_verification aborts startup")

# Throttling: the passkey login was the only sign-in path without a brake — and every call
# created a flow row that expired only after five minutes.
_db_r = os.path.join(tempfile.mkdtemp(), "t.db")
_auth_r = TinySesam(TinySesamConfig(db_path=_db_r, csrf_enabled=False, cookie_secure=False,
                                    passkey_enabled=True, rp_id="localhost",
                                    origin="http://localhost:8000"))
_auth_r.store.set_setting("rate_limit_max", "3")
_app_r = FastAPI()
_app_r.include_router(_auth_r.router())
_c_r = TestClient(_app_r)
_codes = [_c_r.post("/auth/passkey/login/begin").status_code for _ in range(6)]
assert 429 in _codes, f"no throttling on the passkey login: {_codes}"
ok_("B2-10: the passkey login is throttled like every other entry")

# Protocol: an unknown key is a failed attempt and hits the fail2ban jail.
import io as _io_b210, logging as _logging_b210                             # noqa: E402
from tinysesam import security as _sec_b210                                 # noqa: E402

# Own instance: the throttling above deliberately sealed off the previous one.
_db_l = os.path.join(tempfile.mkdtemp(), "t.db")
_auth_l = TinySesam(TinySesamConfig(db_path=_db_l, csrf_enabled=False, cookie_secure=False,
                                    passkey_enabled=True, rp_id="localhost",
                                    origin="http://localhost:8000"))
_app_l = FastAPI()
_app_l.include_router(_auth_l.router())
_puffer_b = _io_b210.StringIO()
_haken_b = _logging_b210.StreamHandler(_puffer_b)
_sec_b210.seclog.addHandler(_haken_b)
try:
    _c_l = TestClient(_app_l)
    _c_l.post("/auth/passkey/login/begin")
    _c_l.post("/auth/passkey/login/finish", content=_json_b210.dumps({"id": "gibtsnicht"}))
finally:
    _sec_b210.seclog.removeHandler(_haken_b)
_text_b = _puffer_b.getvalue()
assert _sec_b210.log_ereignis("passkey") in _text_b, f"no jail line: {_text_b[:200]!r}"
assert "reason=unknown_key" in _text_b, _text_b[:200]
assert any(e["event"] == "passkey_unknown" for e in _auth_l.store.recent_audit(limit=10))
ok_("B2-10: a failed passkey sign-in is in the log and hits the jail")

for _d in (_db_p, _db_r, _db_l):
    os.remove(_d)

os.remove(db)
print("\nMETHODEN-STRUKTUR OK ✅")
