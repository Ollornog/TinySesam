"""Batch C: TOTP recovery codes (one-shot) + forgot password (reset by e-mail)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import time
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


sent = []
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, magiclink_enabled=True, password_reset_enabled=True,
                                 recovery_code_count=6,
                                 # Mail links have required a promised address since R4-01.
                                 base_url="https://auth.example.com"))
auth.set_mailer(lambda to, s, t, html=None: sent.append({"to": to, "text": t}))
auth.ensure_admin("admin", "dummy123-long-enough")
uid = auth.store.get_user_by_name("admin")["id"]
auth.store._exec("UPDATE users SET email=? WHERE id=?", ("admin@example.com", uid))
app = FastAPI()
app.include_router(auth.router())


@app.get("/secret")
def secret_text(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# ---------- Recovery codes: redeemable in the TOTP step, one-shot ----------
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))
codes = auth.generate_recovery_codes(uid)
assert len(codes) == 6 and auth.recovery_codes_remaining(uid) == 6
ok("generate_recovery_codes → 6 Codes")

# login → TOTP step; enter a recovery code instead of TOTP
c.post("/auth/login", data={"username": "admin", "password": "dummy123-long-enough", "next": "/secret"}, follow_redirects=False)
assert c.get("/secret", headers=JSON).status_code == 401
r = c.post("/auth/totp", data={"code": codes[0], "next": "/secret"}, follow_redirects=False)
assert r.status_code == 303 and c.get("/secret", headers=JSON).json() == {"u": "admin"}
assert auth.recovery_codes_remaining(uid) == 5
ok("recovery code instead of TOTP → logged in (consumed: 6→5)")

# the same code a second time → invalid
c.get("/auth/logout")
c.post("/auth/login", data={"username": "admin", "password": "dummy123-long-enough", "next": "/"}, follow_redirects=False)
assert c.post("/auth/totp", data={"code": codes[0], "next": "/"}).status_code == 401
ok("consumed recovery code is invalid (one-shot)")

# Self-service regeneration requires being logged in + TOTP
c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
r = c.post("/auth/totp/recovery")
assert r.status_code == 200 and len(r.json()["codes"]) == 6
assert auth.recovery_codes_remaining(uid) == 6   # replaces the old ones
ok("self-service: new recovery codes replace the old ones")
c.get("/auth/logout")

# ---------- Forgot-Password ----------
assert "Passwort vergessen" in c.get("/auth/login").text   # link to the login page
sent.clear()
# unknown address → generic, no mail
c.post("/auth/forgot", data={"email": "foreign@example.com"})
assert sent == []
# known address → reset mail
c.post("/auth/forgot", data={"email": "admin@example.com"})
assert len(sent) == 1
# The reset link points straight at the reset page — until 0.15 it went via /auth/magic/ and
# thus took a detour through an endpoint that has nothing to do with the reset.
token = re.search(r"/auth/reset\?token=([\w\-]+)", sent[0]["text"]).group(1)
assert "/auth/magic/" not in sent[0]["text"]
ok("forgot: reset link only for an existing account (no enumeration)")

assert "Neues Passwort" in c.get(f"/auth/reset?token={token}").text
# password too short → 400
assert c.post("/auth/reset", data={"token": token, "password": "x"}).status_code == 400
# set new password → redirect to login, token consumed
r = c.post("/auth/reset", data={"token": token, "password": "ganzneuespw-long-enough"}, follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"]
assert auth.peek_magic(token, purpose="reset_password") is None
ok("Reset: new password set, token consumed")

# The reset depends on the mailer, not on the magic link. Until 0.15 the route required both
# (password_reset_enabled AND magiclink_enabled) — two things that have nothing to do with each other.
db_x = os.path.join(tempfile.mkdtemp(), "t.db")
post_x = []
ax = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_x, cookie_secure=False,
                               passkey_enabled=False, password_reset_enabled=True,
                               magiclink_enabled=False, base_url="https://auth.example.com"))
ax.set_mailer(lambda to, subject, text, html=None: post_x.append(text))
ax.create_user("without", "old-secret", email="without@example.com")
appx = FastAPI()
appx.include_router(ax.router())
cx = TestClient(appx, headers={"Accept": "text/html"})
assert cx.get("/auth/magic/request").status_code == 404, "magic link is off"
assert cx.get("/auth/forgot").status_code == 200, "forgot-password remains reachable anyway"
cx.post("/auth/forgot", data={"email": "without@example.com"})
tok_x = re.search(r"/auth/reset\?token=([\w\-]+)", post_x[0]).group(1)
r = cx.post("/auth/reset", data={"token": tok_x, "password": "fresh-passwordxxx"},
            follow_redirects=False)
assert r.status_code == 303
assert ax._check_password("without", "fresh-passwordxxx")
os.remove(db_x)
ok("password reset works without magic link (coupling removed)")

# old password gone, new one works
c2 = TestClient(app)
assert c2.post("/auth/login", data={"username": "admin", "password": "dummy123-long-enough"}, follow_redirects=False).status_code == 401
r = c2.post("/auth/login", data={"username": "admin", "password": "ganzneuespw-long-enough", "next": "/"}, follow_redirects=False)
assert r.status_code == 303
ok("after reset: old password invalid, new one valid")

# ---------- R4-13 / H-10: the reset is the way out of the lockout ----------
# Until T-13 the self-service reset set the password and left the failed attempts standing:
# whoever had locked themselves out and took the intended path stood in front of
# the same 429 with the NEW password — until the window expired or an admin ran `tinysesam unlock`. The reset
# does not check the lockout (independent path, H-10) and now lifts the password lockout. The
# TOTP failed attempts remain: a mailbox does not prove the second factor.
# (Mutation probe: remove `lift_lockout` in `reset_submit` → 429 instead of 303.)
db_s = os.path.join(tempfile.mkdtemp(), "t.db")
post_s = []
a_s = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_s, cookie_secure=False,
                                passkey_enabled=False, password_reset_enabled=True,
                                base_url="https://auth.example.com"))
a_s.set_mailer(lambda to, subject, text, html=None: post_s.append(text))
a_s.create_user("gesperrt", "old-secret-1xxxxx", email="locked@example.com")
app_s = FastAPI()
app_s.include_router(a_s.router())
c_s = TestClient(app_s, headers={"Accept": "text/html"})
for _i in range(a_s._sec("max_login_attempts")):
    assert c_s.post("/auth/login", data={"username": "gesperrt", "password": f"forgotten-{_i}"}).status_code == 401
a_s._record_login("gesperrt", "testclient", False, "totp")       # a slip on the second factor
assert c_s.post("/auth/login", data={"username": "gesperrt", "password": "old-secret-1xxxxx"}).status_code == 429, \
    "precondition: the account is locked"
c_s.post("/auth/forgot", data={"email": "locked@example.com"})
# The reset mail — not the first: since ASVS 6.3.5 the lockout notice goes out beforehand.
a_s._notice_outcome.wait()
tok_s = re.search(r"/auth/reset\?token=([\w\-]+)", next(m for m in post_s if "/auth/reset?token=" in m)).group(1)
assert c_s.post("/auth/reset", data={"token": tok_s, "password": "new-secret-2xxxxx"},
                follow_redirects=False).status_code == 303, "the reset itself depends on the lockout"
r = c_s.post("/auth/login", data={"username": "gesperrt", "password": "new-secret-2xxxxx"},
             follow_redirects=False)
assert r.status_code == 303, f"still locked after the reset: {r.status_code}"
ok("R4-13/H-10: the reset bypasses the lockout and lifts it")
# The login above was complete and thus cleared everything anyway (R7-1); the
# reset is therefore measured directly on the counter, with a fresh slip per method.
a_s._record_login("gesperrt", "testclient", False, "password")
a_s._record_login("gesperrt", "testclient", False, "totp")
away = a_s.lift_lockout(a_s.store.get_user_by_name("gesperrt")["id"], methods=("password",))
assert away == 1 and a_s.store.count_fails(0, username="gesperrt", method="totp") == 1, \
    "the reset also clears failed attempts on the second factor"
assert any("failed_attempts_discarded=" in (z["detail"] or "") for z in a_s.store.recent_audit(20)
           if z["event"] == "password_reset"), "the audit log does not say what the reset cleared"
ok("…only the password failed attempts, not those of the second factor; the audit log gives the number")
os.remove(db_s)


# ---------- base_url with whitespace (C-2): the link stays clean, an unusable base fails at build time ----------
from tinysesam.errors import ConfigError as _CfgErr
_db2 = os.path.join(tempfile.mkdtemp(), "t.db")
_a2 = TinySesam(TinySesamConfig(db_path=_db2, rp_name="T", passkey_enabled=False, oidc_enabled=False,
                                cookie_secure=False, password_reset_enabled=True,
                                base_url="https://auth.example.com "))
_post = []
_a2.set_mailer(lambda to, subject, text, html=None: _post.append(text))
_a2.create_user("lea", password="dummy12345-long-enough", email="lea@example.com")
_a2.send_password_reset("lea@example.com", _a2.cfg.base_url)
assert _post and " " not in _post[0].split("https://auth.example.com", 1)[1].split()[0] \
    and "https://auth.example.com/auth/reset" in _post[0], _post
try:
    TinySesam(TinySesamConfig(db_path=_db2, rp_name="T", passkey_enabled=False, oidc_enabled=False,
                              cookie_secure=False, password_reset_enabled=True, base_url="auth.example.com"))
    raise AssertionError("base_url without scheme was accepted")
except _CfgErr as e:
    assert "base_url" in str(e), e
os.remove(_db2)
print("  (C-2) base_url is trimmed, rejected without scheme ok")

# ---------- B2-7: a consumed recovery code is tracked and reported ----------
# (Mutation probe: in `verify_recovery_code` directly `return self.store.consume_recovery_code(…)`
# as before T-13 → red: no audit row, no event.)
db_r = os.path.join(tempfile.mkdtemp(), "r.db")
auth_r = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_r, passkey_enabled=False,
                                   oidc_enabled=False, cookie_secure=False, recovery_code_count=4,
                                   password_reset_enabled=True, base_url="https://auth.example.com"))
post_r = []
auth_r.set_mailer(lambda to, s, t, html=None: post_r.append(t))
event_r = []
auth_r.on_security_event = lambda e, k, d: event_r.append((e, d))
uid_r = auth_r.create_user("rita", "rita-secret-1-long", email="rita@example.com")
secret_text_r = auth_r.totp_begin(uid_r)["secret"]
auth_r.totp_confirm(uid_r, pyotp.TOTP(secret_text_r).at(time.time() - 30))
codes_r = auth_r.generate_recovery_codes(uid_r)
app_r = FastAPI()
app_r.include_router(auth_r.router())
cr = TestClient(app_r)
cr.post("/auth/login", data={"username": "rita", "password": "rita-secret-1-long"}, follow_redirects=False)
assert cr.post("/auth/totp", data={"code": codes_r[0], "next": "/"}, follow_redirects=False).status_code == 303
lines = [z for z in auth_r.store.recent_audit(20) if z["event"] == "recovery_used"]
assert len(lines) == 1 and "remaining=3" in lines[0]["detail"], lines
assert ("recovery_code_used", {"remaining": 3}) in event_r, event_r
page_html = cr.get("/auth/account").text
assert "Nur noch 3 Recovery-Codes" in page_html, "the account page does not show the small remainder"
auth_r.generate_recovery_codes(uid_r)
assert "4 Recovery-Codes übrig" in cr.get("/auth/account").text
assert [e for e, _ in event_r] == ["totp_enabled", "recovery_codes_generated", "recovery_code_used",
                                   "recovery_codes_generated"], event_r
ok("B2-7: recovery consumption → audit with remainder, event, display on the account page")

# ---------- R4-14: the self-service reset revokes the API keys ----------
# (Mutation probe: remove `revoke_user_api_keys` from reset_submit → red.)
key_r = auth_r.create_api_key(uid_r, name="ci")["key"]
assert auth_r.verify_api_key(key_r)[0] is not None
auth_r.send_password_reset("rita@example.com", auth_r.cfg.base_url)
tok_r = re.search(r"/auth/reset\?token=([\w\-]+)", post_r[-1]).group(1)
# The rule first: a weak password is rejected and leaves the link valid. Long enough
# for the single-factor length (B2-4), but only the account name twice — the context word applies.
r = cr.post("/auth/reset", data={"token": tok_r, "password": "Rita2024!Rita2024!"})
assert r.status_code == 400 and "leicht zu erraten" in r.text
assert auth_r.peek_magic(tok_r, purpose="reset_password"), "a rejected password invalidates the link"
r = cr.post("/auth/reset", data={"token": tok_r, "password": "a-fresh-passwordxxxxx"}, follow_redirects=False)
assert r.status_code == 303
assert auth_r.verify_api_key(key_r)[0] is None, "the API key survives the reset"
assert auth_r.store.count_active_api_keys(uid_r) == 0
assert any(z["event"] == "password_reset" and "api_keys_revoked=1" in (z["detail"] or "")
           for z in auth_r.store.recent_audit(20))
# Since limit e the reset also reports the collected key revocation — after the password change.
assert [e for e, _ in event_r[-2:]] == ["password_changed", "api_keys_revoked"], event_r[-2:]
ok("R4-14: password reset by mail revokes the API keys (and checks the password rule)")

# A-8: a dead link takes precedence over the password rule — otherwise it said "too easy", and only the
# second attempt revealed that the link no longer applies. (tok_r is consumed above.)
for _tok in ("nonsense", tok_r):
    r = cr.post("/auth/reset", data={"token": _tok, "password": "password"})
    assert r.status_code == 400 and auth_r.t("magic.invalid") in r.text, r.text[:300]
    assert "leicht zu erraten" not in r.text
ok("A-8: invalid or consumed link → “Link invalid” before the password rule")

# Integration finding 4 (A-8 × B5-18): the A-8 pre-check returned early WITHOUT
# `token_rejected` — the call from B5-18 was only behind `redeem_magic` and was unreachable for a
# dead token. Whoever probed reset tokens via POST or replayed a used link
# appeared neither in the audit log nor in the fail2ban verify jail; the GET did.
# (Mutation probe: remove the `token_rejected` call in the A-8 branch of `reset_submit` → red.)
import io as _io  # noqa: E402
import logging as _logging  # noqa: E402
from tinysesam import security as _security  # noqa: E402


def _token_traces():
    return len(auth_r.store._all("SELECT id FROM audit WHERE event='token_invalid' "
                                 "AND detail LIKE 'purpose=reset_password%'"))


_buffer_r = _io.StringIO()
_check_r = _logging.StreamHandler(_buffer_r)
_security.seclog.addHandler(_check_r)
try:
    _before_r = _token_traces()
    for _tok, _pw in (("invented-1", "a-fresh-passwordxxxxx"),   # guessed, password is acceptable
                      ("invented-2", "x"),                       # guessed, password too short
                      (tok_r, "still-a-fresh-passwordxxxx")):     # already redeemed
        r = cr.post("/auth/reset", data={"token": _tok, "password": _pw})
        assert r.status_code == 400, (_tok, r.status_code)
    _new_r = _token_traces() - _before_r
    _log_r = [z for z in _buffer_r.getvalue().splitlines()
              if z.startswith(_security.LOG_CHECK) and "token_reset_password" in z]
    assert _new_r == 3 and len(_log_r) == 3, (_new_r, _buffer_r.getvalue())
    # Without a token this is not a presented link (A3) — no row, as with the GET.
    assert cr.post("/auth/reset", data={"token": "", "password": "whatever-was"}).status_code == 400
    assert _token_traces() - _before_r == 3 and len(
        [z for z in _buffer_r.getvalue().splitlines() if "token_reset_password" in z]) == 3
finally:
    _security.seclog.removeHandler(_check_r)
ok("finding 4: POST /auth/reset with dead token → token_invalid in the audit + “failed verification” (like the GET)")
auth_r.totp_disable(uid_r)
assert event_r[-1] == ("totp_disabled", {"recovery_codes_deleted": 4}), event_r[-1]
os.remove(db_r)

# ---------- H-4: no reset link for a pure SSO account ----------
# A reset on an account that signs in only via IdP/directory set a LOCAL
# password — a second path around lockout, group removal and the provider's MFA requirement. With
# LDAP a local password even wins over the directory.
sent.clear()
_sso = auth.create_user("sso-user", email="sso@example.com")
auth.store.link_oidc("https://idp.example.com", "sub-sso", _sso)
_ldap = auth.create_user("ldap-user", email="ldap@example.com")
auth.store.link_federated("ldap", "uuid-ldap", _ldap, 0)
_mixed = auth.create_user("mixed", password="local-pw-123-ab", email="mixed@example.com")
auth.store.link_oidc("https://idp.example.com", "sub-mixed", _mixed)
for _address in ("sso@example.com", "ldap@example.com"):
    assert c.post("/auth/forgot", data={"email": _address}).status_code == 200
assert sent == [], f"a pure SSO account got a reset link: {[m['to'] for m in sent]}"
assert sum(1 for z in auth.store.recent_audit(30) if z["event"] == "reset_sso_only") == 2
# The outward answer is the same as for an unknown address — no account probing.
def _without_nonce(response):
    return response.status_code, re.sub(r'nonce="[^"]*"', "", response.text)


assert _without_nonce(c.post("/auth/forgot", data={"email": "sso@example.com"})) == \
    _without_nonce(c.post("/auth/forgot", data={"email": "gibtsnicht@example.com"}))
ok("H-4: pure SSO account (OIDC or LDAP bound, no local password) gets no reset link")
# Counter-check: bound AND with a local password — the local password is a path of its own and
# remains resettable.
c.post("/auth/forgot", data={"email": "mixed@example.com"})
assert [m["to"] for m in sent] == ["mixed@example.com"], sent
ok("H-4: …a federated account WITH a local password remains resettable")

os.remove(db)
print("\nRECOVERY + RESET OK ✅")
