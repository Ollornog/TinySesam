"""Phase 6: Registrierung (deaktivierbar) + E-Mail-Verifikation + Einladung (invite-only)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def build(**cfgkw):
    sent = []
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False,
                                     # Since R4-01 the confirmation link comes from base_url,
                                     # no longer from the Host header (overridable).
                                     **{"base_url": "https://auth.example.com", **cfgkw}))
    auth.set_mailer(lambda to, s, t, html=None: sent.append({"to": to, "text": t}))
    auth.ensure_admin("admin", "geheim123-lang-genug")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, app, sent, TestClient(app)


JSON = {"Accept": "application/json"}

# ---------- Registration disabled (default) → no route ----------
db, auth, app, sent, c = build(allow_signup=False)
assert c.get("/auth/register").status_code == 404
os.remove(db)
ok("allow_signup=False → /auth/register does not exist (404)")

# ---------- Einfache Registrierung → sofort eingeloggt ----------
db, auth, app, sent, c = build(allow_signup=True)
assert "Konto erstellen" in c.get("/auth/register").text
r = c.post("/auth/register", data={"username": "neu", "password": "supergeheim-lang-genug", "email": "neu@example.com", "next": "/geheim"},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "neu"}
# zu kurzes Passwort abgelehnt
r = c.post("/auth/register", data={"username": "x", "password": "1", "next": "/"})
assert r.status_code == 400
# E-mail is required (signup_require_email, default on)
r = c.post("/auth/register", data={"username": "y", "password": "supergeheim-lang-genug", "next": "/"})
assert r.status_code == 400
# taken name (with own, free e-mail → really fails on the name)
r = c.post("/auth/register", data={"username": "neu", "password": "supergeheim-lang-genug",
                                   "email": "anders@example.com", "next": "/"})
assert r.status_code == 409
os.remove(db)
ok("allow_signup=True: Konto anlegen → eingeloggt; Validierung greift")

# ---------- E-mail verification: account only active after the link ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True)
r = c.post("/auth/register", data={"username": "verify", "password": "supergeheim-lang-genug", "email": "v@example.com", "next": "/"})
assert "Bestätigung" in r.text or "bestätig" in r.text.lower()
uid = auth.store.get_user_by_name("verify")["id"]
assert auth.store.get_user(uid)["disabled"] == 1     # still locked
assert len(sent) == 1
# The confirmation link points to its OWN endpoint, no longer to /auth/magic/ —
# otherwise magiclink_enabled=False takes the e-mail confirmation along (see below).
token = re.search(r"/auth/verify/([\w\-]+)", sent[0]["text"]).group(1)
assert "/auth/magic/" not in sent[0]["text"]
# R4-02: The GET (mail scanner, preview) only shows a confirmation page and consumes NOTHING.
for _ in range(3):
    r = c.get(f"/auth/verify/{token}", follow_redirects=False)
    assert r.status_code == 200 and "action='/auth/verify/" in r.text, (r.status_code, r.text[:200])
assert auth.store.get_user(uid)["disabled"] == 1, "a GET must not unlock the account"
assert auth.peek_magic(token, purpose="verify_email"), "a GET must not consume the token"
ok("R4-02: GET on the confirmation link consumes nothing (mail scanner)")
r = c.post(f"/auth/verify/{token}", follow_redirects=False)
assert r.status_code == 303
assert auth.store.get_user(uid)["disabled"] == 0     # aktiviert
assert c.post(f"/auth/verify/{token}", follow_redirects=False).status_code == 400   # one-shot
assert c.get(f"/auth/verify/{token}", follow_redirects=False).status_code == 400    # the page says so too
ok("signup_verify_email: own endpoint /auth/verify/{token}, redeemable once")

# B5-18: An invalid token leaves a trace (audit + security log, NOT the login jail)
import logging, io
from tinysesam import security as _sec
_puffer = io.StringIO()
_h = logging.StreamHandler(_puffer)
_sec.seclog.addHandler(_h)
try:
    c.get("/auth/verify/erfunden-123", follow_redirects=False)
finally:
    _sec.seclog.removeHandler(_h)
_zeilen = auth.store._all("SELECT * FROM audit WHERE event='token_invalid'")
assert _zeilen and "verify_email" in (_zeilen[0]["detail"] or ""), _zeilen
assert "failed verification" in _puffer.getvalue() and "failed login" not in _puffer.getvalue(), _puffer.getvalue()
ok("B5-18: invalid one-time token → audit token_invalid + `failed verification` (no login jail)")
os.remove(db)

# ---------- R4-03: a taken address answers like a free one (with confirmation) ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
auth.create_user("inhaber", password="supergeheim-lang-genug", email="da@example.com")
frei = c.post("/auth/register", data={"username": "neu1", "password": "supergeheim-lang-genug",
                                      "email": "frei@example.com", "next": "/"})
vergeben = c.post("/auth/register", data={"username": "neu2", "password": "supergeheim-lang-genug",
                                          "email": "Da@Example.com", "next": "/"})
assert frei.status_code == vergeben.status_code == 200, (frei.status_code, vergeben.status_code)
_rumpf = lambda t: re.sub(r"(nonce|value)=['\"][^'\"]*['\"]", "", t)
assert _rumpf(frei.text) == _rumpf(vergeben.text), "response differs — enumeration"
assert auth.store.get_user_by_email("da@example.com")["username"] == "inhaber", "no second account for the address"
_ph = auth.store.get_user_by_name("neu2")   # A1: name taken as with real creation, but locked and without address
assert _ph is not None and _ph["disabled"] == 1 and not _ph["email"], dict(_ph) if _ph else None
_an_inhaber = [m for m in sent if m["to"] == "da@example.com"]
assert len(_an_inhaber) == 1 and "/auth/verify/" not in _an_inhaber[0]["text"] \
    and "https://auth.example.com/auth/login" in _an_inhaber[0]["text"], _an_inhaber
ok("R4-03: taken address → same response, owner gets a notice (without token)")
# Without confirmation the success case signs in immediately — there 409 remains (limit, named in the code)
db2, auth2, app2, sent2, c2 = build(allow_signup=True)
auth2.create_user("inhaber", password="supergeheim-lang-genug", email="da@example.com")
assert c2.post("/auth/register", data={"username": "neu2", "password": "supergeheim-lang-genug",
                                       "email": "da@example.com", "next": "/"}).status_code == 409
os.remove(db2)
ok("R4-03: without confirmation it stays 409 (success signs in immediately — cannot be hidden)")
os.remove(db)

# ---------- B6-5: if sending the confirmation fails, no zombie account and no 500 remains ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
def _kaputt(*a, **k):
    raise OSError("Mailserver weg")
auth.set_mailer(_kaputt)
cx = TestClient(app, raise_server_exceptions=False)
r = cx.post("/auth/register", data={"username": "pech", "password": "supergeheim-lang-genug",
                                    "email": "pech@example.com", "next": "/"})
assert r.status_code == 200, r.status_code
assert auth.store.get_user_by_name("pech") is None, "account must be withdrawn"
_ev = [z["event"] for z in auth.store._all("SELECT event FROM audit")]
assert "verify_send_error" in _ev, _ev
# … and the registration can be repeated as soon as the mailer works again
auth.set_mailer(lambda to, s_, t, html=None: sent.append({"to": to, "text": t}))
r = cx.post("/auth/register", data={"username": "pech", "password": "supergeheim-lang-genug",
                                    "email": "pech@example.com", "next": "/"})
assert r.status_code == 200 and auth.store.get_user_by_name("pech") is not None
ok("B6-5: mailer error during registration → no 500, account withdrawn, possible again")
os.remove(db)

# ---------- R4-09: never-confirmed accounts are cleared by gc() — and ONLY those ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
c.post("/auth/register", data={"username": "squatter", "password": "supergeheim-lang-genug",
                               "email": "opfer@example.com", "next": "/"})
sq = auth.store.get_user_by_name("squatter")["id"]
# Counter-check 1: an existing account locked by the admin without a confirmation token
alt = auth.create_user("gesperrt", password="supergeheim-lang-genug", email="g@example.com")
auth.store.set_disabled(alt, True)
# Counter-check 2: a confirmed and later locked account (redeemed token alongside)
c.post("/auth/register", data={"username": "echt", "password": "supergeheim-lang-genug",
                               "email": "echt@example.com", "next": "/"})
echt = auth.store.get_user_by_name("echt")["id"]
_tok = re.search(r"/auth/verify/([\w\-]+)", sent[-1]["text"]).group(1)
assert auth.redeem_magic(_tok, purpose="verify_email")
auth.store._exec("UPDATE magic_token SET expires_at=0")
auth.store.set_disabled(echt, True)
assert auth.gc()["unverified_accounts"] == 1
assert auth.store.get_user(sq) is None, "never-confirmed account removed after expiry"
assert auth.store.get_user(alt) is not None, "locked existing account remains"
assert auth.store.get_user(echt) is not None, "confirmed account remains"
assert c.post("/auth/register", data={"username": "richtig", "password": "supergeheim-lang-genug",
                                      "email": "opfer@example.com", "next": "/"}).status_code == 200
assert auth.store.get_user_by_name("richtig") is not None, "the address is free again"
ok("R4-09: gc() removes never-confirmed accounts after the link expires — only those")
os.remove(db)

# ---------- Attack A1: username as an oracle for the address (R4-03 bypassed) ----------
# Before, the registration checked the address BEFORE the name: taken name + taken address
# → 200, taken name + free address → 409. And a throwaway name revealed on the second attempt
# by 409 whether the first had created an account.
for _modus in ("both", "username"):
    db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, login_identifier=_modus)
    auth.create_user("opfer", password="supergeheim-lang-genug", email="vergeben@example.com")
    _reg = lambda n, e: c.post("/auth/register", data={"username": n, "password": "supergeheim-lang-genug",
                                                       "email": e, "next": "/"}).status_code
    assert _reg("admin", "vergeben@example.com") == _reg("admin", "frei@example.com") == 409, _modus
    assert _reg("zz1", "vergeben@example.com") == _reg("zz2", "frei2@example.com") == 200, _modus
    assert _reg("zz1", "zz1@probe.example") == _reg("zz2", "zz2@probe.example") == 409, _modus
    # The address in the name field (foreign address) revealed the same via the cross check
    assert _reg("vergeben@example.com", "x1@probe.example") == _reg("frei3@example.com", "x2@probe.example") == 400
    assert auth.store._exec("SELECT COUNT(*) FROM users WHERE email='vergeben@example.com'").fetchone()[0] == 1
    # The placeholder is cleared by gc() after expiry — like a never-confirmed real account
    auth.store._exec("UPDATE magic_token SET expires_at=0")
    auth.gc()
    assert auth.store.get_user_by_name("zz1") is None and auth.store.get_user_by_name("zz2") is None
    assert auth.store.get_user_by_name("opfer") is not None
    os.remove(db)
# Name = own address remains allowed and goes through the address check (same response)
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
auth.create_user("opfer", password="supergeheim-lang-genug", email="vergeben@example.com")
_reg = lambda n, e: c.post("/auth/register", data={"username": n, "password": "supergeheim-lang-genug",
                                                   "email": e, "next": "/"}).status_code
assert _reg("vergeben@example.com", "vergeben@example.com") == _reg("frei@example.com", "frei@example.com") == 200
os.remove(db)
ok("A1: taken name, throwaway name and address in the name field no longer reveal the address")

# ---------- Attack A2: notice mails do not use up the owner's quota ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                               password_reset_enabled=True)
auth.create_user("opfer", password="supergeheim-lang-genug", email="opfer@example.com")
for _i in range(5):
    c.post("/auth/register", data={"username": f"angr{_i}", "password": "supergeheim-lang-genug",
                                   "email": "opfer@example.com", "next": "/"})
_hinweise = [m for m in sent if m["to"] == "opfer@example.com"]
assert len(_hinweise) == 3, len(_hinweise)          # the notices themselves remain throttled
_n = len(sent)
assert c.post("/auth/forgot", data={"email": "opfer@example.com"}).status_code == 200
assert c.post("/auth/magic/request", data={"email": "opfer@example.com", "next": "/"}).status_code == 200
_neu = sent[_n:]
assert len(_neu) == 2 and "/auth/reset" in _neu[0]["text"] and "/auth/magic/" in _neu[1]["text"], _neu
os.remove(db)
ok("A2: notices triggered by others do not block the owner's reset and sign-in link")

# ---------- Attack A3: invalid tokens do not fill the audit log ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                               password_reset_enabled=True)
import logging as _logging, io as _io
from tinysesam import security as _sec2
_puffer = _io.StringIO()
_h = _logging.StreamHandler(_puffer)
_sec2.seclog.addHandler(_h)
try:
    for _i in range(200):
        assert c.get(f"/auth/magic/x{_i}").status_code == 400
finally:
    _sec2.seclog.removeHandler(_h)
_z = lambda ev: auth.store._exec("SELECT COUNT(*) FROM audit WHERE event=?", (ev,)).fetchone()[0]
assert _z("token_invalid") == auth._TOKEN_AUDIT_MAX, _z("token_invalid")
assert _z("token_invalid_throttled") == 1, "exactly one row when the cap applies"
assert _puffer.getvalue().count("failed verification") == 200, "the security log (fail2ban) sees everything"
# GET /auth/reset without a token is not a presented link — no entry, no log line
db2, auth2, app2, sent2, c2 = build(password_reset_enabled=True)
_puffer = _io.StringIO()
_h = _logging.StreamHandler(_puffer)
_sec2.seclog.addHandler(_h)
try:
    assert c2.get("/auth/reset").status_code == 400
finally:
    _sec2.seclog.removeHandler(_h)
assert auth2.store._exec("SELECT COUNT(*) FROM audit WHERE event='token_invalid'").fetchone()[0] == 0
assert "failed verification" not in _puffer.getvalue()
os.remove(db); os.remove(db2)
ok("A3: token_invalid in the audit log globally capped (+1 notice row), /auth/reset without token no false alarm")

# ---------- Attack A5: existing address in Unicode form, input as A-label ----------
db, auth, app, sent, c = build(allow_signup=True)
auth.store._exec("INSERT INTO users(username, email, created_at) VALUES ('alt', 'user@bücher.example', 0)")
assert auth.store.get_user_by_email("user@xn--bcher-kva.example")["username"] == "alt"
assert auth.store.get_user_by_email("USER@XN--BCHER-KVA.example")["username"] == "alt"
assert c.post("/auth/register", data={"username": "neu", "password": "supergeheim-lang-genug",
                                      "email": "user@xn--bcher-kva.example", "next": "/"}).status_code == 409
assert auth.store._exec("SELECT COUNT(*) FROM users WHERE username IN ('alt','neu')").fetchone()[0] == 1
os.remove(db)
ok("A5: A-label input finds the existing address in Unicode form — no second account")

# … and that works WITHOUT magic link. That was the actual error: both hung on the same
# endpoint, so losing the sign-in link also lost the confirmation.
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=False)
c.post("/auth/register", data={"username": "ohne", "password": "supergeheim-lang-genug",
                               "email": "o@example.com", "next": "/"})
uid = auth.store.get_user_by_name("ohne")["id"]
token = re.search(r"/auth/verify/([\w\-]+)", sent[0]["text"]).group(1)
assert c.post(f"/auth/verify/{token}", follow_redirects=False).status_code == 303
assert auth.store.get_user(uid)["disabled"] == 0
assert c.get("/auth/magic/request").status_code == 404     # magic link is really off
ok("e-mail confirmation works without magic link")
os.remove(db)

# ---------- Invite-only: no access without invitation, ok with invitation ----------
db, auth, app, sent, c = build(allow_signup=True, signup_invite_only=True, magiclink_enabled=True)
assert c.get("/auth/register").status_code == 403        # without invitation
# The base comes from base_url, not from the host of the TestClient: `create_invite` checks it
# itself since R4-01 and rejects a foreign host with ConfigError (no token, no mail).
inv = auth.create_invite("gast@example.com", auth.cfg.base_url, roles=["editor"])
token = inv["token"]
# open link → redirect to registration (token NOT consumed)
assert "/auth/invite/" in inv["url"] and "/auth/magic/" not in inv["url"]
r = c.get(f"/auth/invite/{token}", follow_redirects=False)
assert r.status_code == 303 and "/auth/register?invite=" in r.headers["location"]
# registration page reachable with invitation, e-mail prefilled
page = c.get(f"/auth/register?invite={token}").text
assert "gast@example.com" in page
# register → account with roles from the invitation, logged in
r = c.post("/auth/register", data={"username": "gast", "password": "supergeheim-lang-genug", "invite": token, "next": "/geheim"},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
u = auth.store.get_user_by_name("gast")
assert u and auth.has_role(u, "editor")
# invitation is consumed → using it again fails
assert auth.peek_magic(token, purpose="invite") is None
r2 = TestClient(app).get(f"/auth/register?invite={token}")
assert r2.status_code == 403
ok("invite-only: only with a valid invitation; roles taken over; invitation one-shot")
os.remove(db)

print("\nREGISTER + INVITE OK ✅")
