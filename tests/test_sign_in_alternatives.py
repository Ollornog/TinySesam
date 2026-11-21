"""T-33: sign-in alternatives — cross-device sign-in (QR code), admin-issued sign-in link
without mail, and the switch `magiclink_self_request`.

Done criteria from the backlog entry, each pinned here:
* QR approval from a foreign session is refused (no session, API key, half session), and a
  device that only knows the code (read off the screen) gets no session;
* the admin link is single use and dies on disable and on password reset;
* self-request off ⇒ `/auth/magic/request` is 404, while issued links still redeem;
* `config_check`: the mailer is only needed for the self-request.
"""
import hashlib
import os
import re
import tempfile
import time

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from tinysesam import ConfigError, TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


BASE = "https://auth.example.com"
JSON = {"Accept": "application/json"}


def build(**over):
    cfg = dict(csrf_enabled=False, lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
               passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
               magiclink_enabled=True, base_url=BASE)
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    auth.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/who")
    def who(u=Depends(auth.require_user)):
        return {"u": u["username"]}
    return auth, app


def signed_in(app, user, password):
    c = TestClient(app)
    r = c.post("/auth/login", data={"username": user, "password": password}, follow_redirects=False)
    assert r.status_code == 303, (r.status_code, r.text[:200])
    return c


def who(c):
    r = c.get("/who", headers=JSON)
    return r.json().get("u") if r.status_code == 200 else None


def token_of(url):
    m = re.search(r"/auth/magic/([\w\-]+)$", url)
    assert m, url
    return m.group(1)


def audit_events(auth, event):
    return [a for a in auth.store.recent_audit(200) if a["event"] == event]


# =====================================================================================
# 1) magiclink_self_request=False: request route gone, button gone, issued links redeem
# =====================================================================================
auth, app = build(magiclink_self_request=False)
auth.ensure_admin("admin", "adminpw12345")
auth.create_user("bob", password="bobpw12345", email="bob@example.com")
bob = auth.store.get_user_by_name("bob")["id"]
guest = TestClient(app)

assert guest.get("/auth/magic/request").status_code == 404
assert guest.post("/auth/magic/request", data={"email": "bob@example.com"}).status_code == 404
ok("self-request off: GET and POST /auth/magic/request answer 404")

page = guest.get("/auth/login").text
assert "/auth/magic/request" not in page and "Email me a sign-in link" not in page, page[:400]
ok("self-request off: the login page shows no \"email me a link\" button")

link = auth.create_signin_link(bob, next="/who")
assert link["url"].startswith(BASE + "/auth/magic/"), link
tok = token_of(link["url"])
fresh = TestClient(app)
r = fresh.get(f"/auth/magic/{tok}")
assert r.status_code == 200 and "method=post" in r.text
r = fresh.post(f"/auth/magic/{tok}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/who", (r.status_code, r.headers.get("location"))
assert who(fresh) == "bob"
ok("self-request off: a link issued by app code still redeems (confirm page + POST)")

# The other side of the switch: default (True) keeps today's behaviour.
auth_on, app_on = build(smtp_host="")
assert TestClient(app_on).get("/auth/magic/request").status_code == 200
assert "/auth/magic/request" in TestClient(app_on).get("/auth/login").text
ok("self-request on (default): request route and button exist as before")

# config_check: the mailer is needed only for the self-request.
warn_on = TinySesamConfig(magiclink_enabled=True, base_url=BASE).validate()
warn_off = TinySesamConfig(magiclink_enabled=True, magiclink_self_request=False, base_url=BASE).validate()
assert any("magiclink_enabled=True" in w and "smtp_host" in w for w in warn_on), warn_on
assert not any("smtp_host" in w for w in warn_off), warn_off
ok("config_check: no mailer warning without the self-request, unchanged with it")

chain = TinySesamConfig(magiclink_enabled=True, magiclink_self_request=False, base_url=BASE,
                        login_chain=["magic"]).validate()
assert any("magiclink_self_request=False" in w for w in chain), chain
ok("config_check: a chain step 'magic' without self-request is named")

# Still mandatory: links are absolute addresses, built only from base_url.
try:
    TinySesam(TinySesamConfig(magiclink_enabled=True, magiclink_self_request=False,
                              db_path=os.path.join(tempfile.mkdtemp(), "t.db")))
    raise AssertionError("magiclink without base_url must not start")
except Exception as e:
    assert "base_url" in str(e), e
ok("base_url stays mandatory for magiclink_enabled (also without self-request)")


# =====================================================================================
# 2) Admin-issued sign-in link without mail
# =====================================================================================
auth, app = build(magiclink_self_request=False)
auth.ensure_admin("admin", "adminpw12345")
auth.create_user("bob", password="bobpw12345")
bob = auth.store.get_user_by_name("bob")["id"]
assert not auth.mail_configured()
adm = signed_in(app, "admin", "adminpw12345")
P = "/auth/admin/api/users"

before = time.time()
r = adm.post(f"{P}/{bob}/signin-link", json={"ttl_min": 30})
assert r.status_code == 200, r.text
res = r.json()
assert res["url"].startswith(BASE + "/auth/magic/") and set(res) == {"url", "expires_at", "qr"}, res
assert before + 30 * 60 - 5 <= res["expires_at"] <= time.time() + 30 * 60 + 5, res["expires_at"]
row = auth.store.get_magic_token(hashlib.sha256(token_of(res["url"]).encode()).hexdigest())
assert row["purpose"] == "login" and row["user_id"] == bob and row["email"] is None
ok("admin issues a link without a mailer: absolute address from base_url, TTL as asked")

try:
    import qrcode  # noqa: F401
    assert str(res["qr"]).startswith("data:image/png;base64,"), str(res["qr"])[:40]
    ok("admin link comes with a QR code (extra [qr] installed)")
except ImportError:
    assert res["qr"] is None
    ok("admin link without QR code (extra [qr] missing) — link only")

line = audit_events(auth, "signin_link_issue")
assert line and line[0]["username"] == "bob" and "actor=admin" in (line[0]["detail"] or "") \
    and "ttl_min=30" in line[0]["detail"], [dict(a) for a in line]
ok("audit: signin_link_issue under the account, with the admin as actor")

# Host header does not get into the link: base_url wins.
r = adm.post(f"{P}/{bob}/signin-link", json={}, headers={"Host": "evil.example.net"})
assert r.status_code == 200 and r.json()["url"].startswith(BASE + "/"), r.text
ok("the link address never comes from the Host header")

# Single use.
tok = token_of(res["url"])
dev = TestClient(app)
assert dev.post(f"/auth/magic/{tok}", follow_redirects=False).status_code == 303
assert who(dev) == "bob"
again = TestClient(app)
assert again.post(f"/auth/magic/{tok}", follow_redirects=False).status_code == 400
assert who(again) is None
ok("admin link is single use")

# Revoked on disable (and stays dead after re-enabling).
tok = token_of(adm.post(f"{P}/{bob}/signin-link", json={}).json()["url"])
assert auth.peek_magic(tok, purpose="login")
assert adm.post(f"{P}/{bob}/disable", json={"disabled": True}).status_code == 200
assert not auth.peek_magic(tok, purpose="login")
assert adm.post(f"{P}/{bob}/disable", json={"disabled": False}).status_code == 200
assert TestClient(app).post(f"/auth/magic/{tok}", follow_redirects=False).status_code == 400
ok("admin link is revoked when the account is disabled")

# Revoked on password reset by the admin.
tok = token_of(adm.post(f"{P}/{bob}/signin-link", json={}).json()["url"])
assert adm.post(f"{P}/{bob}/password", json={"password": "a-new-long-pw-123"}).status_code == 200
assert TestClient(app).post(f"/auth/magic/{tok}", follow_redirects=False).status_code == 400
ok("admin link is revoked on password reset")

# Input checks.
# T-51: the bound is `signin_link_max_ttl_min` (default 24 h; up to 0.25.x a fixed week).
for bad in (0, -5, 24 * 60 + 1, 7 * 24 * 60, "30", True, 1.5):
    r = adm.post(f"{P}/{bob}/signin-link", json={"ttl_min": bad})
    assert r.status_code == 400, (bad, r.status_code, r.text)
assert adm.post(f"{P}/{bob}/signin-link", json={"ttl_min": 24 * 60}).status_code == 200
assert adm.post(f"{P}/{bob}/signin-link", json={"ttl_min": 1}).status_code == 200
ok("TTL: 1 minute to 24 hours (signin_link_max_ttl_min), anything else 400")

assert adm.post(f"{P}/99999/signin-link", json={}).status_code == 404
svc = adm.post(P, json={"username": "svc1", "is_service": True}).json()["id"]
assert adm.post(f"{P}/{svc}/signin-link", json={}).status_code == 400
auth.create_user("carol", password="carolpw12345")
carol = auth.store.get_user_by_name("carol")["id"]
auth.set_disabled(carol, True)
assert adm.post(f"{P}/{carol}/signin-link", json={}).status_code == 400
assert not auth.store.open_token(carol, "login")
ok("no link for an unknown (404), a service or a disabled account (400)")

# Owner model: an owner's link is issued only by an owner (as password, keys, passkeys).
auth.create_user("eve", password="evepw1234567", is_admin=True)
eve = signed_in(app, "eve", "evepw1234567")
owner = auth.store.get_user_by_name("admin")["id"]
assert auth.store.get_user(owner)["is_owner"]
assert eve.post(f"{P}/{owner}/signin-link", json={}).status_code == 403
assert not auth.store.open_token(owner, "login")
assert eve.post(f"{P}/{bob}/signin-link", json={}).status_code == 200
ok("an owner's link only from an owner; another admin may issue for normal accounts")

# Not for a plain user, not for a guest.
# (bob's password above came from the admin — a start secret since T-46, his sign-in stays half until he
# chooses his own; a plain account with its own password is the case here.)
auth.create_user("plain", password="plainpw-12345")
bobc = signed_in(app, "plain", "plainpw-12345")
assert bobc.post(f"{P}/{bob}/signin-link", json={}).status_code == 403
assert TestClient(app).post(f"{P}/{bob}/signin-link", json={}).status_code in (401, 403)
ok("only admins issue links")

# The second-factor rule of every magic link applies (decision: no recovery path).
auth.totp_begin(bob)
auth.store.confirm_totp(bob)
tok = token_of(adm.post(f"{P}/{bob}/signin-link", json={}).json()["url"])
dev = TestClient(app)
r = dev.post(f"/auth/magic/{tok}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp"), r.headers.get("location")
assert who(dev) is None
ok("admin link + account with TOTP: the second factor is still demanded")

# Without base_url at runtime: 503, nothing issued.
open_before = auth.store._one("SELECT COUNT(*) AS n FROM magic_token")["n"]
auth.cfg.base_url = ""
try:
    r = adm.post(f"{P}/{bob}/signin-link", json={})
    assert r.status_code == 503, (r.status_code, r.text)
    # In code the reason names the rule (not merely "base address not allowed").
    try:
        auth.create_signin_link(bob)
        raise AssertionError("create_signin_link without base_url must raise")
    except ConfigError as e:
        assert "only from base_url" in str(e), e
finally:
    auth.cfg.base_url = BASE
assert auth.store._one("SELECT COUNT(*) AS n FROM magic_token")["n"] == open_before
ok("without base_url: 503 and no token (never a Host-header address)")

# The panel offers the button (and only with magic links on).
html_panel = adm.get("/auth/admin").text
assert "const LINKS=true" in html_panel and "signin-link" in html_panel
auth_nolink, app_nolink = build(magiclink_enabled=False, base_url="")
auth_nolink.ensure_admin("admin", "adminpw12345")
adm2 = signed_in(app_nolink, "admin", "adminpw12345")
assert "const LINKS=false" in adm2.get("/auth/admin").text
uid2 = auth_nolink.store.get_user_by_name("admin")["id"]
assert adm2.post(f"/auth/admin/api/users/{uid2}/signin-link", json={}).status_code == 404
ok("panel button and route only with magiclink_enabled")


# =====================================================================================
# 3) Cross-device sign-in (QR code)
# =====================================================================================
# The mechanics of the request with bob, an account without a second factor: that needs the switch
# `qr_login_require_second_factor=False` since H2 (T-44) — the default refusal and the number
# matching are measured in tests/test_h2_hardening.py.
auth, app = build(magiclink_enabled=False, qr_login_enabled=True, apikey_enabled=True,
                  qr_login_require_second_factor=False)
auth.ensure_admin("admin", "adminpw12345")
auth.create_user("bob", password="bobpw12345")
auth.create_user("tina", password="tinapw12345")
bob = auth.store.get_user_by_name("bob")["id"]
tina = auth.store.get_user_by_name("tina")["id"]
auth.totp_begin(tina)
auth.store.confirm_totp(tina)

UA = "ProbeDevice/1.0 (new phone)"


def start(client):
    page = client.get("/auth/login").text
    assert "/auth/qr/start" in page, page[:300]
    r = client.post("/auth/qr/start", data={"next": "/who"}, headers={"User-Agent": UA})
    assert r.status_code == 200, r.text[:300]
    code = re.search(r"name=code value='([A-Z0-9]{8})'", r.text).group(1)
    secret = re.search(r"name=secret value='([\w\-]+)'", r.text).group(1)
    # T-44: the number the approving device has to type stands only on this screen.
    MATCH[code] = re.search(r"id=qrmatch>(\d\d)<", r.text).group(1)
    return code, secret, r.text


MATCH: dict = {}


def state(client, code, secret):
    return client.post("/auth/qr/status", data={"code": code, "secret": secret}).json()["state"]


new = TestClient(app)
code, secret, page = start(new)
assert f"{BASE}/auth/qr/approve" in page and f"{code[:4]}-{code[4:]}" in page
assert secret not in re.sub(r"name=secret value='[^']*'", "", page), "the secret must only be in the hidden field"
ok("new device: page with short code, approval address from base_url, secret only hidden")

assert state(new, code, secret) == "pending"
r = new.post("/auth/qr/finish", data={"code": code, "secret": secret}, follow_redirects=False)
assert r.status_code == 409 and who(new) is None
ok("before the approval: status pending, finishing gives no session")

# The approving side needs a FULL interactive session.
r = TestClient(app).get(f"/auth/qr/approve?code={code}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login?next="), r.headers.get("location")
assert TestClient(app).post("/auth/qr/approve", data={"code": code, "match": MATCH.get(code, "")}).status_code == 401
key = auth.create_api_key(bob, name="ci")["key"]
r = TestClient(app).post("/auth/qr/approve", data={"code": code, "match": MATCH.get(code, "")}, headers={"Authorization": f"Bearer {key}"})
assert r.status_code == 401, r.status_code
half = TestClient(app)
r = half.post("/auth/login", data={"username": "tina", "password": "tinapw12345"}, follow_redirects=False)
assert r.headers["location"].startswith("/auth/totp"), r.headers.get("location")
assert half.post("/auth/qr/approve", data={"code": code, "match": MATCH.get(code, "")}).status_code == 401
assert state(new, code, secret) == "pending"
ok("approval refused without session, with an API key and from a half session")

phone = signed_in(app, "bob", "bobpw12345")
r = phone.get(f"/auth/qr/approve?code={code.lower()[:4]}-{code.lower()[4:]}")
assert r.status_code == 200 and UA in r.text and "testclient" in r.text and "bob" in r.text, r.text[:600]
ok("approving device sees the asking device (user agent, IP) and its own account")

thief = TestClient(app)
assert state(thief, code, "x" * 43) == "invalid"
r = thief.post("/auth/qr/finish", data={"code": code, "secret": "x" * 43}, follow_redirects=False)
assert r.status_code == 400 and who(thief) is None

r = phone.post("/auth/qr/approve", data={"code": code, "match": MATCH.get(code, "")})
assert r.status_code == 200 and "approved" in r.text.lower(), r.text[:300]
assert phone.post("/auth/qr/approve", data={"code": code, "match": MATCH.get(code, "")}).status_code == 400
assert state(new, code, secret) == "approved"
ok("approval works once; a second approval is refused")

r = thief.post("/auth/qr/finish", data={"code": code, "secret": "x" * 43}, follow_redirects=False)
assert r.status_code == 400 and who(thief) is None
assert state(thief, code, "") == "invalid"
ok("a device that only knows the code (read off the screen) gets no session")

r = new.post("/auth/qr/finish", data={"code": code, "secret": secret}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/who", (r.status_code, r.headers.get("location"))
assert who(new) == "bob"
assert who(phone) == "bob", "the approving device keeps its own session"
s_new = new.cookies.get(auth.session_cookie_name)
assert s_new and s_new != phone.cookies.get(auth.session_cookie_name)
ok("new device gets its OWN session after the approval")

again = new.post("/auth/qr/finish", data={"code": code, "secret": secret}, follow_redirects=False)
assert again.status_code == 400
assert state(new, code, secret) == "invalid"
ok("single use: the request cannot be redeemed twice")

ap = audit_events(auth, "qr_login_approve")
done = audit_events(auth, "qr_login")
assert ap and ap[0]["username"] == "bob" and "device_ip=" in (ap[0]["detail"] or "")
assert done and done[0]["username"] == "bob"
ok("audit: qr_login_approve (approving account) and qr_login (sign-in)")

# Direct building blocks: the store binds only once, redeem needs the approval.
code2, secret2, _ = start(TestClient(app))
assert auth._qr_redeem(code2, secret2) is None, "redeem before the approval must fail"
h2 = auth._qr_hash(code2)
assert auth.store.approve_qr_token(h2, bob) is True
assert auth.store.approve_qr_token(h2, tina) is False, "a second approval must not rebind the request"
assert auth._qr_peek(code2)["user_id"] == bob
ok("store: approval binds atomically and only once; redeem without approval fails")

# Refuse.
dev = TestClient(app)
code3, secret3, _ = start(dev)
r = phone.post("/auth/qr/deny", data={"code": code3})
assert r.status_code == 200 and "refused" in r.text.lower()
assert state(dev, code3, secret3) == "invalid"
assert dev.post("/auth/qr/finish", data={"code": code3, "secret": secret3}, follow_redirects=False).status_code == 400
assert audit_events(auth, "qr_login_deny")
ok("refusing voids the request")

# Expired.
dev = TestClient(app)
code4, secret4, _ = start(dev)
auth.store._exec("UPDATE magic_token SET expires_at=0 WHERE token_hash=?", (auth._qr_hash(code4),))
assert state(dev, code4, secret4) == "invalid"
assert phone.get(f"/auth/qr/approve?code={code4}").status_code == 400
ok("expired request: invalid on both sides")

# Approved, then the account is disabled before the new device collects: nothing.
dev = TestClient(app)
code5, secret5, _ = start(dev)
assert phone.post("/auth/qr/approve", data={"code": code5, "match": MATCH.get(code5, "")}).status_code == 200
auth.set_disabled(bob, True)
r = dev.post("/auth/qr/finish", data={"code": code5, "secret": secret5}, follow_redirects=False)
assert r.status_code == 400 and who(dev) is None
auth.set_disabled(bob, False)
ok("an approved request dies when the account is disabled")

# Second-factor rule as for the magic link: tina (TOTP) approves, the new device must still pass TOTP.
# The approving device gets a full session directly (password + TOTP done) — its own TOTP step
# is not what this case is about.
full, _ = auth.start_session(tina, "password")
auth.store.set_session_factors(auth.store.session_hash(full), ["password", "totp"], mfa_ok=True)
tphone = TestClient(app)
tphone.cookies.set(auth.session_cookie_name, full)
assert who(tphone) == "tina"
dev = TestClient(app)
code6, secret6, _ = start(dev)
assert tphone.post("/auth/qr/approve", data={"code": code6, "match": MATCH.get(code6, "")}).status_code == 200
r = dev.post("/auth/qr/finish", data={"code": code6, "secret": secret6}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp"), r.headers.get("location")
assert who(dev) is None
ok("QR sign-in + account with TOTP: the second factor is demanded (rule of the magic link)")

# Without the switch the routes do not exist.
auth_off, app_off = build(magiclink_enabled=False, base_url="")
g = TestClient(app_off)
assert g.post("/auth/qr/start").status_code == 404 and g.get("/auth/qr/approve").status_code == 404
assert "/auth/qr/start" not in g.get("/auth/login").text
ok("qr_login_enabled=False: no routes, no button")

# Without base_url: no QR code, only the short code and a relative address — never the Host header.
auth_nb, app_nb = build(magiclink_enabled=False, base_url="", qr_login_enabled=True)
auth_nb.create_user("bob", password="bobpw12345")
d = TestClient(app_nb)
r = d.post("/auth/qr/start", data={}, headers={"Host": "evil.example.net"})
assert r.status_code == 200 and "<img class=qr" not in r.text and "evil.example.net" not in r.text
assert "/auth/qr/approve" in r.text
w = TinySesamConfig(qr_login_enabled=True).validate()
assert any("qr_login_enabled=True" in x and "base_url" in x for x in w), w
ok("without base_url: short code only, no address from the Host header, config_check warns")

assert any("qr_login_ttl_sec=5" in x for x in TinySesamConfig(qr_login_ttl_sec=5).validate())
assert not any("qr_login_ttl_sec" in x for x in TinySesamConfig(qr_login_ttl_sec=120).validate())
ok("config_check: qr_login_ttl_sec within 30…900")

print("T-33 sign-in alternatives: all green")
