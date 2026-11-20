"""Account setup after the first sign-in: B-8, B-9a/B-9b and B-10.

B-8   A voluntary TOTP setup answered `{"ok": true}` without `next` — the page stayed on "2FA active".
B-9a  The setup created no recovery codes; the account page then greeted the fresh 2FA with
      "only 0 recovery codes left".
B-9b  The remainder line sat inline next to the buttons (wrapped, overlapped) and kept the old number
      after "generate" — the layout itself is measured in `tests/test_browser.py`.
B-10  An account without a password (sign-in link, OIDC, passkey) could never get one: the account page
      asked for the current password and `change_password` refused the empty one.

Real CSRF everywhere (the default), so the routes are measured as the browser meets them.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    cfg = dict(db_path=db, cookie_secure=False, passkey_enabled=False, lang="en", rp_name="Test")
    cfg.update(over)
    a = TinySesam(TinySesamConfig(**cfg))
    a.set_security("password_min_length_single_factor", 8)
    app = FastAPI()
    app.include_router(a.router())
    return a, app


def csrf(client, a):
    return client.cookies.get(a.csrf_cookie_name) or ""


def sign_in(a, app, uid, method="magic"):
    """A browser with a full session of `uid` — the way a sign-in link or OIDC leaves it."""
    c = TestClient(app)
    token, full = a.start_session(uid, method)
    assert full, "the probe needs a full session"
    c.cookies.set(a.session_cookie_name, token)
    assert c.get("/auth/account").status_code == 200       # also hands out the CSRF cookie
    return c


def setup_totp(c, a, next_=None):
    """Walk the built-in setup: page → start (secret) → confirm. Returns the confirm response."""
    q = "" if next_ is None else f"?next={next_}"
    page = c.get(f"/auth/totp/setup{q}")
    assert page.status_code == 200, page.status_code
    shown_next = re.search(r"name=next value='([^']*)'", page.text).group(1)
    started = c.post("/auth/totp/setup/start", data={"_csrf": csrf(c, a), "next": shown_next})
    assert started.status_code == 200, started.status_code
    secret = re.search(r"class=mono>([A-Z2-7]+)<", started.text).group(1)
    data_next = re.search(r"data-next='([^']*)'", started.text).group(1)
    return c.post("/auth/totp/setup", data={"code": pyotp.TOTP(secret).now(), "next": data_next},
                  headers={"X-CSRF-Token": csrf(c, a)}), started.text


# ---------- B-8 + B-9a: the voluntary setup leads on and hands out the codes ----------
auth, app = build()
alice = auth.create_user("alice", password="alice-pw-123456")
c = sign_in(auth, app, alice, "password")
r, page = setup_totp(c, auth, next_="/auth/account")
j = r.json()
assert r.status_code == 200 and j["ok"] is True, r.text[:200]
assert j.get("next") == "/auth/account", f"B-8: no target after the voluntary setup: {j!r}"
ok("B-8: voluntary setup answers with `next` (the given target)")

codes = j.get("recovery_codes") or []
assert len(codes) == auth.cfg.recovery_code_count, f"B-9a: setup hands out {len(codes)} recovery codes"
assert auth.recovery_codes_remaining(alice) == len(codes), auth.recovery_codes_remaining(alice)
assert auth.store.consume_recovery_code(alice, auth._rc_hash(codes[0])), "a handed-out code does not work"
ok(f"B-9a: activation creates {len(codes)} recovery codes and hands them out once")

# The page shows them only after activation, with a confirmation before it leads on.
assert "id=rcbox hidden" in page and "id=rcdone" in page, "no hidden code box on the setup page"
assert auth.t("setup.recovery_done") in page
assert re.search(r"if\(!codes\.length\)\{go\(\);return false\}", page), "the page leads on without the codes"
ok("B-9a: setup page holds the codes back until activation, then waits for „written down“")

# Without `next`: back to the account page (it is on), not to `/`.
bob = auth.create_user("bob", password="bob-pw-1234567")
cb = sign_in(auth, app, bob, "password")
r, page = setup_totp(cb, auth)
assert "data-next='/auth/account'" in page, re.search(r"data-next='[^']*'", page)
assert r.json().get("next") == "/auth/account", r.json()
# …and a foreign target stays out (open redirect).
carl = auth.create_user("carl", password="carl-pw-1234567")
cc = sign_in(auth, app, carl, "password")
r, _ = setup_totp(cc, auth, next_="https://evil.example/x")
assert r.json().get("next") == "/", r.json()
ok("B-8: without a target → account page; a foreign target → fallback, not the foreign host")

# Without the account page the fallback is `login_redirect`.
auth_na, app_na = build(account_enabled=False)
dora = auth_na.create_user("dora", password="dora-pw-123456")
cd = TestClient(app_na)
cd.get("/auth/login")
assert cd.post("/auth/login", data={"username": "dora", "password": "dora-pw-123456", "_csrf": csrf(cd, auth_na)},
               follow_redirects=False).status_code == 303
r, page = setup_totp(cd, auth_na)
assert r.json().get("next") == "/", r.json()
ok("B-8: account page off → fallback `login_redirect`")

# ---------- B-9a: the mandatory setup under the chain hands them out too ----------
auth_ch, app_ch = build(login_chain=["password", "totp"])
auth_ch.create_user("erin", password="erin-pw-123456")
erin = auth_ch.store.get_user_by_name("erin")["id"]
ce = TestClient(app_ch)
ce.get("/auth/login")
assert ce.post("/auth/login", data={"username": "erin", "password": "erin-pw-123456", "_csrf": csrf(ce, auth_ch),
                                    "next": "/target"}, follow_redirects=False).status_code == 303
r, page = setup_totp(ce, auth_ch, next_="/target")
j = r.json()
assert j["ok"] is True and j["next"] == "/target", j
assert len(j.get("recovery_codes") or []) == auth_ch.cfg.recovery_code_count, j
assert auth_ch.recovery_codes_remaining(erin) == auth_ch.cfg.recovery_code_count
assert "id=rcbox hidden" in page
ok("B-9a: mandatory setup (login_chain) hands out the codes as well, then leads to the target")

# A wrong code creates nothing.
frank = auth.create_user("frank", password="frank-pw-123456")
cf = sign_in(auth, app, frank, "password")
cf.get("/auth/totp/setup")
cf.post("/auth/totp/setup/start", data={"_csrf": csrf(cf, auth), "next": "/"})
r = cf.post("/auth/totp/setup", data={"code": "000000", "next": "/"}, headers={"X-CSRF-Token": csrf(cf, auth)})
assert r.json() == {"ok": False, "other_sessions": 0}, r.json()
assert auth.recovery_codes_remaining(frank) == 0
ok("wrong code: no codes, no target")

# ---------- B-9a/B-9b: the account page tells „none“ from „only n“, below the buttons ----------
gina = auth.create_user("gina", password="gina-pw-1234567")
cg = sign_in(auth, app, gina, "password")
auth.totp_begin(gina)
auth.store.confirm_totp(gina)
html = cg.get("/auth/account").text
none_text = auth.t("acc.recovery_none")
assert none_text in html, "B-9a: zero codes are not reported as „none“"
assert auth.t("acc.recovery_low", n=0) not in html, "„only 0 left“ is still there"
# B-9b: the line is a block of its own after the buttons, not an inline badge between them.
m = re.search(r"<div id=rc_left class='rcleft err'>", html)
assert m, "B-9b: remainder is not its own block"
assert html.index("data-act=recovery") < m.start(), "B-9b: the line still sits in the button row"
assert ".rcleft{display:block" in html
auth.generate_recovery_codes(gina, n=2)
assert auth.t("acc.recovery_low", n=2) in cg.get("/auth/account").text
auth.generate_recovery_codes(gina)
html = cg.get("/auth/account").text
assert auth.t("acc.recovery_left", n=auth.cfg.recovery_code_count) in html
assert "<div id=rc_left class='rcleft ok'>" in html
ok("B-9a/b: account page — „none“ vs „only n“ vs „n left“, as a block below the buttons")
# The JS updates the line after „generate“ (B-9b) — measured in the browser; here the texts it needs.
assert '"rc_left": ' in html and "__N__" in html and "getElementById('rc_left')" in html
ok("B-9b: the account JS carries the remainder texts and updates #rc_left")

# ---------- B-10: set the first password ----------
auth10, app10 = build(stepup_max_age_sec=900)
hank = auth10.create_user("hank")                       # no password: sign-in link, OIDC, passkey
assert not auth10.store.get_password_hash(hank)
ch = sign_in(auth10, app10, hank, "magic")
html = ch.get("/auth/account").text
assert "data-act=setpw" in html and "id=pw_cur" not in html, "B-10: page still asks for the current password"
assert auth10.t("acc.pw_none") in html
ok("B-10: account without a password → „set password“ without the field for the current one")

# CSRF: without the token → 403 (and nothing set).
assert ch.post("/auth/password/set", json={"new": "fresh-pass-2468"}).status_code == 403
assert not auth10.store.get_password_hash(hank)
# Rule: too short → 400.
r = ch.post("/auth/password/set", json={"new": "short"}, headers={"X-CSRF-Token": csrf(ch, auth10)})
assert r.status_code == 400 and not auth10.store.get_password_hash(hank), r.text
other, _ = auth10.start_session(hank, "magic")
r = ch.post("/auth/password/set", json={"new": "fresh-pass-2468"}, headers={"X-CSRF-Token": csrf(ch, auth10)})
assert r.status_code == 200 and r.json()["ok"] is True, r.text
assert r.json()["other_sessions"] == 1, r.json()     # offered, not ended (as after a new factor)
assert auth10.store.get_session(other) is not None
assert any(e["event"] == "password_set" for e in auth10.own_events(hank)), auth10.own_events(hank)
ok("B-10: CSRF, rule, then set — audit `password_set`, other sessions offered")

# The password now signs in, and from here on the old one is required again.
cl = TestClient(app10)
cl.get("/auth/login")
assert cl.post("/auth/login", data={"username": "hank", "password": "fresh-pass-2468", "_csrf": csrf(cl, auth10)},
               follow_redirects=False).status_code == 303
r = ch.post("/auth/password/set", json={"new": "other-pass-1357"}, headers={"X-CSRF-Token": csrf(ch, auth10)})
assert r.status_code == 409, r.status_code
html = ch.get("/auth/account").text
assert "id=pw_cur" in html and "data-act=setpw" not in html
r = ch.post("/auth/password", json={"current": "", "new": "other-pass-1357"}, headers={"X-CSRF-Token": csrf(ch, auth10)})
assert r.status_code == 400, r.status_code
ok("B-10: sign-in with the new password; with a password the old one is required again (409 / missing)")

# Freshness instead of the old password: no factor → age of the sign-in (`login_fresh`).
ivy = auth10.create_user("ivy")
ci = sign_in(auth10, app10, ivy, "magic")
auth10.store.db.execute("UPDATE session SET created_at = created_at - 3600, mfa_at = mfa_at - 3600 WHERE user_id = ?",
                        (ivy,))
auth10.store.db.commit()
r = ci.post("/auth/password/set", json={"new": "fresh-pass-2468"}, headers={"X-CSRF-Token": csrf(ci, auth10)})
assert r.status_code == 403 and "X-TinySesam-Reauth" not in r.headers, (r.status_code, dict(r.headers))
assert r.json()["detail"] == auth10.t("api.stepup_relogin")
assert not auth10.store.get_password_hash(ivy)
ok("B-10: old sign-in without any factor → 403 „sign in again“ (no reauth page that could not help)")

# Has a factor (TOTP), but no fresh confirmation → step-up, the page is sent to the reauth page.
jay = auth10.create_user("jay")
cj = sign_in(auth10, app10, jay, "magic")
auth10.totp_begin(jay)
auth10.store.confirm_totp(jay)
auth10.store.db.execute("UPDATE session SET mfa_at = mfa_at - 3600 WHERE user_id = ?", (jay,))
auth10.store.db.commit()
r = cj.post("/auth/password/set", json={"new": "fresh-pass-2468"}, headers={"X-CSRF-Token": csrf(cj, auth10)})
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth", "").endswith("/auth/reauth"), \
    (r.status_code, dict(r.headers))
assert not auth10.store.get_password_hash(jay)
ok("B-10: account with a factor → fresh step-up required (403 + X-TinySesam-Reauth)")

# An API key never sets a password.
kim = auth10.create_user("kim")
key = auth10.create_api_key(kim, name="ci")["key"]
ck = TestClient(app10)
r = ck.post("/auth/password/set", json={"new": "fresh-pass-2468"}, headers={"X-API-Key": key})
assert r.status_code == 403 and not auth10.store.get_password_hash(kim), r.status_code
# Refused for being a key, not merely for lacking freshness (a key never counts as a session).
assert r.json()["detail"] == auth10.t("api.password_needs_session"), r.json()
ok("B-10: API key → 403 „needs a session“, nothing set")

# With a directory the password lives there — no local one next to it.
lee = auth10.create_user("lee")
cle = sign_in(auth10, app10, lee, "magic")
auth10.cfg.ldap_enabled = True
try:
    r = cle.post("/auth/password/set", json={"new": "fresh-pass-2468"}, headers={"X-CSRF-Token": csrf(cle, auth10)})
    assert r.status_code == 409 and not auth10.store.get_password_hash(lee), r.status_code
finally:
    auth10.cfg.ldap_enabled = False
ok("B-10: ldap_enabled → 409, no local password next to the directory")

# Password sign-in off → 404, nothing set.
mia = auth10.create_user("mia")
cm = sign_in(auth10, app10, mia, "magic")
auth10.cfg.password_enabled = False
try:
    r = cm.post("/auth/password/set", json={"new": "fresh-pass-2468"}, headers={"X-CSRF-Token": csrf(cm, auth10)})
    assert r.status_code == 404 and not auth10.store.get_password_hash(mia), r.status_code
finally:
    auth10.cfg.password_enabled = True
ok("B-10: password sign-in off → 404, nothing set")

# The building block itself checks CSRF — an own route without the built-in middleware is protected too
# (as `change_password`: an empty form field does not fall back to anything).
from fastapi import Form, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

own_app = FastAPI()


@own_app.post("/own/password")
def own_password(request: Request, new: str = Form(""), csrf: str = Form("", alias="_csrf")):
    res = auth10.set_initial_password(request, new, csrf=csrf)
    return JSONResponse({"ok": res.ok, "reason": res.reason}, status_code=res.status)


own_app.include_router(app10.router)
nina = auth10.create_user("nina")
cn = sign_in(auth10, own_app, nina, "magic")
r = cn.post("/own/password", data={"new": "fresh-pass-2468", "_csrf": ""})
assert r.status_code == 403 and not auth10.store.get_password_hash(nina), r.status_code
r = cn.post("/own/password", data={"new": "fresh-pass-2468", "_csrf": csrf(cn, auth10)})
assert r.status_code == 200 and r.json() == {"ok": True, "reason": "ok"}, r.text
assert auth10.store.get_password_hash(nina)
ok("set_initial_password in an own route: CSRF checked by the building block (403), then set")

# The public building block (T-34 builds on it) gives the same result type as `change_password`.
from tinysesam import PasswordChangeResult  # noqa: E402
assert {"has_password", "directory", "method_disabled", "stepup", "relogin"} <= set(PasswordChangeResult.REASONS)
ok("set_initial_password: reasons documented on PasswordChangeResult")

print("OK test_account_setup")
