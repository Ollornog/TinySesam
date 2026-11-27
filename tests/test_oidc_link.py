"""T-99, ADR-18: linking a local account with an OIDC identity, and pre-created OIDC accounts — never by an address alone.

Linking by the person: `POST /auth/oidc/link` from the account page (CSRF token, a fresh confirmation here), an active
sign-in at the provider (`prompt=login`, `auth_time` after the request), and the callback binds only in the session that
started it. Pre-created accounts: the operator pre-registers the `sub` (`tinysesam oidc-link`), or — opt-in
`oidc_bind_precreated` — the first sign-in binds by the provider's explicitly verified address, only to an account
nobody ever used. The attack tests: an identity whose provider vouches for the victim's address takes no account in
use; a link started by a foreign page, in another browser, from a stale session, with an old provider sign-in, or for an
identity of another account binds nothing.
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import __main__ as cli  # noqa: E402
from tinysesam.oidc import OIDCClient  # noqa: E402

IDP = "https://idp.example.invalid"
PW = "a long local password 4711"
STALE = 100000


def ok(name):
    print(f"  ✓ {name}")


class _Claims(dict):
    def validate(self, *a, **k):
        pass


def oidc_app(**cfg):
    """OIDC without network: discovery prefilled, the token exchange returns `state["claims"]` (auth_time = now unless
    the claims say otherwise)."""
    values = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, oidc_enabled=True,
                  oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret", base_url="http://testserver",
                  csrf_enabled=True, stepup_max_age_sec=900, lang="en")
    values.update(cfg)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                       "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
    state = {"claims": {}}
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({"auth_time": int(time.time()), **state["claims"], "nonce": nonce}), {"access_token": "at"})
    auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
    return auth, app, state


def csrf(c):
    return c.cookies.get("tinysesam_csrf") or ""


def local_client(app, name):
    c = TestClient(app)
    c.get("/auth/login")
    r = c.post("/auth/login", data={"username": name, "password": PW, "_csrf": csrf(c)}, follow_redirects=False)
    assert r.status_code == 303, (r.status_code, r.text[:200])
    return c


def callback(c, location):
    got = parse_qs(urlparse(location).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={got}", follow_redirects=False)


def oidc_sign_in(app):
    c = TestClient(app)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    return c, callback(c, start.headers["location"])


def make_stale(auth, c):
    tok = c.cookies.get(auth.session_cookie_name)
    then = int(time.time()) - STALE
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (then, then, auth.store.session_hash(tok)))


def audited(auth, event):
    return [a for a in auth.store.recent_audit(80) if a["event"] == event]


# ======================= linking by the person =======================
auth, app, state = oidc_app()
lena = int(auth.create_user("lena", password=PW, email="lena@example.com"))
c = local_client(app, "lena")
page = c.get("/auth/account").text
assert "action='/auth/oidc/link'" in page and "name=_csrf" in page, "the account page offers no link form"

# A foreign page (no CSRF token) cannot start it; a GET does not exist.
assert c.post("/auth/oidc/link", follow_redirects=False).status_code == 403
assert c.get("/auth/oidc/link", follow_redirects=False).status_code in (404, 405)
ok("the account page offers the link as a form with the CSRF token; without the token 403, no GET route")

# A stale session must confirm first.
make_stale(auth, c)
r = c.post("/auth/oidc/link", data={"_csrf": csrf(c)}, follow_redirects=False)
assert r.status_code == 403 and "x-tinysesam-reauth" in {k.lower() for k in r.headers}, (r.status_code, r.headers)
c = local_client(app, "lena")
ok("a stale session is sent to confirm first (403 with X-TinySesam-Reauth)")

# The link asks the provider for an active sign-in; an old auth_time binds nothing.
r = c.post("/auth/oidc/link", data={"_csrf": csrf(c)}, follow_redirects=False)
assert r.status_code == 303, r.status_code
q = parse_qs(urlparse(r.headers["location"]).query)
assert q.get("prompt") == ["login"] and q.get("max_age") == ["0"], q
state["claims"] = {"sub": "lena-idp", "email": "lena@example.com", "email_verified": True,
                   "auth_time": int(time.time()) - 3600}
assert callback(c, r.headers["location"]).status_code == 401
assert auth.store.get_oidc_user(IDP, "lena-idp") is None and audited(auth, "oidc_link_refused")
ok("the provider is asked for an active sign-in (prompt=login, max_age=0); an old auth_time binds nothing")

# Another browser (the attacker who lures the victim to the callback) — the flow cookie is not there.
r = c.post("/auth/oidc/link", data={"_csrf": csrf(c)}, follow_redirects=False)
state["claims"] = {"sub": "attacker-idp"}
other = TestClient(app)
assert callback(other, r.headers["location"]).status_code == 400
assert auth.store.get_oidc_user(IDP, "attacker-idp") is None
ok("the callback in another browser binds nothing (400, no flow cookie)")

# The same browser, but the session changed in between (signed out, another account signed in): refused.
r = c.post("/auth/oidc/link", data={"_csrf": csrf(c)}, follow_redirects=False)
auth.create_user("mallory", password=PW)
c.post("/auth/logout", data={"_csrf": csrf(c)}, follow_redirects=False)
c.get("/auth/login")
c.post("/auth/login", data={"username": "mallory", "password": PW, "_csrf": csrf(c)}, follow_redirects=False)
state["claims"] = {"sub": "lena-idp"}
assert callback(c, r.headers["location"]).status_code == 403
assert auth.store.get_oidc_user(IDP, "lena-idp") is None
ok("a callback in another session than the one that started the link binds nothing (403)")

# An identity that belongs to another account is not moved.
state["claims"] = {"sub": "kim-idp", "preferred_username": "kim"}
_, r0 = oidc_sign_in(app)
assert r0.status_code == 303 and auth.store.get_oidc_user(IDP, "kim-idp")
c = local_client(app, "lena")
r = c.post("/auth/oidc/link", data={"_csrf": csrf(c)}, follow_redirects=False)
assert callback(c, r.headers["location"]).status_code == 409
assert auth.store.get_oidc_user(IDP, "kim-idp") != lena
ok("an identity of another account is not moved (409 identity_taken)")

# The real link: fresh here, active sign-in there, the same session.
r = c.post("/auth/oidc/link", data={"_csrf": csrf(c)}, follow_redirects=False)
state["claims"] = {"sub": "lena-idp", "email": "lena@example.com", "email_verified": True}
done = callback(c, r.headers["location"])
assert done.status_code == 303 and done.headers["location"].endswith("/auth/account"), done.status_code
assert auth.store.get_oidc_user(IDP, "lena-idp") == lena and audited(auth, "oidc_linked")
_, again = oidc_sign_in(app)
assert again.status_code == 303 and auth.store.get_user_by_name("lena") is not None
assert auth.store.account_sources([lena])[lena] == ["local", "oidc"]
r = c.post("/auth/oidc/link", data={"_csrf": csrf(c)}, follow_redirects=False)
assert r.status_code == 409, "a second identity at the same provider"
ok("the link binds in the starting session after an active sign-in; the account is mixed (local + oidc)")

# ======================= no binding by address, unless opted in and unused =======================
auth2, app2, state2 = oidc_app(csrf_enabled=False)
victim = int(auth2.create_user("vera", password=PW, email="vera@example.com"))
state2["claims"] = {"sub": "evil-1", "preferred_username": "vera2", "email": "vera@example.com", "email_verified": True}
_, r = oidc_sign_in(app2)
assert auth2.store.get_oidc_user(IDP, "evil-1") != victim, "an address bound an identity to an existing account"
ok("attack: an identity whose provider vouches for a local account's address takes no account (switch off)")

auth3, app3, state3 = oidc_app(csrf_enabled=False, oidc_bind_precreated=True)
used = int(auth3.create_user("used", password=PW, email="used@example.com"))          # has a password
pre = int(auth3.create_user("pre", email="pre@example.com"))                          # created, never used
boss = int(auth3.create_user("boss", email="boss@example.com", is_admin=True))        # an administrator
for sub, mail, verified, who in (("e1", "used@example.com", True, used), ("e2", "boss@example.com", True, boss),
                                 ("e3", "pre@example.com", None, pre)):
    claims = {"sub": sub, "email": mail}
    if verified is not None:
        claims["email_verified"] = verified
    state3["claims"] = claims
    oidc_sign_in(app3)
    assert auth3.store.get_oidc_user(IDP, sub) != who, (sub, mail)
ok("attack (switch on): no binding to an account with a password, to an administrator, or without an explicit "
   "email_verified")
state3["claims"] = {"sub": "pre-1", "email": "pre@example.com", "email_verified": True}
_, r = oidc_sign_in(app3)
assert r.status_code == 303 and auth3.store.get_oidc_user(IDP, "pre-1") == pre and audited(auth3, "oidc_bound_precreated")
ok("opt-in: a pre-created, never used account is bound by the explicitly verified address")
auth3.store.mark_first_login(pre, int(time.time()))
state3["claims"] = {"sub": "pre-2", "email": "pre@example.com", "email_verified": True}
oidc_sign_in(app3)
assert auth3.store.get_oidc_user(IDP, "pre-2") != pre, "a used account was bound to a second identity by address"
linky = int(auth3.create_user("linky", email="linky@example.com"))   # signed in once by a link: no factor, no identity
auth3.store.mark_first_login(linky, int(time.time()))
state3["claims"] = {"sub": "linky-1", "email": "linky@example.com", "email_verified": True}
oidc_sign_in(app3)
assert auth3.store.get_oidc_user(IDP, "linky-1") != linky, "an account in use (signed in by a link) was taken by address"
ok("once used (or bound), the address binds no further identity — also an account used only through sign-in links")

# ======================= the operator pre-registers the sub =======================
db = auth2.cfg.db_path
anna = int(auth2.create_user("anna", email="anna@example.com"))
out, err = io.StringIO(), io.StringIO()
with redirect_stdout(out), redirect_stderr(err):
    rc = cli._oidc_link(["anna", "--db", db, "--issuer", IDP, "--sub", "anna-idp"])
assert rc == 0 and "linked" in out.getvalue(), (rc, out.getvalue(), err.getvalue())
state2["claims"] = {"sub": "anna-idp", "preferred_username": "someone-else"}
_, r = oidc_sign_in(app2)
assert r.status_code == 303 and auth2.store.get_oidc_user(IDP, "anna-idp") == anna
with redirect_stdout(io.StringIO()), redirect_stderr(err):
    assert cli._oidc_link(["vera", "--db", db, "--issuer", IDP, "--sub", "anna-idp"]) == 1, "moved a bound identity"
ok("tinysesam oidc-link pre-registers the sub; the first sign-in lands in that account; a bound identity is not moved")

print("OK test_oidc_link")
