"""T-99: a missing group claim is not an empty list.

An OIDC sign-in whose ID token and userinfo document carry no group claim (the scope `groups` was not asked, the
provider leaves it out) says nothing about the groups. Until now the callback read it as "no groups" and withdrew
every mapped role — and the admin flag the provider had granted — at each such sign-in. Now only a claim that is
there synchronises, an empty one included; a missing one leaves the roles and logs a warning. The periodic re-check
(`_oidc_swap`) already followed this rule.
"""
from __future__ import annotations

import io
import logging
import os
import sys
import tempfile
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig, security  # noqa: E402
from tinysesam.oidc import OIDCClient  # noqa: E402

IDP = "https://idp.example.invalid"


def ok(name):
    print(f"  ✓ {name}")


class _Claims(dict):
    def validate(self, *a, **k):
        pass


def oidc_app(**cfg):
    """OIDC without network: discovery prefilled, the token exchange returns `state["claims"]`."""
    values = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False, oidc_enabled=True,
                  oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="secret", base_url="http://testserver",
                  csrf_enabled=False, oidc_group_role_map={"staff": "editor", "admins": "__admin__"})
    values.update(cfg)
    auth = TinySesam(TinySesamConfig(**values))
    app = FastAPI()
    app.include_router(auth.router())
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                       "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
    state = {"claims": {}, "userinfo": {}}
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**state["claims"], "nonce": nonce}), {"access_token": "at"})
    auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo(dict(state["userinfo"]), expected_sub)
    return auth, app, state


def sign_in(app):
    c = TestClient(app)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    got = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={got}", follow_redirects=False)


BASE = {"sub": "kim-1", "preferred_username": "kim", "email": "kim@example.com", "email_verified": True}
auth, app, state = oidc_app()

# (a) the first sign-in with groups: role and the provider's admin flag
state["claims"] = {**BASE, "groups": ["staff", "admins"]}
assert sign_in(app).status_code == 303
kim = auth.store.get_user_by_name("kim")
assert auth.user_roles(kim) == ["editor"] and kim["is_admin"] == 2, (auth.user_roles(kim), kim["is_admin"])
ok("a sign-in with the claim grants the mapped role and the provider's admin flag")

# (b) a sign-in WITHOUT the claim (neither ID token nor userinfo): nothing withdrawn, a warning in the security log
buffer = io.StringIO()
handler = logging.StreamHandler(buffer)
security.seclog.addHandler(handler)
try:
    state["claims"] = dict(BASE)
    state["userinfo"] = {"sub": "kim-1", "email": "kim@example.com"}
    assert sign_in(app).status_code == 303
finally:
    security.seclog.removeHandler(handler)
kim = auth.store.get_user(kim["id"])
assert auth.user_roles(kim) == ["editor"] and kim["is_admin"] == 2, (auth.user_roles(kim), kim["is_admin"])
assert "without the group claim groups" in buffer.getvalue(), buffer.getvalue()
ok("a sign-in without the claim keeps role and admin flag, and says so in the security log")

# (c) the claim in the userinfo document only: it synchronises like one in the ID token
state["userinfo"] = {"sub": "kim-1", "groups": ["staff"]}
assert sign_in(app).status_code == 303
kim = auth.store.get_user(kim["id"])
assert auth.user_roles(kim) == ["editor"] and not kim["is_admin"], "the admin group left: the provider's flag goes"
ok("the claim in the userinfo document synchronises (admin group gone → the provider's flag goes)")

# (d) an EMPTY claim is a statement: every mapped role goes
state["userinfo"] = {}
state["claims"] = {**BASE, "groups": []}
assert sign_in(app).status_code == 303
assert auth.user_roles(auth.store.get_user(kim["id"])) == []
ok("an empty claim withdraws the mapped roles — empty is not missing")

# (e) a role granted by hand stays either way; the group gate still refuses a sign-in without the claim
auth.set_roles(kim["id"], ["reviewer"])
state["claims"] = dict(BASE)
assert sign_in(app).status_code == 303 and auth.user_roles(auth.store.get_user(kim["id"])) == ["reviewer"]
auth2, app2, state2 = oidc_app(oidc_allowed_groups=["staff"])
state2["claims"] = dict(BASE)
assert sign_in(app2).status_code == 403, "allowed_groups without the claim: refused (fail closed), as before"
ok("a hand-granted role stays; allowed_groups still refuses a sign-in without the claim")
print("OK test_idp_group_claim")
