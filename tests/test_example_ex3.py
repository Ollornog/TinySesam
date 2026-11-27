"""T-102 acceptance, example Ex3 (`examples/ex3/app.py`): an IdP group arrives at sign-in, the administrator gives it a
permission, the group is withdrawn at the provider and the permission is gone after the re-check.

The provider is stubbed (discovery prefilled, the token exchange and the refresh exchange answer what the test says);
everything else runs through the real routes — the OIDC callback, the re-check a request triggers, the admin panel with
its CSRF token, and the application's own route.

 1. Kim signs in through the provider with the group `team-docs` (and `other`, which the filter leaves out): the role
    arrives on the account, and the panel's role catalog lists it as from the IdP (`source` idp, `idp_source` oidc).
    The application still refuses: the role grants nothing by itself.
 2. The administrator assigns `docs.read` to `team-docs` in the permission matrix — Kim reads the documents.
 3. The provider withdraws the group. Kim's running session is re-checked against the provider (refresh exchange):
    from then on the role is gone and the application refuses (403) — without a new sign-in.
 4. A re-check whose answer carries no group claim changes nothing (it would not have given the role back either).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from fastapi.testclient import TestClient  # noqa: E402

from tinysesam.oidc import DEFAULT_CLIENT, OIDCClient  # noqa: E402

spec = importlib.util.spec_from_file_location("example_ex3", os.path.join(ROOT, "examples", "ex3", "app.py"))
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)

IDP = "https://idp.example.com"
BASE = "http://testserver"
PW = "a long probe password 4711"


def ok(name):
    print(f"  ✓ {name}")


class _Claims(dict):
    def validate(self, *a, **k):
        pass


app, auth = example.build(os.path.join(tempfile.mkdtemp(), "ex3.db"), issuer=IDP, client_id="docs",
                          client_secret="probe-secret", base_url=BASE)
auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                   "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
provider = {"groups": ["team-docs", "other"], "refresh": []}
auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "kim-1", "preferred_username": "kim", "email": "kim@example.com", "email_verified": True,
             "groups": list(provider["groups"]), "nonce": nonce}), {"access_token": "at", "refresh_token": "rt-1"})
auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
auth.oidc_clients[DEFAULT_CLIENT].refresh = lambda rt, sub: provider["refresh"].pop(0)
ada = int(auth.create_user("ada", password=PW, is_admin=True))


def csrf(c):
    return c.cookies.get(auth.csrf_cookie_name) or ""


def admin_session():
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    c.get("/auth/login")
    r = c.post("/auth/login", data={"username": "ada", "password": PW, "_csrf": csrf(c)})
    assert r.status_code == 303, (r.status_code, r.text[:200])
    return c


def panel(c, path, body):
    r = c.post("/auth/admin/api" + path, json=body, headers={"X-CSRF-Token": csrf(c)})
    assert r.status_code == 200, (path, r.status_code, r.text[:300])
    return r.json()


def recheck(c, answer):
    """Kim's session is due for its re-check against the provider; one request claims it, the exchange runs."""
    auth.store._exec("UPDATE oidc_session SET checked_at=?", (int(time.time()) - 600,))
    provider["refresh"].append(answer)
    c.get("/auth/me")
    auth._oidc_outcome.wait()


# 1 ──────────────────────────────────────────────────────────────────────────────────────────────────
kim_browser = TestClient(app, base_url=BASE, follow_redirects=False)
start = kim_browser.get("/auth/oidc/start")
state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
assert kim_browser.get(f"/auth/oidc/callback?code=x&state={state}").status_code == 303
kim = auth.store.get_user_by_name("kim")
assert auth.user_roles(kim) == ["team-docs"], auth.user_roles(kim)
admin = admin_session()
roles = {r["name"]: r for r in admin.get("/auth/admin/api/roles").json()["roles"]}
assert roles["team-docs"]["source"] == "idp" and roles["team-docs"]["idp_source"] == "oidc", roles
assert "other" not in roles, "the filter team-* let another group in"
assert kim_browser.get("/", headers={"Accept": "application/json"}).status_code == 403
ok("1. the group arrives at sign-in and the catalog lists it as from the IdP; it grants nothing by itself")

# 2 ──────────────────────────────────────────────────────────────────────────────────────────────────
matrix = admin.get("/auth/admin/api/permissions").json()
assert "team-docs" in matrix["roles"] and matrix["idp_roles"] == ["team-docs"], matrix
panel(admin, "/permissions/assign", {"app": "docs", "permission": "docs.read", "role": "team-docs", "granted": True})
page = kim_browser.get("/")
assert page.status_code == 200 and "Quarterly report" in page.text, (page.status_code, page.text[:200])
ok("2. the administrator assigns docs.read to the imported role in the matrix — the application lets kim read")

# 4 (first, while the group is still there): a re-check without the claim changes nothing.
recheck(kim_browser, ("ok", {"sub": "kim-1"}, {"refresh_token": "rt-2"}))
assert kim_browser.get("/").status_code == 200 and auth.user_roles(auth.get_user(kim["id"])) == ["team-docs"]
ok("4. a re-check whose answer carries no group claim withdraws nothing")

# 3 ──────────────────────────────────────────────────────────────────────────────────────────────────
provider["groups"] = ["other"]
recheck(kim_browser, ("ok", {"sub": "kim-1", "groups": ["other"]}, {"refresh_token": "rt-3"}))
assert auth.user_roles(auth.get_user(kim["id"])) == [], auth.user_roles(auth.get_user(kim["id"]))
assert kim_browser.get("/", headers={"Accept": "application/json"}).status_code == 403
assert not auth.has_permission(auth.get_user(kim["id"]), "docs.read", app="docs")
assert any("withdrawn=team-docs" in (r["detail"] or "") for r in auth.store._all(
    "SELECT detail FROM audit WHERE event='idp_roles_synced'"))
ok("3. the provider withdraws the group: after the re-check the role and the permission are gone (403), audited")
print("OK test_example_ex3")
