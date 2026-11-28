"""Example Ex3 (`deploy/ex3`, `clients/js/examples/ex3`): T-102's IdP role sync and T-104's surface "hybrid", behind the
TinySesam server.

The server is built from `deploy/ex3/tinysesam.toml` exactly as the gateway image builds it (`TINYSESAM_CONFIG`); the
application is the Node program of `clients/js/examples/ex3` (no Python in it, M-2), which reads the identity and
`Remote-Permissions` from the proxy. Here the proxy's call is made directly: `/auth/forward` for `app.example.com`.
The provider is stubbed (discovery prefilled, the token exchange and the refresh exchange answer what the test says);
everything else runs through the real routes — the OIDC callback, the re-check a request triggers, the admin panel
with its CSRF token. The browser half (the Node program behind a proxy, the area) is `tests/test_hybrid_browser.py`.

 1. T-102: Kim signs in through the provider with the group `team-docs` (and `other`, which the filter leaves out): the
    role arrives, and the panel's role catalog lists it as from the IdP. The role grants nothing by itself.
 2. The administrator assigns `docs.read` to `team-docs` in the permission matrix — forward auth sends it.
 3. The provider withdraws the group. Kim's running session is re-checked against the provider: from then on the role
    is gone and forward auth sends no permission — without a new sign-in.
 4. A re-check whose answer carries no group claim changes nothing.
 5. Mixed: a local account with the local role `docs-local` reads too, once that role holds the permission.
 6. T-104: the application's area — `/auth/area?app=docs` in the frame of app.example.com with the icon of
    `apps.docs.icon`, the sign-in page "Sign in to Documents" with the icon; the Node program links "Account" there and
    draws its own navigation; the compose file fits together.
"""
from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from tinysesam.oidc import DEFAULT_CLIENT, OIDCClient  # noqa: E402

EX3 = ROOT / "deploy" / "ex3"
IDP = "https://idp.example.com"
BASE = "https://auth.example.com"
PW = "a long probe password 4711"
APP_HOST = {"X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/", "X-Forwarded-Proto": "https"}


def ok(name):
    print(f"  ✓ {name}")


class _Claims(dict):
    def validate(self, *a, **k):
        pass


saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith(("TINYSESAM_", "EX3_"))}
os.environ.update(TINYSESAM_CONFIG=str(EX3 / "tinysesam.toml"), TINYSESAM_DB=os.path.join(tempfile.mkdtemp(), "ex3.db"),
                  EX3_OIDC_CLIENT_SECRET="probe-secret")
try:
    from tinysesam import gateway  # noqa: E402
    app = gateway.build_app()
finally:
    for k in ("TINYSESAM_CONFIG", "TINYSESAM_DB", "EX3_OIDC_CLIENT_SECRET"):
        os.environ.pop(k, None)
    os.environ.update(saved)
auth = app.state.auth
cfg = auth.cfg
assert cfg.oidc_enabled and cfg.password_enabled and cfg.oidc_group_import and cfg.forward_auth_enabled, cfg
assert cfg.apps["docs"]["hosts"] == ["app.example.com"] and cfg.apps["docs"]["icon"].startswith("data:image/svg+xml,")
ok("deploy/ex3/tinysesam.toml builds the server: local and OIDC accounts, group import team-*, forward auth, the "
   "docs application with host, icon and manifest")

auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                   "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
provider = {"groups": ["team-docs", "other"], "refresh": []}
auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "kim-1", "preferred_username": "kim", "email": "kim@example.com", "email_verified": True,
             "groups": list(provider["groups"]), "nonce": nonce}), {"access_token": "at", "refresh_token": "rt-1"})
auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
auth.oidc_clients[DEFAULT_CLIENT].refresh = lambda rt, sub: provider["refresh"].pop(0)
auth.create_user("ada", password=PW, is_admin=True)


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


def permissions(c):
    """What the proxy's forward auth hands the Node program for this browser: `Remote-Permissions` (absent = none)."""
    r = c.get("/auth/forward", headers=APP_HOST)
    assert r.status_code == 200, (r.status_code, dict(r.headers))
    return r.headers.get("Remote-Permissions", "")


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
assert permissions(kim_browser) == "", "the imported role granted a permission by itself"
ok("1. the group arrives at sign-in and the catalog lists it as from the IdP; it grants nothing by itself")

# 2 ──────────────────────────────────────────────────────────────────────────────────────────────────
matrix = admin.get("/auth/admin/api/permissions").json()
assert "team-docs" in matrix["roles"] and matrix["idp_roles"] == ["team-docs"], matrix
panel(admin, "/permissions/assign", {"app": "docs", "permission": "docs.read", "role": "team-docs", "granted": True})
assert permissions(kim_browser) == "docs.read", permissions(kim_browser)
ok("2. the administrator assigns docs.read to the imported role in the matrix — forward auth sends it to the app")

# 4 (first, while the group is still there): a re-check without the claim changes nothing.
recheck(kim_browser, ("ok", {"sub": "kim-1"}, {"refresh_token": "rt-2"}))
assert permissions(kim_browser) == "docs.read" and auth.user_roles(auth.get_user(kim["id"])) == ["team-docs"]
ok("4. a re-check whose answer carries no group claim withdraws nothing")

# 3 ──────────────────────────────────────────────────────────────────────────────────────────────────
provider["groups"] = ["other"]
recheck(kim_browser, ("ok", {"sub": "kim-1", "groups": ["other"]}, {"refresh_token": "rt-3"}))
assert auth.user_roles(auth.get_user(kim["id"])) == [], auth.user_roles(auth.get_user(kim["id"]))
assert permissions(kim_browser) == "", "the permission outlived the withdrawn group"
assert not auth.has_permission(auth.get_user(kim["id"]), "docs.read", app="docs")
assert any("withdrawn=team-docs" in (r["detail"] or "") for r in auth.store._all(
    "SELECT detail FROM audit WHERE event='idp_roles_synced'"))
ok("3. the provider withdraws the group: after the re-check the role and the permission are gone, audited")

# 5 ──────────────────────────────────────────────────────────────────────────────────────────────────
lou = int(auth.create_user("lou", password=PW, roles=["docs-local"]))
lou_browser = TestClient(app, base_url=BASE, follow_redirects=False)
lou_browser.cookies.set(auth.session_cookie_name, auth.start_session(lou, "password")[0])
assert permissions(lou_browser) == ""
panel(admin, "/permissions/assign", {"app": "docs", "permission": "docs.read", "role": "docs-local", "granted": True})
assert permissions(lou_browser) == "docs.read", permissions(lou_browser)
assert auth.store.account_sources([lou]).get(lou, ["local"]) == ["local"]
ok("5. mixed: the local account with docs-local reads beside the provider's people, through the same permission")

# 6 ──────────────────────────────────────────────────────────────────────────────────────────────────
icon = cfg.apps["docs"]["icon"]
area = lou_browser.get("/auth/area?app=docs")
assert area.status_code == 200 and "tsbar tsframe" in area.text, area.status_code
assert f"<img class=app-icon src='{icon}'" in area.text and "<span>Documents</span>" in area.text
assert "<a class=btn2 href='https://app.example.com/'>Back to Documents</a>" in area.text
anon = TestClient(app, base_url=BASE, follow_redirects=False)
login = anon.get("/auth/login?next=https://app.example.com/").text
assert f"<img class=app-icon src='{icon}'" in login and "Sign in to Documents" in login
main_ts = (ROOT / "clients/js/examples/ex3/main.ts").read_text(encoding="utf-8")
assert "${AUTH_URL}/auth/area?app=${APP}" in main_ts and "const APP = 'docs';" in main_ts, "Ex3 no longer links the area"
assert "hasPermission(`${APP}.read`)" in main_ts, "Ex3 no longer checks docs.read"
compose = (EX3 / "docker-compose.yml").read_text(encoding="utf-8")
assert "TINYSESAM_CONFIG: /etc/tinysesam.toml" in compose and "./tinysesam.toml:/etc/tinysesam.toml:ro" in compose
assert "dockerfile: examples/ex3/Dockerfile" in compose and "TS_APP_UPSTREAM: app:9003" in compose
subnet = re.search(r"subnet: (\S+)", compose).group(1)
assert f'TS_TRUSTED_PROXY: "{subnet}"' in compose and subnet in cfg.trusted_proxies, (subnet, cfg.trusted_proxies)
dockerfile = (ROOT / "clients/js/examples/ex3/Dockerfile").read_text(encoding="utf-8")
assert all("@sha256:" in line for line in dockerfile.splitlines() if line.startswith("FROM ")), "an unpinned base"
assert not (ROOT / "examples" / "ex3").exists(), "Ex3 has Python again (M-2: each example uses only its client)"
ok("6. hybrid: the area in the frame of app.example.com with the icon and the way back, \"Sign in to Documents\" with "
   "the icon; the Node program links Account to the area and checks docs.read; compose, image and trust fit together")
print("OK test_example_ex3")
