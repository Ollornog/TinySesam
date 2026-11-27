"""T-101 (ADR-17 stage S5, server side): an application's permissions travel with the requests to its hosts.

  (a) `apps[id].hosts` — the configuration check: shape, a host in two applications, `permission_scopes` and what they
      need (an `account`, `apikey_enabled`); a host of `forward_apps` without its own name takes the application's
  (b) forward auth: `Remote-Permissions` for a host of the application — the union over the account's roles, sorted,
      joined with `,`; empty for a host of no application and for another application's permissions; the gate token
      carries the same as `ts_perms`; a change counts at the next request (the proxy path after the token's TTL); a set
      above `PERMISSIONS_VALUE_MAX` is refused with 403 and a security-log line, never cut
  (c) `account.json` on an application's host names its permissions; elsewhere `null`
  (d) the permission API: `PUT /auth/api/apps/{id}/permissions` registers (grants nothing), only with an automation key
      of THIS application's service account and the scope; `GET /auth/api/users/{id}/permissions?app=` reads; a locked,
      unknown or service account is 404; the read is throttled; the routes exist only with `permission_scopes`
"""
from __future__ import annotations

import base64
import io
import logging
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig, _permissions_api, gate, security  # noqa: E402

BASE = "https://auth.example.com"
DOCS = "docs.example.com"
WIKI = "wiki.example.com"
OTHER = "other.example.com"
PW = "a long test password 4711"
MANIFEST = [{"name": "docs.read", "label": {"en": "Read documents"}},
            {"name": "docs.delete", "label": {"en": "Delete documents"}, "danger": True}]


def ok(name):
    print(f"  ✓ {name}")


def build(**over):
    cfg = dict(lang="en", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False,
               oidc_enabled=False, cookie_secure=False, base_url=BASE, forward_auth_enabled=True,
               trusted_redirect_hosts=[DOCS, WIKI, OTHER], apikey_enabled=True, gate_token_enabled=True,
               available_roles=["docs-reader", "docs-editor", "wiki-editor"],
               apps={"docs": {"name": {"en": "Documents", "de": "Dokumente"}, "account": "svc-docs", "hosts": [DOCS],
                              "permissions": MANIFEST,
                              "permission_scopes": ["permissions:register", "permissions:read"]},
                     "wiki": {"name": "Wiki", "account": "svc-wiki", "hosts": [WIKI],
                              "permissions": [{"name": "wiki.edit"}], "permission_scopes": ["permissions:read"]}})
    cfg.update(over)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def refused(**over):
    try:
        build(**over)
    except ConfigError as e:
        return str(e)
    raise AssertionError(f"accepted: {over}")


def session_client(auth, app, uid):
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok, _ = auth.start_session(uid, "password")
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def forward(app, client, host=DOCS):
    return client.get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": host,
                                                "X-Forwarded-Uri": "/", "X-Forwarded-Method": "GET"})


def claims_of(auth, response, host=DOCS):
    token = response.headers["X-TinySesam-Gate-Cookie"].split(";", 1)[0].split("=", 1)[1]
    return gate.check(base64.b64decode(auth.gate_public_key()), token, aud=host, iss=BASE, now=int(time.time()))


# ── (a) ─────────────────────────────────────────────────────────────────────────────────────────────
APPS = build()[0].cfg.apps
for bad in ([], ["Docs.example.com"], ["docs.example.com:8443"], ["https://docs.example.com"], ["docs.example.com."],
            "docs.example.com", [DOCS] * 33, [7]):
    assert "hosts" in refused(apps={**APPS, "docs": {**APPS["docs"], "hosts": bad}}), bad
msg = refused(apps={**APPS, "wiki": {**APPS["wiki"], "hosts": [WIKI, DOCS]}})
assert "both name the host" in msg and DOCS in msg, msg
assert "permission_scopes" in refused(apps={**APPS, "docs": {**APPS["docs"], "permission_scopes": ["users:read"]}})
assert "permission_scopes" in refused(apps={**APPS, "docs": {**APPS["docs"], "permission_scopes": []}})
no_account = {k: v for k, v in APPS["docs"].items() if k != "account"}
assert "account" in refused(apps={"docs": no_account})
assert "apikey_enabled" in refused(apikey_enabled=False)
plain, _ = build(apps={"docs": {"name": "Documents", "hosts": [DOCS], "permissions": MANIFEST}})
assert plain._forward_app(DOCS)["name"] == "Documents" and plain._forward_app(OTHER)["name"] == ""
named, _ = build(forward_apps={DOCS: {"name": "Docs (own)"}})
assert named._forward_app(DOCS)["name"] == "Docs (own)" and named._forward_app(f"https://{DOCS}/x")["name"] == "Docs (own)"
assert build(lang="de")[0]._forward_app(DOCS)["name"] == "Dokumente"
ok("(a) apps[id].hosts and permission_scopes are checked at construction; a host takes the application's name")

# ── (b) ─────────────────────────────────────────────────────────────────────────────────────────────
auth, app = build()
assert TinySesam.FORWARD_HEADERS_DEFAULT["perms"] == "Remote-Permissions"
ana = int(auth.create_user("ana", password=PW, roles=["docs-reader", "docs-editor", "wiki-editor"]))
auth.grant_permission("docs-reader", "docs.read", app="docs")
auth.grant_permission("docs-editor", "docs.delete", app="docs")
auth.grant_permission("docs-editor", "docs.read", app="docs")
auth.grant_permission("wiki-editor", "wiki.edit", app="wiki")
c = session_client(auth, app, ana)
r = forward(app, c)
assert r.status_code == 200 and r.headers["Remote-Permissions"] == "docs.delete,docs.read", dict(r.headers)
assert claims_of(auth, r)["ts_perms"] == "docs.delete,docs.read"
r = forward(app, c, host=WIKI)
assert r.headers["Remote-Permissions"] == "wiki.edit" and claims_of(auth, r, WIKI)["ts_perms"] == "wiki.edit"
r = forward(app, c, host=OTHER)
assert r.status_code == 200 and r.headers.get("Remote-Permissions", "") == "", dict(r.headers)
assert claims_of(auth, r, OTHER)["ts_perms"] == ""
auth.revoke_permission("docs-editor", "docs.delete", app="docs")
assert forward(app, c).headers["Remote-Permissions"] == "docs.read", "a change did not count at the next request"
bot = auth.create_service("svc-docs")
bot_key = auth.create_api_key(bot, name="app")["key"]
r = TestClient(app, base_url="http://testserver").get("/auth/forward", headers={
    "X-Forwarded-Proto": "https", "X-Forwarded-Host": DOCS, "X-Forwarded-Uri": "/", "X-Api-Key": bot_key})
assert r.status_code == 200 and r.headers["Remote-Kind"] == "service" and r.headers.get("Remote-Permissions", "") == "", \
    "a service account without roles holds no permission"
ok("(b) Remote-Permissions and ts_perms carry the permissions of the host's application only, sorted; another host "
   "gets none; a change counts at the next request")

auth.PERMISSIONS_VALUE_MAX = len("docs.read") - 1
buf = io.StringIO()
handler = logging.StreamHandler(buf)
security.seclog.addHandler(handler)
try:
    r = forward(app, c)
finally:
    security.seclog.removeHandler(handler)
assert r.status_code == 403 and "Remote-Permissions" not in r.headers, (r.status_code, dict(r.headers))
assert "x-tinysesam-gate-cookie" not in {k.lower() for k in r.headers}
assert "exceed" in buf.getvalue() and "app=docs" in buf.getvalue(), buf.getvalue()
assert forward(app, c, host=OTHER).status_code == 200, "a host of no application is not affected by the limit"
own, own_app = build(db_path=auth.cfg.db_path, forward_headers={"user": "Remote-User", "groups": "Remote-Groups"})
own.PERMISSIONS_VALUE_MAX = 1
r = forward(own_app, session_client(own, own_app, ana))
assert r.status_code == 200 and "Remote-Permissions" not in r.headers, "a mapping without `perms` was refused"
auth.PERMISSIONS_VALUE_MAX = TinySesam.PERMISSIONS_VALUE_MAX
assert forward(app, c).status_code == 200
ok("(b) a permission set above PERMISSIONS_VALUE_MAX is refused with 403 and a security-log line, never cut")

# ── (c) ─────────────────────────────────────────────────────────────────────────────────────────────
view = c.get("/.tinysesam/account.json", headers={"X-Forwarded-Host": DOCS}).json()
assert view["signed_in"] and view["permissions"] == {"app": "docs", "names": ["docs.read"]}, view.get("permissions")
assert c.get("/.tinysesam/account.json", headers={"X-Forwarded-Host": WIKI}).json()["permissions"] == {
    "app": "wiki", "names": ["wiki.edit"]}
assert c.get("/auth/account.json").json()["permissions"] is None
ok("(c) account.json on an application's host names its permissions; /auth/account.json says null")

# ── (d) ─────────────────────────────────────────────────────────────────────────────────────────────
api = TestClient(app, base_url="http://testserver")


def put(app_id, body, key=bot_key):
    return api.put(f"/auth/api/apps/{app_id}/permissions", json=body, headers={"X-Api-Key": key} if key else {})


def read(uid, app_id, key=bot_key):
    return api.get(f"/auth/api/users/{uid}/permissions", params={"app": app_id},
                   headers={"X-Api-Key": key} if key else {})


new = MANIFEST + [{"name": "docs.share", "label": {"en": "Share", "de": "Teilen"}}]
r = put("docs", {"permissions": new})
assert r.status_code == 200 and r.json()["added"] == ["docs.share"] and r.json()["app"] == "docs", (r.status_code, r.text)
assert r.headers["cache-control"] == "no-store"
assert {p["name"]: p["source"] for p in auth.app_permissions("docs")}["docs.share"] == "app"
assert not auth.has_permission(auth.get_user(ana), "docs.share", app="docs"), "registering granted something"
assert put("docs", new).status_code == 200, "a bare list is the manifest too"
assert put("docs", {"permissions": [{"name": "Not Valid"}]}).json()["error"] == "invalid"
assert put("docs", {"permissions": new}, key=None).status_code == 401
assert put("docs", {"permissions": new}, key="tsk_nonsense").status_code == 401
assert put("wiki", {"permissions": [{"name": "wiki.edit"}]}).json()["error"] == "not_this_app"
wiki_bot = auth.create_service("svc-wiki")
wiki_key = auth.create_api_key(wiki_bot, name="app")["key"]
r = put("wiki", {"permissions": [{"name": "wiki.edit"}]}, key=wiki_key)
assert r.status_code == 403 and r.json()["error"] == "scope_missing", r.text
human_key = auth.create_api_key(ana, name="mine")["key"]
assert put("docs", {"permissions": new}, key=human_key).json()["error"] == "not_this_app"
denied = [a for a in auth.store.recent_audit(80) if a["event"] == "permission_api_denied"]
assert denied and any("reason=not_this_app" in (a["detail"] or "") for a in denied)
ok("(d) PUT registers the manifest (grants nothing) only for the key's own application and with the scope")

r = read(ana, "docs")
assert r.status_code == 200 and r.json() == {"app": "docs", "user": ana, "permissions": ["docs.read"]}, r.text
assert read(ana, "wiki", key=wiki_key).json()["permissions"] == ["wiki.edit"]
assert read(ana, "wiki").json()["error"] == "not_this_app"
assert read(ana, "nosuch").json()["error"] == "not_this_app"
assert read(999999, "docs").status_code == 404 and read("x1", "docs").status_code == 404
assert read(int(bot), "docs").status_code == 404, "a service account is no person"
gone = int(auth.create_user("gone", password=PW))
auth.set_disabled(gone, True)
assert read(gone, "docs").status_code == 404
saved = _permissions_api.READS_PER_MINUTE
_permissions_api.READS_PER_MINUTE = 0
try:
    r = read(ana, "docs")
    assert r.status_code == 429 and r.headers["retry-after"] == "60", r.status_code
finally:
    _permissions_api.READS_PER_MINUTE = saved
ok("(d) GET reads the account's permissions for the key's application; 404 for an unknown, locked or service account; "
   "throttled per application")

bare, bare_app = build(apps={"docs": {"name": "Documents", "hosts": [DOCS], "permissions": MANIFEST}})
bare_api = TestClient(bare_app, base_url="http://testserver")
assert bare_api.put("/auth/api/apps/docs/permissions", json=MANIFEST, headers={"X-Api-Key": bot_key}).status_code \
    in (404, 405)
assert bare_api.get(f"/auth/api/users/{ana}/permissions", params={"app": "docs"},
                    headers={"X-Api-Key": bot_key}).status_code == 404
ok("(d) the permission API is served only when an application has permission_scopes")
