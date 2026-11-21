"""The recipe "link your app's admin from TinySesam and back" (examples/app_admin.py) works as the README says.

* there: the top bar link to the application's administration only for administrators, the team link only for the
  role, on TinySesam's pages and the application's own;
* back: the application's admin page links to TinySesam's admin panel with the address `topbar_data` reports;
* data: the internal app hands a frontend the bar of the account behind `Remote-Id` — the same as `auth.topbar_data`,
  and it is a separate app (never routed by the proxy), not a route of the public one.
"""
import importlib
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ["APP_ADMIN_DB"] = os.path.join(tempfile.mkdtemp(), "app_admin.db")
os.environ["APP_ADMIN_BASE_URL"] = "http://testserver"

from fastapi.testclient import TestClient  # noqa: E402

example = importlib.import_module("examples.app_admin")
auth, app, internal = example.auth, example.app, example.internal
HTML = {"Accept": "text/html"}
PW = "a long test password 4711"


def ok(name):
    print(f"  ✓ {name}")


def client(uid):
    c = TestClient(app)
    c.cookies.set(auth.session_cookie_name, auth.start_session(uid, "password")[0])
    return c


def links(page: str) -> list:
    nav = re.search(r"<nav class=tsbar-links[^>]*>(.*?)</nav>", page, re.S)
    return re.findall(r">([^<]+)</a>", nav.group(1)) if nav else []


boss = auth.create_user("boss", password=PW)
auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (boss,))
carol = auth.create_user("carol", password=PW)
tara = auth.create_user("tara", password=PW, roles=["teamadmin"])
c_boss, c_carol, c_tara = client(boss), client(carol), client(tara)

# ══ There: the link to the application's admin, only for administrators ═════════════════════════════════════════
for path in ("/", "/auth/account"):
    assert "App admin" in links(c_boss.get(path, headers=HTML).text), path
    assert links(c_carol.get(path, headers=HTML).text) == ["Home"], path
    assert links(c_tara.get(path, headers=HTML).text) == ["Home", "Team"], path
assert "App admin" in links(c_boss.get("/auth/admin", headers=HTML).text), "the panel's bar leads to the app's admin"
ok("there: the admin panel, the account page and the application's pages show App admin to administrators only")

# ══ Back: the application's admin page links to the panel ═══════════════════════════════════════════════════════
r = c_boss.get("/app-admin", headers=HTML)
assert r.status_code == 200 and "href='http://testserver/auth/admin'" in r.text, r.text[-600:]
assert c_boss.get("/auth/admin", headers=HTML).status_code == 200
assert c_carol.get("/app-admin", headers=HTML).status_code == 403, "the target checks access itself"
assert c_tara.get("/team", headers=HTML).status_code == 200 and c_carol.get("/team", headers=HTML).status_code == 403
ok("back: the app's admin page links to TinySesam's panel (absolute on base_url); the targets check access themselves")

# ══ Data: the internal app for a frontend not drawn in Python ═══════════════════════════════════════════════════
inner = TestClient(internal)
for uid in (boss, carol, tara):
    assert inner.get(f"/topbar/{uid}").json() == auth.topbar_data(auth.get_user(uid)), uid
assert [x["title"] for x in inner.get(f"/topbar/{tara}").json()["links"]] == ["Home", "Team"]
assert inner.get("/topbar/99999").status_code == 404
paths = {getattr(route, "path", "") for route in app.routes}
assert not any(p.startswith("/topbar") for p in paths), "the internal endpoint must not be a route of the public app"
assert not any(p.startswith("/auth") for p in {getattr(route, "path", "") for route in internal.routes})
ok("data: the internal app answers auth.topbar_data for the account ID; it is a separate app, not a public route")
