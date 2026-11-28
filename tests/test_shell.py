"""T-103: the shell on top and at the side — one component, layout top or side.

The configuration (`shell_layout`, `apps[id].layout`, the permission rule of a link), the part `frame` of
`topbar.json`, the side layout of the built-in pages and of `auth.topbar(layout=…)`, and the assets of the component
`<ts-shell>` under `/auth/` and `/.tinysesam/`. The component in a real browser (both layouts, 375 and 1280 px, light
and dark, strict CSP, Ex1 and Ex2) is in tests/test_shell_browser.py.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from voraussetzung import pflicht_werkzeug  # noqa: E402

HTML = {"Accept": "text/html"}
BASE = "https://auth.example.com"
PW = "a long test password 4711"
DOCS = {"name": "Documents", "hosts": ["docs.example.com"], "layout": "side",
        "permissions": [{"name": "docs.read", "label": {"en": "Read"}},
                        {"name": "docs.delete", "label": {"en": "Delete"}, "danger": True}]}
TRASH = ("Trash", "/trash", {"permission": "docs.delete", "app": "docs"})


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=["docs.example.com", "wiki.example.com"],
               available_roles=["docs-editor", "docs-reader"], apps={"docs": DOCS},
               topbar_links=[("Docs", "/"), TRASH])
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/own", response_class=HTMLResponse)
    def own(request: Request, layout: str = ""):
        return (f"<!doctype html><html><head>{auth.topbar_head()}</head><body>"
                f"{auth.topbar(request, layout=layout, current='/')}</body></html>")
    return auth, app


def client(auth, app, uid, base_url=BASE):
    c = TestClient(app, base_url=base_url)
    tok, _ = auth.start_session(uid, "password")
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def refused(**kw) -> str:
    try:
        make(**kw)
    except ConfigError as e:
        return str(e)
    raise AssertionError(f"accepted: {kw}")


# ══ Configuration ════════════════════════════════════════════════════════════════════════════════════════════════
assert "shell_layout" in refused(shell_layout="left")
assert "apps['docs'].layout" in refused(apps={"docs": {**DOCS, "layout": "bottom"}})
msg = refused(apps={"docs": {k: v for k, v in DOCS.items() if k != "hosts"}})
assert "layout without hosts" in msg, msg
assert "permission" in refused(topbar_links=[("Trash", "/trash", {"permission": "docs.delete", "app": "nope"})])
assert "permission" in refused(topbar_links=[("Trash", "/trash", {"permission": "Not A Name", "app": "docs"})])
assert "visibility" in refused(topbar_links=[("Trash", "/trash", {"permission": "docs.delete"})])
de = refused(shell_layout="left", lang="de")
assert "\"top\" oder \"side\"" in de, de
auth, app = make()
assert auth.cfg.shell_layout == "top"
ok("configuration: shell_layout and apps[id].layout only top/side, a layout needs hosts, a permission link names a "
   "permission of an application in apps (German findings too)")

# ══ Permission links (T-103): has_permission decides, like require_permission ════════════════════════════════════
eddi = auth.create_user("eddi", password=PW, roles=["docs-editor"])
rita = auth.create_user("rita", password=PW, roles=["docs-reader"])
c_eddi, c_rita = client(auth, app, eddi), client(auth, app, rita)
assert [x["title"] for x in c_eddi.get("/auth/topbar.json").json()["links"]] == ["Docs"], "a link before the grant"
auth.grant_permission("docs-editor", "docs.delete", app="docs", by="test")
assert [x["title"] for x in c_eddi.get("/auth/topbar.json").json()["links"]] == ["Docs", "Trash"]
assert [x["title"] for x in c_rita.get("/auth/topbar.json").json()["links"]] == ["Docs"]
assert "href='/trash'" in c_eddi.get("/own").text and "href='/trash'" not in c_rita.get("/own").text
ok("a link with {permission, app} appears for the holder of the permission only — JSON and bar")

# ══ The part `frame` of topbar.json ══════════════════════════════════════════════════════════════════════════════
anon = TestClient(app, base_url=BASE)
assert anon.get("/auth/topbar.json").json()["frame"] == {"name": None, "home": None, "links": [], "layout": "top"}
# `?app=` with a host of an application: its layout; an unknown host answers byte for byte like none.
assert c_rita.get("/auth/topbar.json?app=docs.example.com").json()["frame"]["layout"] == "side"
assert (c_rita.get("/auth/topbar.json?app=evil.example.net").content == c_rita.get("/auth/topbar.json").content)
auth.cfg.shell_layout = "side"
assert anon.get("/auth/topbar.json").json()["frame"]["layout"] == "side"
auth.cfg.shell_layout = "top"
ok("topbar.json `frame`: always there; layout from apps[id].layout for ?app=<host>, else shell_layout; an unknown "
   "host changes nothing")

# On the application's host through the proxy: the app frame of forward_apps, its links filtered, the account framed.
auth_g, app_g = make(forward_auth_enabled=True, cookie_domain=".example.com",
                     forward_apps={"docs.example.com": {"name": "Documents", "home": "/",
                                                       "links": [("All", "/all"), ("Trash", "/trash",
                                                                 {"permission": "docs.delete", "app": "docs"})]},
                                   "wiki.example.com": {"name": "Wiki"}})
u_g = auth_g.create_user("eddi", password=PW, roles=["docs-editor"])
auth_g.grant_permission("docs-editor", "docs.delete", app="docs", by="test")
proxy = {"X-Forwarded-Host": "docs.example.com", "X-Forwarded-Proto": "https"}
g = client(auth_g, app_g, u_g, "https://docs.example.com")
j = g.get("/.tinysesam/topbar.json", headers=proxy).json()
assert j["frame"] == {"name": "Documents", "home": "https://docs.example.com/", "layout": "side",
                      "links": [{"title": "All", "href": "https://docs.example.com/all"},
                                {"title": "Trash", "href": "https://docs.example.com/trash"}]}, j["frame"]
assert j["account"]["href"] == f"{BASE}/auth/account?app=docs.example.com", j["account"]
g_anon = TestClient(app_g, base_url="https://docs.example.com")
j = g_anon.get("/.tinysesam/topbar.json", headers=proxy).json()
assert j["frame"] == {"name": "Documents", "home": None, "links": [], "layout": "side"}, j["frame"]
# A host of forward_apps without a frame and without an application: no name, the instance's layout.
j = g.get("/.tinysesam/topbar.json", headers={**proxy, "X-Forwarded-Host": "wiki.example.com"}).json()
assert j["frame"] == {"name": None, "home": None, "links": [], "layout": "top"}, j["frame"]
assert j["account"]["href"] == f"{BASE}/auth/account", j["account"]
ok("/.tinysesam/topbar.json: the frame of the host (name, home, links for the viewer as addresses on the host, "
   "layout of the application), the account page framed; signed out the name only")

# ══ Side layout of the built-in pages and of auth.topbar ═════════════════════════════════════════════════════════
c_boss = client(auth, app, auth.create_user("boss", password=PW, is_admin=True))
assert "<header class=tsbar>" in c_boss.get("/auth/account", headers=HTML).text, "top is the default"
auth.cfg.shell_layout = "side"
for path in ("/auth/account", "/auth/admin", "/auth/login"):
    page = (c_boss if path != "/auth/login" else anon).get(path, headers=HTML).text
    assert "<header class='tsbar tsside'>" in page, f"{path}: no side layout"
    assert "body:has(> .tsbar.tsside)" in page, f"{path}: the page does not give way"
auth.cfg.shell_layout = "top"
assert "<header class='tsbar tsside'>" in c_boss.get("/own?layout=side").text
assert "<header class=tsbar>" in c_boss.get("/own?layout=top").text
try:
    auth.topbar(None, layout="left")
    raise AssertionError("layout='left' accepted")
except ValueError:
    pass
# A page in an application's frame takes that application's layout.
framed = client(auth_g, app_g, u_g).get("/auth/account?app=docs.example.com", headers=HTML).text
assert "<header class='tsbar tsside tsframe'>" in framed, re.findall(r"<header[^>]*>", framed)
assert "aria-current=page" in client(auth_g, app_g, u_g).get("/auth/account?app=docs.example.com",
                                                              headers=HTML).text
ok("side layout: shell_layout puts the account page, the panel and the sign-in page at the side; "
   "auth.topbar(layout=…) chooses per page; a framed page follows apps[id].layout")

# ══ The component's assets ═══════════════════════════════════════════════════════════════════════════════════════
r = anon.get("/auth/shell.js")
assert r.status_code == 200 and r.headers["content-type"].startswith("text/javascript"), r.headers
assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-cache"
js = r.text
assert "customElements.define('ts-shell'" in js and "Signed in as" in js and "__TEXTS__" not in js
assert "alert(" not in js and "confirm(" not in js and "prompt(" not in js and "eval(" not in js
assert anon.get("/auth/shell.js", headers={"If-None-Match": r.headers["etag"]}).status_code == 304
css = anon.get("/auth/shell.css")
assert css.status_code == 200 and css.headers["content-type"].startswith("text/css")
assert "--ts-bg:" in css.text and ".tsbar.tsside" in css.text and ":host([layout=side])" in css.text
assert not re.search(r"#[0-9a-fA-F]{3,8}\b", css.text.replace(auth_g.cfg.rp_name, "").split("}\n}", 1)[1]), \
    "a colour outside the tokens"
auth_de, app_de = make(lang="de")
assert "Angemeldet als" in TestClient(app_de).get("/auth/shell.js").text
auth.cfg.topbar_enabled = False
assert anon.get("/auth/shell.js").status_code == 404 and anon.get("/auth/shell.css").status_code == 404
auth.cfg.topbar_enabled = True
# The application's host: only a protected one, and only with forward auth.
assert g.get("/.tinysesam/shell.js", headers=proxy).status_code == 200
assert g.get("/.tinysesam/shell.css", headers=proxy).text == TestClient(app_g).get("/auth/shell.css").text
assert g.get("/.tinysesam/shell.js", headers={**proxy, "X-Forwarded-Host": "evil.example.net"}).status_code == 404
assert anon.get("/.tinysesam/shell.js").status_code == 404, "the gate path without forward auth"
node = pflicht_werkzeug("node", "the syntax of shell.js")
if node:
    path = os.path.join(tempfile.mkdtemp(), "shell.js")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(js)
    out = subprocess.run([node, "--check", path], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
ok("assets: /auth/shell.js (texts in the instance's language, ETag/304, nosniff, no system dialog) and "
   "/auth/shell.css (tokens, side layout, host rules, no colour outside the tokens); /.tinysesam/ on a protected "
   "host only; 404 with topbar_enabled=False; node --check")
