"""T-76: visibility per top bar link, and the bar as JSON for applications that draw their own (`/auth/topbar.json`).

`topbar_links` entries take an optional third element: `{"admin": True}` (accounts with the admin flag) or
`{"role": "…"}` (accounts with the role, by `has_role` — so with `admin_implies_roles`, the default, an admin sees
role links too). A plain pair stays visible to everyone. One filter serves the bar, the phone menu (`tsbar-mlinks`),
`auth.topbar(request)` and the JSON.

B1–B7 are the acceptance tests of a deployment that asked for it. The behaviour in a real browser (menu, phone width)
is in tests/test_browser.py; this suite checks the HTML and the JSON.
"""
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig, config_check  # noqa: E402

HTML = {"Accept": "text/html"}
BASE = "https://auth.example.com"
LINKS = [("Docs", "/"), ("Admin App", "https://app.example.com/admin", {"admin": True}),
         ("Team", "/t", {"role": "teamadmin"})]
PW = "a long test password 4711"


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=["app.example.com"], topbar_links=LINKS,
               available_roles=["teamadmin", "editors"])
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    auth.install_error_pages(app)

    @app.get("/own", response_class=HTMLResponse)
    def own(request: Request):
        return f"<!doctype html><html><head>{auth.topbar_head()}</head><body>{auth.topbar(request)}</body></html>"

    @app.get("/boom", response_class=HTMLResponse)
    def boom(request: Request):
        from fastapi import HTTPException
        raise HTTPException(404)
    return auth, app


def client(auth, app, uid):
    c = TestClient(app, base_url="https://auth.example.com")
    tok, _ = auth.start_session(uid, "password")
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def bar_of(page: str) -> str:
    return re.search(r"<header class=tsbar>.*?</header>", page, re.S).group(0)


def titles(fragment: str) -> list:
    return re.findall(r"<a [^>]*>(?:<svg.*?</svg>)?([^<]+)</a>", fragment, re.S)


def bar_links(page: str) -> tuple:
    """(links in the bar's nav, links in the phone menu) of a page."""
    bar = bar_of(page)
    nav = re.search(r"<nav class=tsbar-links[^>]*>(.*?)</nav>", bar, re.S)
    mob = re.search(r"<div class=tsbar-mlinks>(.*?)<div class=tsbar-sep>", bar, re.S)
    return titles(nav.group(1)) if nav else [], titles(mob.group(1)) if mob else []


auth, app = make()
admin = auth.create_user("boss", password=PW)
auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (admin,))
plain = auth.create_user("carol", password=PW, roles=["editors"])
lead = auth.create_user("tara", password=PW, roles=["teamadmin"])
c_admin, c_plain, c_lead = (client(auth, app, u) for u in (admin, plain, lead))

# ══ B1: neither admin nor teamadmin → only "Docs", in the bar and in the phone menu ═════════════════════════════
for path in ("/auth/account", "/own"):
    page = c_plain.get(path, headers=HTML).text
    assert bar_links(page) == (["Docs"], ["Docs"]), (path, bar_links(page))
    assert "app.example.com/admin" not in page and "href='/t'" not in page, path
ok("B1: an account without admin and teamadmin sees only Docs — bar and phone menu, account page and topbar(request)")

# ══ B2: admin → Docs and Admin App, Team through admin_implies_roles ═════════════════════════════════════════════
page = c_admin.get("/auth/account", headers=HTML).text
assert bar_links(page) == (["Docs", "Admin App", "Team"], ["Docs", "Admin App", "Team"]), bar_links(page)
auth.cfg.admin_implies_roles = False
page = c_admin.get("/auth/account", headers=HTML).text
assert bar_links(page) == (["Docs", "Admin App"], ["Docs", "Admin App"]), bar_links(page)
auth.cfg.admin_implies_roles = True
ok("B2: admin sees Docs + Admin App; Team only while admin_implies_roles holds (default on) — like has_role")

# ══ B3: teamadmin without admin → Docs and Team ═════════════════════════════════════════════════════════════════
page = c_lead.get("/own", headers=HTML).text
assert bar_links(page) == (["Docs", "Team"], ["Docs", "Team"]), bar_links(page)
assert "app.example.com/admin" not in page
ok("B3: teamadmin without admin sees Docs + Team")

# ══ B4: the old pair format is unchanged ════════════════════════════════════════════════════════════════════════
auth4, app4 = make(topbar_links=[("Wiki", "/wiki"), ("Files", "https://app.example.com/files/")])
u4 = auth4.create_user("carol", password=PW)
page = client(auth4, app4, u4).get("/auth/account", headers=HTML).text
assert bar_links(page) == (["Wiki", "Files"], ["Wiki", "Files"]), bar_links(page)
ok("B4: (title, target) pairs are visible to everyone, as before")

# ══ B5: pages without the menu carry no restricted link — not even in the source ═══════════════════════════════
anon = TestClient(app, base_url="https://auth.example.com")
for c, who in ((anon, "anonymous"), (c_admin, "admin")):
    for path in ("/auth/login", "/boom"):
        r = c.get(path, headers=HTML, follow_redirects=False)
        if r.status_code in (302, 303):
            continue                                       # a signed-in admin is sent on from the sign-in page
        assert "<header class=tsbar>" in r.text, (who, path, r.status_code)
        for restricted in ("app.example.com/admin", "href='/t'", "Admin App", ">Team<"):
            assert restricted not in r.text, (who, path, restricted)
        assert "class=tsbar-links" not in r.text and "tsbar-mlinks>" not in r.text, (who, path)
assert c_admin.get("/boom", headers=HTML).status_code == 404
ok("B5: sign-in and error page (anonymous and an admin) — logo and name only, no restricted link in the HTML")

# ══ B6: config_check — a visibility role outside available_roles warns; a broken rule is an error ══════════════
_cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), base_url=BASE, available_roles=["editors"],
                       topbar_links=[("Team", "/t", {"role": "teamadmin"}), ("Ed", "/e", {"role": "editors"})])
errors, warnings = config_check.check_config(_cfg)
assert not [e for e in errors if "topbar_links" in e], errors
assert [w for w in warnings if "topbar_links" in w and "'teamadmin'" in w and "available_roles" in w], warnings
assert not [w for w in warnings if "'editors'" in w and "topbar_links" in w], "a listed role must not warn"
_cfg.lang = "de"
_de = [w for w in config_check.check_config(_cfg)[1] if "topbar_links" in w and "'teamadmin'" in w]
assert _de and _de[0] not in warnings, "no translated text"
for rule in ({"admin": False}, {"admin": "yes"}, {"role": ""}, {"role": 3}, {"admin": True, "role": "x"},
             {"roles": ["x"]}, {}, ["admin"], "admin"):
    try:
        make(topbar_links=[("X", "/x", rule)])
    except ConfigError as e:
        assert "topbar_links" in str(e) and "visibility" in str(e), (rule, e)
    else:
        raise AssertionError(f"visibility {rule!r} accepted")
ok("B6: a role outside available_roles warns (en/de), a listed one does not; a broken visibility stops the start")

# ══ B7: the bar as JSON ═════════════════════════════════════════════════════════════════════════════════════════
r = c_admin.get("/auth/topbar.json", headers={"Origin": "https://evil.example"})
assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
assert r.headers["cache-control"] == "no-store" and "cookie" in r.headers.get("vary", "").lower(), dict(r.headers)
assert not [k for k in r.headers if k.lower().startswith("access-control-")], dict(r.headers)
j = r.json()
assert j["signed_in"] is True and j["name"] == "boss", j
assert j["links"] == [{"title": "Docs", "href": "/"}, {"title": "Admin App", "href": "https://app.example.com/admin"},
                      {"title": "Team", "href": "/t"}], j["links"]
assert j["account"] == {"shown": True, "href": f"{BASE}/auth/account"}, j["account"]
assert j["admin_panel"] == {"shown": True, "href": f"{BASE}/auth/admin"}, j["admin_panel"]
assert j["logout"] == {"href": f"{BASE}/auth/logout"}, j["logout"]
j = c_plain.get("/auth/topbar.json").json()
assert [x["title"] for x in j["links"]] == ["Docs"] and j["admin_panel"] == {"shown": False, "href": None}, j
assert [x["title"] for x in c_lead.get("/auth/topbar.json").json()["links"]] == ["Docs", "Team"]
j = anon.get("/auth/topbar.json").json()
assert j == {"brand": auth.cfg.rp_name, "signed_in": False, "name": None, "links": [], "menu_links": [],
             "account": {"shown": False, "href": None}, "admin_panel": {"shown": False, "href": None},
             "logout": None, "frame": {"name": None, "home": None, "links": [], "layout": "top"}}, j
# An API key is no browser session: the bar shows it no menu, the JSON says the same.
key = auth.create_api_key(admin, name="probe")["key"]
j = TestClient(app).get("/auth/topbar.json", headers={"Authorization": f"Bearer {key}"}).json()
assert j["signed_in"] is False and j["links"] == [], j
# The account page off: "Account" is not shown.
auth.cfg.account_enabled = False
assert c_plain.get("/auth/topbar.json").json()["account"] == {"shown": False, "href": None}
auth.cfg.account_enabled = True
# Display name instead of the username, when there is one.
auth.store._exec("UPDATE users SET display_name=? WHERE id=?", ("Tara Lead", lead))
assert c_lead.get("/auth/topbar.json").json()["name"] == "Tara Lead"
ok("B7: /auth/topbar.json — the same links as the bar, name, account and admin panel with absolute paths; no-store, "
   "Vary: Cookie, no CORS; anonymous and API key get no menu")

# Without base_url the paths are relative to the mount prefix.
auth_nb, app_nb = make(base_url="", trusted_redirect_hosts=[], topbar_links=[("Docs", "/")])
u_nb = auth_nb.create_user("carol", password=PW)
j = client(auth_nb, app_nb, u_nb).get("/auth/topbar.json").json()
assert j["account"]["href"] == "/auth/account" and j["logout"]["href"] == "/auth/logout", j
ok("without base_url: TinySesam's paths relative to the mount prefix")

# ══ B7 on the application's host: /.tinysesam/topbar.json through the proxy (same origin, no CORS) ══════════════
auth_g, app_g = make(forward_auth_enabled=True, cookie_domain=".example.com")
u_g = auth_g.create_user("tara", password=PW, roles=["teamadmin"])
tok_g, _ = auth_g.start_session(u_g, "password")
proxy = {"X-Forwarded-Host": "app.example.com", "X-Forwarded-Proto": "https"}
g = TestClient(app_g, base_url="https://app.example.com")
g.cookies.set(auth_g.session_cookie_name, tok_g)
r = g.get("/.tinysesam/topbar.json", headers=proxy)
assert r.status_code == 200 and r.headers["cache-control"] == "no-store", (r.status_code, r.text[:200])
j = r.json()
assert [x["title"] for x in j["links"]] == ["Docs", "Team"] and j["account"]["href"] == f"{BASE}/auth/account", j
assert TestClient(app_g).get("/.tinysesam/topbar.json", headers=proxy).json()["signed_in"] is False
assert g.get("/.tinysesam/topbar.json", headers={"X-Forwarded-Host": "foreign.example.net"}).status_code == 404
ok("/.tinysesam/topbar.json on a protected application's host — the same answer; a foreign host gets 404")

# ══ The gateway's variable takes the visibility ═════════════════════════════════════════════════════════════════
from tinysesam import gateway  # noqa: E402

_saved = dict(os.environ)
try:
    os.environ.update({"TINYSESAM_BASE_URL": BASE, "TINYSESAM_OIDC_ISSUER": "https://idp.example.com",
                       "TINYSESAM_OIDC_CLIENT_ID": "x", "TINYSESAM_OIDC_CLIENT_SECRET": "y",
                       "TINYSESAM_DB_PATH": os.path.join(tempfile.mkdtemp(), "g.db"),
                       "TINYSESAM_TOPBAR_LINKS": '[["Docs", "/"], ["Admin", "/admin", {"admin": true}], '
                                                 '["Team", "/t", {"role": "teamadmin"}]]'})
    _gcfg = gateway.config_from_env()
    assert _gcfg.topbar_links == [("Docs", "/"), ("Admin", "/admin", {"admin": True}),
                                  ("Team", "/t", {"role": "teamadmin"})], _gcfg.topbar_links
    for broken in ('[["Admin", "/admin", "admin"]]', '[["A", "/a", {"admin": true}, 4]]'):
        os.environ["TINYSESAM_TOPBAR_LINKS"] = broken
        try:
            gateway.config_from_env()
        except SystemExit as e:
            assert "TINYSESAM_TOPBAR_LINKS" in str(e), e
        else:
            raise AssertionError(f"broken TINYSESAM_TOPBAR_LINKS accepted: {broken}")
finally:
    os.environ.clear()
    os.environ.update(_saved)
ok("TINYSESAM_TOPBAR_LINKS takes [title, target, {visibility}]; a visibility that is no object ends the start")

# ══ auth.topbar_data — the same answer for a library app that renders elsewhere ═════════════════════════════════
_lead_row = auth.get_user(lead)
assert auth.topbar_data(_lead_row) == c_lead.get("/auth/topbar.json").json(), "topbar_data and the JSON route differ"
assert auth.topbar_data(auth.get_user(admin)) == c_admin.get("/auth/topbar.json").json()
assert auth.topbar_data(None) == anon.get("/auth/topbar.json").json()
assert auth.topbar_data(_lead_row)["account"]["href"] == f"{BASE}/auth/account", "base defaults to base_url"
assert auth.topbar_data(_lead_row, base="/sso")["account"]["href"] == "/sso/auth/account"
assert auth_nb.topbar_data(auth_nb.get_user(u_nb))["account"]["href"] == "/auth/account", "without base_url: relative"
# A locked account is none: no links, no menu — also when a stale dict is handed in.
auth.store._exec("UPDATE users SET disabled=1 WHERE id=?", (lead,))
assert auth.topbar_data(_lead_row)["signed_in"] is False and auth.topbar_data(_lead_row)["links"] == []
auth.store._exec("UPDATE users SET disabled=0 WHERE id=?", (lead,))
assert auth.topbar_data({"id": 99999, "username": "ghost", "is_admin": 1})["signed_in"] is False, "unknown account"
# The caller's dict decides the flags: an API key's dict carries no admin flag, so no admin link and no panel.
_key_view = {**dict(auth.get_user(admin)), "is_admin": 0}
assert [x["title"] for x in auth.topbar_data(_key_view)["links"]] == ["Docs"], auth.topbar_data(_key_view)
assert auth.topbar_data(_key_view)["admin_panel"]["shown"] is False
ok("auth.topbar_data(user): the JSON route's answer for an account dict — base from base_url or given, a locked or "
   "unknown account gets no menu, the caller's flags count")
