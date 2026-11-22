"""`topbar_menu_links` (links in the account menu) and `brand_icon_title` (the logo's tooltip).

`topbar_menu_links` has the shape of `topbar_links` — `(title, target)` or `(title, target, rule)` — and shares its
check (`config_check`) and its filter (`topbar.visible_links`, `link_visible`). The links appear in the account menu
after "Signed in as …" and before "Account"; on a phone the bar links come first. `topbar_data`, `/auth/topbar.json`
and `/.tinysesam/topbar.json` carry them as `menu_links` (always present, `[]` signed out or locked).

`brand_icon_title` becomes `title` on the logo `<img>` (escaped, at most 200 characters, no control characters);
empty = byte-identical to before. The behaviour in a real browser (order at phone width) is in tests/test_browser.py.
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

from tinysesam import ConfigError, TinySesam, TinySesamConfig, config_check, gateway, topbar  # noqa: E402

HTML = {"Accept": "text/html"}
BASE = "https://auth.example.com"
MENU = [("My collections", "/collections"), ("Moderation", "/mod", {"role": "moderators"}),
        ("App admin", "https://app.example.com/admin", {"admin": True})]
PW = "a long test password 4711"


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=["app.example.com"], topbar_menu_links=MENU,
               topbar_links=[("Docs", "/docs")], available_roles=["moderators", "editors"])
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/own", response_class=HTMLResponse)
    def own(request: Request):
        return f"<!doctype html><html><head>{auth.topbar_head()}</head><body>{auth.topbar(request)}</body></html>"
    return auth, app


def client(auth, app, uid):
    c = TestClient(app, base_url=BASE)
    tok, _ = auth.start_session(uid, "password")
    c.cookies.set(auth.session_cookie_name, tok)
    return c


def menu_titles(page: str) -> list:
    """The titles in the account menu's menu-link block, in order."""
    block = re.search(r"<div class=tsbar-menulinks>(.*?)<div class=tsbar-sep>", page, re.S)
    return re.findall(r"<a [^>]*>(?:<svg.*?</svg>)?([^<]+)</a>", block.group(1), re.S) if block else []


auth, app = make()
boss = auth.create_user("boss", password=PW)
auth.store._exec("UPDATE users SET is_admin=1 WHERE id=?", (boss,))
carol = auth.create_user("carol", password=PW, roles=["editors"])
mo = auth.create_user("mo", password=PW, roles=["moderators"])
c_boss, c_carol, c_mo = (client(auth, app, u) for u in (boss, carol, mo))

# ── visibility: the same filter as topbar_links, in the menu and in the JSON ──────────────────────────────────────
for c, want in ((c_carol, ["My collections"]), (c_mo, ["My collections", "Moderation"]),
                (c_boss, ["My collections", "Moderation", "App admin"])):
    for path in ("/auth/account", "/own"):
        assert menu_titles(c.get(path, headers=HTML).text) == want, (path, want)
    assert [x["title"] for x in c.get("/auth/topbar.json").json()["menu_links"]] == want, want
auth.cfg.admin_implies_roles = False
assert menu_titles(c_boss.get("/auth/account", headers=HTML).text) == ["My collections", "App admin"]
assert [x["title"] for x in c_boss.get("/auth/topbar.json").json()["menu_links"]] == ["My collections", "App admin"]
auth.cfg.admin_implies_roles = True
page = c_carol.get("/auth/account", headers=HTML).text
assert "href='/mod'" not in page and "app.example.com/admin" not in page
ok("role link only for the role, admin link only for admins (admin_implies_roles as has_role) — menu and JSON")

# ── place: after "Signed in as", before "Account"; the phone's bar links first ─────────────────────────────────────
page = c_mo.get("/auth/account", headers=HTML).text
pop = re.search(r"<div class=tsbar-pop id=tsbar-pop hidden>(.*?)</div></div></header>", page, re.S).group(1)
i_who, i_mobile = pop.index("tsbar-who"), pop.index("tsbar-mlinks")
i_menu, i_account = pop.index("tsbar-menulinks"), pop.index("/auth/account'")
assert i_who < i_mobile < i_menu < i_account, (i_who, i_mobile, i_menu, i_account)
assert "<div class=tsbar-sep></div></div><a class=tsbar-item href='/auth/account'" in pop.replace(
    "__TS_P__", ""), "the menu links end with a separator of their own right before Account"
ok("order in the menu: Signed in as · bar links (phone) · menu links + separator · Account")

# ── signed out, locked, API key: no menu links ─────────────────────────────────────────────────────────────────────
anon = TestClient(app, base_url=BASE)
assert anon.get("/auth/topbar.json").json()["menu_links"] == []
assert "tsbar-menulinks" not in anon.get("/auth/login", headers=HTML).text
key = auth.create_api_key(boss, name="probe")["key"]
assert TestClient(app).get("/auth/topbar.json", headers={"Authorization": f"Bearer {key}"}).json()["menu_links"] == []
assert auth.topbar_data(None)["menu_links"] == []
assert [x["title"] for x in auth.topbar_data(auth.get_user(mo))["menu_links"]] == ["My collections", "Moderation"]
auth.store._exec("UPDATE users SET disabled=1 WHERE id=?", (mo,))
assert auth.topbar_data(auth.get_user(mo))["menu_links"] == [], "a locked account sees no menu links"
auth.store._exec("UPDATE users SET disabled=0 WHERE id=?", (mo,))
ok("menu_links is always present: [] signed out, for an API key and for a locked account")

# ── escaping: a title is text ──────────────────────────────────────────────────────────────────────────────────────
auth_x, app_x = make(topbar_menu_links=[("<script>x</script>", "/s")])
ux = auth_x.create_user("carol", password=PW)
page = client(auth_x, app_x, ux).get("/auth/account", headers=HTML).text
assert "<script>x</script>" not in page and "&lt;script&gt;x&lt;/script&gt;" in page
ok("a menu link title with markup is escaped")

# ── config_check: one rule for both fields ─────────────────────────────────────────────────────────────────────────
for bad in ([("JS", "javascript:alert(1)")], [("Slash", "//evil.example/")], [("Back", "/\\evil.example")],
            [("Evil", "https://evil.example/")], [("Quote", "/a'onmouseover=x")], [("Space", "/a b")],
            [("Data", "data:text/html,x")], [("", "/x")], [("T" * 61, "/x")], [("Bell\x07", "/x")],
            [("A", "/x", {"admin": False})], [("A", "/x", {"role": ""})], ["/x"]):
    try:
        make(topbar_menu_links=bad)
    except ConfigError as e:
        assert "topbar_menu_links" in str(e), (bad, e)
    else:
        raise AssertionError(f"topbar_menu_links={bad!r} accepted")
_cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), base_url=BASE, available_roles=["editors"],
                       topbar_menu_links=[("Team", "/t", {"role": "teamadmin"})] + [(f"L{n}", f"/l{n}")
                                                                                     for n in range(10)])
errors, warnings = config_check.check_config(_cfg)
assert not errors, errors
assert [w for w in warnings if "topbar_menu_links" in w and "'teamadmin'" in w], warnings
assert [w for w in warnings if "topbar_menu_links: 11 entries" in w], warnings
_cfg.lang = "de"
de = config_check.check_config(_cfg)[1]
assert [w for w in de if "topbar_menu_links: 11 Einträge" in w] and [w for w in de if "steht — ein Tippfehler" in w], de
_cfg.topbar_menu_links = _cfg.topbar_menu_links[:10]
assert not [w for w in config_check.check_config(_cfg)[1] if "Einträge" in w], "10 entries must not warn"
ok("config_check refuses javascript:, //, /\\, a foreign https host, ' and control characters in menu links; a role "
   "outside available_roles and more than 10 entries warn (en/de)")

# ── gateway environment ────────────────────────────────────────────────────────────────────────────────────────────
_saved = dict(os.environ)
try:
    os.environ.update({"TINYSESAM_BASE_URL": BASE, "TINYSESAM_OIDC_ISSUER": "https://idp.example.com",
                       "TINYSESAM_OIDC_CLIENT_ID": "x", "TINYSESAM_OIDC_CLIENT_SECRET": "y",
                       "TINYSESAM_TOPBAR_MENU_LINKS": '[["Mine", "/mine"], ["Mod", "/mod", {"role": "moderators"}]]',
                       "TINYSESAM_BRAND_ICON_TITLE": " Logo: Example Icons, CC BY 4.0 "})
    _g = gateway.config_from_env()
    assert _g.topbar_menu_links == [("Mine", "/mine"), ("Mod", "/mod", {"role": "moderators"})], _g.topbar_menu_links
    assert _g.brand_icon_title == "Logo: Example Icons, CC BY 4.0"
    for broken in ("[not json", '{"Mine": "/mine"}', '[["Mine"]]', '[["A", "/a", "admin"]]'):
        os.environ["TINYSESAM_TOPBAR_MENU_LINKS"] = broken
        try:
            gateway.config_from_env()
        except SystemExit as e:
            assert "TINYSESAM_TOPBAR_MENU_LINKS" in str(e), e
        else:
            raise AssertionError(f"broken TINYSESAM_TOPBAR_MENU_LINKS accepted: {broken}")
    del os.environ["TINYSESAM_TOPBAR_MENU_LINKS"], os.environ["TINYSESAM_BRAND_ICON_TITLE"]
    _g = gateway.config_from_env()
    assert _g.topbar_menu_links == [] and _g.brand_icon_title == ""
finally:
    os.environ.clear()
    os.environ.update(_saved)
ok("TINYSESAM_TOPBAR_MENU_LINKS and TINYSESAM_BRAND_ICON_TITLE reach the config; broken JSON ends the start")

# ══ brand_icon_title ═══════════════════════════════════════════════════════════════════════════════════════════════
plain_img = topbar.logo(TinySesamConfig(brand_icon="/static/logo.svg"))
assert plain_img == "<img class=tsbar-logo src='/static/logo.svg' alt='' width=26 height=26>", plain_img
titled = topbar.logo(TinySesamConfig(brand_icon="/static/logo.svg", brand_icon_title="Logo: Example, CC BY 4.0"))
assert titled == ("<img class=tsbar-logo src='/static/logo.svg' alt='' title='Logo: Example, CC BY 4.0' width=26 "
                  "height=26>"), titled
evil = topbar.logo(TinySesamConfig(brand_icon="/l.svg", brand_icon_title="x'><script>alert(1)</script>\""))
assert "<script>" not in evil and "title='x&#x27;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&quot;'" in evil, evil
assert evil.count("'") == 6, f"no attribute breakout: {evil}"
for icon in ("", "none", "https://cdn.example.com/x.svg"):
    out = topbar.logo(TinySesamConfig(brand_icon=icon, brand_icon_title="Credit"))
    assert "title=" not in out and "Credit" not in out, (icon, out)
ok("brand_icon_title: title on the <img>, escaped ('><script> cannot break out); empty → byte-identical img; built-in "
   "mark and none carry no title")

# Through a real page: the bar of the account page.
auth_t, app_t = make(brand_icon="/static/logo.svg", brand_icon_title="Logo & Co")
ut = auth_t.create_user("carol", password=PW)
assert "alt='' title='Logo &amp; Co' width=26" in client(auth_t, app_t, ut).get("/auth/account", headers=HTML).text
ok("brand_icon_title reaches the bar of a built-in page")

for bad in ("x" * 201, "a\nb", "tab\there", "del\x7f", 5):
    try:
        make(brand_icon="/l.svg", brand_icon_title=bad)
    except ConfigError as e:
        assert "brand_icon_title" in str(e), e
    else:
        raise AssertionError(f"brand_icon_title={bad!r} accepted")
make(brand_icon="/l.svg", brand_icon_title="x" * 200)
_w = config_check.check_config(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "w.db"),
                                               brand_icon_title="Credit"))[1]
assert [w for w in _w if "brand_icon_title works only with an image" in w], _w
_w = config_check.check_config(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "w.db"),
                                               brand_icon="data:image/png;base64,AAAA", brand_icon_title="Credit"))[1]
assert not [w for w in _w if "brand_icon_title" in w], _w
ok("brand_icon_title: more than 200 characters or a control character stops the start; without an image it warns")
