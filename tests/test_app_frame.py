"""T-91, stage E1: the app frame on TinySesam's own pages.

`forward_apps[host]` takes `home` and `links`: whoever comes from that host sees TinySesam's sign-in, step-up, account
and approval pages in the application's frame — "‹ Example" back to `home`, the application's links, an account menu
with "Security" — instead of the gateway's own bar. The frame is chosen by `?app=<host>`, by the host of an absolute
`next`, by `app=<host>` inside a relative `next`, else by `forward_frame_default`; every target comes from the
configuration, never from the request. The same rules hold for the library without forward auth (draft §9).

The browser half (375 px, light/dark, strict CSP, no horizontal scrolling) is in tests/test_browser.py.
"""
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig, config_check  # noqa: E402

HTML = {"Accept": "text/html"}
BASE = "https://auth.example.com"
PW = "a long test password 4711"
APP = "team.example.com"
FRAME = {"name": "Example", "home": "/start",
         "links": [("Spaces", "/spaces"), ("Team", "/team", {"role": "example-lead"})]}


def ok(name):
    print(f"  ✓ {name}")


def make(**kw):
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), passkey_enabled=False, cookie_secure=False,
               lang="en", base_url=BASE, trusted_redirect_hosts=[APP, "other.example.com"],
               topbar_links=[("GatewayLink", "/gwlink")], topbar_menu_links=[("GatewayMenu", "/gwmenu")],
               available_roles=["example-lead"], account_enabled=True, gate_brand="Example Gate",
               forward_apps={APP: dict(FRAME), "other.example.com": {"name": "Other"}})
    cfg.update(kw)
    auth = TinySesam(TinySesamConfig(**cfg))
    app = FastAPI()
    app.include_router(auth.router())
    auth.install_error_pages(app)

    @app.get("/boom")
    def boom():
        raise HTTPException(404)
    return auth, app


def client(auth, app, uid=None):
    c = TestClient(app, base_url=BASE, follow_redirects=False)
    if uid is not None:
        tok, _ = auth.start_session(uid, "password")
        c.cookies.set(auth.session_cookie_name, tok)
    return c


def header(page: str) -> str:
    m = re.search(r"<header class=(?:'tsbar tsframe'|tsbar)>.*?</header>", page, re.S)
    assert m, page[:400]
    return m.group(0)


def framed(page: str) -> bool:
    return "<header class='tsbar tsframe'>" in page


def back_href(page: str) -> str:
    m = re.search(r"<a class='tsbar-brand tsbar-back' href='([^']*)'", page)
    return m.group(1) if m else ""


def normal(page: str) -> str:
    """The page without what differs per response (nonce, CSRF token)."""
    page = re.sub(r'nonce="[^"]*"', 'nonce=""', page)
    return re.sub(r"name=_csrf value='[^']*'", "name=_csrf value=''", page)


# Two installations: the gateway (forward auth) and the library alone — the frame is the same in both (draft §9).
auth_g, app_g = make(forward_auth_enabled=True)
auth_l, app_l = make()
for auth, app, kind in ((auth_g, app_g, "gateway"), (auth_l, app_l, "library")):
    anna = auth.create_user("anna", password=PW)
    c = client(auth, app, anna)
    # ══ F1: ?app=<host> → the frame, the back link from the configuration ══════════════════════════════════════
    page = c.get(f"/auth/account?app={APP}", headers=HTML).text
    assert framed(page), (kind, header(page)[:300])
    bar = header(page)
    assert back_href(page) == f"https://{APP}/start", (kind, back_href(page))
    assert "aria-label='Back to Example'" in bar and "<span>Example</span>" in bar, bar[:600]
    assert "via Example Gate" in bar, "the desktop line 'via <gate_brand>' is missing"
    assert "tsbar-logo" not in bar, "no TinySesam mark in the frame"
    assert f"href='/auth/account?app={APP}' aria-current=page" in bar, "Security does not lead to the framed page"
    ok(f"F1 ({kind}): ?app=<host> → '‹ Example' back to home (https://<host>/start), 'via Example Gate', "
       "Security framed and marked")

    # ══ F2: a home or next from the request never becomes the back link ═══════════════════════════════════════
    page = c.get(f"/auth/account?app={APP}&home=https://evil.example/&next=https://evil.example/",
                 headers=HTML).text
    assert framed(page) and back_href(page) == f"https://{APP}/start", back_href(page)
    assert "evil.example" not in page, "a value of the request reached the page"
    ok(f"F2 ({kind}): ?home=… and ?next=… of the request leave the back link at the configured value")

    # ══ F3: unknown host or an entry without a frame → the gateway's bar, 200, byte-equal to the page without app ═
    plain = c.get("/auth/account", headers=HTML)
    assert plain.status_code == 200 and not framed(plain.text)
    for host in ("unknown.example", "other.example.com", "", "%00", "x" * 300):
        r = c.get(f"/auth/account?app={host}", headers=HTML)
        assert r.status_code == 200 and normal(r.text) == normal(plain.text), (kind, host, r.status_code)
    ok(f"F3 ({kind}): ?app=unknown, an entry without home/links, empty, NUL, 300 characters → 200, the gateway's bar, "
       "byte-equal to the page without app (no oracle)")

    # ══ F4: the frame shows none of the gateway-wide links ═════════════════════════════════════════════════════
    page = c.get(f"/auth/account?app={APP}", headers=HTML).text
    for gw in ("GatewayLink", "/gwlink", "GatewayMenu", "/gwmenu"):
        assert gw not in page, (kind, gw)
    assert "GatewayLink" in plain.text and "GatewayMenu" in plain.text, "probe: the gateway's bar has them"
    ok(f"F4 ({kind}): a framed page carries neither topbar_links nor topbar_menu_links (the plain page does)")

    # ══ F5: a frame link with {"role": …} only for holders of the role — bar and phone menu ═══════════════════
    def titles(page):
        bar = header(page)
        nav = re.search(r"<nav class=tsbar-links[^>]*>(.*?)</nav>", bar, re.S)
        mob = re.search(r"<div class=tsbar-mlinks>(.*?)<div class=tsbar-sep>", bar, re.S)
        pick = (lambda s: re.findall(r"<a [^>]*>(?:<svg.*?</svg>)?([^<]+)</a>", s, re.S))
        return (pick(nav.group(1)) if nav else []), (pick(mob.group(1)) if mob else [])
    assert titles(page) == (["Spaces"], ["Spaces"]), titles(page)
    lead = auth.create_user("lena", password=PW, roles=["example-lead"])
    page_lead = client(auth, app, lead).get(f"/auth/account?app={APP}", headers=HTML).text
    assert titles(page_lead) == (["Spaces", "Team"], ["Spaces", "Team"]), titles(page_lead)
    assert f"href='https://{APP}/team'" in page_lead and f"https://{APP}/team" not in page
    assert "<div class=tsbar-label>Example</div>" in header(page_lead), "the phone menu names the application"
    ok(f"F5 ({kind}): the role link only for its holders, in the bar and in the phone menu; a path lies on the "
       "application's host")

    # ══ F6: pages without an account — the name only, no back link, no link at all in the source ═════════════
    anon = client(auth, app)
    pages = {"sign-in (absolute next)": anon.get(f"/auth/login?next=https://{APP}/x", headers=HTML),
             "sign-in (?app)": anon.get(f"/auth/login?app={APP}", headers=HTML),
             "error page": anon.get(f"/boom?app={APP}", headers=HTML)}
    for was, r in pages.items():
        assert framed(r.text), (kind, was, r.status_code, r.text[:300])
        bar = header(r.text)
        assert "<span>Example</span>" in bar and "<a " not in bar and "tsbar-menu" not in bar, (kind, was, bar)
        for hidden in ("/spaces", "Spaces", f"{APP}/team", f"{APP}/start", "GatewayLink", "GatewayMenu"):
            assert hidden not in r.text, (kind, was, hidden)
    ok(f"F6 ({kind}): sign-in (absolute next, ?app) and error page — the name only, no back link, no link in the "
       "source")

    # ══ F7: account → TOTP setup → step-up → back stays framed ══════════════════════════════════════════════
    stale = auth.create_user("sven", password=PW)
    cs = client(auth, app, stale)
    auth.store._exec("UPDATE session SET mfa_at=mfa_at-100000, created_at=created_at-100000 WHERE user_id=?",
                     (stale,))
    page = cs.get(f"/auth/account?app={APP}", headers=HTML).text
    link = re.search(r"<a class=btnlink href='([^']*/auth/totp/setup[^']*)'>", page).group(1)
    assert link == f"/auth/totp/setup?app={APP}", link
    r = cs.get(link, headers=HTML)
    assert r.status_code == 303 and "/auth/reauth?next=" in r.headers["location"], (r.status_code, r.headers)
    reauth = cs.get(r.headers["location"], headers=HTML)
    assert reauth.status_code == 200 and framed(reauth.text), ("the step-up page lost the frame", kind)
    csrf = re.search(r"name=_csrf value='([^']*)'", reauth.text).group(1)
    nxt = re.search(r"name=next value='([^']*)'", reauth.text).group(1)
    r = cs.post("/auth/reauth", data={"_csrf": csrf, "next": nxt, "password": PW}, headers=HTML)
    assert r.status_code == 303 and r.headers["location"].endswith(f"/auth/totp/setup?app={APP}"), r.headers
    setup = cs.get(r.headers["location"], headers=HTML).text
    assert framed(setup), "the setup page lost the frame"
    back = re.search(r"name=next value='([^']*)'", setup).group(1)
    assert back == f"/auth/account?app={APP}", back
    csrf = re.search(r"name=_csrf value='([^']*)'", setup).group(1)
    started = cs.post("/auth/totp/setup/start", data={"_csrf": csrf, "next": back}, headers=HTML)
    assert started.status_code == 200 and framed(started.text), "the page with the QR code lost the frame"
    assert f"data-next='/auth/account?app={APP}'" in started.text
    assert framed(cs.get(back, headers=HTML).text)
    ok(f"F7 ({kind}): account → TOTP setup → step-up → setup → back to the account page, framed all the way")

# ══ F8: config_check — home/links on a foreign host, a frame without a name, a bad default ═════════════════════
def refused(**fa):
    try:
        make(**fa)
    except ConfigError as e:
        return str(e)
    return ""


for bad, needle in (({APP: {"name": "E", "home": "https://evil.example/"}}, "['home']"),
                    ({APP: {"name": "E", "home": "//evil.example/"}}, "['home']"),
                    ({APP: {"name": "E", "home": "javascript:alert(1)"}}, "['home']"),
                    ({APP: {"name": "E", "home": "https://team.example.com@evil.example/"}}, "['home']"),
                    ({APP: {"name": "E", "links": [("X", "https://evil.example/")]}}, "app frame"),
                    ({APP: {"name": "E", "links": [("X", "/a'b")]}}, "app frame"),
                    ({APP: {"name": "E", "links": "/spaces"}}, "['links']"),
                    ({APP: {"links": [("Spaces", "/spaces")]}}, "no name"),
                    ({APP: {"name": " ", "home": "/"}}, "no name")):
    msg = refused(forward_apps=bad)
    assert msg and needle in msg, (bad, msg)
msg = refused(forward_frame_default="other.example.com")
assert "forward_frame_default" in msg, msg
msg = refused(forward_frame_default="nowhere.example")
assert "forward_frame_default" in msg, msg
assert make(forward_frame_default=APP.upper())[0]
many = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), base_url=BASE,
                       forward_apps={APP: {"name": "E", "links": [(f"L{i}", f"/l{i}") for i in range(9)]}})
errors, warnings = config_check.check_config(many)
assert not errors and [w for w in warnings if "9 entries" in w], (errors, warnings)
assert not [w for w in warnings if "forward_auth_enabled is False" in w], "a frame alone is read by the library"
off = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), base_url=BASE, topbar_enabled=False,
                      forward_apps={APP: {"name": "E", "home": "/"}})
assert [w for w in config_check.check_config(off)[1] if "topbar_enabled=False" in w]
english = [w for w in warnings if "9 entries" in w]
many.lang = "de"
de = [w for w in config_check.check_config(many)[1] if "['links']" in w and " 9 " in w]
assert de and de[0] != english[0], "no German text"
ok("F8: home/links on a foreign host, // , javascript:, a user part, a quote, links not a list, a frame without a name, "
   "a default without a frame → ConfigError; 9 links and topbar_enabled=False warn (en/de)")

# ══ F9: delegates whose roles overlap an application's allowlist → a warning ═══════════════════════════════════
def delegate_warnings(delegate_roles):
    cfg = TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "c.db"), base_url=BASE, magiclink_enabled=True,
                          available_roles=["example-member", "example-editor", "teamadmin", "editors"],
                          admin_delegates={"teamadmin": {"roles": delegate_roles}},
                          apps={"example": {"account": "svc-example", "name": "Example",
                                            "provisioning": {"roles": ["example-member", "example-editor"],
                                                             "scopes": ["users:read"]}}})
    errors, warnings = config_check.check_config(cfg)
    assert not errors, errors
    return [w for w in warnings if "admin_delegates['teamadmin']" in w and "apps['example']" in w]


hit = delegate_warnings(["example-editor", "editors"])
assert hit and "example-editor" in hit[0] and "'editors'" not in hit[0], hit
assert delegate_warnings(["editors"]) == []
ok("F9: a delegate role managing a role of an application's allowlist warns (names the shared role); disjoint ones "
   "do not")

# ══ F10: the default frame — without any hint, and an unknown ?app falls back to it ═══════════════════════════
auth_d, app_d = make(forward_auth_enabled=True, forward_frame_default=APP,
                     forward_apps={APP: dict(FRAME), "two.example.com": {"name": "Two", "home": "/"}},
                     trusted_redirect_hosts=[APP, "two.example.com"])
anon = client(auth_d, app_d)
page = anon.get("/auth/login", headers=HTML).text
assert framed(page) and "<span>Example</span>" in header(page), header(page)
assert normal(anon.get("/auth/login?app=unknown.example", headers=HTML).text) == normal(page)
two = anon.get("/auth/login?app=two.example.com", headers=HTML).text
assert framed(two) and "<span>Two</span>" in header(two), "a named frame wins over the default"
assert not framed(client(*make()).get("/auth/login", headers=HTML).text), "without a default: the gateway's bar"
ok("F10: forward_frame_default frames every page without a hint; an unknown ?app falls back to it; a named host wins")

# ══ F11: menu — Security and approvals carry app=, approvals number AND word, admin panel only for operators ══
auth_m, app_m = make(forward_auth_enabled=True)
boss = auth_m.create_user("boss", password=PW, is_admin=True)
carl = auth_m.create_user("carl", password=PW)
auth_m._approvals_pending = lambda viewer: 2
bar = header(client(auth_m, app_m, boss).get(f"/auth/account?app={APP}", headers=HTML).text)
assert f"href='/auth/approvals?app={APP}'" in bar and "Approvals (2)" in bar, bar
assert "tsbar-count" in bar and "/auth/admin" in bar, "number with word; the panel for the operator"
bar = header(client(auth_m, app_m, carl).get(f"/auth/account?app={APP}", headers=HTML).text)
assert "/auth/admin" not in bar
auth_m.cfg.lang = "de"
bar = header(client(auth_m, app_m, carl).get(f"/auth/account?app={APP}", headers=HTML).text)
t = auth_m.t
for text in (t("bar.back", name="Example"), t("bar.via", name="Example Gate"), t("bar.security"),
             t("bar.approvals_n", n=2)):
    assert text in bar or text.replace("'", "&#x27;") in bar, text
assert t("bar.security") != "Security", "probe: the German table answers"
ok("F11: Security and approvals keep app=, 'Approvals (2)' as number and word, admin panel for operators only; "
   "German texts")

# ══ F12: anchors on the account page ═══════════════════════════════════════════════════════════════════════════
auth_a, app_a = make(forward_auth_enabled=True, oauth_enabled=True, oauth_resources=[f"https://{APP}/mcp"],
                     forward_apps={APP: {**FRAME, "app_passwords": True}})
page = client(auth_a, app_a, auth_a.create_user("anna", password=PW)).get("/auth/account", headers=HTML).text
for anchor in ("sessions", "totp", "devices", "app-passwords"):
    assert re.search(rf"<h2 id={anchor}>", page), anchor
ok("F12: the account page has the anchors #sessions, #totp, #devices, #app-passwords (passkeys/services when on)")

# ══ F13: topbar_enabled=False → no frame either ════════════════════════════════════════════════════════════════
auth_o, app_o = make(topbar_enabled=False)
page = client(auth_o, app_o, auth_o.create_user("anna", password=PW)).get(f"/auth/account?app={APP}",
                                                                            headers=HTML).text
assert "tsbar" not in page.split("<body>", 1)[1].split("<div class=tsmain>", 1)[0]
ok("F13: topbar_enabled=False — no bar, no frame")

print("app frame OK")
