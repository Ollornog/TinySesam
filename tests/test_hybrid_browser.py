"""T-104 acceptance in a real browser: example Ex3, surface "hybrid" — a Node application behind the TinySesam server.

The stack of deploy/ex3 in one process: the server built from deploy/ex3/tinysesam.toml (host names moved to
example.test, which Chrome resolves to 127.0.0.1; the identity provider stubbed in the server's process), the Node
program of clients/js/examples/ex3, and in front the forward-auth proxy of `_browser_stack`. Mixed accounts: a local
one signs in through the pages, a provider's one (its group imported as a role) and an administrator come by cookie.

  H1 the local account opens the application, signs in on "Sign in to Documents" (with the application's icon) and
     lands back on the documents; the application's own navigation, one link "Account" to TinySesam's area.
  H2 the area at 375 and 1280 px, light and dark: the frame of app.example.test (‹ Documents, the icon), the tiles,
     the way back to the application; a tile opens the account page in the same frame. Strict CSP everywhere, no
     console error, no broken request, no sideways scrolling, tap targets ≥ 44 px.
  H3 the provider's account (team-docs) reads the documents too and finds its area; the administrator's area has the
     panel; an account without the permission is refused by the application (403).

Skipped without Chrome, `websockets` or `uvicorn`; needs `node` ≥ 22.18 (CI installs it in the jobs that run this suite).
`TINYSESAM_SCREENSHOTS=<dir>` keeps a screenshot of every state.
"""
from __future__ import annotations

import asyncio
import os
import pathlib
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlparse

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from voraussetzung import braucht, braucht_modul, find_chrome, pflicht_werkzeug  # noqa: E402

braucht_modul("websockets")
braucht_modul("uvicorn")
CHROME = find_chrome()
braucht(CHROME, "no Chrome found")

import websockets  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from _browser_stack import SIZES, ForwardProxy, clean, free_port, serve, shot, view  # noqa: E402
from _cdp import Chrome, Page  # noqa: E402

PW = "a long probe password 4711"
NODE = pflicht_werkzeug("node", "example Ex3 (Node) behind the proxy")


def ok(name):
    print(f"  ✓ {name}", flush=True)


if NODE:
    _version = subprocess.run([NODE, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
    _major, _minor = (int(x) for x in _version.lstrip("v").split(".")[:2])
    assert (_major, _minor) >= (22, 18), f"Ex3 needs Node >= 22.18 (type stripping), found {_version}"

    proxy = ForwardProxy(0, 0, auth_name="auth.example.test", app_name="app.example.test")
    AUTH, EX3 = f"http://auth.example.test:{proxy.port}", f"http://app.example.test:{proxy.port}"
    _tmp = tempfile.mkdtemp(prefix="ex3-")
    toml = (ROOT / "deploy" / "ex3" / "tinysesam.toml").read_text(encoding="utf-8")
    toml = (toml.replace("https://auth.example.com", AUTH).replace("example.com", "example.test")
            .replace('trusted_proxies = ["172.30.0.0/16"]', 'trusted_proxies = ["127.0.0.1/32"]')
            .replace('https_mode = "warn"', 'https_mode = "warn"\ncookie_secure = false\n'
                                            'cookie_domain = ".example.test"'))
    assert "example.com" not in toml and "cookie_domain" in toml, "deploy/ex3/tinysesam.toml changed its shape"
    with open(os.path.join(_tmp, "tinysesam.toml"), "w", encoding="utf-8") as fh:
        fh.write(toml)
    _saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith(("TINYSESAM_", "EX3_"))}
    os.environ.update(TINYSESAM_CONFIG=os.path.join(_tmp, "tinysesam.toml"), TINYSESAM_DB=os.path.join(_tmp, "ex3.db"),
                      EX3_OIDC_CLIENT_SECRET="probe-secret")
    try:
        from tinysesam import gateway
        ex3_app = gateway.build_app()
    finally:
        for _k in ("TINYSESAM_CONFIG", "TINYSESAM_DB", "EX3_OIDC_CLIENT_SECRET"):
            os.environ.pop(_k, None)
        os.environ.update(_saved)
    auth = ex3_app.state.auth
    ICON = auth.cfg.apps["docs"]["icon"]
    TS_PORT, ts_server = serve(ex3_app)

    # The provider, stubbed in the server's process (as in tests/test_example_ex3.py): Kim brings the group team-docs.
    class _Claims(dict):
        def validate(self, *a, **k):
            pass

    from tinysesam.oidc import OIDCClient
    _idp = "https://idp.example.test"
    auth.oidc._meta = {"issuer": _idp, "authorization_endpoint": _idp + "/authorize", "token_endpoint": _idp + "/token",
                       "userinfo_endpoint": _idp + "/userinfo", "jwks_uri": _idp + "/jwks"}
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({"sub": "kim-1", "preferred_username": "kim", "email": "kim@example.test", "email_verified": True,
                 "groups": ["team-docs"], "nonce": nonce}), {"access_token": "at", "refresh_token": "rt-1"})
    auth.oidc.userinfo = lambda at, expected_sub="": OIDCClient.check_userinfo({}, expected_sub)
    _kim = TestClient(ex3_app, base_url=AUTH, follow_redirects=False)
    _state = parse_qs(urlparse(_kim.get("/auth/oidc/start").headers["location"]).query)["state"][0]
    assert _kim.get(f"/auth/oidc/callback?code=x&state={_state}").status_code == 303
    KIM_TOKEN = _kim.cookies.get(auth.session_cookie_name)
    assert KIM_TOKEN and auth.user_roles(auth.store.get_user_by_name("kim")) == ["team-docs"]
    auth.create_user("lou", password=PW, roles=["docs-local"])     # signs in through the pages (H1)
    ADA = int(auth.create_user("ada", password=PW, is_admin=True))
    NIA = int(auth.create_user("nia", password=PW))
    for _role in ("team-docs", "docs-local"):
        auth.grant_permission(_role, "docs.read", app="docs", by="test")

    APP_PORT = free_port()
    _node_log = open(os.path.join(_tmp, "ex3.log"), "w", encoding="utf-8")
    node_proc = subprocess.Popen([NODE, "examples/ex3/main.ts"], cwd=ROOT / "clients" / "js",
                                 env={**os.environ, "TS_AUTH_URL": AUTH, "TS_LISTEN": f"127.0.0.1:{APP_PORT}"},
                                 stdout=_node_log, stderr=subprocess.STDOUT)
    import socket
    for _ in range(200):
        if node_proc.poll() is not None:
            raise RuntimeError(f"ex3 ended at start (exit {node_proc.returncode})")
        try:
            socket.create_connection(("127.0.0.1", APP_PORT), timeout=1).close()
            break
        except OSError:
            time.sleep(0.1)       # not listening yet
    else:
        raise RuntimeError("ex3 does not listen")
    proxy.ts_port, proxy.app_port = TS_PORT, APP_PORT

DOCS = "!!document.getElementById('doc-d1')"
AREA = "!!document.querySelector('.tiles .tile')"


async def leave(p: Page) -> None:
    """Off every page of the stack before cookies change: no request of the old page races the new account."""
    await p.go("about:blank")


async def as_cookie(p: Page, token: str) -> None:
    await leave(p)
    await p.cmd("Network.clearBrowserCookies")
    await p.cmd("Network.setCookie", name=auth.session_cookie_name, value=token, domain=".example.test", path="/")


async def to_area(p: Page) -> None:
    """From the application's page through its own link "Account" into TinySesam's area."""
    href = await p.js("document.querySelector('nav.nav a[href*=\"/auth/area\"]').href")
    assert href == f"{AUTH}/auth/area?app=docs", href
    await p.go(href, AREA)


async def part_h(p: Page) -> None:
    import json
    console_before, failed_before = len(p.console), len(p.failed)

    # H1 ─ the local account signs in through the pages.
    await leave(p)
    await p.cmd("Network.clearBrowserCookies")
    await p.go(EX3 + "/", "!!document.querySelector('input[name=username]')")
    assert (await p.js("location.href")).startswith(f"{AUTH}/auth/login"), await p.js("location.href")
    assert await p.js("document.querySelector('h1').textContent") == "Sign in to Documents"
    assert await p.js(f"document.querySelector('img.app-icon').getAttribute('src')==={json.dumps(ICON)}"
                      "&&document.querySelector('img.app-icon').naturalWidth>0"), "the sign-in page lacks the icon"
    await p.js(f"document.querySelector('input[name=username]').value='lou';"
               f"document.querySelector('input[name=password]').value={json.dumps(PW)};"
               "window.__old=true;document.querySelector('input[name=password]').form.requestSubmit();true")
    await p.until(f"window.__old===undefined&&document.readyState==='complete'&&location.origin==={json.dumps(EX3)}"
                  f"&&{DOCS}", "the sign-in did not lead back to the documents")
    nav = await p.js("[...document.querySelectorAll('nav.nav a')].map(a=>a.textContent).join()")
    assert nav == "Documents,About,Account", nav
    assert await p.js("document.getElementById('who').textContent") == "Signed in as lou."
    await clean(p, "Ex3 after the sign-in", console_before, failed_before)
    ok("H1 the local account opens Ex3, signs in on \"Sign in to Documents\" with the application's icon and lands on "
       "the documents; the application's own navigation: Documents, About, Account")

    # H2 ─ the area at both sizes, light and dark.
    for width, height in SIZES:
        for theme in ("light", "dark"):
            where = f"Ex3 / lou {width}px {theme}"
            await p.go(EX3 + "/about")
            await view(p, width, height, theme)
            await p.go(EX3 + "/", DOCS)
            assert await p.js("document.documentElement.classList.contains('dark')") == (theme == "dark"), where
            bg = await p.js("getComputedStyle(document.querySelector('nav.nav')).backgroundColor")
            assert bg == ("rgb(22, 26, 34)" if theme == "dark" else "rgb(255, 255, 255)"), f"{where}: tokens {bg}"
            await clean(p, f"{where}: the application", console_before, failed_before)
            await to_area(p)
            await view(p, width, height, theme)
            await p.go(f"{AUTH}/auth/area?app=docs", AREA)
            assert await p.js("document.documentElement.classList.contains('dark')") == (theme == "dark"), where
            assert await p.js("document.querySelector('header').className") == "tsbar tsframe", f"{where}: no frame"
            back = await p.js("document.querySelector('a.tsbar-back').getAttribute('aria-label')")
            assert back == "Back to Documents", f"{where}: {back}"
            assert await p.js("[...document.querySelectorAll('img')].filter(i=>i.getAttribute('src')==="
                              f"{json.dumps(ICON)}).every(i=>i.naturalWidth>0)&&document.querySelectorAll("
                              f"'img.app-icon').length===1"), f"{where}: the icon"
            assert await p.js("document.querySelector('.area-app span').textContent") == "Documents"
            tiles = await p.js("[...document.querySelectorAll('.tile')].map(t=>t.dataset.tile).join()")
            assert tiles == "account,security,sessions", f"{where}: tiles {tiles}"
            way = await p.js("document.querySelector('.area-back a').getAttribute('href')")
            assert way == "https://app.example.test/", f"{where}: the way back {way}"
            small = await p.js("[...document.querySelectorAll('.tile,.area-back a,.tsbar-btn,.tsbar-item,.tsbar-links a')]"
                               ".filter(e=>e.offsetHeight&&e.getBoundingClientRect().height<44).length")
            assert small == 0, f"{where}: tap targets under 44 px"
            await clean(p, f"{where}: the area", console_before, failed_before)
            await shot(p, f"hybrid-area-{width}-{theme}")
    ok("H2 the area at 375 and 1280 px, light and dark: the frame of app.example.test (‹ Documents), the application's "
       "icon and name, the tiles account, security, sessions, the way back to the application; the application's "
       "page in TinySesam's tokens; strict CSP, no console error, no broken request, tap targets ≥ 44 px")

    href = await p.js("document.querySelector('.tile[data-tile=sessions]').getAttribute('href')")
    assert href == f"{AUTH}/auth/account?app=app.example.test#sessions", href
    await p.go(href, "!!document.querySelector('header.tsframe')")
    assert await p.js("location.pathname") == "/auth/account"
    await clean(p, "the account page from the area", console_before, failed_before)
    ok("H2 a tile opens TinySesam's account page in the application's frame")

    # H3 ─ the provider's account, the administrator, an account without the permission.
    await as_cookie(p, KIM_TOKEN)
    await p.go(EX3 + "/", DOCS)
    assert await p.js("document.getElementById('who').textContent") == "Signed in as kim."
    await to_area(p)
    assert await p.js("document.querySelector('.tile[data-tile=account] span').textContent") == "kim"
    await clean(p, "the provider's account", console_before, failed_before)
    await as_cookie(p, auth.start_session(ADA, "password")[0])
    await p.go(f"{AUTH}/auth/area?app=docs", AREA)
    assert await p.js("[...document.querySelectorAll('.tile')].map(t=>t.dataset.tile).pop()") == "admin"
    await clean(p, "the administrator's area", console_before, failed_before)
    await as_cookie(p, auth.start_session(NIA, "password")[0])
    await p.go(EX3 + "/", "!!document.getElementById('denied')")
    p.failed = [f for f in p.failed if not (f[0] == 403 and f[1] == EX3 + "/")]
    await clean(p, "an account without docs.read", console_before, failed_before)
    ok("H3 mixed: the provider's account (team-docs) reads the documents and finds its area; the administrator's area "
       "holds the panel; an account without docs.read is refused by the application")


async def main() -> None:
    chrome = Chrome(CHROME, ("--host-resolver-rules=MAP *.example.test 127.0.0.1",))
    try:
        async with websockets.connect(chrome.new_tab(), max_size=30_000_000) as ws:
            p = Page(ws)
            await p.start()
            await proxy.start()
            try:
                await part_h(p)
            finally:
                proxy.close()
    finally:
        chrome.close()


if NODE:
    try:
        asyncio.run(main())
        print("OK test_hybrid_browser")
    finally:
        node_proc.terminate()
        node_proc.wait(timeout=10)
        _node_log.close()
        ts_server.should_exit = True
        import shutil
        shutil.rmtree(_tmp, ignore_errors=True)
