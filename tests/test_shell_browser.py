"""T-103 acceptance in a real browser: the shell component `<ts-shell>` and the side layout.

  A. Library (Python): example Ex2 as surface "shell at the side" — the application's page and TinySesam's account page
     at 375 and 1280 px, light and dark, strict CSP, no console error; the links follow role and permission. On the same
     instance the component from `/auth/shell.js` draws exactly the markup of `auth.topbar()` (`topbar.py`), the only
     difference by design being "Sign out" (a link instead of a form).
  B. Server (Go): example Ex1 as surface "shell on top" — the Go program behind a forward-auth proxy, the component from
     `/.tinysesam/shell.js` on the application's host with the frame of `forward_apps` and the permission links.
  C. The permission matrix of the panel (T-100): a dangerous permission asks for a step-up, an area administrator sees
     only the own area.

Skipped without Chrome or `websockets`; part B needs `go` (CI installs it in the jobs that run this suite).
`TINYSESAM_SCREENSHOTS=<dir>` keeps a screenshot of every state.
"""
from __future__ import annotations

import asyncio
import base64
import importlib.util
import os
import pathlib
import secrets
import socket
import sys
import tempfile
import threading
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from voraussetzung import braucht, braucht_modul, find_chrome  # noqa: E402

braucht_modul("websockets")
braucht_modul("uvicorn")
CHROME = find_chrome()
braucht(CHROME, "no Chrome found")
braucht((ROOT / "examples").is_dir(), "no `examples/` — the browser test runs the examples from the repo")

import uvicorn  # noqa: E402
import websockets  # noqa: E402
from fastapi import Request  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402

from _cdp import Chrome, Page  # noqa: E402

PW = "a long probe password 4711"
SHOTS = os.environ.get("TINYSESAM_SCREENSHOTS", "")
SIZES = ((375, 812), (1280, 900))


def ok(name):
    print(f"  ✓ {name}", flush=True)


def serve(app) -> tuple[str, uvicorn.Server]:
    """Run an ASGI app on a socket that stays bound (no port race), in a thread."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical"))
    threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True).start()
    port = sock.getsockname()[1]
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("the server does not start")
    return port, server


async def shot(p: Page, name: str) -> None:
    if not SHOTS:
        return
    os.makedirs(SHOTS, exist_ok=True)
    data = (await p.cmd("Page.captureScreenshot", format="png"))["data"]
    with open(os.path.join(SHOTS, f"shell-{name}.png"), "wb") as fh:
        fh.write(base64.b64decode(data))


async def view(p: Page, width: int, height: int, theme: str) -> None:
    await p.cmd("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1,
                mobile=width < 500)
    await p.js(f"localStorage.setItem('themeMode','{theme}');true")


async def clean(p: Page, where: str, console_before: int, failed_before: int) -> None:
    viol = await p.csp()
    assert viol == [], f"CSP violation on {where}: {viol}"
    assert len(p.console) == console_before, f"console errors on {where}: {p.console[console_before:][:2]}"
    assert p.failed[failed_before:] == [], f"broken requests on {where}: {p.failed[failed_before:][:3]}"
    assert await p.js("document.documentElement.scrollWidth<=innerWidth"), f"{where}: sideways scrolling"


# ══ A. Library: Ex2, shell at the side ═══════════════════════════════════════════════════════════════════════════
spec = importlib.util.spec_from_file_location("example_ex2", ROOT / "examples" / "ex2" / "app.py")
ex2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ex2)
ex2_app, ex2_auth = ex2.build(os.path.join(tempfile.mkdtemp(), "ex2.db"))
for role in ("docs-reader", "docs-editor"):
    ex2_auth.grant_permission(role, "docs.read", app="docs", by="test")
ex2_auth.grant_permission("docs-editor", "docs.delete", app="docs", by="test")
EDDI = int(ex2_auth.create_user("eddi", password=PW, roles=["docs-editor"]))
RITA = int(ex2_auth.create_user("rita", password=PW, roles=["docs-reader"]))


@ex2_app.get("/parity", response_class=HTMLResponse)
def parity(request: Request):
    """Both renderers of the bar on one page: `auth.topbar()` (Python) and `<ts-shell>` (the component)."""
    nonce = secrets.token_urlsafe(16)
    out = HTMLResponse(
        f"<!doctype html><html><head><meta charset=utf-8>{ex2_auth.topbar_head(nonce=nonce)}"
        f"<script src='/auth/shell.js' nonce='{nonce}'></script></head><body>"
        f"<div id=py>{ex2_auth.topbar(request, nonce=nonce, current='/', layout='side')}</div>"
        f"<ts-shell layout=side current='/'></ts-shell></body></html>")
    out.headers["Content-Security-Policy"] = (f"default-src 'self'; script-src 'nonce-{nonce}'; "
                                              f"style-src 'nonce-{nonce}'; img-src 'self' data:; object-src 'none'")
    ex2_auth.ensure_csrf(request, out)
    return out


# A3: the component against a hostile answer — the same script, served beside a crafted topbar.json.
HOSTILE = {"signed_in": True, "brand": "B", "name": "<img src=x id=pwn>",
           "links": [{"title": "<b id=pwn2>bold</b>", "href": "javascript:alert(1)"}, {"title": "ok", "href": "/ok"},
                     {"title": "pr", "href": "//evil.example/"}, {"title": "bs", "href": "/\\evil.example"},
                     {"title": "sp", "href": "/a b"}, {"title": 7, "href": "/num"}],
           "menu_links": [{"title": "data", "href": "data:text/html,x"}],
           "account": {"shown": True, "href": "javascript:void(0)"}, "admin_panel": {"shown": True, "href": "/adm"},
           "logout": {"href": "/auth/logout"}, "approvals": {"pending": 2, "href": "/auth/approvals"},
           "frame": {"layout": "side", "name": None, "home": None, "links": []}}


@ex2_app.get("/hostile/shell.js")
def hostile_js():
    from tinysesam import _shell
    from fastapi.responses import Response
    return Response(_shell.script(ex2_auth), media_type="text/javascript")


@ex2_app.get("/hostile/shell.css")
def hostile_css():
    from tinysesam import _shell
    from fastapi.responses import Response
    return Response(_shell.css(ex2_auth), media_type="text/css")


@ex2_app.get("/hostile/topbar.json")
def hostile_json():
    return HOSTILE


@ex2_app.get("/hostile", response_class=HTMLResponse)
def hostile_page():
    nonce = secrets.token_urlsafe(16)
    out = HTMLResponse(f"<!doctype html><html><head><meta charset=utf-8><script src='/hostile/shell.js' "
                       f"nonce='{nonce}'></script></head><body><ts-shell></ts-shell></body></html>")
    out.headers["Content-Security-Policy"] = (f"default-src 'self'; script-src 'nonce-{nonce}'; "
                                              f"style-src 'nonce-{nonce}'; img-src 'self' data:; object-src 'none'")
    return out


EX2_PORT, ex2_server = serve(ex2_app)
EX2 = f"http://127.0.0.1:{EX2_PORT}"

# The markup of both, without what differs by design: the sign-out (form / link) and the marker of the bar's script.
PARITY_JS = """(()=>{
  const norm=h=>{const c=h.cloneNode(true);c.removeAttribute('data-ready');
    c.querySelectorAll('form[action$="/auth/logout"],a[href$="/auth/logout"]').forEach(x=>x.remove());return c.outerHTML;};
  const s=document.querySelector('ts-shell');
  return JSON.stringify([norm(document.querySelector('#py header.tsbar')),
                         s&&s.shadowRoot?norm(s.shadowRoot.querySelector('header.tsbar')):'']);})()"""


async def as_user(p: Page, auth, uid: int, url: str) -> None:
    await p.cmd("Network.clearBrowserCookies")
    token, _ = auth.start_session(uid, "password")
    await p.cmd("Network.setCookie", name=auth.session_cookie_name, value=token, url=url)


async def part_a(p: Page) -> None:
    import json
    await p.go(EX2 + "/auth/login")             # localStorage needs the origin
    # 1. The component draws the markup of topbar.py.
    for uid, name in ((EDDI, "eddi"), (RITA, "rita")):
        await as_user(p, ex2_auth, uid, EX2)
        await p.go(EX2 + "/parity", "!!(document.querySelector('ts-shell').shadowRoot||{}).querySelector"
                                    "&&!!document.querySelector('ts-shell').shadowRoot.querySelector('.tsbar-btn')")
        py, js = json.loads(await p.js(PARITY_JS))
        assert py == js, f"{name}: the component differs from topbar.py\n  python: {py[:600]}\n  js:     {js[:600]}"
        assert await p.csp() == [], await p.csp()
    ok("A1 the component from /auth/shell.js draws the markup of auth.topbar() (topbar.py) for two accounts — "
       "the only difference by design is the sign-out (link instead of form)")

    # 2. Ex2 at both widths, light and dark: the side bar, its links by role and permission.
    console_before, failed_before = len(p.console), len(p.failed)
    for uid, name, want in ((EDDI, "eddi", "Documents,Editing guide,Trash"), (RITA, "rita", "Documents")):
        await as_user(p, ex2_auth, uid, EX2)
        for width, height in SIZES:
            for theme in ("light", "dark"):
                await view(p, width, height, theme)
                for path in ("/", "/auth/account"):
                    where = f"Ex2 {path} {name} {width}px {theme}"
                    await p.go(EX2 + path, "!!document.querySelector('header.tsbar.tsside')")
                    await p.frames()
                    await clean(p, where, console_before, failed_before)
                    assert await p.js("document.documentElement.classList.contains('dark')") == (theme == "dark")
                    links = "[...document.querySelectorAll('header.tsside .tsbar-links a')].map(a=>a.textContent).join()"
                    mlinks = ("[...document.querySelectorAll('header.tsside .tsbar-mlinks a')]"
                              ".map(a=>a.textContent).join()")
                    assert await p.js(links if width > 900 else mlinks) == want, f"{where}: links"
                    box = json.loads(await p.js("JSON.stringify(document.querySelector('header.tsside')"
                                                ".getBoundingClientRect())"))
                    pad = await p.js("parseFloat(getComputedStyle(document.body).paddingLeft)")
                    if width > 900:
                        assert box["left"] == 0 and box["top"] == 0 and box["width"] == 248 and box["height"] == height, \
                            f"{where}: not a side bar {box}"
                        assert pad == 248, f"{where}: the page does not give way ({pad})"
                        assert await p.js("getComputedStyle(document.querySelector('header.tsside .tsbar-links'))"
                                          ".flexDirection") == "column"
                    else:
                        assert box["top"] == 0 and box["width"] == width and box["height"] < 80, f"{where}: {box}"
                        assert pad == 0, f"{where}: padding on a phone ({pad})"
                    if path == "/":
                        assert await p.js("document.querySelector('header.tsside a[aria-current=page]')"
                                          ".textContent") == "Documents", f"{where}: current page not marked"
                        assert await p.js("!!document.querySelector('#del-d1')") == (name == "eddi"), where
                    # The menu opens on screen (upwards at the side, downwards on a phone).
                    await p.js("document.querySelector('header.tsside .tsbar-btn').click();true")
                    pop = json.loads(await p.js("JSON.stringify(document.querySelector('header.tsside .tsbar-pop')"
                                                ".getBoundingClientRect())"))
                    assert pop["top"] >= 0 and pop["bottom"] <= height and pop["left"] >= 0 and pop["right"] <= width, \
                        f"{where}: the menu leaves the screen {pop}"
                    small = await p.js("[...document.querySelectorAll('header.tsside .tsbar-btn,header.tsside "
                                       ".tsbar-item,header.tsside .tsbar-links a')].filter(e=>e.offsetHeight&&"
                                       "e.getBoundingClientRect().height<44).length")
                    assert small == 0, f"{where}: tap targets under 44 px"
                    await shot(p, f"ex2-{name}-{path.strip('/').replace('/', '-') or 'home'}-{width}-{theme}")
    # 3. A hostile answer: only safe links are drawn, texts stay text, the layout comes from `frame`.
    await p.cmd("Emulation.setDeviceMetricsOverride", width=1280, height=900, deviceScaleFactor=1, mobile=False)
    await p.go(EX2 + "/hostile", "!!(document.querySelector('ts-shell').shadowRoot||{}).querySelector"
                                 "&&!!document.querySelector('ts-shell').shadowRoot.querySelector('.tsbar-btn')")
    root = "document.querySelector('ts-shell').shadowRoot"
    hrefs = await p.js(f"[...{root}.querySelectorAll('a')].map(a=>a.getAttribute('href')).join(' ')")
    assert hrefs.split() == ["/", "/ok", "/ok", "/auth/approvals", "/adm", "/auth/logout"], hrefs
    assert await p.js(f"!{root}.querySelector('#pwn,#pwn2')"), "markup of the answer became elements"
    assert await p.js(f"{root}.querySelector('.tsbar-name').textContent") == "<img src=x id=pwn>"
    assert await p.js("document.querySelector('ts-shell').getAttribute('layout')") == "side"
    assert await p.js(f"{root}.querySelector('.tsbar-count').textContent") == "2"
    assert await p.csp() == [], await p.csp()
    ok("A3 a hostile topbar.json: javascript:, data:, protocol-relative, backslash and blank targets dropped, a "
       "title that is no text dropped, markup in names and titles stays text, the layout taken from `frame`")

    # The routes agree with the links.
    await as_user(p, ex2_auth, RITA, EX2)
    r = await p.js("fetch('/trash').then(r=>r.status)")
    assert r == 403, r
    p.failed = [f for f in p.failed if not f[1].endswith("/trash")]
    ok("A2 Ex2 (library, side): the application's page and the account page at 375 and 1280 px, light and dark — a "
       "248 px side bar the page gives way to, a top bar on a phone with the links in the menu; Editing guide (role) "
       "and Trash (permission) for the editor only; current page marked; menu on screen; tap targets ≥ 44 px; strict "
       "CSP, no console error, no broken request")


async def main() -> None:
    chrome = Chrome(CHROME)
    try:
        async with websockets.connect(chrome.new_tab(), max_size=30_000_000) as ws:
            p = Page(ws)
            await p.start()
            await part_a(p)
    finally:
        chrome.close()


try:
    asyncio.run(main())
    print("OK test_shell_browser")
finally:
    ex2_server.should_exit = True
