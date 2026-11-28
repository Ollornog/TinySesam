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

from voraussetzung import braucht, braucht_modul, find_chrome, pflicht_werkzeug  # noqa: E402

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


# ══ B. Server: Ex1, shell on top ═════════════════════════════════════════════════════════════════════════════════
# The stack of deploy/ex1 in one process: the TinySesam server built from deploy/ex1/tinysesam.toml (host names moved
# to example.test, which Chrome resolves to 127.0.0.1), the Go program of clients/go/examples/ex1, and in front a small
# forward-auth proxy that does what the Caddy template does: /.tinysesam/* and the sign-in host to TinySesam, every
# other request on the application's host first to /auth/forward, then — with the Remote-* headers of the answer and
# without the browser's cookies (spec §2.1, duty 4) — to the Go program.
GO = pflicht_werkzeug("go", "example Ex1 (Go) behind the proxy")
EX1 = None
if GO:
    import subprocess

    _proxy_sock = socket.socket()
    _proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _proxy_sock.bind(("127.0.0.1", 0))
    _proxy_sock.listen(128)
    PROXY_PORT = _proxy_sock.getsockname()[1]
    AUTH_HOST, APP_HOST = f"auth.example.test:{PROXY_PORT}", f"app.example.test:{PROXY_PORT}"
    _tmp = tempfile.mkdtemp(prefix="ex1-")
    toml = (ROOT / "deploy" / "ex1" / "tinysesam.toml").read_text(encoding="utf-8")
    toml = (toml.replace("https://auth.example.com", f"http://{AUTH_HOST}").replace("example.com", "example.test")
            .replace('trusted_proxies = ["172.30.0.0/16"]', 'trusted_proxies = ["127.0.0.1/32"]')
            .replace('https_mode = "warn"', 'https_mode = "warn"\ncookie_secure = false\n'
                                            'cookie_domain = ".example.test"'))
    assert "example.com" not in toml and "cookie_domain" in toml, "deploy/ex1/tinysesam.toml changed its shape"
    with open(os.path.join(_tmp, "tinysesam.toml"), "w", encoding="utf-8") as fh:
        fh.write(toml)
    _saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("TINYSESAM_")}
    os.environ.update(TINYSESAM_CONFIG=os.path.join(_tmp, "tinysesam.toml"), TINYSESAM_DB=os.path.join(_tmp, "ex1.db"))
    try:
        from tinysesam import gateway
        ex1_app = gateway.build_app()
    finally:
        for _k in ("TINYSESAM_CONFIG", "TINYSESAM_DB"):
            os.environ.pop(_k, None)
        os.environ.update(_saved)
    ex1_auth = ex1_app.state.auth
    TS_PORT, ts_server = serve(ex1_app)
    _svc = ex1_auth.create_service("svc-ex1")
    _key = ex1_auth.create_api_key(int(_svc), name="ex1", kind="automation")["key"]
    SAM = int(ex1_auth.create_user("sam", password=PW, roles=["ex1-staff"]))
    MIA = int(ex1_auth.create_user("mia", password=PW, roles=["ex1-member"]))

    _bin = os.path.join(_tmp, "ex1-bin")
    _built = subprocess.run([GO, "build", "-o", _bin, "./examples/ex1"], cwd=ROOT / "clients" / "go",
                            capture_output=True, text=True, timeout=900)
    assert _built.returncode == 0, _built.stderr[-2000:]
    _probe = socket.socket()
    _probe.bind(("127.0.0.1", 0))
    GO_PORT = _probe.getsockname()[1]
    _probe.close()
    _go_log = open(os.path.join(_tmp, "ex1.log"), "w", encoding="utf-8")
    go_proc = subprocess.Popen([_bin], env={**os.environ, "TS_AUTH_URL": f"http://{AUTH_HOST}",
                                            "TS_API_URL": f"http://127.0.0.1:{TS_PORT}", "TS_API_KEY": _key,
                                            "TS_LISTEN": f"127.0.0.1:{GO_PORT}"},
                               stdout=_go_log, stderr=subprocess.STDOUT)
    for _ in range(200):
        if go_proc.poll() is not None:
            raise RuntimeError(f"ex1 ended at start (exit {go_proc.returncode})")
        if ex1_auth.app_permissions("ex1"):
            try:
                socket.create_connection(("127.0.0.1", GO_PORT), timeout=1).close()
                break
            except OSError:
                pass  # not listening yet
        time.sleep(0.1)
    else:
        raise RuntimeError("ex1 did not register its permissions or does not listen")
    ex1_auth.grant_permission("ex1-staff", "ex1.members.read", app="ex1", by="test")
    HOP = {"connection", "keep-alive", "transfer-encoding", "content-length", "host", "proxy-connection"}

    async def _upstream(port: int, method: str, target: str, headers: list, body: bytes) -> bytes:
        """One request to a server on loopback, the whole raw answer back (`Connection: close`, read to the end)."""
        r, w = await asyncio.open_connection("127.0.0.1", port)
        head = "".join(f"{k}: {v}\r\n" for k, v in headers)
        w.write(f"{method} {target} HTTP/1.1\r\n{head}Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                .encode("latin-1") + body)
        await w.drain()
        data = await r.read()
        w.close()
        return data

    def _status_and_headers(raw: bytes) -> tuple[int, list]:
        lines = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        return int(lines[0].split(" ", 2)[1]), [tuple(x.strip() for x in z.split(":", 1)) for z in lines[1:] if ":" in z]

    async def _proxy(reader, writer):
        """The proxy, on the bytes: one request per connection, the upstream's answer passed back unchanged."""
        try:
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1").split("\r\n")
            method, target = head[0].split(" ")[:2]
            pairs = [tuple(x.strip() for x in z.split(":", 1)) for z in head[1:] if ":" in z]
            low = {k.lower(): v for k, v in pairs}
            body = await reader.readexactly(int(low.get("content-length") or 0))
            host = low.get("host", "")
            name = host.split(":")[0]
            own = [(k, v) for k, v in pairs if k.lower() not in HOP and not k.lower().startswith(("remote-", "x-forwarded-"))]
            fwd = [("X-Forwarded-Host", host), ("X-Forwarded-Proto", "http"), ("X-Forwarded-For", "127.0.0.1")]
            if name == "auth.example.test" or (name == "app.example.test" and target.startswith("/.tinysesam/")):
                out = await _upstream(TS_PORT, method, target, own + fwd + [("Host", host)], body)
            elif name == "app.example.test":
                check = await _upstream(TS_PORT, "GET", "/auth/forward", [
                    ("Cookie", low.get("cookie", "")), ("Accept", low.get("accept", "")), ("X-Forwarded-Uri", target),
                    ("X-Forwarded-Method", method), *fwd, ("Host", AUTH_HOST)], b"")
                status, answer = _status_and_headers(check)
                if not 200 <= status < 300:
                    out = check
                else:
                    passed = [(k, v) for k, v in answer if k.lower().startswith("remote-")]
                    out = await _upstream(GO_PORT, method, target,
                                          [(k, v) for k, v in own if k.lower() != "cookie"] + passed + [("Host", host)],
                                          body)
            else:
                out = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            writer.write(out)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass  # the browser gave up the connection (a preconnect it never used)
        finally:
            writer.close()

    EX1 = f"http://{APP_HOST}"


async def part_b(p: Page) -> None:
    import json
    root = "document.querySelector('ts-shell').shadowRoot"
    drawn = f"!!document.querySelector('ts-shell')&&!!{root}&&!!{root}.querySelector('.tsbar-btn')"
    console_before, failed_before = len(p.console), len(p.failed)
    for uid, name, want in ((SAM, "sam", "Home,Members,Staff"), (MIA, "mia", "Home")):
        await p.cmd("Network.clearBrowserCookies")
        token, _ = ex1_auth.start_session(uid, "password")
        await p.cmd("Network.setCookie", name=ex1_auth.session_cookie_name, value=token, domain=".example.test",
                    path="/")
        for width, height in SIZES:
            for theme in ("light", "dark"):
                await p.go(EX1 + "/")                       # the origin for localStorage
                await view(p, width, height, theme)
                where = f"Ex1 / {name} {width}px {theme}"
                await p.go(EX1 + "/", drawn)
                await p.frames()
                await clean(p, where, console_before, failed_before)
                assert await p.js("document.querySelector('ts-shell').getAttribute('layout')") == "top", \
                    f"{where}: the layout of apps.ex1 did not arrive"
                head = await p.js(f"{root}.querySelector('header').className")
                assert head == "tsbar tsframe", f"{where}: {head}"
                assert await p.js("document.documentElement.classList.contains('dark')") == (theme == "dark")
                bg = await p.js(f"getComputedStyle({root}.querySelector('header')).backgroundColor")
                assert bg == ("rgb(22, 26, 34)" if theme == "dark" else "rgb(255, 255, 255)"), f"{where}: {bg}"
                sel = ".tsbar-links a" if width > 640 else ".tsbar-mlinks a"
                titles = await p.js(f"[...{root}.querySelectorAll('{sel}')].map(a=>a.textContent).join()")
                assert titles == want, f"{where}: links {titles!r}"
                hrefs = await p.js(f"[...{root}.querySelectorAll('{sel}')].map(a=>a.getAttribute('href')).join()")
                assert all(h.startswith("https://app.example.test/") for h in hrefs.split(",")), hrefs
                back = await p.js(f"{root}.querySelector('a.tsbar-back').getAttribute('aria-label')")
                assert back == "Back to Ex1", f"{where}: {back}"
                box = json.loads(await p.js(f"JSON.stringify({root}.querySelector('header').getBoundingClientRect())"))
                assert box["top"] == 0 and box["left"] == 0 and box["width"] == width and box["height"] < 80, \
                    f"{where}: not a top bar {box}"
                # The menu: opens, the account menu names Security (framed) and sign-out; Escape closes, focus back.
                await p.js(f"{root}.querySelector('.tsbar-btn').click();true")
                assert await p.js(f"!{root}.querySelector('.tsbar-pop').hidden"), f"{where}: the menu does not open"
                security = await p.js(f"[...{root}.querySelectorAll('.tsbar-pop a')].find(a=>a.textContent==="
                                      "'Security').getAttribute('href')")
                assert security == f"http://{AUTH_HOST}/auth/account?app=app.example.test", security
                pop = json.loads(await p.js(f"JSON.stringify({root}.querySelector('.tsbar-pop')"
                                            ".getBoundingClientRect())"))
                assert pop["left"] >= 0 and pop["right"] <= width and pop["bottom"] <= height, f"{where}: {pop}"
                small = await p.js(f"[...{root}.querySelectorAll('.tsbar-btn,.tsbar-item,.tsbar-links a')]"
                                   ".filter(e=>e.offsetHeight&&e.getBoundingClientRect().height<44).length")
                assert small == 0, f"{where}: tap targets under 44 px"
                await shot(p, f"ex1-{name}-{width}-{theme}")
                await p.js(f"{root}.querySelector('.tsbar-btn').focus();true")
                await p.key("Escape")
                assert await p.js(f"{root}.querySelector('.tsbar-pop').hidden"), f"{where}: Escape does not close"
                assert await p.js(f"{root}.activeElement==={root}.querySelector('.tsbar-btn')"), \
                    f"{where}: the focus is not back on the menu button"
    ok("B1 Ex1 (Go, server, shell on top): the component from /.tinysesam/shell.js on the application's host at 375 "
       "and 1280 px, light and dark — the layout of apps.ex1, the frame with \u2039 Ex1, Members (permission) and Staff "
       "(role) for the staff, Home only for a member; the menu with Security framed, on screen, Escape closes it "
       "(focus back); tap targets ≥ 44 px; the Go page's strict CSP, no console error, no broken request")

    # The theme switch of the component, and the routes agree with the links.
    await p.cmd("Emulation.setDeviceMetricsOverride", width=1280, height=900, deviceScaleFactor=1, mobile=False)
    await p.go(EX1 + "/", drawn)
    await p.js(f"{root}.querySelector('.tsbar-btn').click();{root}.querySelector('[data-theme-mode=dark]').click();true")
    assert await p.js("document.documentElement.classList.contains('dark')&&localStorage.getItem('themeMode')==='dark'")
    await p.js("document.querySelector('main h1').click();true")
    assert await p.js(f"{root}.querySelector('.tsbar-pop').hidden"), "a click outside does not close the menu"
    status = await p.js("fetch('/staff').then(r=>r.status)")
    assert status == 403, status
    p.failed = [f for f in p.failed if not f[1].endswith("/staff")]
    # Security leads to TinySesam's account page in Ex1's frame, in the layout of apps.ex1.
    await p.go(f"http://{AUTH_HOST}/auth/account?app=app.example.test", "!!document.querySelector('header.tsframe')")
    assert await p.js("document.querySelector('header.tsframe').className") == "tsbar tsframe"
    await clean(p, "the framed account page", console_before, failed_before)
    ok("B2 the component's theme switch sets `dark` on <html> and keeps it; a click outside closes the menu; the Go "
       "route refuses /staff to a member (403); Security opens TinySesam's account page in Ex1's frame")


# ══ C. The permission matrix of the panel (T-100) ════════════════════════════════════════════════════════════════
# Checked by screenshot only until now: a dangerous permission asks the administrator for a fresh confirmation (the
# panel goes over the reauth page and back), an ordinary one does not; an area administrator sees only the
# applications of the own area and only the roles it manages.
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

MATRIX_APPS = {"docs": {"name": "Documents", "permissions": [
                   {"name": "docs.read", "label": {"en": "Read documents"}},
                   {"name": "docs.delete", "label": {"en": "Delete documents"}, "danger": True}]},
               "wiki": {"name": "Wiki", "permissions": [{"name": "wiki.edit", "label": {"en": "Edit the wiki"}}]}}
mx_auth = TinySesam(TinySesamConfig(
    db_path=os.path.join(tempfile.mkdtemp(), "matrix.db"), lang="en", cookie_secure=False, passkey_enabled=False,
    available_roles=["docs-reader", "docs-editor", "wiki-editor", "area-docs"],
    admin_delegates={"area-docs": {"roles": ["docs-reader", "docs-editor"], "apps": ["docs"]}},
    apps=MATRIX_APPS, admin_require_mfa=False, shell_layout="side"))
from fastapi import FastAPI  # noqa: E402

mx_app = FastAPI()
mx_app.include_router(mx_auth.router())
MX_PORT, mx_server = serve(mx_app)
MX = f"http://127.0.0.1:{MX_PORT}"
ADA = int(mx_auth.create_user("ada", password=PW, is_admin=True))
LEA = int(mx_auth.create_user("lea", password=PW, roles=["area-docs"]))


def _held(app: str, perm: str, role: str) -> bool:
    return role in next(r for r in mx_auth.app_permissions(app) if r["name"] == perm)["roles"]


async def _until_py(cond, why, tries=80):
    for _ in range(tries):
        if cond():
            return
        await asyncio.sleep(0.25)
    raise AssertionError(why)


async def part_c(p: Page) -> None:
    console_before, failed_before = len(p.console), len(p.failed)
    await p.cmd("Emulation.setDeviceMetricsOverride", width=1280, height=900, deviceScaleFactor=1, mobile=False)

    async def matrix(uid: int, age: bool) -> None:
        # Leave the previous account's page first: a request it still sends would go out with the next account's
        # cookies — or with none, between clearing and setting them (a 401 that was the test's own doing).
        await p.go("about:blank")
        await p.cmd("Network.clearBrowserCookies")
        token, _ = mx_auth.start_session(uid, "password")
        if age:                                     # signed in long ago: no fresh confirmation any more
            old = int(time.time()) - 100000
            mx_auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE user_id=?", (old, old, uid))
        await p.cmd("Network.setCookie", name=mx_auth.session_cookie_name, value=token, url=MX)
        await p.go(MX + "/auth/account")           # a new document each time (a same-URL hash change reloads nothing)
        await p.go(MX + "/auth/admin")
        await p.js("location.hash='#perms';true")
        await p.until("!!document.querySelector('table.permgrid')", "permission matrix not built")

    def box(app: str, perm: str, role: str) -> str:
        return f"document.querySelector('input[aria-label=\"{role} · {perm}\"]')"

    async def tick(app: str, perm: str, role: str) -> None:
        """Assign by a click and wait until the panel has drawn the matrix anew from the server (`permsview` after the
        answer) with the box ticked — the server's state, and no request of the panel still on its way."""
        await p.js("document.querySelector('table.permgrid').__old=true;" + f"{box(app, perm, role)}.click();true")
        await p.until(f"!document.querySelector('table.permgrid').__old && {box(app, perm, role)}.checked",
                      f"the matrix was not drawn anew with {role} · {perm} ticked")
        await _until_py(lambda: _held(app, perm, role), f"{role} · {perm} not assigned")

    # 1. The administrator: an ordinary permission is assigned at once, a dangerous one only after the step-up.
    await matrix(ADA, age=True)
    cards = await p.js("[...document.querySelectorAll('table.permgrid')].length")
    assert cards == 2, f"the administrator sees {cards} applications"
    danger = await p.js("document.querySelector('#perm-docs-docs\\\\.delete th').innerText")
    assert "⚠" in danger and "dangerous" in danger.lower(), f"the danger is not said in words: {danger!r}"
    await tick("docs", "docs.read", "docs-reader")
    assert await p.js("location.pathname") == "/auth/admin", "an ordinary permission asked for a step-up"
    await p.js("window.__old=true;" + f"{box('docs', 'docs.delete', 'docs-editor')}.click();true")
    await p.until("window.__old===undefined && location.pathname==='/auth/reauth' && document.readyState==='complete'"
                  " && !!document.querySelector(\"form[action$='/auth/reauth'] [name=password]\")",
                  "a dangerous permission did not ask for a fresh confirmation")
    assert not _held("docs", "docs.delete", "docs-editor"), "assigned without the step-up"
    refused = (403, MX + "/auth/admin/api/permissions/assign")      # the server's step-up answer, expected once
    assert p.failed[failed_before:].count(refused) == 1, p.failed[failed_before:]
    p.failed.remove(refused)
    await clean(p, "the reauth page", console_before, failed_before)
    await shot(p, "matrix-stepup-1280")
    field = "document.querySelector(\"form[action$='/auth/reauth'] [name=password]\")"
    await p.js(f"{field}.value={PW!r};window.__old=true;"
               "document.querySelector(\"form[action$='/auth/reauth'] button\").click();true")
    await p.until("window.__old===undefined && location.pathname==='/auth/admin' && document.readyState==='complete'",
                  "the reauth page did not lead back to the panel")
    await p.js("location.hash='#perms';true")
    await p.until("!!document.querySelector('table.permgrid')", "permission matrix not built after the step-up")
    await tick("docs", "docs.delete", "docs-editor")
    await clean(p, "the panel after the step-up", console_before, failed_before)
    ok("C1 permission matrix, administrator: an ordinary permission is assigned at once; a dangerous one (⚠ and the "
       "word) sends a signed-in-long-ago administrator over the reauth page and back, and only then is assigned")

    # 2. The area administrator: only the own area, only the roles it manages.
    await matrix(LEA, age=False)
    names = await p.js("[...document.querySelectorAll('section.card h2')].map(h=>h.textContent)")
    assert "Documents" in " ".join(names) and "Wiki" not in " ".join(names), f"the area administrator sees {names}"
    heads = await p.js("[...document.querySelector('table.permgrid').querySelectorAll('thead th')]"
                       ".slice(1).map(t=>t.innerText.split('\\n')[0])")
    assert heads == ["docs-editor", "docs-reader"], f"the area administrator sees the roles {heads}"
    await tick("docs", "docs.read", "docs-editor")
    r = await p.js("fetch('/auth/admin/api/permissions/assign',{method:'POST',headers:{'Content-Type':"
                   "'application/json','X-CSRF-Token':(document.cookie.match(/(?:^|; )"
                   f"{mx_auth.csrf_cookie_name}=([^;]+)/)||[])[1]||''}},body:JSON.stringify({{app:'wiki',"
                   "permission:'wiki.edit',role:'wiki-editor',granted:true})}).then(r=>r.status)")
    assert r in (403, 404) and not _held("wiki", "wiki.edit", "wiki-editor"), f"outside the area: {r}"
    p.failed = [f for f in p.failed if not f[1].endswith("/api/permissions/assign")]
    await clean(p, "the area administrator's matrix", console_before, failed_before)
    await shot(p, "matrix-area-1280")
    ok("C2 permission matrix, area administrator: only the application of the own area and only the roles it "
       "manages; assigning inside works, the server refuses an application outside")


async def main() -> None:
    chrome = Chrome(CHROME, ("--host-resolver-rules=MAP *.example.test 127.0.0.1",))
    try:
        async with websockets.connect(chrome.new_tab(), max_size=30_000_000) as ws:
            p = Page(ws)
            await p.start()
            await part_a(p)
            if EX1:
                proxy = await asyncio.start_server(_proxy, sock=_proxy_sock)
                try:
                    await part_b(p)
                finally:
                    proxy.close()
            await part_c(p)
    finally:
        chrome.close()


try:
    asyncio.run(main())
    print("OK test_shell_browser")
finally:
    ex2_server.should_exit = True
    mx_server.should_exit = True
    if EX1:
        go_proc.terminate()
        go_proc.wait(timeout=10)
        _go_log.close()
        ts_server.should_exit = True
        import shutil
        shutil.rmtree(_tmp, ignore_errors=True)
