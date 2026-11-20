"""Check the pages in a REAL browser — design and behaviour, not just HTML strings.

Starts the showcase with uvicorn, drives headless Chrome over the DevTools protocol and measures
what the user sees: console errors, broken requests, widths, language switching, light/dark down to
the preview iframes, the login and the error handling of empty forms.

Skipped when Chrome or `websockets` are missing (`run_all.py` knows about that).
So no developer setup breaks, but CI runs it.
"""
import asyncio
import json
import shutil
import socket
import subprocess
import os
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pathlib  # noqa: E402
from voraussetzung import braucht, braucht_modul  # noqa: E402

# Three prerequisites, all three declared by THIS suite — not a guessing game for the runner.
# It used to piece this together from stderr and could not tell „the test is missing something" from
# „the library crashes".
braucht_modul("websockets")
braucht_modul("uvicorn")

import websockets            # noqa: E402
import uvicorn               # noqa: E402

# `browser-actions/setup-chrome` installs the binary as `chrome`, Debian as `chromium`.
CHROME = next((b for b in ("google-chrome", "chrome", "chromium", "chromium-browser")
               if shutil.which(b)), None)
braucht(CHROME, "no Chrome found")
# The showcase lives in the repo, not in the sdist — skip there instead of going red.
braucht((pathlib.Path(__file__).resolve().parent.parent / "examples").is_dir(),
        "no `examples/` — the browser test runs the showcase from the repo")
braucht((pathlib.Path(__file__).resolve().parent.parent / "web").is_dir(),
        "no `web/` — the showcase renders the pages of the website generator")


def _server_socket():
    """Open a listening socket for the test server — and **keep it bound**.

    The obvious version (bind, close, remember the number, start uvicorn with it) has a
    window: between closing and binding again another process can take the same port.
    On a runner with parallel jobs that is no thought experiment, and the test then goes red
    rarely and inexplicably. uvicorn accepts ready-made sockets (`run(sockets=…)`),
    so we never give this one up again — that way the window does not exist.

    Chrome solves the same problem its own way: `--remote-debugging-pplace=0` and the actual
    number from `DevToolsActivePort` (see `_cdp_port`).
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(128)
    return s


_app_sock = _server_socket()
APP_PORT = _app_sock.getsockname()[1]
BASE = f"http://127.0.0.1:{APP_PORT}"

# Own DB so that a running demo showcase does not interfere
_db = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["TINYSESAM_SHOWCASE_DB"] = _db
import examples.showcase as showcase   # noqa: E402

_server = uvicorn.Server(uvicorn.Config(showcase.app, log_level="critical"))
# Pass the already bound socket, not host/port — otherwise uvicorn binds anew and the
# gap from above would be back (even as "Address already in use").
threading.Thread(target=lambda: _server.run(sockets=[_app_sock]), daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(f"{BASE}/demo", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("Showcase does not start")

# T-33: a second, small app for the sign-in alternatives — cross-device sign-in and the admin's
# sign-in link need switches the showcase (and the website built from the same config) does not
# carry. Real CSRF, strict CSP, its own cookie prefix: both servers live on 127.0.0.1, and cookies
# do not tell ports apart — without the prefix this app's sign-in would replace the showcase's.
from fastapi import FastAPI as _FastAPI          # noqa: E402
from tinysesam import TinySesam as _TinySesam, TinySesamConfig as _TinySesamConfig   # noqa: E402

_t33_sock = _server_socket()
T33 = f"http://127.0.0.1:{_t33_sock.getsockname()[1]}"
_t33_db = os.path.join(tempfile.mkdtemp(), "t33.db")
t33 = _TinySesam(_TinySesamConfig(
    db_path=_t33_db, cookie_secure=False, cookie_prefix="tst33_", passkey_enabled=False, lang="en",
    magiclink_enabled=True, magiclink_self_request=False, qr_login_enabled=True, base_url=T33))
t33.set_security("password_min_length_single_factor", 8)
t33.ensure_admin("boss", "boss-pw-12345")
t33.create_user("carol", password="carol-pw-12345")
_t33_app = _FastAPI()
_t33_app.include_router(t33.router())


@_t33_app.get("/", include_in_schema=False)
def _t33_home():
    from fastapi.responses import HTMLResponse
    return HTMLResponse("<!doctype html><link rel=icon href=\"data:,\"><title>t33</title><p>home</p>")


_t33_server = uvicorn.Server(uvicorn.Config(_t33_app, log_level="critical"))
threading.Thread(target=lambda: _t33_server.run(sockets=[_t33_sock]), daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(f"{T33}/auth/login", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("T-33 app does not start")

# T-34: a third app for the setup pass after a sign-in link — it needs a chain, which the other two do
# not carry. Own cookie prefix for the same reason as above.
_t34_sock = _server_socket()
T34 = f"http://127.0.0.1:{_t34_sock.getsockname()[1]}"
_t34_db = os.path.join(tempfile.mkdtemp(), "t34.db")
t34 = _TinySesam(_TinySesamConfig(
    db_path=_t34_db, cookie_secure=False, cookie_prefix="tst34_", passkey_enabled=False, lang="en",
    magiclink_enabled=True, magiclink_self_request=False, magiclink_first_login_only=True, base_url=T34,
    login_chain=["password", "totp"]))
t34.set_security("password_min_length_single_factor", 8)
_t34_app = _FastAPI()
_t34_app.include_router(t34.router())


@_t34_app.get("/", include_in_schema=False)
def _t34_home():
    from fastapi.responses import HTMLResponse
    return HTMLResponse("<!doctype html><link rel=icon href=\"data:,\"><title>t34</title><p>home</p>")


_t34_server = uvicorn.Server(uvicorn.Config(_t34_app, log_level="critical"))
threading.Thread(target=lambda: _t34_server.run(sockets=[_t34_sock]), daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(f"{T34}/auth/login", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("T-34 app does not start")

# T-36: a fourth app with the OAuth authorization server — consent page and device list in a real browser.
# The "program" is played by a small loopback listener that only records the callback.
_t36_sock = _server_socket()
# `localhost`, not 127.0.0.1: cookies do not tell ports apart, and a gateway keeps the cookie prefix `tinysesam_`
# (forward auth) — on its own host name it shares no cookie with the other apps of this test.
T36 = f"http://localhost:{_t36_sock.getsockname()[1]}"
_t36_db = os.path.join(tempfile.mkdtemp(), "t36.db")
t36 = _TinySesam(_TinySesamConfig(
    db_path=_t36_db, cookie_secure=False, passkey_enabled=False, lang="en", base_url=T36,
    forward_auth_enabled=True, oauth_enabled=True, oauth_resources=["http://127.0.0.1:9/mcp"]))
t36.set_security("password_min_length_single_factor", 8)
_t36_app = _FastAPI()
_t36_app.include_router(t36.router())
_t36_server = uvicorn.Server(uvicorn.Config(_t36_app, log_level="critical"))
threading.Thread(target=lambda: _t36_server.run(sockets=[_t36_sock]), daemon=True).start()
_t36_cb_seen: list = []


class _T36Callback(__import__("http.server").server.BaseHTTPRequestHandler):
    def do_GET(self):
        _t36_cb_seen.append(self.path)
        body = b"<!doctype html><link rel=icon href='data:,'><title>cb</title><p id=cb>callback received</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


_t36_cb = __import__("http.server").server.ThreadingHTTPServer(("127.0.0.1", 0), _T36Callback)
T36_CB = f"http://127.0.0.1:{_t36_cb.server_address[1]}/callback"
threading.Thread(target=_t36_cb.serve_forever, daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(f"{T36}/auth/login", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("T-36 app does not start")

_profile = tempfile.mkdtemp()

# Do NOT send Chrome's output to DEVNULL: if it dies at startup, the error message used to
# be gone and the test only reported "Chrome does not respond" — without a reason.
# Into a file (not PIPE): a full pipe buffer would block Chrome.
_chrome_log = tempfile.NamedTemporaryFile(prefix="chrome-", suffix=".log", delete=False)
_chrome = subprocess.Popen(
    # --disable-dev-shm-usage: CI containers have a tiny /dev/shm, otherwise the renderer dies.
    [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
     "--window-size=1280,900", f"--user-data-dir={_profile}",
     "--remote-debugging-port=0", "about:blank"],
    stdout=_chrome_log, stderr=subprocess.STDOUT)

# On a cold CI runner the first Chrome start regularly takes longer than
# the earlier 10 s — hence the more generous cap. The test only waits while
# Chrome is actually starting: if the process is dead, it aborts immediately.
CHROME_START_TIMEOUT = float(os.environ.get("CHROME_START_TIMEOUT", "30"))


def _chrome_output():
    try:
        _chrome_log.flush()
        with open(_chrome_log.name, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()[-2000:]
    except OSError:
        return "(no output)"


def _cdp_port():
    """Chrome picks the port itself and writes it into the profile.

    A port reserved in advance is a race: between closing the probe socket
    and starting Chrome another process can claim it. On a CI runner with
    parallel jobs that is no thought experiment.
    """
    port_file = os.path.join(_profile, "DevToolsActivePort")
    deadline = time.time() + CHROME_START_TIMEOUT
    while time.time() < deadline:
        if _chrome.poll() is not None:
            raise RuntimeError(
                f"Chrome died at startup (exit {_chrome.returncode}).\n"
                f"--- Chrome output ---\n{_chrome_output()}")
        try:
            with open(port_file, encoding="utf-8", errors="replace") as fh:
                first = fh.readline().strip()
            if first.isdigit():
                return int(first)
        except OSError:
            pass  # Port file not there yet — Chrome is still starting
        time.sleep(0.1)
    raise RuntimeError(
        f"Chrome wrote no DevTools port (after {CHROME_START_TIMEOUT:.0f}s).\n"
        f"--- Chrome output ---\n{_chrome_output()}")


def _ws_url():
    port = _cdp_port()
    deadline = time.time() + CHROME_START_TIMEOUT
    while time.time() < deadline:
        if _chrome.poll() is not None:
            raise RuntimeError(
                f"Chrome died at startup (exit {_chrome.returncode}).\n"
                f"--- Chrome output ---\n{_chrome_output()}")
        try:
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
            return [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(
        f"Chrome does not respond (after {CHROME_START_TIMEOUT:.0f}s on port {port}).\n"
        f"--- Chrome output ---\n{_chrome_output()}")


class Page:
    """A very small CDP client: navigate, evaluate JS, record console and network."""

    def __init__(self, ws):
        self.ws, self._id = ws, 0
        self.console, self.failed = [], []

    async def cmd(self, method, **params):
        self._id += 1
        await self.ws.send(json.dumps({"id": self._id, "method": method, "params": params}))
        while True:
            m = json.loads(await self.ws.recv())
            if m.get("method") == "Runtime.consoleAPICalled" and m["params"]["type"] == "error":
                self.console.append(m["params"])
            if m.get("method") == "Runtime.exceptionThrown":
                self.console.append(m["params"])
            if m.get("method") == "Network.responseReceived":
                r = m["params"]["response"]
                if r["status"] >= 400 and "/gibtsnicht" not in r["url"] and "/boom" not in r["url"]:
                    self.failed.append((r["status"], r["url"]))
            if m.get("id") == self._id:
                return m.get("result", {})

    async def js(self, expr):
        r = await self.cmd("Runtime.evaluate", expression=expr, returnByValue=True)
        if "exceptionDetails" in r:
            raise AssertionError(f"JS error: {r['exceptionDetails'].get('text')} — {expr[:60]}")
        return r.get("result", {}).get("value")

    async def go(self, path, wait=1.4):
        await self.cmd("Page.navigate", url=BASE + path)
        await asyncio.sleep(wait)
        # Not just a fixed pause: on a cold runner the first page after Chrome's start was not
        # ready after 1.4 s (PR #142, `header.shell` was missing). Wait up to 15 s for a complete document.
        for _ in range(60):
            if await self.js("document.readyState") == "complete":
                break
            await asyncio.sleep(0.25)

    async def click(self, selector):
        await self.js(f"document.querySelector({selector!r}).click()")
        await asyncio.sleep(1.2)

    async def until(self, expr, why, tries=80):
        """Wait for a condition in the page (every 0.25 s, at most `tries` times) — instead of a fixed pause."""
        for _ in range(tries):
            try:
                if await self.js(expr):
                    return
            except AssertionError:
                pass                                  # navigation in flight — the context is gone briefly
            await asyncio.sleep(0.25)
        raise AssertionError(f"{why} (at {await self.js('location.href')!r})")

    async def key(self, name, shift=False):
        """A real key press (trusted event) — Escape, Enter or Tab."""
        code = {"Escape": 27, "Enter": 13, "Tab": 9}[name]
        extra = {"text": "\r"} if name == "Enter" else {}
        await self.cmd("Input.dispatchKeyEvent", type="keyDown" if extra else "rawKeyDown", key=name, code=name,
                       windowsVirtualKeyCode=code, nativeVirtualKeyCode=code, modifiers=8 if shift else 0, **extra)
        await self.cmd("Input.dispatchKeyEvent", type="keyUp", key=name, code=name,
                       windowsVirtualKeyCode=code, nativeVirtualKeyCode=code, modifiers=8 if shift else 0)

    async def answer(self, ok=True, value=None):
        """Answer the page's own dialog (T-35): wait for it, fill in `value`, click OK or Cancel, wait until it is gone."""
        await self.until("!!document.querySelector('dialog.tsdlg[open]')", "no dialog opened")
        if value is not None:
            await self.js(f"document.querySelector('dialog.tsdlg[open] input').value={json.dumps(value)};true")
        button = ".tsdlg-ok" if ok else ".tsdlg-cancel"
        await self.js(f"document.querySelector('dialog.tsdlg[open] {button}').click();true")
        await self.until("!document.querySelector('dialog.tsdlg')", "the dialog did not close")


async def until_py(cond, why, tries=80):
    """Wait for a condition on the server side (a store value) — the browser answers asynchronously."""
    for _ in range(tries):
        if cond():
            return
        await asyncio.sleep(0.25)
    raise AssertionError(why)


PAGES = ["/", "/demo", "/demo/flows", "/legal", "/auth/login", "/auth/register", "/gibtsnicht"]


async def run():
    async with websockets.connect(_ws_url(), max_size=30_000_000) as ws:
        p = Page(ws)
        await p.cmd("Page.enable")
        await p.cmd("Runtime.enable")
        await p.cmd("Network.enable")

        # CSP violations do NOT go through the JS console (Runtime); they must be caught in the
        # document. The listener is installed fresh on EVERY new document
        # (window.__csp starts empty) → after loading it is the proof whether
        # the strict nonce CSP of the built-in pages blocked a <script>/<style>.
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source=(
            "window.__csp=[];addEventListener('securitypolicyviolation',function(e){"
            "window.__csp.push(e.effectiveDirective+' blocked '+(e.blockedURI||'inline'))})"))

        # ---------- 1) Every page loads, without console errors and without broken requests ----------
        for path in PAGES:
            await p.go(path)
            assert await p.js("document.querySelectorAll('header.shell').length") == 1, path
            assert await p.js("document.querySelectorAll('nav.row').length") == 2, path
            assert await p.js("document.querySelectorAll('footer').length") == 1, path
        assert not p.console, f"console errors: {p.console[:2]}"
        assert not p.failed, f"broken requests: {p.failed[:3]}"
        print("  every page: one header, two nav rows, one footer; no console errors")

        # ---------- CSP: the built-in auth pages run under a strict nonce CSP ----------
        # No violation = the browser accepted every <script>/<style> via nonce; a
        # wrong/missing nonce would have blocked them and produced an entry here.
        for path in ("/auth/login", "/auth/register"):
            await p.go(path)
            viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
            assert viol == "[]", f"CSP violation on {path}: {viol}"
        print("  auth pages under strict CSP: no violation (nonce accepted)")

        # ---------- 2) Header, content and footer are equally wide ----------
        for path in ("/demo", "/legal", "/demo/flows"):
            await p.go(path)
            w = json.loads(await p.js("""JSON.stringify({
                nav:Math.round(document.querySelector('nav.row').getBoundingClientRect().width),
                main:Math.round(document.querySelector('main').getBoundingClientRect().width),
                foot:Math.round(document.querySelector('footer .inner').getBoundingClientRect().width)})"""))
            assert w["nav"] == w["main"] == w["foot"], (path, w)
        print("  widths: nav = content = footer, on every page")

        # ---------- 3) Icons as large as intended (not squeezed by the nav padding) ----------
        await p.go("/demo")
        box = json.loads(await p.js("""JSON.stringify((function(){
            const a=document.querySelector('.ilink'), s=a.querySelector('svg');
            const rs=s.getBoundingClientRect(), ra=a.getBoundingClientRect();
            const rp=document.querySelector('.pill2').getBoundingClientRect();
            return {svg:[Math.round(rs.width),Math.round(rs.height)],
                    icon_h:Math.round(ra.height), pill_h:Math.round(rp.height)};})())"""))
        assert box["svg"] == [20, 20], box
        assert box["icon_h"] == box["pill_h"], box
        print(f"  icons {box['svg']} in {box['icon_h']}px frame = pill height {box['pill_h']}px")

        # ---------- 4) One language system: `?lang=` on every page ----------
        for path in ("/", "/demo", "/demo/flows", "/legal"):
            await p.cmd("Network.clearBrowserCookies")
            await p.go(path + "?lang=en")
            en = await p.js("document.title")
            await p.go(path + "?lang=de")
            de = await p.js("document.title")
            assert en != de, (path, en)
            assert await p.js("document.documentElement.lang") == "de", path
        print("  language: `?lang=` switches on all pages, `<html lang>` follows")

        # ---------- 4b) …and down into the panels ----------
        # The admin panel builds its UI in the browser. Only here can one see whether the texts
        # really arrive — in the source they are JSON, not markup.
        panel = """(function(){const f=[...document.querySelectorAll('.frame iframe')]
            .find(f=>f.src.includes('admin'));
            const d=f&&f.contentDocument; if(!d||!d.body) return '';
            return d.documentElement.lang + '|' + d.body.innerText;})()"""
        for lang, want, nope in (("en", "Hardening", "Härtung"), ("de", "Härtung", "Hardening")):
            await p.cmd("Network.clearBrowserCookies")
            await p.go(f"/demo?lang={lang}", wait=2.4)
            got = await p.js(panel)
            assert got, f"admin preview not readable ({lang})"
            head, text = got.split("|", 1)
            assert head == lang, (lang, head)
            assert want in text and nope not in text, (lang, text[:120])
        print("  admin panel follows `?lang=` like any other page (tabs, cards, `<html lang>`)")

        # ---------- 5) Light/dark down to the preview iframes ----------
        await p.go("/demo")
        await p.js("localStorage.setItem('ts-theme','dark')")
        await p.go("/demo", wait=3.0)
        assert await p.js("document.documentElement.dataset.theme") == "dark"
        frames = json.loads(await p.js("""JSON.stringify([...document.querySelectorAll('.frame iframe')]
            .map(f=>{try{const d=f.contentDocument;
              return {theme:d.documentElement.dataset.theme, bg:getComputedStyle(d.body).backgroundColor};}
              catch(e){return {err:''+e};}}))"""))
        assert len(frames) == 3, frames
        for f in frames:
            assert f.get("theme") == "dark", frames
            assert f["bg"] != "rgb(246, 241, 236)", "iframe stayed light"
        print("  dark mode also applies in all three preview iframes")

        # ---------- 5b) Code blocks follow the theme and can be copied ----------
        # The button needs `navigator.clipboard`; we replace it to see WHAT arrives.
        # What gets copied must be the plain text — without the syntax-colour spans.
        # Measured on `.cw`: the box (background, border) sits there, `.code` is
        # transparent — only that way can the copy button sit on its own line in the block.
        lum = """(function(s){const m=getComputedStyle(document.querySelector(s)).backgroundColor
            .match(/\\d+/g).map(Number); return (m[0]*.299+m[1]*.587+m[2]*.114)/255;})('.cw')"""
        for theme, light in (("light", True), ("dark", False)):
            await p.js(f"localStorage.setItem('ts-theme','{theme}')")
            await p.go("/", wait=1.6)
            assert await p.js("document.querySelectorAll('.cw .copy').length") == 2, theme
            l = await p.js(lum)
            assert (l > 0.85 if light else l < 0.2), f"code block in the {theme} theme: brightness {l:.2f}"
            # The button sits on its own line above the code — it does not overlap it.
            over = await p.js("""(function(){
                const b=document.querySelector('.cw .copy').getBoundingClientRect(),
                      c=document.querySelector('.cw .code').getBoundingClientRect();
                return b.bottom <= c.top + 1;})()""")
            assert over, f"copy button overlaps the code ({theme})"
        # The click — in the dark theme, no matter, it is about the clipboard.
        await p.js("window.__copied=null;"
                   "navigator.clipboard.writeText=t=>{window.__copied=t;return Promise.resolve();}")
        await p.js("document.querySelector('.cw .copy').click()")
        await asyncio.sleep(0.3)          # below the 1.6 s the checkmark stays
        got = await p.js("window.__copied")
        assert got and got.startswith("pip install "), f"copied: {got!r}"
        assert "<span" not in got, "the markup was copied along"
        assert await p.js("document.querySelector('.cw .copy').classList.contains('done')")
        # Second block: multi-line — proves that `white-space:pre` preserves the line breaks.
        await p.js("document.querySelectorAll('.cw .copy')[1].click()")
        await asyncio.sleep(0.2)
        code2 = await p.js("window.__copied")
        assert code2.count("\n") >= 4, f"line breaks lost: {code2!r}"
        assert code2.startswith("auth = TinySesam("), code2[:40]
        await p.js("localStorage.removeItem('ts-theme')")
        print("  code blocks: light in the light theme, dark in the dark one; copy button delivers plain text")

        # ---------- 6) The previews are locked and carry no demo notice ----------
        await p.go("/demo/preview/login")
        assert await p.js("getComputedStyle(document.documentElement).pointerEvents") == "none"
        assert await p.js("!document.querySelector('.demobar')"), "the notice belongs on the real page"
        print("  previews: read-only, without demo notice")

        # ---------- 7) Empty form → error message, no JSON ----------
        # From here on exactly one 400 is expected (the empty form) — everything else remains an error.
        p.failed.clear()
        await p.js("localStorage.removeItem('ts-theme')")
        await p.cmd("Network.clearBrowserCookies")
        await p.go("/auth/login")
        assert await p.js("!document.querySelector('form').checkValidity()"), "required is missing"
        await p.js("document.querySelectorAll('form [required]').forEach(e=>e.removeAttribute('required'));"
                   "document.querySelector('form').submit()")
        await asyncio.sleep(1.5)
        assert not await p.js("!!document.querySelector('pre')"), "422 JSON instead of a page"
        # Since 0.24.6 errors appear as a message BELOW the card (own box with an icon), no longer inside it.
        err = (await p.js("(document.querySelector('.notices .notice.error')||{textContent:''}).textContent")).strip()
        assert err, "no error message"
        assert await p.js("!document.querySelector('.card .notice') && !!document.querySelector('.notice.error svg')"), \
            "message inside the card or without an icon"
        print(f"  empty form: {err!r} instead of JSON")

        # ---------- 8) Login works — even when the browser fills in a password ----------
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source="""
            (function(){var n=0,iv=setInterval(function(){var f=document.querySelector('[name=password]');
              if(f){f.value='wrongOldPasswort';clearInterval(iv);} if(++n>40)clearInterval(iv);},5);})();""")
        await p.go("/auth/login", wait=2.0)
        assert await p.js("document.querySelector('[name=password]').value") == "", "autofill not discarded"
        await p.click(".demofill[data-u=demoadmin]")
        assert await p.js("document.querySelector('[name=username]').value") == "demoadmin"
        await p.js("document.querySelector('form').submit()")
        await asyncio.sleep(2.0)
        who = (await p.js("(document.querySelector('.dd.r summary')||{textContent:''}).textContent")).strip()
        assert who == "demoadmin", f"not signed in: {who!r}"
        await p.go("/app")
        assert "demoadmin" in await p.js("document.querySelector('h1').textContent")
        print("  login: autofill discarded, button fills, signed in, /app reachable")

        # ---------- 8b) Admin panel under strict CSP: the buttons work anyway ----------
        # R8-1: The panel only got the CSP once its inline handlers were gone. Whether the
        # delegated `data-on` buttons really work, only a browser with a real policy shows.
        await p.go("/auth/admin", wait=1.5)
        assert await p.js("document.querySelectorAll('#view tr').length") > 1, "user list empty"
        await p.click("[data-on=keys]")
        await asyncio.sleep(0.6)
        assert await p.js("!!document.querySelector('#view #kn')"), "keys button without effect"
        # G13/G3: „Rename“ and „Make owner“ work in the browser. The owner button was never
        # wired up (missing in ACT, the click did nothing), and its label did not arrive.
        # The questions come in the panel's own dialog (T-35) — answered like a person would.
        _st = showcase.auth.store
        _demo = _st.get_user_by_name("demo")["id"]
        await p.js(f"document.querySelector('[data-on=ren][data-a^=\"[{_demo},\"]').click();true")
        await p.answer(value="demo-probe")
        await until_py(lambda: _st.get_user(_demo)["username"] == "demo-probe",
                       f"rename without effect: {_st.get_user(_demo)['username']!r}")
        # The list reloads with the new name — only then does the button carry it (otherwise „demo“ = the old name).
        await p.until(f"[...document.querySelectorAll('[data-on=ren]')].some(b=>b.dataset.a==="
                      f"JSON.stringify([{_demo},'demo-probe']))", "the list did not reload after renaming")
        await p.js(f"document.querySelector('[data-on=ren][data-a^=\"[{_demo},\"]').click();true")
        await p.answer(value="demo")
        await until_py(lambda: _st.get_user(_demo)["username"] == "demo", "renaming back without effect")
        # Only an owner can grant the owner role — the demo account is not one, so for this probe
        # it is made one and afterwards reset to its previous state.
        _demoadmin = _st.get_user_by_name("demoadmin")["id"]
        _was_owner = bool(_st.get_user(_demoadmin)["is_owner"])
        _st.set_owner(_demoadmin, True)
        try:
            await p.go("/auth/admin", wait=1.5)
            _button = await p.js(f"document.querySelector('[data-on=own][data-a^=\"[{_demo},\"]').textContent.trim()")
            assert _button, "owner button without label"
            await p.js(f"document.querySelector('[data-on=own][data-a^=\"[{_demo},\"]').click();true")
            await p.answer()
            await until_py(lambda: _st.get_user(_demo)["is_owner"], "„Make owner“ without effect")
            await p.until(f"!!document.querySelector('[data-on=own][data-a^=\"[{_demo},false\"]')",
                          "the list did not reload after „Make owner“")
            await p.js(f"document.querySelector('[data-on=own][data-a^=\"[{_demo},\"]').click();true")
            await p.answer()
            await until_py(lambda: not _st.get_user(_demo)["is_owner"], "„Give up owner“ without effect")
        finally:
            _st.set_owner(_demoadmin, _was_owner)
        print("  admin panel: rename and owner button work (G13, G3)")
        await p.click(".tab[data-on=go]:nth-child(2)")
        await asyncio.sleep(0.6)
        assert await p.js("document.querySelector('.tab.on').textContent") != \
            await p.js("document.querySelector('.tab').textContent"), "tab switch without effect"
        viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
        assert viol == "[]", f"CSP violation in the admin panel: {viol}"
        print("  admin panel under strict CSP: buttons and tabs work, no violation")

        # ---------- 9) Expired step-up freshness: the button sends the user to reauth ----------
        # R3-3 put factor management behind `require_mfa()`. Since then
        # /auth/totp/disable answers with 403 + `X-TinySesam-Reauth` once the step-up freshness
        # has expired — and the button on the account page failed **silently**: the page simply
        # reloaded, the factor was still there. The switch in the account JS is the only
        # UI change of this round; only in the browser is it measurable at all.
        before_fresh = showcase.auth.cfg.stepup_max_age_sec
        demoadmin_id = showcase.auth.store.get_user_by_name("demoadmin")["id"]
        # Set up a second factor so that the account page shows the „disable 2FA" button at all
        # — it is the path that R3-3 put behind the freshness check.
        showcase.auth.totp_begin(demoadmin_id)
        showcase.auth.store.confirm_totp(demoadmin_id)
        try:
            showcase.auth.cfg.stepup_max_age_sec = 1        # artificially age the freshness
            await p.go("/auth/account", wait=1.6)
            assert await p.js("!!document.querySelector('[data-act=deltotp]')"), \
                "no 2FA button on the account page — then the test measures nothing"
            await asyncio.sleep(1.5)                        # … now the confirmation is too old
            await p.js("document.querySelector('[data-act=deltotp]').click();true")
            await p.answer()                                # confirm the button's question
            await p.until("location.pathname.startsWith('/auth/reauth') && document.readyState==='complete'",
                          "the 403 fails silently, the page merely reloads")
            destination = await p.js("location.pathname + location.search")
            assert destination.startswith("/auth/reauth"), \
                f"stayed on {destination!r} — the 403 fails silently, the page merely reloads"
            assert "auth%2Faccount" in destination or "/auth/account" in destination, destination
            assert await p.js("!!document.querySelector('form')"), "reauth page without a form"
            assert showcase.auth.store.has_confirmed_totp(demoadmin_id), \
                "the second factor was removed without fresh confirmation"
        finally:
            showcase.auth.cfg.stepup_max_age_sec = before_fresh
        print("  account page: expired freshness → reauth page instead of a silent 403")

        # ---------- 10) Offer after a factor change: actually execute `offer()` (B1-7, A-5) ----------
        # Previously only a string test checked that `offer(` is in the HTML. Here we measure what
        # the user experiences: consent ends the other session — and with expired
        # freshness it is not lost but comes back as a prompt after the reauth.
        response = "new Response(JSON.stringify({ok:true,other_sessions:1}),{status:200})"
        other, _ = showcase.auth.start_session(demoadmin_id, "password")
        await p.go("/auth/account", wait=1.6)
        await p.js(f"offer({response}).then(()=>{{window.__offer_done=true}});1")
        await p.answer()
        await p.until("window.__offer_done===true", "offer() did not return")
        assert showcase.auth.store.get_session(other) is None, \
            "offer confirmed, yet the other session keeps running"
        # Freshness expired: detour via reauth, the consent travels along as ?revoke_others=1.
        other, _ = showcase.auth.start_session(demoadmin_id, "password")
        try:
            showcase.auth.cfg.stepup_max_age_sec = 1
            await asyncio.sleep(1.5)
            await p.js(f"offer({response});1")
            await p.answer()
            await p.until("location.pathname.startsWith('/auth/reauth') && document.readyState==='complete'",
                          "the consent would be lost")
            destination = await p.js("location.pathname + decodeURIComponent(location.search)")
            assert destination.startswith("/auth/reauth") and "/auth/account?revoke_others=1" in destination, \
                f"stayed on {destination!r} — the consent would be lost"
            assert showcase.auth.store.get_session(other) is not None, "ended without freshness"
        finally:
            showcase.auth.cfg.stepup_max_age_sec = before_fresh   # ≙ reauth passed
        await p.go("/auth/account?revoke_others=1", wait=0.2)
        await p.answer()                                    # asked once more after the reauth
        await until_py(lambda: showcase.auth.store.get_session(other) is None,
                       "not asked/ended after the reauth — the consent is lost")
        assert await p.js("location.search") == "", "?revoke_others stays in the address"
        print("  account page: offer ends the other sessions, also via the reauth detour")

        assert not p.console, f"console errors: {p.console[:2]}"
        # Exactly three failures are expected: the empty form (400) and the 403s with which
        # factor management and ending sessions reject the expired freshness (sections 9, 10).
        unexpected = [f for f in p.failed
                      if not (f[0] == 400 and f[1].endswith("/auth/login"))
                      and not (f[0] == 403 and f[1].endswith("/auth/totp/disable"))
                      and not (f[0] == 403 and f[1].endswith("/auth/sessions/revoke"))]
        assert not unexpected, f"broken requests: {unexpected[:3]}"

        await t33_alternatives(p)
        await own_dialogs(p)


async def t33_alternatives(p):
    """T-33 in a real browser: the polling script of the new device, the approval page and the
    admin's sign-in link — each under the strict nonce CSP, with real CSRF."""
    import re
    from fastapi.testclient import TestClient

    async def go(path, wait=1.4):
        await p.cmd("Page.navigate", url=T33 + path)
        await asyncio.sleep(wait)
        for _ in range(60):
            if await p.js("document.readyState") == "complete":
                break
            await asyncio.sleep(0.25)

    async def me():
        r = await p.cmd("Runtime.evaluate", awaitPromise=True, returnByValue=True, expression=(
            "fetch('/auth/me',{headers:{Accept:'application/json'}})"
            ".then(r=>r.ok?r.json():{}).then(j=>j.username||'')"))
        return r.get("result", {}).get("value")

    failed_before = len(p.failed)
    # The QR image needs the extra `[qr]`; the browser job installs the core only. Then the page
    # must show the short code (and the panel the link) without an image — measured either way.
    try:
        import qrcode  # noqa: F401
        has_qr = True
    except ImportError:
        has_qr = False
    boss = t33.store.get_user_by_name("boss")

    # 1) The browser is the NEW device: start, the script polls; the other device approves.
    await go("/auth/login")
    assert await p.js("!!document.querySelector('form.qrstart button')"), "no cross-device button"
    assert not await p.js("!!document.querySelector('a[href*=\"/auth/magic/request\"]')"), \
        "self-request is off — the link button must be gone"
    await p.click("form.qrstart button")
    await asyncio.sleep(0.6)
    code = await p.js("document.querySelector('#tsqr [name=code]').value")
    assert re.fullmatch(r"[A-Z0-9]{8}", code or ""), code
    assert await p.js("!!document.querySelector('img.qr')") == has_qr, \
        f"QR image {'missing although [qr] is installed' if has_qr else 'without the extra [qr]'}"
    shown = await p.js("document.querySelector('.qrcode').textContent")
    assert shown == f"{code[:4]}-{code[4:]}", shown
    assert await p.js("document.body.innerText.indexOf(document.querySelector('#tsqr [name=secret]').value)") == -1, \
        "the device secret must never be visible"
    assert t33._qr_approve(code, boss), "approval (other device) failed"
    for _ in range(30):                      # the script polls every 2 s and then submits by itself
        await asyncio.sleep(0.5)
        if await p.js("location.pathname") != "/auth/qr/start":
            break
    await asyncio.sleep(0.8)
    assert await me() == "boss", f"new device not signed in: {await me()!r} at {await p.js('location.href')!r}"
    viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
    assert viol == "[]", f"CSP violation on the cross-device page: {viol}"
    print(f"  cross-device: {'QR' if has_qr else 'short-code'} page, the poll script signs the new device in by "
          "itself, strict CSP")

    # 2) The browser is the APPROVING device: a second device opens a request, the page names it.
    other = TestClient(_t33_app)
    page = other.get("/auth/login").text
    tok = re.search(r"name=_csrf value='([^']+)'", page).group(1)
    r = other.post("/auth/qr/start", data={"_csrf": tok, "next": "/"}, headers={"User-Agent": "T33-Probe/2.0"})
    code2 = re.search(r"name=code value='([A-Z0-9]{8})'", r.text).group(1)
    await go(f"/auth/qr/approve?code={code2}")
    assert "T33-Probe/2.0" in await p.js("document.querySelector('table.qrinfo').innerText"), \
        "the approval page must name the asking device"
    await p.click("form[action$='/auth/qr/approve'] button")
    assert t33._qr_peek(code2)["user_id"] == boss["id"], "approve button without effect"
    viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
    assert viol == "[]", f"CSP violation on the approval page: {viol}"
    print("  cross-device: the approval page names the device, the button approves (CSRF, CSP)")

    # 3) Admin panel: the sign-in link button shows link and QR code once.
    carol = t33.store.get_user_by_name("carol")["id"]
    await go("/auth/admin", wait=1.5)
    await p.js(f"document.querySelector('[data-on=link][data-a^=\"[{carol},\"]').click();true")
    await p.answer(value="30")
    await p.until(f"!!document.getElementById('lk{carol}')", "no link shown")
    url = await p.js(f"(document.getElementById('lk{carol}')||{{}}).value||''")
    assert url.startswith(T33 + "/auth/magic/"), f"no link shown: {url!r}"
    assert await p.js("!!document.querySelector('#view img.qr')") == has_qr, \
        f"panel QR image {'missing although [qr] is installed' if has_qr else 'without the extra [qr]'}"
    assert t33.store.open_token(carol, "login"), "no open sign-in token for the account"
    viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
    assert viol == "[]", f"CSP violation in the admin panel: {viol}"
    assert not p.console, f"console errors: {p.console[:2]}"
    assert p.failed[failed_before:] == [], f"broken requests: {p.failed[failed_before:][:3]}"
    print(f"  admin panel: sign-in link button shows the link{' + QR code' if has_qr else ''} once (strict CSP)")

    await account_setup(p, go)


async def account_setup(p, go):
    """B-8/B-9/B-10 in a real browser on the T-33 app: the TOTP setup shows the recovery codes and
    then leads on, the remainder line on the account page sits below the buttons and follows
    „generate“, and an account without a password sets its first one."""
    import pyotp

    failed_before = len(p.failed)

    async def as_user(uid):
        token, _ = t33.start_session(uid, "magic")
        await p.cmd("Network.setCookie", name=t33.session_cookie_name, value=token, url=T33)

    # 1) Voluntary setup from the account page: codes shown once, „written down“ leads back (B-8, B-9a).
    nora = t33.create_user("nora", password="nora-pw-123456")
    await as_user(nora)
    await go("/auth/account")
    await p.click("a.btnlink[href$='/auth/totp/setup']")
    await p.click("form[action$='/auth/totp/setup/start'] button")
    # The page after the POST may still be loading on a cold runner — the submit handler must be there
    # before the click, otherwise the browser sends the form natively and nothing is measured.
    for _ in range(60):
        if await p.js("document.readyState==='complete' && !!document.getElementById('tstotp')"):
            break
        await asyncio.sleep(0.25)
    secret = await p.js("document.querySelector('.mono').textContent")
    await p.js(f"document.querySelector('#tstotp [name=code]').value={pyotp.TOTP(secret).now()!r};"
               "document.querySelector('#tstotp button').click()")
    for _ in range(60):                                  # fetch + offer(): wait for the box, at most 15 s
        await asyncio.sleep(0.25)
        if await p.js("!!document.getElementById('rcbox') && !document.getElementById('rcbox').hidden"):
            break
    assert await p.js("location.pathname") == "/auth/totp/setup/start", \
        f"left the page before the recovery codes could be noted: {await p.js('location.href')!r}"
    assert await p.js("!document.getElementById('rcbox').hidden && document.getElementById('tstotp').hidden"), \
        (f"codes not shown: msg={await p.js('document.getElementById(`msg`).textContent')!r} "
         f"totp={t33.store.has_confirmed_totp(nora)} codes={t33.recovery_codes_remaining(nora)} "
         f"failed={p.failed[failed_before:][:3]} console={p.console[:2]}")
    shown = (await p.js("document.getElementById('rccodes').textContent")).split("\n")
    assert len(shown) == t33.cfg.recovery_code_count == t33.recovery_codes_remaining(nora), shown
    await p.click("#rcdone")
    assert await p.js("location.pathname") == "/auth/account", \
        f"B-8: stayed on {await p.js('location.pathname')!r} after the setup"
    print(f"  TOTP setup: {len(shown)} recovery codes shown once, „written down“ leads to the account page")

    # 2) The remainder line: own block below the buttons, one line wide, follows „generate“ (B-9b).
    t33.store.delete_recovery_codes(nora)
    geometry = """JSON.stringify((()=>{const b=document.getElementById('rc_left'),r=b.getBoundingClientRect(),
        k=[...document.querySelectorAll('.sec button')].filter(x=>x.closest('.sec')===b.closest('.sec'))
          .map(x=>x.getBoundingClientRect());
        return {text:b.textContent.trim(),top:r.top,h:r.height,
                lh:parseFloat(getComputedStyle(b).lineHeight)||(parseFloat(getComputedStyle(b).fontSize)*1.4),
                pad:parseFloat(getComputedStyle(b).paddingTop)+parseFloat(getComputedStyle(b).paddingBottom),
                below:Math.max(...k.map(x=>x.bottom))}})())"""
    for width in (1280, 390):
        await p.cmd("Emulation.setDeviceMetricsOverride", width=width, height=900, deviceScaleFactor=1,
                    mobile=width < 500)
        await go("/auth/account")
        g = json.loads(await p.js(geometry))
        assert g["text"] == t33.t("acc.recovery_none"), g
        assert g["top"] >= g["below"], f"B-9b at {width}px: the line overlaps the button row {g}"
        assert g["h"] - g["pad"] < 2 * g["lh"], f"B-9b at {width}px: the line wraps {g}"
    await p.cmd("Emulation.clearDeviceMetricsOverride")
    await go("/auth/account")
    await p.js("document.querySelector('[data-act=recovery]').click();true")
    await p.answer()                                         # „generate new codes?“
    # The codes come once, in the secret dialog (T-35); the line below the buttons is updated before.
    await p.until("!!document.querySelector('dialog.tsdlg[open] textarea')", "no recovery codes dialog")
    codes = (await p.js("document.querySelector('dialog.tsdlg[open] textarea').value")).split("\n")
    assert len(codes) == t33.cfg.recovery_code_count == t33.recovery_codes_remaining(nora), codes
    left = await p.js("document.getElementById('rc_left').textContent")
    assert left == t33.t("acc.recovery_left", n=t33.cfg.recovery_code_count), \
        f"B-9b: the line still says {left!r} after „generate“"
    await p.answer()                                         # „Done“ closes the dialog
    print("  account page: recovery line below the buttons on one line (1280/390 px), updated after „generate“")

    # 3) An account without a password sets its first one (B-10).
    olga = t33.create_user("olga")
    await as_user(olga)
    await go("/auth/account")
    assert await p.js("!!document.querySelector('[data-act=setpw]') && !document.getElementById('pw_cur')"), \
        "B-10: no „set password“ form without the current-password field"
    await p.js("document.getElementById('pw_new').value='olga-first-2468';true")
    await p.click("[data-act=setpw]")
    await asyncio.sleep(1.0)
    assert t33.store.get_password_hash(olga), \
        f"B-10: password not set: {await p.js('document.getElementById(`pw_msg`)?.textContent')!r}"
    assert await p.js("!!document.getElementById('pw_cur')"), "after setting, the regular change form is missing"
    viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
    assert viol == "[]", f"CSP violation on the account page: {viol}"
    assert not p.console, f"console errors: {p.console[:2]}"
    assert p.failed[failed_before:] == [], f"broken requests: {p.failed[failed_before:][:3]}"
    print("  account page: an account without a password sets its first one (no current-password field)")

    await link_setup_pass(p)


async def link_setup_pass(p):
    """T-34 in a real browser: the admin creates an account and hands out a link; the link leads into
    the setup pass (password, then TOTP with recovery codes), and only then is the sign-in full —
    strict CSP, real CSRF, waits on events, not on fixed pauses."""
    import pyotp

    failed_before = len(p.failed)

    async def go(path):
        await p.cmd("Page.navigate", url=T34 + path)
        await until("document.readyState==='complete'", f"page {path} did not load")

    async def until(expr, why, tries=80):
        for _ in range(tries):
            try:
                if await p.js(expr):
                    return
            except AssertionError:
                pass                                  # navigation in flight — the context is gone briefly
            await asyncio.sleep(0.25)
        raise AssertionError(f"{why} (at {await p.js('location.href')!r})")

    async def me():
        r = await p.cmd("Runtime.evaluate", awaitPromise=True, returnByValue=True, expression=(
            "fetch('/auth/me',{headers:{Accept:'application/json'}})"
            ".then(r=>r.ok?r.json():{}).then(j=>j.username||'')"))
        return r.get("result", {}).get("value")

    tess = t34.create_user("tess", email="tess@example.com")
    url = t34.create_signin_link(tess, next="/")["url"]
    await go(url[len(T34):])
    await p.js("document.querySelector('form button').click()")
    await until("location.pathname==='/auth/setup' && document.readyState==='complete'",
                "the link did not lead into the setup pass")
    assert await me() == "", "the link alone signed in fully"
    assert await p.js("!!document.getElementById('ob_password') && !document.getElementById('ob_totp')"), \
        "first step: the password, nothing else"

    # A typo in the repetition is caught on the page, nothing is sent.
    await p.js("document.getElementById('ob_pw1').value='tess-first-2468';"
               "document.getElementById('ob_pw2').value='tess-first-2469';"
               "document.querySelector('#ob_password button').click();true")
    await until("!document.getElementById('obmsg').hidden", "no message for two different passwords")
    assert not t34.store.get_password_hash(tess)
    await p.js("document.getElementById('ob_pw2').value='tess-first-2468';"
               "document.querySelector('#ob_password button').click();true")
    await until("!!document.getElementById('ob_totp') && document.readyState==='complete'",
                "after the password the page must offer the TOTP step")
    assert t34.store.get_password_hash(tess) and await me() == "", "half way, the session must stay half"

    await p.js("document.querySelector('#ob_totp a').click();true")
    await until("!!document.querySelector(\"form[action$='/auth/totp/setup/start'] button\")", "no TOTP start page")
    await p.js("document.querySelector(\"form[action$='/auth/totp/setup/start'] button\").click();true")
    await until("document.readyState==='complete' && !!document.getElementById('tstotp')", "no TOTP form")
    secret = await p.js("document.querySelector('.mono').textContent")
    await p.js(f"document.querySelector('#tstotp [name=code]').value={pyotp.TOTP(secret).now()!r};"
               "document.querySelector('#tstotp button').click();true")
    await until("!!document.getElementById('rcbox') && !document.getElementById('rcbox').hidden",
                "no recovery codes after the TOTP step")
    await p.js("document.getElementById('rcdone').click();true")
    await until("location.pathname==='/' && document.readyState==='complete'", "did not land on the target")
    assert await me() == "tess", f"not fully signed in after the pass: {await me()!r}"
    viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
    assert viol == "[]", f"CSP violation in the setup pass: {viol}"
    assert not p.console, f"console errors: {p.console[:2]}"
    # The two probes of /auth/me while the session is half answer 401 — that is the point of them.
    broken = [f for f in p.failed[failed_before:] if not (f[0] == 401 and f[1].endswith("/auth/me"))]
    assert broken == [], f"broken requests: {broken[:3]}"
    print("  setup pass: link → password (typo caught) → TOTP + recovery codes → fully signed in (strict CSP)")

    await oauth_consent(p)


async def oauth_consent(p):
    """T-36 in a real browser: the consent page (strict CSP with frame-ancestors 'none'; the form leads to the
    program's loopback address, which Chrome checks against form-action after the POST) and the device list on
    the account page, at 390 and 1280 px. `TINYSESAM_SCREENSHOTS=<dir>` keeps the screenshots."""
    import base64
    import hashlib
    import secrets as _s
    from urllib.parse import urlencode, urlsplit, parse_qs

    failed_before = len(p.failed)
    shots = os.environ.get("TINYSESAM_SCREENSHOTS", "")

    async def go(url):
        await p.cmd("Page.navigate", url=url)
        for _ in range(80):
            if await p.js("document.readyState") == "complete":
                break
            await asyncio.sleep(0.15)
        await asyncio.sleep(0.3)

    async def shot(name):
        if not shots:
            return
        os.makedirs(shots, exist_ok=True)
        data = (await p.cmd("Page.captureScreenshot", format="png", captureBeyondViewport=True))["data"]
        with open(os.path.join(shots, name), "wb") as fh:
            fh.write(base64.b64decode(data))

    req = urllib.request.Request(f"{T36}/auth/oauth/register", method="POST",
                                 headers={"Content-Type": "application/json"},
                                 data=json.dumps({"client_name": "Claude Code", "redirect_uris": [T36_CB],
                                                  "token_endpoint_auth_method": "none"}).encode())
    cid = json.load(urllib.request.urlopen(req))["client_id"]
    uid = t36.create_user("paula", password="paula-pw-1234")
    tok, _ = t36.start_session(uid, "password")
    await p.cmd("Network.setCookie", name=t36.session_cookie_name, value=tok, url=T36 + "/")
    verifier = _s.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    q = urlencode({"response_type": "code", "client_id": cid, "redirect_uri": T36_CB, "code_challenge": challenge,
                   "code_challenge_method": "S256", "state": "st", "scope": "mcp offline_access",
                   "resource": "http://127.0.0.1:9/mcp"})
    for width in (390, 1280):
        await p.cmd("Emulation.setDeviceMetricsOverride", width=width, height=900, deviceScaleFactor=1,
                    mobile=width < 500)
        await go(f"{T36}/auth/oauth/authorize?{q}")
        assert await p.js("location.pathname") == "/auth/oauth/consent", await p.js("location.href")
        assert (await p.js("document.getElementById('oaclient').textContent")).startswith("Claude Code")
        assert "127.0.0.1" in await p.js("document.getElementById('oarhost').textContent")
        over = await p.js("document.documentElement.scrollWidth - window.innerWidth")
        assert over <= 0, f"consent page scrolls sideways at {width}px ({over}px)"
        await shot(f"consent-{width}.png")
    assert await p.js("window.top === window.self")
    await p.click("#oaallow")
    for _ in range(40):
        if _t36_cb_seen:
            break
        await asyncio.sleep(0.2)
    assert _t36_cb_seen, f"the browser did not reach the program's callback: {await p.js('location.href')}"
    cbq = parse_qs(urlsplit(_t36_cb_seen[-1]).query)
    assert cbq["state"] == ["st"] and cbq["iss"] == [T36] and cbq["code"][0].startswith("tsac_"), cbq
    tok_req = urllib.request.Request(f"{T36}/auth/oauth/token", method="POST",
                                     data=urlencode({"grant_type": "authorization_code", "code": cbq["code"][0],
                                                     "redirect_uri": T36_CB, "code_verifier": verifier,
                                                     "client_id": cid}).encode(),
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert json.load(urllib.request.urlopen(tok_req))["access_token"].startswith("tsat_")
    print("  OAuth consent: client, redirect host, strict CSP; allow leads to the loopback callback (form-action)")

    for width in (390, 1280):
        await p.cmd("Emulation.setDeviceMetricsOverride", width=width, height=900, deviceScaleFactor=1,
                    mobile=width < 500)
        await go(f"{T36}/auth/account")
        assert await p.js("document.querySelectorAll('#devlist form.devrevoke').length") == 1
        over = await p.js("document.documentElement.scrollWidth - window.innerWidth")
        assert over <= 0, f"account page scrolls sideways at {width}px ({over}px)"
        await p.js("document.getElementById('devlist').scrollIntoView();true")
        await shot(f"devices-{width}.png")
    await p.cmd("Emulation.clearDeviceMetricsOverride")
    await p.click("#devlist form.devrevoke button")
    await go(f"{T36}/auth/account")
    assert await p.js("document.querySelectorAll('#devlist form.devrevoke').length") == 0
    assert t36._oauth.devices(uid) == []
    viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
    assert viol == "[]", f"CSP violation: {viol}"
    assert not p.console, f"console errors: {p.console[:2]}"
    assert p.failed[failed_before:] == [], f"broken requests: {p.failed[failed_before:][:3]}"
    print("  OAuth devices: listed on the account page (390/1280 px), „Disconnect“ ends it at once")


async def own_dialogs(_first):
    """In a tab of its own — see `_own_dialogs`.

    Why a new tab: in the first one, key presses sent over CDP (`Input.dispatchKeyEvent`) stop arriving after the
    showcase login of section 8 — every later page of that tab, on either server, saw no keydown at all, while
    `Runtime.evaluate` kept working. Not tracked down further (a fresh tab of the same browser receives them, a
    standalone login form does not reproduce it); the dialog checks need real key presses, so they get a fresh tab."""
    port = _cdp_port()
    tab = json.load(urllib.request.urlopen(urllib.request.Request(
        f"http://127.0.0.1:{port}/json/new?about:blank", method="PUT")))
    async with websockets.connect(tab["webSocketDebuggerUrl"], max_size=30_000_000) as ws:
        p = Page(ws)
        await p.cmd("Page.enable")
        await p.cmd("Runtime.enable")
        await p.cmd("Network.enable")
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source=(
            "window.__csp=[];addEventListener('securitypolicyviolation',function(e){"
            "window.__csp.push(e.effectiveDirective+' blocked '+(e.blockedURI||'inline'))})"))
        await _own_dialogs(p)


async def _own_dialogs(p):
    """T-35 in a real browser on the T-33 app (strict CSP, real CSRF): the own dialog answers the keyboard like the
    system one did — Escape cancels, Enter confirms, Tab stays inside, the focus goes back — and every secret shown
    once has a copy button that writes to the clipboard, or selects the text where there is no clipboard API.
    With `TS_SHOT_DIR` set, it saves screenshots (390 + 1280 px) of the dialogs there."""
    import base64
    import pyotp

    failed_before = len(p.failed)
    shots = os.environ.get("TS_SHOT_DIR", "")

    async def go(path):
        # Mark the old document: until the new one is there, `readyState` would still answer for the old one.
        await p.js("window.__old=true")
        await p.cmd("Page.navigate", url=T33 + path)
        await p.until("window.__old===undefined && document.readyState==='complete'", f"page {path} did not load")

    async def ajs(expr):
        r = await p.cmd("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        if "exceptionDetails" in r:
            raise AssertionError(f"JS error: {r['exceptionDetails'].get('text')} — {expr[:60]}")
        return r.get("result", {}).get("value")

    async def as_user(uid):
        token, _ = t33.start_session(uid, "password")
        await p.cmd("Network.setCookie", name=t33.session_cookie_name, value=token, url=T33)

    async def shot(name):
        if not shots:
            return
        for width in (390, 1280):
            await p.cmd("Emulation.setDeviceMetricsOverride", width=width, height=820, deviceScaleFactor=1,
                        mobile=width < 500)
            await ajs("new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))")   # layout settled
            data = (await p.cmd("Page.captureScreenshot", format="png"))["data"]
            pathlib.Path(shots, f"{name}-{width}.png").write_bytes(base64.b64decode(data))
        await p.cmd("Emulation.clearDeviceMetricsOverride")

    async def pending(call):
        """Start a dialog function; its result lands in window.__r ('pending' until then)."""
        await p.js(f"window.__r='pending';{call}.then(v=>{{window.__r=v===undefined?'(undefined)':v}});true")
        await p.until("!!document.querySelector('dialog.tsdlg[open]')", f"{call}: no dialog")

    async def result():
        await p.until("window.__r!=='pending'", "the dialog did not resolve")
        return await p.js("window.__r")

    inside = "document.querySelector('dialog.tsdlg[open]').contains(document.activeElement)"
    gone = "!document.querySelector('dialog.tsdlg')"

    # The clipboard needs permission and a focused page — headless Chrome has neither by itself.
    await go("/auth/login")
    await p.cmd("Browser.grantPermissions", origin=T33,
                permissions=["clipboardReadWrite", "clipboardSanitizedWrite"])
    await p.cmd("Emulation.setFocusEmulationEnabled", enabled=True)

    carol = t33.store.get_user_by_name("carol")["id"]
    await as_user(carol)
    await go("/auth/account")
    assert await p.js("typeof tsConfirm==='function' && typeof tsSecret==='function'"), "no dialog building block"

    # 1) Confirm: Escape cancels, Enter confirms, Cancel cancels — the focus is back on the button that asked.
    other, _ = t33.start_session(carol, "password")
    # focus() first: a scripted click() does not move the focus the way a real one does.
    await p.js("{const b=document.querySelector('[data-act=revokeothers]');b.focus();b.click()}true")
    await p.until("!!document.querySelector('dialog.tsdlg[open]')", "the button opened no dialog")
    assert await p.js("document.activeElement.classList.contains('tsdlg-ok')"), "focus not on OK"
    aria = json.loads(await p.js("""JSON.stringify((()=>{const d=document.querySelector('dialog.tsdlg[open]');
        const l=document.getElementById(d.getAttribute('aria-labelledby'));
        return {role:d.getAttribute('role'),modal:d.getAttribute('aria-modal'),label:l?l.textContent:''}})())"""))
    assert aria["role"] == "alertdialog" and aria["modal"] == "true", aria
    assert aria["label"] == "End all other sessions?", f"the dialog is not labelled by its question: {aria}"
    for shift in (False, False, False, True, True, True):          # the focus stays inside the dialog
        await p.key("Tab", shift=shift)
        assert await p.js(inside), f"Tab{' (shift)' if shift else ''} left the dialog"
    await shot("confirm")
    await p.key("Escape")
    await p.until(gone, "Escape did not close the dialog")
    assert await p.js("document.activeElement.dataset.act==='revokeothers'"), "focus not back on the button"
    await asyncio.sleep(0.5)                                         # an (unwanted) revoke would have run by now
    assert t33.store.get_session(other) is not None, "Escape confirmed: the other session was ended"

    await p.js("document.querySelector('[data-act=revokeothers]').focus();true")
    await pending("tsConfirm('Probe?')")
    await p.key("Escape")
    assert await result() is False, "Escape must cancel (false)"
    assert await p.js("document.activeElement.dataset.act==='revokeothers'"), "focus not back after Escape"
    await pending("tsConfirm('Probe?')")
    await p.key("Enter")
    assert await result() is True, "Enter on OK must confirm (true)"
    assert await p.js("document.activeElement.dataset.act==='revokeothers'"), "focus not back after Enter"
    await pending("tsConfirm('Probe?')")
    await p.js("document.querySelector('dialog.tsdlg[open] .tsdlg-cancel').click();true")
    assert await result() is False, "Cancel must yield false"

    # 2) Prompt: Enter in the field takes its value, Escape yields null. Alert: closes and resolves.
    await pending("tsPrompt('Name?','abc')")
    assert await p.js("document.activeElement.tagName==='INPUT' && document.activeElement.value==='abc'"), \
        "the prompt field is not focused with its value"
    await p.js("document.activeElement.value='xyz';true")
    await p.key("Enter")
    assert await result() == "xyz", "Enter in the field must take its value"
    await pending("tsPrompt('Name?','abc')")
    await p.key("Escape")
    assert await result() is None, "Escape on a prompt must yield null"
    await pending("tsAlert('Note')")
    await p.key("Enter")
    assert await result() == "(undefined)" and await p.js(gone), "the alert did not close"
    print("  dialog: Escape cancels, Enter confirms, Tab stays inside, focus back on the asking button (alertdialog)")

    # 3) A new API key on the account page: shown once in the secret dialog, the copy button fills the clipboard.
    await p.js("document.getElementById('key_name').value='probe';"
               "{const b=document.querySelector('[data-act=mkkey]');b.focus();b.click()}true")
    await p.until("!!document.querySelector('dialog.tsdlg[open] textarea')", "no API key dialog")
    key = await p.js("document.querySelector('dialog.tsdlg[open] textarea').value")
    assert t33.verify_api_key(key)[0]["id"] == carol, f"the dialog does not show the new key: {key[:8]!r}"
    assert await p.js("document.activeElement.classList.contains('tsdlg-copy')"), "focus not on the copy button"
    await shot("apikey-account")
    await p.js("document.querySelector('dialog.tsdlg[open] .tsdlg-copy').click();true")
    await p.until(f"document.querySelector('dialog.tsdlg[open] .tsdlg-status').textContent==={json.dumps(t33.t('dlg.copied'))}",
                  "no „Copied“ after the click")
    assert await ajs("navigator.clipboard.readText()") == key, "the clipboard does not hold the key"
    assert not await p.js(f"location.href.includes({json.dumps(key)}) || JSON.stringify(localStorage).includes("
                          f"{json.dumps(key)}) || JSON.stringify(sessionStorage).includes({json.dumps(key)})"), \
        "the key landed in the URL or in browser storage"
    await p.js("document.querySelector('dialog.tsdlg[open] .tsdlg-ok').click();true")
    await p.until(gone, "„Done“ did not close the secret dialog")
    assert await p.js("document.activeElement.dataset.act==='mkkey'"), "focus not back on „Create key“"

    # 4) Without the clipboard API (plain HTTP, old browser): the key is pre-selected, the button says Ctrl+C.
    await p.js("Object.defineProperty(navigator,'clipboard',{value:undefined,configurable:true});"
               "document.getElementById('key_name').value='probe2';"
               "document.querySelector('[data-act=mkkey]').click();true")
    await p.until("!!document.querySelector('dialog.tsdlg[open] textarea')", "no API key dialog (fallback)")
    selected = ("(()=>{const t=document.querySelector('dialog.tsdlg[open] textarea');return document.activeElement===t"
                " && t.value.length>20 && t.selectionStart===0 && t.selectionEnd===t.value.length})()")
    assert await p.js(selected), "fallback: the key is not pre-selected"
    # Selection gone and focus on the button, as after a click elsewhere — the button must select it again.
    await p.js("{const d=document.querySelector('dialog.tsdlg[open]');d.querySelector('textarea').setSelectionRange(0,0);"
               "d.querySelector('.tsdlg-copy').focus();d.querySelector('.tsdlg-copy').click()}true")
    await p.until(f"document.querySelector('dialog.tsdlg[open] .tsdlg-status').textContent==="
                  f"{json.dumps(t33.t('dlg.copy_manual'))}", "fallback: no Ctrl+C hint")
    assert await p.js(selected), "fallback: the copy button does not select the key"
    await p.key("Escape")
    await p.until(gone, "Escape did not close the secret dialog")
    print("  API key (account): secret dialog, copy → clipboard; without clipboard API pre-selected + Ctrl+C hint")

    # 5) Recovery codes on the TOTP setup page: the copy button below the codes.
    uma = t33.create_user("uma", password="uma-pw-1234567")
    await as_user(uma)
    await go("/auth/totp/setup")
    await p.js("document.querySelector(\"form[action$='/auth/totp/setup/start'] button\").click();true")
    await p.until("document.readyState==='complete' && !!document.getElementById('tstotp')", "no TOTP form")
    secret = await p.js("document.querySelector('.mono').textContent")
    await p.js(f"document.querySelector('#tstotp [name=code]').value={pyotp.TOTP(secret).now()!r};"
               "document.querySelector('#tstotp button').click();true")
    await p.until("!document.getElementById('rcbox').hidden", "no recovery codes after the TOTP setup")
    await shot("recovery-setup")
    await p.js("document.getElementById('rccopy').click();true")
    await p.until(f"document.getElementById('rcstate').textContent==={json.dumps(t33.t('dlg.copied'))}",
                  "TOTP setup: no „Copied“")
    assert await ajs("navigator.clipboard.readText()") == await p.js("document.getElementById('rccodes').textContent")
    # 6) …and on the account page („new recovery codes“), in the same session.
    await go("/auth/account")
    assert await p.js("!!document.querySelector('[data-act=recovery]')"), \
        f"no „new recovery codes“ button: {(await p.js('document.body.innerText'))[:300]!r}"
    await p.js("document.querySelector('[data-act=recovery]').click();true")
    await p.answer()
    await p.until("!!document.querySelector('dialog.tsdlg[open] textarea')", "no recovery codes dialog")
    codes = await p.js("document.querySelector('dialog.tsdlg[open] textarea').value")
    assert len(codes.split("\n")) == t33.cfg.recovery_code_count, codes
    await shot("recovery-account")
    await p.js("document.querySelector('dialog.tsdlg[open] .tsdlg-copy').click();true")
    await p.until("document.querySelector('dialog.tsdlg[open] .tsdlg-status').textContent!==''", "no copy status")
    assert await ajs("navigator.clipboard.readText()") == codes, "the clipboard does not hold the recovery codes"
    await p.key("Escape")
    await p.until(gone, "the recovery dialog did not close")

    print("  recovery codes: secret dialog on the account page, copy button on the TOTP setup page — both copy")

    # 7) Admin panel: API key in the secret dialog, the sign-in link with its copy button.
    await as_user(t33.store.get_user_by_name("boss")["id"])
    await go("/auth/admin")
    await p.until(f"!!document.querySelector('[data-on=keys][data-a^=\"[{carol},\"]')", "user list empty")
    await p.js(f"document.querySelector('[data-on=keys][data-a^=\"[{carol},\"]').click();true")
    await p.until("!!document.getElementById('kn')", "keys button without effect")
    await p.js("document.getElementById('kn').value='panel';document.querySelector('[data-on=mkkey]').click();true")
    await p.until("!!document.querySelector('dialog.tsdlg[open] textarea')", "panel: no API key dialog")
    key = await p.js("document.querySelector('dialog.tsdlg[open] textarea').value")
    assert t33.verify_api_key(key)[0]["id"] == carol, "panel: the dialog does not show the new key"
    await shot("apikey-panel")
    await p.js("document.querySelector('dialog.tsdlg[open] .tsdlg-copy').click();true")
    await p.until("document.querySelector('dialog.tsdlg[open] .tsdlg-status').textContent!==''", "panel: no copy status")
    assert await ajs("navigator.clipboard.readText()") == key, "panel: the clipboard does not hold the key"
    await p.key("Escape")
    await p.until(gone, "panel: the secret dialog did not close")
    await p.js(f"document.querySelector('[data-on=link][data-a^=\"[{carol},\"]').click();true")
    await p.answer(value="30")
    await p.until(f"!!document.getElementById('lk{carol}')", "panel: no sign-in link")
    await p.js(f"document.querySelector('[data-on=copylink]').click();true")
    await p.until(f"document.getElementById('lks{carol}').textContent==={json.dumps(t33.t('dlg.copied'))}",
                  "panel: the link's copy button says nothing")
    assert await ajs("navigator.clipboard.readText()") == await p.js(f"document.getElementById('lk{carol}').value")
    print("  admin panel: API key in the secret dialog, sign-in link with copy button — both copy")

    viol = await p.js("JSON.stringify(window.__csp===undefined?['(no Listener)']:window.__csp)")
    assert viol == "[]", f"CSP violation with the dialogs: {viol}"
    assert not p.console, f"console errors: {p.console[:2]}"
    assert p.failed[failed_before:] == [], f"broken requests: {p.failed[failed_before:][:3]}"
    await p.cmd("Emulation.setFocusEmulationEnabled", enabled=False)


try:
    asyncio.run(run())
    print("OK test_browser")
finally:
    _chrome.terminate()
    _server.should_exit = True
    _t33_server.should_exit = True
    _t34_server.should_exit = True
    _t36_server.should_exit = True
    _t36_cb.shutdown()
    shutil.rmtree(_profile, ignore_errors=True)
    # Also clean up the Chrome log file — the test must leave nothing behind.
    try:
        _chrome_log.close()
        os.unlink(_chrome_log.name)
    except OSError:
        pass  # Log already gone — nothing to clean up
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_db + suffix)
        except OSError:
            pass  # file did not exist — not an error when cleaning up
    shutil.rmtree(os.path.dirname(_t33_db), ignore_errors=True)
    shutil.rmtree(os.path.dirname(_t34_db), ignore_errors=True)
    shutil.rmtree(os.path.dirname(_t36_db), ignore_errors=True)
