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

    Chrome solves the same problem its own way: `--remote-debugging-port=0` and the actual
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
            "window.__csp.push(e.effectiveDirective+' blockte '+(e.blockedURI||'inline'))})"))

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
            viol = await p.js("JSON.stringify(window.__csp===undefined?['(kein Listener)']:window.__csp)")
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
        err = (await p.js("(document.querySelector('.meldungen .meldung.fehler')||{textContent:''}).textContent")).strip()
        assert err, "no error message"
        assert await p.js("!document.querySelector('.card .meldung') && !!document.querySelector('.meldung.fehler svg')"), \
            "message inside the card or without an icon"
        print(f"  empty form: {err!r} instead of JSON")

        # ---------- 8) Login works — even when the browser fills in a password ----------
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source="""
            (function(){var n=0,iv=setInterval(function(){var f=document.querySelector('[name=password]');
              if(f){f.value='falschesAltesPasswort';clearInterval(iv);} if(++n>40)clearInterval(iv);},5);})();""")
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
        # Dialogs replaced so that no real prompt/confirm/alert halts the page; restored afterwards.
        _st = showcase.auth.store
        _demo = _st.get_user_by_name("demo")["id"]
        await p.js("window.prompt=()=>window.__name;window.confirm=()=>true;"
                   "window.alert=m=>{window.__alert=m};window.__name='demo-probe';true")
        await p.click(f'[data-on=ren][data-a^="[{_demo},"]')
        assert _st.get_user(_demo)["username"] == "demo-probe", \
            f"rename without effect: {_st.get_user(_demo)['username']!r} {await p.js('window.__alert')!r}"
        await p.js("window.__name='demo';true")
        await p.click(f'[data-on=ren][data-a^="[{_demo},"]')
        assert _st.get_user(_demo)["username"] == "demo", "renaming back without effect"
        # Only an owner can grant the owner role — the demo account is not one, so for this probe
        # it is made one and afterwards reset to its previous state.
        _demoadmin = _st.get_user_by_name("demoadmin")["id"]
        _was_owner = bool(_st.get_user(_demoadmin)["is_owner"])
        _st.set_owner(_demoadmin, True)
        try:
            await p.go("/auth/admin", wait=1.5)
            await p.js("window.confirm=()=>true;window.alert=m=>{window.__alert=m};true")
            _button = await p.js(f"document.querySelector('[data-on=own][data-a^=\"[{_demo},\"]').textContent.trim()")
            assert _button, "owner button without label"
            await p.click(f'[data-on=own][data-a^="[{_demo},"]')
            assert _st.get_user(_demo)["is_owner"], \
                f"„Make owner“ without effect: {await p.js('window.__alert')!r}"
            await p.click(f'[data-on=own][data-a^="[{_demo},"]')
            assert not _st.get_user(_demo)["is_owner"], "„Give up owner“ without effect"
        finally:
            _st.set_owner(_demoadmin, _was_owner)
        print("  admin panel: rename and owner button work (G13, G3)")
        await p.click(".tab[data-on=go]:nth-child(2)")
        await asyncio.sleep(0.6)
        assert await p.js("document.querySelector('.tab.on').textContent") != \
            await p.js("document.querySelector('.tab').textContent"), "tab switch without effect"
        viol = await p.js("JSON.stringify(window.__csp===undefined?['(kein Listener)']:window.__csp)")
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
            await p.js("window.confirm=()=>true")           # confirm the button's prompt
            await asyncio.sleep(1.5)                        # … now the confirmation is too old
            await p.click("[data-act=deltotp]")
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
        await p.js("window.confirm=()=>true")
        await p.js(f"offer({response}).then(()=>{{window.__offer_fertig=true}});1")
        await asyncio.sleep(1.2)
        assert await p.js("window.__offer_fertig===true"), "offer() did not return"
        assert showcase.auth.store.get_session(other) is None, \
            "offer confirmed, yet the other session keeps running"
        # Freshness expired: detour via reauth, the consent travels along as ?revoke_others=1.
        other, _ = showcase.auth.start_session(demoadmin_id, "password")
        try:
            showcase.auth.cfg.stepup_max_age_sec = 1
            await asyncio.sleep(1.5)
            await p.js(f"offer({response});1")
            await asyncio.sleep(1.4)
            destination = await p.js("location.pathname + decodeURIComponent(location.search)")
            assert destination.startswith("/auth/reauth") and "/auth/account?revoke_others=1" in destination, \
                f"stayed on {destination!r} — the consent would be lost"
            assert showcase.auth.store.get_session(other) is not None, "ended without freshness"
        finally:
            showcase.auth.cfg.stepup_max_age_sec = before_fresh   # ≙ reauth passed
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source="window.confirm=()=>true")
        await p.go("/auth/account?revoke_others=1", wait=1.8)
        assert showcase.auth.store.get_session(other) is None, \
            "not asked/ended after the reauth — the consent is lost"
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


try:
    asyncio.run(run())
    print("OK test_browser")
finally:
    _chrome.terminate()
    _server.should_exit = True
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
