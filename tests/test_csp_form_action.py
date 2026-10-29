"""CSP `form-action` in a REAL browser (0.24.13, DAST 2026-10-11, ZAP 10055-13).

`form-action` does not fall back to `default-src`. If the directive is missing, an injected form may submit
anywhere. Chrome also checks it on the redirect AFTER submitting — a list with only `'self'` would therefore have broken every
sign-in with `next` to a protected host, signing out at the provider and “Weiter als …”.

  (a) header: `form-action 'self'` plus base_url, issuer and `trusted_redirect_hosts` as `name:*`
  (b) Chrome: sign-in with `next` to an allowed second host → the redirect arrives there
  (c) Chrome: a form to a foreign origin is blocked — the foreign server sees no request

Mutations 2026-10-11: hosts from `trusted_redirect_hosts` not in form-action → (b) red; `form-action` removed entirely → (c)
red.
"""
import asyncio
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from voraussetzung import braucht, braucht_modul  # noqa: E402

braucht_modul("websockets")
braucht_modul("uvicorn")
import uvicorn  # noqa: E402
import websockets  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

CHROME = next((b for b in ("google-chrome", "chrome", "chromium", "chromium-browser") if shutil.which(b)), None)
braucht(CHROME, "no Chrome found")


def ok(text):
    print(f"  ok   {text}")


def _sock():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(64)
    return s


# Target server on a second port: allowed as `localhost`, foreign as `127.0.0.1` (different origin than the app).
ZIEL_AUFRUFE = []


class _Ziel(http.server.BaseHTTPRequestHandler):
    def _antwort(self):
        ZIEL_AUFRUFE.append((self.command, self.path))
        body = b"<!doctype html><title>ziel</title>angekommen"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _antwort

    def log_message(self, *a):
        pass


_ziel_sock = _sock()
ZIEL = _ziel_sock.getsockname()[1]
_zs = http.server.HTTPServer(("127.0.0.1", ZIEL), _Ziel, bind_and_activate=False)
_zs.socket = _ziel_sock
threading.Thread(target=_zs.serve_forever, daemon=True).start()

_app_sock = _sock()
APP = _app_sock.getsockname()[1]
BASE = f"http://127.0.0.1:{APP}"
auth = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
                                 csrf_enabled=False, passkey_enabled=False, base_url=BASE, lang="de",
                                 trusted_redirect_hosts=["localhost"]))
auth.set_security("rate_limit_max", 100000)
auth.create_user("anna", "Richtiges-Pw-2026")
app = FastAPI()
app.include_router(auth.router())
_srv = uvicorn.Server(uvicorn.Config(app, log_level="critical"))
threading.Thread(target=lambda: _srv.run(sockets=[_app_sock]), daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(f"{BASE}/auth/login", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("App does not start")

print("CSP form-action")

# (a)
kopf = urllib.request.urlopen(f"{BASE}/auth/login").headers["Content-Security-Policy"]
fa = [d.strip() for d in kopf.split(";") if d.strip().startswith("form-action")]
assert fa and fa[0].split()[1] == "'self'" and "localhost:*" in fa[0].split() and f"127.0.0.1:{APP}" in fa[0], kopf
ok(f"Kopf: {fa[0]}")

_profil = tempfile.mkdtemp()
_log = tempfile.NamedTemporaryFile(prefix="chrome-", suffix=".log", delete=False)
_chrome = subprocess.Popen([CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
                            f"--user-data-dir={_profil}", "--remote-debugging-port=0", "about:blank"],
                           stdout=_log, stderr=subprocess.STDOUT)


def _ws_url():
    datei = os.path.join(_profil, "DevToolsActivePort")
    ende = time.time() + float(os.environ.get("CHROME_START_TIMEOUT", "30"))
    while time.time() < ende:
        if _chrome.poll() is not None:
            raise RuntimeError(f"Chrome gestorben (Exit {_chrome.returncode})")
        try:
            with open(datei, encoding="utf-8") as fh:
                port = int(fh.readline().strip())
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
            return [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("Chrome does not respond")


async def _lauf():
    async with websockets.connect(_ws_url(), max_size=None) as ws:
        n = [0]

        async def cmd(method, **params):
            n[0] += 1
            await ws.send(json.dumps({"id": n[0], "method": method, "params": params}))
            while True:
                m = json.loads(await ws.recv())
                if m.get("id") == n[0]:
                    return m.get("result", {})

        async def js(expr):
            r = await cmd("Runtime.evaluate", expression=expr, returnByValue=True)
            return r.get("result", {}).get("value")

        async def warte_auf(pruef, sek=10):
            for _ in range(int(sek / 0.2)):
                if await pruef():
                    return True
                await asyncio.sleep(0.2)
            return False

        await cmd("Page.enable")
        # (b) Sign-in with next to the allowed second host
        ziel = f"http://localhost:{ZIEL}/ziel"
        await cmd("Page.navigate", url=f"{BASE}/auth/login?next={ziel}")
        await warte_auf(lambda: js("!!document.querySelector('input[name=password]')"))
        await js("document.querySelector('input[name=username]').value='anna';"
                 "document.querySelector('input[name=password]').value='Richtiges-Pw-2026';"
                 "document.querySelector('input[name=password]').form.submit()")
        angekommen = await warte_auf(lambda: js(f"location.href === {json.dumps(ziel)}"))
        assert angekommen, (await js("location.href"), ZIEL_AUFRUFE)
        ok("sign-in with next to an allowed host: Chrome follows the redirect")

        # (c) injected form to a foreign origin
        # Signed out, otherwise /auth/login redirects — to a page of the test app without CSP, and the probe measures nothing.
        await cmd("Network.enable")
        await cmd("Network.clearBrowserCookies")
        await cmd("Page.navigate", url=f"{BASE}/auth/login")
        assert await warte_auf(lambda: js("!!document.querySelector('input[name=password]')")), await js("location.href")
        vorher = len(ZIEL_AUFRUFE)
        fremd = f"http://127.0.0.1:{ZIEL}/fremd"
        await js(f"const f=document.createElement('form');f.method='post';f.action={json.dumps(fremd)};"
                 "document.body.appendChild(f);f.submit()")
        await asyncio.sleep(2)
        assert not any(p == "/fremd" for _, p in ZIEL_AUFRUFE[vorher:]), ZIEL_AUFRUFE
        assert (await js("location.href")).startswith(BASE), await js("location.href")
        ok("form to a foreign origin: blocked, the foreign server sees nothing")


try:
    asyncio.run(_lauf())
finally:
    _chrome.terminate()
print("CSP form-action OK")
