"""Shared pieces of the browser suites that run a whole stack: a server on a bound socket, the viewport and theme, the
clean-page check, screenshots, and a small forward-auth proxy that does what the Caddy template does.

The proxy, on the bytes: the sign-in host and `/.tinysesam/*` on the application's host go to TinySesam; every other
request on the application's host first to `/auth/forward`, then — with the `Remote-*` headers of the answer and
without the browser's cookies (spec §2.1, duty 4) — to the application; a 401 with `X-TinySesam-Location` (a page view
without a session) becomes the redirect to that sign-in address. One request per connection.
"""
from __future__ import annotations

import asyncio
import base64
import os
import socket
import threading
import time

try:
    import uvicorn
except ImportError:      # the extra `gateway`; every suite that serves checks it first (`braucht_modul`)
    uvicorn = None

SHOTS = os.environ.get("TINYSESAM_SCREENSHOTS", "")
SIZES = ((375, 812), (1280, 900))
HOP = {"connection", "keep-alive", "transfer-encoding", "content-length", "host", "proxy-connection"}


def serve(app):
    """Run an ASGI app on a socket that stays bound (no port race), in a thread; (port, uvicorn server). The suite
    checks `uvicorn` first (`braucht_modul`): it belongs to the extra `gateway`."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical"))
    threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("the server does not start")
    return sock.getsockname()[1], server


def free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


async def shot(p, name: str) -> None:
    if not SHOTS:
        return
    os.makedirs(SHOTS, exist_ok=True)
    data = (await p.cmd("Page.captureScreenshot", format="png"))["data"]
    with open(os.path.join(SHOTS, f"{name}.png"), "wb") as fh:
        fh.write(base64.b64decode(data))


async def view(p, width: int, height: int, theme: str) -> None:
    await p.cmd("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1,
                mobile=width < 500)
    await p.js(f"localStorage.setItem('themeMode','{theme}');true")


async def sign_in_with_provider(p, name: str, done: str) -> None:
    """From TinySesam's sign-in page through the identity provider of `_test_idp` as `name` (T-107): the page's
    provider button, the provider's page, its button for `name`; then wait for `done` (a JS condition of the page
    the round ends on)."""
    await p.until("!!document.querySelector('a[href*=\"/auth/oidc/start\"]')", "no provider button on the page")
    await p.js("window.__old=true;document.querySelector('a[href*=\"/auth/oidc/start\"]').click();true")
    await p.until(f"window.__old===undefined&&!!document.getElementById('idp-{name}')", "no provider page")
    await p.js(f"window.__old=true;document.getElementById('idp-{name}').click();true")
    try:
        await p.until(f"window.__old===undefined&&document.readyState==='complete'&&{done}",
                      f"the provider's round for {name} did not end where expected")
    except AssertionError as e:
        text = await p.js("document.body?document.body.innerText.slice(0,300):''")
        raise AssertionError(f"{e} — the page says: {text!r}") from None


async def clean(p, where: str, console_before: int, failed_before: int) -> None:
    viol = await p.csp()
    assert viol == [], f"CSP violation on {where}: {viol}"
    assert len(p.console) == console_before, f"console errors on {where}: {p.console[console_before:][:2]}"
    assert p.failed[failed_before:] == [], f"broken requests on {where}: {p.failed[failed_before:][:3]}"
    assert await p.js("document.documentElement.scrollWidth<=innerWidth"), f"{where}: sideways scrolling"


class ForwardProxy:
    """The proxy in front of the stack; `auth_name` and `app_name` are the host names without port."""

    def __init__(self, ts_port: int, app_port: int, *, auth_name: str, app_name: str):
        self.ts_port, self.app_port, self.auth_name, self.app_name = ts_port, app_port, auth_name, app_name
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.server = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, sock=self.sock)

    def close(self) -> None:
        if self.server is not None:
            self.server.close()

    @staticmethod
    async def _upstream(port: int, method: str, target: str, headers: list, body: bytes) -> bytes:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        head = "".join(f"{k}: {v}\r\n" for k, v in headers)
        w.write(f"{method} {target} HTTP/1.1\r\n{head}Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                .encode("latin-1") + body)
        await w.drain()
        data = await r.read()
        w.close()
        return data

    @staticmethod
    def _status_and_headers(raw: bytes) -> tuple[int, list]:
        lines = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        return int(lines[0].split(" ", 2)[1]), [tuple(x.strip() for x in z.split(":", 1)) for z in lines[1:] if ":" in z]

    async def _handle(self, reader, writer):
        try:
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1").split("\r\n")
            method, target = head[0].split(" ")[:2]
            pairs = [tuple(x.strip() for x in z.split(":", 1)) for z in head[1:] if ":" in z]
            low = {k.lower(): v for k, v in pairs}
            body = await reader.readexactly(int(low.get("content-length") or 0))
            host = low.get("host", "")
            name = host.split(":")[0]
            own = [(k, v) for k, v in pairs
                   if k.lower() not in HOP and not k.lower().startswith(("remote-", "x-forwarded-"))]
            fwd = [("X-Forwarded-Host", host), ("X-Forwarded-Proto", "http"), ("X-Forwarded-For", "127.0.0.1")]
            if name == self.auth_name or (name == self.app_name and target.startswith("/.tinysesam/")):
                out = await self._upstream(self.ts_port, method, target, own + fwd + [("Host", host)], body)
            elif name == self.app_name:
                check = await self._upstream(self.ts_port, "GET", "/auth/forward", [
                    ("Cookie", low.get("cookie", "")), ("Accept", low.get("accept", "")), ("X-Forwarded-Uri", target),
                    ("X-Forwarded-Method", method), *fwd, ("Host", f"{self.auth_name}:{self.port}")], b"")
                status, answer = self._status_and_headers(check)
                to = next((v for k, v in answer if k.lower() == "x-tinysesam-location"), "")
                if status == 401 and to:
                    # What the Caddy template does with a page view: the sign-in address of the answer as a redirect.
                    out = (f"HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\n"
                           "Connection: close\r\n\r\n").encode("latin-1")
                elif not 200 <= status < 300:
                    out = check
                else:
                    passed = [(k, v) for k, v in answer if k.lower().startswith("remote-")]
                    out = await self._upstream(self.app_port, method, target,
                                               [(k, v) for k, v in own if k.lower() != "cookie"] + passed
                                               + [("Host", host)], body)
            else:
                out = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            writer.write(out)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass  # the browser gave up the connection (a preconnect it never used)
        finally:
            writer.close()
