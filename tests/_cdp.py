"""A small headless Chrome over the DevTools protocol for the browser suites besides tests/test_browser.py (T-103).

`Chrome` starts the browser the suites agree on (`voraussetzung.find_chrome`, read once before the timed start, B-13)
with a port of its own choosing (`DevToolsActivePort`, no race), `Page` drives one tab: navigate, evaluate, wait,
real key presses, and it records console errors, uncaught exceptions, CSP violations and failed requests.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request

from voraussetzung import prewarm_chrome

START_TIMEOUT = float(os.environ.get("CHROME_START_TIMEOUT", "30"))

#: Installed in every new document: CSP violations do not reach the console, they are collected in the page.
CSP_PROBE = ("window.__csp=[];addEventListener('securitypolicyviolation',function(e){"
             "window.__csp.push(e.effectiveDirective+' blocked '+(e.blockedURI||'inline'))});")


class Chrome:
    def __init__(self, chrome: str):
        self.profile = tempfile.mkdtemp(prefix="cdp-")
        prewarm_chrome(chrome)
        self.log = tempfile.NamedTemporaryFile(prefix="chrome-", suffix=".log", delete=False)
        self.proc = subprocess.Popen(
            [chrome, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
             "--window-size=1280,900", f"--user-data-dir={self.profile}", "--remote-debugging-port=0", "about:blank"],
            stdout=self.log, stderr=subprocess.STDOUT)
        self.port = self._port()

    def _output(self) -> str:
        try:
            self.log.flush()
            with open(self.log.name, encoding="utf-8", errors="replace") as fh:
                return fh.read().strip()[-2000:]
        except OSError:
            return "(no output)"

    def _port(self) -> int:
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"Chrome died at startup (exit {self.proc.returncode}):\n{self._output()}")
            try:
                with open(os.path.join(self.profile, "DevToolsActivePort"), encoding="utf-8") as fh:
                    first = fh.readline().strip()
                if first.isdigit():
                    return int(first)
            except OSError:
                pass  # not written yet: Chrome is still starting
            time.sleep(0.1)
        raise RuntimeError(f"Chrome wrote no DevTools port (after {START_TIMEOUT:.0f}s):\n{self._output()}")

    def new_tab(self) -> str:
        """A fresh tab; its websocket address."""
        deadline = time.time() + START_TIMEOUT
        while True:
            try:
                tab = json.load(urllib.request.urlopen(urllib.request.Request(
                    f"http://127.0.0.1:{self.port}/json/new?about:blank", method="PUT"), timeout=5))
                return tab["webSocketDebuggerUrl"]
            except OSError:
                if time.time() > deadline:
                    raise
                time.sleep(0.2)

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)
        try:
            self.log.close()
            os.unlink(self.log.name)
        except OSError:
            pass  # already gone


class Page:
    """One tab: commands, evaluation, waiting; console errors and failed requests are kept."""

    def __init__(self, ws):
        self.ws, self._id = ws, 0
        self.console, self.failed = [], []

    async def start(self):
        for domain in ("Page", "Runtime", "Network"):
            await self.cmd(f"{domain}.enable")
        await self.cmd("Page.addScriptToEvaluateOnNewDocument", source=CSP_PROBE)

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
                if r["status"] >= 400:
                    self.failed.append((r["status"], r["url"]))
            if m.get("id") == self._id:
                return m.get("result", {})

    async def js(self, expr):
        r = await self.cmd("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
        if "exceptionDetails" in r:
            raise AssertionError(f"JS error: {r['exceptionDetails'].get('text')} — {expr[:80]}")
        return r.get("result", {}).get("value")

    async def go(self, url, ready="true"):
        """Navigate and wait for the new document to be complete and `ready` (a JS condition) to hold."""
        await self.js("window.__old=true")
        await self.cmd("Page.navigate", url=url)
        await self.until(f"window.__old===undefined && document.readyState==='complete' && ({ready})",
                         f"{url} did not load")

    async def until(self, expr, why, tries=80):
        error = ""
        for _ in range(tries):
            try:
                if await self.js(expr):
                    return
                error = ""
            except AssertionError as e:
                error = str(e)
            await asyncio.sleep(0.25)
        raise AssertionError(f"{why} (at {await self.js('location.href')!r})"
                             + (f" — the condition threw: {error}" if error else ""))

    async def key(self, name):
        code = {"Escape": 27, "Enter": 13, "Tab": 9}[name]
        for kind in ("rawKeyDown", "keyUp"):
            await self.cmd("Input.dispatchKeyEvent", type=kind, key=name, code=name, windowsVirtualKeyCode=code,
                           nativeVirtualKeyCode=code)

    async def csp(self) -> list:
        return json.loads(await self.js("JSON.stringify(window.__csp===undefined?['(no listener)']:window.__csp)"))

    async def frames(self):
        await self.js("new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r)))")
