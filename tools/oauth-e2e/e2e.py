#!/usr/bin/env python3
"""End-to-end check of the OAuth authorization server (T-36) with the REAL Claude Code CLI.

Manual and optional — not part of the CI: it needs the `claude` CLI, Docker (Caddy), Google Chrome and
OpenSSL. Everything runs on 127.0.0.1 in a throwaway directory; your own Claude Code configuration is never
touched (`CLAUDE_CONFIG_DIR` points into the work directory).

    python tools/oauth-e2e/e2e.py [--work DIR] [--keep]

What runs:

* TinySesam in this process (uvicorn, plain HTTP on 127.0.0.1), chain password + TOTP, OAuth on, access
  tokens 60 s (so a restart of the CLI must refresh).
* Caddy in a container (`--network host`, every site bound to 127.0.0.1) with a Caddyfile GENERATED from
  `deploy/forward-auth/Caddyfile` — the template itself is under test, only host names and TLS files change.
* A minimal MCP server (JSON-RPC over HTTP, tool `whoami`) behind Caddy's forward auth — no OAuth code in it.
* A model stand-in (`ANTHROPIC_BASE_URL`): it answers with a `tool_use` of `mcp__ts__whoami`, so the CLI
  itself executes the MCP `tools/call`. No Anthropic account and no real model are involved.
* `claude mcp login --no-browser` in a pseudo terminal; the authorization URL goes to headless Chrome, which
  signs in (password + TOTP) and allows the access on the consent page.

The acceptance list (each step prints ✅/❌ and lands with evidence in <work>/report.jsonl):

1. `claude mcp add --transport http` → sign-in → the tool answers with the signed-in account
2. a new CLI process after the access token expired: works without a sign-in (silent refresh)
3. the device is disconnected on the account page → 401 → a new sign-in is needed
4. an old refresh token presented again → the family is revoked (audit) → a new sign-in is needed
5. the account is locked → access gone
6. `claude mcp logout` revokes the tokens at the server (RFC 7009)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import pty
import re
import secrets
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

CADDY_IMAGE = "caddy:2.11.8@sha256:4fcafa98afd1c2e642e353e3c5cf9ddbe892fcee14bc990e7ba2c5b78e51f9cf"
SERVER = "ts"
TOOL = f"mcp__{SERVER}__whoami"
USER, PASSWORD = "alice", "alice-pw-12345"


def as_alice(text: str) -> bool:
    """The model stand-in quoted a tool result that names alice as Remote-User."""
    return "TOOL_RESULT" in text and "remote_user" in text and "alice" in text


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Report:
    def __init__(self, path):
        self.path, self.results = path, []

    def log(self, event, **kw):
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": round(time.time(), 3), "event": event, **kw}) + "\n")

    def check(self, name, ok, evidence=""):
        self.results.append((name, bool(ok)))
        self.log("check", name=name, ok=bool(ok), evidence=evidence)
        print(f"{'✅' if ok else '❌'} {name}" + (f"  — {evidence}" if evidence else ""), flush=True)


# ---------------------------------------------------------------- certificates
def make_certs(d):
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=TinySesam e2e CA",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", f"{d}/ca.key", "-out", f"{d}/ca.pem")
    with open(f"{d}/ext.cnf", "w") as fh:
        fh.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                 "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", f"{d}/leaf.key",
        "-out", f"{d}/leaf.csr")
    run("openssl", "x509", "-req", "-in", f"{d}/leaf.csr", "-CA", f"{d}/ca.pem", "-CAkey", f"{d}/ca.key",
        "-CAcreateserial", "-days", "2", "-extfile", f"{d}/ext.cnf", "-out", f"{d}/leaf.pem")
    for f in ("leaf.key", "leaf.pem", "ca.pem"):
        os.chmod(f"{d}/{f}", 0o644)        # read by the Caddy container's user


def caddyfile(auth_port, app_port, ts_up, app_up) -> str:
    """The repo template with this test's addresses: two sites, own certificate, bound to 127.0.0.1."""
    text = open(os.path.join(ROOT, "deploy", "forward-auth", "Caddyfile"), encoding="utf-8").read()
    tls = "\n\tbind 127.0.0.1\n\ttls /certs/leaf.pem /certs/leaf.key"
    assert text.count("auth.example.com {") == 1 and text.count("app.example.com {") == 1
    text = text.replace("auth.example.com {", f"https://localhost:{auth_port} {{{tls}", 1)
    text = text.replace("app.example.com {", f"https://127.0.0.1:{app_port} {{{tls}", 1)
    text = text.replace("{$TS_AUTH_UPSTREAM:127.0.0.1:8000}", ts_up).replace("{$TS_APP_UPSTREAM:127.0.0.1:9000}", app_up)
    return "{\n\tadmin off\n\tauto_https off\n\tskip_install_trust\n}\n" + text


# ---------------------------------------------------------------- the MCP server (no OAuth code)
def mcp_app(report):
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Route

    async def mcp(request):
        if request.method != "POST":
            return Response(status_code=405)
        body = await request.json()
        out = []
        for m in body if isinstance(body, list) else [body]:
            method, mid = m.get("method"), m.get("id")
            report.log("mcp_rpc", method=method, remote_user=request.headers.get("remote-user"))
            if mid is None:
                continue
            if method == "initialize":
                res = {"protocolVersion": (m.get("params") or {}).get("protocolVersion", "2025-06-18"),
                       "capabilities": {"tools": {}}, "serverInfo": {"name": "tinysesam-e2e", "version": "1"}}
            elif method == "tools/list":
                res = {"tools": [{"name": "whoami", "description": "Who the gate says is calling",
                                  "inputSchema": {"type": "object", "properties": {}}}]}
            elif method == "tools/call":
                res = {"content": [{"type": "text", "text": json.dumps(
                    {"remote_user": request.headers.get("remote-user"),
                     "remote_groups": request.headers.get("remote-groups")})}]}
            elif method == "ping":
                res = {}
            else:
                out.append({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown"}})
                continue
            out.append({"jsonrpc": "2.0", "id": mid, "result": res})
        if not out:
            return Response(status_code=202)
        return JSONResponse(out if isinstance(body, list) else out[0])

    return Starlette(routes=[Route("/mcp", mcp, methods=["GET", "POST", "DELETE"])])


# ---------------------------------------------------------------- the model stand-in
def model_app(report):
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse, StreamingResponse
    from starlette.routing import Route

    def plan(body):
        msgs = body.get("messages") or []
        tools = [t.get("name") for t in body.get("tools") or []]
        called = {c["id"]: c["name"] for m in msgs if m.get("role") == "assistant" and isinstance(m.get("content"), list)
                  for c in m["content"] if c.get("type") == "tool_use"}
        last = msgs[-1] if msgs else {}
        results = [c for c in last.get("content") or [] if isinstance(c, dict) and c.get("type") == "tool_result"]
        tid = "toolu_" + uuid.uuid4().hex[:20]
        if results and called.get(results[0].get("tool_use_id")) == TOOL:
            return [{"type": "text", "text": "TOOL_RESULT " + json.dumps(results[0].get("content"))[:600]}], "end_turn"
        if TOOL in tools:
            return [{"type": "tool_use", "id": tid, "name": TOOL, "input": {}}], "tool_use"
        if "ToolSearch" in tools and "ToolSearch" not in called.values():
            return [{"type": "tool_use", "id": tid, "name": "ToolSearch",
                     "input": {"query": "select:" + TOOL, "max_results": 1}}], "tool_use"
        return [{"type": "text", "text": f"NO_TOOL {[t for t in tools if t and t.startswith('mcp__')]}"}], "end_turn"

    async def messages(request):
        body = await request.json()
        content, stop = plan(body)
        report.log("model", stop=stop, answer=content)
        msg = {"id": "msg_" + uuid.uuid4().hex[:20], "type": "message", "role": "assistant",
               "model": body.get("model", "stand-in"), "content": content, "stop_reason": stop,
               "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}
        if not body.get("stream"):
            return JSONResponse(msg)

        def sse():
            ev = lambda n, d: f"event: {n}\ndata: {json.dumps(d)}\n\n"  # noqa: E731
            yield ev("message_start", {"type": "message_start", "message": dict(msg, content=[], stop_reason=None)})
            for i, c in enumerate(content):
                if c["type"] == "text":
                    yield ev("content_block_start", {"type": "content_block_start", "index": i,
                                                     "content_block": {"type": "text", "text": ""}})
                    yield ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                     "delta": {"type": "text_delta", "text": c["text"]}})
                else:
                    yield ev("content_block_start", {"type": "content_block_start", "index": i,
                                                     "content_block": dict(c, input={})})
                    yield ev("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {
                        "type": "input_json_delta", "partial_json": json.dumps(c["input"])}})
                yield ev("content_block_stop", {"type": "content_block_stop", "index": i})
            yield ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                       "usage": {"output_tokens": 1}})
            yield ev("message_stop", {"type": "message_stop"})
        return StreamingResponse(sse(), media_type="text/event-stream")

    async def count(request):
        return JSONResponse({"input_tokens": 1})

    async def other(request):
        return JSONResponse({}, status_code=404)

    return Starlette(routes=[Route("/v1/messages", messages, methods=["POST"]),
                             Route("/v1/messages/count_tokens", count, methods=["POST"]),
                             Route("/{p:path}", other, methods=["GET", "POST"])])


def serve(app, port):
    import uvicorn
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            return server
        time.sleep(0.05)
    raise RuntimeError(f"server on {port} did not start")


# ---------------------------------------------------------------- headless Chrome
class Browser:
    def __init__(self, work, totp_secret, report):
        self.work, self.secret, self.report, self.last_code = work, totp_secret, report, ""

    def totp(self):
        import pyotp
        code = pyotp.TOTP(self.secret).now()
        while code == self.last_code:          # TinySesam accepts a code exactly once
            time.sleep(2)
            code = pyotp.TOTP(self.secret).now()
        self.last_code = code
        return code

    async def _session(self, url, goal):
        import websockets
        profile = tempfile.mkdtemp(prefix="chrome-", dir=self.work)
        chrome = subprocess.Popen(["google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox",
                                   "--disable-dev-shm-usage", "--ignore-certificate-errors",
                                   f"--user-data-dir={profile}", "--remote-debugging-port=0", "--no-first-run",
                                   "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            port_file = os.path.join(profile, "DevToolsActivePort")
            for _ in range(300):
                if os.path.exists(port_file) and open(port_file).read().strip():
                    break
                time.sleep(0.1)
            port = open(port_file).read().split()[0]
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
            ws_url = [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
            async with websockets.connect(ws_url, max_size=30_000_000) as ws:
                n = 0
                events = []

                async def cmd(method, **params):
                    nonlocal n
                    n += 1
                    await ws.send(json.dumps({"id": n, "method": method, "params": params}))
                    while True:
                        m = json.loads(await ws.recv())
                        if m.get("id") == n:
                            return m.get("result", {})
                        events.append(m)

                async def js(expr):
                    r = await cmd("Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True)
                    return r.get("result", {}).get("value")

                await cmd("Page.enable")
                await cmd("Network.enable")
                await cmd("Page.navigate", url=url)
                return await goal(js, events)
        finally:
            chrome.terminate()
            chrome.wait(10)
            shutil.rmtree(profile, ignore_errors=True)

    async def _drive(self, js, done, events):
        acted, deadline = set(), time.time() + 90
        while time.time() < deadline:
            await asyncio.sleep(0.5)
            href = await js("location.href") or ""
            result = await done(js, href, events)
            if result is not None:
                return result
            state = await js("""(()=>{const q=s=>document.querySelector(s);
              if(q('input[name=password]')&&q('input[name=username]'))return 'login';
              if(q('#oaallow'))return 'consent'; if(q('input[name=code]'))return 'totp'; return 'other'})()""")
            if (href, state) in acted or state == "other":
                continue
            acted.add((href, state))
            if state == "login":
                await js(f"""(()=>{{document.querySelector('input[name=username]').value={json.dumps(USER)};
                  document.querySelector('input[name=password]').value={json.dumps(PASSWORD)};
                  document.querySelector('input[name=password]').form.submit()}})()""")
            elif state == "totp":
                code = self.totp()
                await js(f"(()=>{{const i=document.querySelector('input[name=code]');i.value={json.dumps(code)};"
                         "i.form.submit()})()")
            elif state == "consent":
                info = await js("JSON.stringify({client:document.getElementById('oaclient').innerText,"
                                "host:document.getElementById('oarhost').innerText,"
                                "csp:!!document.querySelector('form')})")
                self.report.log("consent_page", info=info)
                await js("document.getElementById('oaallow').click()")
            self.report.log("browser_act", state=state, url=href[:200])
        raise RuntimeError("browser: no result within 90 s")

    def authorize(self, url):
        async def done(js, href, events):
            if href.startswith(("http://localhost", "http://127.0.0.1")):
                return href
            if href.startswith("chrome-error"):
                docs = [e["params"]["request"]["url"] for e in events
                        if e.get("method") == "Network.requestWillBeSent" and e["params"].get("type") == "Document"]
                loop = [u for u in docs if u.startswith(("http://localhost", "http://127.0.0.1"))]
                return loop[-1] if loop else "ERROR"
            return None
        return asyncio.run(self._session(url, lambda js, ev: self._drive(js, done, ev)))

    def disconnect_device(self, account_url):
        async def done(js, href, events):
            if href.startswith(account_url) and await js("!!document.getElementById('devlist')"):
                n = await js("document.querySelectorAll('#devlist form.devrevoke').length")
                if n:
                    await js("document.querySelector('#devlist form.devrevoke button').click()")
                    await asyncio.sleep(1.5)
                    return n
            return None
        return asyncio.run(self._session(account_url, lambda js, ev: self._drive(js, done, ev)))


# ---------------------------------------------------------------- the CLI
class CLI:
    def __init__(self, work, env, report):
        self.work, self.env, self.report = work, env, report
        os.makedirs(f"{work}/project", exist_ok=True)

    def run(self, *args, timeout=120):
        r = subprocess.run(["claude", *args], cwd=f"{self.work}/project", env=self.env, capture_output=True,
                           stdin=subprocess.DEVNULL, text=True, timeout=timeout)
        out = (r.stdout + r.stderr).strip()
        self.report.log("cli", args=list(args), rc=r.returncode, out=out[-1500:])
        return out

    def status(self):
        out = self.run("mcp", "get", SERVER, timeout=90)
        m = re.search(r"Status:\s*(.+)", out)
        return (m.group(1) if m else out[-200:]).strip()

    def tool(self):
        return self.run("-p", "Call the whoami tool.", "--allowedTools", TOOL, "--output-format", "text", timeout=180)

    def credentials(self):
        try:
            data = json.load(open(f"{self.env['CLAUDE_CONFIG_DIR']}/.credentials.json"))
        except OSError:
            return {}
        return next(iter(data.get("mcpOAuth", {}).values()), {})

    def login(self, browser):
        """`claude mcp login --no-browser` in a pty; the printed URL goes to the browser."""
        ansi = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.chdir(f"{self.work}/project")
                os.execvpe("claude", ["claude", "mcp", "login", SERVER, "--no-browser"], self.env)
            finally:
                os._exit(127)          # never let the forked child run the rest of this script
        buf, t0, handed = "", time.time(), False
        result = None
        while time.time() - t0 < 150:
            r, _, _ = select.select([fd], [], [], 0.5)
            if r:
                try:
                    buf += ansi.sub("", os.read(fd, 65536).decode(errors="replace"))
                except OSError:
                    break
            if not handed:
                m = re.search(r"(https://\S+?/auth/oauth/authorize\?\S+)", buf.replace("\n", " "))
                if m:
                    handed = True
                    url = m.group(1)
                    self.report.log("authorize_url", url=re.sub(r"code_challenge=[^&]+", "code_challenge=…", url))
                    result = browser.authorize(url)
                    self.report.log("callback", url=re.sub(r"code=[^&]+", "code=…", result or ""))
                    if result and result != "ERROR" and "Paste" in buf:
                        os.write(fd, (result + "\r").encode())
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid:
                while select.select([fd], [], [], 0.3)[0]:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    buf += ansi.sub("", chunk.decode(errors="replace"))
                break
        else:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        tail = buf[-800:]
        self.report.log("login_output", out=tail)
        return "Authenticated" in buf or "uccess" in buf, tail


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default="")
    ap.add_argument("--keep", action="store_true", help="keep the work directory")
    a = ap.parse_args()
    work = os.path.abspath(a.work or tempfile.mkdtemp(prefix="tinysesam-oauth-e2e-"))
    os.makedirs(work, exist_ok=True)
    report = Report(f"{work}/report.jsonl")
    version = subprocess.run(["claude", "--version"], capture_output=True, text=True).stdout.strip()
    report.log("start", claude=version, work=work)
    print(f"Claude Code {version}; work directory {work}", flush=True)

    os.makedirs(f"{work}/certs", exist_ok=True)
    make_certs(f"{work}/certs")
    auth_port, app_port, ts_up, app_up, model_port = (free_port() for _ in range(5))
    base, resource = f"https://localhost:{auth_port}", f"https://127.0.0.1:{app_port}/mcp"

    from tinysesam import TinySesam, TinySesamConfig
    from fastapi import FastAPI
    auth = TinySesam(TinySesamConfig(
        db_path=f"{work}/tinysesam.db", base_url=base, rp_name="TinySesam e2e", lang="en", passkey_enabled=False,
        login_chain=["password", "totp"], forward_auth_enabled=True, trusted_redirect_hosts=["127.0.0.1"],
        oauth_enabled=True, oauth_resources=[resource], oauth_access_token_ttl_sec=60))
    auth.set_security("password_min_length_single_factor", 8)
    uid = auth.create_user(USER, password=PASSWORD)
    auth.totp_begin(uid)
    auth.store.confirm_totp(uid)
    secret = auth.store.get_totp(uid)["secret"]
    app = FastAPI()
    app.include_router(auth.router())
    servers = [serve(app, ts_up), serve(mcp_app(report), app_up), serve(model_app(report), model_port)]

    with open(f"{work}/Caddyfile", "w") as fh:
        fh.write(caddyfile(auth_port, app_port, f"127.0.0.1:{ts_up}", f"127.0.0.1:{app_up}"))
    caddy = f"tinysesam-e2e-{secrets.token_hex(4)}"
    subprocess.run(["sg", "docker", "-c", f"docker run -d --rm --name {caddy} --label tinysesam-e2e=1 "
                    f"--network host -v {work}/Caddyfile:/etc/caddy/Caddyfile:ro -v {work}/certs:/certs:ro "
                    f"{CADDY_IMAGE}"], check=True, capture_output=True)
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(urllib.request.Request(f"{base}/auth/login"), timeout=1,
                                       context=__import__("ssl").create_default_context(cafile=f"{work}/certs/ca.pem"))
                break
            except Exception:
                time.sleep(0.2)
        env = dict(os.environ, CLAUDE_CONFIG_DIR=f"{work}/cc", NODE_EXTRA_CA_CERTS=f"{work}/certs/ca.pem",
                   ANTHROPIC_BASE_URL=f"http://127.0.0.1:{model_port}", ANTHROPIC_API_KEY="stand-in",
                   DISABLE_AUTOUPDATER="1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
        cli, browser = CLI(work, env, report), Browser(work, secret, report)
        audit = lambda: [(e["event"], e["detail"] or "") for e in auth.store.recent_audit(500)]  # noqa: E731

        # 1
        cli.run("mcp", "add", "--transport", "http", SERVER, resource)
        ok, out = cli.login(browser)
        tool = cli.tool()
        report.check("1 mcp add → sign-in (password + TOTP + consent) → tool answers as alice",
                     ok and as_alice(tool) and "admin" not in tool.split("remote_groups")[-1],
                     f"login ok={ok}; status={cli.status()!r}; tool: {tool[-160:]!r}")
        rt0 = cli.credentials().get("refreshToken", "")

        # 2
        time.sleep(65)
        before = sum(1 for e, _ in audit() if e == "oauth_refresh")
        tool = cli.tool()
        after = sum(1 for e, _ in audit() if e == "oauth_refresh")
        rt1 = cli.credentials().get("refreshToken", "")
        report.check("2 new CLI process after the access token expired: works without a sign-in (silent refresh)",
                     as_alice(tool) and after > before and rt1 and rt1 != rt0,
                     f"oauth_refresh audit lines {before}→{after}, refresh token rotated={rt1 != rt0}")

        # 4 (with the tokens of this sign-in): the OLD refresh token again
        cid = cli.credentials().get("clientId", "")
        import ssl
        ctx = ssl.create_default_context(cafile=f"{work}/certs/ca.pem")
        req = urllib.request.Request(f"{base}/auth/oauth/token", method="POST", data=urllib.parse.urlencode(
            {"grant_type": "refresh_token", "refresh_token": rt0, "client_id": cid}).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            urllib.request.urlopen(req, context=ctx)
            answer = "200"
        except urllib.error.HTTPError as e:
            answer = f"{e.code} {e.read().decode()[:120]}"
        st = cli.status()
        tool = cli.tool()
        reuse = [d for e, d in audit() if e in ("oauth_refresh_reuse", "oauth_revoked") and "refresh_reuse" in (d + e)]
        report.check("4 old refresh token presented again → family revoked (audit) → new sign-in needed",
                     answer.startswith("400") and "invalid_grant" in answer and reuse and "alice" not in tool
                     and "auth" in st.lower(),
                     f"token endpoint: {answer}; audit: {reuse[:2]}; status={st!r}")

        # 3
        ok, out = cli.login(browser)
        tool_ok = as_alice(cli.tool())
        n = browser.disconnect_device(f"{base}/auth/account")
        st = cli.status()
        tool = cli.tool()
        denied = [d for e, d in audit() if e == "forward_denied" and "oauth_token" in d]
        report.check("3 device disconnected on the account page → 401 → new sign-in needed",
                     ok and tool_ok and n and "alice" not in tool and "auth" in st.lower(),
                     f"re-login ok={ok}; devices on the page={n}; status={st!r}; forward_denied={denied[:1]}")

        # 5
        ok, out = cli.login(browser)
        tool_ok = as_alice(cli.tool())
        auth.set_disabled(uid, True)
        tool = cli.tool()
        st = cli.status()
        auth.set_disabled(uid, False)
        report.check("5 account locked → access gone at once (and the device is revoked)",
                     ok and tool_ok and "alice" not in tool and "connected" not in st.lower().replace("disconnected", ""),
                     f"re-login ok={ok}; status while locked={st!r}")

        # 6
        ok, out = cli.login(browser)
        before = sum(1 for e, d in audit() if e == "oauth_revoked" and "reason=client" in d)
        cli.run("mcp", "logout", SERVER)
        after = sum(1 for e, d in audit() if e == "oauth_revoked" and "reason=client" in d)
        report.check("6 claude mcp logout revokes at the server (RFC 7009, public client)", ok and after > before,
                     f"oauth_revoked reason=client {before}→{after}")
    finally:
        subprocess.run(["sg", "docker", "-c", f"docker stop {caddy}"], capture_output=True)
        for s in servers:
            s.should_exit = True
    passed = all(ok for _, ok in report.results)
    report.log("end", passed=passed, results=report.results)
    print(("✅ all " if passed else "❌ not all ") + f"{len(report.results)} acceptance steps; evidence: {work}/report.jsonl")
    if not a.keep and passed:
        shutil.rmtree(f"{work}/cc", ignore_errors=True)
        shutil.rmtree(f"{work}/certs", ignore_errors=True)
    return 0 if passed else 1


if __name__ == "__main__":
    import urllib.error
    import urllib.parse
    sys.exit(main())
