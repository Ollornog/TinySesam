"""Gate token through a REAL Caddy with caddy-jwt — the template deploy/forward-auth/Caddyfile.gate.
The share exception (T-20, B-3) is measured against the plain template Caddyfile as well.

The claim of ADR-9 is one about the proxy: with a valid gate cookie a request reaches
the application without TinySesam being asked. That can only be proven with the proxy itself.
Started are TinySesam (uvicorn), a dummy of the application that reports back what arrives
at it, and Caddy with the template from the repo — word for word, only the site addresses point to
a free port and `auto_https` is off.

Caddy with the plugin comes from TINYSESAM_GATE_CADDY (path to the binary). The CI job `gate-caddy`
builds it from deploy/forward-auth/caddy-gate/Dockerfile and sets the variable — if it is set,
the binary is required. Without the variable the suite builds it itself when Docker is there (T-116, cached by content,
tests/_gate_caddy_binary.py) and reports “skipped” naming the missing tool when it is not.
"""
import base64
import http.server
import json
import os
import pathlib
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from voraussetzung import braucht, braucht_modul  # noqa: E402

CADDY = os.environ.get("TINYSESAM_GATE_CADDY", "")
if not CADDY and not os.environ.get("CI"):
    # T-116: on a machine with Docker the binary is built once and kept by content (tests/_gate_caddy_binary.py);
    # without Docker the skip names the missing tool. CI sets the variable itself (and without it, a job
    # of CI that has Docker anyway must not build here).
    from _gate_caddy_binary import ensure_binary  # noqa: E402
    CADDY, _why = ensure_binary()
    braucht(CADDY, f"Caddy with caddy-jwt missing: {_why}")
braucht(CADDY, "TINYSESAM_GATE_CADDY not set (in CI the job gate-caddy builds it)")
braucht_modul("uvicorn")
# Set means required: a wrong path or a Caddy without the plugin is an error, not a skip.
assert os.access(CADDY, os.X_OK), f"TINYSESAM_GATE_CADDY={CADDY!r} is not an executable file"
_module = subprocess.run([CADDY, "list-modules"], capture_output=True, text=True, timeout=30).stdout
assert "http.authentication.providers.jwt" in _module.split(), "this Caddy does not have caddy-jwt"

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import gate, gate_client, keys  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
ISS = "https://auth.example.com"


def ok(name):
    print(f"  ✓ {name}")


def listening_socket():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(128)
    return s


# ---------- TinySesam ----------
_tmp = tempfile.mkdtemp()
auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=os.path.join(_tmp, "t.db"), rp_name="Test",
    passkey_enabled=False, oidc_enabled=False, cookie_secure=False, forward_auth_enabled=True,
    base_url=ISS, trusted_redirect_hosts=["app.example.com", "dav.example.com"], gate_token_enabled=True,
    # A second application that takes app passwords (T-66) — the F1 section below uses one of its passwords at
    # app.example.com.
    forward_apps={"dav.example.com": {"name": "Files", "app_passwords": True}}))
auth.ensure_admin("admin", "dummy123")
uid = auth.create_user("anna", "dummy123", roles=["editors"])
auth.store._exec("UPDATE users SET display_name=? WHERE id=?", ("Anna Ärger", uid))
bot = auth.create_service("backup-bot", roles=["editors"])

FORWARD = {"n": 0}
ts_app = FastAPI()


@ts_app.middleware("http")
async def count(request: Request, call_next):
    if request.url.path == "/auth/forward":
        FORWARD["n"] += 1
    return await call_next(request)

ts_app.include_router(auth.router())
_ts_sock = listening_socket()
TS = f"127.0.0.1:{_ts_sock.getsockname()[1]}"
_ts_server = uvicorn.Server(uvicorn.Config(ts_app, log_level="critical"))
threading.Thread(target=lambda: _ts_server.run(sockets=[_ts_sock]), daemon=True).start()


# ---------- Dummy of the application: reports back what arrives at it ----------
class Application(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _response(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = {k: v for k, v in self.headers.items()}
        b = json.dumps({"path": self.path, "method": self.command,
                        "body": self.rfile.read(n).decode(), "header": raw}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "app_own=1; Path=/")
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = _response


_app_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Application)
APP = f"127.0.0.1:{_app_srv.server_address[1]}"
threading.Thread(target=_app_srv.serve_forever, daemon=True).start()

# Wait until TinySesam responds.
for _ in range(100):
    try:
        urllib.request.urlopen(f"http://{TS}/auth/forward", timeout=1)
    except urllib.error.HTTPError:
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("TinySesam does not start")
FORWARD["n"] = 0


# ---------- Caddy with the template from the repo ----------
#: Public paths for this run (T-20) — the way an operator would set them.
SHARE = "^/(s|public/share)/"


#: The site lines of each template as they stand in the file. The quickstart (deploy/quickstart) names its sites from
#: the environment and selects HSTS through `import tls-{$TS_TLS}` — measured here in mode `acme` (HSTS, no `tls`
#: line), its TLS modes themselves in tests/test_quickstart.py.
SITES = {"Caddyfile.gate": ("\nauth.example.com {", "\napp.example.com {"),
         "Caddyfile": ("\nauth.example.com {", "\napp.example.com {"),
         "../quickstart/Caddyfile": ("\nhttps://{$TS_AUTH_HOST} {", "\nhttps://{$TS_APP_HOST}:{$TS_APP_PORT:443} {")}


def start_caddy(templates_file="Caddyfile.gate", upstream=None, suffix="", transform=None):
    """Caddy needs a port that it binds itself — a bound socket cannot be
    passed on. So find a free one, release it and let Caddy bind; if that fails (another
    process was faster), try again with the next one."""
    template = (ROOT / "deploy/forward-auth" / templates_file).read_text(encoding="utf-8")
    if transform:
        template = transform(template)
    name = (os.path.basename(os.path.dirname(templates_file) or "forward-auth") + "-" + os.path.basename(templates_file)
            + suffix)
    auth_site, app_site = SITES[templates_file]
    for _ in range(5):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        # A template with global options of its own gets the two lines there — a second global block is an error.
        first = next(z for z in template.splitlines() if z.strip() and not z.startswith("#"))
        if first == "{":
            text = template.replace("\n{\n", "\n{\n\tauto_https off\n\tadmin off\n", 1)
        else:
            text = "{\n\tauto_https off\n\tadmin off\n}\n" + template
        text = text.replace(auth_site, f"\nhttp://auth.example.com:{port} {{", 1)
        text = text.replace(app_site, f"\nhttp://app.example.com:{port} {{", 1)
        assert text.count(f":{port} {{") == 2, "the site addresses of the template have shifted"
        file = os.path.join(_tmp, name)
        with open(file, "w", encoding="utf-8") as f:
            f.write(text)
        env = {**os.environ, "TS_GATE_PUBKEY": auth.gate_public_key(), "TS_GATE_ISSUER": ISS,
               "TS_SHARE_PREFIX": SHARE, "TS_TLS": "acme", "TS_AUTH_HOST": "auth.example.com",
               "TS_AUTH_UPSTREAM": upstream or TS, "TS_APP_UPSTREAM": APP, "XDG_DATA_HOME": _tmp,
               "XDG_CONFIG_HOME": _tmp}
        # Popen gives the child its own copy of the file descriptor — the parent process's one
        # may be closed right away.
        with open(os.path.join(_tmp, name + ".log"), "w") as log:
            p = subprocess.Popen([CADDY, "run", "--config", file, "--adapter", "caddyfile"],
                                 stdout=log, stderr=subprocess.STDOUT, env=env)
        for _ in range(100):
            if p.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return p, port
            except OSError:
                time.sleep(0.1)
        p.kill()
    with open(os.path.join(_tmp, name + ".log"), encoding="utf-8", errors="replace") as log:
        raise RuntimeError("Caddy does not start: " + log.read()[-2000:])


_caddy, PORT = start_caddy()
#: The plain template (forward_auth without gate token) carries the same share exception — it needs
#: no plugin, but its own Caddy, and it is measured just the same (B-3).
_caddy_plain, PORT_PLAIN = start_caddy("Caddyfile")
#: The quickstart's Caddyfile (deploy/quickstart) — the plain forward auth in one file per stack, measured alike.
_caddy_quick, PORT_QUICK = start_caddy("../quickstart/Caddyfile")


class _WithoutRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_WithoutRedirect)


def request(path, cookies=None, head=None, method="GET", body=None, port=None):
    """A request to Caddy, host app.example.com. Returns (status, headers, JSON of the dummy)."""
    port = port or PORT
    h = {"Host": f"app.example.com:{port}", **(head or {})}
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h, method=method,
                                 data=body.encode() if body is not None else None)
    try:
        r = _opener.open(req, timeout=10)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, None
    raw = r.read()
    try:
        return r.status, r.headers, json.loads(raw)
    except ValueError:
        return r.status, r.headers, None


def gate_cookie(header):
    for value in header.get_all("Set-Cookie") or []:
        if value.startswith("__Host-tinysesam_gate="):
            return value.split(";", 1)[0].split("=", 1)[1]
    return None


def utf8(value):
    """Headers arrive as Latin-1 with http.client; TinySesam sends UTF-8 over the wire."""
    return value.encode("latin-1").decode("utf-8") if value is not None else None


try:
    # ---------- without sign-in ----------
    st, h, _ = request("/start")
    assert st == 302 and "/auth/login?next=" in h["Location"], (st, dict(h))
    assert FORWARD["n"] == 1
    ok("without sign-in → 302 to the login (way back via /auth/forward)")

    # ---------- session, no gate cookie yet: way back, new token ----------
    from fastapi.testclient import TestClient  # noqa: E402
    tc = TestClient(ts_app)
    tc.post("/auth/login", data={"username": "anna", "password": "dummy123", "next": "/"},
            follow_redirects=False)
    session = {auth.session_cookie_name: tc.cookies.get(auth.session_cookie_name)}
    assert session[auth.session_cookie_name]
    before = FORWARD["n"]
    st, h, a = request("/page", session, {"Remote-User": "admin"}, method="POST", body="field=value")
    assert st == 200, st
    assert FORWARD["n"] == before + 1
    tok = gate_cookie(h)
    assert tok, f"no gate cookie in the response: {h.get_all('Set-Cookie')}"
    assert "app_own=1; Path=/" in (h.get_all("Set-Cookie") or []), "the application's cookie is missing"
    assert a["method"] == "POST" and a["body"] == "field=value", a
    assert a["header"].get("Remote-User") == "anna", a["header"]
    assert "tinysesam" not in (a["header"].get("Cookie") or ""), a["header"].get("Cookie")
    ok("session without gate cookie → way back: 200, POST including body, new gate cookie, "
       "Remote-User from the browser overwritten, TinySesam cookies removed")

    # ---------- H1: identity headers of the browser never reach the application ----------
    # Measured 2026-11-20 with Caddy 2.11.9 (suspicion from the security review: the plain and the home-network
    # template do not strip Remote-* up front like the gate template, they rely on `request_header` in
    # handle_response). Result: an EMPTY value from TinySesam (Anna has no address) overwrites the browser's
    # value with "" — closed. Pinned here for both the plain template and the gate template's way back.
    forged = {"Remote-User": "admin", "Remote-Groups": "admin", "Remote-Email": "chef@example.com",
              "Remote-Name": "Chef", "Remote-Id": "1", "Remote-Auth": "oauth", "Remote-Kind": "service"}
    # F1 towards the application: a target the browser made up never reaches it (measured for every template below).
    target_forged = {"X-Original-URL": "https://evil.example/", "X-Original-URI": "/evil"}
    for port, was in ((PORT, "gate template, way back"), (PORT_PLAIN, "plain template"),
                      (PORT_QUICK, "quickstart template")):
        st, h, a = request("/h1", session, forged, port=port)
        hd = a["header"] if a else {}
        assert st == 200 and hd.get("Remote-User") == "anna" and hd.get("Remote-Groups") == "editors", (was, st, hd)
        assert hd.get("Remote-Email", "") == "" and hd.get("Remote-Id") == str(uid), (was, hd)
        assert utf8(hd.get("Remote-Name")) == "Anna Ärger", (was, hd.get("Remote-Name"))
        assert hd.get("Remote-Auth") == "session", (was, hd.get("Remote-Auth"))       # T-75, the browser said oauth
        assert hd.get("Remote-Kind") == "user", (was, hd.get("Remote-Kind"))          # spec v2, the browser said service
        st, h, a = request("/h1-target", session, target_forged, port=port)
        assert st == 200 and not {"x-original-url", "x-original-uri"} & {k.lower() for k in a["header"]}, (was, a)
        # HSTS (H1): the application's responses and the redirect to the sign-in carry it.
        assert h.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains", (was, dict(h))
        st, h, _ = request("/h1", None, forged, port=port)
        assert st == 302 and h.get("Strict-Transport-Security") == "max-age=31536000; includeSubDomains", (was, st)
    ok("H1: Remote-* sent by the browser (also Remote-Email against an empty value, Remote-Kind: service) → "
       "TinySesam's values reach the application — plain, quickstart and gate way back; HSTS on 200 and on the redirect")

    # ---------- A-3: the client's credentials never reach the application ----------
    # Attack round 2026-11-21: every template passed `Authorization` on, and an API key (valid at every host and at
    # TinySesam's API), an app password or an OAuth token landed in whatever the application logs. Measured with a
    # session plus both headers, and with a real API key ALONE (forward auth accepts it — the check needs the
    # header, the application must not get it), on the way back, the plain, the quickstart template and the share
    # path. The fast path (gate cookie) follows below.
    api_key = auth.create_api_key(uid, name="a3", expires_days=1)["key"]
    creds = {"Authorization": "Basic not-for-the-app", "X-Api-Key": "tsk_not-for-the-app"}
    for port, was in ((PORT, "gate template, way back"), (PORT_PLAIN, "plain template"),
                      (PORT_QUICK, "quickstart template")):
        # T-75 (A6): the client also claims `Remote-Auth: session` — the application must see `apikey`.
        for path, cookies, head in (("/a3", session, creds),
                                    ("/a3-key", None, {"Authorization": f"Bearer {api_key}", "Remote-Auth": "session"}),
                                    ("/a3-key2", None, {"X-Api-Key": api_key, "Remote-Auth": "session"}),
                                    ("/s/a3-share", None, creds)):
            if path.startswith("/s/") and port == PORT_QUICK:
                continue                                    # the quickstart has no share exception
            st, h, a = request(path, cookies, head, port=port)
            hd = {k.lower(): v for k, v in (a["header"] if a else {}).items()}
            assert st == 200, (was, path, st)
            assert "authorization" not in hd and "x-api-key" not in hd, (was, path, hd)
            if path.startswith("/a3-key"):
                assert hd.get("remote-user") == "anna", (was, path, hd)      # the key DID sign in at the check
                assert hd.get("remote-auth") == "apikey", (was, path, hd.get("remote-auth"))
                assert hd.get("remote-kind") == "user", (was, path, hd.get("remote-kind"))
    ok("A-3: Authorization and X-Api-Key never reach the application — session, an API key alone (it still signs in "
       "at the check), share path; plain, quickstart and gate way back")

    # ---------- Remote-Kind (spec v2): a service account's key says `service`, a forged value never arrives ----------
    bot_key = auth.create_api_key(bot, name="kind", expires_days=1)["key"]
    for port, was in ((PORT, "gate template, way back"), (PORT_PLAIN, "plain template"),
                      (PORT_QUICK, "quickstart template")):
        st, h, a = request("/kind-bot", None, {"X-Api-Key": bot_key, "Remote-Kind": "user"}, port=port)
        hd = {k.lower(): v for k, v in (a["header"] if a else {}).items()}
        assert st == 200 and hd.get("remote-user") == "backup-bot" and hd.get("remote-kind") == "service", (was, st, hd)
        st, h, a = request("/kind-person", session, {"Remote-Kind": "service"}, port=port)
        hd = a["header"] if a else {}
        assert st == 200 and [v for k, v in hd.items() if k.lower() == "remote-kind"] == ["user"], (was, st, hd)
        if port != PORT_QUICK:
            st, h, a = request("/s/kind-share", None, {"Remote-Kind": "service", "Remote-User": "admin"}, port=port)
            assert st == 200 and not {"remote-kind", "remote-user"} & {k.lower() for k in a["header"]}, (was, a)
    ok("Remote-Kind: a service account's API key → service (the client said user); a person's session → user, never "
       "the client's service; nothing on the share path — plain, quickstart and gate way back")

    # ---------- T-58: a header MISSING from the answer reaches the application as nothing ----------
    # Before 2026-11-20 the templates set every Remote-* from `{rp.header.…}` unconditionally; when TinySesam's answer
    # did not carry one (forward_headers reduced or renamed), Caddy left the placeholder as literal text and the
    # application received `{http.reverse_proxy.header.Remote-Email}` as the address. Now: strip up front, set each
    # header only when the answer carries it.
    auth.cfg.forward_headers = {"user": "Remote-User", "groups": "Remote-Groups"}
    try:
        for port, was in ((PORT, "gate template, way back"), (PORT_PLAIN, "plain template"),
                          (PORT_QUICK, "quickstart template")):
            st, h, a = request("/t58", session, forged, port=port)
            hd = a["header"] if a else {}
            assert st == 200 and hd.get("Remote-User") == "anna" and hd.get("Remote-Groups") == "editors", (was, st, hd)
            leaked = {k: v for k, v in hd.items() if k in ("Remote-Email", "Remote-Name", "Remote-Id", "Remote-Auth")}
            assert not leaked, (was, leaked)
            # The mandatory slot: Remote-Kind is sent whatever forward_headers lists — TinySesam's `user`, not the
            # browser's `service`.
            assert hd.get("Remote-Kind") == "user", (was, hd.get("Remote-Kind"))
    finally:
        auth.cfg.forward_headers = {}
    ok("T-58: forward_headers without email/name/id → the application gets no such header — neither placeholder text "
       "nor the browser's forgery (plain, quickstart, gate way back)")

    # ---------- Attack round B, F1: an X-Original-URL from the browser does not move the check to another host ----------
    # Caddy passes every header of the browser on to /auth/forward. Up to 0.25 TinySesam preferred an absolute
    # X-Original-URL to Caddy's own X-Forwarded-Host: an app password bound to dav.example.com opened app.example.com
    # (measured with Caddy 2.11.7 and the quickstart template), and "signed out of this application only" (T-22) was
    # skipped. Two layers now, each enough on its own: the templates remove X-Original-URL/-URI before the
    # sub-request, and TinySesam refuses a request whose X-Original-URL disagrees with X-Forwarded-Host.
    app_pw = auth.create_app_password(uid, "Phone", hosts=["dav.example.com"])["secret"]
    spoof = {"X-Original-URL": "https://dav.example.com/", "X-Original-URI": "/",
             "Authorization": "Basic " + base64.b64encode(f"anna:{app_pw}".encode()).decode()}
    handle = auth.store.session_hash(session[auth.session_cookie_name])
    for port, was in ((PORT, "gate template, way back"), (PORT_PLAIN, "plain template"),
                      (PORT_QUICK, "quickstart template")):
        before = FORWARD["n"]
        st, h, a = request("/f1-app-password", None, spoof, port=port)
        assert st != 200 and a is None and FORWARD["n"] == before + 1, (
            f"{was}: the app password of dav.example.com opened app.example.com via X-Original-URL",
            st, a and a["header"].get("Remote-User"))
        auth.store.gate_sign_out(handle, "app.example.com")
        try:
            st, h, a = request("/f1-signed-out", session, {"X-Original-URL": "https://dav.example.com/"}, port=port)
            assert st == 302 and a is None, (f"{was}: X-Original-URL skipped the sign-out of app.example.com", st)
        finally:
            auth.store.gate_resume(handle, "app.example.com")
        assert request("/f1-back", session, port=port)[0] == 200, was
    ok("F1: X-Original-URL from the browser → the app password of dav.example.com does not open app.example.com, "
       "and “signed out here only” holds — plain, quickstart and gate way back")

    # ---------- OAuth (T-36): the resource metadata of the application's host go to TinySesam, past the gate ----------
    # TinySesam here has no OAuth switched on, so it answers its own 404 — what is measured is the route: not the
    # application (it would answer 200 with JSON of its own), not the sign-in (302), and no call to /auth/forward.
    for port, was in ((PORT, "gate template"), (PORT_PLAIN, "plain template"), (PORT_QUICK, "quickstart template")):
        before = FORWARD["n"]
        st, h, a = request("/.well-known/oauth-protected-resource/mcp", None, port=port)
        assert st == 404 and a is None and FORWARD["n"] == before, (was, st, a)
    ok("/.well-known/oauth-protected-resource* reaches TinySesam without sign-in — plain, quickstart and gate template")

    # ---------- T-76: the bar as data on the application's host, through the proxy ----------
    # The templates strip TinySesam's cookies before the application, so its server cannot forward them; the page's
    # script fetches /.tinysesam/topbar.json from its own origin instead — the proxy passes /.tinysesam/* on with them.
    for port, was in ((PORT, "gate template"), (PORT_PLAIN, "plain template"), (PORT_QUICK, "quickstart template")):
        st, h, a = request("/.tinysesam/topbar.json", session, port=port)
        assert st == 200 and a and a.get("signed_in") is True and a.get("name") == "Anna Ärger", (was, st, a)
        assert "path" not in a, (was, "the application answered, not TinySesam", a)
        assert h.get("Cache-Control") == "no-store", (was, dict(h))
        st, h, a = request("/.tinysesam/topbar.json", None, port=port)
        assert st == 200 and a and a.get("signed_in") is False and a.get("links") == [], (was, st, a)
        # T-91: the own account as data takes the same way — with the cookies, never answered by the application.
        st, h, a = request("/.tinysesam/account.json", session, port=port)
        assert st == 200 and a and a.get("signed_in") is True and a["account"]["display_name"] == "Anna Ärger", \
            (was, st, a)
        assert "path" not in a and h.get("Cache-Control") == "no-store", (was, dict(h))
        st, h, a = request("/.tinysesam/account.json", None, port=port)
        assert st == 401, (was, "without a session", st, a)
    ok("T-76/T-91: /.tinysesam/topbar.json and /.tinysesam/account.json on the application's host reach TinySesam "
       "with the browser's cookies (account.json 401 without) — "
       "plain, quickstart and gate template")

    # ---------- with gate cookie: TinySesam is not asked ----------
    with_gate = {**session, "__Host-tinysesam_gate": tok, "other": "1"}
    before = FORWARD["n"]
    for i in range(10):
        st, h, a = request(f"/asset-{i}.js", with_gate, {"Remote-User": "admin", "Remote-Groups": "admin",
                                                         "Remote-Email": "chef@example.com", "Remote-Auth": "apikey",
                                                         "Remote-Kind": "service"})
        assert st == 200 and a["path"] == f"/asset-{i}.js", (st, a)
    assert FORWARD["n"] == before, f"{FORWARD['n'] - before} calls to TinySesam despite a valid gate cookie"
    hd = a["header"]
    assert hd.get("Remote-User") == "anna" and hd.get("Remote-Groups") == "editors", hd
    assert utf8(hd.get("Remote-Name")) == "Anna Ärger", hd.get("Remote-Name")
    assert hd.get("Remote-Id") == str(uid), hd
    # T-75 (A5): the signed claim ts_auth — the same value the way back set above, never the browser's `apikey`.
    assert hd.get("Remote-Auth") == "session", hd.get("Remote-Auth")
    # Spec v2: the signed claim ts_kind, never the browser's `service`.
    assert hd.get("Remote-Kind") == "user", hd.get("Remote-Kind")
    # Anna has no address — the claim is empty. The address from the browser must still not
    # get through: for that the template removes every Remote-* of the request before it sets it.
    assert hd.get("Remote-Email", "") == "", hd.get("Remote-Email")
    assert hd.get("Cookie") == "other=1", hd.get("Cookie")
    assert gate_cookie(h) is None, "no new token is issued on the fast path"
    st, h, a = request("/a3-fast", with_gate, creds)
    assert st == 200 and not {"authorization", "x-api-key"} & {k.lower() for k in a["header"]}, a["header"]
    ok("valid gate cookie → 10 requests at the application, 0 at TinySesam; identity from the "
       "token (UTF-8 as with /auth/forward), Remote-* from the browser overwritten, gate cookie removed")

    # ---------- caddy-jwt never sees a credential from Authorization ----------
    # caddy-jwt (v1.4.0, jwt.go `Authenticate`) adds the `Authorization` header to its token candidates ALWAYS, even
    # with only `from_cookies`, and logs a candidate that is no JWT at level error with a third of its beginning and
    # end (`token_string`, `desensitizedTokenString`): an API key, an OAuth token or an app password of every MCP or
    # API call stood half in the proxy log (PO, Caddy 2.11.9 from caddy-gate v0.26.0; against A-3: credentials end at
    # the proxy). The template now sends a request with Authorization, or without the gate cookie, straight to the
    # way back; jwtauth only ever sees the cookie. (Mutation probe: drop the two `error` lines → red.)
    gate_log = os.path.join(_tmp, "forward-auth-Caddyfile.gate.log")
    bearer = "tsk_" + secrets.token_urlsafe(24)
    basic = base64.b64encode(f"anna:{app_pw}".encode()).decode()
    for head, cookies, want in (({"Authorization": f"Bearer {bearer}"}, None, 302),
                                ({"Authorization": f"Basic {basic}"}, None, 302),
                                ({"Authorization": f"Bearer {bearer}"}, with_gate, 200)):
        before = FORWARD["n"]
        st, h, a = request("/no-token-log", cookies, head)
        assert st == want and FORWARD["n"] == before + 1, (head, st, FORWARD["n"] - before)
        assert not a or not {"authorization", "x-api-key"} & {k.lower() for k in a["header"]}, a
    before = FORWARD["n"]
    assert request("/gate-only", with_gate)[0] == 200 and FORWARD["n"] == before, "counter-check: cookie alone"
    time.sleep(0.5)                               # Caddy writes its log lines asynchronously
    logged = pathlib.Path(gate_log).read_text(encoding="utf-8", errors="replace")
    pieces = [bearer, bearer[4:10], bearer[-6:], basic, basic[:8], basic[-6:], app_pw, api_key, api_key[4:10],
              api_key[-6:]]
    # What caddy-jwt still logs is the gate cookie it checked (a JWT, `eyJ…`, shortened — at info on every fast-path
    # request): never a value from Authorization.
    foreign = [z for z in re.findall(r'"token_string":"([^"]*)"', logged) if not z.startswith("eyJ")]
    assert not foreign, foreign[:3]
    assert not [z for z in pieces if z in logged], [z for z in pieces if z in logged]
    ok("Authorization (Bearer tsk_…, Basic app password, also next to a valid gate cookie) → straight to the way back; "
       "the Caddy log names only gate cookies and holds no piece of any credential; the gate cookie alone still takes "
       "the fast path")

    # ---------- B-3: `;` and `%3B` in the path ----------
    def raw_a(path, cookies=None):
        """Raw path on the wire, headers of the dummy back (http.client normalises nothing)."""
        import http.client
        v = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        v.putrequest("GET", path, skip_host=True)
        v.putheader("Host", f"app.example.com:{PORT}")
        if cookies:
            v.putheader("Cookie", "; ".join(f"{k}={w}" for k, w in cookies.items()))
        v.endheaders()
        a = v.getresponse()
        text = a.read()
        v.close()
        try:
            return a.status, a.getheader("Location"), json.loads(text)
        except ValueError:
            return a.status, a.getheader("Location"), None

    semi = ["/a;b.pdf", "/a%3Bb.pdf", "/a%3bb.pdf", "/Tom&amp;Jerry.pdf", "/a;b.pdf?x=1&y=;z", "/d/x;y/z"]
    for cookies, was in ((with_gate, "gate cookie"), (session, "session only")):
        for path in semi:
            st, loc, a = raw_a(path, cookies)
            assert st == 200 and a and a["path"] == path, (was, path, st, loc, a)
    ok(f"B-3: {len(semi)} paths with ; / %3B / &amp; reach the application unchanged — with gate cookie and with session alone")
    for path in semi:
        st, loc, a = raw_a(path)
        assert st == 302 and a is None, (path, st, loc)
        nxt = parse_qs(urlsplit(loc).query)["next"][0]
        assert nxt == f"http://app.example.com:{PORT}{path}", (path, nxt)
    ok("B-3: signed out → login, and `next` carries the path unchanged (; survives, & stays encoded)")

    # ---------- every forgery falls back to the way back ----------
    now = int(time.time())
    base = gate.check(base64.b64decode(auth.gate_public_key()), tok, aud="app.example.com",
                         iss=ISS, now=now)
    assert base
    own = {k[3:]: v for k, v in base.items() if k.startswith("ts_")}

    def signed(aud="app.example.com", iss=ISS, ttl=300, now_=None, key_name=None):
        return gate.issue(key_name or auth._gate_key_name, iss=iss, aud=aud, sub=str(uid),
                               claims=own, ttl=ttl, now=now if now_ is None else now_)

    assert request("/x", {"__Host-tinysesam_gate": signed()})[0] == 200, "control: freshly signed"

    # ---------- measured: a gate token WITHOUT ts_kind (issued before the update) on the fast path ----------
    # caddy-jwt passes a missing meta claim on as an EMPTY placeholder (measured 2026-11-22 with Caddy 2.11.9,
    # caddy-jwt 1.4.0): `header_up Remote-Kind {http.auth.user.ts_kind}` then sends `Remote-Kind` with an empty value —
    # never the literal `{http.auth.user.ts_kind}` (the old placeholder fault of the way back, T-58). A gate client after spec v2
    # refuses such a request (`header`: Remote-Kind missing) until the token expires; the next one carries ts_kind.
    # The client's own Remote-Kind is stripped up front, so it cannot fill the gap.
    legacy = gate.issue(auth._gate_key_name, iss=ISS, aud="app.example.com", sub=str(uid),
                        claims={k: v for k, v in own.items() if k != "kind"}, ttl=300, now=now)
    assert "ts_kind" not in gate.check(base64.b64decode(auth.gate_public_key()), legacy, aud="app.example.com",
                                       iss=ISS, now=now)
    before = FORWARD["n"]
    st, h, a = request("/legacy-token", {"__Host-tinysesam_gate": legacy}, {"Remote-Kind": "service"})
    assert st == 200 and FORWARD["n"] == before, (st, FORWARD["n"] - before)
    kinds = [v for k, v in a["header"].items() if k.lower() == "remote-kind"]
    assert kinds in ([], [""]), f"a missing ts_kind reached the application as {kinds!r}"
    assert not [v for v in a["header"].values() if "{http." in v], a["header"]
    assert a["header"].get("Remote-User") == "anna" and a["header"].get("Remote-Auth") == "session", a["header"]
    ok(f"measured: a gate token without ts_kind takes the fast path, the application gets Remote-Kind as {kinds!r} "
       "(empty, never placeholder text, never the client's `service`) — a spec v2 client refuses it")
    k, i, s = tok.split(".")
    cases = {
        # Flip a BYTE of the signature, do not replace the last characters: the last base64 characters
        # carry padding bits, and `…AA` instead of `…AB` is sometimes the same signature (1 in 256 runs).
        "signature altered": f"{k}.{i}." + gate._b64u(bytes([gate._read_b64u(s)[0] ^ 1]) + gate._read_b64u(s)[1:]),
        "alg none": base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode() + f".{i}.",
        "foreign key": signed(key_name=Ed25519PrivateKey.from_private_bytes(b"\x00" * 32)),
        "expired": signed(now_=now - 400),
        "other issuer": signed(iss="https://evil.example"),
        "other audience": signed(aud="wiki.example.com"),
        "audience with roles on a path without": signed(aud="app.example.com|roles=admin"),
    }
    for was, wrong in cases.items():
        before = FORWARD["n"]
        st, h, _ = request("/x", {"__Host-tinysesam_gate": wrong}, {"Remote-User": "admin"})
        assert st == 302 and FORWARD["n"] == before + 1, (was, st)
    ok(f"{len(cases)} forged gate cookies → way back, without session 302 (the counter-check gets through)")

    # With a session the way back replaces an expired token with a new one.
    st, h, _ = request("/x", {**session, "__Host-tinysesam_gate": cases["expired"]})
    assert st == 200 and gate_cookie(h) and gate_cookie(h) != cases["expired"]
    ok("expired token + session → 200 and a new gate cookie")

    # ---------- T-48/T-53: the fixed gate key (sign_key), rotation, typ ----------
    # The template takes one key, not the key set: caddy-jwt 1.4.0 hangs on `jwk_url` after one failed first fetch
    # (section "jwk_url hang" below).
    template = (ROOT / "deploy/forward-auth/Caddyfile.gate").read_text(encoding="utf-8")
    assert re.search(r"^\s*sign_key \{\$TS_GATE_PUBKEY\}$", template, re.M), "the template should take the fixed key"
    assert not re.search(r"^\s*jwk_url ", template, re.M), "jwk_url hangs with caddy-jwt 1.4.0"
    head_jwt = base64.urlsafe_b64encode(b'{"alg":"EdDSA","typ":"JWT","kid":"' + auth._gate_keyring.active.kid.encode()
                                        + b'"}').rstrip(b"=").decode()
    body = signed().split(".")[1]
    typ_jwt = f"{head_jwt}.{body}." + gate._b64u(auth._gate_key_name.sign(f"{head_jwt}.{body}".encode()))
    before = FORWARD["n"]
    assert request("/x", {"__Host-tinysesam_gate": typ_jwt})[0] == 200 and FORWARD["n"] == before
    assert gate.check(base64.b64decode(auth.gate_public_key()), typ_jwt, aud="app.example.com", iss=ISS,
                      now=int(time.time())) is None
    ok("typ: caddy-jwt lets a gate-key-signed `typ: JWT` through (it has no typ check, ADR-12) — gate.check refuses it; "
       "at the proxy the dedicated key and aud separate")
    # Rotation as a restart after `tinysesam keys rotate --purpose gate` leaves it: a new active key, the old one
    # previous. Caddy still holds the old key: the old key's token passes, the new key's token takes the way back —
    # slower, nobody is signed out — until the operator gives Caddy the new `tinysesam gate-key`.
    old_pub = auth.gate_public_key()
    old_token = signed()
    auth.store.key_ring_rotate("gate", os.urandom(32))
    auth._gate_keyring = keys.Keyring("gate", auth.store.key_ring_rows("gate"), "database")
    auth._gate_key_name = keys.gate_private(auth._gate_keyring.active.material)
    new_token = signed()
    assert auth.gate_public_key() != old_pub
    before = FORWARD["n"]
    assert request("/x", {"__Host-tinysesam_gate": old_token})[0] == 200 and FORWARD["n"] == before
    before = FORWARD["n"]
    st, h, _ = request("/x", {**session, "__Host-tinysesam_gate": new_token})
    assert st == 200 and FORWARD["n"] == before + 1, (st, FORWARD["n"] - before)
    # The operator's step after a rotation: Caddy restarted with the new `tinysesam gate-key`.
    _caddy.terminate()
    _caddy.wait(timeout=10)
    _caddy, PORT = start_caddy()
    before = FORWARD["n"]
    assert request("/x", {"__Host-tinysesam_gate": new_token})[0] == 200 and FORWARD["n"] == before
    ok("rotation with sign_key: the old key's token keeps the fast path, the new key's token takes the way back "
       "(200 with a session) until Caddy gets the new key — then the new one passes without TinySesam")

    # ---------- jwk_url hang: TinySesam unreachable when Caddy starts, reachable afterwards ----------
    # caddy-jwt 1.4.0 (`getOrCreateJWKCache`): the first request with a token registers the JWKS URL with jwx's
    # `Cache.Register(context.Background(), url)` under the plugin's write lock; httprc waits for the first successful
    # fetch (`WaitReady`, no deadline) and retries only after its interval. One failed first fetch — TinySesam not up
    # yet — and every request with a gate token hung (measured in a rollout: 4 × 40 s, no second fetch). The template
    # checks a fixed key instead. Here: Caddy starts while its TinySesam upstream refuses connections; a request with a
    # valid gate token must pass at once, and once TinySesam listens the way back works too.
    # (Mutation probe: `jwk_url http://{$TS_AUTH_UPSTREAM…}/auth/gate/jwks.json` back instead of `sign_key` → the first
    # request with a token hangs → red.)
    _late_sock = listening_socket()
    _late_port = _late_sock.getsockname()[1]
    _late_sock.close()                                          # nothing listens there yet
    _caddy_late, PORT_LATE = start_caddy(upstream=f"127.0.0.1:{_late_port}", suffix="-late")
    try:
        fresh = signed(now_=int(time.time()))
        t0 = time.monotonic()
        try:
            st, h, a = request("/late-1", {"__Host-tinysesam_gate": fresh}, port=PORT_LATE)
        except OSError as e:          # a timeout of the request: Caddy hangs
            raise AssertionError(f"a request with a gate token hangs while TinySesam is unreachable: {e!r}")
        assert st == 200 and a and a["path"] == "/late-1", (st, a)
        assert time.monotonic() - t0 < 5, f"took {time.monotonic() - t0:.1f}s"
        # TinySesam comes up on that port: the way back works, and the gate token still passes at once.
        _late = socket.socket()
        _late.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _late.bind(("127.0.0.1", _late_port))
        _late.listen(128)
        _late_server = uvicorn.Server(uvicorn.Config(ts_app, log_level="critical"))
        threading.Thread(target=lambda: _late_server.run(sockets=[_late]), daemon=True).start()
        for _ in range(100):
            if _late_server.started:
                break
            time.sleep(0.05)
        st, h, _ = request("/late-2", session, port=PORT_LATE)
        assert st == 200 and gate_cookie(h), (st, dict(h))
        t0 = time.monotonic()
        assert request("/late-3", {"__Host-tinysesam_gate": fresh}, port=PORT_LATE)[0] == 200
        assert time.monotonic() - t0 < 5
        _late_server.should_exit = True
    finally:
        _caddy_late.terminate()
        try:
            _caddy_late.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _caddy_late.kill()
    ok("TinySesam unreachable when Caddy starts: a gate token passes at once (no hang); once TinySesam listens, "
       "the way back issues a new token and the gate token still passes")

    # ---------- Variant "the application uses FetchTopbar/FetchAccount": only the session cookie gets through ----------
    # The template carries the variant as a comment; here it is put in place exactly as the comment says (both
    # application upstreams behind the gate, never the share path) and measured: the session cookie and the connection
    # cookie reach the application, every other TinySesam cookie and a browser-made placeholder do not, and the
    # forwarded cookie is enough for the server-side helper.
    _strip = ('header_up Cookie "(^|;)\\s*(__Host-|__Secure-)?tinysesam_[^=;]*=[^;]*" ""\n',
              'header_up Cookie "^[;\\s]+" ""\n')

    def _with_fetch_variant(text):
        variant = re.findall(r"^\t+#   (header_up Cookie .*)$", text, re.M)
        assert len(variant) == 5, variant
        parts = re.split(r"(\t+)" + re.escape(_strip[0]) + r"\1" + re.escape(_strip[1]), text)
        # [before share, indent, share … fast path, indent, fast path … way back, indent, rest]
        assert len(parts) == 7, "the three application upstreams of the template have shifted"
        out = parts[0] + parts[1] + _strip[0] + parts[1] + _strip[1] + parts[2]
        for indent, rest in ((parts[3], parts[4]), (parts[5], parts[6])):
            out += "".join(indent + line + "\n" for line in variant) + rest
        return out

    _caddy_fetch, PORT_FETCH = start_caddy(suffix="-fetch", transform=_with_fetch_variant)
    try:
        sname, sval = next(iter(session.items()))
        assert sname == "tinysesam_session", sname
        extra = {"__Host-tinysesam_link": "L", "tinysesam_csrf": "C", "ts-keep.tinysesam_session": "FORGED",
                 "other": "1"}
        before = FORWARD["n"]
        st, _, a = request("/fetch-fast", {**session, "__Host-tinysesam_gate": signed(now_=int(time.time())),
                                           **extra}, port=PORT_FETCH)
        assert st == 200 and FORWARD["n"] == before, (st, FORWARD["n"] - before)
        assert a["header"].get("Cookie") == f"{sname}={sval}; __Host-tinysesam_link=L; other=1", a["header"]
        st, _, a = request("/fetch-back", {**session, **extra}, port=PORT_FETCH)
        assert st == 200 and FORWARD["n"] == before + 1, (st, FORWARD["n"] - before)
        assert a["header"].get("Cookie") == f"{sname}={sval}; __Host-tinysesam_link=L; other=1", a["header"]
        st, _, a = request("/s/fetch", {**session, "__Host-tinysesam_link": "L", "other": "1"}, port=PORT_FETCH)
        assert st == 200 and a["header"].get("Cookie") == "other=1", ("share path", a["header"])
        bar = gate_client.fetch_topbar(f"http://{TS}/auth/topbar.json", f"{sname}={sval}; other=1")
        assert bar.signed_in and bar.name == "Anna Ärger", bar
    finally:
        _caddy_fetch.terminate()
        try:
            _caddy_fetch.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _caddy_fetch.kill()
    ok("variant for FetchTopbar/FetchAccount: fast path and way back pass exactly the session and the connection "
       "cookie (no CSRF, gate or placeholder cookie), the share path still none; the forwarded cookie signs the "
       "server-side top bar in")

    # ---------- Signing out at the application (T-22): /.tinysesam/* bypasses the gate ----------
    before = FORWARD["n"]
    st, h, _ = request("/.tinysesam/logout?scope=app", session)
    assert st == 303 and h["Location"] == "/", (st, dict(h))
    assert any(v.startswith("__Host-tinysesam_gate=;") and "Max-Age=0" in v for v in h.get_all("Set-Cookie") or []), \
        h.get_all("Set-Cookie")
    assert FORWARD["n"] == before, "the sign-out path must not go through the gate (there is no sign-in to check)"
    st, h, _ = request("/page", session)
    assert st == 302 and "/auth/login?next=" in h["Location"], (st, dict(h))
    ok("/.tinysesam/logout?scope=app through Caddy: past the gate, gate cookie deleted, then 302 to the login page")
    tc.post("/auth/gate/resume", data={"next": f"http://app.example.com:{PORT}/page"}, follow_redirects=False)
    assert request("/page", session)[0] == 200
    ok("“Continue as …” → the application lets through again")

    # ---------- Share exception (T-20): public only the prefix, without path tricks ----------
    def raw(path, head=None, port=None):
        """Like `request`, but the path goes onto the wire UNCHANGED (http.client normalises
        nothing) — otherwise the test would not check the path tricks at all."""
        import http.client
        port = port or PORT
        v = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        v.putrequest("GET", path, skip_host=True)
        v.putheader("Host", f"app.example.com:{port}")
        for k, w in (head or {}).items():
            v.putheader(k, w)
        v.endheaders()
        a = v.getresponse()
        raw_text = a.read()
        v.close()
        try:
            return a.status, json.loads(raw_text)
        except ValueError:
            return a.status, None

    unclosed = ["/s/abc", "/s/abc/def.js", "/public/share/x", "/s/abc?x=../../admin", "/s/a.b..c",
             # B-3: `;` and `%3B` are ordinary characters in a file name. A share download such as
             # /s/<token>/file_%3B%29.bin must reach the application, not the login.
             "/s/abc;jsessionid=1", "/s/%3b", "/s/%3B", "/s/a;b.pdf", "/s/a%3Bb.pdf", "/s/file_%3B%29.bin",
             "/s/tok/file_;).bin", "/s/x;y/z", "/s/x/a.;b", "/s/x/;", "/public/share/a;b",
             # a literal `%3b` in the file name (raw %253b) is no dot segment either
             "/s/a%253Bb"]
    # Both templates carry the same exception and are measured alike: the gate template (caddy-jwt) and
    # the plain forward_auth template.
    for port, was in ((PORT, "gate template"), (PORT_PLAIN, "plain template")):
        before = FORWARD["n"]
        for path in unclosed:
            st, a = raw(path, {"Remote-User": "admin", "Cookie": "tinysesam_session=SECRET; a=1"}, port)
            assert st == 200 and a and a["header"].get("Remote-User") is None, (was, path, st, a and a["header"])
            assert a["header"].get("Cookie") == "a=1", (was, path, a["header"].get("Cookie"))
            assert a["path"] == path, (was, path, a["path"])
        assert FORWARD["n"] == before, f"{was}: a share path must not ask TinySesam"
    ok(f"{len(unclosed)} share paths open (also with ; / %3B in the file name), without TinySesam, without identity "
       "(none from the browser either), without TinySesam cookies — gate template and plain template")

    # T-20 path tricks, unchanged. Only the two cases `;`/`%3b` as an ordinary character moved to `offen` (B-3);
    # a `;` that makes a dot segment (`..;`, `.;`, `..%3b`, doubly encoded `..%253b`) stays closed.
    to = ["/s/..;/admin", "/s/%2e%2e;/admin", "/s/..%5cadmin", "/s/..\\admin",
          "/s%2f..%2fadmin", "/s/abc%00", "/x/../s/abc", "/s/../admin", "/s/./abc", "/S/abc", "//s/abc",
          "/sx/abc", "/s", "/admin/x.js",
          # B-3: the dot segment counts with a path parameter — Tomcat/Spring read `..;x` as `..`
          "/s/.;/x", "/s/..;", "/s/..;jsessionid=1/admin", "/s/x/.;y/z", "/s/..%3b/admin", "/s/..%3B/admin",
          "/s/%2e%2e%3b/admin", "/s/..%253b/admin", "/s/..%253B/admin", "/s/.%253b/x", "/s/.%2e;/admin",
          "/s/x/..%00", "/s/a%5Cb", "/s/a%252fb", "/s/a%2500", "/s/a%252e%252e"]
    for port, was in ((PORT, "gate template"), (PORT_PLAIN, "plain template")):
        for path in to:
            before = FORWARD["n"]
            st, _ = raw(path, None, port)
            assert st == 302 and FORWARD["n"] == before + 1, (was, path, st)
    ok(f"{len(to)} path tricks and neighbouring paths → through the gate (..;, .;, ..%3b, ..%253b, %2e, %5c, NUL, "
       "/x/../s/, /S/, //s/ …) — gate template and plain template")

    # ---------- Acceptance pattern (T-24): deploy/forward-auth/acceptance.sh against this setup ----------
    import shutil  # noqa: E402
    assert shutil.which("bash") and shutil.which("curl"), "acceptance.sh needs bash and curl"
    script = ROOT / "deploy/forward-auth/acceptance.sh"
    env_a = {**os.environ, "APP": f"http://app.example.com:{PORT}", "SHARE": "/s/abc123",
             "SESSION": "; ".join(f"{k}={v}" for k, v in session.items()),
             "CURL_EXTRA": f"--resolve app.example.com:{PORT}:127.0.0.1", "ECHO": "1"}
    a = subprocess.run(["bash", str(script)], env=env_a, capture_output=True, text=True, timeout=120)
    assert a.returncode == 0 and "passed" in a.stdout and "FAIL" not in a.stdout, a.stdout + a.stderr
    lines = [z for z in a.stdout.splitlines() if z.startswith("  ok")]
    assert len(lines) >= 19 and any("HSTS" in z for z in lines), a.stdout
    assert sum("Remote-Kind" in z for z in lines) == 3, a.stdout
    ok(f"acceptance.sh against this setup: {len(lines)} checks passed")
    # Counter-check: the script must turn red when an expectation is wrong — here a path that is
    # closed but is given as a share. Otherwise “passed” would also be the answer of a script that
    # checks nothing.
    a = subprocess.run(["bash", str(script)], env={**env_a, "SHARE": "/admin/x.js"},
                       capture_output=True, text=True, timeout=120)
    assert a.returncode == 1 and "FAIL Share path /admin/x.js is open" in a.stdout, a.stdout
    ok("counter-check: a path that is closed, given as share → acceptance.sh red (exit 1)")
    # Counter-check of the Remote-Kind probe: straight at the application, without a proxy that strips, the forged
    # value arrives — the script must say so on both paths.
    a = subprocess.run(["bash", str(script)], env={**env_a, "APP": f"http://{APP}", "CURL_EXTRA": ""},
                       capture_output=True, text=True, timeout=120)
    assert a.returncode == 1, a.stdout
    assert "FAIL a forged Remote-Kind does not reach the application on the share path" in a.stdout, a.stdout
    assert "FAIL with session: the application gets TinySesam's Remote-Kind, never a forged one" in a.stdout, a.stdout
    ok("counter-check: without a stripping proxy acceptance.sh sees the forged Remote-Kind (share path and session)")
    tc.post("/auth/gate/resume", data={"next": f"http://app.example.com:{PORT}/"}, follow_redirects=False)

    # ---------- the price: revocation only takes effect on expiry ----------
    auth.store.delete_user_sessions(uid)
    assert request("/x", session)[0] == 302
    assert request("/x", {"__Host-tinysesam_gate": new_token})[0] == 200      # a token of the key Caddy holds
    ok("after signing out: session alone → 302, the gate token applies until its expiry (ADR-9)")

    # ---------- Counter-check: without gate the proxy asks every time again ----------
    tc.post("/auth/login", data={"username": "anna", "password": "dummy123", "next": "/"},
            follow_redirects=False)
    session = {auth.session_cookie_name: tc.cookies.get(auth.session_cookie_name)}
    auth.cfg.gate_token_enabled = False
    before = FORWARD["n"]
    for i in range(3):
        st, h, _ = request(f"/asset-{i}.js", session)
        assert st == 200 and gate_cookie(h) is None
    assert FORWARD["n"] == before + 3
    auth.cfg.gate_token_enabled = True
    ok("gate_token_enabled=False → every request goes via /auth/forward (as without gate)")
finally:
    for _c in (_caddy, _caddy_plain, _caddy_quick):
        _c.terminate()
        try:
            _c.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _c.kill()
    _app_srv.shutdown()
    _ts_server.should_exit = True

print("Gate token through Caddy OK")
