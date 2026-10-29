"""Gate token through a REAL Caddy with caddy-jwt — the template deploy/forward-auth/Caddyfile.gate.
The share exception (T-20, B-3) is measured against the plain template Caddyfile as well.

The claim of ADR-9 is one about the proxy: with a valid gate cookie a request reaches
the application without TinySesam being asked. That can only be proven with the proxy itself.
Started are TinySesam (uvicorn), a dummy of the application that reports back what arrives
at it, and Caddy with the template from the repo — word for word, only the site addresses point to
a free port and `auto_https` is off.

Caddy with the plugin comes from TINYSESAM_GATE_CADDY (path to the binary). The CI job `gate-caddy`
builds it from deploy/forward-auth/caddy-gate/Dockerfile and sets the variable — if it is set,
the binary is required. Without the variable the suite reports “skipped” with a reason.
"""
import base64
import http.server
import json
import os
import pathlib
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
braucht(CADDY, "TINYSESAM_GATE_CADDY not set — Caddy with caddy-jwt missing "
               "(build: deploy/forward-auth/caddy-gate/Dockerfile)")
braucht_modul("uvicorn")
# Set means required: a wrong path or a Caddy without the plugin is an error, not a skip.
assert os.access(CADDY, os.X_OK), f"TINYSESAM_GATE_CADDY={CADDY!r} is not an executable file"
_module = subprocess.run([CADDY, "list-modules"], capture_output=True, text=True, timeout=30).stdout
assert "http.authentication.providers.jwt" in _module.split(), "this Caddy does not have caddy-jwt"

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import gate  # noqa: E402

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
    base_url=ISS, trusted_redirect_hosts=["app.example.com"], gate_token_enabled=True))
auth.ensure_admin("admin", "geheim123")
uid = auth.create_user("anna", "geheim123", roles=["redaktion"])
auth.store._exec("UPDATE users SET display_name=? WHERE id=?", ("Anna Ärger", uid))

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
        b = json.dumps({"pfad": self.path, "methode": self.command,
                        "body": self.rfile.read(n).decode(), "header": raw}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "app_eigen=1; Path=/")
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = _response


_app_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Application)
APP = f"127.0.0.1:{_app_srv.server_address[1]}"
threading.Thread(target=_app_srv.serve_forever, daemon=True).start()

# Warten, bis TinySesam antwortet.
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


def start_caddy(templates_file="Caddyfile.gate"):
    """Caddy needs a port that it binds itself — a bound socket cannot be
    passed on. So find a free one, release it and let Caddy bind; if that fails (another
    process was faster), try again with the next one."""
    template = (ROOT / "deploy/forward-auth" / templates_file).read_text(encoding="utf-8")
    for _ in range(5):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        text = "{\n\tauto_https off\n\tadmin off\n}\n" + template
        text = text.replace("\nauth.example.com {", f"\nhttp://auth.example.com:{port} {{", 1)
        text = text.replace("\napp.example.com {", f"\nhttp://app.example.com:{port} {{", 1)
        assert text.count(f":{port} {{") == 2, "the site addresses of the template have shifted"
        file = os.path.join(_tmp, templates_file)
        with open(file, "w", encoding="utf-8") as f:
            f.write(text)
        env = {**os.environ, "TS_GATE_PUBKEY": auth.gate_public_key(), "TS_GATE_ISSUER": ISS,
               "TS_SHARE_PREFIX": SHARE,
               "TS_AUTH_UPSTREAM": TS, "TS_APP_UPSTREAM": APP, "XDG_DATA_HOME": _tmp,
               "XDG_CONFIG_HOME": _tmp}
        # Popen gives the child its own copy of the file descriptor — the parent process's one
        # may be closed right away.
        with open(os.path.join(_tmp, templates_file + ".log"), "w") as log:
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
    with open(os.path.join(_tmp, templates_file + ".log"), encoding="utf-8", errors="replace") as log:
        raise RuntimeError("Caddy does not start: " + log.read()[-2000:])


_caddy, PORT = start_caddy()
#: The plain template (forward_auth without gate token) carries the same share exception — it needs
#: no plugin, but its own Caddy, and it is measured just the same (B-3).
_caddy_plain, PORT_PLAIN = start_caddy("Caddyfile")


class _WithoutRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_WithoutRedirect)


def request(path, cookies=None, head=None, method="GET", body=None):
    """A request to Caddy, host app.example.com. Returns (status, headers, JSON of the dummy)."""
    h = {"Host": f"app.example.com:{PORT}", **(head or {})}
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", headers=h, method=method,
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
    tc.post("/auth/login", data={"username": "anna", "password": "geheim123", "next": "/"},
            follow_redirects=False)
    session = {auth.session_cookie_name: tc.cookies.get(auth.session_cookie_name)}
    assert session[auth.session_cookie_name]
    before = FORWARD["n"]
    st, h, a = request("/seite", session, {"Remote-User": "admin"}, method="POST", body="feld=wert")
    assert st == 200, st
    assert FORWARD["n"] == before + 1
    tok = gate_cookie(h)
    assert tok, f"no gate cookie in the response: {h.get_all('Set-Cookie')}"
    assert "app_eigen=1; Path=/" in (h.get_all("Set-Cookie") or []), "the application's cookie is missing"
    assert a["methode"] == "POST" and a["body"] == "feld=wert", a
    assert a["header"].get("Remote-User") == "anna", a["header"]
    assert "tinysesam" not in (a["header"].get("Cookie") or ""), a["header"].get("Cookie")
    ok("session without gate cookie → way back: 200, POST including body, new gate cookie, "
       "Remote-User from the browser overwritten, TinySesam cookies removed")

    # ---------- with gate cookie: TinySesam is not asked ----------
    with_gate = {**session, "__Host-tinysesam_gate": tok, "andere": "1"}
    before = FORWARD["n"]
    for i in range(10):
        st, h, a = request(f"/asset-{i}.js", with_gate, {"Remote-User": "admin", "Remote-Groups": "admin",
                                                         "Remote-Email": "chef@example.com"})
        assert st == 200 and a["pfad"] == f"/asset-{i}.js", (st, a)
    assert FORWARD["n"] == before, f"{FORWARD['n'] - before} calls to TinySesam despite a valid gate cookie"
    hd = a["header"]
    assert hd.get("Remote-User") == "anna" and hd.get("Remote-Groups") == "redaktion", hd
    assert utf8(hd.get("Remote-Name")) == "Anna Ärger", hd.get("Remote-Name")
    assert hd.get("Remote-Id") == str(uid), hd
    # Anna has no address — the claim is empty. The address from the browser must still not
    # get through: for that the template removes every Remote-* of the request before it sets it.
    assert hd.get("Remote-Email", "") == "", hd.get("Remote-Email")
    assert hd.get("Cookie") == "andere=1", hd.get("Cookie")
    assert gate_cookie(h) is None, "no new token is issued on the fast path"
    ok("valid gate cookie → 10 requests at the application, 0 at TinySesam; identity from the "
       "token (UTF-8 as with /auth/forward), Remote-* from the browser overwritten, gate cookie removed")

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
            assert st == 200 and a and a["pfad"] == path, (was, path, st, loc, a)
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

    assert request("/x", {"__Host-tinysesam_gate": signed()})[0] == 200, "Gegenprobe: frisch signiert"
    k, i, s = tok.split(".")
    cases = {
        # Flip a BYTE of the signature, do not replace the last characters: the last base64 characters
        # carry padding bits, and `…AA` instead of `…AB` is sometimes the same signature (1 in 256 runs).
        "signature altered": f"{k}.{i}." + gate._b64u(bytes([gate._read_b64u(s)[0] ^ 1]) + gate._read_b64u(s)[1:]),
        "alg none": base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode() + f".{i}.",
        "foreign key": signed(key_name=gate.derive_key_name(b"\x00" * 32)),
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

    # ---------- Signing out at the application (T-22): /.tinysesam/* bypasses the gate ----------
    before = FORWARD["n"]
    st, h, _ = request("/.tinysesam/logout?scope=app", session)
    assert st == 303 and h["Location"] == "/", (st, dict(h))
    assert any(v.startswith("__Host-tinysesam_gate=;") and "Max-Age=0" in v for v in h.get_all("Set-Cookie") or []), \
        h.get_all("Set-Cookie")
    assert FORWARD["n"] == before, "the sign-out path must not go through the gate (there is no sign-in to check)"
    st, h, _ = request("/seite", session)
    assert st == 302 and "/auth/login?next=" in h["Location"], (st, dict(h))
    ok("/.tinysesam/logout?scope=app through Caddy: past the gate, gate cookie deleted, then 302 to the login page")
    tc.post("/auth/gate/resume", data={"next": f"http://app.example.com:{PORT}/seite"}, follow_redirects=False)
    assert request("/seite", session)[0] == 200
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
            st, a = raw(path, {"Remote-User": "admin", "Cookie": "tinysesam_session=GEHEIM; a=1"}, port)
            assert st == 200 and a and a["header"].get("Remote-User") is None, (was, path, st, a and a["header"])
            assert a["header"].get("Cookie") == "a=1", (was, path, a["header"].get("Cookie"))
            assert a["pfad"] == path, (was, path, a["pfad"])
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

    # ---------- Abnahmemuster (T-24): deploy/forward-auth/acceptance.sh gegen diesen Aufbau ----------
    import shutil  # noqa: E402
    assert shutil.which("bash") and shutil.which("curl"), "acceptance.sh needs bash and curl"
    script = ROOT / "deploy/forward-auth/acceptance.sh"
    env_a = {**os.environ, "APP": f"http://app.example.com:{PORT}", "SHARE": "/s/abc123",
             "SESSION": "; ".join(f"{k}={v}" for k, v in session.items()),
             "CURL_EXTRA": f"--resolve app.example.com:{PORT}:127.0.0.1"}
    a = subprocess.run(["bash", str(script)], env=env_a, capture_output=True, text=True, timeout=120)
    assert a.returncode == 0 and "passed" in a.stdout and "FAIL" not in a.stdout, a.stdout + a.stderr
    lines = [z for z in a.stdout.splitlines() if z.startswith("  ok")]
    assert len(lines) >= 15, a.stdout
    ok(f"acceptance.sh against this setup: {len(lines)} checks passed")
    # Counter-check: the script must turn red when an expectation is wrong — here a path that is
    # closed but is given as a share. Otherwise “passed” would also be the answer of a script that
    # checks nothing.
    a = subprocess.run(["bash", str(script)], env={**env_a, "SHARE": "/admin/x.js"},
                       capture_output=True, text=True, timeout=120)
    assert a.returncode == 1 and "FAIL Share path /admin/x.js is open" in a.stdout, a.stdout
    ok("counter-check: a path that is closed, given as share → acceptance.sh red (exit 1)")
    tc.post("/auth/gate/resume", data={"next": f"http://app.example.com:{PORT}/"}, follow_redirects=False)

    # ---------- the price: revocation only takes effect on expiry ----------
    auth.store.delete_user_sessions(uid)
    assert request("/x", session)[0] == 302
    assert request("/x", {"__Host-tinysesam_gate": tok})[0] == 200
    ok("after signing out: session alone → 302, the gate token applies until its expiry (ADR-9)")

    # ---------- Counter-check: without gate the proxy asks every time again ----------
    tc.post("/auth/login", data={"username": "anna", "password": "geheim123", "next": "/"},
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
    for _c in (_caddy, _caddy_plain):
        _c.terminate()
        try:
            _c.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _c.kill()
    _app_srv.shutdown()
    _ts_server.should_exit = True

print("Gate token through Caddy OK")
