"""Gate token through a REAL Caddy with caddy-jwt — the template deploy/forward-auth/Caddyfile.gate.

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from voraussetzung import braucht, braucht_modul  # noqa: E402

CADDY = os.environ.get("TINYSESAM_GATE_CADDY", "")
braucht(CADDY, "TINYSESAM_GATE_CADDY nicht gesetzt — Caddy mit caddy-jwt fehlt "
               "(bauen: deploy/forward-auth/caddy-gate/Dockerfile)")
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


def lauschender_socket():
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
async def zaehlen(request: Request, call_next):
    if request.url.path == "/auth/forward":
        FORWARD["n"] += 1
    return await call_next(request)

ts_app.include_router(auth.router())
_ts_sock = lauschender_socket()
TS = f"127.0.0.1:{_ts_sock.getsockname()[1]}"
_ts_server = uvicorn.Server(uvicorn.Config(ts_app, log_level="critical"))
threading.Thread(target=lambda: _ts_server.run(sockets=[_ts_sock]), daemon=True).start()


# ---------- Dummy of the application: reports back what arrives at it ----------
class Anwendung(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _antwort(self):
        n = int(self.headers.get("Content-Length") or 0)
        roh = {k: v for k, v in self.headers.items()}
        b = json.dumps({"pfad": self.path, "methode": self.command,
                        "body": self.rfile.read(n).decode(), "header": roh}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "app_eigen=1; Path=/")
        self.end_headers()
        self.wfile.write(b)

    do_GET = do_POST = _antwort


_app_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Anwendung)
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
    raise RuntimeError("TinySesam startet nicht")
FORWARD["n"] = 0


# ---------- Caddy with the template from the repo ----------
#: Public paths for this run (T-20) — the way an operator would set them.
SHARE = "^/(s|public/share)/"


def caddy_starten():
    """Caddy needs a port that it binds itself — a bound socket cannot be
    passed on. So find a free one, release it and let Caddy bind; if that fails (another
    process was faster), try again with the next one."""
    vorlage = (ROOT / "deploy/forward-auth/Caddyfile.gate").read_text(encoding="utf-8")
    for _ in range(5):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        text = "{\n\tauto_https off\n\tadmin off\n}\n" + vorlage
        text = text.replace("\nauth.example.com {", f"\nhttp://auth.example.com:{port} {{", 1)
        text = text.replace("\napp.example.com {", f"\nhttp://app.example.com:{port} {{", 1)
        assert text.count(f":{port} {{") == 2, "the site addresses of the template have shifted"
        datei = os.path.join(_tmp, "Caddyfile")
        with open(datei, "w", encoding="utf-8") as f:
            f.write(text)
        umg = {**os.environ, "TS_GATE_PUBKEY": auth.gate_public_key(), "TS_GATE_ISSUER": ISS,
               "TS_SHARE_PRAEFIX": SHARE,
               "TS_AUTH_UPSTREAM": TS, "TS_APP_UPSTREAM": APP, "XDG_DATA_HOME": _tmp,
               "XDG_CONFIG_HOME": _tmp}
        # Popen gives the child its own copy of the file descriptor — the parent process's one
        # may be closed right away.
        with open(os.path.join(_tmp, "caddy.log"), "w") as log:
            p = subprocess.Popen([CADDY, "run", "--config", datei, "--adapter", "caddyfile"],
                                 stdout=log, stderr=subprocess.STDOUT, env=umg)
        for _ in range(100):
            if p.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                return p, port
            except OSError:
                time.sleep(0.1)
        p.kill()
    with open(os.path.join(_tmp, "caddy.log"), encoding="utf-8", errors="replace") as log:
        raise RuntimeError("Caddy startet nicht: " + log.read()[-2000:])


_caddy, PORT = caddy_starten()


class _OhneUmleitung(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_oeffner = urllib.request.build_opener(_OhneUmleitung)


def anfrage(pfad, cookies=None, kopf=None, methode="GET", body=None):
    """A request to Caddy, host app.example.com. Returns (status, headers, JSON of the dummy)."""
    h = {"Host": f"app.example.com:{PORT}", **(kopf or {})}
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{pfad}", headers=h, method=methode,
                                 data=body.encode() if body is not None else None)
    try:
        r = _oeffner.open(req, timeout=10)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, None
    roh = r.read()
    try:
        return r.status, r.headers, json.loads(roh)
    except ValueError:
        return r.status, r.headers, None


def gate_cookie(header):
    for wert in header.get_all("Set-Cookie") or []:
        if wert.startswith("__Host-tinysesam_gate="):
            return wert.split(";", 1)[0].split("=", 1)[1]
    return None


def utf8(wert):
    """Headers arrive as Latin-1 with http.client; TinySesam sends UTF-8 over the wire."""
    return wert.encode("latin-1").decode("utf-8") if wert is not None else None


try:
    # ---------- without sign-in ----------
    st, h, _ = anfrage("/start")
    assert st == 302 and "/auth/login?next=" in h["Location"], (st, dict(h))
    assert FORWARD["n"] == 1
    ok("without sign-in → 302 to the login (way back via /auth/forward)")

    # ---------- session, no gate cookie yet: way back, new token ----------
    from fastapi.testclient import TestClient  # noqa: E402
    tc = TestClient(ts_app)
    tc.post("/auth/login", data={"username": "anna", "password": "geheim123", "next": "/"},
            follow_redirects=False)
    sitzung = {auth.session_cookie_name: tc.cookies.get(auth.session_cookie_name)}
    assert sitzung[auth.session_cookie_name]
    vorher = FORWARD["n"]
    st, h, a = anfrage("/seite", sitzung, {"Remote-User": "admin"}, methode="POST", body="feld=wert")
    assert st == 200, st
    assert FORWARD["n"] == vorher + 1
    tok = gate_cookie(h)
    assert tok, f"no gate cookie in the response: {h.get_all('Set-Cookie')}"
    assert "app_eigen=1; Path=/" in (h.get_all("Set-Cookie") or []), "the application's cookie is missing"
    assert a["methode"] == "POST" and a["body"] == "feld=wert", a
    assert a["header"].get("Remote-User") == "anna", a["header"]
    assert "tinysesam" not in (a["header"].get("Cookie") or ""), a["header"].get("Cookie")
    ok("session without gate cookie → way back: 200, POST including body, new gate cookie, "
       "Remote-User from the browser overwritten, TinySesam cookies removed")

    # ---------- with gate cookie: TinySesam is not asked ----------
    mit_gate = {**sitzung, "__Host-tinysesam_gate": tok, "andere": "1"}
    vorher = FORWARD["n"]
    for i in range(10):
        st, h, a = anfrage(f"/asset-{i}.js", mit_gate, {"Remote-User": "admin", "Remote-Groups": "admin",
                                                         "Remote-Email": "chef@example.com"})
        assert st == 200 and a["pfad"] == f"/asset-{i}.js", (st, a)
    assert FORWARD["n"] == vorher, f"{FORWARD['n'] - vorher} calls to TinySesam despite a valid gate cookie"
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

    # ---------- every forgery falls back to the way back ----------
    jetzt = int(time.time())
    basis = gate.pruefen(base64.b64decode(auth.gate_public_key()), tok, aud="app.example.com",
                         iss=ISS, jetzt=jetzt)
    assert basis
    eigene = {k[3:]: v for k, v in basis.items() if k.startswith("ts_")}

    def signiert(aud="app.example.com", iss=ISS, ttl=300, jetzt_=None, schluessel=None):
        return gate.ausstellen(schluessel or auth._gate_schluessel, iss=iss, aud=aud, sub=str(uid),
                               claims=eigene, ttl=ttl, jetzt=jetzt if jetzt_ is None else jetzt_)

    assert anfrage("/x", {"__Host-tinysesam_gate": signiert()})[0] == 200, "Gegenprobe: frisch signiert"
    k, i, s = tok.split(".")
    faelle = {
        # Flip a BYTE of the signature, do not replace the last characters: the last base64 characters
        # carry padding bits, and `…AA` instead of `…AB` is sometimes the same signature (1 in 256 runs).
        "Signatur verändert": f"{k}.{i}." + gate._b64u(bytes([gate._b64u_lesen(s)[0] ^ 1]) + gate._b64u_lesen(s)[1:]),
        "alg none": base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode() + f".{i}.",
        "fremder Schlüssel": signiert(schluessel=gate.schluessel_ableiten(b"\x00" * 32)),
        "abgelaufen": signiert(jetzt_=jetzt - 400),
        "anderer Aussteller": signiert(iss="https://evil.example"),
        "andere Zielgruppe": signiert(aud="wiki.example.com"),
        "Zielgruppe mit Rollen an einem Pfad ohne": signiert(aud="app.example.com|roles=admin"),
    }
    for was, falsch in faelle.items():
        vorher = FORWARD["n"]
        st, h, _ = anfrage("/x", {"__Host-tinysesam_gate": falsch}, {"Remote-User": "admin"})
        assert st == 302 and FORWARD["n"] == vorher + 1, (was, st)
    ok(f"{len(faelle)} forged gate cookies → way back, without session 302 (the counter-check gets through)")

    # With a session the way back replaces an expired token with a new one.
    st, h, _ = anfrage("/x", {**sitzung, "__Host-tinysesam_gate": faelle["abgelaufen"]})
    assert st == 200 and gate_cookie(h) and gate_cookie(h) != faelle["abgelaufen"]
    ok("expired token + session → 200 and a new gate cookie")

    # ---------- Signing out at the application (T-22): /.tinysesam/* bypasses the gate ----------
    vorher = FORWARD["n"]
    st, h, _ = anfrage("/.tinysesam/logout?scope=app", sitzung)
    assert st == 303 and h["Location"] == "/", (st, dict(h))
    assert any(v.startswith("__Host-tinysesam_gate=;") and "Max-Age=0" in v for v in h.get_all("Set-Cookie") or []), \
        h.get_all("Set-Cookie")
    assert FORWARD["n"] == vorher, "the sign-out path must not go through the gate (there is no sign-in to check)"
    st, h, _ = anfrage("/seite", sitzung)
    assert st == 302 and "/auth/login?next=" in h["Location"], (st, dict(h))
    ok("/.tinysesam/logout?scope=app through Caddy: past the gate, gate cookie deleted, then 302 to the login page")
    tc.post("/auth/gate/resume", data={"next": f"http://app.example.com:{PORT}/seite"}, follow_redirects=False)
    assert anfrage("/seite", sitzung)[0] == 200
    ok("“Continue as …” → the application lets through again")

    # ---------- Share exception (T-20): public only the prefix, without path tricks ----------
    def roh(pfad, kopf=None):
        """Like `anfrage`, but the path goes onto the wire UNCHANGED (http.client normalises
        nothing) — otherwise the test would not check the path tricks at all."""
        import http.client
        v = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        v.putrequest("GET", pfad, skip_host=True)
        v.putheader("Host", f"app.example.com:{PORT}")
        for k, w in (kopf or {}).items():
            v.putheader(k, w)
        v.endheaders()
        a = v.getresponse()
        roh_text = a.read()
        v.close()
        try:
            return a.status, json.loads(roh_text)
        except ValueError:
            return a.status, None

    offen = ["/s/abc", "/s/abc/def.js", "/public/share/x", "/s/abc?x=../../admin", "/s/a.b..c"]
    vorher = FORWARD["n"]
    for pfad in offen:
        st, a = roh(pfad, {"Remote-User": "admin", "Cookie": "tinysesam_session=GEHEIM; a=1"})
        assert st == 200 and a and a["header"].get("Remote-User") is None, (pfad, st, a and a["header"])
        assert a["header"].get("Cookie") == "a=1", (pfad, a["header"].get("Cookie"))
    assert FORWARD["n"] == vorher, "a share path must not ask TinySesam"
    ok(f"{len(offen)} share paths open, without TinySesam, without identity (none from the browser either), without TinySesam cookies")

    zu = ["/s/..;/admin", "/s/%2e%2e;/admin", "/s/abc;jsessionid=1", "/s/..%5cadmin", "/s/..\\admin",
          "/s%2f..%2fadmin", "/s/abc%00", "/x/../s/abc", "/s/../admin", "/s/./abc", "/S/abc", "//s/abc",
          "/s/%3b", "/sx/abc", "/s", "/admin/x.js"]
    for pfad in zu:
        vorher = FORWARD["n"]
        st, _ = roh(pfad)
        assert st == 302 and FORWARD["n"] == vorher + 1, (pfad, st)
    ok(f"{len(zu)} path tricks and neighbouring paths → through the gate (..;, %2e, %5c, NUL, /x/../s/, /S/, //s/ …)")

    # ---------- Abnahmemuster (T-24): deploy/forward-auth/abnahme.sh gegen diesen Aufbau ----------
    import shutil  # noqa: E402
    assert shutil.which("bash") and shutil.which("curl"), "abnahme.sh needs bash and curl"
    skript = ROOT / "deploy/forward-auth/abnahme.sh"
    umg_a = {**os.environ, "APP": f"http://app.example.com:{PORT}", "SHARE": "/s/abc123",
             "SESSION": "; ".join(f"{k}={v}" for k, v in sitzung.items()),
             "CURL_EXTRA": f"--resolve app.example.com:{PORT}:127.0.0.1"}
    a = subprocess.run(["bash", str(skript)], env=umg_a, capture_output=True, text=True, timeout=120)
    assert a.returncode == 0 and "bestanden" in a.stdout and "ROT" not in a.stdout, a.stdout + a.stderr
    zeilen = [z for z in a.stdout.splitlines() if z.startswith("  ok")]
    assert len(zeilen) >= 15, a.stdout
    ok(f"abnahme.sh gegen diesen Aufbau: {len(zeilen)} checks passed")
    # Counter-check: the script must turn red when an expectation is wrong — here a path that is
    # closed but is given as a share. Otherwise “passed” would also be the answer of a script that
    # checks nothing.
    a = subprocess.run(["bash", str(skript)], env={**umg_a, "SHARE": "/admin/x.js"},
                       capture_output=True, text=True, timeout=120)
    assert a.returncode == 1 and "ROT  Share-Pfad /admin/x.js ist offen" in a.stdout, a.stdout
    ok("counter-check: a path that is closed, given as share → abnahme.sh red (exit 1)")
    tc.post("/auth/gate/resume", data={"next": f"http://app.example.com:{PORT}/"}, follow_redirects=False)

    # ---------- the price: revocation only takes effect on expiry ----------
    auth.store.delete_user_sessions(uid)
    assert anfrage("/x", sitzung)[0] == 302
    assert anfrage("/x", {"__Host-tinysesam_gate": tok})[0] == 200
    ok("after signing out: session alone → 302, the gate token applies until its expiry (ADR-9)")

    # ---------- Counter-check: without gate the proxy asks every time again ----------
    tc.post("/auth/login", data={"username": "anna", "password": "geheim123", "next": "/"},
            follow_redirects=False)
    sitzung = {auth.session_cookie_name: tc.cookies.get(auth.session_cookie_name)}
    auth.cfg.gate_token_enabled = False
    vorher = FORWARD["n"]
    for i in range(3):
        st, h, _ = anfrage(f"/asset-{i}.js", sitzung)
        assert st == 200 and gate_cookie(h) is None
    assert FORWARD["n"] == vorher + 3
    auth.cfg.gate_token_enabled = True
    ok("gate_token_enabled=False → every request goes via /auth/forward (as without gate)")
finally:
    _caddy.terminate()
    try:
        _caddy.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _caddy.kill()
    _app_srv.shutdown()
    _ts_server.should_exit = True

print("Gate token through Caddy OK")
