"""Gate-Token durch einen ECHTEN Caddy mit caddy-jwt — die Vorlage deploy/forward-auth/Caddyfile.gate.

Die Behauptung von ADR-9 ist eine über den Proxy: Mit gültigem Gate-Cookie erreicht eine Anfrage
die Anwendung, ohne dass TinySesam gefragt wird. Das lässt sich nur mit dem Proxy selbst belegen.
Gestartet werden TinySesam (uvicorn), eine Attrappe der Anwendung, die zurückmeldet, was bei ihr
ankommt, und Caddy mit der Vorlage aus dem Repo — Wort für Wort, nur die Site-Adressen zeigen auf
einen freien Port und `auto_https` ist aus.

Caddy mit dem Plugin kommt aus TINYSESAM_GATE_CADDY (Pfad zur Binärdatei). Der CI-Job `gate-caddy`
baut sie aus deploy/forward-auth/caddy-gate/Dockerfile und setzt die Variable — ist sie gesetzt,
ist die Binärdatei Pflicht. Ohne Variable meldet die Suite „übersprungen" mit Grund.
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
# Gesetzt heisst Pflicht: Ein falscher Pfad oder ein Caddy ohne Plugin ist ein Fehler, kein Skip.
assert os.access(CADDY, os.X_OK), f"TINYSESAM_GATE_CADDY={CADDY!r} ist keine ausführbare Datei"
_module = subprocess.run([CADDY, "list-modules"], capture_output=True, text=True, timeout=30).stdout
assert "http.authentication.providers.jwt" in _module.split(), "dieser Caddy hat caddy-jwt nicht"

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


# ---------- Attrappe der Anwendung: meldet zurück, was bei ihr ankommt ----------
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


# ---------- Caddy mit der Vorlage aus dem Repo ----------
def caddy_starten():
    """Caddy braucht einen Port, den es selbst bindet — ein gebundener Socket lässt sich nicht
    übergeben. Also einen freien suchen, freigeben und Caddy binden lassen; scheitert das (ein
    anderer Prozess war schneller), mit dem nächsten noch einmal."""
    vorlage = (ROOT / "deploy/forward-auth/Caddyfile.gate").read_text(encoding="utf-8")
    for _ in range(5):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        text = "{\n\tauto_https off\n\tadmin off\n}\n" + vorlage
        text = text.replace("\nauth.example.com {", f"\nhttp://auth.example.com:{port} {{", 1)
        text = text.replace("\napp.example.com {", f"\nhttp://app.example.com:{port} {{", 1)
        assert text.count(f":{port} {{") == 2, "die Site-Adressen der Vorlage haben sich verschoben"
        datei = os.path.join(_tmp, "Caddyfile")
        with open(datei, "w", encoding="utf-8") as f:
            f.write(text)
        umg = {**os.environ, "TS_GATE_PUBKEY": auth.gate_public_key(), "TS_GATE_ISSUER": ISS,
               "TS_AUTH_UPSTREAM": TS, "TS_APP_UPSTREAM": APP, "XDG_DATA_HOME": _tmp,
               "XDG_CONFIG_HOME": _tmp}
        # Popen gibt dem Kind eine eigene Kopie des Datei-Deskriptors — die des Elternprozesses
        # darf gleich wieder zu.
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
    """Eine Anfrage an Caddy, Host app.example.com. Rückgabe (Status, Header, JSON der Attrappe)."""
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
    """Header kommen bei http.client als Latin-1 an; TinySesam schickt UTF-8 über die Leitung."""
    return wert.encode("latin-1").decode("utf-8") if wert is not None else None


try:
    # ---------- ohne Anmeldung ----------
    st, h, _ = anfrage("/start")
    assert st == 302 and "/auth/login?next=" in h["Location"], (st, dict(h))
    assert FORWARD["n"] == 1
    ok("ohne Anmeldung → 302 zum Login (Rückweg über /auth/forward)")

    # ---------- Sitzung, noch kein Gate-Cookie: Rückweg, neues Token ----------
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
    assert tok, f"kein Gate-Cookie in der Antwort: {h.get_all('Set-Cookie')}"
    assert "app_eigen=1; Path=/" in (h.get_all("Set-Cookie") or []), "das Cookie der Anwendung fehlt"
    assert a["methode"] == "POST" and a["body"] == "feld=wert", a
    assert a["header"].get("Remote-User") == "anna", a["header"]
    assert "tinysesam" not in (a["header"].get("Cookie") or ""), a["header"].get("Cookie")
    ok("Sitzung ohne Gate-Cookie → Rückweg: 200, POST samt Body, neues Gate-Cookie, "
       "Remote-User vom Browser überschrieben, TinySesam-Cookies entfernt")

    # ---------- mit Gate-Cookie: TinySesam wird nicht gefragt ----------
    mit_gate = {**sitzung, "__Host-tinysesam_gate": tok, "andere": "1"}
    vorher = FORWARD["n"]
    for i in range(10):
        st, h, a = anfrage(f"/asset-{i}.js", mit_gate, {"Remote-User": "admin", "Remote-Groups": "admin",
                                                         "Remote-Email": "chef@example.com"})
        assert st == 200 and a["pfad"] == f"/asset-{i}.js", (st, a)
    assert FORWARD["n"] == vorher, f"{FORWARD['n'] - vorher} Aufrufe bei TinySesam trotz gültigem Gate-Cookie"
    hd = a["header"]
    assert hd.get("Remote-User") == "anna" and hd.get("Remote-Groups") == "redaktion", hd
    assert utf8(hd.get("Remote-Name")) == "Anna Ärger", hd.get("Remote-Name")
    assert hd.get("Remote-Id") == str(uid), hd
    # Anna hat keine Adresse — der Claim ist leer. Die Adresse aus dem Browser darf trotzdem nicht
    # durchkommen: Dafür entfernt die Vorlage jeden Remote-* der Anfrage, bevor sie ihn setzt.
    assert hd.get("Remote-Email", "") == "", hd.get("Remote-Email")
    assert hd.get("Cookie") == "andere=1", hd.get("Cookie")
    assert gate_cookie(h) is None, "auf dem schnellen Weg wird kein neues Token ausgestellt"
    ok("gültiges Gate-Cookie → 10 Anfragen bei der Anwendung, 0 bei TinySesam; Identität aus dem "
       "Token (UTF-8 wie bei /auth/forward), Remote-* vom Browser überschrieben, Gate-Cookie entfernt")

    # ---------- jede Verfälschung fällt auf den Rückweg ----------
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
        # Ein BYTE der Signatur kippen, nicht die letzten Zeichen ersetzen: Die letzten Base64-Zeichen
        # tragen Füllbits, und `…AA` statt `…AB` ist mitunter dieselbe Signatur (1 in 256 Läufen).
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
    ok(f"{len(faelle)} verfälschte Gate-Cookies → Rückweg, ohne Sitzung 302 (die Gegenprobe kommt durch)")

    # Mit Sitzung ersetzt der Rückweg ein abgelaufenes Token durch ein neues.
    st, h, _ = anfrage("/x", {**sitzung, "__Host-tinysesam_gate": faelle["abgelaufen"]})
    assert st == 200 and gate_cookie(h) and gate_cookie(h) != faelle["abgelaufen"]
    ok("abgelaufenes Token + Sitzung → 200 und ein neues Gate-Cookie")

    # ---------- der Preis: Widerruf greift erst mit Ablauf ----------
    auth.store.delete_user_sessions(uid)
    assert anfrage("/x", sitzung)[0] == 302
    assert anfrage("/x", {"__Host-tinysesam_gate": tok})[0] == 200
    ok("nach dem Abmelden: Sitzung allein → 302, das Gate-Token gilt bis zu seinem Ablauf (ADR-9)")

    # ---------- Gegenprobe: ohne Gate fragt der Proxy wieder jedes Mal ----------
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
    ok("gate_token_enabled=False → jede Anfrage geht über /auth/forward (wie ohne Gate)")
finally:
    _caddy.terminate()
    try:
        _caddy.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _caddy.kill()
    _app_srv.shutdown()
    _ts_server.should_exit = True

print("Gate-Token durch Caddy OK")
