"""nginx, nginx with PHP (FastCGI) and Traefik with the templates of deploy/forward-auth — real proxies, measured.

tests/test_gate_caddy.py measures the Caddy templates (the recommended way, with the gate token). nginx and Traefik are
supported too; every request of theirs goes through `/auth/forward`. The claims of their templates are claims about the
proxy, so they are measured with the proxy:

* without sign-in the template's answer (nginx: redirect to the sign-in, Traefik: 401 with `X-TinySesam-Location`);
* with a session the application sees TinySesam's `Remote-*`, `Remote-Auth` and `Remote-Kind` included;
* `Remote-User`, `Remote-Groups`, `Remote-Id`, `Remote-Auth`, `Remote-Kind`, `X-Original-URL` and `X-Forwarded-Host`
  sent by the client never reach the application — also when TinySesam sends NO value for a header (`forward_headers`
  reduced); a service account's API key arrives as `Remote-Kind: service` although the client says `user`;
* an API key signs in (`Remote-Auth: apikey`), and neither the key nor `Authorization` reaches the application or the
  proxy's log;
* `/.tinysesam/*` (top bar JSON, sign-out of the application, T-22) reaches TinySesam on the application's host.

The templates are used word for word; only the listen address, the upstream addresses and (nginx-path.conf) the
site root and the FastCGI address (TCP instead of the socket) point to this run. PHP is a FastCGI stand-in that answers
with the parameters nginx sent it — exactly what PHP would see as `$_SERVER`. The configuration is copied into the
containers (`docker cp`), not bind-mounted: no host file needs permissions for the proxy's worker user.

Images: the FROM lines of tests/proxies/Dockerfile (digest-pinned, Dependabot keeps them current). The suite runs when
TINYSESAM_PROXY_TESTS=1 — the CI job `gate-caddy` sets it, and then a missing Docker is an error. Without the variable
it reports "skipped" (locally: `sg docker -c 'TINYSESAM_PROXY_TESTS=1 python tests/test_proxies.py'`). The containers
use the host network, listen on 127.0.0.1 only, carry the label `tinysesam.test=proxies` and are removed afterwards.
"""
import http.server
import json
import os
import pathlib
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from voraussetzung import braucht, braucht_modul  # noqa: E402

# Static, runs without Docker too: nginx stands on the stable line (even minor), not on mainline (T-114).
_nginx_ref = re.search(r"^FROM nginx:(\d+)\.(\d+)\.\d+-alpine@sha256:", pathlib.Path(__file__).resolve().parent.joinpath(
    "proxies/Dockerfile").read_text(encoding="utf-8"), re.M)
assert _nginx_ref, "tests/proxies/Dockerfile: nginx must be pinned as `nginx:X.Y.Z-alpine@sha256:…` (stable line)"
assert int(_nginx_ref.group(2)) % 2 == 0, f"nginx {_nginx_ref.group(1)}.{_nginx_ref.group(2)} is mainline (odd minor) — T-114: stable only"

braucht(os.environ.get("TINYSESAM_PROXY_TESTS") == "1",
        "TINYSESAM_PROXY_TESTS not set — nginx and Traefik run in Docker (the CI job gate-caddy sets it)")
braucht_modul("uvicorn")
assert shutil.which("docker"), "TINYSESAM_PROXY_TESTS=1 but no docker"

import uvicorn  # noqa: E402
from fastapi import FastAPI  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

LABEL = "tinysesam.test=proxies"
IMAGES = dict((m.group(2), m.group(1)) for m in re.finditer(
    r"^FROM (\S+) AS (\w+)\s*$", (ROOT / "tests/proxies/Dockerfile").read_text(encoding="utf-8"), re.M))
assert set(IMAGES) == {"nginx", "traefik"} and all("@sha256:" in i for i in IMAGES.values()), IMAGES
_tmp = tempfile.mkdtemp()
PW = "a long test password 4711"


def ok(name):
    print(f"  ✓ {name}")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def docker(*args, check=True, timeout=180):
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise AssertionError(f"docker {' '.join(args)} → {p.returncode}\n{p.stdout[-2000:]}\n{p.stderr[-2000:]}")
    return p


# ---------- TinySesam ----------
auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="en", db_path=os.path.join(_tmp, "t.db"), passkey_enabled=False, oidc_enabled=False,
    cookie_secure=False, forward_auth_enabled=True, apikey_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com", "example.com"], trusted_proxies=["127.0.0.1/32"]))
uid = auth.create_user("anna", password=PW, roles=["editors"])
auth.store._exec("UPDATE users SET display_name=? WHERE id=?", ("Anna Example", uid))
TOKEN, _ = auth.start_session(uid, "password")
SESSION = f"{auth.session_cookie_name}={TOKEN}"
API_KEY = auth.create_api_key(uid, name="ci", expires_days=1)["key"]
bot = auth.create_service("backup-bot", roles=["editors"])
SERVICE_KEY = auth.create_api_key(bot, name="kind", expires_days=1)["key"]


def throwaway_session() -> str:
    """A session of its own for a sign-out probe — "signed out of this application" would hold for SESSION too."""
    return f"{auth.session_cookie_name}={auth.start_session(uid, 'password')[0]}"

ts_app = FastAPI()
ts_app.include_router(auth.router())
_ts_port = free_port()
TS = f"127.0.0.1:{_ts_port}"
_ts_server = uvicorn.Server(uvicorn.Config(ts_app, host="127.0.0.1", port=_ts_port, log_level="critical"))
threading.Thread(target=_ts_server.run, daemon=True).start()


# ---------- the application: reports back what arrives at it ----------
class Application(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"app": True, "path": self.path, "header": {k: v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


_app = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Application)
APP = f"127.0.0.1:{_app.server_address[1]}"
threading.Thread(target=_app.serve_forever, daemon=True).start()


# ---------- PHP: a FastCGI responder that answers with the parameters it got ----------
def _fcgi_record(kind: int, request_id: int, content: bytes) -> bytes:
    return struct.pack("!BBHHBx", 1, kind, request_id, len(content), 0) + content


def _fcgi_pairs(data: bytes) -> dict:
    out, i = {}, 0
    while i < len(data):
        lengths = []
        for _ in range(2):
            n = data[i]
            if n >> 7:
                n = struct.unpack("!I", data[i:i + 4])[0] & 0x7FFFFFFF
                i += 4
            else:
                i += 1
            lengths.append(n)
        name = data[i:i + lengths[0]].decode("latin-1")
        i += lengths[0]
        out.setdefault(name, []).append(data[i:i + lengths[1]].decode("latin-1"))
        i += lengths[1]
    return out


class FastCGI(socketserver.StreamRequestHandler):
    """One request per connection (nginx does not keep FastCGI connections without `fastcgi_keep_conn`). Every value
    of a parameter is kept: a header nginx passed twice would show up as two values."""

    def handle(self):
        params = b""
        while True:
            head = self.rfile.read(8)
            if len(head) < 8:
                return
            _, kind, request_id, length, padding = struct.unpack("!BBHHBx", head)
            content = self.rfile.read(length)
            self.rfile.read(padding)
            if kind == 4:
                params += content
            elif kind == 5 and length == 0:
                break
        raw = _fcgi_pairs(params)
        body = json.dumps({"php": True, "params": raw}).encode()
        out = b"Status: 200 OK\r\nContent-Type: application/json\r\n\r\n" + body
        self.wfile.write(_fcgi_record(6, request_id, out) + _fcgi_record(6, request_id, b"")
                         + _fcgi_record(3, request_id, struct.pack("!IB3x", 0, 0)))


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


# Over TCP on 127.0.0.1 instead of the template's unix socket: a socket shared with the container would have to be
# writable for nginx's worker user.
_php = _TCPServer(("127.0.0.1", 0), FastCGI)
PHP = f"127.0.0.1:{_php.server_address[1]}"
threading.Thread(target=_php.serve_forever, daemon=True).start()

for _ in range(100):
    try:
        urllib.request.urlopen(f"http://{TS}/auth/forward", timeout=1)
    except urllib.error.HTTPError:
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("TinySesam does not start")


# ---------- the proxies ----------
CONTAINERS = []


def start(name: str, image: str, copies: list, port: int, command=()) -> str:
    """Create the container, copy the configuration in (owned by root there — no bind mount whose host permissions
    the proxy's worker user would need), start it and wait for its port."""
    cname = f"tsproxy-{name}-{os.getpid()}"
    docker("create", "--rm", "--network", "host", "--label", LABEL, "--name", cname, image, *command)
    CONTAINERS.append(cname)
    for src, dst in copies:
        docker("cp", src, f"{cname}:{dst}")
    docker("start", cname)
    for _ in range(150):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return cname
        except OSError:
            if docker("inspect", "-f", "{{.State.Running}}", cname, check=False).stdout.strip() != "true":
                break
            time.sleep(0.2)
    logs = docker("logs", cname, check=False)
    raise RuntimeError(f"{name} does not start:\n{logs.stdout[-2000:]}\n{logs.stderr[-2000:]}")


def logs_of(cname: str) -> str:
    p = docker("logs", cname, check=False)
    return p.stdout + p.stderr


def nginx_config(template: str, port: int) -> str:
    text = (ROOT / "deploy/forward-auth" / template).read_text(encoding="utf-8")
    assert text.count("listen 443 ssl;") == 1, "the listen line of the template has shifted"
    text = text.replace("listen 443 ssl;", f"listen 127.0.0.1:{port};")
    assert "127.0.0.1:8000" in text, "the TinySesam upstream of the template has shifted"
    text = text.replace("127.0.0.1:8000", TS).replace("127.0.0.1:9000", APP)
    return text.replace("unix:/run/php/php-fpm.sock", PHP).replace("root /var/www/example;", f"root {SITE};")


#: Where nginx-path.conf's site lies in the container (the template's /var/www has no parent in the image).
SITE = "/usr/share/nginx/example"


#: Debian's snippet (`snippets/fastcgi-php.conf`, which nginx-path.conf includes) — the official image has none.
FASTCGI_PHP = """fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
try_files $fastcgi_script_name =404;
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;
fastcgi_index index.php;
include fastcgi.conf;
"""


def write(path: str, text: str) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def start_nginx(template: str, name: str):
    port = free_port()
    conf = write(os.path.join(_tmp, name, "default.conf"), nginx_config(template, port))
    snippet = write(os.path.join(_tmp, name, "snippets", "fastcgi-php.conf"), FASTCGI_PHP)
    site = os.path.join(_tmp, name, "www")
    for page in ("intern/page.php", "open.php"):
        write(os.path.join(site, page), "<?php // the FastCGI stand-in answers, not this file\n")
    copies = [(conf, "/etc/nginx/conf.d/default.conf"), (os.path.dirname(snippet), "/etc/nginx/snippets"),
              (site, SITE)]
    return start(name, IMAGES["nginx"], copies, port), port


def traefik_dynamic(template_text: str) -> str:
    text = template_text.replace("http://tinysesam:8000", f"http://{TS}")
    text = text.replace("http://127.0.0.1:9000", f"http://{APP}")
    assert f"http://{TS}/auth/forward" in text and f"http://{APP}" in text, "the addresses of the template have shifted"
    return text


def start_traefik(name="traefik"):
    port = free_port()
    write(os.path.join(_tmp, name, "dynamic.yml"),
          traefik_dynamic((ROOT / "deploy/forward-auth/traefik.yml").read_text("utf-8")))
    static = write(os.path.join(_tmp, name, "traefik.yml"), (
        "entryPoints:\n"
        f"  web:\n    address: \"127.0.0.1:{port}\"\n"
        "providers:\n  file:\n    filename: /tsconf/dynamic.yml\n"
        "accessLog: {}\n"
        # The static setting the template's header asks for: a header whose name aliases another (`Remote_User`,
        # `Remote.User`) is deleted at the entry point, otherwise a CGI/WSGI/PHP backend reads it as `Remote-User`.
        "global:\n  aliasHeadersStrategy: delete\n"
        "log:\n  level: INFO\n"))
    return start(name, IMAGES["traefik"], [(os.path.dirname(static), "/tsconf")], port,
                 command=("--configFile=/tsconf/traefik.yml",)), port


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def request(port, path, host, head=None, cookies=None):
    h = {"Host": host, **(head or {})}
    if cookies:
        h["Cookie"] = cookies
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        r = _opener.open(req, timeout=15)
        status, headers, raw = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, headers, raw = e.code, e.headers, e.read()
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    return status, headers, data


#: What a client forges. TinySesam's own values must arrive instead, or nothing.
FORGED = {"Remote-User": "admin", "Remote-Groups": "admin", "Remote-Id": "1", "Remote-Auth": "oauth",
          "Remote-Email": "boss@example.com", "Remote-Name": "Boss", "Remote-Kind": "service",
          "X-Original-URL": "https://evil.example/", "X-Forwarded-Host": "evil.example",
          # Aliases: a CGI/WSGI/PHP backend derives HTTP_REMOTE_USER from `Remote_User` and `Remote.User` too.
          "Remote_User": "admin", "Remote.Groups": "admin", "Remote_Kind": "service"}


def lower(d) -> dict:
    return {k.lower(): v for k, v in (d or {}).items()}


def app_header_checks(was, hd, *, auth_kind):
    """The application's view after a successful check: TinySesam's identity, never the forgery."""
    assert hd.get("remote-user") == "anna" and hd.get("remote-groups") == "editors", (was, hd)
    assert hd.get("remote-id") == str(uid) and hd.get("remote-auth") == auth_kind, (was, hd)
    assert hd.get("remote-kind") == "user", (was, "Remote-Kind: the client's service or nothing", hd)
    assert hd.get("remote-name") == "Anna Example" and hd.get("remote-email", "") == "", (was, hd)
    assert "x-original-url" not in hd, (was, "X-Original-URL from the client reaches the application", hd)
    assert hd.get("x-forwarded-host", "") != "evil.example", (was, "X-Forwarded-Host from the client", hd)
    assert "authorization" not in hd and "x-api-key" not in hd, (was, "a credential reaches the application", hd)
    aliases = [k for k in hd if re.sub(r"[_.]", "-", k) != k and re.sub(r"[_.]", "-", k).startswith("remote-")]
    assert not aliases, (was, "an alias of a Remote-* header reaches the application", aliases)


def reduced_checks(was, hd):
    """forward_headers without email/name/id/auth: TinySesam sends no value — the forgery must not fill the gap."""
    leaked = {k: v for k, v in hd.items() if k in ("remote-email", "remote-name", "remote-id", "remote-auth")}
    assert not leaked, (was, "a forged header passes where TinySesam sends none", leaked)
    assert hd.get("remote-user") == "anna", (was, hd)
    assert hd.get("remote-kind") == "user", (was, "the mandatory Remote-Kind, TinySesam's value", hd)


def service_checks(was, hd):
    """A service account's API key, the client claiming `user`: TinySesam's `service` arrives, once."""
    assert hd.get("remote-user") == "backup-bot" and hd.get("remote-kind") == "service", (was, hd)
    assert hd.get("remote-auth") == "apikey", (was, hd)


SERVICE_FORGED = {**FORGED, "Remote-Kind": "user", "Remote_Kind": "user", "X-Api-Key": SERVICE_KEY}


try:
    # ══ nginx (nginx.conf: a whole host, application on :9000) ═══════════════════════════════════════════════════
    ng, NG = start_nginx("nginx.conf", "nginx")
    st, h, a = request(NG, "/", "app.example.com")
    assert st == 302 and "/auth/login?next=" in (h.get("Location") or ""), (st, dict(h))
    st, h, a = request(NG, "/x", "app.example.com", FORGED, SESSION)
    assert st == 200 and a and a.get("app"), (st, a)
    app_header_checks("nginx, session", lower(a["header"]), auth_kind="session")
    assert "tinysesam" not in (lower(a["header"]).get("cookie") or ""), a["header"]
    for head in ({"Authorization": f"Bearer {API_KEY}"}, {"X-Api-Key": API_KEY}):
        st, h, a = request(NG, "/key", "app.example.com", {**FORGED, **head, "Remote-Auth": "session"})
        assert st == 200 and a and a.get("app"), (st, a)
        app_header_checks(f"nginx, {list(head)[0]}", lower(a["header"]), auth_kind="apikey")
    st, h, a = request(NG, "/service", "app.example.com", SERVICE_FORGED)
    assert st == 200 and a and a.get("app"), (st, a)
    service_checks("nginx, service key", lower(a["header"]))
    auth.cfg.forward_headers = {"user": "Remote-User", "groups": "Remote-Groups"}
    try:
        st, h, a = request(NG, "/reduced", "app.example.com", FORGED, SESSION)
        assert st == 200, st
        reduced_checks("nginx, reduced", lower(a["header"]))
    finally:
        auth.cfg.forward_headers = {}
    st, h, a = request(NG, "/.tinysesam/topbar.json", "app.example.com", cookies=SESSION)
    assert st == 200 and a and a.get("signed_in") is True and not a.get("app"), (st, a)
    st, h, a = request(NG, "/.tinysesam/account.json", "app.example.com", cookies=SESSION)       # T-91
    assert st == 200 and a and a.get("signed_in") is True and a.get("account") and not a.get("app"), (st, a)
    assert h.get("Cache-Control") == "no-store", dict(h)
    st, h, a = request(NG, "/.tinysesam/logout?scope=app", "app.example.com", cookies=throwaway_session())
    assert st in (200, 303) and not (a and a.get("app")), ("sign-out reached the application", st, a)
    log = logs_of(ng)
    assert API_KEY not in log and API_KEY[:12] not in log and TOKEN[:12] not in log, "a credential in nginx's log"
    ok("nginx: anonymous → redirect to the sign-in; session and API key (Bearer, X-Api-Key) → TinySesam's Remote-* "
       "incl. Remote-Auth and Remote-Kind (a service key → service), no forgery (also X-Original-URL, X-Forwarded-Host, and where TinySesam sends no value), no "
       "credential at the application or in the log; /.tinysesam/* reaches TinySesam")

    # ══ nginx with PHP (nginx-path.conf: one host, protected paths, FastCGI) ═════════════════════════════════════
    ngp, NGP = start_nginx("nginx-path.conf", "nginx-path")

    def php_params(was, a):
        assert a and a.get("php"), (was, "not answered by PHP", a)
        params = a["params"]
        doubled = {k: v for k, v in params.items() if k.startswith("HTTP_") and len(v) > 1}
        assert not doubled, (was, "a header reaches PHP twice", doubled)
        return {k: v[0] for k, v in params.items()}

    st, h, a = request(NGP, "/intern/page.php", "example.com")
    assert st == 302 and "/auth/login?next=" in (h.get("Location") or ""), (st, dict(h))
    st, h, a = request(NGP, "/intern/page.php", "example.com", FORGED, SESSION)
    p = php_params("nginx-path, session", a)
    assert p.get("HTTP_REMOTE_USER") == "anna" and p.get("HTTP_REMOTE_GROUPS") == "editors", p
    assert p.get("HTTP_REMOTE_ID") == str(uid) and p.get("HTTP_REMOTE_AUTH") == "session", p
    assert p.get("HTTP_REMOTE_KIND") == "user", ("the client's Remote-Kind reaches PHP", p.get("HTTP_REMOTE_KIND"))
    assert p.get("HTTP_REMOTE_NAME") == "Anna Example" and p.get("HTTP_REMOTE_EMAIL", "") == "", p
    assert p.get("HTTP_X_ORIGINAL_URL", "") == "" and p.get("HTTP_X_FORWARDED_HOST", "") != "evil.example", p
    assert "tinysesam" not in p.get("HTTP_COOKIE", ""), p
    st, h, a = request(NGP, "/intern/page.php", "example.com", {**FORGED, "Authorization": f"Bearer {API_KEY}"})
    p = php_params("nginx-path, API key", a)
    assert p.get("HTTP_REMOTE_AUTH") == "apikey" and p.get("HTTP_AUTHORIZATION", "") == "", p
    p = php_params("nginx-path, service key", request(NGP, "/intern/page.php", "example.com", SERVICE_FORGED)[2])
    assert p.get("HTTP_REMOTE_KIND") == "service" and p.get("HTTP_REMOTE_USER") == "backup-bot", p
    auth.cfg.forward_headers = {"user": "Remote-User", "groups": "Remote-Groups"}
    try:
        p = php_params("nginx-path, reduced", request(NGP, "/intern/page.php", "example.com", FORGED, SESSION)[2])
        leaked = {k: v for k, v in p.items() if k in ("HTTP_REMOTE_EMAIL", "HTTP_REMOTE_NAME", "HTTP_REMOTE_ID",
                                                      "HTTP_REMOTE_AUTH") and v}
        assert not leaked and p.get("HTTP_REMOTE_USER") == "anna", leaked
        assert p.get("HTTP_REMOTE_KIND") == "user", p.get("HTTP_REMOTE_KIND")
    finally:
        auth.cfg.forward_headers = {}
    # The open remainder: no gate, and every identity header the client sends is emptied.
    st, h, a = request(NGP, "/open.php", "example.com", FORGED)
    p = php_params("nginx-path, open part", a)
    leaked = {k: v for k, v in p.items() if k.startswith("HTTP_REMOTE_") and v}
    assert not leaked, ("the open part passes the client's identity to PHP", leaked)
    st, h, a = request(NGP, "/.tinysesam/topbar.json", "example.com", cookies=SESSION)
    assert st == 200 and a and a.get("signed_in") is True and not a.get("php"), (st, a)
    st, h, a = request(NGP, "/.tinysesam/account.json", "example.com", cookies=SESSION)       # T-91
    assert st == 200 and a and a.get("signed_in") is True and a.get("account") and not a.get("php"), (st, a)
    assert h.get("Cache-Control") == "no-store", dict(h)
    log = logs_of(ngp)
    assert API_KEY not in log and API_KEY[:12] not in log, "a credential in nginx's log"
    ok("nginx + PHP (FastCGI): anonymous → redirect; session and API key → $_SERVER carries TinySesam's Remote-* incl. "
       "Remote-Id, Remote-Auth and Remote-Kind once each, no forgery (also where TinySesam sends no value), no Authorization; the "
       "open part empties every Remote-* the client sends")

    # ══ Traefik (forwardAuth middleware, file provider) ══════════════════════════════════════════════════════════
    tr, TR = start_traefik()
    for _ in range(50):                               # the file provider loads the dynamic configuration a moment later
        if request(TR, "/", "app.example.com")[0] != 404:
            break
        time.sleep(0.2)
    st, h, a = request(TR, "/", "app.example.com")
    assert st == 401 and "/auth/login?next=" in (h.get("X-Tinysesam-Location") or ""), (st, dict(h))
    st, h, a = request(TR, "/plain", "app.example.com", cookies=SESSION)
    assert st == 200 and a and a.get("app"), ("Traefik, session without forgery", st, dict(h), logs_of(tr)[-1500:])
    st, h, a = request(TR, "/x", "app.example.com", FORGED, SESSION)
    assert st == 200 and a and a.get("app"), (st, a)
    app_header_checks("Traefik, session", lower(a["header"]), auth_kind="session")
    for head in ({"Authorization": f"Bearer {API_KEY}"}, {"X-Api-Key": API_KEY}):
        st, h, a = request(TR, "/key", "app.example.com", {**FORGED, **head, "Remote-Auth": "session"})
        assert st == 200 and a and a.get("app"), (st, a)
        app_header_checks(f"Traefik, {list(head)[0]}", lower(a["header"]), auth_kind="apikey")
    st, h, a = request(TR, "/service", "app.example.com", SERVICE_FORGED)
    assert st == 200 and a and a.get("app"), (st, a)
    service_checks("Traefik, service key", lower(a["header"]))
    auth.cfg.forward_headers = {"user": "Remote-User", "groups": "Remote-Groups"}
    try:
        st, h, a = request(TR, "/reduced", "app.example.com", FORGED, SESSION)
        assert st == 200, st
        reduced_checks("Traefik, reduced", lower(a["header"]))
    finally:
        auth.cfg.forward_headers = {}
    st, h, a = request(TR, "/.tinysesam/topbar.json", "app.example.com", cookies=SESSION)
    assert st == 200 and a and a.get("signed_in") is True and not a.get("app"), (st, a)
    st, h, a = request(TR, "/.tinysesam/account.json", "app.example.com", cookies=SESSION)       # T-91
    assert st == 200 and a and a.get("signed_in") is True and a.get("account") and not a.get("app"), (st, a)
    assert h.get("Cache-Control") == "no-store", dict(h)
    st, h, a = request(TR, "/.tinysesam/logout?scope=app", "app.example.com", cookies=throwaway_session())
    assert st in (200, 303) and not (a and a.get("app")), ("sign-out reached the application", st, a)
    log = logs_of(tr)
    assert API_KEY not in log and API_KEY[:12] not in log and TOKEN[:12] not in log, "a credential in Traefik's log"
    ok("Traefik: anonymous → 401 with X-TinySesam-Location; session and API key → TinySesam's Remote-* incl. "
       "Remote-Auth and Remote-Kind (a service key → service), no forgery (also where TinySesam sends no value), no credential at the application or in the "
       "access log; /.tinysesam/* reaches TinySesam")
finally:
    for c in CONTAINERS:
        docker("rm", "-f", c, check=False)
    _app.shutdown()
    _php.shutdown()
