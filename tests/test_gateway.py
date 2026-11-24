"""OIDC-Forward-Auth-Gateway-Preset: TinySesamConfig.oidc_gateway + tinysesam.gateway."""
import os
import re
import time
import tempfile, os
from fastapi.testclient import TestClient
from urllib.parse import parse_qs, urlparse
from tinysesam import TinySesam, TinySesamConfig, security
from tinysesam import gateway


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
cfg = TinySesamConfig.oidc_gateway(csrf_enabled=False, 
    issuer="https://id.example.invalid", client_id="cid", client_secret="sec",
    base_url="https://auth.example.com", cookie_domain=".example.com",
    trusted_redirect_hosts=["app.example.com"], db_path=db)

# ---------- Preset sets the right flags ----------
assert cfg.oidc_enabled and cfg.forward_auth_enabled
assert not (cfg.password_enabled or cfg.pin_enabled or cfg.passkey_enabled or cfg.magiclink_enabled)
assert not (cfg.admin_enabled or cfg.account_enabled or cfg.apikey_enabled or cfg.allow_signup
            or cfg.resource_locks_enabled or cfg.totp_enabled)
assert cfg.enabled_methods() == ["oidc"]
ok("oidc_gateway preset: only OIDC + forward auth active, everything else off")

app = gateway.build_app(cfg)
c = TestClient(app, raise_server_exceptions=False)

# ---------- OIDC-only: only OIDC login, no other methods/routes ----------
html = c.get("/auth/login").text
assert "/auth/oidc/start" in html and "name=password" not in html
ok("login page: only OIDC button, no password form")
assert c.post("/auth/login", data={"username": "x", "password": "y"}).status_code == 404
for path in ("/auth/pin", "/auth/register", "/auth/account", "/auth/magic/request"):
    assert c.get(path, follow_redirects=False).status_code == 404, path
ok("password/PIN/register/account/magic are off (404)")

# ---------- Forward auth: not logged in → 401 + login URL back to the app ----------
r = c.get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com",
                                    "X-Forwarded-Uri": "/secret"})
assert r.status_code == 401
loc = r.headers.get("X-TinySesam-Location")
assert loc and loc.startswith("https://auth.example.com/auth/login?next=") and urlparse(parse_qs(urlparse(loc).query)["next"][0]).netloc == "app.example.com"
ok("Forward-Auth: 401 + X-TinySesam-Location (central login, next=app URL)")

# ---------- Config from env ----------
os.environ.update({
    "TINYSESAM_OIDC_ISSUER": "https://id.example.invalid", "TINYSESAM_OIDC_CLIENT_ID": "cid",
    "TINYSESAM_OIDC_CLIENT_SECRET": "sec", "TINYSESAM_BASE_URL": "https://auth.example.com",
    "TINYSESAM_PROTECTED_HOSTS": "app.example.com, wiki.example.com", "TINYSESAM_DB": db})
envcfg = gateway.config_from_env()
assert envcfg.oidc_client_id == "cid" and envcfg.forward_auth_enabled
assert envcfg.trusted_redirect_hosts == ["app.example.com", "wiki.example.com"]
ok("config_from_env: Env → Gateway-Config (Hosts geparst)")

assert envcfg.lang == "en"
os.environ["TINYSESAM_LANG"] = "de"
assert gateway.config_from_env().lang == "de"
os.environ["TINYSESAM_LANG"] = "klingonisch"
try:
    gateway.config_from_env(); assert False, "unknown language starts"
except SystemExit as e:
    assert "TINYSESAM_LANG" in str(e)
del os.environ["TINYSESAM_LANG"]
os.environ["TINYSESAM_OIDC_NAME"] = "PocketID"
assert gateway.config_from_env().oidc_name == "PocketID"
del os.environ["TINYSESAM_OIDC_NAME"]
assert gateway.config_from_env().oidc_name == "SSO"
ok("TINYSESAM_LANG: default en, de selectable, unknown → start error; TINYSESAM_OIDC_NAME names the button")
assert gateway.config_from_env().gate_brand == ""
os.environ["TINYSESAM_GATE_BRAND"] = "  Company A  "
assert gateway.config_from_env().gate_brand == "Company A"
del os.environ["TINYSESAM_GATE_BRAND"]
ok("TINYSESAM_GATE_BRAND: empty by default, set without margin")

# OAuth for MCP clients (T-36) behind the gateway: one variable, off without it. Until 2026-11-20 the gateway had no
# way to switch it on — the proxy templates routed /.well-known/oauth-protected-resource* to a gateway that always said 404.
assert not envcfg.oauth_enabled and envcfg.oauth_resources == []
os.environ["TINYSESAM_OAUTH_RESOURCES"] = " https://app.example.com/mcp , "
_oauth_cfg = gateway.config_from_env()
assert _oauth_cfg.oauth_enabled and _oauth_cfg.oauth_resources == ["https://app.example.com/mcp"], _oauth_cfg
del os.environ["TINYSESAM_OAUTH_RESOURCES"]
from fastapi.testclient import TestClient as _OAuthClient  # noqa: E402
_meta = _OAuthClient(gateway.build_app(_oauth_cfg)).get(
    "/.well-known/oauth-protected-resource/mcp", headers={"Host": "app.example.com", "X-Forwarded-Proto": "https"})
assert _meta.status_code == 200 and _meta.json()["resource"] == "https://app.example.com/mcp", (_meta.status_code,
                                                                                               _meta.text)
ok("TINYSESAM_OAUTH_RESOURCES: off by default; set, the gateway answers the resource metadata of the application")

# Services (T-60) and the top bar's links (T-64) behind the gateway: both had no variable, so the gateway image could
# switch neither on. (Mutation probe: leave either out of `config_from_env` → red.)
assert envcfg.oauth_service_clients is False and envcfg.topbar_links == []
os.environ["TINYSESAM_OAUTH_RESOURCES"] = "https://app.example.com/mcp"
os.environ["TINYSESAM_OAUTH_SERVICE_CLIENTS"] = "1"
os.environ["TINYSESAM_TOPBAR_LINKS"] = '[["Wiki", "/wiki"], ["Files", "https://app.example.com/files/"]]'
_svc_cfg = gateway.config_from_env()
assert _svc_cfg.oauth_service_clients is True, _svc_cfg.oauth_service_clients
assert _svc_cfg.topbar_links == [("Wiki", "/wiki"), ("Files", "https://app.example.com/files/")], _svc_cfg.topbar_links
for broken in ('{"Wiki": "/wiki"}', '[["Wiki"]]', '[["Wiki", 3]]', "[not json"):
    os.environ["TINYSESAM_TOPBAR_LINKS"] = broken
    try:
        gateway.config_from_env(); assert False, f"broken TINYSESAM_TOPBAR_LINKS accepted: {broken}"
    except SystemExit as e:
        assert "TINYSESAM_TOPBAR_LINKS" in str(e), e
del os.environ["TINYSESAM_TOPBAR_LINKS"]
ok("TINYSESAM_OAUTH_SERVICE_CLIENTS and TINYSESAM_TOPBAR_LINKS: off/empty by default, set they reach the config, "
   "broken JSON ends the start")

# A pairing code from the command line (T-60 follow-up): the gateway has neither account page nor admin panel, so a
# service could not be paired at all. `python -m tinysesam.gateway pair` issues it through the same building block
# (`create_service_pairing`: resources, roles, audit). (Mutation probe: drop the `pair` branch of `main` → red.)
import contextlib as _ctx  # noqa: E402
import io as _io  # noqa: E402
os.environ["TINYSESAM_DB"] = os.path.join(tempfile.mkdtemp(), "pair.db")
_out, _err = _io.StringIO(), _io.StringIO()
with _ctx.redirect_stdout(_out), _ctx.redirect_stderr(_err):
    _rc = gateway.main(["pair", "backup-job", "--create-service", "--name", "nightly backup"])
assert _rc == 0, (_rc, _err.getvalue())
_m = re.search(r"\b([A-Z0-9]{4}(?:-[A-Z0-9]{4}){3,})\b", _out.getvalue())
assert _m and "tinysesam-client pair https://auth.example.com" in _out.getvalue(), _out.getvalue()
_pa = TinySesam(gateway.config_from_env())
_svc = _pa.store.get_user_by_name("backup-job")
assert _svc is not None and _svc["is_service"], "the service account was not created"
from tinysesam import oauth_services as _os_mod  # noqa: E402
_tok = _pa.store._one("SELECT * FROM magic_token WHERE token_hash=? AND purpose='oauth_pairing'",
                      (_pa.store.token_digest(_os_mod.code_digest(_os_mod.normalize_code(_m.group(1))), "magic"),))
assert _tok is not None and int(_tok["user_id"]) == int(_svc["id"]), "the printed code is not the stored one"
assert any(z["event"] == "oauth_pairing_issued" for z in _pa.store.recent_audit(20)), "no audit line"
_pa.close()
with _ctx.redirect_stdout(_io.StringIO()), _ctx.redirect_stderr(_io.StringIO()) as _e2:
    assert gateway.main(["pair", "nobody"]) == 1 and "nobody" in _e2.getvalue()
del os.environ["TINYSESAM_OAUTH_SERVICE_CLIENTS"], os.environ["TINYSESAM_OAUTH_RESOURCES"], os.environ["TINYSESAM_DB"]
ok("python -m tinysesam.gateway pair: code for a (new) service account, stored as digest, audited; unknown account → 1")
assert gateway.config_from_env().brand_icon == ""
for good in ("/favicon.svg", "data:image/png;base64,iVBORw0KGgo="):
    os.environ["TINYSESAM_BRAND_ICON"] = good
    assert gateway.config_from_env().brand_icon == good, good
for foreign in ("https://cdn.example.com/icon.png", "//cdn.example.com/icon.png", "javascript:alert(1)", "data:text/html,x"):
    os.environ["TINYSESAM_BRAND_ICON"] = foreign
    try:
        gateway.config_from_env(); assert False, f"foreign favicon accepted:{foreign}"
    except SystemExit as e:
        assert "TINYSESAM_BRAND_ICON" in str(e)
del os.environ["TINYSESAM_BRAND_ICON"]
ok("TINYSESAM_BRAND_ICON: path and data:image/ yes; foreign URL, //, javascript:, data:text/ → start error")

# With the code exchange host-only is intended — the warning “without cookie_domain” would be a false alarm.
import logging as _logging
_caught = []
_h = _logging.Handler(); _h.emit = lambda rec: _caught.append(rec.getMessage())
security.seclog.addHandler(_h)
try:
    for link in (False, True):
        _caught.clear()
        TinySesam(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True, base_url="https://auth.example.com",
                                  trusted_redirect_hosts=["app.example.com"], gate_token_enabled=True,
                                  gate_link_enabled=link))
        warns = any("without cookie_domain" in m for m in _caught)
        assert warns is (not link), (link, _caught)
    # Cookies do not separate by port (RFC 6265, 8.5): the gateway on :8443 shares its host-only cookie with :443.
    # Up to 0.26.0 the entries were compared raw with the hostname of base_url, so `auth.example.com:8443` counted as a
    # foreign host. (Mutation probe: compare the raw entry again → the port lines fall.)
    for hosts, base, foreign in ((["auth.example.com:8443"], "https://auth.example.com", False),
                                 (["AUTH.example.com"], "https://auth.example.com:8443", False),
                                 (["[2001:db8::1]:8443"], "https://[2001:db8::1]", False),
                                 (["auth.example.com:8443", "app.example.com:8443"], "https://auth.example.com", True)):
        _caught.clear()
        TinySesam(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True, base_url=base,
                                  trusted_redirect_hosts=hosts))
        lines = [m for m in _caught if "without cookie_domain" in m]
        assert bool(lines) is foreign, (hosts, base, lines)
        # The named hosts, read out of the line (not a substring test on it).
        named = re.search(r"not on (.*?)\. Each of", lines[0]).group(1).split(", ") if foreign else []
        assert named == ([] if not foreign else ["app.example.com"]), (named, lines)
finally:
    security.seclog.removeHandler(_h)
ok("warning “without cookie_domain” yes without code exchange, not with it (no false alarm)")
ok("… and a port on the own host (also IPv6 in brackets) is no foreign host; only real foreign hosts are named")
# The runtime compares by host name too: a `next=` to a host written with a port in trusted_redirect_hosts was dropped
# (the entry never matched `hostname`). (Mutation probe: raw entries in `TinySesam.safe_next` again → red.)
_pn = TinySesam(TinySesamConfig(db_path=":memory:", base_url="https://auth.example.com",
                                trusted_redirect_hosts=["wiki.example.com:8443"]))
assert _pn.safe_next("https://wiki.example.com:8443/page") == "https://wiki.example.com:8443/page"
assert _pn.safe_next("https://evil.example.com:8443/page") == _pn.cfg.login_redirect
ok("safe_next: a trusted host written with a port is matched by name; a foreign host stays refused")

# The gateway starts uvicorn without proxy headers: uvicorn applies X-Forwarded-For by default (`proxy_headers=True`,
# trusting `forwarded_allow_ips`), and TinySesam then judged an address that uvicorn had already replaced —
# `trusted_proxies` came to nothing. (Mutation probe: drop `proxy_headers=False` in `_server_config` → red.)
try:
    import uvicorn as _uv_probe  # noqa: F401
except ImportError:
    print("  - proxy headers skipped: uvicorn (extra `gateway`) not installed")
else:
    assert gateway._server_config(gateway.build_app(cfg), "127.0.0.1", 0).proxy_headers is False
    ok("python -m tinysesam.gateway: uvicorn with proxy_headers=False — TinySesam alone reads X-Forwarded-For")

# When the server has already applied X-Forwarded-For, the address it hands on stands in that very header — a direct
# peer never names itself there. The warning then names the switch that helps: `--no-proxy-headers`.
# (Mutation probe: drop the branch → the line names no switch.)
class _Peer:
    def __init__(self, peer, xff):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff}


security.once_report_reset()
security._REPORTED_PEERS.clear()
_caught.clear()
security.seclog.addHandler(_h)
try:
    assert security.client_ip(_Peer("203.0.113.40", "203.0.113.40"), ["127.0.0.1/32"]) == "203.0.113.40"
    assert any("--no-proxy-headers" in m and "proxy_headers=False" in m for m in _caught), _caught
    _caught.clear()
    assert security.client_ip(_Peer("198.51.100.3", "203.0.113.41"), ["127.0.0.1/32"]) == "198.51.100.3"
    assert _caught and not any("--no-proxy-headers" in m for m in _caught), _caught
finally:
    security.seclog.removeHandler(_h)
ok("X-Forwarded-For already applied by the server: the warning names --no-proxy-headers; an untrusted proxy does not")

del os.environ["TINYSESAM_OIDC_ISSUER"]
try:
    gateway.config_from_env(); assert False
except SystemExit:
    ok("missing required env → SystemExit (clear error message)")

# ---------- Start page and error pages (0.24.2) ----------
sapp = gateway.build_app(TinySesamConfig.oidc_gateway(
    issuer="https://id.example.invalid", client_id="cid", client_secret="sec",
    base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "s.db"), lang="de"))
sc = TestClient(sapp, base_url="https://auth.example.com")
r = sc.get("/", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/login", (r.status_code, r.headers.get("location"))
r = sc.get("/gibtsnicht", headers={"Accept": "text/html"})
assert r.status_code == 404 and r.headers["content-type"].startswith("text/html") and "<html" in r.text.lower(), r.text[:120]
assert '"detail"' not in r.text
assert "Diese Seite gibt es nicht." in r.text and "Not Found" not in r.text, "404 text not translated"
r = sc.get("/gibtsnicht", headers={"Accept": "application/json"})
assert r.status_code == 404 and r.json() == {"detail": "Not Found"}
sauth = sapp.state.auth
sauth.session_user = lambda request: {"username": "anna", "display_name": "Anna A."}
r = sc.get("/", headers={"Accept": "text/html"})
assert r.status_code == 200 and "Angemeldet als Anna A.<" in r.text and "action='/auth/logout'" in r.text, r.text[:300]
assert "name=_csrf" in r.text or "name='_csrf'" in r.text, "sign-out form without CSRF"
ok("gateway: / → sign-in or “Signed in as …” with sign-out; browsers get the error page, API still JSON")

# ---------- /healthz: without sign-in, even when HTTPS is enforced ----------
# The container HEALTHCHECK talks to the process from inside over HTTP. If the
# redirect middleware redirected it too, the check would only check the redirect.
hdb = os.path.join(tempfile.mkdtemp(), "t.db")
happ = gateway.build_app(TinySesamConfig.oidc_gateway(
    issuer="https://id.example.invalid", client_id="cid", client_secret="sec",
    base_url="https://auth.example.com", db_path=hdb, https_mode="force"))
r = TestClient(happ, base_url="http://auth.example.com").get("/healthz", follow_redirects=False)
assert r.status_code == 200, f"/healthz → {r.status_code} (redirect instead of response?)"
assert r.json() == {"status": "ok"}, r.json()
# T-52 (ASVS 13.4.6): the version only with the switch — and then exactly the package's.
from tinysesam import current_version
os.environ["TINYSESAM_HEALTH_VERSION"] = "1"
try:
    vapp = gateway.build_app(TinySesamConfig.oidc_gateway(
        issuer="https://id.example.invalid", client_id="cid", client_secret="sec",
        base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "v.db")))
finally:
    del os.environ["TINYSESAM_HEALTH_VERSION"]
assert TestClient(vapp).get("/healthz").json() == {"status": "ok", "version": current_version()}
# Counter-check: every other path is indeed redirected to HTTPS with force.
r2 = TestClient(happ, base_url="http://auth.example.com").get("/auth/login", follow_redirects=False)
assert r2.status_code in (301, 307, 308), f"HTTPS enforcement no longer applies: {r2.status_code}"
ok("/healthz: without auth, 200 also with https_mode=force; other paths are redirected; version only with "
   "TINYSESAM_HEALTH_VERSION=1")
# HSTS (H1, ASVS 3.4.1): with force on every HTTPS response, never over HTTP (RFC 6797 §7.2) — the health
# check over HTTP and the redirect to HTTPS carry none.
assert "strict-transport-security" not in r.headers and "strict-transport-security" not in r2.headers
r3 = TestClient(happ, base_url="https://auth.example.com").get("/auth/login", follow_redirects=False)
assert r3.headers.get("strict-transport-security") == "max-age=31536000", dict(r3.headers)
r3 = TestClient(happ, base_url="https://auth.example.com").get("/healthz")
assert r3.headers.get("strict-transport-security") == "max-age=31536000", dict(r3.headers)
r3 = TestClient(gateway.build_app(cfg), base_url="https://auth.example.com").get("/auth/login")
assert "strict-transport-security" not in r3.headers, "HSTS without https_mode=force (gateway default: warn)"
ok("gateway with force: HSTS on HTTPS responses (also /healthz over HTTPS), none over HTTP; none with warn")

# ---------- H1: no API documentation without sign-in (ASVS 13.4.5) ----------
# FastAPI serves /docs (Swagger from a third-party CDN, no CSP), /redoc and /openapi.json (every route
# including the admin API) by default — measured 200 on b1d166c.
for _path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
    _r = c.get(_path, headers={"Accept": "application/json"})
    assert _r.status_code == 404, (_path, _r.status_code)
    assert "cdn.jsdelivr" not in _r.text and "swagger" not in _r.text.lower(), _path
assert app.openapi_url is None and app.docs_url is None and app.redoc_url is None
ok("gateway: /docs, /redoc, /openapi.json → 404 (no Swagger from a CDN, no route map)")

# ---------- /healthz sees a database that has become read-only (B6-4) ----------
# Read-only mount, permissions after a restore: reading works, every sign-in fails at its
# first INSERT. A `SELECT 1` reported 200 meanwhile — Docker considered the container healthy.
import sqlite3  # noqa: E402
hstore = happ.state.auth.store
only_read = sqlite3.connect(f"file:{hdb}?mode=ro", uri=True, check_same_thread=False)
only_read.row_factory = sqlite3.Row
old_db, hstore.db = hstore.db, only_read
# Without the probe's throttle (see below): this is about detection, not about the deadline.
hstore.WRITE_PROBE_SEC = 0
hc = TestClient(happ, base_url="http://auth.example.com")
r = hc.get("/healthz")
assert r.status_code == 503 and r.json()["status"] == "degraded", (r.status_code, r.text)
assert "readonly" not in r.text and "database" not in r.text, "error text does not belong on the network"
assert hstore._one("SELECT 1 AS one")["one"] == 1, "counter-check: reading must still work here"
# The same via the switch that SQLite itself has for it.
hstore.db = old_db
hstore.db.execute("PRAGMA query_only=ON")
assert hc.get("/healthz").status_code == 503
hstore.db.execute("PRAGMA query_only=OFF")
assert hc.get("/healthz").status_code == 200, "healthy again after the recovery"
only_read.close()
ok("/healthz: read-only database → 503 degraded (reading alone does not count as healthy)")

# ---------- /healthz can be flooded, but is not expensive (A-B6-4-schreiblast) ----------
# Reachable without sign-in: a commit with fsync under Store._lock per call let anyone who
# floods /healthz occupy the write lock that sign-ins wait for, and the WAL grow.
del hstore.WRITE_PROBE_SEC                     # back to the class default
assert hstore.WRITE_PROBE_SEC >= 1
hstore._written = None                      # the next probe really writes
_commands = []
hstore.db.set_trace_callback(_commands.append)
for _ in range(200):
    assert hc.get("/healthz").status_code == 200
hstore.db.set_trace_callback(None)
_writes = sum(1 for b in _commands if b.strip().upper() == "COMMIT")
assert 1 <= _writes <= 2, f"{_writes} write operations for 200 probes"
# The throttle does not hide a broken connection: the intermediate probe reads anyway.
_to = sqlite3.connect(":memory:", check_same_thread=False); _to.close()
old_db, hstore.db = hstore.db, _to
assert hc.get("/healthz").status_code == 503, "closed connection hidden behind the throttle"
hstore.db = old_db
ok(f"/healthz: 200 probes → {_writes} commit(s); a dead connection is still noticed immediately")
os.remove(hdb)

# ---------- B-5: a forward-auth check with `Upgrade: websocket` is a plain HTTP request ----------
# Through a REAL uvicorn with the gateway's own configuration: where `websockets` is installed, uvicorn's default
# (`ws="auto"`) took the check for a handshake and answered 403. uvicorn is the extra `gateway`: without it
# (job `minimal`) this part has nothing to start.
import base64
import http.client as _http
import threading as _threading
import time as _time


def _b5_real_uvicorn(uvicorn):
    caught = []
    h = _logging.Handler(); h.emit = lambda rec: caught.append(rec.getMessage())
    uv_log = _logging.getLogger("uvicorn.error")
    server = uvicorn.Server(gateway._server_config(gateway.build_app(cfg), "127.0.0.1", 0))
    uv_log.addHandler(h)
    thread = _threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = _time.monotonic() + 20
        while not server.started:
            assert _time.monotonic() < deadline and thread.is_alive(), "uvicorn did not start"
            _time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]

        def status(path, headers):
            conn = _http.HTTPConnection("127.0.0.1", port, timeout=10)
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse(); resp.read(); conn.close()
            return resp.status

        fwd = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/chat"}
        ws = {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
              "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode()}   # a nonce, like a browser sends
        plain = status("/auth/forward", fwd)
        assert plain == 401, plain
        assert status("/auth/forward", {**fwd, **ws}) == plain, "forward auth with Upgrade header differs"
        assert status("/healthz", ws) == 200
        uv_log.warning("another uvicorn warning")          # the filter drops only the upgrade pair
        assert not any(m.startswith(gateway._UPGRADE_WARNINGS) for m in caught), caught
        assert "another uvicorn warning" in caught, caught
    finally:
        server.should_exit = True
        thread.join(10)
        uv_log.removeHandler(h)


try:
    import uvicorn as _uvicorn
except ImportError:
    print("  - B-5 skipped: uvicorn (extra `gateway`) not installed")
else:
    _b5_real_uvicorn(_uvicorn)
    ok("B-5: forward auth with Upgrade: websocket answers like without (401, no 403), upgrade warnings dropped")

# ---------- expired flows do not pile up ----------
# A gateway in production held 159 285 rows in `flow`: every OIDC start writes `state`/`nonce` there (also for a
# scanner that follows the redirect and never comes back), and only `auth.gc()` removed expired rows — called by a cron
# job that the image does not have. Two layers now: writing a flow clears expired ones at most every
# `Store.FLOW_GC_SEC`, and the gateway runs `auth.gc()` at start and every `gateway.GC_INTERVAL_SEC`.
# (Mutation probes: drop the clearing in `put_flow` → the first line falls; drop the housekeeping task → the second.)
_fdb = os.path.join(tempfile.mkdtemp(), "flows.db")
_fa = TinySesam(TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="c", client_secret="s",
                                             base_url="https://auth.example.com", db_path=_fdb))
for _i in range(500):
    _fa.store.put_flow(f"stale-{_i}", {"x": _i}, ttl=-60)            # already expired
_fa.store._flow_gc_at = None                                         # "not cleared yet in this process"
_fa.store.put_flow("fresh", {"x": 1})
_left = _fa.store._one("SELECT COUNT(*) AS n FROM flow")["n"]
assert _left == 1, f"{_left} rows left: expired flows are only removed by an explicit gc()"
ok("put_flow clears expired flows (at most every FLOW_GC_SEC): 500 stale rows → 1")
for _i in range(50):
    _fa.store.put_flow(f"stale2-{_i}", {"x": _i}, ttl=-60)
_sess_db = _fa.store._one("SELECT COUNT(*) AS n FROM flow")["n"]
_fa.close()
_gcfg = TinySesamConfig.oidc_gateway(issuer="https://id.example.com", client_id="c", client_secret="s",
                                     base_url="https://auth.example.com", db_path=_fdb)
with TestClient(gateway.build_app(_gcfg)) as _gc_client:               # the context runs the lifespan
    _deadline = time.monotonic() + 10
    while _gc_client.app.state.auth.store._one("SELECT COUNT(*) AS n FROM flow")["n"] > 1:
        assert time.monotonic() < _deadline, "the gateway does not run gc() on its own"
        time.sleep(0.05)
ok(f"the gateway runs gc() at start and every GC_INTERVAL_SEC ({gateway.GC_INTERVAL_SEC} s): {_sess_db} rows → 1")

os.remove(db)
print("\nOIDC-GATEWAY OK ✅")
