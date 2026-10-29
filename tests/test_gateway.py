"""OIDC-Forward-Auth-Gateway-Preset: TinySesamConfig.oidc_gateway + tinysesam.gateway."""
import os
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
                                    "X-Forwarded-Uri": "/geheim"})
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
os.environ["TINYSESAM_GATE_BRAND"] = "  Firma A  "
assert gateway.config_from_env().gate_brand == "Firma A"
del os.environ["TINYSESAM_GATE_BRAND"]
ok("TINYSESAM_GATE_BRAND: empty by default, set without margin")
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
finally:
    security.seclog.removeHandler(_h)
ok("warning “without cookie_domain” yes without code exchange, not with it (no false alarm)")

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
assert r.json()["status"] == "ok" and r.json()["version"][0].isdigit(), r.json()
# Counter-check: every other path is indeed redirected to HTTPS with force.
r2 = TestClient(happ, base_url="http://auth.example.com").get("/auth/login", follow_redirects=False)
assert r2.status_code in (301, 307, 308), f"HTTPS enforcement no longer applies: {r2.status_code}"
ok("/healthz: without auth, 200 also with https_mode=force; other paths are redirected")

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
assert hstore._one("SELECT 1 AS eins")["eins"] == 1, "counter-check: reading must still work here"
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

os.remove(db)
print("\nOIDC-GATEWAY OK ✅")
