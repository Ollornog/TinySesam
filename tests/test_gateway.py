"""OIDC-Forward-Auth-Gateway-Preset: TinySesamConfig.oidc_gateway + tinysesam.gateway."""
import os
import tempfile, os
from fastapi.testclient import TestClient
from urllib.parse import parse_qs, urlparse
from tinysesam import TinySesamConfig
from tinysesam import gateway


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
cfg = TinySesamConfig.oidc_gateway(csrf_enabled=False, 
    issuer="https://id.example.invalid", client_id="cid", client_secret="sec",
    base_url="https://auth.example.com", cookie_domain=".example.com",
    trusted_redirect_hosts=["app.example.com"], db_path=db)

# ---------- Preset setzt die richtigen Flags ----------
assert cfg.oidc_enabled and cfg.forward_auth_enabled
assert not (cfg.password_enabled or cfg.pin_enabled or cfg.passkey_enabled or cfg.magiclink_enabled)
assert not (cfg.admin_enabled or cfg.account_enabled or cfg.apikey_enabled or cfg.allow_signup
            or cfg.resource_locks_enabled or cfg.totp_enabled)
assert cfg.enabled_methods() == ["oidc"]
ok("oidc_gateway-Preset: nur OIDC + Forward-Auth aktiv, sonst alles aus")

app = gateway.build_app(cfg)
c = TestClient(app, raise_server_exceptions=False)

# ---------- OIDC-only: nur OIDC-Login, keine anderen Methoden/Routen ----------
html = c.get("/auth/login").text
assert "/auth/oidc/start" in html and "name=password" not in html
ok("Login-Seite: nur OIDC-Button, keine Passwort-Form")
assert c.post("/auth/login", data={"username": "x", "password": "y"}).status_code == 404
for path in ("/auth/pin", "/auth/register", "/auth/account", "/auth/magic/request"):
    assert c.get(path, follow_redirects=False).status_code == 404, path
ok("Passwort/PIN/Register/Account/Magic sind aus (404)")

# ---------- Forward-Auth: nicht eingeloggt → 401 + Login-URL zurück auf die App ----------
r = c.get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com",
                                    "X-Forwarded-Uri": "/geheim"})
assert r.status_code == 401
loc = r.headers.get("X-TinySesam-Location")
assert loc and loc.startswith("https://auth.example.com/auth/login?next=") and urlparse(parse_qs(urlparse(loc).query)["next"][0]).netloc == "app.example.com"
ok("Forward-Auth: 401 + X-TinySesam-Location (zentraler Login, next=App-URL)")

# ---------- Config aus Env ----------
os.environ.update({
    "TINYSESAM_OIDC_ISSUER": "https://id.example.invalid", "TINYSESAM_OIDC_CLIENT_ID": "cid",
    "TINYSESAM_OIDC_CLIENT_SECRET": "sec", "TINYSESAM_BASE_URL": "https://auth.example.com",
    "TINYSESAM_PROTECTED_HOSTS": "app.example.com, wiki.example.com", "TINYSESAM_DB": db})
envcfg = gateway.config_from_env()
assert envcfg.oidc_client_id == "cid" and envcfg.forward_auth_enabled
assert envcfg.trusted_redirect_hosts == ["app.example.com", "wiki.example.com"]
ok("config_from_env: Env → Gateway-Config (Hosts geparst)")

del os.environ["TINYSESAM_OIDC_ISSUER"]
try:
    gateway.config_from_env(); assert False
except SystemExit:
    ok("fehlende Pflicht-Env → SystemExit (klare Fehlermeldung)")

# ---------- /healthz: ohne Anmeldung, auch wenn HTTPS erzwungen wird ----------
# Der Container-HEALTHCHECK spricht den Prozess von innen über HTTP an. Würde die
# Redirect-Middleware auch ihn umleiten, prüfte der Check nur noch den Redirect.
hdb = os.path.join(tempfile.mkdtemp(), "t.db")
happ = gateway.build_app(TinySesamConfig.oidc_gateway(
    issuer="https://id.example.invalid", client_id="cid", client_secret="sec",
    base_url="https://auth.example.com", db_path=hdb, https_mode="force"))
r = TestClient(happ, base_url="http://auth.example.com").get("/healthz", follow_redirects=False)
assert r.status_code == 200, f"/healthz → {r.status_code} (Redirect statt Antwort?)"
assert r.json()["status"] == "ok" and r.json()["version"][0].isdigit(), r.json()
# Gegenprobe: jeder andere Pfad wird bei force sehr wohl auf HTTPS umgeleitet.
r2 = TestClient(happ, base_url="http://auth.example.com").get("/auth/login", follow_redirects=False)
assert r2.status_code in (301, 307, 308), f"HTTPS-Zwang greift nicht mehr: {r2.status_code}"
ok("/healthz: ohne Auth, 200 auch bei https_mode=force; andere Pfade werden umgeleitet")

# ---------- /healthz sieht eine nur noch lesbare Datenbank (B6-4) ----------
# Read-only-Mount, Rechte nach einem Rückspielen: Lesen geht, jede Anmeldung scheitert an ihrem
# ersten INSERT. Ein `SELECT 1` meldete dabei 200 — Docker hielt den Container für gesund.
import sqlite3  # noqa: E402
hstore = happ.state.auth.store
nur_lesen = sqlite3.connect(f"file:{hdb}?mode=ro", uri=True, check_same_thread=False)
nur_lesen.row_factory = sqlite3.Row
alt_db, hstore.db = hstore.db, nur_lesen
# Ohne die Drossel der Probe (s. unten): Hier geht es um das Erkennen, nicht um die Frist.
hstore.SCHREIBPROBE_SEK = 0
hc = TestClient(happ, base_url="http://auth.example.com")
r = hc.get("/healthz")
assert r.status_code == 503 and r.json()["status"] == "degraded", (r.status_code, r.text)
assert "readonly" not in r.text and "database" not in r.text, "Fehlertext gehört nicht ins Netz"
assert hstore._one("SELECT 1 AS eins")["eins"] == 1, "Gegenprobe: Lesen muss hier noch gehen"
# Dasselbe über den Schalter, den SQLite selbst dafür hat.
hstore.db = alt_db
hstore.db.execute("PRAGMA query_only=ON")
assert hc.get("/healthz").status_code == 503
hstore.db.execute("PRAGMA query_only=OFF")
assert hc.get("/healthz").status_code == 200, "nach der Heilung wieder gesund"
nur_lesen.close()
ok("/healthz: nur lesbare Datenbank → 503 degraded (Lesen allein zählt nicht als gesund)")

# ---------- /healthz ist flutbar, aber nicht teuer (A-B6-4-schreiblast) ----------
# Ohne Anmeldung erreichbar: Ein Commit mit fsync unter Store._lock je Aufruf liess jeden, der
# /healthz flutet, die Schreibsperre belegen, auf die Anmeldungen warten, und das WAL wachsen.
del hstore.SCHREIBPROBE_SEK                     # zurück auf die Vorgabe der Klasse
assert hstore.SCHREIBPROBE_SEK >= 1
hstore._geschrieben = None                      # nächste Probe schreibt wirklich
_befehle = []
hstore.db.set_trace_callback(_befehle.append)
for _ in range(200):
    assert hc.get("/healthz").status_code == 200
hstore.db.set_trace_callback(None)
_schreibvorgaenge = sum(1 for b in _befehle if b.strip().upper() == "COMMIT")
assert 1 <= _schreibvorgaenge <= 2, f"{_schreibvorgaenge} Schreibvorgänge für 200 Proben"
# Die Drossel verdeckt keine kaputte Verbindung: Die Zwischenprobe liest trotzdem.
_zu = sqlite3.connect(":memory:", check_same_thread=False); _zu.close()
alt_db, hstore.db = hstore.db, _zu
assert hc.get("/healthz").status_code == 503, "geschlossene Verbindung hinter der Drossel versteckt"
hstore.db = alt_db
ok(f"/healthz: 200 Proben → {_schreibvorgaenge} Commit(s); eine tote Verbindung fällt trotzdem sofort auf")
os.remove(hdb)

os.remove(db)
print("\nOIDC-GATEWAY OK ✅")
