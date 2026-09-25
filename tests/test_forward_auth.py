"""Phase 8: Forward-Auth (Reverse-Proxy-Verify-Endpoint) + next zurück auf die App."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from urllib.parse import urlparse
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", 
    db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
    forward_auth_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com"]))
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
auth.store._exec("UPDATE users SET email=?, roles=? WHERE id=?",
                 ("admin@example.com", '["editor"]', uid))

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/geheim"}

# nicht eingeloggt → 401 + Login-URL mit next zurück auf die App.
# Diese Instanz hat KEIN cookie_domain, das Session-Cookie ist also host-only. Die Login-Seite
# wird deshalb auf dem angefragten Host gebaut, nicht auf base_url — sonst setzte TinySesam das
# Cookie auf auth.example.com und schickte den Browser nach app.example.com, wo es nicht gilt:
# eine stille Endlosschleife. (Bis 2026-09 stand hier base_url und der Test schrieb genau die
# Schleife fest. Mit cookie_domain gilt weiter der zentrale Login — siehe unten.)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 401
loc = r.headers.get("X-TinySesam-Location")
assert loc and loc.startswith("https://app.example.com/auth/login?next="), loc
assert urlparse(loc).netloc == "app.example.com"
ok("nicht eingeloggt → 401 + X-TinySesam-Location (host-only: Login auf dem angefragten Host)")

# eingeloggt (Session) → 200 + Remote-*-Header
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200
assert r.headers["Remote-User"] == "admin"
assert r.headers["Remote-Email"] == "admin@example.com"
assert "editor" in r.headers["Remote-Groups"] and "admin" in r.headers["Remote-Groups"]
ok("eingeloggt → 200 + Remote-User/Email/Groups")

# /auth/verify Alias verhält sich gleich
assert c.get("/auth/verify", headers=PROXY).status_code == 200
ok("/auth/verify Alias funktioniert")

# API-Key erfüllt Forward-Auth (maschinell)
key = auth.create_api_key(uid, name="k")["key"]
c2 = TestClient(app)
r = c2.get("/auth/forward", headers={**PROXY, "Authorization": f"Bearer {key}"})
assert r.status_code == 200 and r.headers["Remote-User"] == "admin"
ok("API-Key → 200 (maschineller Zugang)")

# Open-Redirect-Schutz: safe_next lässt die App-URL nur wegen trusted_redirect_hosts durch
assert auth.safe_next("https://app.example.com/geheim") == "https://app.example.com/geheim"
assert auth.safe_next("https://evil.example/x") == "/"
ok("safe_next: App-Host erlaubt (trusted_redirect_hosts), Fremd-Host blockiert")

# ---------- Rollenprüfung im Proxy-Modus (?roles= / X-TinySesam-Roles) ----------
auth.create_user("anna", "geheim123", roles=["redaktion"])
ca = TestClient(app)
ca.post("/auth/login", data={"username": "anna", "password": "geheim123", "next": "/"},
        follow_redirects=False)

assert ca.get("/auth/forward", headers=PROXY).status_code == 200
ok("ohne roles= bleibt /auth/forward binär (unverändertes Verhalten)")

assert ca.get("/auth/forward?roles=redaktion", headers=PROXY).status_code == 200
assert ca.get("/auth/forward?roles=chef,redaktion", headers=PROXY).status_code == 200
ok("?roles=a,b — eine der Rollen genügt")

r = ca.get("/auth/forward?roles=chef", headers=PROXY)
assert r.status_code == 403, r.status_code
assert r.headers.get("X-TinySesam-Reason") == "role"
assert "Remote-User" not in r.headers        # bei 403 fliesst nichts an die App
ok("fehlende Rolle → 403 (nicht 401: sonst Login-Schleife), ohne Remote-*-Header")

assert ca.get("/auth/forward", headers={**PROXY, "X-TinySesam-Roles": "redaktion"}).status_code == 200
assert ca.get("/auth/forward", headers={**PROXY, "X-TinySesam-Roles": "chef"}).status_code == 403
ok("Header X-TinySesam-Roles wirkt wie der Query-Parameter")

# fail-closed: mehrere Angaben werden UND-verknüpft — ein Client kann nur verschärfen
assert ca.get("/auth/forward?roles=chef&roles=redaktion", headers=PROXY).status_code == 403
assert ca.get("/auth/forward?roles=redaktion",
              headers={**PROXY, "X-TinySesam-Roles": "chef"}).status_code == 403
ok("mehrere Angaben = UND (fail-closed: selbst angehängte roles können nur verschärfen)")

# Admin erfüllt die Rolle mit (admin_implies_roles), Anonyme bleiben bei 401
assert c.get("/auth/forward?roles=chef", headers=PROXY).status_code == 200
assert TestClient(app).get("/auth/forward?roles=chef", headers=PROXY).status_code == 401
ok("Admin erfüllt die Rolle mit; nicht angemeldet bleibt 401 (Login, nicht 403)")

assert any(a["event"] == "forward_role_denied" and a["username"] == "anna"
           for a in auth.store.recent_audit(50))
ok("Abweisung steht im Audit-Log (eine 403 im Proxy-Log sagt nicht, wer woran scheiterte)")

# ---------- Login-URL: host-only Cookie darf nicht auf einen fremden Host zeigen ----------
# Ohne cookie_domain gilt das Cookie nur auf dem Host, auf dem der Login stattfand. Zeigte die
# Login-URL dann auf base_url, entstünde eine stille Endlosschleife.
assert auth.forward_login_url("https://app.example.com/geheim").startswith(
    "https://app.example.com/auth/login?next=")
ok("ohne cookie_domain: Login-URL auf dem angefragten Host (keine Redirect-Schleife)")

assert auth.forward_login_url("https://auth.example.com/x").startswith("https://auth.example.com/auth/login")
ok("derselbe Host wie base_url → unverändert")

# Ein gefälschter X-Forwarded-Host kann die Login-URL nicht umbiegen: nur Hosts aus
# trusted_redirect_hosts kommen infrage.
assert auth.forward_login_url("https://evil.example/x").startswith("https://auth.example.com/auth/login")
ok("fremder Host ausserhalb trusted_redirect_hosts → bleibt bei base_url")

db2 = os.path.join(tempfile.mkdtemp(), "t.db")
sso = TinySesam(TinySesamConfig(db_path=db2, csrf_enabled=False, cookie_secure=False,
                                passkey_enabled=False, forward_auth_enabled=True,
                                base_url="https://auth.example.com", cookie_domain=".example.com",
                                trusted_redirect_hosts=["app.example.com"]))
assert sso.forward_login_url("https://app.example.com/geheim").startswith(
    "https://auth.example.com/auth/login?next=")
ok("mit cookie_domain: zentraler Login auf base_url (echtes SSO über Subdomains)")

# ---------- next= auf den eigenen Host (Ein-Host-Betrieb) ----------
assert auth.safe_next("https://auth.example.com/tief/drin") == "https://auth.example.com/tief/drin"
assert auth.safe_next("https://evil.example/x") == "/"
ok("safe_next: der Host der eigenen base_url ist immer erlaubt, fremde nicht")

# ---------- Welche Header hinausgehen (config.forward_headers) ----------
# Vorgabe ist der Authelia-Satz; nicht jede nachgelagerte App will alle davon, und manche
# erwarten andere Namen (Grafana: X-WEBAUTH-USER, oauth2-proxy-Stil: X-Auth-Request-*).
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
eigen = TinySesam(TinySesamConfig(
    db_path=db3, csrf_enabled=False, cookie_secure=False, passkey_enabled=False,
    forward_auth_enabled=True, base_url="https://auth.example.com",
    forward_headers={"user": ["X-WEBAUTH-USER", "Remote-User"], "groups": "X-Auth-Request-Groups"}))
eigen.create_user("carla", "geheim123", roles=["redaktion"])
app3 = FastAPI()
app3.include_router(eigen.router())
c3 = TestClient(app3)
c3.post("/auth/login", data={"username": "carla", "password": "geheim123", "next": "/"},
        follow_redirects=False)
r = c3.get("/auth/forward", headers={"X-Forwarded-Proto": "https",
                                     "X-Forwarded-Host": "auth.example.com",
                                     "X-Forwarded-Uri": "/x"})
assert r.status_code == 200
assert r.headers["X-WEBAUTH-USER"] == "carla" and r.headers["Remote-User"] == "carla"
assert r.headers["X-Auth-Request-Groups"] == "redaktion"
ok("forward_headers: eigene Namen, ein Feld darf auf mehrere Header zeigen")

assert "Remote-Email" not in r.headers and "Remote-Name" not in r.headers
ok("die Liste ist vollständig, nicht ergänzend — Weglassen gibt die E-Mail nicht heraus")

# Ohne das Feld bleibt es beim bisherigen Satz
vorgabe = auth.forward_response_headers(auth.store.get_user_by_name("admin"))
# Seit 2026-09-25 gehört `Remote-Id` (die Konto-ID) dazu — nicht still: CHANGELOG und die
# Proxy-Beispiele unter deploy/ nennen ihn, und die Beispiele setzen ihn selbst (sonst reichte der
# Proxy einen vom Browser gefälschten durch).
assert sorted(vorgabe) == ["Remote-Email", "Remote-Groups", "Remote-Id", "Remote-Name", "Remote-User"]
assert vorgabe["Remote-Id"] == str(auth.store.get_user_by_name("admin")["id"])
ok("Vorgabe: Remote-User/-Name/-Email/-Groups und Remote-Id (die Konto-ID)")

# Ein Tippfehler im Feldnamen liesse den Header still weg — deshalb Abbruch beim Start.
# Ein Header-Name mit Zeilenumbruch wäre Header-Injection.
for kaputt in ({"mail": "X-Mail"}, {"user": "Bad Name"}, {"user": "X-U\r\nSet-Cookie: a=b"},
               {"user": ["Remote-User", ""]}):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
                                  passkey_enabled=False, forward_auth_enabled=True,
                                  forward_headers=kaputt))
        raise AssertionError(f"forward_headers={kaputt} hätte abgelehnt werden müssen")
    except ValueError:
        pass
ok("unbekanntes Feld und ungültiger Header-Name brechen beim Start ab, nicht still zur Laufzeit")

# ---------- T-14: mehrere Anwendungen, ein TinySesam ----------
# Wer in welche Anwendung darf, entscheidet der Provider je OIDC-Client. „Angemeldet" ist
# deshalb nicht mehr dieselbe Frage wie „darf hier rein": Die Freigabe hängt an der Sitzung UND
# der Anwendung. Ohne diesen Block wäre der Zustand vor T-14 wieder da — eine Anmeldung für
# app-a öffnete auch app-b.
import time as _zeit                                                        # noqa: E402
from tinysesam.oidc import VORGABE_CLIENT                                    # noqa: E402

db4 = os.path.join(tempfile.mkdtemp(), "t.db")
auth4 = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=db4, rp_name="Test", passkey_enabled=False,
    cookie_secure=False, forward_auth_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"],
    oidc_enabled=True, oidc_issuer="https://id.example.com",
    oidc_client_id="haupt", oidc_client_secret="s-haupt",
    oidc_revalidate_minutes=15,
    oidc_clients={
        "app-a.example.com": {"client_id": "a", "client_secret": "s-a"},
        "app-b.example.com": {"client_id": "b", "client_secret": "s-b",
                              "group_role_map": {"b-team": "redakteur"}},
    }))
auth4.ensure_admin("admin", "geheim123")
app4 = FastAPI()
app4.include_router(auth4.router())

assert auth4.oidc_clients.namen() == ["app-a.example.com", "app-b.example.com"]
assert auth4.oidc_clients.fuer_host("app-a.example.com").client_id == "a"
assert auth4.oidc_clients.fuer_host("app-b.example.com:8443").client_id == "b"
assert auth4.oidc_clients.schluessel_fuer_host("fremd.example.com") == VORGABE_CLIENT
ok("T-14: jede Anwendung hat ihren eigenen Client, ein unbekannter Host den Vorgabe-Client")

c14 = TestClient(app4)
c14.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"},
         follow_redirects=False)
_sitzung = c14.cookies.get("tinysesam_session")
_h = auth4.store.session_hash(_sitzung)
PROXY_A = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app-a.example.com",
           "X-Forwarded-Uri": "/geheim"}
PROXY_B = {**PROXY_A, "X-Forwarded-Host": "app-b.example.com"}

# Ohne Freigabe ist auch eine gültige Sitzung nicht genug — der Provider wurde für diese
# Anwendung nie gefragt. (Mutationsprobe: die Prüfung in `_forward` entfernen → 200 statt 401.)
r = c14.get("/auth/forward", headers=PROXY_A)
assert r.status_code == 401, (r.status_code, dict(r.headers))
assert r.headers.get("X-TinySesam-Reason") == "app-fehlt", dict(r.headers)
assert "app=app-a.example.com" in r.headers.get("X-TinySesam-Location", ""), r.headers.get("X-TinySesam-Location")
ok("T-14: angemeldet, aber ohne Freigabe für diese Anwendung → 401 mit app= in der Login-URL")

# Der Provider hat für A zugestimmt.
auth4.vermerke_oidc_freigabe(_sitzung, "app-a.example.com", rollen=["a-team"])
r = c14.get("/auth/forward", headers=PROXY_A)
assert r.status_code == 200, (r.status_code, r.headers.get("X-TinySesam-Reason"))

# …und genau deshalb noch lange nicht für B.
r = c14.get("/auth/forward", headers=PROXY_B)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-fehlt", dict(r.headers)
assert "app=app-b.example.com" in r.headers.get("X-TinySesam-Location", "")
ok("T-14: die Freigabe für A gilt nicht für B — dieselbe Sitzung, zwei Antworten")

# Widerruf: die Frist läuft ab, die Sitzung bleibt. Der nächste Aufruf geht über den Provider.
auth4.store._exec("UPDATE oidc_grant SET checked_at=? WHERE token_hash=? AND client=?",
                  (int(_zeit.time()) - 16 * 60, _h, "app-a.example.com"))
r = c14.get("/auth/forward", headers=PROXY_A)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-veraltet", dict(r.headers)
assert c14.get("/auth/forward", headers=PROXY_A).status_code == 401
# Die Sitzung selbst ist unberührt — das ist der Unterschied zum Abmelden.
assert auth4.store.get_session(_sitzung) is not None, "die Sitzung darf die abgelaufene Freigabe überleben"
auth4.vermerke_oidc_freigabe(_sitzung, "app-a.example.com")
assert c14.get("/auth/forward", headers=PROXY_A).status_code == 200
ok("T-14: nach oidc_revalidate_minutes verfällt die Freigabe (Sitzung bleibt), Bestätigung öffnet wieder")

# Entzug von Hand: eine Anwendung zu, die andere offen.
auth4.vermerke_oidc_freigabe(_sitzung, "app-b.example.com")
assert c14.get("/auth/forward", headers=PROXY_B).status_code == 200
_weg = auth4.store.drop_oidc_grant(_h, "app-b.example.com")
assert _weg == 1
assert c14.get("/auth/forward", headers=PROXY_B).status_code == 401
assert c14.get("/auth/forward", headers=PROXY_A).status_code == 200
ok("T-14: eine Freigabe entziehen trifft genau eine Anwendung")

# Der Flow merkt sich, für WELCHE Anwendung er läuft. Die Redirect-URI ist für alle Clients
# dieselbe (beim Provider steht eine Adresse), also kann der Client nicht aus der Rückkehr-
# Adresse kommen — er steht im Flow-Satz. Ohne das liefe jede Anmeldung über den Vorgabe-Client
# und die Freigabe je Client wäre wirkungslos.
_META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
         "token_endpoint": "https://id.example.com/token",
         "authorization_endpoint": "https://id.example.com/auth"}
for _schluessel in [VORGABE_CLIENT] + auth4.oidc_clients.namen():
    _k = auth4.oidc_clients[_schluessel]
    _k._meta, _k._meta_zeit = dict(_META), _zeit.time()

from urllib.parse import parse_qs as _pq                                      # noqa: E402


def _abfrage_der_umleitung(pfad):
    """Die Query der Provider-Umleitung, die /auth/oidc/start baut."""
    a = TestClient(app4).get(pfad, follow_redirects=False)
    assert a.status_code == 303, (pfad, a.status_code)
    return _pq(urlparse(a.headers["location"]).query)

assert _abfrage_der_umleitung("/auth/oidc/start?app=app-a.example.com")["client_id"] == ["a"]
assert _abfrage_der_umleitung("/auth/oidc/start?app=app-b.example.com")["client_id"] == ["b"]
assert _abfrage_der_umleitung("/auth/oidc/start")["client_id"] == ["haupt"]
assert _abfrage_der_umleitung("/auth/oidc/start?app=fremd.example.com")["client_id"] == ["haupt"]
_abfrage_b = _abfrage_der_umleitung("/auth/oidc/start?app=app-b.example.com")
_flow_b = auth4.store.pop_flow("oidc:" + _abfrage_b["state"][0])
assert (_flow_b or {}).get("app") == "app-b.example.com", _flow_b
ok("T-14: /auth/oidc/start wählt den Client der Anwendung und hält ihn im Flow-Satz fest")

# Und der Bestandsfall: EIN Client, keine Zuordnung — alles wie in 0.18.0, ohne app= irgendwo.
db5 = os.path.join(tempfile.mkdtemp(), "t.db")
auth5 = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=db5, rp_name="Test", passkey_enabled=False,
    cookie_secure=False, forward_auth_enabled=True, base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com"], oidc_enabled=True,
    oidc_issuer="https://id.example.com", oidc_client_id="haupt", oidc_client_secret="s"))
auth5.ensure_admin("admin", "geheim123")
app5 = FastAPI()
app5.include_router(auth5.router())
c15 = TestClient(app5)
c15.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"},
         follow_redirects=False)
r = c15.get("/auth/forward", headers=PROXY)
assert r.status_code == 200, (r.status_code, r.headers.get("X-TinySesam-Reason"))
assert auth5.oidc_anwendung("https://app.example.com/x") == ""
assert "app=" not in auth5.forward_login_url("https://app.example.com/x")
assert auth5.oidc_freigabe_gueltig("egal", "egal") == (True, "")
ok("T-14: eine Installation mit einem Client verhält sich unverändert (kein app=, keine Freigabe nötig)")

# Die Vorgabe des Gateway-Presets steht hier, damit eine Änderung daran auffällt: Sie ist die
# einzige Stelle, an der TinySesam von sich aus eine Frist setzt — im Grundaufbau bleibt sie 0.
_preset = TinySesamConfig.oidc_gateway(
    issuer="https://id.example.com", client_id="g", client_secret="s",
    base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "t.db"))
assert _preset.oidc_revalidate_minutes == 60, _preset.oidc_revalidate_minutes
assert TinySesamConfig(db_path="/dev/null").oidc_revalidate_minutes == 0
ok("T-14: oidc_gateway() prüft stündlich nach, der Grundaufbau gar nicht")

os.remove(db)
os.remove(db2)
os.remove(db3)
os.remove(db4)
os.remove(db5)
print("\nFORWARD-AUTH OK ✅")
