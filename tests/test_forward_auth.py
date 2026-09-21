"""Phase 8: Forward-Auth (Reverse-Proxy-Verify-Endpoint) + next zurück auf die App."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
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
assert "app.example.com" in loc
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
assert auth.safe_next("https://evil.com/x") == "/"
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
assert sorted(vorgabe) == ["Remote-Email", "Remote-Groups", "Remote-Name", "Remote-User"]
ok("Vorgabe unverändert (keine stille Änderung für Bestandsnutzer)")

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

os.remove(db)
os.remove(db2)
os.remove(db3)
print("\nFORWARD-AUTH OK ✅")
