"""Login-Modi vor dem Gate (T-21) und die Schleife bei fehlender App-Freigabe (B-2).

`forward_login` / `forward_apps[host].login`: "page" schickt einen nicht Angemeldeten auf die
Login-Seite (mit dem Namen der Anwendung), "direct" einen Seitenaufruf gleich zum Provider.
Hintergrund-Anfragen gehen immer zur Login-Seite — sonst begänne jede einen eigenen OIDC-Flow.
"""
import os
import re
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, ConfigError
from tinysesam import konfigpruefung
from tinysesam.oidc import VORGABE_CLIENT


def ok(name):
    print(f"  ✓ {name}")


META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
        "token_endpoint": "https://id.example.com/token",
        "authorization_endpoint": "https://id.example.com/auth"}
PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/seite"}
SEITE = {"Sec-Fetch-Mode": "navigate", "Accept": "text/html"}


def instanz(cfg: TinySesamConfig):
    auth = TinySesam(cfg)
    registry = getattr(auth, "oidc_clients", None)
    if registry is not None:
        for schluessel in [VORGABE_CLIENT] + registry.namen():
            registry[schluessel]._meta, registry[schluessel]._meta_zeit = dict(META), time.time()
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def gateway(**extra):
    werte = dict(issuer="https://id.example.com", client_id="haupt", client_secret="s",
                 base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "g.db"),
                 trusted_redirect_hosts=["app.example.com", "wiki.example.com"],
                 allowed_groups=["leute"], oidc_scopes="openid profile email groups",
                 https_mode="off", lang="de")
    werte.update(extra)
    cfg = TinySesamConfig.oidc_gateway(**werte)
    cfg.cookie_secure = False
    cfg.csrf_enabled = False
    return instanz(cfg)


def ort(r):
    return urlsplit(r.headers.get("X-TinySesam-Location", ""))


# ---------- Vorgabe im Gateway: direct ----------
auth, app = gateway(forward_apps={"wiki.example.com": {"name": "Wiki", "login": "page"}})
assert auth.cfg.forward_login == "direct"
c = TestClient(app)

r = c.get("/auth/forward", headers={**PROXY, **SEITE})
assert r.status_code == 401
assert ort(r).path == "/auth/oidc/start", r.headers.get("X-TinySesam-Location")
assert parse_qs(ort(r).query)["next"] == ["https://app.example.com/seite"]
ok("Gateway (Vorgabe direct): Seitenaufruf → direkt /auth/oidc/start mit next")

# Wohin führt dieser Einstieg? Zum Provider, mit genau einer Umleitung.
a = c.get(ort(r).path + "?" + ort(r).query, follow_redirects=False)
assert a.status_code == 303 and a.headers["location"].startswith("https://id.example.com/auth?"), a.status_code
ok("… und von dort mit einer Umleitung zum Provider")

for name, kopf in (("XHR (Sec-Fetch-Mode: cors)", {"Sec-Fetch-Mode": "cors", "Accept": "*/*"}),
                   ("Skript (no-cors)", {"Sec-Fetch-Mode": "no-cors", "Accept": "*/*"}),
                   ("Werkzeug ohne Sec-Fetch, Accept */*", {"Accept": "*/*"})):
    r = c.get("/auth/forward", headers={**PROXY, **kopf})
    assert ort(r).path == "/auth/login", (name, r.headers.get("X-TinySesam-Location"))
r = c.get("/auth/forward", headers={**PROXY, "Accept": "text/html,application/xhtml+xml"})
assert ort(r).path == "/auth/oidc/start"
ok("Hintergrund-Anfragen → Login-Seite (kein Flow); ohne Sec-Fetch entscheidet Accept: text/html")

# Zur Laufzeit eine zweite Methode dazu (`auth.cfg` ist veränderlich): Dann gibt es Wege, die nur
# die Login-Seite zeigt — direct darf sie nicht überspringen, auch wenn die Prüfung beim Start
# davon nichts wusste.
auth.cfg.password_enabled = True
r = c.get("/auth/forward", headers={**PROXY, **SEITE})
auth.cfg.password_enabled = False
assert ort(r).path == "/auth/login", r.headers.get("X-TinySesam-Location")
ok("direct, aber OIDC nicht mehr die einzige Methode → Login-Seite")

# Je Anwendung überschrieben: wiki.example.com will das Fenster.
r = c.get("/auth/forward", headers={**PROXY, **SEITE, "X-Forwarded-Host": "wiki.example.com"})
assert ort(r).path == "/auth/login", r.headers.get("X-TinySesam-Location")
seite = c.get(ort(r).path + "?" + ort(r).query)
assert "<h1>Anmelden bei Wiki</h1>" in seite.text, re.findall(r"<h1>.*?</h1>", seite.text)
ok("forward_apps: wiki.example.com mit login=page → Login-Seite „Anmelden bei Wiki“")

# Ohne Namen bleibt die Überschrift der Dienstname.
seite = c.get("/auth/login?next=" + "https%3A%2F%2Fapp.example.com%2Fx")
assert f"<h1>{auth.cfg.rp_name}</h1>" in seite.text
ok("ohne Namen: Überschrift wie bisher (rp_name)")

# Bibliothek: Vorgabe bleibt page.
assert TinySesamConfig(db_path=":memory:").forward_login == "page"
ok("Bibliothek: Vorgabe bleibt page")

# ---------- Fehler beim Provider: keine Schleife ----------
r = c.get("/auth/oidc/callback?error=access_denied&state=x", follow_redirects=False)
assert r.status_code == 400 and "location" not in r.headers, r.status_code
ok("Absage des Providers → Fehlerseite (400), keine Umleitung zurück in die Runde")

# ---------- Konfigurationsprüfung ----------
def befunde(**w):
    werte = dict(db_path=":memory:", forward_auth_enabled=True)
    werte.update(w)
    return konfigpruefung.pruefe(TinySesamConfig(**werte))[0]


assert any("forward_login" in b for b in befunde(forward_login="unsichtbar"))
assert any("einzige Anmeldemethode" in b for b in befunde(forward_login="direct"))   # Passwort ist an
assert any("einzige Anmeldemethode" in b
           for b in befunde(forward_apps={"app.example.com": {"login": "direct"}}))
assert any("logn" in b for b in befunde(forward_apps={"app.example.com": {"logn": "page"}}))
assert any("['login']" in b for b in befunde(forward_apps={"app.example.com": {"login": "fenster"}}))
assert not [b for b in befunde(forward_apps={"app.example.com": {"name": "App", "login": "page"}})
            if "forward" in b]
try:
    TinySesam(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True, forward_login="direct"))
except ConfigError as e:
    assert "einzige Anmeldemethode" in str(e)
else:
    raise AssertionError("direct neben der Passwort-Anmeldung startet")
ok("Konfigurationsprüfung: unbekannter Modus, direct neben anderen Methoden, Tippfehler im Schlüssel")

# ---------- B-2: mehrere Clients, Freigabe fehlt ----------
auth2, app2 = gateway(trusted_redirect_hosts=["app-a.example.com", "app-b.example.com"],
                      clients={"app-a.example.com": {"client_id": "a", "client_secret": "x"},
                               "app-b.example.com": {"client_id": "b", "client_secret": "y"}})
# Eine Sitzung ohne Provider-Runde (wie nach einer Anmeldung für eine ANDERE Anwendung).
uid = auth2.create_user("anna")
token = auth2.store.create_session(uid, 3600, True, "oidc")
c2 = TestClient(app2)
c2.cookies.set(auth2.session_cookie_name, token)
auth2._vermerke_oidc_freigabe(token, "app-a.example.com")
PA = {**PROXY, **SEITE, "X-Forwarded-Host": "app-a.example.com"}
PB = {**PA, "X-Forwarded-Host": "app-b.example.com"}

assert c2.get("/auth/forward", headers=PA).status_code == 200
r = c2.get("/auth/forward", headers=PB)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-fehlt"
assert ort(r).path == "/auth/oidc/start", r.headers.get("X-TinySesam-Location")
assert parse_qs(ort(r).query)["app"] == ["app-b.example.com"]
ok("B-2: Freigabe für B fehlt → direkt /auth/oidc/start mit app=B (nicht die Login-Seite)")

# Die Login-Seite mit Sitzung, aber ohne Freigabe: früher 303 zurück zu next → Schleife.
r = c2.get("/auth/login?next=https%3A%2F%2Fapp-b.example.com%2Fx&app=app-b.example.com",
           follow_redirects=False)
assert r.status_code == 303
ziel = urlsplit(r.headers["location"])
assert ziel.path == "/auth/oidc/start" and parse_qs(ziel.query)["app"] == ["app-b.example.com"], r.headers["location"]
ok("B-2: Login-Seite mit Sitzung ohne Freigabe → zum Provider, nicht zurück zur Anwendung")

r = c2.get("/auth/login?next=https%3A%2F%2Fapp-a.example.com%2Fx&app=app-a.example.com",
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "https://app-a.example.com/x"
r = c2.get("/auth/login?next=https%3A%2F%2Fapp-b.example.com%2Fx&app=erfunden.example.com",
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "https://app-b.example.com/x"
ok("B-2: mit Freigabe → zurück zu next; ein unbekannter app-Name wird nicht weitergetragen")

# Der Knopf trägt app= mit (vorher fehlte es, die Runde lief über den Vorgabe-Client).
leer = TestClient(app2)
seite = leer.get("/auth/login?next=https%3A%2F%2Fapp-b.example.com%2Fx&app=app-b.example.com").text
knopf = re.findall(r"href='([^']*oidc/start[^']*)'", seite)
assert knopf and "app=app-b.example.com" in knopf[0], knopf
ok("B-2: der OIDC-Knopf der Login-Seite trägt app=")

# /auth/oidc/start ohne app: der Host von next entscheidet.
a = leer.get("/auth/oidc/start?next=https%3A%2F%2Fapp-b.example.com%2Fx", follow_redirects=False)
assert parse_qs(urlsplit(a.headers["location"]).query)["client_id"] == ["b"]
a = leer.get("/auth/oidc/start?next=/lokal", follow_redirects=False)
assert parse_qs(urlsplit(a.headers["location"]).query)["client_id"] == ["haupt"]
ok("B-2: /auth/oidc/start ohne app nimmt den Client zum Host von next (sonst den Vorgabe-Client)")

print("Login-Modi OK")
