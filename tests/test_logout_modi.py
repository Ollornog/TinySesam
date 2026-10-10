"""Abmelden an der Anwendung (T-22): /.tinysesam/logout mit "app", "all" und "ask".

"app" lässt die Sitzung stehen, sperrt aber DIESEN Host, bis der Mensch auf der Login-Seite
„Weiter als …" wählt. "all" beendet die Sitzung und — bei einer OIDC-Anmeldung mit
oidc_rp_logout — die beim Provider, mit dem ID-Token als `id_token_hint`.
"""
import os
import re
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig
from tinysesam import konfigpruefung
from tinysesam.oidc import VORGABE_CLIENT


def ok(name):
    print(f"  ✓ {name}")


META = {"issuer": "https://id.example.com", "jwks_uri": "https://id.example.com/jwks",
        "token_endpoint": "https://id.example.com/token",
        "authorization_endpoint": "https://id.example.com/auth",
        "end_session_endpoint": "https://id.example.com/api/oidc/end-session"}
APP = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com"}
WIKI = {**APP, "X-Forwarded-Host": "wiki.example.com"}


def instanz(**extra):
    werte = dict(issuer="https://id.example.com", client_id="haupt", client_secret="s",
                 base_url="https://auth.example.com", db_path=os.path.join(tempfile.mkdtemp(), "g.db"),
                 trusted_redirect_hosts=["app.example.com", "wiki.example.com"],
                 allowed_groups=["leute"], oidc_scopes="openid profile email groups",
                 https_mode="off", lang="de")
    werte.update(extra)
    cfg = TinySesamConfig.oidc_gateway(**werte)
    cfg.cookie_secure = False
    cfg.csrf_enabled = False
    auth = TinySesam(cfg)
    for schluessel in [VORGABE_CLIENT] + auth.oidc_clients.namen():
        auth.oidc_clients[schluessel]._meta, auth.oidc_clients[schluessel]._meta_zeit = dict(META), time.time()
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def angemeldet(auth, app, name="anna", id_token=None):
    """Eine OIDC-Sitzung wie nach dem Callback: Methode oidc, Freigabe, ID-Token."""
    uid = auth.create_user(name)
    token = auth.store.create_session(uid, 3600, True, "oidc")
    auth._vermerke_oidc_freigabe(token, VORGABE_CLIENT)
    if id_token:
        auth.store.set_oidc_id_token(auth.store.session_hash(token), VORGABE_CLIENT, id_token)
    c = TestClient(app)
    c.cookies.set(auth.session_cookie_name, token)
    return c, token, uid


def forward(c, kopf, uri="/seite"):
    return c.get("/auth/forward", headers={**kopf, "X-Forwarded-Uri": uri,
                                           "Sec-Fetch-Mode": "navigate", "Accept": "text/html"})


def gate_geloescht(r, auth):
    return any(v.startswith(f"{auth.cfg.gate_cookie_name}=;") and "Max-Age=0" in v
               for v in r.headers.get_list("set-cookie"))


auth, app = instanz(gate_token_enabled=True,
                    forward_apps={"wiki.example.com": {"name": "Wiki", "logout": "app"}})
assert auth.cfg.forward_logout == "all" and auth.cfg.oidc_rp_logout is True
ok("Gateway: Vorgabe forward_logout=all, oidc_rp_logout=True")

# ---------- nur von einer Anwendung abmelden ----------
c, token, uid = angemeldet(auth, app)
assert forward(c, WIKI).status_code == 200 and forward(c, APP).status_code == 200
r = c.get("/.tinysesam/logout", headers=WIKI, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/", (r.status_code, r.headers.get("location"))
assert gate_geloescht(r, auth), r.headers.get_list("set-cookie")
assert auth.store.get_session(token), "die Sitzung muss bleiben"
ok("logout=app: 303 zurück zur Anwendung, Gate-Cookie gelöscht, Sitzung bleibt")

r = forward(c, WIKI)
assert r.status_code == 401 and r.headers.get("X-TinySesam-Reason") == "app-abgemeldet", dict(r.headers)
loc = urlsplit(r.headers["X-TinySesam-Location"])
assert loc.path == "/auth/login", "nach „nur hier abmelden“ nie direkt zum Provider (der meldete lautlos an)"
assert forward(c, APP).status_code == 200
assert "X-TinySesam-Gate-Cookie" not in forward(c, WIKI).headers
ok("danach: Wiki → 401 app-abgemeldet zur Login-Seite (nicht direct), App weiter 200, kein Gate-Token für Wiki")

seite = c.get(loc.path + "?" + loc.query)
assert seite.status_code == 200, seite.status_code
assert "<h1>Anmelden bei Wiki</h1>" in seite.text and "Weiter als anna" in seite.text, \
    re.findall(r"<h1>.*?</h1>|<button[^>]*>[^<]*", seite.text)
ok("Login-Seite statt Rücksprung (keine Schleife): „Anmelden bei Wiki“ mit „Weiter als anna“")

nxt = parse_qs(loc.query)["next"][0]
r = c.post("/auth/gate/resume", data={"next": nxt}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == nxt
assert forward(c, WIKI).status_code == 200
ok("„Weiter als …“ → zurück zur Anwendung, Wiki lässt wieder durch")

# Eine neue Anmeldung mit Ziel Wiki hebt die Sperre ebenso auf (der Abschluss jedes Logins).
c.get("/.tinysesam/logout", headers=WIKI, follow_redirects=False)
assert forward(c, WIKI).status_code == 401
assert auth._login_redirect_after(None, token, uid, "https://wiki.example.com/x") == "https://wiki.example.com/x"
assert forward(c, WIKI).status_code == 200
ok("eine abgeschlossene Anmeldung mit Ziel Wiki hebt „nur hier abgemeldet“ auf")

# Die Sperre überlebt das Drehen der Sitzung (Step-up) — sonst wäre sie mit dem nächsten Faktor weg.
c.get("/.tinysesam/logout", headers=WIKI, follow_redirects=False)
neu = auth.store.rotate_session(auth.store.session_hash(token))
c.cookies.set(auth.session_cookie_name, neu)
assert forward(c, WIKI).status_code == 401 and forward(c, APP).status_code == 200
ok("„nur hier abgemeldet“ zieht beim Drehen der Sitzung mit")

# ---------- überall abmelden, mit id_token_hint ----------
c2, token2, _ = angemeldet(auth, app, "bea", id_token="eyJ.ID.TOKEN")
r = c2.get("/.tinysesam/logout?scope=all", headers=APP, follow_redirects=False)
assert r.status_code == 303, r.status_code
ziel = urlsplit(r.headers["location"])
q = parse_qs(ziel.query)
assert f"{ziel.scheme}://{ziel.netloc}{ziel.path}" == META["end_session_endpoint"], r.headers["location"]
assert q["id_token_hint"] == ["eyJ.ID.TOKEN"] and q["client_id"] == ["haupt"], q
assert q["post_logout_redirect_uri"] == ["https://app.example.com/.tinysesam/after-logout"], q
assert not auth.store.get_session(token2), "die Sitzung muss enden"
assert gate_geloescht(r, auth)
ok("scope=all: Sitzung beendet, Gate-Cookie gelöscht, zum Provider mit id_token_hint, client_id und Rückweg")

# Rückweg vom Provider: ohne Sitzung eine Seite „Abgemeldet“, keine Umleitung in eine neue Runde.
r = TestClient(app).get("/.tinysesam/after-logout", headers=APP, follow_redirects=False)
assert r.status_code == 200 and "Abgemeldet" in r.text and gate_geloescht(r, auth)
assert "content='10;url=/'" in r.text, "Modus direct (oidc_gateway): nach 10 s zurück zur Anwendung"
_pa, _papp = instanz(forward_login="page")
_pr = TestClient(_papp).get("/.tinysesam/after-logout", headers=APP, follow_redirects=False)
assert "http-equiv=refresh" not in _pr.text and "Wieder anmelden" in _pr.text, "Modus page: die Seite führt nicht von selbst weiter"
ok("after-logout ohne Sitzung: Seite „Abgemeldet“ (keine neue Runde), Gate-Cookie gelöscht")

# Kette von der Anwendung aus (deren RP-Logout → Provider → after-logout): die Sitzung lebt noch.
c3, token3, _ = angemeldet(auth, app, "cleo", id_token="eyJ.C")
r = c3.get("/.tinysesam/after-logout", headers={**APP, "Sec-Fetch-Site": "same-site"}, follow_redirects=False)
assert not auth.store.get_session(token3), "after-logout muss die noch lebende Sitzung beenden"
assert r.status_code == 303 and r.headers["location"].startswith(META["end_session_endpoint"]), r.headers.get("location")
ok("after-logout mit noch lebender Sitzung (Kette von der App): Sitzung endet")

# Von einer fremden Seite: erst fragen (Logout-CSRF, F-07).
c4, token4, _ = angemeldet(auth, app, "dora")
r = c4.get("/.tinysesam/logout?scope=all", headers={**APP, "Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 200 and "Überall abmelden?" in r.text and auth.store.get_session(token4)
r = c4.get("/.tinysesam/after-logout", headers={**APP, "Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 200 and auth.store.get_session(token4)
r = c4.post("/.tinysesam/logout", data={"scope": "all", "next": "/"}, headers=APP, follow_redirects=False)
assert r.status_code == 303 and not auth.store.get_session(token4)
ok("von einer fremden Seite: Rückfrage statt Abmelden; der POST meldet ab")

# Ohne OIDC-Anmeldung (Passwort-Sitzung o. ä.) kein Umweg über den Provider.
uid5 = auth.create_user("emil")
t5 = auth.store.create_session(uid5, 3600, True, "password")
c5 = TestClient(app)
c5.cookies.set(auth.session_cookie_name, t5)
r = c5.get("/.tinysesam/logout?scope=all", headers=APP, follow_redirects=False)
assert r.headers["location"] == "/.tinysesam/after-logout" and not auth.store.get_session(t5)
ok("Sitzung ohne OIDC: abmelden ohne Provider-Umweg")

# ---------- fragen ----------
auth2, app2 = instanz(forward_logout="ask", forward_apps={"wiki.example.com": {"name": "Wiki"}})
c6, t6, _ = angemeldet(auth2, app2)
r = c6.get("/.tinysesam/logout", headers=WIKI)
assert r.status_code == 200 and "Nur von Wiki abmelden oder überall?" in r.text, r.text[:400]
assert "Nur von Wiki" in r.text and "Überall" in r.text and auth2.store.get_session(t6)
r = c6.post("/.tinysesam/logout", data={"scope": "app", "next": "/"}, headers=WIKI, follow_redirects=False)
assert r.status_code == 303 and auth2.store.get_session(t6) and forward(c6, WIKI).status_code == 401
ok("logout=ask: Seite mit beiden Wegen; „Nur von Wiki“ per POST sperrt nur Wiki")

assert c6.post("/.tinysesam/logout", data={"scope": "egal"}, headers=WIKI).status_code == 400
ok("POST mit unbekanntem scope → 400")

# ---------- fremder Host ----------
r = TestClient(app).get("/.tinysesam/logout", headers={**APP, "X-Forwarded-Host": "fremd.example.net"})
assert r.status_code == 404
ok("ein Host, den diese Installation nicht schützt → 404")

# ---------- Konfigurationsprüfung ----------
def befunde(**w):
    return konfigpruefung.pruefe(TinySesamConfig(db_path=":memory:", **w))[0]


assert any("forward_logout" in b for b in befunde(forward_logout="nur_hier"))
assert any("['logout']" in b for b in befunde(forward_apps={"a.example.com": {"logout": "jetzt"}}))
assert not [b for b in befunde(forward_logout="ask", forward_apps={"a.example.com": {"logout": "app"}})
            if "logout" in b]
ok("Konfigurationsprüfung: unbekannter Logout-Modus (global und je App)")

print("Logout-Modi OK")
