"""E2: CSRF-Schutz (double-submit). CSRF ist hier AN (Default)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False))   # csrf_enabled default True
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


def csrf_token(client):
    """CSRF-Cookie + versteckten Feldwert von der Login-Seite holen (double-submit)."""
    html = client.get("/auth/login").text
    field = re.search(r"name=_csrf value='([^']+)'", html).group(1)
    cookie = client.cookies.get("tinysesam_csrf")
    return field, cookie


c = TestClient(app)
JSON = {"Accept": "application/json"}

# ---------- Login-Seite setzt CSRF-Cookie + bettet _csrf-Feld ein (identisch) ----------
field, cookie = csrf_token(c)
assert field and cookie and field == cookie
ok("Login-Seite: CSRF-Cookie == verstecktes _csrf-Feld (double-submit)")

# ---------- POST OHNE Token → 403 ----------
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert r.status_code == 403, r.status_code
ok("Login-POST ohne CSRF-Token → 403")

# ---------- POST MIT Token → ok ----------
field, cookie = csrf_token(c)
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/", "_csrf": field},
           follow_redirects=False)
assert r.status_code == 303 and c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("Login-POST mit gültigem CSRF-Token → 303")

# ---------- R4-02: der Einmal-Link löst per POST ein — und der braucht das CSRF-Token ----------
_m_db = os.path.join(tempfile.mkdtemp(), "t.db")
_m = TinySesam(TinySesamConfig(db_path=_m_db, passkey_enabled=False, cookie_secure=False,
                               magiclink_enabled=True, base_url="https://auth.example.com"))
_m_uid = _m.create_user("mia", password="geheim12345", email="mia@example.com")
_m_app = FastAPI(); _m_app.include_router(_m.router())
_mc = TestClient(_m_app)
_m_tok = _m.create_magic_token("login", user_id=_m_uid, email="mia@example.com", payload={"next": "/"})
assert _mc.post(f"/auth/magic/{_m_tok}", follow_redirects=False).status_code == 403, "ohne Token"
_seite = _mc.get(f"/auth/magic/{_m_tok}").text
_feld = re.search(r"name=_csrf value='([^']+)'", _seite).group(1)
assert _mc.post(f"/auth/magic/{_m_tok}", data={"_csrf": _feld}, follow_redirects=False).status_code == 303
os.remove(_m_db)
ok("R4-02: Bestätigungsseite trägt das CSRF-Feld; POST ohne Token 403, mit Token eingelöst")

# ---------- JSON-Endpoint ohne Header → 403, mit Header → ok ----------
assert c.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"}).status_code == 403
tok = c.cookies.get("tinysesam_csrf")
r = c.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"},
           headers={"X-CSRF-Token": tok})
assert r.status_code == 200, r.status_code
ok("JSON-POST: ohne X-CSRF-Token → 403, mit → 200")

# ---------- falscher Token → 403 ----------
c.get("/auth/logout")                 # ausloggen, damit die Login-Seite wieder ein Formular zeigt
csrf_token(c)                          # frisches CSRF-Cookie holen
r = c.post("/auth/login", data={"username": "admin", "password": "neuespasswort", "_csrf": "falsch"})
assert r.status_code == 403
ok("falscher CSRF-Token → 403")

# ---------- API-Key ist von CSRF ausgenommen (maschinell, kein Cookie-Risiko) ----------
key = auth.create_api_key(uid, name="k")["key"]
c2 = TestClient(app)
# JSON-Endpoint per Key ohne CSRF-Token → erlaubt
r = c2.get("/auth/apikeys", headers={"Authorization": f"Bearer {key}"})
assert r.status_code == 200
ok("API-Key-Request ohne CSRF-Token erlaubt (ausgenommen)")

os.remove(db)
print("\nCSRF OK ✅")

# ---------- Das Token darf nicht bei jedem Rendern rotieren ----------
# Sonst macht jede andere gerenderte Seite ein offenes Formular ungültig ("Formular abgelaufen").
import re as _re

_db = os.path.join(tempfile.mkdtemp(), "t.db")
_a = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, cookie_secure=False,
                               allow_signup=True, signup_require_email=False,
                               login_identifier="username"))
_a.create_user("max", password="geheim12345")
_app = FastAPI()
_app.include_router(_a.router())
_a.install_error_pages(_app)
_c = TestClient(_app, headers={"accept": "text/html"}, raise_server_exceptions=False)

_r1 = _c.get("/auth/login")
_tok = _re.search(r"name=_csrf value='([^']+)'", _r1.text).group(1)
assert "tinysesam_csrf" in _r1.headers.get("set-cookie", ""), "erstes Rendern setzt das Cookie"

# jede weitere gerenderte Seite (auch Fehlerseiten) darf es NICHT überschreiben
for _p in ("/auth/login", "/auth/register", "/gibtsnicht"):
    assert "tinysesam_csrf" not in _c.get(_p).headers.get("set-cookie", ""), _p

_r = _c.post("/auth/login", data={"username": "max", "password": "geheim12345", "next": "/", "_csrf": _tok},
             follow_redirects=False)
assert _r.status_code == 303, f"Token der offenen Seite muss gültig bleiben, war {_r.status_code}"

# Schutz bleibt scharf
assert _c.post("/auth/login", data={"username": "max", "password": "geheim12345", "_csrf": "falsch"}).status_code == 403
assert _c.post("/auth/login", data={"username": "max", "password": "geheim12345"}).status_code == 403
os.remove(_db)
print("  CSRF-Token bleibt über Seitenwechsel gültig; falsches/fehlendes Token weiterhin 403")

# ---------- H-2 / F-02: Herkunft vor dem Token-Vergleich ----------
# Das naive Double-Submit prüft nur, ob Cookie und Feld zusammenpassen. Wer über eine
# Nachbar-Subdomain Cookies setzen kann, setzt das passende Paar gleich mit und schickt das
# Opfer per Formular in SEIN Konto (Login-CSRF). Hier ist das Paar deshalb immer GÜLTIG — nur
# die Herkunft entscheidet.
import logging  # noqa: E402

_db = os.path.join(tempfile.mkdtemp(), "t.db")


def _instanz(**kw):
    a = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, cookie_secure=False,
                                  apikey_enabled=True, **kw))
    a.ensure_admin("admin", "geheim123")
    ap = FastAPI()
    ap.include_router(a.router())
    return a, ap


_a, _app = _instanz(trusted_redirect_hosts=["portal.example.com"])


def _login(kopf, app=None):
    cl = TestClient(app or _app)
    feld = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    return cl.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                        "_csrf": feld}, headers=kopf, follow_redirects=False).status_code


class _Fang(logging.Handler):
    zeilen: list = []

    def emit(self, record):
        _Fang.zeilen.append(record.getMessage())


_log = logging.getLogger("tinysesam.security")
_fang = _Fang()
_log.addHandler(_fang)
try:
    assert _login({"Origin": "https://angreifer.example"}) == 403, "fremder Origin mit gültigem Paar"
    assert _login({"Origin": "https://nachbar.example.com", "Sec-Fetch-Site": "same-site"}) == 403, \
        "Nachbar-Subdomain (cookie tossing) muss scheitern"
    assert _login({"Sec-Fetch-Site": "cross-site"}) == 403, "cross-site ohne Origin"
    assert any("csrf origin rejected" in z for z in _Fang.zeilen), "Abweisung muss im Log stehen"
    ok("H-2: fremder Origin, Nachbar-Subdomain und cross-site → 403, obwohl das Token-Paar stimmt")

    assert _login({"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}) == 303
    assert _login({}) == 303, "ohne beide Header entscheidet das Token (alter Browser, Skript)"
    assert _login({"Origin": "null"}) == 303, "Origin null allein sagt nichts — Token entscheidet"
    ok("H-2: eigener Origin, fehlende Header und Origin null gehen durch")

    # `trusted_redirect_hosts` sind erlaubte ZIELE für `?next=` — im Forward-Auth-Aufbau die
    # geschützten Apps. Ein eigener Origin sind sie nicht: Eine kompromittierte App auf einem
    # dieser Hosts schickte sonst Formulare mit gültigem Origin an TinySesam (Login-CSRF,
    # Sitzungen des Opfers beenden). Bis zur Nacharbeit zählten sie hier als eigen.
    # (Mutationsprobe: `trusted_redirect_hosts` wieder in `_eigene_hosts` aufnehmen → rot.)
    assert _login({"Origin": "https://portal.example.com"}) == 403, \
        "ein Host aus trusted_redirect_hosts gilt als eigener Origin"
    assert _login({"Origin": "https://portal.example.com", "Sec-Fetch-Site": "same-site"}) == 403
    ok("H-2: trusted_redirect_hosts sind Redirect-Ziele, kein eigener Origin → 403")

    # Dieselbe App liefert ihre Seite mit `Referrer-Policy: no-referrer` aus: Dann trägt ihr
    # Formular-POST `Origin: null`, und `Sec-Fetch-Site` sagt weiter `same-site`. Bis zur
    # Nacharbeit wog nur `cross-site` ohne Origin schwer — `null` mit `same-site` ging durch,
    # und wo das CSRF-Cookie kein `__Host-` tragen kann, entschied wieder allein das Token.
    # (Mutationsprobe: in `_herkunft_ok` die Abweisung bei `same-site` ohne eigenen Origin auf
    # `cross-site` allein zurückstellen → rot.)
    assert _login({"Origin": "null", "Sec-Fetch-Site": "same-site"}) == 403, \
        "Origin null von einer Nachbar-Subdomain (no-referrer) besteht die Herkunftsprüfung"
    assert _login({"Sec-Fetch-Site": "same-site"}) == 403, "same-site ohne Origin"
    assert _login({"Origin": "null", "Sec-Fetch-Site": "cross-site"}) == 403
    ok("H-2: same-site oder cross-site ohne brauchbaren Origin (null, fehlt) → 403")

    # Proxy schreibt den Host um (upstream-Name), ohne X-Forwarded-Host — base_url rettet es.
    _a2, _app2 = _instanz(base_url="https://auth.example.com")
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}, _app2) == 303
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000",
                   "X-Forwarded-Host": "auth.example.com"}, _app) == 303, "X-Forwarded-Host zählt"
    assert _login({"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}, _app) == 403
    ok("H-2: Proxy mit umgeschriebenem Host — base_url oder X-Forwarded-Host machen den Origin eigen")

    # A-3: Derselbe Proxy OHNE base_url (nginx-Vorgabe, reiner Passwort-Login) sperrte nach dem
    # Update jeden POST aus. Ein heutiger Browser sagt `Sec-Fetch-Site: same-origin` — gemessen
    # an der Adresse, die ER sieht — und das trägt. Eine Nachbar-Subdomain bekommt `same-site`.
    _proxy = {"Origin": "https://auth.example.com", "Host": "127.0.0.1:8000"}
    assert _login({**_proxy, "Sec-Fetch-Site": "same-origin"}, _app) == 303, \
        "Proxy ohne base_url/X-Forwarded-Host sperrt den eigenen Login aus"
    assert _login({"Origin": "https://nachbar.example.com", "Host": "127.0.0.1:8000",
                   "Sec-Fetch-Site": "same-site"}, _app) == 403, "Nachbar-Subdomain bleibt draussen"
    ok("A-3: Proxy mit umgeschriebenem Host ohne base_url — Sec-Fetch-Site: same-origin trägt den Login")

    # JSON-Weg (json_body) prüft genauso.
    cl = TestClient(_app)
    feld = re.search(r"name=_csrf value='([^']+)'", cl.get("/auth/login").text).group(1)
    cl.post("/auth/login", data={"username": "admin", "password": "geheim123", "_csrf": feld})
    r = cl.post("/auth/password", json={"current": "geheim123", "new": "anderespasswort1"},
                headers={"X-CSRF-Token": feld, "Origin": "https://angreifer.example"})
    assert r.status_code == 403, r.status_code
    ok("H-2: auch der JSON-Weg (X-CSRF-Token) weist fremde Herkunft ab")

    # Ein echter API-Key bleibt ausgenommen — ein Daemon hat keinen Browser.
    _key = _a.create_api_key(_a.store.get_user_by_name("admin")["id"], name="k")["key"]
    r = TestClient(_app).get("/auth/apikeys", headers={"Authorization": f"Bearer {_key}",
                                                       "Origin": "https://angreifer.example"})
    assert r.status_code == 200
    ok("H-2: API-Key-Requests bleiben von der CSRF-Schicht ausgenommen")

    _a3, _app3 = _instanz(csrf_origin_check=False)
    assert _login({"Origin": "https://angreifer.example"}, _app3) == 303
    ok("csrf_origin_check=False schaltet nur die Vorprüfung ab (Notausgang für schiefe Proxys)")
finally:
    _log.removeHandler(_fang)

# ---------- H-1 im Forward-Auth-Aufbau: das CSRF-Cookie trägt `__Host-` auch mit cookie_domain ----------
# Mit `cookie_domain` (SSO über Subdomains) kann das SITZUNGS-Cookie kein `__Host-` tragen. Das
# CSRF-Cookie setzt TinySesam aber nie mit Domain — es ist immer host-only und darf das Präfix
# immer tragen. Ohne es setzte jede Nachbar-Subdomain (eine kompromittierte App) ein
# `tinysesam_csrf=BEKANNT; Domain=.example.com`, und das Double-Submit bestand mit ihrem Wert.
# (Mutationsprobe: in `csrf_cookie_name` host_only=True streichen → rot.)
_fa_db = os.path.join(tempfile.mkdtemp(), "t.db")
_fa = TinySesam(TinySesamConfig(db_path=_fa_db, lang="de", passkey_enabled=False, oidc_enabled=False,
                                cookie_secure=True, base_url="https://auth.example.com",
                                cookie_domain=".example.com", forward_auth_enabled=True,
                                trusted_redirect_hosts=["app.example.com"]))
_fa.ensure_admin("admin", "geheim123")
_fa.create_user("mallory", password="angreifer-pw-1")
_fa_app = FastAPI()
_fa_app.include_router(_fa.router())
assert _fa.session_cookie_name == "tinysesam_session", "Sitzung mit cookie_domain: ohne Präfix"
assert _fa.csrf_cookie_name == "__Host-tinysesam_csrf", _fa.csrf_cookie_name
_fa_c = TestClient(_fa_app, base_url="https://auth.example.com")
_seite = _fa_c.get("/auth/login")
_zeile = [z for z in _seite.headers.get_list("set-cookie") if z.startswith("__Host-tinysesam_csrf=")]
assert len(_zeile) == 1 and "domain" not in _zeile[0].lower() and "secure" in _zeile[0].lower() \
    and "path=/" in _zeile[0].lower(), _seite.headers.get_list("set-cookie")
_feld = re.search(r"name=_csrf value='([^']+)'", _seite.text).group(1)
assert _fa_c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                       "_csrf": _feld}, follow_redirects=False).status_code == 303
ok("H-1: mit cookie_domain heisst das CSRF-Cookie __Host-…, ohne Domain; der Login geht")


def _geworfen(kopf):
    """Login-CSRF mit einem untergeschobenen Domain-Cookie `tinysesam_csrf=BEKANNT`."""
    cl = TestClient(_fa_app, base_url="https://auth.example.com")
    cl.cookies.set("tinysesam_csrf", "BEKANNT", domain=".example.com", path="/")
    return cl.post("/auth/login", data={"username": "mallory", "password": "angreifer-pw-1",
                                        "next": "/", "_csrf": "BEKANNT"},
                   headers=kopf, follow_redirects=False).status_code


assert _geworfen({}) == 403, "ein untergeschobenes tinysesam_csrf besteht das Double-Submit"
assert _geworfen({"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"}) == 403, \
    "Login-CSRF von der geschützten App"
# Und mit der Sitzung des Opfers: Die geschützte App beendet dessen andere Sitzungen nicht.
_opfer = TestClient(_fa_app, base_url="https://auth.example.com")
_f = re.search(r"name=_csrf value='([^']+)'", _opfer.get("/auth/login").text).group(1)
_opfer.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                 "_csrf": _f}, follow_redirects=False)
_opfer.cookies.set("tinysesam_csrf", "BEKANNT", domain=".example.com", path="/")
_r = _opfer.post("/auth/sessions/revoke", content='{"scope":"others","_csrf":"BEKANNT"}',
                 headers={"Content-Type": "text/plain", "Origin": "https://app.example.com",
                          "Sec-Fetch-Site": "same-site"})
assert _r.status_code == 403, (_r.status_code, _r.text[:120])
ok("H-1/H-2: ein von einer App untergeschobenes CSRF-Cookie trägt weder Login noch Sitzungsaktion")
os.remove(_fa_db)

# Wo das Präfix nicht greifen kann (hier abgeschaltet, ebenso bei cookie_path≠"/" oder ohne
# Secure), lässt sich `tinysesam_csrf` unterschieben — dann trägt die Herkunftsprüfung allein.
# Die kompromittierte App schickt ihr Formular unter `Referrer-Policy: no-referrer`, also mit
# `Origin: null` und `Sec-Fetch-Site: same-site`. Vorher: 303 und eine Sitzung als mallory.
# (Mutationsprobe: wie oben, `same-site` ohne eigenen Origin wieder durchlassen → rot.)
_np_db = os.path.join(tempfile.mkdtemp(), "t.db")
_np = TinySesam(TinySesamConfig(db_path=_np_db, lang="de", passkey_enabled=False, oidc_enabled=False,
                                cookie_secure=True, base_url="https://auth.example.com",
                                cookie_domain=".example.com", forward_auth_enabled=True,
                                cookie_host_prefix=False, trusted_redirect_hosts=["app.example.com"]))
_np.ensure_admin("admin", "geheim123")
_np.create_user("mallory", password="angreifer-pw-1")
_np_app = FastAPI()
_np_app.include_router(_np.router())
assert _np.csrf_cookie_name == "tinysesam_csrf"


def _ohne_praefix(kopf):
    cl = TestClient(_np_app, base_url="https://auth.example.com")
    cl.cookies.set("tinysesam_csrf", "BEKANNT", domain=".example.com", path="/")
    r = cl.post("/auth/login", data={"username": "mallory", "password": "angreifer-pw-1",
                                     "next": "/", "_csrf": "BEKANNT"},
                headers=kopf, follow_redirects=False)
    return r.status_code, [z.split("=", 1)[0] for z in r.headers.get_list("set-cookie")]


assert _ohne_praefix({"Origin": "null", "Sec-Fetch-Site": "same-site"}) == (403, []), \
    "Login-CSRF über Origin null + same-site ohne __Host--CSRF-Cookie"
assert _ohne_praefix({"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"})[0] == 403
assert _ohne_praefix({"Origin": "https://auth.example.com", "Sec-Fetch-Site": "same-origin"})[0] == 303, \
    "der eigene Login muss ohne Präfix weiter gehen"
ok("H-2: ohne __Host--Präfix hält die Herkunftsprüfung Origin null + same-site allein auf")
os.remove(_np_db)

# Das eingebaute JS liest den TATSÄCHLICHEN Cookie-Namen — mit __Host- (H-1) hieße das Cookie
# sonst anders als das, was die Kontoseite sucht, und jeder Knopf dort antwortete 403.
_a4 = TinySesam(TinySesamConfig(db_path=_db, lang="de", passkey_enabled=False, pin_enabled=True))
assert _a4.csrf_cookie_name == "__Host-tinysesam_csrf"
_html = _a4.templates.render("account", _a4, {"user": {"username": "x", "display_name": "x"},
                                              "methods": ["password", "pin"]})
assert "__Host-tinysesam_csrf=" in _html and "; )tinysesam_csrf=" not in _html, "Kontoseite liest falschen Namen"
ok("Kontoseite liest das CSRF-Cookie unter seinem tatsächlichen Namen (__Host-…)")
os.remove(_db)


# ======================================================================================
# 0.20.1 — CSRF für einbettende Apps: `ensure_csrf()`, Rotation beim Anmelden, Abmelden
# ======================================================================================
# Zwei Abnehmer mussten beim Heben auf 0.20.0 TinySesam nachbauen: `issue_csrf()` würfelt
# immer neu (jede Seite entwertete die Formulare der anderen Reiter), `csrf_token()` setzt kein
# Cookie. Beide kombinierten `csrf_cookie_name` + `issue_csrf()` auf einer Träger-Antwort und
# kopierten die Set-Cookie-Zeile hinüber. Dazu versprach `csrf_rotieren()` ein frisches Token
# „beim Login" — gerufen wurde es nur am Ende eines TOTP-Schritts, und das Abmelden liess das
# CSRF-Cookie stehen.
import ast  # noqa: E402
import importlib.util  # noqa: E402
import json as _json  # noqa: E402
import pathlib  # noqa: E402
import time as _time  # noqa: E402
import types as _types  # noqa: E402
from urllib.parse import parse_qs as _parse_qs, urlparse as _urlparse  # noqa: E402

import pyotp  # noqa: E402
from fastapi import Form, Request, Response  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse  # noqa: E402

CK = "__Host-tinysesam_csrf"
BASIS = "https://testserver"
_FORM = re.compile(r"[A-Za-z0-9_-]{32,128}")


def _set_cookies(antwort) -> list:
    h = antwort.headers
    return list(h.get_list("set-cookie") if hasattr(h, "get_list") else h.getlist("set-cookie"))


def _zeilen(antwort, name=CK) -> list:
    """Die rohen Set-Cookie-Zeilen dieser Antwort für genau diesen Namen."""
    return [z for z in _set_cookies(antwort) if z.startswith(name + "=")]


def _wert(zeile: str) -> str:
    return zeile.split(";", 1)[0].split("=", 1)[1].strip()


def _attribute(zeile: str) -> set:
    """Alle Attribute ausser Wert, Ablauf und Max-Age — klein geschrieben, als Menge."""
    teile = [t.strip().lower() for t in zeile.split(";")[1:]]
    return {t for t in teile if t and not t.startswith(("expires=", "max-age="))}


def _geloescht(zeile: str) -> bool:
    return _wert(zeile) in ("", '""') and "max-age=0" in zeile.lower()


def _feld(html: str) -> str:
    return re.search(r"name=_csrf value='([^']+)'", html).group(1)


def _instanz(**kw):
    """Instanz mit `__Host-`-Cookies (Secure, host-only) und den Routen einer einbettenden App."""
    cfg = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), lang="de", passkey_enabled=False,
               oidc_enabled=False, base_url=BASIS)
    cfg.update(kw)
    a = TinySesam(TinySesamConfig(**cfg))
    ap = FastAPI()
    ap.include_router(a.router())

    # Weg 1 der Doku: FastAPI-Antwortparameter, die Seite als Rückgabewert.
    @ap.get("/app/formular", response_class=HTMLResponse)
    def formular(request: Request, response: Response):
        csrf = a.ensure_csrf(request, response)
        return (f"<meta name=tinysesam-csrf-cookie content='{a.csrf_cookie_name}'>"
                f"<form method=post action=/app/speichern><input name=_csrf value='{csrf}'></form>")

    # Weg 2 der Doku: eine fertige Antwort (Jinja-`TemplateResponse` & Co.) — erst das Token,
    # dann die Seite, dann das Cookie an die fertige Antwort.
    @ap.get("/app/fertig")
    def fertig(request: Request):
        csrf = a.csrf_token(request)
        antwort = HTMLResponse(f"<input name=_csrf value='{csrf}'>")
        antwort.headers["x-ensure"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/speichern")
    def speichern(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        a.require_csrf(request, csrf_tok)
        return {"ok": True}

    # Eine eigene Anmelderoute der App: `start_session` + `set_cookie`, danach das Formular
    # derselben Antwort.
    @ap.post("/app/anmelden")
    def anmelden(request: Request):
        token, _ok = a.start_session(a.store.get_user_by_name("erika")["id"], "password")
        antwort = JSONResponse({})
        a.set_cookie(antwort, token)
        antwort.headers["x-csrf"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/abmelden")
    def abmelden(request: Request):
        antwort = JSONResponse({})
        a.logout(request, antwort)
        antwort.headers["x-csrf"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/nur-abmelden")
    def nur_abmelden(request: Request):
        antwort = JSONResponse({})
        a.logout(request, antwort)
        return antwort

    # Weg 2 und An-/Abmelden in DERSELBEN Antwort — die Grenze, die die Doku seit der
    # Nachbesserung nennt: Die fertige Seite ist gerendert, bevor `set_cookie`/`logout` dreht.
    @ap.post("/app/anmelden-fertig")
    def anmelden_fertig(request: Request):
        token, _ok = a.start_session(a.store.get_user_by_name("erika")["id"], "password")
        csrf = a.csrf_token(request)
        antwort = HTMLResponse(f"<input name=_csrf value='{csrf}'>")
        a.set_cookie(antwort, token)
        antwort.headers["x-ensure"] = a.ensure_csrf(request, antwort)
        return antwort

    @ap.post("/app/abmelden-fertig")
    def abmelden_fertig(request: Request):
        csrf = a.csrf_token(request)
        antwort = HTMLResponse(f"<input name=_csrf value='{csrf}'>")
        a.logout(request, antwort)
        antwort.headers["x-ensure"] = a.ensure_csrf(request, antwort)
        return antwort

    # Der Weg, den die Doku dafür nennt: an-/abmelden, umleiten, die Folgeanfrage rendert.
    @ap.post("/app/anmelden-umleiten")
    def anmelden_umleiten(request: Request):
        token, _ok = a.start_session(a.store.get_user_by_name("erika")["id"], "password")
        antwort = RedirectResponse("/app/fertig", 303)
        a.set_cookie(antwort, token)
        return antwort

    @ap.post("/app/abmelden-umleiten")
    def abmelden_umleiten(request: Request):
        antwort = RedirectResponse("/app/fertig", 303)
        a.logout(request, antwort)
        return antwort

    a.create_user("erika", password="geheim12345", email="erika@example.com")
    return a, ap


def _client(ap):
    return TestClient(ap, base_url=BASIS)


# Die Attribute, die `issue_csrf()` setzt — der Massstab für jeden anderen Setzer.
_a0, _ = _instanz()
_r0 = Response()
_a0.issue_csrf(_r0)
_ATTR = _attribute(_zeilen(_r0)[0])
assert _ATTR == {"path=/", "samesite=lax", "secure"}, _ATTR

# ---------- E1. ensure_csrf(): vorhandenes Token weiter, sonst eins setzen ----------
# (Mutationsprobe: in `ensure_csrf` immer neu würfeln wie `issue_csrf` → rot.)
_a, _ap = _instanz()
_c = _client(_ap)
_r = _c.get("/app/formular")
assert _r.status_code == 200 and len(_zeilen(_r)) == 1, _set_cookies(_r)
_t1 = _wert(_zeilen(_r)[0])
assert _feld(_r.text) == _t1 and _FORM.fullmatch(_t1), (_feld(_r.text), _t1)
assert _attribute(_zeilen(_r)[0]) == _ATTR, "ensure_csrf setzt andere Attribute als issue_csrf"
assert f"content='{_a.csrf_cookie_name}'" in _r.text
ok("ensure_csrf: erster Besuch setzt das Cookie (Attribute wie issue_csrf), Rückgabe = Formularwert")

_r = _c.get("/app/formular")
assert not _zeilen(_r) and _feld(_r.text) == _t1, (_set_cookies(_r), _feld(_r.text))
_r = _c.get("/app/fertig")
assert not _zeilen(_r) and _feld(_r.text) == _t1 == _r.headers["x-ensure"]
_r = _c.get("/auth/login")
assert not _zeilen(_r) and _feld(_r.text) == _t1, "render_page und ensure_csrf teilen sich das Token"
assert _c.post("/app/speichern", data={"_csrf": _t1}).status_code == 200
assert _c.post("/app/speichern", data={"_csrf": "falsch"}).status_code == 403
ok("ensure_csrf: vorhandenes Token bleibt (kein Set-Cookie) — die Formulare anderer Reiter gelten weiter")

# Weg 2: `csrf_token()` vor dem Rendern, `ensure_csrf()` an der fertigen Antwort — dasselbe Token.
# (Mutationsprobe: in `_csrf_der_anfrage` das neue Token nicht je Anfrage merken → rot.)
_c2 = _client(_ap)
_r = _c2.get("/app/fertig")
assert len(_zeilen(_r)) == 1 and _wert(_zeilen(_r)[0]) == _feld(_r.text) == _r.headers["x-ensure"], \
    (_set_cookies(_r), _feld(_r.text), _r.headers.get("x-ensure"))
ok("csrf_token() + ensure_csrf(fertige Antwort): dasselbe Token im Formular und im Cookie")

# Nichts Beliebiges übernehmen: Ein Cookie, das nicht wie ein Token aussieht, wird ersetzt —
# von ensure_csrf, csrf_token und render_page gleich.
# (Mutationsprobe: die Formatprüfung in `_csrf_der_anfrage` streichen → rot.)
for _schlecht in ("kurz", "A" * 31, "A" * 129, "A" * 30 + "<>", "A" * 30 + "'x"):
    for _pfad in ("/app/formular", "/app/fertig", "/auth/login"):
        _cs = _client(_ap)
        _cs.cookies.set(CK, _schlecht)
        _r = _cs.get(_pfad)
        assert len(_zeilen(_r)) == 1, (_schlecht, _pfad, _set_cookies(_r))
        _neu = _wert(_zeilen(_r)[0])
        assert _neu != _schlecht and _FORM.fullmatch(_neu) and _feld(_r.text) == _neu, \
            (_schlecht, _pfad, _neu, _feld(_r.text))
_gut = "B" * 43                          # z. B. secrets.token_urlsafe(32) — gültig, bleibt
_cs = _client(_ap)
_cs.cookies.set(CK, _gut)
_r = _cs.get("/app/formular")
assert not _zeilen(_r) and _feld(_r.text) == _gut
ok("ensure_csrf/csrf_token/render_page: ungültiges Cookie (kurz, zu lang, fremde Zeichen) wird ersetzt")

_ax, _apx = _instanz(csrf_enabled=False)
_r = _client(_apx).get("/app/formular")
assert not _set_cookies(_r) and "value=''" in _r.text
ok("csrf_enabled=False: ensure_csrf setzt nichts und liefert ''")

# Anmelden in DERSELBEN Antwort: ensure_csrf danach liefert das gedrehte Token, nicht das alte.
# (Mutationsprobe: in `ensure_csrf` die Antwort nicht befragen → rot.)
_c3 = _client(_ap)
_alt = _feld(_c3.get("/app/formular").text)
_r = _c3.post("/app/anmelden")
assert len(_zeilen(_r)) == 1, _set_cookies(_r)
_neu = _wert(_zeilen(_r)[0])
assert _neu != _alt and _r.headers["x-csrf"] == _neu, (_alt, _neu, _r.headers.get("x-csrf"))
_r = _c3.get("/app/formular")
assert not _zeilen(_r) and _feld(_r.text) == _neu
ok("eigene Anmelderoute (start_session + set_cookie): Token gedreht, ensure_csrf danach liefert das neue")

# Abmelden in derselben Antwort: ensure_csrf danach setzt ein NEUES (die Löschzeile ersetzt).
# (Mutationsprobe: in `_csrf_cookie_setzen` die vorhandene Zeile nicht entfernen → rot.)
_r = _c3.post("/app/abmelden")
assert len(_zeilen(_r)) == 1 and not _geloescht(_zeilen(_r)[0]), _set_cookies(_r)
assert _wert(_zeilen(_r)[0]) == _r.headers["x-csrf"] not in (_neu, _alt)
ok("logout() + ensure_csrf() in einer Antwort: genau eine Zeile, ein neues Token statt der Löschung")

# Weg 2 (fertige Antwort) und An-/Abmelden in DERSELBEN Antwort geht nicht — die Grenze, die
# README und `ensure_csrf` seit der Nachbesserung 0.20.1 nennen (Befund aus dem Angriff auf die
# CSRF-Änderungen: die Zusage „beide liefern dasselbe Token" galt dort nicht, still). Die Seite ist
# gerendert, bevor `set_cookie` das Token dreht bzw. `logout` es löscht; ihr Formular trägt das
# alte und scheitert mit 403. Das ist fail-closed und bleibt so: Die Drehung beim Anmelden ist die
# Sicherheitszusage, sie darf nicht davon abhängen, ob vorher ein Token ausgegeben wurde. Kein
# Code-Fix, darum keine Mutationsprobe — der Block hält fest, was die Doku sagt. Wird er rot, weil
# das Formular plötzlich gilt, ist entweder die Drehung weg oder die Doku veraltet.
for _weg in ("anmelden", "abmelden"):
    _cw = _client(_ap)
    if _weg == "abmelden":
        assert _cw.post("/app/anmelden").status_code == 200
    _vorher = _feld(_cw.get("/app/formular").text)
    _r = _cw.post(f"/app/{_weg}-fertig")
    _nachher = _cw.cookies.get(CK)
    assert _feld(_r.text) == _vorher != _nachher == _r.headers["x-ensure"], \
        (_weg, _vorher, _feld(_r.text), _nachher, _r.headers.get("x-ensure"))
    assert _cw.post("/app/speichern", data={"_csrf": _feld(_r.text)}).status_code == 403, _weg
    # Der dokumentierte Weg: umleiten; die Folgeanfrage rendert mit dem neuen Cookie.
    _cw = _client(_ap)
    if _weg == "abmelden":
        assert _cw.post("/app/anmelden").status_code == 200
    _vorher = _feld(_cw.get("/app/formular").text)
    _r = _cw.post(f"/app/{_weg}-umleiten", follow_redirects=False)
    assert _r.status_code == 303, (_weg, _r.status_code)
    _r = _cw.get("/app/fertig")
    assert _feld(_r.text) == _cw.cookies.get(CK) != _vorher, (_weg, _feld(_r.text), _vorher)
    assert _cw.post("/app/speichern", data={"_csrf": _feld(_r.text)}).status_code == 200, _weg
ok("Weg 2 + An-/Abmelden in einer Antwort: Formular trägt das alte Token (403, dokumentiert); "
   "umleiten geht")


# ---------- E2. Jeder Anmeldeweg dreht das CSRF-Token (OWASP: „changes with each login") ----------
# Zentral an `set_cookie()`: Jede voll angemeldete Sitzung entsteht in `_sitzung_anlegen()` und
# ist dort vorgemerkt; das Setzen ihres Cookies dreht das CSRF-Token in derselben Antwort. Ein
# Step-up dreht es nicht — das würde nur die Formulare der anderen offenen Reiter entwerten.
# (Mutationsprobe: in `set_cookie` den Aufruf von `csrf_rotieren` streichen → rot;
# in `_sitzung_anlegen` das Vormerken streichen → rot; in `complete_totp` wieder
# `store.create_session` direkt rufen → rot; in `set_cookie` jede volle Sitzung drehen statt nur
# der vorgemerkten → rot beim Step-up.)
def _dreht(name, cl, schritt, ap_=None):
    """`schritt(cl)` meldet an. Prüft: genau eine neue CSRF-Zeile, das alte Token ist tot, das
    neue gilt, und die nächste Seite — eingebaut wie eigen — rendert mit dem neuen."""
    alt = cl.cookies.get(CK)
    assert alt, f"{name}: Vorbedingung — vor der Anmeldung liegt ein CSRF-Cookie"
    r = schritt(cl)
    assert r.status_code in (200, 303), (name, r.status_code, r.text[:200])
    zeilen = _zeilen(r)
    assert len(zeilen) == 1, f"{name}: das CSRF-Token wurde nicht gedreht: {_set_cookies(r)}"
    neu = _wert(zeilen[0])
    assert neu != alt and _FORM.fullmatch(neu), (name, alt, neu)
    assert _attribute(zeilen[0]) == _ATTR, (name, zeilen[0])
    assert cl.cookies.get(CK) == neu
    assert cl.post("/app/speichern", data={"_csrf": alt}).status_code == 403, f"{name}: altes Token gilt"
    assert cl.post("/app/speichern", data={"_csrf": neu}).status_code == 200, f"{name}: neues gilt nicht"
    seite = cl.get("/app/formular")
    assert not _zeilen(seite) and _feld(seite.text) == neu, (name, _feld(seite.text))
    # Eine eingebaute Seite nach der Anmeldung (die Rückfrage des Abmeldens) trägt das neue Token.
    seite = cl.get("/auth/logout", headers={"Sec-Fetch-Site": "cross-site"})
    assert seite.status_code == 200 and _feld(seite.text) == neu, (name, seite.status_code)
    ok(f"Anmeldeweg {name}: CSRF-Token gedreht, Folgeseiten rendern mit dem neuen")
    return neu


def _bleibt(name, cl, schritt, warum="ein Step-up entwertet keine anderen Reiter"):
    alt = cl.cookies.get(CK)
    r = schritt(cl)
    assert r.status_code in (200, 303), (name, r.status_code, r.text[:200])
    assert not _zeilen(r) and cl.cookies.get(CK) == alt, f"{name}: dreht das CSRF-Token: {_set_cookies(r)}"
    ok(f"{name}: CSRF-Token bleibt ({warum})")


def _passwort(cl, user="erika", pw="geheim12345"):
    seite = cl.get("/auth/login", follow_redirects=False)     # angemeldet: 303 statt Formular
    f = _feld(seite.text) if seite.status_code == 200 else cl.cookies.get(CK)
    return cl.post("/auth/login", data={"username": user, "password": pw, "next": "/", "_csrf": f},
                   follow_redirects=False)


# Passwort
_a, _ap = _instanz()
_c = _client(_ap)
_c.get("/auth/login")
_dreht("Passwort", _c, _passwort)
# Step-up per Passwort (Reauth) auf der vollen Sitzung dreht nicht.
_bleibt("Step-up /auth/reauth", _c, lambda cl: cl.post(
    "/auth/reauth", data={"password": "geheim12345", "next": "/", "_csrf": cl.cookies.get(CK)},
    follow_redirects=False))
# Erneut anmelden als dieselbe Person mit voller Sitzung ist ein Step-up, als eine andere ein Login.
_a.create_user("otto", password="geheim67890")
_dreht("Identitätswechsel (andere Person meldet sich an)", _c,
       lambda cl: _passwort(cl, "otto", "geheim67890"))

# Registrierung mit sofortiger Anmeldung
_a, _ap = _instanz(allow_signup=True, signup_require_email=False, login_identifier="username")
_c = _client(_ap)
_c.get("/auth/register")
_dreht("Registrierung", _c, lambda cl: cl.post(
    "/auth/register", data={"username": "neu1", "password": "langes-passwort-1", "next": "/",
                            "_csrf": _feld(cl.get("/auth/register").text)}, follow_redirects=False))

# PIN als Erstfaktor
_a, _ap = _instanz(pin_enabled=True, pin_login=True)
_a.set_pin(_a.store.get_user_by_name("erika")["id"], "480915")
_c = _client(_ap)
_c.get("/auth/login")
_dreht("PIN", _c, lambda cl: cl.post(
    "/auth/pin", data={"username": "erika", "pin": "480915", "next": "/",
                       "_csrf": _feld(cl.get("/auth/pin").text)}, follow_redirects=False))

# Anmelde-Link
_a, _ap = _instanz(magiclink_enabled=True)
_tok = _a.create_magic_token("login", user_id=_a.store.get_user_by_name("erika")["id"],
                             email="erika@example.com", payload={"next": "/"})
_c = _client(_ap)
_c.get("/auth/login")
_dreht("Anmelde-Link", _c, lambda cl: cl.post(
    f"/auth/magic/{_tok}", data={"_csrf": _feld(cl.get(f"/auth/magic/{_tok}").text)},
    follow_redirects=False))

# Kette Passwort → TOTP: gedreht wird dort, wo die Sitzung voll wird — nicht schon beim ersten
# Faktor (die halbe Sitzung ist keine Anmeldung).
_a, _ap = _instanz(login_chain=["password", "totp"])
_uid = _a.store.get_user_by_name("erika")["id"]
_geheim = _a.totp_begin(_uid)["secret"]
assert _a.totp_confirm(_uid, pyotp.TOTP(_geheim).at(int(_time.time()) - 30))
_c = _client(_ap)
_c.get("/auth/login")
_bleibt("Kette: erster Faktor", _c, _passwort, "die halbe Sitzung ist noch keine Anmeldung")
_dreht("Kette Passwort → TOTP", _c, lambda cl: cl.post(
    "/auth/totp", data={"code": pyotp.TOTP(_geheim).now(), "next": "/",
                        "_csrf": _feld(cl.get("/auth/totp").text)}, follow_redirects=False))
_bleibt("Step-up per TOTP", _c, lambda cl: cl.post(
    "/auth/totp", data={"code": pyotp.TOTP(_geheim).at(int(_time.time()) + 30), "next": "/",
                        "_csrf": cl.cookies.get(CK)}, follow_redirects=False))

# Kette mit Pflicht-Einrichtung: der Bestätigungscode schliesst die Anmeldung ab (JSON-Antwort).
_a, _ap = _instanz(login_chain=["password", "totp"])
_uid = _a.store.get_user_by_name("erika")["id"]
_c = _client(_ap)
_c.get("/auth/login")
assert _passwort(_c).status_code == 303
_start = _c.post("/auth/totp/setup/start", data={"next": "/", "_csrf": _c.cookies.get(CK)})
assert _start.status_code == 200, _start.status_code
_geheim = _a.store.get_totp(_uid)["secret"]
_dreht("Kette mit TOTP-Einrichtung", _c, lambda cl: cl.post(
    "/auth/totp/setup", data={"code": pyotp.TOTP(_geheim).now(), "next": "/"},
    headers={"X-CSRF-Token": cl.cookies.get(CK)}))

# OIDC-Rückweg (ohne Netz: Discovery vorbefüllt, Token-Tausch als Attrappe)
if importlib.util.find_spec("authlib") is None:
    print("  - OIDC ausgelassen: Extra [oidc] (authlib) fehlt — der Wächter E3 deckt den Weg strukturell")
else:
    class _Claims(dict):
        def validate(self, *a, **k):
            pass

    _idp = "https://idp.example.com"
    _a, _ap = _instanz(oidc_enabled=True, oidc_issuer=_idp, oidc_client_id="probe",
                       oidc_client_secret="geheim")
    _a.oidc._meta = {"issuer": _idp, "authorization_endpoint": _idp + "/authorize",
                     "token_endpoint": _idp + "/token", "userinfo_endpoint": _idp + "/userinfo",
                     "jwks_uri": _idp + "/jwks"}
    _a.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({"sub": "oidc-1", "preferred_username": "olga", "name": "Olga",
                 "email": "olga@example.com", "email_verified": True, "nonce": nonce}),
        {"access_token": "at"})
    _a.oidc.userinfo = lambda at, erwartetes_sub="": {}
    _c = _client(_ap)
    _c.get("/auth/login")

    def _oidc(cl):
        start = cl.get("/auth/oidc/start", follow_redirects=False)
        state = _parse_qs(_urlparse(start.headers["location"]).query)["state"][0]
        return cl.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)
    _dreht("OIDC", _c, _oidc)

# SAML-ACS (Assertion als Attrappe — die Signaturprüfung prüft test_saml.py)
if importlib.util.find_spec("onelogin") is None:
    print("  - SAML ausgelassen: Extra [saml] fehlt — der Wächter E3 deckt den Weg strukturell")
else:
    class _FakeSAML:
        def login_url(self, req, base, return_to="/"):
            return "https://idp.example.com/sso?SAMLRequest=abc", "_id-1"

        def process(self, req, base, request_id=""):
            return {"nameid": "sara", "attrs": {"email": ["sara@example.com"]}}

        def metadata(self, base):
            return "<md:EntityDescriptor/>"

    _db_s = os.path.join(tempfile.mkdtemp(), "t.db")
    _a = TinySesam(TinySesamConfig(db_path=_db_s, lang="de", passkey_enabled=False, oidc_enabled=False,
                                   base_url=BASIS, saml_enabled=True,
                                   saml_idp_sso_url="https://idp.example.com/sso",
                                   saml_idp_x509cert="MIID...dummy", saml_attr_email="email"))
    _a.saml = _FakeSAML()
    _ap = FastAPI()
    _ap.include_router(_a.router())

    @_ap.post("/app/speichern")
    def _s_speichern(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        _a.require_csrf(request, csrf_tok)
        return {"ok": True}

    @_ap.get("/app/formular", response_class=HTMLResponse)
    def _s_formular(request: Request, response: Response):
        return f"<input name=_csrf value='{_a.ensure_csrf(request, response)}'>"

    _c = _client(_ap)
    _c.get("/auth/login")
    _dreht("SAML", _c, lambda cl: cl.post("/auth/saml/acs", data={"SAMLResponse": "x", "RelayState": "/"},
                                          follow_redirects=False))

# Passkey (Signaturprüfung ersetzt — geprüft wird der Draht, nicht WebAuthn)
if importlib.util.find_spec("webauthn") is None:
    print("  - Passkey ausgelassen: Extra [passkey] fehlt — der Wächter E3 deckt den Weg strukturell")
else:
    import webauthn as _webauthn
    _echt = _webauthn.verify_authentication_response
    _webauthn.verify_authentication_response = lambda **kw: _types.SimpleNamespace(new_sign_count=1)
    try:
        _a, _ap = _instanz(passkey_enabled=True, rp_id="testserver", origin=BASIS)
    finally:
        _webauthn.verify_authentication_response = _echt
    _a.store.add_webauthn(_a.store.get_user_by_name("erika")["id"], "Y3JlZC10ZXN0", "pk", 0,
                          ["internal"], "Test")
    _c = _client(_ap)
    _c.get("/auth/login")

    def _passkey(cl):
        kopf = {"X-CSRF-Token": cl.cookies.get(CK), "Content-Type": "application/json"}
        assert cl.post("/auth/passkey/login/begin", headers=kopf).status_code == 200
        return cl.post("/auth/passkey/login/finish", content=_json.dumps({"id": "Y3JlZC10ZXN0"}),
                       headers=kopf)
    _dreht("Passkey", _c, _passkey)

# Eigene Anmelderoute der App (start_session + set_cookie, ohne eingebaute Route)
_a, _ap = _instanz()
_c = _client(_ap)
_c.get("/app/formular")
_dreht("eigene Route (start_session + set_cookie)", _c, lambda cl: cl.post("/app/anmelden"))


# ---------- E2b. Abmelden löscht das CSRF-Cookie ----------
# (Mutationsprobe: in `logout()` die Löschung des CSRF-Cookies streichen → rot; in
# `_csrf_cookie_loeschen` das `secure=` weglassen → rot.)
def _abmelden_loescht(name, schritt):
    a, ap = _instanz()
    cl = _client(ap)
    assert _passwort(cl).status_code == 303
    alt = cl.cookies.get(CK)
    r = schritt(cl)
    zeilen = _zeilen(r)
    assert len(zeilen) == 1 and _geloescht(zeilen[0]), f"{name}: {_set_cookies(r)}"
    assert _attribute(zeilen[0]) == _ATTR, (name, zeilen[0])     # Secure + Path=/: sonst verwirft
    assert cl.cookies.get(CK) is None                            # der Browser die __Host-Löschung
    neu = _feld(cl.get("/auth/login").text)
    assert neu != alt and cl.cookies.get(CK) == neu, (name, alt, neu)
    ok(f"{name}: CSRF-Cookie gelöscht, die Seite danach bekommt ein neues Token")


_abmelden_loescht("POST /auth/logout", lambda cl: cl.post(
    "/auth/logout", data={"_csrf": cl.cookies.get(CK)}, follow_redirects=False))
_abmelden_loescht("GET /auth/logout (eigene Seite)",
                  lambda cl: cl.get("/auth/logout", follow_redirects=False))
_abmelden_loescht("auth.logout() in einer eigenen Route", lambda cl: cl.post("/app/nur-abmelden"))


# ---------- E3. Wächter: kein Anmeldeweg kann die Rotation umgehen ----------
# Die Rotation hängt an zwei Engstellen: Jede Sitzungszeile entsteht in `_sitzung_anlegen()`
# (dort wird die volle vorgemerkt), und jedes Sitzungs-Cookie setzt `set_cookie()` (dort wird
# gedreht). Ein neuer Anmeldeweg, der eine davon umgeht, fällt hier auf — auch einer, für den
# E2 keinen Durchlauf hat.
# (Mutationsprobe: in `apply_factor` wieder `self.store.create_session(…)` direkt rufen → rot.)
class _Aufrufe(ast.NodeVisitor):
    def __init__(self):
        self.stapel, self.funde = [], []

    def visit_FunctionDef(self, node):
        self.stapel.append(node.name)
        self.generic_visit(node)
        self.stapel.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        f = node.func
        if isinstance(f, ast.Attribute):
            erstes = node.args[0] if node.args else None
            if f.attr == "create_session" and isinstance(f.value, ast.Attribute) and f.value.attr == "store":
                self.funde.append(("create_session", tuple(self.stapel), node.lineno))
            if (f.attr == "set_cookie" and isinstance(erstes, ast.Attribute)
                    and erstes.attr == "session_cookie_name"):
                self.funde.append(("sitzungs_cookie", tuple(self.stapel), node.lineno))
        self.generic_visit(node)


_paket = pathlib.Path(__file__).resolve().parent.parent / "tinysesam"
_funde = []
for _datei in sorted(_paket.glob("*.py")):
    _v = _Aufrufe()
    _v.visit(ast.parse(_datei.read_text(encoding="utf-8")))
    _funde += [(_datei.name,) + f for f in _v.funde]
_anlage = [f for f in _funde if f[1] == "create_session"]
_cookie = [f for f in _funde if f[1] == "sitzungs_cookie"]
assert _anlage and all(f[0] == "manager.py" and f[2][-1:] == ("_sitzung_anlegen",) for f in _anlage), \
    f"eine Sitzung entsteht an `_sitzung_anlegen` vorbei (wird nicht vorgemerkt): {_anlage}"
assert _cookie and all(f[0] == "manager.py" and f[2][-1:] == ("set_cookie",) for f in _cookie), \
    f"ein Sitzungs-Cookie wird an `set_cookie` vorbei gesetzt (dreht kein CSRF-Token): {_cookie}"
ok(f"Wächter: {len(_anlage)} Sitzungsanlage(n) nur in _sitzung_anlegen, Sitzungs-Cookie nur in set_cookie")
print("\nCSRF 0.20.1 (ensure_csrf, Rotation, Abmelden) OK ✅")
