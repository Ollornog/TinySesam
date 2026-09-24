"""E2: Cookie-Flags — HttpOnly/Secure/SameSite/Max-Age an jedem Cookie, das TinySesam setzt.

Nagelt fest, was im Code steht, aber bisher kein Test hielt: Ein Refactor, der am
Session-Cookie `httponly=True` verliert, fiele sonst niemandem auf — die Bibliothek
bliebe grün und gäbe die Sitzung an jedes XSS weiter.

Geprüft wird der ROHE `Set-Cookie`-Header, nicht der Cookie-Jar des Clients: nur der
zeigt, was wirklich beim Browser ankommt. Ein Jar verschluckt Attribute.

Parser und Prüfregel kommen aus dem geteilten Kit (`_kit/headers.py`, via `repokit sync`);
hier steht nur, was TinySesam-eigen ist: welche Cookies es gibt und was jedes mitbringen
muss (`ERWARTUNG`). Ein Cookie, das gesetzt wird und in `ERWARTUNG` fehlt, ist ein
Verstoß — wer eins einführt, muss seine Flags erklären.

Die wichtigste Aussage steht bei `tinysesam_csrf`: das Cookie ist ABSICHTLICH nicht
HttpOnly — Double-Submit braucht JS-Lesezugriff (siehe test_csrf.py). Ein pauschales
„alle Cookies HttpOnly" wäre also falsch und würde genau das richtige Cookie anmeckern.
Darum je Cookie eine eigene Erwartung, nicht eine Regel für alle.

Nicht abgedeckt, bewusst:

* `tinysesam_waflow` (webauthn_.py) nur, wenn das Extra [passkey] da ist (Block D2c). Ein
  harter `webauthn`-Import ließe run_all.py die GANZE Suite überspringen, sobald das Extra
  fehlt, und die Flags oben wären ungeprüft — deshalb fehlt ohne das Extra nur dieser Block.
* Der CSRF-Setzer in `admin.py`. Es gibt drei (`manager.render_page`, `manager.issue_csrf`,
  `admin.py`); die ersten beiden prüft diese Suite. Der dritte bräuchte das gemountete
  Admin-Panel — das steht in test_adminmount.py und gehört dorthin, nicht hierher.
"""
import importlib.util
import os
import re
import sys
import tempfile
import time

from fastapi import Depends, FastAPI, Request, Response
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _kit import headers  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


def gesetzte_cookies(response) -> dict:
    """Set-Cookie-Header der Antwort → {name: {attribut: wert}}. Parser kommt aus dem Kit."""
    return headers.parse_set_cookie(headers.rohe_set_cookie(response))


# Was jedes Cookie mitbringen MUSS — je Cookie eigens, nicht als eine Regel für alle.
# `httponly: False` beim CSRF-Cookie ist kein Versehen, sondern die Bedingung dafür, dass
# Double-Submit überhaupt funktioniert (JS muss es lesen, siehe test_csrf.py).
ERWARTUNG = {
    "__Host-tinysesam_session": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"},
    "__Host-tinysesam_csrf":    {"httponly": False, "secure": True, "samesite": "lax", "path": "/"},
    "__Host-tinysesam_runlock": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"},
}


def baue(**cfg_kw):
    """Frische Instanz mit eigener DB. Gibt (auth, client).

    base_url richtet sich nach cookie_secure: ein Secure-Cookie legt httpx über http://
    gar nicht erst ab (RFC 6265) — der Login-Flow bräche dann am CSRF-Cookie, nicht am
    Prüfgegenstand.
    """
    kw = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), rp_name="Test",
              passkey_enabled=False, oidc_enabled=False)
    kw.update(cfg_kw)
    auth = TinySesam(TinySesamConfig(**kw))
    auth.ensure_admin("admin", "geheim123")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    base = "http://testserver" if kw.get("cookie_secure") is False else "https://testserver"
    return auth, TestClient(app, base_url=base)


def login(client, remember="on"):
    """Echter Login über den Router (Double-Submit). Gibt die 303-Antwort ungefolgt zurück."""
    html = client.get("/auth/login").text
    field = re.search(r"name=_csrf value='([^']+)'", html).group(1)
    return client.post("/auth/login",
                       data={"username": "admin", "password": "geheim123", "next": "/",
                             "remember": remember, "_csrf": field},
                       follow_redirects=False)


class _FakeReq:
    """Minimale Request-Attrappe: unlock_resource() liest nur .cookies."""
    cookies: dict = {}


# ---------- A. Echter Login-Flow: die Flags überleben den Router ----------
auth, c = baue()

r = c.get("/auth/login")
gesetzt = gesetzte_cookies(r)
assert "__Host-tinysesam_csrf" in gesetzt, "Login-Seite muss das CSRF-Cookie setzen"
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
ok("CSRF-Cookie: bewusst kein HttpOnly, aber Secure + SameSite=lax + Path")

r = login(c)
assert r.status_code == 303, r.status_code
gesetzt = gesetzte_cookies(r)
assert "__Host-tinysesam_session" in gesetzt, "Login muss das Session-Cookie setzen"
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
assert "max-age" in gesetzt["__Host-tinysesam_session"], "remember=on muss persistent sein"
ok("Session-Cookie im echten Login: HttpOnly + Secure + SameSite=lax + Path + Max-Age")

assert c.get("/geheim").json() == {"u": "admin"}
ok("Session trägt: /geheim erreichbar (das Cookie ist echt, nicht nur ein Header)")


# ---------- B. Flag-Matrix direkt an set_cookie() ----------
# Ohne Login-Flow: der Cookie-Jar des Clients würde Secure/Domain-Varianten verschlucken.
auth, _ = baue()

resp = Response()
auth.set_cookie(resp, "tok123", remember=True)
sess = gesetzte_cookies(resp)["__Host-tinysesam_session"]
assert sess["_wert"] == "tok123" and "max-age" in sess
ok("set_cookie(remember=True) → Max-Age gesetzt (persistent)")

resp = Response()
auth.set_cookie(resp, "tok123", remember=False)
sess = gesetzte_cookies(resp)["__Host-tinysesam_session"]
assert "max-age" not in sess, "remember=False muss ein reines Session-Cookie sein"
assert sess.get("httponly") is True, "HttpOnly darf bei remember=False nicht verloren gehen"
ok("set_cookie(remember=False) → kein Max-Age, HttpOnly bleibt")

auth, _ = baue(cookie_secure=False)
resp = Response()
auth.set_cookie(resp, "tok123")
sess = gesetzte_cookies(resp)["tinysesam_session"]
assert "secure" not in sess, "cookie_secure=False muss das Secure-Flag weglassen"
assert sess.get("httponly") is True, "HttpOnly hängt NICHT an cookie_secure"
ok("cookie_secure=False (lokal/Demo) → kein Secure, HttpOnly bleibt")

auth, _ = baue(cookie_samesite="strict")
resp = Response()
auth.set_cookie(resp, "tok123")
assert gesetzte_cookies(resp)["__Host-tinysesam_session"].get("samesite") == "strict"
ok("cookie_samesite wird durchgereicht (strict)")

auth, _ = baue(cookie_domain=".example.com")
resp = Response()
auth.set_cookie(resp, "tok123")
assert gesetzte_cookies(resp)["tinysesam_session"].get("domain") == ".example.com"
ok("cookie_domain wird gesetzt (SSO über Subdomains)")

auth, _ = baue(cookie_path="/app")
resp = Response()
auth.set_cookie(resp, "tok123")
assert gesetzte_cookies(resp)["tinysesam_session"].get("path") == "/app"
ok("cookie_path wird durchgereicht")

# issue_csrf() ist der zweite CSRF-Setzer: öffentliche API für fremde Templates, die nicht
# über render_page() laufen. Er muss dieselben Flags setzen wie der interne Pfad — täte er
# es nicht, wäre ausgerechnet die Fremd-Integration die schwächste.
auth, _ = baue()
resp = Response()
tok = auth.issue_csrf(resp)
gesetzt = gesetzte_cookies(resp)
assert tok and "__Host-tinysesam_csrf" in gesetzt
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
ok("issue_csrf() setzt dieselben Flags wie der interne Pfad")

# Ist CSRF aus, darf auch kein Cookie entstehen — sonst behauptet die Antwort Schutz, den es nicht gibt.
auth, _ = baue(csrf_enabled=False)
resp = Response()
assert auth.issue_csrf(resp) == ""
assert gesetzte_cookies(resp) == {}
ok("csrf_enabled=False → issue_csrf() setzt gar kein Cookie")


# ---------- C. Ressourcen-Cookie ----------
auth, _ = baue()
resp = Response()
auth.unlock_resource(_FakeReq(), resp, "fotos")
gesetzt = gesetzte_cookies(resp)
assert "__Host-tinysesam_runlock" in gesetzt
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
assert "max-age" in gesetzt["__Host-tinysesam_runlock"], "Ressourcen-Freischaltung muss ablaufen"
ok("Ressourcen-Cookie: HttpOnly + Secure + SameSite + Max-Age")


# ---------- D. Logout räumt das Cookie ab ----------
auth, c = baue()
login(c)
r = c.get("/auth/logout", follow_redirects=False)
sess = gesetzte_cookies(r).get("__Host-tinysesam_session")
assert sess is not None, "Logout muss das Session-Cookie überschreiben, nicht nur die DB-Zeile leeren"
assert sess["_wert"] in ("", '""'), f"Logout muss den Cookie-Wert leeren, ist: {sess['_wert']!r}"
# Ein `__Host-`-Set-Cookie ohne Secure verwirft der Browser — auch das löschende. Ohne das
# Flag bliebe das Cookie nach dem Logout einfach stehen.
assert sess.get("secure") is True and sess.get("path") == "/", sess
ok("Logout leert das Session-Cookie beim Browser (mit Secure + Path, sonst nimmt er das __Host-Löschen nicht an)")

# ---------- D2. `__Host-`-Präfix nur, wo der Browser es zulässt (H-1) ----------
# Ein `__Host-`-Cookie kann keine Nachbar-Subdomain setzen oder überschatten — das ist der
# Riegel gegen untergeschobene Sitzungs-, CSRF- und Freigabe-Tokens (F-01, F-02). Der Browser
# nimmt es aber nur mit Secure, ohne Domain und mit Path=/ an; überall sonst hiesse das Präfix:
# gar kein Cookie.
for kw, erwartet in (({}, True), ({"cookie_samesite": "strict"}, True),
                     ({"cookie_secure": False}, False), ({"cookie_domain": ".example.com"}, False),
                     ({"cookie_path": "/app"}, False), ({"cookie_host_prefix": False}, False),
                     # A-7: Pfad "" schickt gar kein Path-Attribut — `__Host-` verlangt Path=/.
                     ({"cookie_path": ""}, False)):
    a, _ = baue(**kw)
    namen = (a.session_cookie_name, a.csrf_cookie_name, a.resource_cookie_name)
    # Die Flow-Cookies (OIDC/SAML/Passkey) und das CSRF-Cookie setzen nie eine Domain — sie
    # tragen das Präfix auch bei gesetztem cookie_domain (A-1; das CSRF-Cookie seit der
    # Nacharbeit zu H-1: ohne Präfix setzte jede Nachbar-Subdomain ein passendes Paar).
    flow_erwartet = erwartet or kw == {"cookie_domain": ".example.com"}
    assert a.session_cookie_name.startswith("__Host-") == erwartet, (kw, namen)
    assert a.resource_cookie_name.startswith("__Host-") == erwartet, (kw, namen)
    assert a.csrf_cookie_name.startswith("__Host-") == flow_erwartet, (kw, namen)
    assert a.flow_cookie_name("tinysesam_oidc_flow").startswith("__Host-") == flow_erwartet, kw
    resp = Response()
    a.set_cookie(resp, "tok123")
    a.issue_csrf(resp)
    a.unlock_resource(_FakeReq(), resp, "fotos")
    gesetzt = gesetzte_cookies(resp)
    assert set(gesetzt) == set(namen), (kw, gesetzt.keys())
    # Jedes `__Host-`-Cookie so, wie der Browser es annimmt — auch das CSRF-Cookie neben einer
    # Sitzung mit Domain: Trüge es selbst eine Domain, verwürfe der Browser es still.
    for n in namen:
        if n.startswith("__Host-"):
            assert gesetzt[n].get("secure") is True and gesetzt[n].get("path") == "/" \
                and "domain" not in gesetzt[n], (n, gesetzt[n])
    # Kein `__Host-`-Cookie ohne Path=/ — das verwirft der Browser still (A-7).
    for n in namen:
        assert not n.startswith("__Host-") or gesetzt[n].get("path") == "/", (kw, n, gesetzt[n])
    fr = Response()
    a._flow_cookie_setzen(fr, "tinysesam_oidc_flow", "w", max_age=60)
    f_n, f_c = next(iter(gesetzte_cookies(fr).items()))
    assert f_n == a.flow_cookie_name("tinysesam_oidc_flow") and "domain" not in f_c, (kw, f_n, f_c)
    assert not f_n.startswith("__Host-") or (f_c.get("secure") is True and f_c.get("path") == "/"), f_c
ok("__Host- an Sitzung, CSRF und Freigabe genau dann, wenn Secure + host-only + Path=/ (sonst ohne)")
ok("A-1/A-7: Flow-Cookies mit __Host- auch bei cookie_domain; cookie_path='' bekommt kein Präfix")

# Ein Cookie gleichen Namens OHNE Präfix — das, was eine Nachbar-Subdomain setzen kann —
# meldet niemanden an.
auth, c = baue()
login(c)
echt = c.cookies.get("__Host-tinysesam_session")
assert echt and c.get("/geheim").status_code == 200
c.cookies.clear()
c.cookies.set("tinysesam_session", echt)
assert c.get("/geheim").status_code in (401, 307), "ungepräfixtes Cookie darf nicht zählen"
ok("ein ungepräfixtes Sitzungs-Cookie (Subdomain-Wurf) wird nicht gelesen")

# ---------- D2b. Die Altnamen von vor dem Präfix räumt TinySesam weg (H-1, B-20) ----------
# Nach dem Update liest TinySesam nur noch `__Host-…`. Die Cookies unter den alten Namen lagen
# bis zu ihrem Ablauf daneben (Sitzung bis 7 Tage, Freigabe 12 h) — gelöscht hat sie niemand,
# auch nicht der Logout. Zusammen mit den neuen trug ein Browser so sieben und mehr
# tinysesam-Cookies, und die nginx-Vorlagen reichten das überzählige an die App durch.
# Jetzt löscht jede Antwort, die das Sitzungs-Cookie schreibt (Anmelden, Abmelden, Step-up),
# die Altnamen, die der Browser mitgeschickt hat — host-only, wie sie gesetzt waren.
# (Mutationsprobe: den Aufruf von `_altnamen_loeschen` in der Routen-Klasse streichen → rot;
# den in `logout()` streichen → rot beim Abmelden über eine eigene Route.)
ALT = ("tinysesam_session", "tinysesam_csrf", "tinysesam_runlock")


def geloescht(response) -> set:
    """Die Namen, die diese Antwort beim Browser löscht (leerer Wert, Max-Age=0)."""
    return {n for n, c in gesetzte_cookies(response).items()
            if c["_wert"] in ("", '""') and str(c.get("max-age")) == "0"}


auth, c = baue()
_uid = auth.store.get_user_by_name("admin")["id"]
_alt_sitzung = auth.store.create_session(_uid, 3600, True, "password")   # aus der Zeit vor dem Update
_alt_freigabe = "alte-freigabe-vor-dem-update"
auth.store.add_resource_unlock(_alt_freigabe, "fotos", int(time.time()) + 3600)
for n in ALT:
    c.cookies.set(n, "ALT")
c.cookies.set("tinysesam_session", _alt_sitzung)
c.cookies.set("tinysesam_runlock", _alt_freigabe)
assert auth.store.get_session(_alt_sitzung) and auth.store.is_resource_unlocked(_alt_freigabe, "fotos")
r = login(c)
assert r.status_code == 303 and "__Host-tinysesam_session" in gesetzte_cookies(r)
assert geloescht(r) >= set(ALT), f"Login löscht die Altnamen nicht: {geloescht(r)}"
for n in ALT:
    zeile = gesetzte_cookies(r)[n]
    assert zeile.get("path") == "/" and "domain" not in zeile, (n, zeile)
ok("H-1: der Login löscht die mitgeschickten Cookies unter den Altnamen (host-only, Path=/)")
# Und die Sitzung dahinter: Das alte Token hätte unter dem neuen Namen noch sieben Tage angemeldet.
# (Mutationsprobe: in `_altnamen_loeschen` delete_session/delete_resource_unlocks streichen → rot.)
assert auth.store.get_session(_alt_sitzung) is None, "die Sitzung hinter dem Altnamen lebt weiter"
assert not auth.store.is_resource_unlocked(_alt_freigabe, "fotos"), "die alte Freigabe lebt weiter"
ok("H-1: …und beendet die Sitzung und die Freigaben dahinter")

auth, c = baue()
login(c)
c.cookies.set("tinysesam_runlock", "ALT")
r = c.get("/auth/logout", follow_redirects=False)
assert "tinysesam_runlock" in geloescht(r) and "__Host-tinysesam_session" in geloescht(r), geloescht(r)
assert not {"tinysesam_session", "tinysesam_csrf"} & set(gesetzte_cookies(r)), \
    "gelöscht wird nur, was der Browser mitgeschickt hat"
ok("H-1: der Logout löscht sie ebenso — und nur die, die der Browser wirklich hat")

# Auch ein Abmelden über eine EIGENE Route der App (`auth.logout()` direkt, ohne die Routen-Klasse).
auth, c = baue()
_app_eigen = c.app


@_app_eigen.post("/eigen/abmelden")
def _eigen_abmelden(request: Request):
    antwort = Response()
    auth.logout(request, antwort)
    return antwort


login(c)
c.cookies.set("tinysesam_session", "ALT")
assert "tinysesam_session" in geloescht(c.post("/eigen/abmelden")), \
    "auth.logout() in einer eigenen Route lässt die Altnamen stehen"
ok("H-1: auth.logout() in einer eigenen Route räumt die Altnamen ebenfalls")

# Ebenso ein Step-up über die öffentliche Methode `auth.rotate_session(request, response)` in einer
# eigenen Route: Sie schreibt die Sitzung und hat den Request — also gehen die Altnamen mit.
# (Mutationsprobe: den Aufruf von `_altnamen_loeschen` in `rotate_session` streichen → rot.)


@_app_eigen.post("/eigen/stepup")
def _eigen_stepup(request: Request):
    antwort = Response()
    auth.rotate_session(request, antwort)
    return antwort


login(c)
_alt_su = auth.store.create_session(auth.store.get_user_by_name("admin")["id"], 3600, True, "password")
c.cookies.set("tinysesam_session", _alt_su)
r = c.post("/eigen/stepup")
assert "__Host-tinysesam_session" in gesetzte_cookies(r), "rotate_session setzt kein Cookie"
assert "tinysesam_session" in geloescht(r), "auth.rotate_session() lässt die Altnamen stehen"
assert auth.store.get_session(_alt_su) is None, "die Sitzung hinter dem Altnamen lebt weiter"
ok("H-1: auth.rotate_session() in einer eigenen Route räumt die Altnamen ebenfalls")

# Gelöscht wird nur, wenn die Antwort die Sitzung schreibt. Eine Seite, die bloss das CSRF-Cookie
# setzt (GET /auth/login), lässt die Altnamen stehen — sonst beendete jeder Seitenaufruf, auch ein
# eingebettetes Bild von fremder Hand, die Sitzung hinter dem alten Cookie.
# (Mutationsprobe: in `_altnamen_loeschen` die Bedingung „Sitzungs-Cookie gesetzt" streichen → rot.)
auth, c = baue()
_alt_get = auth.store.create_session(auth.store.get_user_by_name("admin")["id"], 3600, True, "password")
for n in ALT:
    c.cookies.set(n, "ALT")
c.cookies.set("tinysesam_session", _alt_get)
r = c.get("/auth/login")
assert r.status_code == 200 and "__Host-tinysesam_csrf" in gesetzte_cookies(r), gesetzte_cookies(r)
assert not geloescht(r) and not set(ALT) & set(gesetzte_cookies(r)), gesetzte_cookies(r)
assert auth.store.get_session(_alt_get), "ein blosser Seitenaufruf beendet die Altsitzung"
ok("H-1: eine Antwort ohne Sitzungs-Cookie (GET /auth/login) löscht keine Altnamen")

# Mit `cookie_domain` (Forward-Auth über Subdomains) greift das Präfix nur am CSRF-Cookie — der
# Altname ist dann `tinysesam_csrf`. Den setzte TinySesam auch vorher nie mit Domain; gelöscht
# wird er also host-only. Ein `Domain=`-Attribut träfe ein anderes Cookie und liesse das echte
# liegen.
# (Mutationsprobe: in `_altnamen_loeschen` `_cookie_loeschen` statt der host-only-Löschung → rot.)
auth, c = baue(cookie_domain=".example.com")
assert auth.session_cookie_name == "tinysesam_session" and auth.csrf_cookie_name == "__Host-tinysesam_csrf"
assert auth._altnamen() == ["tinysesam_csrf"], auth._altnamen()
c.cookies.set("tinysesam_csrf", "ALT")
r = login(c)
assert r.status_code == 303 and "tinysesam_session" in gesetzte_cookies(r)
assert "tinysesam_csrf" in geloescht(r), f"Altname tinysesam_csrf nicht gelöscht: {geloescht(r)}"
_zeile = gesetzte_cookies(r)["tinysesam_csrf"]
assert "domain" not in _zeile and _zeile.get("path") == "/", _zeile
assert gesetzte_cookies(r)["tinysesam_session"].get("domain") in (".example.com", "example.com")
ok("H-1: mit cookie_domain wird der Altname tinysesam_csrf host-only gelöscht, die Sitzung bleibt Domain-weit")

# Wo das Präfix nicht greift, SIND die Altnamen die aktuellen Namen — die dürfen nicht fallen.
auth, c = baue(cookie_secure=False)
c.cookies.set("tinysesam_runlock", "AKTUELL")
r = login(c)
assert r.status_code == 303 and not geloescht(r), geloescht(r)
assert gesetzte_cookies(r)["tinysesam_session"]["_wert"] not in ("", '""')
ok("ohne Präfix (cookie_secure=False) löscht der Login keins der eigenen Cookies")

# ---------- D2c. Das Passkey-Flow-Cookie endet mit seinem Flow ----------
# Der Flow-Satz ist nach `finish` verbraucht (pop_flow), das Cookie dazu blieb aber 300 s
# liegen — ein tinysesam-Cookie mehr, das nichts mehr bindet und an jede App mitging. OIDC und
# SAML löschten ihres schon am Rückweg. Der Block braucht das Extra [passkey]; ohne es fehlt nur
# er, nicht die Suite. Geprüft wird die Route, nicht WebAuthn: die Signaturprüfung ist ersetzt.
# (Mutationsprobe: `_flow_cookie_loeschen` in login_finish bzw. reg_finish streichen → rot.)
if importlib.util.find_spec("webauthn") is None:
    print("  - D2c ausgelassen: Extra [passkey] (webauthn) fehlt")
else:
    import json
    import types
    import webauthn
    _echt = (webauthn.verify_authentication_response, webauthn.verify_registration_response)
    webauthn.verify_authentication_response = lambda **kw: types.SimpleNamespace(new_sign_count=1)
    webauthn.verify_registration_response = lambda **kw: types.SimpleNamespace(
        credential_id=b"neu", credential_public_key=b"pk", sign_count=0)
    try:
        auth, c = baue(passkey_enabled=True, rp_id="testserver", origin="https://testserver")
    finally:
        webauthn.verify_authentication_response, webauthn.verify_registration_response = _echt
    auth.store.add_webauthn(auth.store.get_user_by_name("admin")["id"], "Y3JlZC10ZXN0", "pk", 0,
                            ["internal"], "Test")
    c.get("/auth/login")
    kopf = {"X-CSRF-Token": c.cookies.get("__Host-tinysesam_csrf"), "Content-Type": "application/json"}
    r = c.post("/auth/passkey/login/begin", headers=kopf)
    assert r.status_code == 200 and "__Host-tinysesam_waflow" in gesetzte_cookies(r), r.text[:120]
    verstoesse = headers.pruefe_cookie_flags(gesetzte_cookies(r), {
        "__Host-tinysesam_waflow": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"}})
    assert not verstoesse, verstoesse
    r = c.post("/auth/passkey/login/finish", content=json.dumps({"id": "Y3JlZC10ZXN0"}), headers=kopf)
    assert r.status_code == 200 and r.json()["ok"], r.text[:200]
    assert "__Host-tinysesam_session" in gesetzte_cookies(r)
    assert "__Host-tinysesam_waflow" in geloescht(r), f"Flow-Cookie bleibt nach dem Login: {gesetzte_cookies(r)}"
    ok("Passkey-Login: das Flow-Cookie (httponly, __Host-) endet mit dem Flow")

    r = c.post("/auth/passkey/register/begin", headers=kopf)
    assert r.status_code == 200 and "__Host-tinysesam_waflow" in gesetzte_cookies(r), r.text[:120]
    r = c.post("/auth/passkey/register/finish", content=json.dumps({"id": "neu", "response": {}}),
               headers=kopf)
    assert r.status_code == 200 and r.json()["ok"], r.text[:200]
    assert "__Host-tinysesam_waflow" in geloescht(r), f"Flow-Cookie bleibt nach der Anlage: {gesetzte_cookies(r)}"
    ok("Passkey-Anlage: das Flow-Cookie endet ebenso")

# ---------- D3. cookie_secure=False über HTTPS fällt auf (F-04) ----------
import logging  # noqa: E402


class _Fang(logging.Handler):
    def __init__(self):
        super().__init__()
        self.zeilen = []

    def emit(self, record):
        self.zeilen.append(record.getMessage())


def secure_warnungen(cookie_secure, base, headers_=None, n=2):
    fang = _Fang()
    log = logging.getLogger("tinysesam.security")
    log.addHandler(fang)
    try:
        a, _ = baue(cookie_secure=cookie_secure)
        app = FastAPI()
        app.include_router(a.router())
        cl = TestClient(app, base_url=base)
        for _i in range(n):
            cl.get("/auth/login", headers=headers_ or {})
    finally:
        log.removeHandler(fang)
    return [z for z in fang.zeilen if "cookie_secure=False" in z]


assert len(secure_warnungen(False, "http://testserver",
                            {"X-Forwarded-Proto": "https"})) == 1, "TLS-Proxy davor: genau eine Warnung"
assert len(secure_warnungen(False, "https://testserver")) == 1, "direkt HTTPS: genau eine Warnung"
assert secure_warnungen(False, "http://testserver") == [], "lokal ohne TLS ist der erlaubte Fall"
assert secure_warnungen(True, "https://testserver") == [], "mit Secure gibt es nichts zu melden"
ok("cookie_secure=False + HTTPS-Request → eine Warnung je Instanz; lokal über HTTP still")

# ---------- E. Widersprüchliche Config wird beim Bau abgelehnt ----------
# `cookie_secure=False` ist für lokale Aufbauten ohne Zertifikat richtig und bleibt erlaubt.
# Zusammen mit `https_mode='force'` widerspricht es sich: Die App leitet dann jeden Request
# auf HTTPS um und gibt das Session-Cookie trotzdem ohne Secure-Flag heraus.
#
# Geprüft wird nur, was die App über ihr EIGENES Verhalten sagt — nicht, was sie über die
# Außenwelt behauptet. `base_url='https://…' + cookie_secure=False` sieht nach demselben
# Fehler aus, ist aber keiner: `base_url` ist die öffentliche Adresse (SAML/OIDC bauen daraus
# Callbacks), nicht der Transport zwischen Browser und App. Genau diese Kombination brauchen
# test_saml, test_matrix, test_forward_auth und test_sessions_logout.


def baut(**kw) -> bool:
    """True, wenn die Config angenommen wird; False bei ValueError."""
    try:
        baue(**kw)
        return True
    except ValueError:
        return False


assert baut(cookie_secure=False), "cookie_secure=False muss lokal erlaubt bleiben"
assert baut(cookie_secure=True, https_mode="force"), "die saubere Prod-Kombination muss gehen"
assert baut(cookie_secure=False, base_url="https://app.example.com"), \
    "HTTPS-base_url + cookie_secure=False ist KEIN Widerspruch — vier Suiten brauchen das"
ok("erlaubt: cookie_secure=False lokal, cookie_secure=True + https_mode='force' in Prod")

assert not baut(cookie_secure=False, https_mode="force"), \
    "https_mode='force' + cookie_secure=False muss abgelehnt werden"
ok("abgelehnt: die App leitet auf HTTPS um, gibt das Cookie aber ohne Secure heraus")

# Ein Tippfehler in https_mode schaltete den HTTPS-Zwang bisher STILL ab: Ausgewertet wird
# nur `== "force"`, alles andere heißt „kein Redirect". Kein Fehler, kein Hinweis.
assert not baut(https_mode="forse"), "Tippfehler in https_mode muss auffallen"
assert not baut(https_mode=""), "leeres https_mode muss auffallen"
assert baut(https_mode="off") and baut(https_mode="warn")
ok("https_mode wird validiert — ein Tippfehler schaltet den Redirect nicht mehr still ab")


# CSRF aus UND SameSite=None: dann schützt gar nichts mehr (F-03). Einzeln bleibt beides erlaubt.
assert baut(csrf_enabled=False), "csrf_enabled=False allein bleibt erlaubt (SameSite=Lax trägt)"
assert baut(cookie_samesite="none", cookie_secure=True), "SameSite=None mit CSRF bleibt erlaubt"
assert not baut(csrf_enabled=False, cookie_samesite="none", cookie_secure=True), \
    "csrf_enabled=False + cookie_samesite='none' muss abgelehnt werden"
ok("abgelehnt: csrf_enabled=False zusammen mit cookie_samesite='none' (kein CSRF-Schutz übrig)")


print("\ntest_cookies: alle Prüfungen grün")
