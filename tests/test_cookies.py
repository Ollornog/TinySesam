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

* `tinysesam_waflow` (webauthn_.py, ebenfalls httponly). Es zu prüfen hieße `webauthn`
  importieren — dann übersprünge run_all.py die GANZE Suite, sobald das Extra fehlt, und
  die Flags oben wären ungeprüft. Der Preis wäre höher als der Gewinn.
* Der CSRF-Setzer in `admin.py`. Es gibt drei (`manager.render_page`, `manager.issue_csrf`,
  `admin.py`); die ersten beiden prüft diese Suite. Der dritte bräuchte das gemountete
  Admin-Panel — das steht in test_adminmount.py und gehört dorthin, nicht hierher.
"""
import os
import re
import sys
import tempfile

from fastapi import Depends, FastAPI, Response
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
    "tinysesam_session": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"},
    "tinysesam_csrf":    {"httponly": False, "secure": True, "samesite": "lax", "path": "/"},
    "tinysesam_runlock": {"httponly": True, "secure": True, "samesite": "lax", "path": "/"},
}


def baue(**cfg_kw):
    """Frische Instanz mit eigener DB. Gibt (auth, client).

    base_url richtet sich nach cookie_secure: ein Secure-Cookie legt httpx über http://
    gar nicht erst ab (RFC 6265) — der Login-Flow bräche dann am CSRF-Cookie, nicht am
    Prüfgegenstand.
    """
    kw = dict(db_path=tempfile.mktemp(suffix=".db"), rp_name="Test",
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
assert "tinysesam_csrf" in gesetzt, "Login-Seite muss das CSRF-Cookie setzen"
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
ok("CSRF-Cookie: bewusst kein HttpOnly, aber Secure + SameSite=lax + Path")

r = login(c)
assert r.status_code == 303, r.status_code
gesetzt = gesetzte_cookies(r)
assert "tinysesam_session" in gesetzt, "Login muss das Session-Cookie setzen"
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
assert "max-age" in gesetzt["tinysesam_session"], "remember=on muss persistent sein"
ok("Session-Cookie im echten Login: HttpOnly + Secure + SameSite=lax + Path + Max-Age")

assert c.get("/geheim").json() == {"u": "admin"}
ok("Session trägt: /geheim erreichbar (das Cookie ist echt, nicht nur ein Header)")


# ---------- B. Flag-Matrix direkt an set_cookie() ----------
# Ohne Login-Flow: der Cookie-Jar des Clients würde Secure/Domain-Varianten verschlucken.
auth, _ = baue()

resp = Response()
auth.set_cookie(resp, "tok123", remember=True)
sess = gesetzte_cookies(resp)["tinysesam_session"]
assert sess["_wert"] == "tok123" and "max-age" in sess
ok("set_cookie(remember=True) → Max-Age gesetzt (persistent)")

resp = Response()
auth.set_cookie(resp, "tok123", remember=False)
sess = gesetzte_cookies(resp)["tinysesam_session"]
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
assert gesetzte_cookies(resp)["tinysesam_session"].get("samesite") == "strict"
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
assert tok and "tinysesam_csrf" in gesetzt
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
assert "tinysesam_runlock" in gesetzt
verstoesse = headers.pruefe_cookie_flags(gesetzt, ERWARTUNG)
assert not verstoesse, verstoesse
assert "max-age" in gesetzt["tinysesam_runlock"], "Ressourcen-Freischaltung muss ablaufen"
ok("Ressourcen-Cookie: HttpOnly + Secure + SameSite + Max-Age")


# ---------- D. Logout räumt das Cookie ab ----------
auth, c = baue()
login(c)
r = c.get("/auth/logout", follow_redirects=False)
sess = gesetzte_cookies(r).get("tinysesam_session")
assert sess is not None, "Logout muss das Session-Cookie überschreiben, nicht nur die DB-Zeile leeren"
assert sess["_wert"] in ("", '""'), f"Logout muss den Cookie-Wert leeren, ist: {sess['_wert']!r}"
ok("Logout leert das Session-Cookie beim Browser")

print("\ntest_cookies: alle Prüfungen grün")
