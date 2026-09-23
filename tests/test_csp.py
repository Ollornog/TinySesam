"""CSP: nonce-basierte Content-Security-Policy für die eingebauten Seiten.

Beweist die Zusage der Bibliothek: jede eingebaute Seite (Login/Account/TOTP/Fehler)
läuft unter einer strengen, nonce-basierten CSP — kein 'unsafe-inline'. Der zugehörige
Browser-Beweis (Chrome blockt bei falschem Nonce) steht in test_browser.py.
"""
import re
import os
import tempfile
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


_TAG = re.compile(r'<(script|style)\b')


def _cfg(**kw):
    return TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), csrf_enabled=False,
                           cookie_secure=False, pin_enabled=True, apikey_enabled=True, **kw)


def _pages(auth):
    return {
        "login": auth.render_page("login", request=None, next="/"),
        "account": auth.render_page("account", request=None,
                                    user={"username": "u", "display_name": "U", "id": 1},
                                    methods=["password", "pin", "passkey"]),
        "totp": auth.render_page("totp", request=None, next="/"),
        "error": auth.render_page("error", request=None, code=404, message="x"),
    }


def _nonce(resp):
    m = re.search(r"'nonce-([\w-]+)'", resp.headers.get("content-security-policy", ""))
    return m.group(1) if m else None


# 1) Default 'strict': Header da, jedes <script>/<style> genonced, kein Inline-Handler/style=
auth = TinySesam(_cfg())
for name, resp in _pages(auth).items():
    csp = resp.headers.get("content-security-policy", "")
    assert csp.startswith("default-src 'self'"), f"{name}: keine strenge CSP: {csp!r}"
    assert "'unsafe-inline'" not in csp, f"{name}: CSP enthält unsafe-inline"
    n = _nonce(resp)
    assert n, f"{name}: kein Nonce in der CSP"
    body = resp.body.decode()
    tags = len(_TAG.findall(body))
    nonced = len(re.findall(rf'<(?:script|style) nonce="{re.escape(n)}"', body))
    assert tags and tags == nonced, f"{name}: {nonced}/{tags} script/style genonced"
    assert not re.search(r'\son(click|submit)=', body), f"{name}: Inline-Handler geblieben"
    assert not re.search(r'\sstyle=', body), f"{name}: style=-Attribut geblieben"
ok("strict: Header + Nonce auf jedem <script>/<style>, keine Inline-Handler/style=")

# 2) Pro Antwort ein frischer Nonce
n1, n2 = _nonce(auth.render_page("login", request=None)), _nonce(auth.render_page("login", request=None))
assert n1 and n2 and n1 != n2, "Nonce nicht pro Antwort frisch"
ok("Nonce pro Antwort frisch")

# 3) csp='off' → kein Header (z.B. wenn ein Proxy die CSP zentral setzt)
assert not TinySesam(_cfg(csp="off")).render_page("login", request=None) \
    .headers.get("content-security-policy")
ok("csp='off' → kein Header")

# 4) Eigene Policy: {nonce} wird ersetzt, der Rest 1:1
cust = TinySesam(_cfg(csp="default-src 'self'; script-src 'nonce-{nonce}' https://cdn.example"))
csp = cust.render_page("login", request=None).headers["content-security-policy"]
assert "{nonce}" not in csp and csp.split().count("https://cdn.example") == 1 and "nonce-" in csp, csp
ok("eigene Policy: {nonce} ersetzt, Rest 1:1")

# 5) Ungültige csp (kein String) → klare Ablehnung beim Bau
try:
    TinySesam(_cfg(csp=123))
    assert False, "csp=123 haette scheitern muessen"
except ValueError:
    ok("csp muss ein String sein (Bau lehnt ab)")

# 6) Echter HTTP-Pfad: der Header steht auf der GET /auth/login-Antwort
app = FastAPI()
app.include_router(auth.router())
r = TestClient(app).get("/auth/login")
assert r.headers.get("content-security-policy", "").startswith("default-src 'self'")
ok("HTTP GET /auth/login trägt den CSP-Header")

# 7) B3-2: Ein Tippfehler in `csp` war eine „eigene Policy" ohne Direktive — der Browser verwarf
#    den Header, die Seiten liefen ohne CSP, niemand merkte es. Jetzt scheitert der Aufbau.
from tinysesam.errors import ConfigError  # noqa: E402
for falsch in ("Strict", "stirct", "OFF", "default-src 'self'; scirpt-src 'none'", ";"):
    try:
        TinySesam(_cfg(csp=falsch))
        assert False, f"csp={falsch!r} haette scheitern muessen"
    except ConfigError as e:
        assert "csp=" in str(e), str(e)
for gut in ("strict", "off", "", "default-src 'self'; script-src 'nonce-{nonce}'",
            "Default-Src 'self'; upgrade-insecure-requests"):
    TinySesam(_cfg(csp=gut))
ok("csp: Tippfehler und unbekannte Direktiven scheitern beim Aufbau, echte Policies nicht")
# … und auch nach dem Aufbau: `pruefen()` meldet einen nachträglich gesetzten Tippfehler.
_nach = TinySesam(_cfg())
_nach.cfg.csp = "stict"
assert any("csp=" in b for b in _nach.cfg.pruefen()), _nach.cfg.pruefen()
ok("csp: pruefen() meldet den nachträglichen Tippfehler")


# 8) R8-5, R4-08, R5-2: Härtungskopfzeilen auf JEDER TinySesam-Antwort, nicht nur der Seite —
#    und auf keiner Route des Gastgebers.
from fastapi.responses import PlainTextResponse  # noqa: E402


def _haerte_app(**kw):
    a = TinySesam(_cfg(admin_enabled=True, password_reset_enabled=True, smtp_host="smtp.example",
                       base_url="https://auth.example", **kw))
    ap = FastAPI()
    ap.include_router(a.router())
    a.install_error_pages(ap)

    @ap.get("/gast")
    def gast():
        return PlainTextResponse("x", headers={"Vary": "Accept-Encoding"})
    return a, ap


_a8, _app8 = _haerte_app()
_c8 = TestClient(_app8)
_KOPF = {"x-content-type-options": "nosniff", "referrer-policy": "same-origin",
         "cache-control": "no-store"}
# `/auth/admin` ohne Sitzung: Der Wächter WIRFT — die Antwort baut der Exception-Handler,
# an der Routen-Klasse vorbei. Mit und ohne install_error_pages.
_app8b = FastAPI()
_app8b.include_router(_a8.router())
for cl, weg, erwartet in ((_c8, "/auth/login", 200), (_c8, "/auth/me", 401),
                          (_c8, "/auth/reset?token=geheim", 400), (_c8, "/auth/admin", 401),
                          (_c8, "/auth/admin/api/users", 401),
                          (TestClient(_app8b), "/auth/admin/api/users", 401)):
    rr = cl.get(weg, follow_redirects=False)
    assert rr.status_code == erwartet, (weg, rr.status_code)
    for k, v in _KOPF.items():
        assert rr.headers.get(k) == v, (weg, k, rr.headers.get(k))
    assert "Cookie" in rr.headers.get("vary", ""), (weg, rr.headers.get("vary"))
ok("nosniff, Referrer-Policy, no-store, Vary: Cookie auf Seite, JSON, Token-Seite, geworfenem 401")
_g = _c8.get("/gast")
assert "x-content-type-options" not in _g.headers and "cache-control" not in _g.headers, _g.headers
assert _g.headers.get("vary") == "Accept-Encoding", _g.headers.get("vary")
ok("Routen des Gastgebers bleiben unberührt")
# Die gebrandete Fehlerseite läuft an keiner TinySesam-Route vorbei — trägt sie trotzdem.
_f = _c8.get("/gibtsnicht", headers={"accept": "text/html"})
assert _f.status_code == 404 and _f.headers.get("x-content-type-options") == "nosniff", _f.headers
ok("auch die Fehlerseite aus install_error_pages trägt die Kopfzeilen")
# Ein vorhandenes Vary wird ergänzt, nicht ersetzt.
_v = _a8._kopfzeilen(PlainTextResponse("x", headers={"Vary": "Accept-Encoding"}))
assert _v.headers["vary"] == "Accept-Encoding, Cookie", _v.headers["vary"]
_v2 = _a8._kopfzeilen(PlainTextResponse("x", headers={"Vary": "cookie"}))
assert _v2.headers["vary"] == "cookie", _v2.headers["vary"]
ok("Vary: vorhandene Werte bleiben, Cookie kommt genau einmal dazu")
# X-Frame-Options nur bei 'strict' — eine eigene Policy oder 'off' entscheidet selbst.
assert _c8.get("/auth/login").headers.get("x-frame-options") == "SAMEORIGIN"
_, _app_off = _haerte_app(csp="off")
_ro = TestClient(_app_off).get("/auth/login")
assert "x-frame-options" not in _ro.headers and _ro.headers.get("x-content-type-options") == "nosniff"
ok("X-Frame-Options nur bei csp='strict'; die übrigen Kopfzeilen gelten auch bei 'off'")


# 9) R8-1: Das Admin-Panel läuft unter derselben CSP wie jede andere Seite — ohne Inline-
#    Handler und ohne style=, sonst bräche die Policy seine eigenen Knöpfe.
_a8.ensure_admin("chef", "geheim-12345")
_c8.post("/auth/login", data={"username": "chef", "password": "geheim-12345", "next": "/"},
         follow_redirects=False)
_p = _c8.get("/auth/admin")
assert _p.status_code == 200, _p.status_code
_pcsp = _p.headers.get("content-security-policy", "")
assert _pcsp.startswith("default-src 'self'") and "'unsafe-inline'" not in _pcsp, _pcsp
assert _p.headers.get("x-frame-options") == "SAMEORIGIN", _p.headers
_pn = _nonce(_p)
_pb = _p.text
_ptags = len(_TAG.findall(_pb))
assert _ptags and _ptags == len(re.findall(rf'<(?:script|style) nonce="{re.escape(_pn)}"', _pb)), \
    "Panel: nicht jedes <script>/<style> trägt den Nonce"
assert not re.search(r"\son[a-z]+=", _pb), re.findall(r"\son[a-z]+=[^>]{0,40}", _pb)[:3]
assert not re.search(r"\sstyle=", _pb), re.findall(r"\sstyle=[^>]{0,40}", _pb)[:3]
ok("Admin-Panel: CSP mit Nonce, X-Frame-Options, keine Inline-Handler/style=")
_api = _c8.get("/auth/admin/api/users")
assert _api.status_code == 200 and _api.headers.get("cache-control") == "no-store", _api.headers
assert _api.headers.get("x-content-type-options") == "nosniff"
ok("Admin-JSON-API trägt nosniff und no-store")
# Auch an einem frei gewählten Präfix über `admin_router()`.
_app9 = FastAPI()
_app9.include_router(_a8.router())
_app9.include_router(_a8.admin_router(), prefix="/verwaltung")
_c9 = TestClient(_app9)
_c9.post("/auth/login", data={"username": "chef", "password": "geheim-12345", "next": "/"},
         follow_redirects=False)
_p9 = _c9.get("/verwaltung")
assert _p9.status_code == 200 and "nonce-" in _p9.headers.get("content-security-policy", ""), _p9.headers
assert _p9.headers.get("cache-control") == "no-store"
ok("admin_router() an eigenem Präfix: dieselbe CSP und dieselben Kopfzeilen")

print("\ntest_csp: alle Checks grün")
