"""T-15: Die eingebauten Seiten unter einem Unterpfad (`root_path`) — gemessen an echten Montagen.

Drei Aufbauten, derselbe Rundgang (Login, Registrierung, Anmelde-Link, Reset, Konto, Admin-Panel,
Logout, geschützte Seite):

* **Mount** — `Starlette(routes=[Mount("/sso", app)])`, wie eine Host-App TinySesam einhängt.
* **uvicorn --root-path** — der Proxy schneidet `/sso` ab, uvicorn setzt `root_path="/sso"` und
  baut `scope["path"] = root_path + empfangener Pfad` (uvicorn/protocols/http/h11_impl.py). Genau
  das tut die Hülle `_wie_uvicorn` unten; ein echter Server wäre derselbe Scope mit mehr Warten.
* **Wurzel** — ohne Präfix: Hier darf sich nichts geändert haben.

Gemessen wird die Wirkung, nicht der Quelltext: Jeder wurzel-absolute Verweis einer Seite (href,
action, fetch/J-Aufruf) und jede Umleitung muss mit dem Präfix beginnen, und der Platzhalter
`__TS_P__` darf nirgends ankommen.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.applications import Starlette  # noqa: E402
from starlette.routing import Mount  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.templates import PRAEFIX_PLATZHALTER  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Unterpfad (T-15) — eingebaute Seiten unter root_path")
PW = "Unterpfad-Test-Passwort-1"
HTML = {"accept": "text/html"}
VERWEIS = re.compile(r"""(?:href|action)=['"](/[^'"]*)['"]|(?:fetch|J)\(\s*'(/[^']*)'""")


def _aufbau(praefix: str):
    """TinySesam + geschützte Seite; `praefix` nur für base_url (die Mails)."""
    mails: list = []
    cfg = TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                          csrf_enabled=False, passkey_enabled=False, allow_signup=True,
                          password_reset_enabled=True, magiclink_enabled=True, pin_enabled=True,
                          base_url=f"https://example.com{praefix}", lang="de")
    auth = TinySesam(cfg)
    auth.set_mailer(lambda to, betreff, text, html=None: mails.append(text))
    auth.ensure_admin("chefin", PW)
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/app")
    def _app(user=Depends(auth.require_user)):
        return {"u": user["username"]}
    return auth, app, mails


def _wie_uvicorn(inner, root_path: str):
    """So baut uvicorn den Scope bei `--root-path`: der Pfad bekommt den Präfix vorangestellt."""
    async def hulle(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = dict(scope, root_path=root_path, path=root_path + scope["path"],
                         raw_path=root_path.encode() + scope.get("raw_path", scope["path"].encode()))
        await inner(scope, receive, send)
    return hulle


def _pruefe_seite(was: str, antwort, praefix: str, fehler: list) -> None:
    text = antwort.text
    if PRAEFIX_PLATZHALTER in text:
        fehler.append(f"{was}: Platzhalter sickert durch")
    for a, b in VERWEIS.findall(text):
        ziel = a or b
        if praefix and not ziel.startswith(praefix + "/"):
            fehler.append(f"{was}: {ziel!r}")
        if not praefix and ziel.startswith("/sso"):
            fehler.append(f"{was}: Präfix ohne Montage {ziel!r}")


def _rundgang(name: str, client: TestClient, auth, mails: list, praefix: str, basis: str) -> None:
    """`basis`: wie der Browser die Seiten ruft (Mount: mit /sso; hinter dem Proxy: auch mit /sso
    — der Proxy schneidet ab, der Client sieht den Präfix). `client` spricht die App direkt an."""
    fehler: list = []
    umleitungen: list = []

    def get(pfad, **kw):
        a = client.get(pfad, follow_redirects=False, **kw)
        if a.status_code in (301, 302, 303, 307, 308):
            umleitungen.append((pfad, a.headers.get("location", "")))
        return a

    def post(pfad, **kw):
        a = client.post(pfad, follow_redirects=False, **kw)
        if a.status_code in (301, 302, 303, 307, 308):
            umleitungen.append((pfad, a.headers.get("location", "")))
        return a

    # Nicht angemeldet: geschützte Seite → Login mit next im Präfix.
    geschuetzt = get(f"{basis}/app", headers=HTML)
    r.check(f"{name}: geschützte Seite → Login im Präfix, next = Pfad des Browsers",
            geschuetzt.headers.get("location", "") == f"{praefix}/auth/login?next={praefix}/app",
            geschuetzt.headers.get("location", ""))
    for seite in ("/auth/login", "/auth/register", "/auth/forgot", "/auth/magic/request",
                  f"/auth/login?next={praefix}/app"):
        _pruefe_seite(seite, get(f"{basis}{seite}", headers=HTML), praefix, fehler)
    # Anmelden: zurück auf die geschützte Seite (next), dann Konto und Panel.
    post(f"{basis}/auth/login", data={"username": "chefin", "password": PW, "next": f"{praefix}/app"})
    r.check(f"{name}: nach dem Login zurück auf die geschützte Seite",
            get(f"{basis}/app").json() == {"u": "chefin"})
    for seite in ("/auth/account", "/auth/admin", "/auth/totp/setup"):
        antwort = get(f"{basis}{seite}", headers=HTML)
        _pruefe_seite(seite, antwort, praefix, fehler)
    # Ein Konto mit TOTP: nach dem Passwort folgt der Faktor-Schritt — im Präfix.
    import pyotp
    uid_t = auth.create_user("zweifach", password=PW)
    geheim = auth.totp_begin(uid_t)["secret"]
    import time as _t
    auth.totp_confirm(uid_t, pyotp.TOTP(geheim).at(_t.time() - 30))
    schritt = TestClient(client.app).post(f"{basis}/auth/login", follow_redirects=False,
                                          data={"username": "zweifach", "password": PW, "next": f"{praefix}/app"})
    r.check(f"{name}: der nächste Faktor-Schritt (TOTP) liegt im Präfix",
            schritt.headers.get("location", "").startswith(f"{praefix}/auth/totp?next="),
            schritt.headers.get("location", ""))
    # Ohne next: der Rückfall login_redirect ("/") liegt im Präfix.
    ohne_next = post(f"{basis}/auth/login", data={"username": "chefin", "password": PW})
    r.check(f"{name}: ohne next führt der Login auf login_redirect im Präfix",
            ohne_next.headers.get("location", "") == f"{praefix}/", ohne_next.headers.get("location", ""))
    # Logout → logout_redirect im Präfix.
    raus = post(f"{basis}/auth/logout")
    r.check(f"{name}: Logout führt auf logout_redirect im Präfix",
            raus.headers.get("location", "").startswith(f"{praefix}/auth/login"),
            raus.headers.get("location", ""))
    # Anmelde-Link: Bestätigungsseite (Formularziel) und Einlösen.
    tok = auth.create_magic_token("login", user_id=auth.store.get_user_by_name("chefin")["id"])
    _pruefe_seite("magic-confirm", get(f"{basis}/auth/magic/{tok}", headers=HTML), praefix, fehler)
    eingeloest = post(f"{basis}/auth/magic/{tok}")
    r.check(f"{name}: Anmelde-Link eingelöst → Ziel im Präfix",
            eingeloest.headers.get("location", "").startswith(f"{praefix}/"),
            eingeloest.headers.get("location", ""))
    post(f"{basis}/auth/logout")
    # Reset: der Mail-Link trägt den Präfix genau einmal (base_url), die Seite ihre Ziele.
    mails.clear()
    post(f"{basis}/auth/forgot", data={"email": ""}, headers=HTML)
    auth.store.set_email(auth.store.get_user_by_name("chefin")["id"], "chefin@example.com", verified=True)
    post(f"{basis}/auth/forgot", data={"email": "chefin@example.com"}, headers=HTML)
    links = [w for w in " ".join(mails).split() if w.startswith("http")]
    r.check(f"{name}: der Reset-Link trägt den Präfix genau einmal",
            len(links) == 1 and links[0].startswith(f"https://example.com{praefix}/auth/reset?")
            and links[0].count("/sso") == (1 if praefix else 0), str(links))
    if links:
        pfad_reset = links[0].split("example.com", 1)[1]
        pfad_reset = pfad_reset[len(praefix):] if praefix else pfad_reset
        _pruefe_seite("reset", get(f"{basis}{pfad_reset}", headers=HTML), praefix, fehler)
    # Registrierung: nach dem Anlegen im Präfix.
    reg = post(f"{basis}/auth/register", data={"username": "neu", "password": PW + "x",
                                                "email": "neu@example.com"})
    r.check(f"{name}: Registrierung führt in den Präfix",
            reg.headers.get("location", "").startswith(f"{praefix}/"), reg.headers.get("location", ""))

    ausreisser = [(p, z) for p, z in umleitungen
                  if z.startswith("/") and (not z.startswith(praefix + "/") if praefix else z.startswith("/sso"))]
    r.check(f"{name}: jede Umleitung bleibt im Präfix ({len(umleitungen)} gemessen)",
            umleitungen and not ausreisser, str(ausreisser[:5]))
    r.check(f"{name}: jeder Verweis der Seiten bleibt im Präfix, kein Platzhalter",
            not fehler, "; ".join(fehler[:6]))


# ── Mount ────────────────────────────────────────────────────────────────────────────────
auth_m, app_m, mails_m = _aufbau("/sso")
aussen = Starlette(routes=[Mount("/sso", app=app_m)])
_rundgang("Mount /sso", TestClient(aussen), auth_m, mails_m, "/sso", "/sso")

# ── uvicorn --root-path hinter einem Proxy, der /sso abschneidet ──────────────────────────
auth_u, app_u, mails_u = _aufbau("/sso")
_rundgang("uvicorn --root-path /sso", TestClient(_wie_uvicorn(app_u, "/sso")), auth_u, mails_u, "/sso", "")

# ── Wurzel: nichts verändert ─────────────────────────────────────────────────────────────
auth_w, app_w, mails_w = _aufbau("")
_rundgang("Wurzel", TestClient(app_w), auth_w, mails_w, "", "")

# ── Ein root_path in unerwarteter Form wird nicht in Seiten getragen ──────────────────────
# Ohne base_url (nur Passwort) zählt der root_path der Anfrage — hier mit Markup darin.
cfg_x = TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                        csrf_enabled=False, passkey_enabled=False, lang="de")
auth_x = TinySesam(cfg_x)
app_x = FastAPI()
app_x.include_router(auth_x.router())
boese = TestClient(_wie_uvicorn(app_x, "/sso'><script>x</script>"))
seite_x = boese.get("/auth/login", headers=HTML)
r.check("ein root_path mit Markup landet nicht in der Seite (Form geprüft, dann leer)",
        seite_x.status_code == 200 and "<form" in seite_x.text
        and "x</script>" not in seite_x.text and "sso'>" not in seite_x.text
        and PRAEFIX_PLATZHALTER not in seite_x.text,
        f"HTTP {seite_x.status_code} {seite_x.text[:200]}")
ok_x = TestClient(_wie_uvicorn(app_x, "/sso")).get("/auth/login", headers=HTML).text
r.check("… ein gültiger root_path ohne base_url trägt die Seite", "action='/sso/auth/login'" in ok_x)

# ── Gegenprüfung T-15 ────────────────────────────────────────────────────────────────────
# G1: Forward-Auth — die Login-URL im Header trägt den Präfix (mit base_url, auch für einen
#     mitvertrauten Ziel-Host, der die Login-Seite an sich zieht).
cfg_f = TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                        csrf_enabled=False, passkey_enabled=False, forward_auth_enabled=True,
                        base_url="https://example.com/sso", trusted_redirect_hosts=["app.example.com"])
auth_f = TinySesam(cfg_f)
app_f = FastAPI()
app_f.include_router(auth_f.router())
c_f = TestClient(Starlette(routes=[Mount("/sso", app=app_f)]))
loc_f = c_f.get("/sso/auth/forward", headers={"x-forwarded-host": "example.com", "x-forwarded-proto": "https",
                                              "x-forwarded-uri": "/wiki/seite"}).headers.get("x-tinysesam-location", "")
loc_f2 = c_f.get("/sso/auth/forward", headers={"x-forwarded-host": "app.example.com", "x-forwarded-proto": "https",
                                               "x-forwarded-uri": "/wiki"}).headers.get("x-tinysesam-location", "")
r.check("G1: Forward-Auth — Login-URL im Präfix, auch auf dem mitvertrauten Ziel-Host",
        loc_f.startswith("https://example.com/sso/auth/login?next=")
        and loc_f2.startswith("https://app.example.com/sso/auth/login?next="), f"{loc_f} | {loc_f2}")

# G2: Guard einer Host-App AUSSERHALB der TinySesam-Montage (Host an der Wurzel, TinySesam unter /sso).
auth_g, app_g, _ = _aufbau("/sso")
host = FastAPI()
host.mount("/sso", app_g)


@host.get("/dashboard")
def _dash(user=Depends(auth_g.require_user)):
    return {"u": user["username"]}


c_g = TestClient(host)
loc_g = c_g.get("/dashboard", headers=HTML, follow_redirects=False).headers.get("location", "")
form_g = VERWEIS.findall(c_g.get("/sso/auth/login", headers=HTML).text)
nach_g = c_g.post("/sso/auth/login", data={"username": "chefin", "password": PW, "next": "/dashboard"},
                  follow_redirects=False).headers.get("location", "")
r.check("G2: Guard der Host-App → Login im Präfix, next = Pfad der Host-App, zurück dorthin",
        loc_g == "/sso/auth/login?next=/dashboard" and ("/sso/auth/login", "") in form_g
        and nach_g == "/dashboard" and c_g.get("/dashboard").json() == {"u": "chefin"},
        f"{loc_g} | {nach_g}")

# G3: Ein Platzhalter in Daten wird nicht zum Ziel; eigene Templates bleiben byte-gleich.
auth_p, app_p, _ = _aufbau("")
c_p = TestClient(app_p)
r.check("G3: safe_next weist ein Ziel mit dem Platzhalter ab",
        auth_p.safe_next(f"/{PRAEFIX_PLATZHALTER}/evil.example/x") == "/")
auth_p.set_template("login", lambda a, ctx: f"<a href='{ctx.get('next', '')}'>zurück</a> {PRAEFIX_PLATZHALTER}")
eigen = c_p.get(f"/auth/login?next=/{PRAEFIX_PLATZHALTER}/evil.example/x", headers=HTML).text
r.check("… und die Ausgabe eines eigenen Templates bleibt byte-gleich (Platzhalter nicht ersetzt)",
        eigen == f"<a href='/'>zurück</a> {PRAEFIX_PLATZHALTER}", eigen)

# G4: Fehlerseite und Abmelde-Rückfrage bleiben im Präfix; render_panel ist vollständig.
auth_e, app_e, _ = _aufbau("/sso")
auth_e.install_error_pages(app_e)
c_e = TestClient(Starlette(routes=[Mount("/sso", app=app_e)]))
fehler_e: list = []
_pruefe_seite("404", c_e.get("/sso/gibt-es-nicht", headers=HTML), "/sso", fehler_e)
_pruefe_seite("logout-rückfrage", c_e.get("/sso/auth/logout", headers={**HTML, "sec-fetch-site": "cross-site"}),
              "/sso", fehler_e)
from tinysesam.admin import render_panel  # noqa: E402
r.check("G4: Fehlerseite und Abmelde-Rückfrage im Präfix; render_panel ohne Platzhalter",
        not fehler_e and PRAEFIX_PLATZHALTER not in render_panel(auth_e, "/auth/admin")
        and 'href="/sso/auth/logout"' in render_panel(auth_e, "/sso/auth/admin", praefix="/sso"),
        "; ".join(fehler_e))

# G5: Wer den Präfix noch von Hand in login_path trägt, bekommt eine Warnung (sonst /sso/sso/…).
from tinysesam import konfigpruefung as _kp  # noqa: E402
_warn = " ".join(_kp.pruefe(TinySesamConfig(db_path=":memory:", base_url="https://example.com/sso",
                                           login_path="/sso/auth/login"))[1])
r.check("G5: login_path mit dem Präfix der base_url → Warnung", "login_path='/sso/auth/login'" in _warn, _warn[:200])

# (Mutationsproben: `render_page` ersetzt den Platzhalter nicht → „kein Platzhalter" rot;
#  `_praefix` ohne base_url-Pfad → G2 rot; forward_login_url wieder mit base+login_path → G1 rot;
#  Ersatz auch bei eigenen Templates → G3 rot; safe_next ohne Platzhalter-Prüfung → G3 rot;
#  `pfad` gibt den Pfad unverändert zurück → Umleitungen rot; `_praefix` ohne Formprüfung →
#  letzte Prüfung rot; `safe_next` ohne request → „ohne next" rot.)

sys.exit(r.done())
