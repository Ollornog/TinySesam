"""T-15: The built-in pages under a subpath (`root_path`) — measured on real mounts.

Three setups, the same walkthrough (login, registration, sign-in link, reset, account, admin panel,
logout, protected page):

* **Mount** — `Starlette(routes=[Mount("/sso", app)])`, the way a host app mounts TinySesam.
* **uvicorn --root-path** — the proxy strips `/sso`, uvicorn sets `root_path="/sso"` and
  builds `scope["path"] = root_path + received path` (uvicorn/protocols/http/h11_impl.py). Exactly
  that is what the wrapper `_wie_uvicorn` below does; a real server would be the same scope with more waiting.
* **Root** — without prefix: nothing may have changed here.

The effect is measured, not the source text: every root-absolute reference of a page (href,
action, fetch/J call) and every redirect must begin with the prefix, and the placeholder
`__TS_P__` must arrive nowhere.
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
    """TinySesam + protected page; `praefix` only for base_url (the mails)."""
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
    """This is how uvicorn builds the scope with `--root-path`: the path gets the prefix prepended."""
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
    """`basis`: how the browser calls the pages (mount: with /sso; behind the proxy: also with /sso
    — the proxy strips it, the client sees the prefix). `client` talks to the app directly."""
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

    # Not signed in: protected page → login with next in the prefix.
    geschuetzt = get(f"{basis}/app", headers=HTML)
    r.check(f"{name}: protected page → login in the prefix, next = path of the browser",
            geschuetzt.headers.get("location", "") == f"{praefix}/auth/login?next={praefix}/app",
            geschuetzt.headers.get("location", ""))
    for seite in ("/auth/login", "/auth/register", "/auth/forgot", "/auth/magic/request",
                  f"/auth/login?next={praefix}/app"):
        _pruefe_seite(seite, get(f"{basis}{seite}", headers=HTML), praefix, fehler)
    # Sign in: back to the protected page (next), then account and panel.
    post(f"{basis}/auth/login", data={"username": "chefin", "password": PW, "next": f"{praefix}/app"})
    r.check(f"{name}: after the login back to the protected page",
            get(f"{basis}/app").json() == {"u": "chefin"})
    for seite in ("/auth/account", "/auth/admin", "/auth/totp/setup"):
        antwort = get(f"{basis}{seite}", headers=HTML)
        _pruefe_seite(seite, antwort, praefix, fehler)
    # An account with TOTP: after the password the factor step follows — in the prefix.
    import pyotp
    uid_t = auth.create_user("zweifach", password=PW)
    geheim = auth.totp_begin(uid_t)["secret"]
    import time as _t
    auth.totp_confirm(uid_t, pyotp.TOTP(geheim).at(_t.time() - 30))
    schritt = TestClient(client.app).post(f"{basis}/auth/login", follow_redirects=False,
                                          data={"username": "zweifach", "password": PW, "next": f"{praefix}/app"})
    r.check(f"{name}: the next factor step (TOTP) lies in the prefix",
            schritt.headers.get("location", "").startswith(f"{praefix}/auth/totp?next="),
            schritt.headers.get("location", ""))
    # Without next: the fallback login_redirect ("/") lies in the prefix.
    ohne_next = post(f"{basis}/auth/login", data={"username": "chefin", "password": PW})
    r.check(f"{name}: without next the login leads to login_redirect in the prefix",
            ohne_next.headers.get("location", "") == f"{praefix}/", ohne_next.headers.get("location", ""))
    # Logout → logout_redirect in the prefix.
    raus = post(f"{basis}/auth/logout")
    r.check(f"{name}: logout leads to logout_redirect in the prefix",
            raus.headers.get("location", "").startswith(f"{praefix}/auth/login"),
            raus.headers.get("location", ""))
    # Sign-in link: confirmation page (form target) and redeeming.
    tok = auth.create_magic_token("login", user_id=auth.store.get_user_by_name("chefin")["id"])
    _pruefe_seite("magic-confirm", get(f"{basis}/auth/magic/{tok}", headers=HTML), praefix, fehler)
    eingeloest = post(f"{basis}/auth/magic/{tok}")
    r.check(f"{name}: sign-in link redeemed → target in the prefix",
            eingeloest.headers.get("location", "").startswith(f"{praefix}/"),
            eingeloest.headers.get("location", ""))
    post(f"{basis}/auth/logout")
    # Reset: the mail link carries the prefix exactly once (base_url), the page its targets.
    mails.clear()
    post(f"{basis}/auth/forgot", data={"email": ""}, headers=HTML)
    auth.store.set_email(auth.store.get_user_by_name("chefin")["id"], "chefin@example.com", verified=True)
    post(f"{basis}/auth/forgot", data={"email": "chefin@example.com"}, headers=HTML)
    links = [w for w in " ".join(mails).split() if w.startswith("http")]
    r.check(f"{name}: the reset link carries the prefix exactly once",
            len(links) == 1 and links[0].startswith(f"https://example.com{praefix}/auth/reset?")
            and links[0].count("/sso") == (1 if praefix else 0), str(links))
    if links:
        pfad_reset = links[0].split("example.com", 1)[1]
        pfad_reset = pfad_reset[len(praefix):] if praefix else pfad_reset
        _pruefe_seite("reset", get(f"{basis}{pfad_reset}", headers=HTML), praefix, fehler)
    # Registration: after creation in the prefix.
    reg = post(f"{basis}/auth/register", data={"username": "neu", "password": PW + "x",
                                                "email": "neu@example.com"})
    r.check(f"{name}: registration leads into the prefix",
            reg.headers.get("location", "").startswith(f"{praefix}/"), reg.headers.get("location", ""))

    ausreisser = [(p, z) for p, z in umleitungen
                  if z.startswith("/") and (not z.startswith(praefix + "/") if praefix else z.startswith("/sso"))]
    r.check(f"{name}: every redirect stays in the prefix ({len(umleitungen)} measured)",
            umleitungen and not ausreisser, str(ausreisser[:5]))
    r.check(f"{name}: every reference of the pages stays in the prefix, no placeholder",
            not fehler, "; ".join(fehler[:6]))


# ── Mount ────────────────────────────────────────────────────────────────────────────────
auth_m, app_m, mails_m = _aufbau("/sso")
aussen = Starlette(routes=[Mount("/sso", app=app_m)])
_rundgang("Mount /sso", TestClient(aussen), auth_m, mails_m, "/sso", "/sso")

# ── uvicorn --root-path behind a proxy that strips /sso ───────────────────────────────────
auth_u, app_u, mails_u = _aufbau("/sso")
_rundgang("uvicorn --root-path /sso", TestClient(_wie_uvicorn(app_u, "/sso")), auth_u, mails_u, "/sso", "")

# ── Root: nothing changed ─────────────────────────────────────────────────────────────────
auth_w, app_w, mails_w = _aufbau("")
_rundgang("Wurzel", TestClient(app_w), auth_w, mails_w, "", "")

# ── A root_path in an unexpected form is not carried into pages ───────────────────────────
# Without base_url (password only) the root_path of the request counts — here with markup in it.
cfg_x = TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                        csrf_enabled=False, passkey_enabled=False, lang="de")
auth_x = TinySesam(cfg_x)
app_x = FastAPI()
app_x.include_router(auth_x.router())
boese = TestClient(_wie_uvicorn(app_x, "/sso'><script>x</script>"))
seite_x = boese.get("/auth/login", headers=HTML)
r.check("a root_path with markup does not end up in the page (form checked, then empty)",
        seite_x.status_code == 200 and "<form" in seite_x.text
        and "x</script>" not in seite_x.text and "sso'>" not in seite_x.text
        and PRAEFIX_PLATZHALTER not in seite_x.text,
        f"HTTP {seite_x.status_code} {seite_x.text[:200]}")
ok_x = TestClient(_wie_uvicorn(app_x, "/sso")).get("/auth/login", headers=HTML).text
r.check("… a valid root_path without base_url is carried by the page", "action='/sso/auth/login'" in ok_x)

# ── Counter-check T-15 ────────────────────────────────────────────────────────────────────
# G1: forward auth — the login URL in the header carries the prefix (with base_url, also for a
#     co-trusted target host that pulls the login page to itself).
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
r.check("G1: forward auth — login URL in the prefix, also on the co-trusted target host",
        loc_f.startswith("https://example.com/sso/auth/login?next=")
        and loc_f2.startswith("https://app.example.com/sso/auth/login?next="), f"{loc_f} | {loc_f2}")

# G2: guard of a host app OUTSIDE the TinySesam mount (host at the root, TinySesam under /sso).
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
r.check("G2: guard of the host app → login in the prefix, next = path of the host app, back there",
        loc_g == "/sso/auth/login?next=/dashboard" and ("/sso/auth/login", "") in form_g
        and nach_g == "/dashboard" and c_g.get("/dashboard").json() == {"u": "chefin"},
        f"{loc_g} | {nach_g}")

# G3: a placeholder in data does not become a target; own templates stay byte-identical.
auth_p, app_p, _ = _aufbau("")
c_p = TestClient(app_p)
r.check("G3: safe_next rejects a target with the placeholder",
        auth_p.safe_next(f"/{PRAEFIX_PLATZHALTER}/evil.example/x") == "/")
auth_p.set_template("login", lambda a, ctx: f"<a href='{ctx.get('next', '')}'>zurück</a> {PRAEFIX_PLATZHALTER}")
eigen = c_p.get(f"/auth/login?next=/{PRAEFIX_PLATZHALTER}/evil.example/x", headers=HTML).text
r.check("… and the output of an own template stays byte-identical (placeholder not replaced)",
        eigen == f"<a href='/'>zurück</a> {PRAEFIX_PLATZHALTER}", eigen)

# G4: error page and sign-out confirmation stay in the prefix; render_panel is complete.
auth_e, app_e, _ = _aufbau("/sso")
auth_e.install_error_pages(app_e)
c_e = TestClient(Starlette(routes=[Mount("/sso", app=app_e)]))
fehler_e: list = []
_pruefe_seite("404", c_e.get("/sso/gibt-es-nicht", headers=HTML), "/sso", fehler_e)
_pruefe_seite("logout-rückfrage", c_e.get("/sso/auth/logout", headers={**HTML, "sec-fetch-site": "cross-site"}),
              "/sso", fehler_e)
from tinysesam.admin import render_panel  # noqa: E402
r.check("G4: error page and sign-out confirmation in the prefix; render_panel without placeholder",
        not fehler_e and PRAEFIX_PLATZHALTER not in render_panel(auth_e, "/auth/admin")
        and 'href="/sso/auth/logout"' in render_panel(auth_e, "/sso/auth/admin", praefix="/sso"),
        "; ".join(fehler_e))

# G5: whoever still carries the prefix by hand in login_path gets a warning (otherwise /sso/sso/…).
from tinysesam import konfigpruefung as _kp  # noqa: E402
_warn = " ".join(_kp.pruefe(TinySesamConfig(db_path=":memory:", base_url="https://example.com/sso",
                                           login_path="/sso/auth/login"))[1])
r.check("G5: login_path with the prefix of base_url → warning", "login_path='/sso/auth/login'" in _warn, _warn[:200])

# (Mutation probes: `render_page` does not replace the placeholder → “no placeholder” red;
#  `_praefix` without base_url path → G2 red; forward_login_url again with base+login_path → G1 red;
#  replacement also for own templates → G3 red; safe_next without placeholder check → G3 red;
#  `browser_path` returns the path unchanged → redirects red; `_praefix` without form check →
#  last check red; `safe_next` without request → “without next” red.)

sys.exit(r.done())
