"""Showcase — Referenz-Frontend für TinySesam, im Design der Projekt-Website.

    pip install -e '.[all]'
    uvicorn examples.showcase:app --reload
    # → http://127.0.0.1:8000

Alles hängt an je einer Quelle:
  * **Farben** — `docs/theme.css`. Die Website lädt sie per `<link>`, die App reicht sie als
    `brand_css` in die eingebauten Seiten weiter.
  * **Navigation** — `web/site.py` (`nav_top`/`nav_sub`). Website und Demo bauen damit dieselben
    zwei Leisten, nur mit eigenem Inhalt.
  * **Texte** — `TEXTS` unten, zweisprachig. Die Sprache kommt aus `?lang=` bzw. dem Cookie und
    gilt für die Demo-Seiten UND die eingebauten TinySesam-Seiten (`cfg.lang`).
  * **Panels** — die Vorschauen rendern die echten Bausteine (`auth.render_page`, `render_panel`).

Der **Demo-Modus** (`demo_mode=True`) legt die Konten `demo` und `demoadmin` an und zeigt die
Zugangsdaten auf der Login-Seite — samt Warnung, dass er produktiv aus gehört.
"""
import os
import sys
from contextvars import ContextVar
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # damit `web` gefunden wird

from fastapi import FastAPI, Depends, Request, HTTPException            # noqa: E402
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse  # noqa: E402
from starlette.datastructures import MutableHeaders                     # noqa: E402

from tinysesam import TinySesam, __version__                            # noqa: E402

from web.demo import (DEMO_CSS, FIT_JS, PANEL_T, brand_css,             # noqa: E402
                      demo_body, demo_config, mock_api, render_previews)
from web.flows import CSS as FLOW_CSS, render as flow_html              # noqa: E402
from web.site import (INDEX_CSS, LABELS, LEGAL_CSS, T as SITE_T,         # noqa: E402
                      flows_body, hero, index_body, legal_body)
from web.ui import (Ctx, LANG_COOKIE, LANGS as UI_LANGS, Nav, UI_CSS,   # noqa: E402
                    UI_JS, document, footer, header, shell)

REPO = "https://github.com/Ollornog/TinySesam"
DOCS = Path(__file__).resolve().parent.parent / "docs"
ICON_URL = "/wizard.png"

THEME = (DOCS / "theme.css").read_text(encoding="utf-8")

BRAND = brand_css(THEME)

# Dieselbe Config, die `web.demo.build()` für die statische Fassung benutzt — sonst zeigt die
# Website andere Anmeldemethoden als die laufende Demo. Nur was die Live-App zusätzlich braucht,
# steht hier: eine echte Datei-DB und der Demo-Modus mit seinen Beispielkonten.
auth = TinySesam(demo_config(
    db_path=os.environ.get("TINYSESAM_SHOWCASE_DB", "/tmp/tinysesam-showcase.db"),
    brand=BRAND,
    icon=ICON_URL,
    lang="en",
    demo_mode=True,                  # legt `demo` + `demoadmin` an und zeigt die Zugangsdaten
    demo_pin="1234",
))
auth.set_resource_secret("gaeste", "2468", kind="pin", label="Gäste-Bereich")

# Die eingebauten Seiten (Login, Konto, Admin, Fehlerseiten) bekommen denselben Rumpf wie der Rest.
auth.cfg.brand_header = lambda _a: shell_header(_a)
auth.cfg.brand_footer = lambda _a: shell_footer(_a)
auth.cfg.brand_head = UI_JS       # Theme-Pille + „Aufklapper schließen" auch dort

app = FastAPI()
app.include_router(auth.router())
auth.install_error_pages(app)


# ---------------------------------------------------------------- Sprache
def lang_of(request: Request) -> str:
    # Dieselbe Reihenfolge wie auf der Website: `?lang=` vor Cookie vor Projektsprache (Englisch).
    # Die Browsersprache zählt bewusst nicht.
    lang = request.query_params.get("lang") or request.cookies.get(LANG_COOKIE) or UI_LANGS[0]
    return lang if lang in UI_LANGS else UI_LANGS[0]


# Der Rumpf der eingebauten Seiten hängt vom Request ab (Sprache, Login-Status, Pfad).
# ContextVar statt globaler Variable: bei nebenläufigen Requests bleibt jeder bei seinem Wert.
_ctx: ContextVar[Ctx] = ContextVar("ctx")


def nav_of(lang: str) -> Nav:
    """Der Rumpf dieser App — einmal deklariert, überall benutzt."""
    t = TEXTS[lang]
    return Nav(brand_href="/", icon_url=ICON_URL, repo=REPO, css_href="/theme.css",
               flows_href="/demo/flows", legal_href="/legal",
               pages=(("/", t["nav_site"]), ("/demo", t["nav_demo"]), ("/demo/flows", t["nav_flows"])),
               examples=tuple(t["examples"]), examples_label=t["nav_examples"], auth=True)


def ctx_of(request: Request, lang: str) -> Ctx:
    user = auth.current_user(request)
    path = request.url.path
    return Ctx(lang=lang, labels=LABELS[lang], path=path, user=user,
               is_admin=bool(user and auth.is_admin(user)),
               lang_hrefs={c: f"{path}?lang={c}" for c in UI_LANGS})


def _bare(ctx: Ctx) -> bool:
    # Die read-only Vorschauen zeigen nur die Seite selbst — ohne den Rumpf drumherum.
    return ctx.path.startswith("/demo/preview/")


def shell_header(_auth) -> str:
    c = _ctx.get()
    return "" if _bare(c) else header(c, nav_of(c.lang))


def shell_footer(_auth) -> str:
    c = _ctx.get()
    return "" if _bare(c) else footer(c, nav_of(c.lang))


class ShellMiddleware:
    """Sprache und Seiten-Kontext für diesen Request bereitstellen.

    Bewusst **reines ASGI** statt `@app.middleware("http")`: Starlettes `BaseHTTPMiddleware` führt die
    App in einem eigenen Task aus — eine dort gesetzte `ContextVar` ist im Endpoint nicht mehr sichtbar.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        lang = lang_of(request)          # ?lang= schlägt Cookie — überall gleich
        auth.cfg.lang = lang                       # damit auch die eingebauten Seiten folgen
        _ctx.set(ctx_of(request, lang))

        if request.cookies.get(LANG_COOKIE) == lang:
            return await self.app(scope, receive, send)

        async def send_with_cookie(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).append(
                    "set-cookie", f"{LANG_COOKIE}={lang}; Path=/; Max-Age=31536000; SameSite=lax")
            await send(message)

        await self.app(scope, receive, send_with_cookie)


app.add_middleware(ShellMiddleware)


TEXTS = {
    "de": {
        "nav_site": "Projektseite", "nav_demo": "Demo", "nav_flows": "Login-Flows",
        "nav_account": "Konto", "nav_admin": "Admin-Panel", "nav_examples": "Beispielseiten",
        "examples": [("/app", "<code>/app</code>", "geschützt mit <code>require_user</code>"),
                     ("/sensibel", "<code>/sensibel</code>", "Step-up: fragt nach der PIN"),
                     ("/gaeste", "<code>/gaeste</code>", "geteilte PIN, ganz ohne Konto"),
                     ("/gibtsnicht", "404", "gebrandete Fehlerseite"),
                     ("/boom", "500", "gebrandete Fehlerseite")],
        # Panel-Überschriften, „read-only"-Marken und der Demo-Vorspann stehen in `web/demo.py`
        # (PANEL_T) — die gebaute Seite benutzt dieselben Sätze.
        "flows_h1": "Login-Flows",
        "flows_lead": 'Jeder Weg ist ein eigener Schalter. Diese Demo läuft mit '
                      '<code>login_identifier="{ident}"</code> und <code>pin_login={pin}</code> — '
                      'die Markierungen unten liest die Seite direkt aus dieser Config.',
        "back_demo": "← Zur Demo", "try_stepup": "Step-up ausprobieren", "try_pin": "Gäste-PIN ausprobieren",
        "app_h1": "Hallo {u} 👋",
        "app_lead": "Eingeloggt — diese Route ist mit <code>Depends(auth.require_user)</code> geschützt.",
        "sens_h1": "🔒 Sensibler Bereich",
        "sens_lead": "{u}, du hast dich soeben frisch bestätigt (Step-up). Nach "
                     "<code>stepup_max_age_sec</code> fragt TinySesam erneut.",
        "sens_hint": "Zur Bestätigung stand hier: <b>{m}</b>. <code>stepup_methods=[\"totp\", \"pin\"]</code> "
                     "bietet alles an, was du <i>eingerichtet</i> hast — ohne 2FA also nur die PIN. "
                     "Richte auf der <a href='/auth/account'>Konto-Seite</a> 2FA ein und komm zurück: "
                     "dann steht der Einmalcode zusätzlich zur Wahl.",
        "guest_h1": "🔑 Gäste-Bereich",
        "guest_lead": "Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.",
        "footer": "Demo-Frontend",
    },
    "en": {
        "nav_site": "Project page", "nav_demo": "Demo", "nav_flows": "Sign-in flows",
        "nav_account": "Account", "nav_admin": "Admin panel", "nav_examples": "Example pages",
        "examples": [("/app", "<code>/app</code>", "guarded by <code>require_user</code>"),
                     ("/sensibel", "<code>/sensibel</code>", "step-up: asks for the PIN"),
                     ("/gaeste", "<code>/gaeste</code>", "shared PIN, no account at all"),
                     ("/gibtsnicht", "404", "branded error page"),
                     ("/boom", "500", "branded error page")],
        # s.o.: die Panel-Texte kommen aus `web/demo.py`.
        "flows_h1": "Sign-in flows",
        "flows_lead": 'Every way in is its own switch. This demo runs with '
                      '<code>login_identifier="{ident}"</code> and <code>pin_login={pin}</code> — '
                      'the tags below are read straight from that config.',
        "back_demo": "← Back to the demo", "try_stepup": "Try the step-up", "try_pin": "Try the guest PIN",
        "app_h1": "Hello {u} 👋",
        "app_lead": "Signed in — this route is guarded by <code>Depends(auth.require_user)</code>.",
        "sens_h1": "🔒 Sensitive area",
        "sens_lead": "{u}, you just confirmed freshly (step-up). After "
                     "<code>stepup_max_age_sec</code> TinySesam asks again.",
        "sens_hint": "Available here: <b>{m}</b>. <code>stepup_methods=[\"totp\", \"pin\"]</code> "
                     "offers whatever you have <i>set up</i> — without 2FA that is just the PIN. "
                     "Enable 2FA on the <a href='/auth/account'>account page</a> and come back: the "
                     "one-time code then joins the choice.",
        "guest_h1": "🔑 Guest area",
        "guest_lead": "Unlocked with the shared PIN — without any user account.",
        "footer": "Demo front end",
    },
}


# ---------------------------------------------------------------- Seitengerüst der Demo
# `DEMO_CSS` (Rahmen, Glasscheibe, Marke) kommt aus `web/demo.py` — dieselbe Quelle wie für die
# gebaute Seite. Hier steht nur, was allein die laufende App braucht.
_DEMO_CSS = FLOW_CSS + """
h1{font-family:var(--ts-serif);font-size:48px;letter-spacing:-.01em;margin:.2em 0 .2em;text-wrap:balance}
h2{font-size:18px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  font-weight:600;margin:0 0 14px}
.lead{color:var(--muted);font-size:18px;max-width:56ch;text-wrap:balance}
.bar{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn.s{padding:6px 13px;font-size:14px}
.muted{color:var(--muted);font-size:14px}
@media (prefers-reduced-motion:no-preference){main{animation:rise .5s ease both}}
""" + DEMO_CSS


def page(title: str, body: str, request: Request) -> HTMLResponse:
    """Eine Demo-Seite — Rumpf und Fußzeile kommen aus `web/ui.py`, wie überall sonst."""
    c = _ctx.get()
    return HTMLResponse(document(c, nav_of(c.lang), title=f"{title} · TinySesam",
                                 css=_DEMO_CSS, body=body))


# ---------------------------------------------------------------- Website-Seiten (aus web/site.py)
@app.get(ICON_URL, include_in_schema=False)
def wizard():
    return FileResponse(DOCS / "wizard.png", media_type="image/png")


@app.get("/theme.css", include_in_schema=False)
def theme():
    return FileResponse(DOCS / "theme.css", media_type="text/css")


@app.get("/legal", response_class=HTMLResponse)
def legal(request: Request):
    """Impressum + Datenschutz — dieselbe Quelle wie auf GitHub Pages."""
    c = _ctx.get()
    return HTMLResponse(document(c, nav_of(c.lang), title=SITE_T[c.lang]["legal_title"],
                                 desc=SITE_T[c.lang]["legal_desc"], css=LEGAL_CSS,
                                 body=legal_body(c.lang)))


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    """Dieselbe Startseite wie auf GitHub Pages — hier serverseitig in der gewählten Sprache."""
    c = _ctx.get()
    nav = nav_of(c.lang)
    c.hero = hero(c.lang)
    return HTMLResponse(document(c, nav, title=SITE_T[c.lang]["title"], desc=SITE_T[c.lang]["desc"],
                                 css=INDEX_CSS, body=index_body(c.lang, nav)))


# ---------------------------------------------------------------- Demo
#: Die laufende App liefert ihre Vorschauen aus eigenen Routen; die gebaute Seite zeigt Dateien.
#: `demo_body` kennt beides — nur die Quellen unterscheiden sich.
_LIVE_SRC = {k: f"/demo/preview/{k}" for k in ("login", "account", "admin")}
_LIVE_OPEN = {"login": "/auth/login", "account": "/auth/account", "admin": "/auth/admin"}


@app.get("/demo", response_class=HTMLResponse)
def demo(request: Request):
    lang, user = lang_of(request), auth.current_user(request)
    t = PANEL_T[lang]
    lead = t["demo_hello"].format(u=user["username"]) if user else t["demo_lead"]
    body = demo_body(lang, src=_LIVE_SRC, open_urls=_LIVE_OPEN, lead=lead)
    return page(t["demo_h1"], body, request)


@app.get("/demo/flows", response_class=HTMLResponse)
def flows(request: Request):
    lang, user = lang_of(request), auth.current_user(request)
    t, c = TEXTS[lang], auth.cfg
    body = (f"<h1>{t['flows_h1']}</h1>"
            f"<p class=lead>{t['flows_lead'].format(ident=c.login_identifier, pin=c.pin_login)}</p>"
            + flow_html(lang, c) +
            f"<hr class=rule><div class=bar><a class='btn primary' href='/demo'>{t['back_demo']}</a>"
            f"<a class='btn ghost' href='/sensibel'>{t['try_stepup']}</a>"
            f"<a class='btn ghost' href='/gaeste'>{t['try_pin']}</a></div>")
    return page(t["flows_h1"], body, request)


# ---------------------------------------------------------------- Read-only Vorschauen
# Gerendert wird in `web/demo.py` — dieselben drei Panels, die auch die gebaute Seite zeigt.
# Hier hängen sie nur an Routen statt an Dateien.
#
# Bewusst **pro Request**, nicht einmal beim Import: `auth.cfg.lang` setzt die Middleware je
# Anfrage. Ein zwischengespeichertes Panel bliebe für immer in der Sprache des ersten Aufrufs.
@app.get("/demo/preview/{name}", include_in_schema=False)
def prev_panel(name: str):
    previews = render_previews(auth, "/demo/preview/adminapi")
    if name not in previews:
        raise HTTPException(status_code=404)
    return HTMLResponse(previews[name])


#: Die Beispieldaten des Admin-Panels — dieselben, die der Bauschritt als Dateien ablegt.
_FAKE = mock_api(__version__)


@app.get("/demo/preview/adminapi/api/{path:path}", include_in_schema=False)
def prev_api(path: str):
    return JSONResponse(_FAKE.get(path, []))


@app.post("/demo/preview/adminapi/api/{path:path}", include_in_schema=False)
def prev_api_ro(path: str):
    return JSONResponse({"detail": "Vorschau — schreibende Aktionen sind abgeschaltet."}, status_code=403)


# ---------------------------------------------------------------- Geschützte Beispiel-Seiten
@app.get("/app", response_class=HTMLResponse)
def protected(request: Request, user=Depends(auth.require_user)):
    lang = lang_of(request)
    t = TEXTS[lang]
    return page("/app", f"<h1>{t['app_h1'].format(u=user['username'])}</h1>"
                        f"<p class=lead>{t['app_lead']}</p>"
                        f"<div class=bar><a class='btn primary' href='/demo'>{t['back_demo']}</a>"
                        f"<a class='btn ghost' href='/sensibel'>{t['try_stepup']}</a></div>", request)


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(request: Request, user=Depends(auth.require(mfa=True))):
    lang = lang_of(request)
    t = TEXTS[lang]
    method = ", ".join(auth.stepup_options(user)) or "—"
    return page("/sensibel", f"<h1>{t['sens_h1']}</h1>"
                             f"<p class=lead>{t['sens_lead'].format(u=user['username'])}</p>"
                             f"<p class=muted style='max-width:60ch'>{t['sens_hint'].format(m=method)}</p>"
                             f"<div class=bar><a class='btn primary' href='/demo'>{t['back_demo']}</a>"
                             f"<a class='btn ghost' href='/auth/account'>{t['nav_account']}</a></div>", request)


@app.get("/gaeste", response_class=HTMLResponse)
def guests(request: Request, _=Depends(auth.require_resource("gaeste"))):
    lang = lang_of(request)
    t = TEXTS[lang]
    return page("/gaeste", f"<h1>{t['guest_h1']}</h1><p class=lead>{t['guest_lead']}</p>"
                           f"<div class=bar><a class='btn primary' href='/demo'>{t['back_demo']}</a></div>", request)


@app.get("/boom", response_class=HTMLResponse)
def boom():
    raise RuntimeError("absichtlicher Fehler für die Demo")   # → themed 500-Seite
