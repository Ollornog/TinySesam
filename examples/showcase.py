"""Showcase — reference frontend for TinySesam, in the design of the project website.

    pip install -e '.[all]'
    uvicorn examples.showcase:app --reload
    # → http://127.0.0.1:8000

Everything hangs on one source each:
  * **Colours** — `docs/theme.css`. The website loads it via `<link>`, the app passes it on as
    `brand_css` into the built-in pages.
  * **Navigation** — `web/site.py` (`nav_top`/`nav_sub`). Website and demo use it to build the same
    two bars, just with their own content.
  * **Texts** — `TEXTS` below, bilingual. The language comes from `?lang=` or the cookie and
    applies to the demo pages AND the built-in TinySesam pages (`cfg.lang`).
  * **Panels** — the previews render the real building blocks (`auth.render_page`, `render_panel`).

The **demo mode** (`demo_mode=True`) creates the accounts `demo` and `demoadmin` and shows the
credentials on the login page — along with a warning that it does not belong in production.
"""
import html
import os
import sys
from contextvars import ContextVar
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # so that `web` is found

from fastapi import FastAPI, Depends, Request, HTTPException            # noqa: E402
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse  # noqa: E402
from starlette.datastructures import MutableHeaders                     # noqa: E402

from tinysesam import TinySesam, __version__                            # noqa: E402

from web.demo import (DEMO_CSS, PANEL_T, brand_css,                     # noqa: E402
                      demo_body, demo_config, mock_api, render_previews)
from web.flows import CSS as FLOW_CSS, render as flow_html              # noqa: E402
from web.site import (INDEX_CSS, LABELS, LEGAL_CSS, T as SITE_T,         # noqa: E402
                      hero, index_body, legal_body)
from web.ui import (Ctx, LANG_COOKIE, LANGS as UI_LANGS, Nav,           # noqa: E402
                    UI_JS, document, footer, header)

REPO = "https://github.com/Ollornog/TinySesam"
DOCS = Path(__file__).resolve().parent.parent / "docs"
ICON_URL = "/wizard.png"

THEME = (DOCS / "theme.css").read_text(encoding="utf-8")

BRAND = brand_css(THEME)

# The same config that `web.demo.build()` uses for the static version — otherwise the
# website would show different sign-in methods than the running demo. Only what the live app additionally needs
# goes here: a real file DB and the demo mode with its example accounts.
auth = TinySesam(demo_config(
    db_path=os.environ.get("TINYSESAM_SHOWCASE_DB", "/tmp/tinysesam-showcase.db"),
    brand=BRAND,
    icon=ICON_URL,
    lang="en",
    demo_mode=True,                  # creates `demo` + `demoadmin` and shows the credentials
    demo_pin="1234",
))
auth.set_resource_secret("gaeste", "2468", kind="pin", label="Guest area")


app = FastAPI()
app.include_router(auth.router())
auth.install_error_pages(app)


# ---------------------------------------------------------------- Language
def lang_of(request: Request) -> str:
    # Same order as on the website: `?lang=` before cookie before project language (English).
    # The browser language deliberately does not count.
    lang = request.query_params.get("lang") or request.cookies.get(LANG_COOKIE) or UI_LANGS[0]
    return lang if lang in UI_LANGS else UI_LANGS[0]


# The shell of the built-in pages depends on the request (language, login state, path).
# ContextVar instead of a global variable: with concurrent requests each one keeps its own value.
_ctx: ContextVar[Ctx] = ContextVar("ctx")


def nav_of(lang: str) -> Nav:
    """The shell of this app — declared once, used everywhere."""
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
    # The read-only previews show only the page itself — without the shell around it.
    return ctx.path.startswith("/demo/preview/")


def shell_header(_auth) -> str:
    c = _ctx.get()
    return "" if _bare(c) else header(c, nav_of(c.lang))


def shell_footer(_auth) -> str:
    c = _ctx.get()
    return "" if _bare(c) else footer(c, nav_of(c.lang))


# The built-in pages (login, account, admin, error pages) get the same shell as the rest.
# Deliberately placed AFTER the two functions: before, a lambda kept the name open only until the call.
auth.cfg.brand_header = shell_header
auth.cfg.brand_footer = shell_footer
auth.cfg.brand_head = UI_JS       # theme pill + "close dropdown" there as well


class ShellMiddleware:
    """Provide language and page context for this request.

    Deliberately **plain ASGI** instead of `@app.middleware("http")`: Starlette's `BaseHTTPMiddleware` runs the
    app in a task of its own — a `ContextVar` set there is no longer visible in the endpoint.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        lang = lang_of(request)          # ?lang= beats cookie — the same everywhere
        auth.cfg.lang = lang                       # so the built-in pages follow too
        _ctx.set(ctx_of(request, lang))

        if request.cookies.get(LANG_COOKIE) == lang:
            return await self.app(scope, receive, send)

        async def send_with_cookie(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message).append(
                    "set-cookie", f"{LANG_COOKIE}={lang}; Path=/; Max-Age=31536000; SameSite=lax")
            await send(message)

        return await self.app(scope, receive, send_with_cookie)


app.add_middleware(ShellMiddleware)


TEXTS = {
    "de": {
        "nav_site": "Projektseite", "nav_demo": "Demo", "nav_flows": "Login-Flows",
        "nav_account": "Konto", "nav_admin": "Admin-Panel", "nav_examples": "Beispielseiten",
        "examples": [("/app", "<code>/app</code>", "geschützt mit <code>require_user</code>"),
                     ("/sensitive", "<code>/sensitive</code>", "Step-up: fragt nach der PIN"),
                     ("/gaeste", "<code>/gaeste</code>", "geteilte PIN, ganz ohne Konto"),
                     ("/gibtsnicht", "404", "gebrandete Fehlerseite"),
                     ("/boom", "500", "gebrandete Fehlerseite")],
        # Panel headings, "read-only" badges and the demo intro live in `web/demo.py`
        # (PANEL_T) — the built page uses the same sentences.
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
                     ("/sensitive", "<code>/sensitive</code>", "step-up: asks for the PIN"),
                     ("/gaeste", "<code>/gaeste</code>", "shared PIN, no account at all"),
                     ("/gibtsnicht", "404", "branded error page"),
                     ("/boom", "500", "branded error page")],
        # see above: the panel texts come from `web/demo.py`.
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


# ---------------------------------------------------------------- Page scaffold of the demo
# `DEMO_CSS` (frame, glass pane, brand) comes from `web/demo.py` — the same source as for the
# built page. Only what the running app alone needs is here.
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
    """A demo page — shell and footer come from `web/ui.py`, as everywhere else."""
    c = _ctx.get()
    return HTMLResponse(document(c, nav_of(c.lang), title=f"{title} · TinySesam",
                                 css=_DEMO_CSS, body=body))


# ---------------------------------------------------------------- Website pages (from web/site.py)
@app.get(ICON_URL, include_in_schema=False)
def wizard():
    return FileResponse(DOCS / "wizard.png", media_type="image/png")


@app.get("/theme.css", include_in_schema=False)
def theme():
    return FileResponse(DOCS / "theme.css", media_type="text/css")


@app.get("/legal", response_class=HTMLResponse)
def legal(request: Request):
    """Legal notice + privacy policy — the same source as on GitHub Pages."""
    c = _ctx.get()
    return HTMLResponse(document(c, nav_of(c.lang), title=SITE_T[c.lang]["legal_title"],
                                 desc=SITE_T[c.lang]["legal_desc"], css=LEGAL_CSS,
                                 body=legal_body(c.lang)))


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    """The same home page as on GitHub Pages — here rendered server-side in the chosen language."""
    c = _ctx.get()
    nav = nav_of(c.lang)
    c.hero = hero(c.lang)
    return HTMLResponse(document(c, nav, title=SITE_T[c.lang]["title"], desc=SITE_T[c.lang]["desc"],
                                 css=INDEX_CSS, body=index_body(c.lang, nav)))


# ---------------------------------------------------------------- Demo
#: The running app serves its previews from routes of its own; the built page shows files.
#: `demo_body` knows both — only the sources differ.
_LIVE_SRC = {k: f"/demo/preview/{k}" for k in ("login", "account", "admin")}
_LIVE_OPEN = {"login": "/auth/login", "account": "/auth/account", "admin": "/auth/admin"}


@app.get("/demo", response_class=HTMLResponse)
def demo(request: Request):
    lang, user = lang_of(request), auth.current_user(request)
    t = PANEL_T[lang]
    # Escape as on /app and /sensitive (R8-2): the fix from T-12 hit two of the three places
    # where the username goes into a demo page. Whoever registered as `<img src=x onerror=…>`
    # was running along here on every visit to /demo.
    lead = t["demo_hello"].format(u=html.escape(user["username"])) if user else t["demo_lead"]
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
            f"<a class='btn ghost' href='/sensitive'>{t['try_stepup']}</a>"
            f"<a class='btn ghost' href='/gaeste'>{t['try_pin']}</a></div>")
    return page(t["flows_h1"], body, request)


# ---------------------------------------------------------------- Read-only previews
# Rendering happens in `web/demo.py` — the same three panels the built page shows.
# Here they are merely attached to routes instead of files.
#
# Deliberately **per request**, not once at import: the middleware sets `auth.cfg.lang` per
# request. A cached panel would stay in the language of the first call forever.
@app.get("/demo/preview/{name}", include_in_schema=False)
def prev_panel(name: str):
    previews = render_previews(auth, "/demo/preview/adminapi")
    if name not in previews:
        raise HTTPException(status_code=404)
    return HTMLResponse(previews[name])


#: The example data of the admin panel — the same that the build step writes out as files.
_FAKE = mock_api(__version__)


@app.get("/demo/preview/adminapi/api/{path:path}", include_in_schema=False)
def prev_api(path: str):
    return JSONResponse(_FAKE.get(path, []))


@app.post("/demo/preview/adminapi/api/{path:path}", include_in_schema=False)
def prev_api_ro(path: str):
    return JSONResponse({"detail": "Vorschau — schreibende Aktionen sind abgeschaltet."}, status_code=403)


# ---------------------------------------------------------------- Protected example pages
@app.get("/app", response_class=HTMLResponse)
def protected(request: Request, user=Depends(auth.require_user)):
    lang = lang_of(request)
    t = TEXTS[lang]
    return page("/app", f"<h1>{t['app_h1'].format(u=html.escape(user['username']))}</h1>"
                        f"<p class=lead>{t['app_lead']}</p>"
                        f"<div class=bar><a class='btn primary' href='/demo'>{t['back_demo']}</a>"
                        f"<a class='btn ghost' href='/sensitive'>{t['try_stepup']}</a></div>", request)


@app.get("/sensitive", response_class=HTMLResponse)
def sensitive(request: Request, user=Depends(auth.require(mfa=True))):
    lang = lang_of(request)
    t = TEXTS[lang]
    method = html.escape(", ".join(auth.stepup_options(user))) or "—"
    return page("/sensitive", f"<h1>{t['sens_h1']}</h1>"
                             f"<p class=lead>{t['sens_lead'].format(u=html.escape(user['username']))}</p>"
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
    raise RuntimeError("intentional error for the demo")   # → themed 500 page
