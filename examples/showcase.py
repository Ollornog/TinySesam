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
import sys
from contextvars import ContextVar
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # damit `web` gefunden wird

from fastapi import FastAPI, Depends, Request, HTTPException            # noqa: E402
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse  # noqa: E402
from starlette.datastructures import MutableHeaders                     # noqa: E402

from tinysesam import TinySesam, TinySesamConfig                        # noqa: E402
from tinysesam.admin import render_panel                                # noqa: E402

from web.flows import CSS as FLOW_CSS, render as flow_html              # noqa: E402
from web.site import (INDEX_CSS, LABELS, LEGAL_CSS, T as SITE_T,         # noqa: E402
                      flows_body, hero, index_body, legal_body)
from web.ui import (Ctx, LANG_COOKIE, LANGS as UI_LANGS, Nav, UI_CSS,   # noqa: E402
                    UI_JS, document, footer, header, shell)

REPO = "https://github.com/Ollornog/TinySesam"
DOCS = Path(__file__).resolve().parent.parent / "docs"
ICON_URL = "/wizard.png"

THEME = (DOCS / "theme.css").read_text(encoding="utf-8")

BRAND = THEME + UI_CSS + """
body{font-family:var(--ts-font)}
h1{font-family:var(--ts-serif);font-weight:600}
.card{box-shadow:0 14px 44px rgba(90,60,70,.10)}
input:focus{outline:2px solid var(--ts-accent);border-color:var(--ts-accent)}
button:hover,.btn2:hover{filter:brightness(1.05)}
"""

auth = TinySesam(TinySesamConfig.local_accounts(   # nur Benutzername + Passwort, keine E-Mail
    db_path="/tmp/tinysesam-showcase.db",
    rp_name="TinySesam",
    lang="de",
    brand_css=BRAND,
    brand_icon=ICON_URL,
    passkey_enabled=False,
    pin_enabled=True,                # PIN gibt es …
    pin_login=False,                 # … aber nicht als Login-Methode
    stepup_methods=["totp", "pin"],  # … sondern als Bestätigung für sensible Bereiche:
                                     # TOTP, wenn eingerichtet — sonst die PIN
    demo_mode=True,                  # legt `demo` + `demoadmin` an und zeigt die Zugangsdaten
    demo_pin="1234",
    allow_signup=True,
    resource_locks_enabled=True,
    available_roles=["editor", "viewer"],
    cookie_secure=False,
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
    lang = request.query_params.get("lang") or request.cookies.get(LANG_COOKIE) or "de"
    return lang if lang in UI_LANGS else "de"


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
        "demo_h1": "Live-Demo",
        "demo_hello": "Angemeldet als <b>{u}</b> — die Beispielseiten oben sind jetzt begehbar.",
        "demo_lead": "Alles, was TinySesam mitbringt, in einem Frontend. Die Panels unten sind "
                     "<b>echte Seiten</b>, live gerendert — nur die Bedienung ist gesperrt.",
        "p_login": ("Login-Panel", "Die Anmeldeseite zeigt <b>genau die Methoden, die die Config "
                    "aktiviert</b>. Hier: Benutzername und Passwort. Der Demo-Modus blendet die "
                    "Zugangsdaten ein — und warnt, dass er produktiv aus gehört."),
        "p_account": ("Konto-Panel", "Selbstverwaltung unter <code>/auth/account</code>: Passwort, PIN, "
                      "2FA + Recovery-Codes, Passkeys, API-Keys und die eigenen Sitzungen."),
        "p_admin": ("Admin-Panel", "Benutzer &amp; Rollen, Sitzungen, Härtungs-Schwellen, Update, "
                    "Audit-Log. Wahlweise nur als JSON-API für dein eigenes Panel."),
        "open": "Öffnen →", "ro": "read-only", "ro_fake": "read-only · Beispieldaten",
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
        "demo_h1": "Live demo",
        "demo_hello": "Signed in as <b>{u}</b> — the example pages above are open now.",
        "demo_lead": "Everything TinySesam brings, in one front end. The panels below are "
                     "<b>real pages</b>, rendered live — only the interaction is locked.",
        "p_login": ("Login panel", "The sign-in page shows <b>exactly the methods the config enables</b>. "
                    "Here: username and password. Demo mode reveals the credentials — and warns that "
                    "it must be off in production."),
        "p_account": ("Account panel", "Self-service at <code>/auth/account</code>: password, PIN, "
                      "2FA + recovery codes, passkeys, API keys and your own sessions."),
        "p_admin": ("Admin panel", "Users &amp; roles, sessions, hardening thresholds, update, audit log. "
                    "Or just the JSON API, for your own panel."),
        "open": "Open →", "ro": "read-only", "ro_fake": "read-only · sample data",
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
_DEMO_CSS = FLOW_CSS + """
h1{font-family:var(--ts-serif);font-size:48px;letter-spacing:-.01em;margin:.2em 0 .2em;text-wrap:balance}
h2{font-size:18px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  font-weight:600;margin:0 0 14px}
.lead{color:var(--muted);font-size:18px;max-width:56ch;text-wrap:balance}
.bar{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn.s{padding:6px 13px;font-size:14px}
.muted{color:var(--muted);font-size:14px}
hr.rule{height:1px;background:var(--line);border:0;margin:80px 0}
.shot{margin:0 0 96px}
.shot .head{display:flex;align-items:baseline;justify-content:space-between;gap:14px;
  flex-wrap:wrap;margin-bottom:12px}
.shot .head p{margin:4px 0 0;color:var(--muted);font-size:15px;max-width:60ch}
.frame{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:14px;
  background:var(--card);box-shadow:0 12px 36px rgba(90,60,70,.09);transition:height .2s}
.frame iframe{display:block;border:0;transform-origin:top left}
.frame .glass{position:absolute;inset:0;cursor:default}
.frame .tag{position:absolute;right:10px;top:10px;background:var(--chip);border:1px solid var(--line);
  border-radius:999px;padding:3px 10px;font-size:12px;color:var(--muted)}
@media (prefers-reduced-motion:no-preference){main{animation:rise .5s ease both}}
"""


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
def shot(title, blurb, src, open_url, height, scale, tag, open_label):
    return (f"<section class=shot><div class=head><div><h2>{title}</h2><p>{blurb}</p></div>"
            f"<a class='btn ghost s' href='{open_url}'>{open_label}</a></div>"
            f"<div class=frame data-scale='{scale}' style='height:{height}px'>"
            f"<iframe src='{src}' tabindex=-1 scrolling=no title='{title}'"
            f" style='width:{100 / scale:.0f}%;height:{height / scale:.0f}px;transform:scale({scale})'></iframe>"
            f"<span class=glass></span><span class=tag>{tag}</span></div></section>")


# Der Rahmen wächst auf die echte Inhaltshöhe. Das Admin-Panel lädt seine Tabelle per fetch NACH
# dem load-Event — einmaliges Messen schneidet sie ab. Daher ResizeObserver + Nachzügler-Timer.
_FIT_JS = """<script>
function tsFit(frame){
  const f = frame.querySelector('iframe'), s = parseFloat(frame.dataset.scale) || 1;
  try{
    const d = f.contentDocument;
    if(!d || !d.body) return;
    const h = Math.max(d.body.scrollHeight, d.body.offsetHeight);
    if(Math.abs(h - (frame._h || 0)) < 2) return;
    frame._h = h;
    f.style.height = h + 'px';
    frame.style.height = Math.ceil(h * s) + 'px';
  }catch(e){}
}
document.querySelectorAll('.frame').forEach(fr => {
  const f = fr.querySelector('iframe');
  f.addEventListener('load', () => {
    tsFit(fr);
    try{ new ResizeObserver(() => tsFit(fr)).observe(f.contentDocument.body); }catch(e){}
    [120, 400, 1000].forEach(ms => setTimeout(() => tsFit(fr), ms));
  });
});
addEventListener('resize', () => document.querySelectorAll('.frame').forEach(fr => { fr._h = 0; tsFit(fr); }));
</script>"""


@app.get("/demo", response_class=HTMLResponse)
def demo(request: Request):
    lang, user = lang_of(request), auth.current_user(request)
    t = TEXTS[lang]
    hello = (f"<p class=lead>{t['demo_hello'].format(u=user['username'])}</p>" if user
             else f"<p class=lead>{t['demo_lead']}</p>")
    panels = (shot(*t["p_login"], "/demo/preview/login", "/auth/login", 470, 0.86, t["ro"], t["open"])
              + shot(*t["p_account"], "/demo/preview/account", "/auth/account", 470, 0.8, t["ro"], t["open"])
              + shot(*t["p_admin"], "/demo/preview/admin", "/auth/admin", 520, 0.66, t["ro_fake"], t["open"]))
    body = f"<h1>{t['demo_h1']}</h1>{hello}<hr class=rule>{panels}{_FIT_JS}"
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
_LOCK = ("<style>html{pointer-events:none;user-select:none}"
         "html,body{min-height:0!important}.tsmain{padding:0}"
         "::-webkit-scrollbar{display:none}</style>")
_LOCK_CARD = _LOCK + "<style>.tsmain{justify-content:flex-start!important;padding:26px 0}</style>"


def _readonly(html: str, lock: str = _LOCK) -> HTMLResponse:
    return HTMLResponse(html.replace("</body>", lock + "</body>", 1))


@app.get("/demo/preview/login", include_in_schema=False)
def prev_login():
    # In der Vorschau stört der Demo-Hinweis — er gehört auf die echte Login-Seite.
    resp = auth.render_page("login", next="/demo", csrf="", demo_hint=False)
    return _readonly(resp.body.decode(), _LOCK_CARD)


@app.get("/demo/preview/account", include_in_schema=False)
def prev_account():
    demo_user = {"id": 0, "username": "demo", "display_name": "", "is_admin": 0}
    resp = auth.render_page("account", user=demo_user, methods=auth.cfg.enabled_methods(),
                            has_totp=True, has_pin=True, is_admin=False,
                            admin_path=auth.cfg.admin_path, csrf="")
    return _readonly(resp.body.decode())


@app.get("/demo/preview/admin", include_in_schema=False)
def prev_admin():
    return _readonly(render_panel(auth, "/demo/preview/adminapi"))


_FAKE = {
    "/api/users": [
        {"id": 1, "username": "demoadmin", "is_admin": True, "is_service": False, "roles": [], "disabled": False},
        {"id": 2, "username": "demo", "is_admin": False, "is_service": False, "roles": ["editor"], "disabled": False},
        {"id": 3, "username": "martin", "is_admin": False, "is_service": False, "roles": ["viewer"], "disabled": True},
        {"id": 4, "username": "backup-daemon", "is_admin": False, "is_service": True, "roles": ["reader"], "disabled": False},
    ],
    "/api/sessions": [{"id": 1, "username": "demoadmin", "method": "password", "ip": "10.0.0.7",
                       "created": 1_770_000_000, "expires": 1_770_600_000}],
    "/api/security": {"max_login_attempts": 5, "lockout_window_sec": 900, "rate_limit_max": 30},
    "/api/update": {"current": "0.10.0", "latest": "0.10.0", "available": False, "mode": "manual", "pin": ""},
    "/api/audit": [{"ts": 1_770_000_000, "event": "login", "username": "demoadmin", "ip": "10.0.0.7", "detail": ""}],
    "/api/resources": [{"name": "gaeste", "kind": "pin", "label": "Gäste-Bereich"}],
}


@app.get("/demo/preview/adminapi/api/{path:path}", include_in_schema=False)
def prev_api(path: str):
    return JSONResponse(_FAKE.get(f"/api/{path}", []))


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
