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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # damit `web` gefunden wird

from fastapi import FastAPI, Depends, Request, HTTPException            # noqa: E402
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig                        # noqa: E402
from tinysesam.admin import render_panel                                # noqa: E402

from web.flows import CSS as FLOW_CSS, render as flow_html              # noqa: E402
from web.site import (NAV_CSS, THEME_JS, dropdown, footer,              # noqa: E402
                      lang_dropdown_path, link, nav_sub, nav_top,
                      render_flows, render_index, theme_toggle)

REPO = "https://github.com/Ollornog/TinySesam"
DOCS = Path(__file__).resolve().parent.parent / "docs"
ICON_URL = "/wizard.png"
LANG_COOKIE = "ts_lang"
LANGS = ("de", "en")

THEME = (DOCS / "theme.css").read_text(encoding="utf-8")

BRAND = THEME + """
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
    stepup_methods=["pin"],          # … sondern als Bestätigung für sensible Bereiche
    demo_mode=True,                  # legt `demo` + `demoadmin` an und zeigt die Zugangsdaten
    demo_pin="1234",
    allow_signup=True,
    resource_locks_enabled=True,
    available_roles=["editor", "viewer"],
    cookie_secure=False,
))
auth.set_resource_secret("gaeste", "2468", kind="pin", label="Gäste-Bereich")

app = FastAPI()
app.include_router(auth.router())
auth.install_error_pages(app)


# ---------------------------------------------------------------- Sprache
def lang_of(request: Request) -> str:
    lang = request.query_params.get("lang") or request.cookies.get(LANG_COOKIE) or "de"
    return lang if lang in LANGS else "de"


@app.middleware("http")
async def set_language(request: Request, call_next):
    """Eine Sprache für alles: die Demo-Seiten UND die eingebauten TinySesam-Seiten (`cfg.lang`).
    Die Website-Dateien tragen sie im Namen, alles andere im Cookie."""
    path = request.url.path
    if path.endswith(".de.html"):
        lang = "de"
    elif path.endswith(".html"):
        lang = "en"
    else:
        lang = lang_of(request)
    auth.cfg.lang = lang
    response = await call_next(request)
    if request.cookies.get(LANG_COOKIE) != lang:
        response.set_cookie(LANG_COOKIE, lang, path="/", samesite="lax", max_age=31536000)
    return response


TEXTS = {
    "de": {
        "nav_site": "Projektseite", "nav_demo": "Demo", "nav_flows": "Login-Flows",
        "nav_account": "Konto", "nav_admin": "Admin-Panel", "nav_examples": "Beispielseiten",
        "logout": "Abmelden", "login": "Anmelden", "register": "Registrieren",
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
        "guest_h1": "🔑 Gäste-Bereich",
        "guest_lead": "Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.",
        "footer": "Demo-Frontend",
    },
    "en": {
        "nav_site": "Project page", "nav_demo": "Demo", "nav_flows": "Sign-in flows",
        "nav_account": "Account", "nav_admin": "Admin panel", "nav_examples": "Example pages",
        "logout": "Sign out", "login": "Sign in", "register": "Register",
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
        "guest_h1": "🔑 Guest area",
        "guest_lead": "Unlocked with the shared PIN — without any user account.",
        "footer": "Demo front end",
    },
}


# ---------------------------------------------------------------- Icons
ICON = {
    "github": '<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/>',
    "book": '<path d="M0 1.75A.75.75 0 0 1 .75 1h4.253c1.227 0 2.317.59 3 1.501A3.743 3.743 0 0 1 11.006 1h4.245a.75.75 0 0 1 .75.75v10.5a.75.75 0 0 1-.75.75h-4.507a2.25 2.25 0 0 0-1.591.659l-.622.621a.75.75 0 0 1-1.06 0l-.622-.621A2.25 2.25 0 0 0 5.258 13H.75a.75.75 0 0 1-.75-.75Zm7.251 10.324.004-5.073-.002-2.253A2.25 2.25 0 0 0 5.003 2.5H1.5v9h3.757a3.75 3.75 0 0 1 1.994.574ZM8.755 4.75l-.004 7.322a3.752 3.752 0 0 1 1.992-.572H14.5v-9h-3.495a2.25 2.25 0 0 0-2.25 2.25Z"/>',
}


def icon(name: str) -> str:
    return f'<svg viewBox="0 0 16 16" aria-hidden="true">{ICON[name]}</svg>'


# ---------------------------------------------------------------- Navigation (Inhalt; Bausteine aus web/site.py)
def nav1(lang, path="/demo", brand=True) -> str:
    """Erste Leiste: Marke + Werkzeuge (Sprache, Dark-Mode). Kennt den Login-Status nicht.
    Nur die Startseite lässt die Marke weg — ihr Titelbereich zeigt sie groß."""
    tools = lang_dropdown_path(path, lang) + theme_toggle()
    return nav_top(tools, brand_href="/" if brand else None, icon=ICON_URL)


def nav2(lang, user=None, active="") -> str:
    """Zweite Leiste: links auf jeder Seite dieselben Einträge, rechts der Aktionsbereich."""
    t = TEXTS[lang]
    items = [link("/", t["nav_site"], active == "/"),
             link("/demo", t["nav_demo"], active == "/demo"),
             link("/demo/flows", t["nav_flows"], active == "/demo/flows")]
    ex = "".join(f"<a href='{h}'><b>{l}</b><span>{d}</span></a>" for h, l, d in t["examples"])
    open_ = any(active == h for h, _, _ in t["examples"])
    items.append(dropdown(t["nav_examples"], ex, open_=open_))
    if user:
        right = (f"<span class=muted>{user['username']}</span>"
                 f"<a class='btn ghost' href='/auth/account'>{t['nav_account']}</a>")
        if auth.is_admin(user):
            right += f"<a class='btn ghost' href='/auth/admin'>{t['nav_admin']}</a>"
        right += f"<a class='btn ghost' href='/auth/logout'>{t['logout']}</a>"
    else:
        right = (f"<a class='btn ghost' href='/auth/register'>{t['register']}</a>"
                 f"<a class='btn primary' href='/auth/login'>{t['login']}</a>")
    return nav_sub("".join(items), right)


# ---------------------------------------------------------------- App-Design
_SITE_CSS = """
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);line-height:1.65;font-family:var(--ts-font)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
svg{width:16px;height:16px;fill:currentColor;flex:0 0 auto}
""" + NAV_CSS + FLOW_CSS + """
main{max-width:900px;margin:0 auto;padding:36px 22px 64px}
h1{font-family:var(--ts-serif);font-size:38px;letter-spacing:-.01em;margin:.2em 0 .1em;text-wrap:balance}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:600;margin:0 0 6px}
.lead{color:var(--muted);font-size:18px;max-width:56ch;text-wrap:balance}
.bar{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 17px;border-radius:10px;font-weight:500;font-size:15px}
.btn.p,.btn.primary{background:var(--accent);color:#fff}
.btn.p:hover,.btn.primary:hover{text-decoration:none;filter:brightness(1.05)}
.btn.g,.btn.ghost{border:1px solid var(--line);color:var(--ink)}
.btn.g:hover,.btn.ghost:hover{text-decoration:none;border-color:var(--accent)}
.btn.s{padding:6px 13px;font-size:14px}
.muted{color:var(--muted);font-size:14px}
code{font-family:var(--ts-mono);font-size:.86em;background:var(--chip);border:1px solid var(--line);
  border-radius:5px;padding:1px 5px}
hr.rule{height:1px;background:var(--line);border:0;margin:44px 0}
.shot{margin:0 0 34px}
.shot .head{display:flex;align-items:baseline;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:12px}
.shot .head p{margin:2px 0 0;color:var(--muted);font-size:14.5px;max-width:60ch}
.frame{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:14px;
  background:var(--card);box-shadow:0 12px 36px rgba(90,60,70,.09);transition:height .2s}
.frame iframe{display:block;border:0;transform-origin:top left}
.frame .glass{position:absolute;inset:0;cursor:default}
.frame .tag{position:absolute;right:10px;top:10px;background:var(--chip);border:1px solid var(--line);
  border-radius:999px;padding:3px 10px;font-size:12px;color:var(--muted)}
@media (prefers-reduced-motion:no-preference){
  nav.sub,main{animation:rise .5s ease both}
  @keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
}
"""


def page(title, body, user=None, active="", lang="de"):
    return HTMLResponse(
        f"<!doctype html><html lang={lang}><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<link rel=icon href='{ICON_URL}'><link rel=stylesheet href='/theme.css'>"
        f"<title>{title} · TinySesam</title><style>{_SITE_CSS}</style>{THEME_JS}</head><body>"
        f"{nav1(lang, active or '/demo')}{nav2(lang, user, active)}"
        f"<main>{body}</main>{footer(lang)}</body></html>")


# ---------------------------------------------------------------- Website-Seiten (aus web/site.py)
SITE_PAGES = {"index.html": ("index", "en"), "index.de.html": ("index", "de"),
              "flows.html": ("flows", "en"), "flows.de.html": ("flows", "de")}



@app.get(ICON_URL, include_in_schema=False)
def wizard():
    return FileResponse(DOCS / "wizard.png", media_type="image/png")


@app.get("/theme.css", include_in_schema=False)
def theme():
    return FileResponse(DOCS / "theme.css", media_type="text/css")


def _index(user, lang) -> HTMLResponse:
    # Einziger Sonderfall: der Titelbereich zeigt die Marke, deshalb erste Leiste ohne sie.
    return HTMLResponse(render_index(lang, nav1=nav1(lang, "/", brand=False), nav2=nav2(lang, user, "/")))


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    lang = lang_of(request)
    return _index(auth.current_user(request), lang)


@app.get("/{name}.html", include_in_schema=False)
def site_page(name: str, request: Request):
    """index.de.html · flows.html · flows.de.html — dieselben Seiten wie auf GitHub Pages."""
    fname = f"{name}.html"
    if fname not in SITE_PAGES:
        raise HTTPException(404)
    which, lang = SITE_PAGES[fname]
    user = auth.current_user(request)
    if which == "index":
        return _index(user, lang)
    return HTMLResponse(render_flows(lang, nav1=nav1(lang, "/demo/flows"),
                                     nav2=nav2(lang, user, "/demo/flows")))


# ---------------------------------------------------------------- Demo
def shot(title, blurb, src, open_url, height, scale, tag, open_label):
    return (f"<section class=shot><div class=head><div><h2>{title}</h2><p>{blurb}</p></div>"
            f"<a class='btn g s' href='{open_url}'>{open_label}</a></div>"
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
    body = (f"<h1>{t['demo_h1']}</h1>{hello}"
            f"<div class=bar><a class='btn g' href='{REPO}'>{icon('github')}GitHub</a>"
            f"<a class='btn g' href='{REPO}#readme'>{icon('book')}Doku</a></div>"
            f"<hr class=rule>{panels}{_FIT_JS}")
    return page(t["demo_h1"], body, user=user, active="/demo", lang=lang)


@app.get("/demo/flows", response_class=HTMLResponse)
def flows(request: Request):
    lang, user = lang_of(request), auth.current_user(request)
    t, c = TEXTS[lang], auth.cfg
    body = (f"<h1>{t['flows_h1']}</h1>"
            f"<p class=lead>{t['flows_lead'].format(ident=c.login_identifier, pin=c.pin_login)}</p>"
            + flow_html(lang, c) +
            f"<hr class=rule><div class=bar><a class='btn p' href='/demo'>{t['back_demo']}</a>"
            f"<a class='btn g' href='/sensibel'>{t['try_stepup']}</a>"
            f"<a class='btn g' href='/gaeste'>{t['try_pin']}</a></div>")
    return page(t["flows_h1"], body, user=user, active="/demo/flows", lang=lang)


# ---------------------------------------------------------------- Read-only Vorschauen
_LOCK = ("<style>html{pointer-events:none;user-select:none}"
         "html,body{min-height:0!important}::-webkit-scrollbar{display:none}</style>")
_LOCK_CARD = _LOCK + "<style>body{align-items:flex-start!important;padding:26px 0}</style>"


def _readonly(html: str, lock: str = _LOCK) -> HTMLResponse:
    return HTMLResponse(html.replace("</body>", lock + "</body>", 1))


@app.get("/demo/preview/login", include_in_schema=False)
def prev_login():
    return _readonly(auth.render_page("login", next="/demo", csrf="").body.decode(), _LOCK_CARD)


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
                        f"<div class=bar><a class='btn p' href='/demo'>{t['back_demo']}</a>"
                        f"<a class='btn g' href='/sensibel'>{t['try_stepup']}</a></div>",
                user=user, active="/app", lang=lang)


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(request: Request, user=Depends(auth.require(mfa=True))):
    lang = lang_of(request)
    t = TEXTS[lang]
    return page("/sensibel", f"<h1>{t['sens_h1']}</h1>"
                             f"<p class=lead>{t['sens_lead'].format(u=user['username'])}</p>"
                             f"<div class=bar><a class='btn p' href='/demo'>{t['back_demo']}</a></div>",
                user=user, active="/sensibel", lang=lang)


@app.get("/gaeste", response_class=HTMLResponse)
def guests(request: Request, _=Depends(auth.require_resource("gaeste"))):
    lang = lang_of(request)
    t = TEXTS[lang]
    return page("/gaeste", f"<h1>{t['guest_h1']}</h1><p class=lead>{t['guest_lead']}</p>"
                           f"<div class=bar><a class='btn p' href='/demo'>{t['back_demo']}</a></div>",
                user=auth.current_user(request), active="/gaeste", lang=lang)


@app.get("/boom", response_class=HTMLResponse)
def boom():
    raise RuntimeError("absichtlicher Fehler für die Demo")   # → themed 500-Seite
