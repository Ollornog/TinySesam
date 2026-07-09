"""Showcase — Referenz-Frontend für TinySesam, im Design der Projekt-Website.

    pip install -e '.[all]'          # Kern (Passwort/PIN/Magic) reicht hier
    uvicorn examples.showcase:app --reload
    # → http://127.0.0.1:8000        (Demo-Login: admin / geheim123)

`/`      = die Projekt-Website (`docs/index.html`) **eins zu eins**, nur mit einem Demo-Knopf.
`/demo`  = das Demo-Frontend: Nav mit Logo + Titel, darunter eine zweite Leiste mit den Testseiten
           (Konto/Admin nur, wenn man die Rechte hat), dann die Panels als read-only Live-Vorschau.

Alles hängt an einer Quelle:
  * **Farben** — `docs/theme.css`. Die Website lädt sie per `<link>`, die App reicht sie als
    `brand_css` in die eingebauten Seiten. Deshalb sehen Login-, Konto-, Admin- und Fehlerseite
    genauso aus wie die Website; eine Farbe ändert man an genau einer Stelle.
  * **Panels** — die Vorschauen sind keine Nachbauten, sondern rendern dieselben Bausteine wie die
    echten Seiten: `auth.render_page(...)` bzw. `admin.render_panel(...)`. Ändert sich ein Panel,
    ändert sich die Vorschau mit. Interaktion ist gesperrt, die Admin-Vorschau liest aus einer Attrappe.
  * **Layout** — Nav, Unterleiste und Vorschau-Rahmen kommen je aus genau einer Funktion.
"""
from pathlib import Path

from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

from tinysesam import TinySesam, TinySesamConfig
from tinysesam.admin import render_panel

REPO = "https://github.com/Ollornog/TinySesam"
DOCS = Path(__file__).resolve().parent.parent / "docs"   # dieselbe Seite wie GitHub Pages
ICON_URL = "/wizard.png"                                 # ein Wert: App-Seiten UND eingebaute Seiten

# Die Farbpalette — dieselbe Datei, die auch die Website per <link> lädt.
THEME = (DOCS / "theme.css").read_text(encoding="utf-8")

# Ergänzt die Tokens um das, was Farbe allein nicht regelt (Typografie, Tiefe).
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
    brand_css=BRAND,                 # ← ein Wert stylt alle eingebauten Seiten
    brand_icon=ICON_URL,             # ← und ein Wert setzt überall das Favicon
    passkey_enabled=False,           # für lokalen HTTP-Test aus
    pin_enabled=True,                # PIN gibt es …
    pin_login=False,                 # … aber NICHT als Login-Methode
    stepup_methods=["pin"],          # … sondern als Bestätigung für sensible Bereiche
    allow_signup=True,
    resource_locks_enabled=True,
    available_roles=["editor", "viewer"],
    cookie_secure=False,             # lokal ohne HTTPS
))
auth.ensure_admin("admin", "geheim123")
auth.set_resource_secret("gaeste", "2468", kind="pin", label="Gäste-Bereich")
auth.set_pin(auth.store.get_user_by_name("admin")["id"], "1234")   # Step-up-PIN für /sensibel

app = FastAPI()
app.include_router(auth.router())
auth.install_error_pages(app)        # themed 403/404/500 …


# ---------------------------------------------------------------- Icons (einmal, überall)
ICON = {
    "github": '<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/>',
    "book": '<path d="M0 1.75A.75.75 0 0 1 .75 1h4.253c1.227 0 2.317.59 3 1.501A3.743 3.743 0 0 1 11.006 1h4.245a.75.75 0 0 1 .75.75v10.5a.75.75 0 0 1-.75.75h-4.507a2.25 2.25 0 0 0-1.591.659l-.622.621a.75.75 0 0 1-1.06 0l-.622-.621A2.25 2.25 0 0 0 5.258 13H.75a.75.75 0 0 1-.75-.75Zm7.251 10.324.004-5.073-.002-2.253A2.25 2.25 0 0 0 5.003 2.5H1.5v9h3.757a3.75 3.75 0 0 1 1.994.574ZM8.755 4.75l-.004 7.322a3.752 3.752 0 0 1 1.992-.572H14.5v-9h-3.495a2.25 2.25 0 0 0-2.25 2.25Z"/>',
    "play": '<path d="M4.5 2.5a.75.75 0 0 1 1.14-.64l7 4.5a.75.75 0 0 1 0 1.28l-7 4.5A.75.75 0 0 1 4.5 11.5Z"/>',
}


def icon(name: str) -> str:
    return f'<svg viewBox="0 0 16 16" aria-hidden="true">{ICON[name]}</svg>'


# ---------------------------------------------------------------- Frontend-Gerüst
_SITE_CSS = """
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);line-height:1.65;font-family:var(--ts-font)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
svg{width:16px;height:16px;fill:currentColor;flex:0 0 auto}
nav{display:flex;align-items:center;justify-content:space-between;gap:14px;
  max-width:900px;margin:0 auto;padding:14px 22px}
nav .brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--ink)}
nav .brand img{width:30px;height:30px}
nav .brand span{font-weight:700;font-size:18px}
nav .brand b{color:var(--accent)}
nav .links{display:flex;align-items:center;gap:10px;font-size:14px}
nav.sub{border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:9px 22px;
  justify-content:flex-start;gap:6px;flex-wrap:wrap;font-size:14px;overflow-x:auto}
nav.sub a{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:8px;
  color:var(--muted);white-space:nowrap}
nav.sub a:hover{background:var(--chip);color:var(--ink);text-decoration:none}
nav.sub a.on{background:var(--chip);color:var(--ink)}
nav.sub code{font-size:.86em;background:none;border:0;padding:0;color:inherit;font-family:var(--ts-mono)}
main{max-width:900px;margin:0 auto;padding:36px 22px 64px}
h1{font-family:var(--ts-serif);font-size:38px;letter-spacing:-.01em;margin:.2em 0 .1em;text-wrap:balance}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);font-weight:600;margin:0 0 6px}
.lead{color:var(--muted);font-size:18px;max-width:56ch;text-wrap:balance}
.bar{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:9px 17px;border-radius:10px;
  font-weight:500;font-size:15px}
.btn.p{background:var(--accent);color:#fff}.btn.p:hover{text-decoration:none;filter:brightness(1.05)}
.btn.g{border:1px solid var(--line);color:var(--ink)}.btn.g:hover{text-decoration:none;border-color:var(--accent)}
.btn.s{padding:6px 13px;font-size:14px}
.muted{color:var(--muted);font-size:14px}
.legend{display:flex;gap:20px;flex-wrap:wrap;margin-top:18px;color:var(--muted);font-size:14px}
.legend span{display:flex;align-items:center;gap:8px}
.legend i.box{width:16px;height:16px;padding:0;display:inline-block}
.flow{margin:0 0 38px}
.flowhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.flowhead h3{font-family:var(--ts-serif);font-size:22px;margin:0}
.pill{font-size:12px;padding:2px 10px;border-radius:999px;border:1px solid var(--line)}
.pill.on{background:var(--ok-bg);color:var(--ok-ink);border-color:transparent}
.pill.off{background:var(--chip);color:var(--muted)}
.flow .muted{margin:6px 0 0}
.chain{list-style:none;display:flex;align-items:center;flex-wrap:wrap;gap:8px;padding:0;margin:16px 0 0}
.chain li{display:flex}
.chain .arr{color:var(--muted);font-size:18px}
.box{display:inline-block;padding:8px 13px;border-radius:10px;font-size:14px;line-height:1.35;
  border:1px solid var(--line);background:var(--card)}
.box code{background:none;border:0;padding:0;font-size:.92em}
.box.do{border-color:var(--accent);color:var(--ink)}
.box.srv{background:var(--chip)}
.box.end{background:var(--ok-bg);color:var(--ok-ink);border-color:transparent}
.flow .note{margin:12px 0 0;color:var(--muted);font-size:14px;max-width:70ch}
.card2{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:14px 0}
.card2 pre{white-space:pre-wrap;word-break:break-word;font-family:var(--ts-mono);font-size:13px;
  color:var(--muted);margin:8px 0 0}
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
footer{max-width:900px;margin:0 auto;padding:24px 22px 60px;border-top:1px solid var(--line);
  color:var(--muted);font-size:14px}
"""

# Zweite Leiste: die Testseiten. `need` = wann der Punkt überhaupt sichtbar ist.
TESTPAGES = [
    ("/demo", "Übersicht", "all"),
    ("/app", "<code>/app</code> · require_user", "all"),
    ("/sensibel", "<code>/sensibel</code> · Step-up", "all"),
    ("/gaeste", "<code>/gaeste</code> · PIN, kein Konto", "all"),
    ("/demo/flows", "Login-Flows", "all"),
    ("/auth/account", "Konto", "user"),
    ("/auth/admin", "Admin-Panel", "admin"),
    ("/gibtsnicht", "404", "all"),
    ("/boom", "500", "all"),
]


def _subnav(user, active) -> str:
    out = []
    for href, label, need in TESTPAGES:
        if need == "user" and not user:
            continue
        if need == "admin" and not (user and auth.is_admin(user)):
            continue
        out.append(f"<a class='{'on' if href == active else ''}' href='{href}'>{label}</a>")
    return f"<nav class=sub>{''.join(out)}</nav>"


def page(title, body, user=None, active=""):
    links = (f"<span class=muted>{user['username']}</span>"
             "<a class='btn g s' href='/auth/account'>Konto</a>"
             "<a class='btn g s' href='/auth/logout'>Abmelden</a>"
             if user else
             "<a class='btn g s' href='/auth/register'>Registrieren</a>"
             "<a class='btn p s' href='/auth/login'>Anmelden</a>")
    return HTMLResponse(
        f"<!doctype html><html lang=de><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<link rel=icon href='{ICON_URL}'><link rel=stylesheet href='/theme.css'>"
        f"<title>{title} · TinySesam</title><style>{_SITE_CSS}</style></head><body>"
        f"<nav><a class=brand href='/demo'><img src='{ICON_URL}' alt=''>"
        f"<span><b>Tiny</b>Sesam</span></a><span class=links>{links}</span></nav>"
        f"{_subnav(user, active)}"
        f"<main>{body}</main>"
        f"<footer>Demo-Frontend · <a href='/'>Projektseite</a> · "
        f"<a href='{REPO}'>GitHub</a> · MIT</footer></body></html>")


# ---------------------------------------------------------------- `/` = die Website, 1:1
_DEMO_BTN = f'<a class="btn primary" href="/demo">{icon("play")}Live-Demo</a>'


@app.get(ICON_URL, include_in_schema=False)
def wizard():
    return FileResponse(DOCS / "wizard.png", media_type="image/png")


@app.get("/theme.css", include_in_schema=False)
def theme():
    return FileResponse(DOCS / "theme.css", media_type="text/css")


@app.get("/", response_class=HTMLResponse)
def landing():
    """Unveränderte Projekt-Website — einzige Ergänzung: der Demo-Knopf im Hero."""
    try:
        html = (DOCS / "index.html").read_text(encoding="utf-8")
    except FileNotFoundError:
        return HTMLResponse("<h1>TinySesam</h1><a href='/demo'>Live-Demo</a>")
    html = html.replace('<div class="cta">', f'<div class="cta">{_DEMO_BTN}', 1)
    # Der Demo-Knopf ist hier der Primärknopf; GitHub rückt eine Stufe zurück.
    html = html.replace('class="btn primary" id="cta-github"', 'class="btn ghost" id="cta-github"', 1)
    return HTMLResponse(html)


# ---------------------------------------------------------------- `/demo` = das Demo-Frontend
def shot(title, blurb, src, open_url, height, scale, tag="read-only"):
    """Live-Vorschau einer echten Seite: iframe + Glasscheibe darüber (keine Interaktion).

    `height` ist nur die Starthöhe — `_FIT_JS` misst nach dem Laden den echten Inhalt und zieht
    den Rahmen auf, damit nichts abgeschnitten wird."""
    return (f"<section class=shot><div class=head><div><h2>{title}</h2><p>{blurb}</p></div>"
            f"<a class='btn g s' href='{open_url}'>Öffnen →</a></div>"
            f"<div class=frame data-scale='{scale}' style='height:{height}px'>"
            f"<iframe src='{src}' tabindex=-1 scrolling=no title='{title}'"
            f" style='width:{100 / scale:.0f}%;height:{height / scale:.0f}px;transform:scale({scale})'></iframe>"
            f"<span class=glass></span><span class=tag>{tag}</span></div></section>")


# Passt jeden Vorschau-Rahmen an die tatsächliche Inhaltshöhe an (gleiches Origin → auslesbar).
_FIT_JS = """<script>
function tsFit(frame){
  const f=frame.querySelector('iframe'), s=parseFloat(frame.dataset.scale)||1;
  try{
    const d=f.contentDocument; if(!d||!d.body) return;
    f.style.height='0px';
    const h=Math.max(d.body.scrollHeight, d.documentElement.scrollHeight);
    f.style.height=h+'px'; frame.style.height=Math.ceil(h*s)+'px';
  }catch(e){}
}
document.querySelectorAll('.frame').forEach(fr=>{
  const f=fr.querySelector('iframe');
  f.addEventListener('load',()=>{tsFit(fr); setTimeout(()=>tsFit(fr),250);});  // 2. Lauf: nach Web-Fonts
});
addEventListener('resize',()=>document.querySelectorAll('.frame').forEach(tsFit));
</script>"""


@app.get("/demo", response_class=HTMLResponse)
def demo(request: Request):
    user = auth.current_user(request)
    hello = (f"<p class=lead>Angemeldet als <b>{user['username']}</b> — die Testseiten oben sind jetzt "
             f"auch wirklich begehbar.</p>" if user else
             "<p class=lead>Alles, was TinySesam mitbringt, in einem Frontend. Die Panels unten sind "
             "<b>echte Seiten</b>, live gerendert — nur die Bedienung ist gesperrt. "
             "Zum Mitmachen anmelden: <b>admin / geheim123</b>.</p>")
    panels = (
        shot("Login-Panel", "Die eingebaute Anmeldeseite zeigt <b>genau die Methoden, die in der Config "
             "aktiv sind</b> — hier Passwort, PIN und Login-Link per E-Mail. Ohne <code>magiclink_enabled</code> "
             "oder <code>pin_enabled</code> verschwinden die entsprechenden Felder ersatzlos. Das Kennungsfeld "
             "beschriftet sich nach <code>login_identifier</code>.",
             "/demo/preview/login", "/auth/login", 430, 0.86)
        + shot("Konto-Panel", "Selbstverwaltung unter <code>/auth/account</code>: Passwort, PIN, "
               "2FA + Recovery-Codes, Passkeys, API-Keys und die eigenen Sitzungen.",
               "/demo/preview/account", "/auth/account", 470, 0.8)
        + shot("Admin-Panel", "Benutzer &amp; Rollen, Sitzungen, Härtungs-Schwellen, Update, Audit-Log. "
               "Wahlweise nur als JSON-API, wenn du dein eigenes Panel baust.",
               "/demo/preview/admin", "/auth/admin", 520, 0.66, tag="read-only · Beispieldaten"))
    body = (f"<h1>Live-Demo</h1>{hello}"
            f"<div class=bar><a class='btn g' href='/'>← Projektseite</a>"
            f"<a class='btn g' href='{REPO}'>{icon('github')}GitHub</a>"
            f"<a class='btn g' href='{REPO}#readme'>{icon('book')}Doku</a></div>"
            f"<hr class=rule>{panels}{_FIT_JS}")
    return page("Live-Demo", body, user=user, active="/demo")


# ---------------------------------------------------------------- Read-only Vorschauen
# `min-height:0` ist wichtig: die Login-Karte zentriert sich sonst über 100vh und die gemessene
# Inhaltshöhe wäre immer die Fensterhöhe statt die der Karte.
_LOCK = ("<style>html{pointer-events:none;user-select:none}"
         "html,body{min-height:0!important}::-webkit-scrollbar{display:none}</style>")
_LOCK_CARD = _LOCK + "<style>body{align-items:flex-start!important;padding:26px 0}</style>"


def _readonly(html: str, lock: str = _LOCK) -> HTMLResponse:
    return HTMLResponse(html.replace("</body>", lock + "</body>", 1))


@app.get("/demo/preview/login", include_in_schema=False)
def prev_login():
    resp = auth.render_page("login", next="/demo", csrf="")     # derselbe Renderer wie /auth/login
    return _readonly(resp.body.decode(), _LOCK_CARD)


@app.get("/demo/preview/account", include_in_schema=False)
def prev_account():
    demo_user = {"id": 0, "username": "melli", "display_name": "", "is_admin": 0}
    resp = auth.render_page("account", user=demo_user, methods=auth.cfg.enabled_methods(),
                            has_totp=True, has_pin=True, is_admin=False,
                            admin_path=auth.cfg.admin_path, csrf="")
    return _readonly(resp.body.decode())


@app.get("/demo/preview/admin", include_in_schema=False)
def prev_admin():
    # dieselbe Panel-UI wie /auth/admin, nur gegen die Attrappen-API unten
    return _readonly(render_panel(auth, "/demo/preview/adminapi"))


# Attrappen-API: liest Beispieldaten, schreibt nie. Hält die Vorschau ohne Anmeldung am Leben.
_FAKE = {
    "/api/users": [
        {"id": 1, "username": "admin", "is_admin": True, "is_service": False, "roles": [], "disabled": False},
        {"id": 2, "username": "melli", "is_admin": False, "is_service": False, "roles": ["editor"], "disabled": False},
        {"id": 3, "username": "martin", "is_admin": False, "is_service": False, "roles": ["viewer"], "disabled": True},
        {"id": 4, "username": "backup-daemon", "is_admin": False, "is_service": True, "roles": ["reader"], "disabled": False},
    ],
    "/api/sessions": [{"id": 1, "username": "admin", "method": "password", "ip": "10.0.0.7",
                       "created": 1_770_000_000, "expires": 1_770_600_000}],
    "/api/security": {"max_login_attempts": 5, "lockout_window_sec": 900, "rate_limit_max": 30},
    "/api/update": {"current": "0.10.0", "latest": "0.10.0", "available": False, "mode": "manual", "pin": ""},
    "/api/audit": [{"ts": 1_770_000_000, "event": "login", "username": "admin", "ip": "10.0.0.7", "detail": ""}],
    "/api/resources": [{"name": "gaeste", "kind": "pin", "label": "Gäste-Bereich"}],
}


@app.get("/demo/preview/adminapi/api/{path:path}", include_in_schema=False)
def prev_api(path: str):
    return JSONResponse(_FAKE.get(f"/api/{path}", []))


@app.post("/demo/preview/adminapi/api/{path:path}", include_in_schema=False)
def prev_api_ro(path: str):
    return JSONResponse({"detail": "Vorschau — schreibende Aktionen sind hier abgeschaltet."}, status_code=403)


# ---------------------------------------------------------------- Die geschützten Beispiel-Seiten
@app.get("/app", response_class=HTMLResponse)
def protected(user=Depends(auth.require_user)):
    return page("Bereich", f"""
      <h1>Hallo {user['username']} 👋</h1>
      <p class=lead>Eingeloggt — diese Route ist mit <code>Depends(auth.require_user)</code> geschützt,
        mehr steht da nicht.</p>
      <div class=bar><a class='btn p' href='/demo'>← Zur Demo</a>
        <a class='btn g' href='/sensibel'>Sensibler Bereich</a></div>""", user=user, active="/app")


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(user=Depends(auth.require(mfa=True))):
    return page("Sensibel", f"""
      <h1>🔒 Sensibler Bereich</h1>
      <p class=lead>{user['username']}, du hast dich soeben frisch bestätigt (Step-up / Sudo-Frische).
        Nach <code>stepup_max_age_sec</code> fragt TinySesam erneut.</p>
      <div class=bar><a class='btn p' href='/demo'>← Zur Demo</a>
        <a class='btn g' href='/app'>Bereich</a></div>""", user=user, active="/sensibel")


@app.get("/gaeste", response_class=HTMLResponse)
def guests(request: Request, _=Depends(auth.require_resource("gaeste"))):
    return page("Gäste", """
      <h1>🔑 Gäste-Bereich</h1>
      <p class=lead>Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.
        Genau richtig für „diese eine Seite soll nicht offen im Netz stehen“.</p>
      <div class=bar><a class='btn p' href='/demo'>← Zur Demo</a>
        <a class='btn g' href='/'>Projektseite</a></div>""",
        user=auth.current_user(request), active="/gaeste")


def chain(*steps) -> str:
    """Eine Kette aus Kästchen mit Pfeilen. `steps` sind (kind, text) — kind: do | srv | end."""
    out = []
    for i, (kind, text) in enumerate(steps):
        if i:
            out.append("<li class=arr aria-hidden=true>&rarr;</li>")
        out.append(f"<li><span class='box {kind}'>{text}</span></li>")
    return f"<ol class=chain>{''.join(out)}</ol>"


def flow(title, why, steps_html, active: bool, note="") -> str:
    pill = ("<span class='pill on'>in dieser Demo aktiv</span>" if active
            else "<span class='pill off'>hier aus</span>")
    note = f"<p class=note>{note}</p>" if note else ""
    return (f"<section class=flow><div class=flowhead><h3>{title}</h3>{pill}</div>"
            f"<p class=muted>{why}</p>{steps_html}{note}</section>")


_IDENT_TEXT = {"username": "Benutzername", "email": "E-Mail", "both": "Benutzername oder E-Mail"}


@app.get("/demo/flows", response_class=HTMLResponse)
def flows(request: Request):
    """Die Login-Wege als Diagramm. Was „aktiv" ist, liest die Seite aus der laufenden Config —
    die Grafik kann also nicht behaupten, was die Demo nicht tut."""
    c = auth.cfg
    m = c.enabled_methods()
    parts = [
        flow("Passwort", "Der klassische Weg. Ein Erstfaktor genügt, solange keine Kette gesetzt ist.",
             chain(("do", "Kennung + Passwort"), ("srv", "<code>/auth/login</code>"),
                   ("end", "Sitzung"), ("end", "geschützte Route")),
             "password" in m,
             f"Das Kennungsfeld akzeptiert hier: <b>{_IDENT_TEXT[c.login_identifier]}</b>."),

        flow("PIN als Erstfaktor", "Statt Passwort mit einer kurzen PIN anmelden — eigener, strenger Lockout.",
             chain(("do", "Kennung + PIN"), ("srv", "<code>/auth/pin</code>"), ("end", "Sitzung")),
             "pin" in m,
             "Hier bewusst aus (<code>pin_login=False</code>): die PIN existiert, ist aber "
             "<b>kein Login-Weg</b> — sie bestätigt nur sensible Bereiche."),

        flow("Zweiter Faktor (TOTP)", "Nach dem Erstfaktor ein Einmalcode aus der Authenticator-App.",
             chain(("do", "Erstfaktor"), ("srv", "<code>/auth/totp</code>"), ("do", "6-stelliger Code"),
                   ("end", "Sitzung <i>mfa_ok</i>")),
             c.totp_enabled,
             "Wer keine 2FA eingerichtet hat, überspringt den Schritt. Recovery-Codes gehen ebenso."),

        flow("Step-up für sensible Bereiche",
             "Du bist eingeloggt — der Bereich verlangt trotzdem eine frische Bestätigung.",
             chain(("do", "<code>/sensibel</code>"), ("srv", "Frische abgelaufen?"),
                   ("srv", "<code>/auth/reauth</code>"), ("do", "PIN"), ("end", "Bereich offen")),
             True,
             f"<code>require(mfa=True)</code> mit <code>stepup_methods={c.stepup_methods}</code>. "
             "Ohne diese Einschränkung fragt TinySesam nach dem stärksten Verfahren, das der Nutzer "
             "eingerichtet hat (TOTP → PIN → Passwort). Nach <code>stepup_max_age_sec</code> erneut."),

        flow("Faktor-Kette pro Route", "Eine Route verlangt mehrere Faktoren in fester Reihenfolge.",
             chain(("do", "Passwort"), ("srv", "Kette unvollständig"), ("srv", "<code>/auth/pin</code>"),
                   ("do", "PIN"), ("end", "Route offen")),
             True,
             "<code>Depends(auth.require(factors=[\"password\", \"pin\"]))</code> — wer schon eingeloggt "
             "ist, bekommt nur das fehlende Feld, nicht noch einmal die ganze Login-Seite."),

        flow("Geteiltes Geheimnis (ohne Konto)", "Ein Bereich, eine PIN. Keine Registrierung, kein Benutzer.",
             chain(("do", "<code>/gaeste</code>"), ("srv", "<code>/auth/resource/gaeste</code>"),
                   ("do", "PIN 2468"), ("end", "Bereich offen, zeitlich begrenzt")),
             c.resource_locks_enabled,
             "<code>Depends(auth.require_resource(\"gaeste\"))</code> — hängt an einem eigenen Cookie, "
             "nicht an einer Sitzung."),

        flow("Login-Link per E-Mail", "Adresse eingeben, Einmal-Link anklicken, drin.",
             chain(("do", "E-Mail"), ("srv", "Mailer"), ("do", "Link klicken"), ("end", "Sitzung")),
             c.magiclink_enabled,
             "Hier aus: die Demo läuft <b>ganz ohne E-Mail</b> "
             "(<code>TinySesamConfig.local_accounts()</code>) — also weder Login-Link noch "
             "Passwort-vergessen, und kein Mailer, der etwas verschicken müsste."),

        flow("Externer IdProvider", "OIDC oder SAML: TinySesam ist der Client, nicht der Provider.",
             chain(("do", "Knopf"), ("srv", "IdP (PocketID, Entra, ADFS …)"), ("srv", "Callback"),
                   ("end", "Sitzung + Rollen aus Gruppen")),
             c.oidc_enabled or c.saml_enabled,
             "Gruppen des IdP lassen sich auf lokale Rollen mappen — dieselben "
             "<code>require_role(...)</code>-Guards wie überall."),

        flow("Forward-Auth (fremde Apps)", "Der Reverse-Proxy fragt vor jedem Request nach.",
             chain(("do", "Request an fremde App"), ("srv", "Proxy → <code>/auth/forward</code>"),
                   ("end", "200 + Remote-User"), ("end", "App antwortet")),
             c.forward_auth_enabled,
             "Ohne Sitzung: 401 + <code>X-TinySesam-Location</code> → der Proxy schickt zum Login."),
    ]
    body = (f"<h1>Login-Flows</h1>"
            f"<p class=lead>Jeder Weg ist ein eigener Schalter, und sie lassen sich kombinieren. "
            f"Diese Demo läuft mit <code>login_identifier=\"{c.login_identifier}\"</code>, "
            f"<code>pin_login={c.pin_login}</code> und <code>stepup_methods={c.stepup_methods}</code> — "
            f"die Markierungen unten liest die Seite direkt aus dieser Config.</p>"
            f"<div class=legend><span><i class='box do'></i> du tust etwas</span>"
            f"<span><i class='box srv'></i> TinySesam</span>"
            f"<span><i class='box end'></i> Ergebnis</span></div>"
            f"<hr class=rule>{''.join(parts)}<hr class=rule>"
            f"<div class=bar><a class='btn p' href='/demo'>← Zur Demo</a>"
            f"<a class='btn g' href='/sensibel'>Step-up ausprobieren</a>"
            f"<a class='btn g' href='/gaeste'>Gäste-PIN ausprobieren</a></div>")
    return page("Login-Flows", body, user=auth.current_user(request), active="/demo/flows")


@app.get("/boom", response_class=HTMLResponse)
def boom():
    raise RuntimeError("absichtlicher Fehler für die Demo")   # → themed 500-Seite
