"""Showcase — Referenz-Frontend für TinySesam, im Design der Projekt-Website.

    pip install -e '.[all]'          # Kern (Passwort/PIN/Magic) reicht hier
    uvicorn examples.showcase:app --reload
    # → http://127.0.0.1:8000        (Demo-Login: admin / geheim123)

`/`      = die Projekt-Website (`docs/index.html`) **eins zu eins**, nur mit einem Demo-Knopf.
`/demo`  = das Demo-Frontend: Nav mit Logo + Titel, Anmelden/Registrieren, darunter die Panels
           (Login, Konto, Admin) als **read-only Live-Vorschau**.

Wichtig: die Vorschauen sind keine Screenshots und keine Nachbauten. Sie rendern dieselben
Bausteine wie die echten Seiten — `auth.render_page(...)` für Login/Konto, `admin.render_panel(...)`
fürs Panel. Ändert sich ein Panel, ändert sich die Demo mit. Interaktion ist gesperrt
(`pointer-events`), die Admin-Vorschau spricht mit einer Attrappen-API, die nur liest.
"""
import re
from pathlib import Path

from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

from tinysesam import TinySesam, TinySesamConfig
from tinysesam.admin import render_panel

REPO = "https://github.com/Ollornog/TinySesam"
DOCS = Path(__file__).resolve().parent.parent / "docs"   # dieselbe Seite wie GitHub Pages

# Eine Palette für ALLES (Cremeweiß/Altrosa, Light+Dark) — wie die Projekt-Website.
_TOKENS = """
:root{--paper:#f6f1ec;--card:#fbf8f4;--ink:#2b2a3a;--muted:#6f6a7d;--accent:#b0566f;
  --accent-2:#d98c93;--line:#e6ddd4;--chip:#efe7de}
@media (prefers-color-scheme:dark){:root{--paper:#1a1922;--card:#221f2c;--ink:#ece9f2;--muted:#a49eb4;
  --accent:#e0919c;--accent-2:#b0566f;--line:#2f2c3b;--chip:#2a2735}}
"""

# brand_css: re-skinnt die EINGEBAUTEN TinySesam-Seiten (Login/PIN/TOTP/Konto/Admin/Fehler).
BRAND = _TOKENS + """
body{background:var(--paper);color:var(--ink);
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.card{background:var(--card);border-color:var(--line);border-radius:16px;
  box-shadow:0 14px 44px rgba(90,60,70,.10)}
h1{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;color:var(--ink)}
label,.hint,.or{color:var(--muted)}
input{background:var(--paper);color:var(--ink);border-color:var(--line)}
input:focus{outline:2px solid var(--accent);border-color:var(--accent)}
button,.btn2{background:var(--accent);color:#fff}
.btn2{background:transparent;color:var(--ink);border:1px solid var(--line)}
button:hover{filter:brightness(1.05)}
a{color:var(--accent)}
.err{background:#f7dde3;color:#a12048}.ok{background:#e2efe4;color:#2f7d4f}
@media (prefers-color-scheme:dark){.err{background:#3a1520;color:#f5a3b0}.ok{background:#12331f;color:#7ee0a1}}
"""

auth = TinySesam(TinySesamConfig(
    db_path="/tmp/tinysesam-showcase.db",
    rp_name="TinySesam",
    lang="de",
    brand_css=BRAND,                 # ← ein Wert stylt alle eingebauten Seiten
    password_enabled=True,
    pin_enabled=True,
    passkey_enabled=False,           # für lokalen HTTP-Test aus
    oidc_enabled=False,
    magiclink_enabled=True,          # Login-Link per E-Mail (hier: Konsolen-Mailer)
    allow_signup=True,
    resource_locks_enabled=True,
    available_roles=["editor", "viewer"],
    cookie_secure=False,             # lokal ohne HTTPS
))
auth.ensure_admin("admin", "geheim123")
auth.set_mailer(lambda to, subject, text, html=None: print(f"\n=== MAIL an {to}: {subject} ===\n{text}\n"))
auth.set_resource_secret("gaeste", "2468", kind="pin", label="Gäste-Bereich")

app = FastAPI()
app.include_router(auth.router())
auth.install_error_pages(app)        # themed 403/404/500 …


# ---------------------------------------------------------------- Frontend-Gerüst
_SITE_CSS = _TOKENS + """
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);line-height:1.65;
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
nav{display:flex;align-items:center;justify-content:space-between;gap:14px;
  max-width:900px;margin:0 auto;padding:14px 22px;border-bottom:1px solid var(--line)}
nav .brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--ink)}
nav .brand img{width:30px;height:30px}
nav .brand span{font-weight:700;font-size:18px}
nav .brand b{color:var(--accent)}
nav .links{display:flex;align-items:center;gap:10px;font-size:14px}
main{max-width:900px;margin:0 auto;padding:36px 22px 64px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  font-size:38px;letter-spacing:-.01em;margin:.2em 0 .1em;text-wrap:balance}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);
  font-weight:600;margin:0 0 6px}
.lead{color:var(--muted);font-size:18px;max-width:56ch;text-wrap:balance}
.bar{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn{display:inline-block;padding:9px 17px;border-radius:10px;font-weight:500;font-size:15px}
.btn.p{background:var(--accent);color:#fff}.btn.p:hover{text-decoration:none;filter:brightness(1.05)}
.btn.g{border:1px solid var(--line);color:var(--ink)}.btn.g:hover{text-decoration:none;border-color:var(--accent)}
.btn.s{padding:6px 13px;font-size:14px}
.muted{color:var(--muted);font-size:14px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.86em;background:var(--chip);
  border:1px solid var(--line);border-radius:5px;padding:1px 5px}
hr.rule{height:1px;background:var(--line);border:0;margin:44px 0}
/* Read-only Live-Vorschau eines echten Panels */
.shot{margin:0 0 34px}
.shot .head{display:flex;align-items:baseline;justify-content:space-between;gap:14px;
  flex-wrap:wrap;margin-bottom:12px}
.shot .head p{margin:2px 0 0;color:var(--muted);font-size:14.5px;max-width:60ch}
.frame{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:14px;
  background:var(--card);box-shadow:0 12px 36px rgba(90,60,70,.09)}
.frame iframe{display:block;border:0;transform-origin:top left}
.frame .glass{position:absolute;inset:0;cursor:default}
.frame .tag{position:absolute;right:10px;top:10px;background:var(--chip);border:1px solid var(--line);
  border-radius:999px;padding:3px 10px;font-size:12px;color:var(--muted)}
footer{max-width:900px;margin:0 auto;padding:24px 22px 60px;border-top:1px solid var(--line);
  color:var(--muted);font-size:14px}
"""


def page(title, body, user=None):
    links = (f"<span class=muted>{user['username']}</span>"
             "<a class='btn g s' href='/auth/account'>Konto</a>"
             "<a class='btn g s' href='/auth/logout'>Abmelden</a>"
             if user else
             "<a class='btn g s' href='/auth/register'>Registrieren</a>"
             "<a class='btn p s' href='/auth/login'>Anmelden</a>")
    return HTMLResponse(
        f"<!doctype html><html lang=de><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<link rel=icon href='/wizard.png'><title>{title} · TinySesam</title>"
        f"<style>{_SITE_CSS}</style></head><body>"
        f"<nav><a class=brand href='/demo'><img src='/wizard.png' alt=''>"
        f"<span><b>Tiny</b>Sesam</span></a><span class=links>{links}</span></nav>"
        f"<main>{body}</main>"
        f"<footer>Demo-Frontend · <a href='/'>Projektseite</a> · <a href='{REPO}'>GitHub</a> · MIT</footer>"
        f"</body></html>")


# ---------------------------------------------------------------- `/` = die Website, 1:1
_GH_BTN = ('<a class="btn primary" href="https://github.com/Ollornog/TinySesam">View on GitHub</a>')
_DEMO_BTN = ('<a class="btn primary" href="/demo">▶ Live-Demo</a>'
             '<a class="btn ghost" href="https://github.com/Ollornog/TinySesam">View on GitHub</a>')


@app.get("/wizard.png", include_in_schema=False)
def wizard():
    return FileResponse(DOCS / "wizard.png", media_type="image/png")


@app.get("/", response_class=HTMLResponse)
def landing():
    """Unveränderte Projekt-Website — einzige Ergänzung: der Demo-Knopf im Hero."""
    try:
        html = (DOCS / "index.html").read_text(encoding="utf-8")
    except FileNotFoundError:
        return HTMLResponse("<h1>TinySesam</h1><a href='/demo'>Live-Demo</a>")
    if _GH_BTN in html:
        html = html.replace(_GH_BTN, _DEMO_BTN, 1)
    else:                                     # Website umgebaut → Knopf trotzdem einhängen
        html = html.replace('<div class="cta">', f'<div class="cta">{_DEMO_BTN}', 1)
    return HTMLResponse(html)


# ---------------------------------------------------------------- `/demo` = das Demo-Frontend
def shot(title, blurb, src, open_url, height, scale, tag="read-only"):
    """Live-Vorschau einer echten Seite: iframe + Glasscheibe darüber (keine Interaktion)."""
    return (f"<section class=shot><div class=head><div><h2>{title}</h2><p>{blurb}</p></div>"
            f"<a class='btn g s' href='{open_url}'>Öffnen →</a></div>"
            f"<div class=frame style='height:{height}px'>"
            f"<iframe src='{src}' loading=lazy tabindex=-1 scrolling=no title='{title}'"
            f" style='width:{100 / scale:.0f}%;height:{height / scale:.0f}px;transform:scale({scale})'></iframe>"
            f"<span class=glass></span><span class=tag>{tag}</span></div></section>")


@app.get("/demo", response_class=HTMLResponse)
def demo(request: Request):
    user = auth.current_user(request)
    hello = (f"<p class=lead>Angemeldet als <b>{user['username']}</b> — die Bereiche unten sind jetzt "
             f"auch wirklich begehbar.</p>" if user else
             "<p class=lead>Alles, was TinySesam mitbringt, in einem Frontend. Die Panels unten sind "
             "<b>echte Seiten</b>, live gerendert — nur die Bedienung ist gesperrt. "
             "Zum Mitmachen anmelden: <b>admin / geheim123</b>.</p>")
    panels = (
        shot("Login-Panel", "Die eingebaute Anmeldeseite. Zeigt genau die Methoden, die in der Config "
             "aktiv sind — hier Passwort, PIN und Login-Link per E-Mail.",
             "/demo/preview/login", "/auth/login", 430, 0.86)
        + shot("Konto-Panel", "Selbstverwaltung unter <code>/auth/account</code>: Passwort, PIN, "
               "2FA + Recovery-Codes, Passkeys, API-Keys und die eigenen Sitzungen.",
               "/demo/preview/account", "/auth/account", 470, 0.8)
        + shot("Admin-Panel", "Benutzer &amp; Rollen, Sitzungen, Härtungs-Schwellen, Update, Audit-Log. "
               "Wahlweise nur als JSON-API, wenn du dein eigenes Panel baust.",
               "/demo/preview/admin", "/auth/admin", 520, 0.66, tag="read-only · Beispieldaten"))
    routes = ("<hr class=rule><section><h2>Geschützte Routen zum Ausprobieren</h2>"
              "<div class=bar>"
              "<a class='btn g' href='/app'>/app — <code>require_user</code></a>"
              "<a class='btn g' href='/sensibel'>/sensibel — Step-up</a>"
              "<a class='btn g' href='/gaeste'>/gaeste — PIN 2468, kein Konto</a>"
              "<a class='btn g' href='/gibtsnicht'>404</a>"
              "<a class='btn g' href='/boom'>500</a></div></section>")
    body = (f"<h1>Live-Demo</h1>{hello}"
            f"<div class=bar><a class='btn g' href='/'>← Projektseite</a>"
            f"<a class='btn g' href='{REPO}'>GitHub</a></div><hr class=rule>{panels}{routes}")
    return page("Live-Demo", body, user=user)


# ---------------------------------------------------------------- Read-only Vorschauen
_LOCK = "<style>html{pointer-events:none;user-select:none}::-webkit-scrollbar{display:none}</style>"


def _readonly(html: str) -> HTMLResponse:
    return HTMLResponse(html.replace("</body>", _LOCK + "</body>", 1))


@app.get("/demo/preview/login", include_in_schema=False)
def prev_login():
    resp = auth.render_page("login", next="/demo", csrf="")     # derselbe Renderer wie /auth/login
    return _readonly(resp.body.decode())


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
        <a class='btn g' href='/sensibel'>Sensibler Bereich</a>
        <a class='btn g' href='/auth/account'>Konto</a></div>""", user=user)


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(user=Depends(auth.require(mfa=True))):
    return page("Sensibel", f"""
      <h1>🔒 Sensibler Bereich</h1>
      <p class=lead>{user['username']}, du hast dich soeben frisch bestätigt (Step-up / Sudo-Frische).
        Nach <code>stepup_max_age_sec</code> fragt TinySesam erneut.</p>
      <div class=bar><a class='btn p' href='/demo'>← Zur Demo</a>
        <a class='btn g' href='/app'>Bereich</a></div>""", user=user)


@app.get("/gaeste", response_class=HTMLResponse)
def guests(request: Request, _=Depends(auth.require_resource("gaeste"))):
    return page("Gäste", """
      <h1>🔑 Gäste-Bereich</h1>
      <p class=lead>Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.
        Genau richtig für „diese eine Seite soll nicht offen im Netz stehen“.</p>
      <div class=bar><a class='btn p' href='/demo'>← Zur Demo</a>
        <a class='btn g' href='/'>Projektseite</a></div>""", user=auth.current_user(request))


@app.get("/boom", response_class=HTMLResponse)
def boom():
    raise RuntimeError("absichtlicher Fehler für die Demo")   # → themed 500-Seite
