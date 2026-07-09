"""Showcase = vorzeigbare Referenz-App im Design der Projekt-Website (GitHub Pages).

    pip install -e '.[all]'          # oder Kern: nur Passwort/PIN/Magic reicht hier
    uvicorn examples.showcase:app --reload
    # → http://127.0.0.1:8000   (Landing = die Website selbst; admin / geheim123)

Die Startseite ist buchstäblich `docs/index.html` — dieselbe Seite wie auf GitHub Pages —, nur mit
demo-tauglichen Buttons im Hero. Von dort führt eine **geführte Tour** (`/demo`) Schritt für Schritt
durch alle Funktionen. Alle Seiten (auch die eingebauten Login-/PIN-/TOTP-/Konto-/Fehlerseiten) tragen
über `brand_css` / `brand_head` denselben Look. Gedacht als Kopiervorlage für eigene Apps.
"""
import re
from pathlib import Path

from fastapi import FastAPI, Depends, Request
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse

from tinysesam import TinySesam, TinySesamConfig

REPO = "https://github.com/Ollornog/TinySesam"
DOCS = Path(__file__).resolve().parent.parent / "docs"   # dieselbe Seite wie GitHub Pages
TOUR_COOKIE = "ts_tour"

# Eine Palette für ALLES (Cremeweiß/Altrosa, Light+Dark) — wie die Projekt-Website.
_TOKENS = """
:root{--paper:#f6f1ec;--card:#fbf8f4;--ink:#2b2a3a;--muted:#6f6a7d;--accent:#b0566f;
  --accent-2:#d98c93;--line:#e6ddd4;--chip:#efe7de}
@media (prefers-color-scheme:dark){:root{--paper:#1a1922;--card:#221f2c;--ink:#ece9f2;--muted:#a49eb4;
  --accent:#e0919c;--accent-2:#b0566f;--line:#2f2c3b;--chip:#2a2735}}
"""

# Die Tour-Leiste erscheint auf JEDER Seite, solange die Tour läuft — auch auf den eingebauten.
_TOURBAR_CSS = """
.tourbar{position:sticky;top:0;z-index:99;display:flex;align-items:center;justify-content:center;
  gap:14px;flex-wrap:wrap;padding:9px 16px;background:var(--accent);color:#fff;font-size:14px}
.tourbar a{color:#fff;text-decoration:underline;font-weight:500}
.tourbar .step{opacity:.85}
"""

# Baut die Leiste im Browser, wenn das Tour-Cookie gesetzt ist (klein genug für den <head>).
_TOURBAR_JS = """<script>document.addEventListener('DOMContentLoaded',function(){
var m=document.cookie.match(/(?:^|; )ts_tour=(\\d+)/);
if(!m||location.pathname.indexOf('/demo')===0)return;
var b=document.createElement('div');b.className='tourbar';
b.innerHTML="<span class=step>\\ud83e\\uddd9 Demo-Tour \\u00b7 Schritt "+m[1]+" von __N__</span>"
 +"<a href='/demo'>Zur\\u00fcck zur Tour \\u2192</a>";
document.body.insertBefore(b,document.body.firstChild);});</script>"""

# brand_css: re-skinnt die EINGEBAUTEN TinySesam-Seiten (Login/PIN/TOTP/Konto/Fehler) im selben Look.
BRAND = _TOKENS + _TOURBAR_CSS + """
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
    brand_head="",                   # ← wird unten mit der Tour-Leiste befüllt
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


# ---------------------------------------------------------------- Die geführte Tour
# (Schritt, Titel, Erklärung, Ziel-URL, Hinweis)
TOUR = [
    ("Anmelden", "Die eingebaute Login-Seite — Passwort oder PIN, „Angemeldet bleiben“, "
     "Login-Link per E-Mail. Vollständig im Look der App, weil <code>brand_css</code> gesetzt ist.",
     "/auth/login?next=/demo", "Demo-Konto: <b>admin</b> / <b>geheim123</b>"),
    ("Geschützter Bereich", "Eine ganz normale Route hinter <code>Depends(auth.require_user)</code>. "
     "Nicht-Angemeldete landen automatisch auf der Login-Seite.",
     "/app?tour=1", ""),
    ("Step-up / Sudo-Frische", "Sensible Route hinter <code>Depends(auth.require(mfa=True))</code>: "
     "verlangt eine <i>frische</i> Bestätigung, auch wenn die Sitzung noch gilt.",
     "/sensibel?tour=1", ""),
    ("Gäste-PIN ohne Konto", "Ein geteiltes Ressourcen-Geheimnis — <code>require_resource(\"gaeste\")</code>. "
     "Kein Benutzerkonto, nur eine PIN für den Bereich.",
     "/gaeste?tour=1", "PIN: <b>2468</b>"),
    ("Konto-Seite", "Eingebaut unter <code>/auth/account</code>: Passwort, PIN, 2FA + Recovery-Codes, "
     "Passkeys, API-Keys und die eigenen Sitzungen.",
     "/auth/account", ""),
    ("Admin-Panel", "Unter <code>/auth/admin</code>: Benutzer &amp; Rollen, Sitzungen, API-Keys, "
     "Härtungs-Schwellen, Audit-Log, Update. Wahlweise nur als JSON-API fürs eigene Panel.",
     "/auth/admin", "Nur mit Admin-Rechten sichtbar."),
    ("Fehlerseite 404", "<code>auth.install_error_pages(app)</code> — Browser bekommen eine gebrandete "
     "Seite, API-Clients weiterhin JSON.",
     "/gibtsnicht", ""),
    ("Fehlerseite 500", "Dieselbe Behandlung für unerwartete Ausnahmen — ohne Stacktrace nach außen.",
     "/boom", ""),
]
N = len(TOUR)
auth.cfg.brand_head = _TOURBAR_JS.replace("__N__", str(N))


def tour_step(request: Request) -> int:
    try:
        return max(0, min(N, int(request.cookies.get(TOUR_COOKIE, "0"))))
    except ValueError:
        return 0


# ---------------------------------------------------------------- App-Design (Kopiervorlage)
_SITE_CSS = _TOKENS + _TOURBAR_CSS + """
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);line-height:1.65;
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
nav{display:flex;align-items:center;justify-content:space-between;gap:12px;
  max-width:760px;margin:0 auto;padding:16px 22px;border-bottom:1px solid var(--line)}
nav .brand{display:flex;align-items:center;gap:9px;font-weight:700;font-size:17px;
  color:var(--ink);text-decoration:none}
nav .brand img{width:26px;height:26px}
nav .brand b{color:var(--accent)}
nav .links{display:flex;gap:16px;font-size:14px}
main{max-width:760px;margin:0 auto;padding:32px 22px 64px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  font-size:38px;letter-spacing:-.01em;margin:.2em 0 .1em;text-wrap:balance}
.lead{color:var(--muted);font-size:18px;max-width:54ch;text-wrap:balance}
.bar{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}
.btn{display:inline-block;padding:10px 18px;border-radius:10px;font-weight:500;font-size:15px}
.btn.p{background:var(--accent);color:#fff}.btn.p:hover{text-decoration:none;filter:brightness(1.05)}
.btn.g{border:1px solid var(--line);color:var(--ink)}.btn.g:hover{text-decoration:none;border-color:var(--accent)}
.muted{color:var(--muted);font-size:14px}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.86em;background:var(--chip);
  border:1px solid var(--line);border-radius:5px;padding:1px 5px}
/* Tour-Schienen */
ol.steps{list-style:none;padding:0;margin:26px 0;display:grid;gap:12px;counter-reset:s}
ol.steps li{display:grid;grid-template-columns:34px 1fr;gap:14px;align-items:start;
  background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px}
ol.steps li.now{border-color:var(--accent);box-shadow:0 6px 24px rgba(176,86,111,.13)}
ol.steps li.done{opacity:.62}
ol.steps .num{display:grid;place-items:center;width:34px;height:34px;border-radius:50%;
  background:var(--chip);border:1px solid var(--line);font-weight:600;font-size:14px}
ol.steps li.done .num{background:var(--accent);color:#fff;border-color:var(--accent)}
ol.steps li.now .num{background:var(--accent);color:#fff;border-color:var(--accent)}
ol.steps b{display:block;font-size:16px}
ol.steps p{margin:4px 0 0;color:var(--muted);font-size:14.5px}
ol.steps .go{margin-top:10px;display:inline-block;padding:7px 14px;border-radius:9px;font-size:14px;
  border:1px solid var(--line);color:var(--ink)}
ol.steps li.now .go{background:var(--accent);color:#fff;border-color:var(--accent)}
ol.steps .go:hover{text-decoration:none}
footer{max-width:760px;margin:0 auto;padding:24px 22px 60px;border-top:1px solid var(--line);
  color:var(--muted);font-size:14px}
"""


def page(title, body, user=None):
    right = ("<a href='/demo'>Tour</a><a href='/auth/account'>Konto</a><a href='/auth/logout'>Abmelden</a>"
             if user else "<a href='/demo'>Tour</a><a href='/auth/login'>Anmelden</a>")
    return HTMLResponse(
        f"<!doctype html><html lang=de><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<link rel=icon href='/wizard.png'>"
        f"<title>{title} · TinySesam</title><style>{_SITE_CSS}</style>"
        f"{_TOURBAR_JS.replace('__N__', str(N))}</head><body>"
        f"<nav><a class=brand href='/'><img src='/wizard.png' alt=''> <span><b>Tiny</b>Sesam</span></a>"
        f"<span class=links>{right}<a href='{REPO}'>GitHub</a></span></nav>"
        f"<main>{body}</main>"
        f"<footer>TinySesam-Showcase · <a href='{REPO}'>GitHub</a> · "
        f"<a href='{REPO}/blob/main/CHANGELOG.md'>Changelog</a> · MIT</footer>"
        f"</body></html>")


# ---------------------------------------------------------------- Landing = die GitHub-Pages-Seite
_CTA_RE = re.compile(r'<div class="cta">.*?</div>', re.S)


def _cta(user) -> str:
    """Ersetzt die zwei Website-Buttons im Hero durch demo-taugliche, session-bewusste Buttons."""
    demo = "<a class='btn primary' href='/demo'>▶ Demo starten</a>"
    account = ("<a class='btn ghost' href='/auth/account'>Konto</a>"
               "<a class='btn ghost' href='/auth/logout'>Abmelden</a>"
               if user else "<a class='btn ghost' href='/auth/login'>Anmelden</a>")
    return (f'<div class="cta">{demo}{account}'
            f"<a class='btn ghost' href='{REPO}'>GitHub</a></div>")


@app.get("/wizard.png", include_in_schema=False)
def wizard():
    return FileResponse(DOCS / "wizard.png", media_type="image/png")


@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    """Buchstäblich die Website (docs/index.html) — nur mit Demo-Buttons statt der GitHub-Buttons."""
    user = auth.current_user(request)
    try:
        html = (DOCS / "index.html").read_text(encoding="utf-8")
    except FileNotFoundError:
        return page("Showcase", f"<h1>TinySesam Showcase</h1>{_cta(user)}")
    html = _CTA_RE.sub(lambda _m: _cta(user), html, count=1)
    hint = "" if user else " · Demo-Login <b>admin / geheim123</b>"
    html = html.replace('<p class="note">MIT', f'<p class="note">Live-Demo{hint} — MIT', 1)
    return HTMLResponse(html)


# ---------------------------------------------------------------- Tour-Hub
@app.get("/demo", response_class=HTMLResponse)
def demo(request: Request):
    user = auth.current_user(request)
    done = tour_step(request)
    nxt = min(done + 1, N)
    items = []
    for i, (title, blurb, url, hint) in enumerate(TOUR, start=1):
        cls = "done" if i <= done else ("now" if i == nxt else "")
        mark = "✓" if i <= done else str(i)
        note = f"<p class=muted style='margin-top:6px'>{hint}</p>" if hint else ""
        label = "Nochmal ansehen" if i <= done else ("Weiter →" if i == nxt else "Ansehen")
        items.append(f"<li class='{cls}'><span class=num>{mark}</span><div><b>{title}</b>"
                     f"<p>{blurb}</p>{note}<a class=go href='/demo/{i}'>{label}</a></div></li>")

    if done >= N:
        head = ("<h1>Tour abgeschlossen 🎉</h1><p class=lead>Das war TinySesam in acht Schritten — "
                "jedes Stück davon ist optional und per Config an- und abschaltbar.</p>"
                f"<div class=bar><a class='btn p' href='{REPO}'>Zum Repo</a>"
                "<a class='btn g' href='/demo/reset'>Tour zurücksetzen</a></div>")
    else:
        head = (f"<h1>Geführte Demo</h1><p class=lead>Acht Schritte durch die Funktionen — "
                f"jeder Schritt öffnet die echte Seite. Die Leiste oben bringt dich jederzeit hierher zurück.</p>"
                f"<div class=bar><a class='btn p' href='/demo/{nxt}'>"
                f"{'Tour starten' if done == 0 else f'Weiter mit Schritt {nxt}'}</a>"
                f"<a class='btn g' href='/'>← Startseite</a></div>")
    return page("Demo-Tour", f"{head}<ol class=steps>{''.join(items)}</ol>", user=user)


@app.get("/demo/reset", include_in_schema=False)
def demo_reset():
    r = RedirectResponse("/demo", status_code=303)
    r.delete_cookie(TOUR_COOKIE, path="/")
    return r


@app.get("/demo/{n}", include_in_schema=False)
def demo_go(n: int, request: Request):
    """Merkt den Fortschritt (Cookie, vom Tour-Leisten-JS gelesen) und springt auf die echte Seite."""
    n = max(1, min(N, n))
    r = RedirectResponse(TOUR[n - 1][2], status_code=303)
    r.set_cookie(TOUR_COOKIE, str(max(n, tour_step(request))), path="/", samesite="lax", max_age=3600)
    return r


# ---------------------------------------------------------------- Die geschützten Beispiel-Seiten
@app.get("/app", response_class=HTMLResponse)
def protected(user=Depends(auth.require_user)):
    return page("Bereich", f"""
      <h1>Hallo {user['username']} 👋</h1>
      <p class=lead>Eingeloggt — diese Route ist mit <code>Depends(auth.require_user)</code> geschützt,
        mehr steht da nicht.</p>
      <div class=bar><a class='btn p' href='/demo'>Zurück zur Tour</a>
        <a class='btn g' href='/sensibel'>Sensibler Bereich</a>
        <a class='btn g' href='/auth/account'>Konto</a></div>""", user=user)


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(user=Depends(auth.require(mfa=True))):
    return page("Sensibel", f"""
      <h1>🔒 Sensibler Bereich</h1>
      <p class=lead>{user['username']}, du hast dich soeben frisch bestätigt (Step-up / Sudo-Frische).
        Nach <code>stepup_max_age_sec</code> fragt TinySesam erneut.</p>
      <div class=bar><a class='btn p' href='/demo'>Zurück zur Tour</a>
        <a class='btn g' href='/app'>← Bereich</a></div>""", user=user)


@app.get("/gaeste", response_class=HTMLResponse)
def guests(request: Request, _=Depends(auth.require_resource("gaeste"))):
    return page("Gäste", """
      <h1>🔑 Gäste-Bereich</h1>
      <p class=lead>Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.
        Genau richtig für „diese eine Seite soll nicht offen im Netz stehen“.</p>
      <div class=bar><a class='btn p' href='/demo'>Zurück zur Tour</a>
        <a class='btn g' href='/'>← Startseite</a></div>""", user=auth.current_user(request))


@app.get("/boom", response_class=HTMLResponse)
def boom():
    raise RuntimeError("absichtlicher Fehler für die Demo")   # → themed 500-Seite
