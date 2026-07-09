"""Showcase = vorzeigbare Referenz-App im selben Design wie die Projekt-Website (GitHub Pages).

    pip install -e '.[all]'          # oder Kern: nur Passwort/PIN/Magic reicht hier
    uvicorn examples.showcase:app --reload
    # → http://127.0.0.1:8000   (öffentliche Landing; admin / geheim123)

Alles in EINEM Look: die App-Seiten (Landing/Bereiche) UND – via `brand_css` – die eingebauten
TinySesam-Seiten (Login/PIN/TOTP/Konto/Fehlerseiten). Gedacht als Kopiervorlage: kleine Nav,
Git-Links, ein Design. Zu sehen: geschützter Bereich, Step-up, Gäste-PIN (ohne Konto), Konto-Seite,
Admin-Panel, Magic-Link (Konsolen-Mailer), themed 404/500.
"""
from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse

from tinysesam import TinySesam, TinySesamConfig

REPO = "https://github.com/Ollornog/TinySesam"

# Eine Palette/Design für ALLES (Cremeweiß/Altrosa, Light+Dark) — wie die Projekt-Website.
_TOKENS = """
:root{--paper:#f6f1ec;--card:#fbf8f4;--ink:#2b2a3a;--muted:#6f6a7d;--accent:#b0566f;
  --accent-2:#d98c93;--line:#e6ddd4;--chip:#efe7de}
@media (prefers-color-scheme:dark){:root{--paper:#1a1922;--card:#221f2c;--ink:#ece9f2;--muted:#a49eb4;
  --accent:#e0919c;--accent-2:#b0566f;--line:#2f2c3b;--chip:#2a2735}}
"""

# brand_css: re-skinnt die EINGEBAUTEN TinySesam-Seiten (Login/PIN/TOTP/Konto/Fehler) im selben Look.
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


# ---------- App-Design: selbe Sprache, kleine Nav, Git-Links (Kopiervorlage) ----------
_SITE_CSS = _TOKENS + """
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);line-height:1.65;
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
nav{display:flex;align-items:center;justify-content:space-between;gap:12px;
  max-width:760px;margin:0 auto;padding:16px 22px;border-bottom:1px solid var(--line)}
nav .brand{font-weight:700;font-size:17px;color:var(--ink);text-decoration:none}
nav .brand b{color:var(--accent)}
nav .links{display:flex;gap:16px;font-size:14px}
main{max-width:760px;margin:0 auto;padding:32px 22px 64px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  font-size:40px;letter-spacing:-.01em;margin:.2em 0 .1em;text-wrap:balance}
h1 .t{color:var(--accent)}
.lead{color:var(--muted);font-size:18px;max-width:52ch;text-wrap:balance}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:22px 0}
.chip{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:6px 13px;font-size:14px}
ul.solves{list-style:none;padding:0;margin:18px 0;display:grid;gap:10px}
ul.solves li{display:grid;grid-template-columns:auto 1fr;gap:10px}
ul.solves .y{color:var(--accent);font-weight:700}
.card2{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:16px 0}
.bar{display:flex;gap:14px;flex-wrap:wrap;margin-top:20px}
.btn{display:inline-block;padding:10px 18px;border-radius:10px;font-weight:500}
.btn.p{background:var(--accent);color:#fff}.btn.p:hover{text-decoration:none;filter:brightness(1.05)}
.btn.g{border:1px solid var(--line);color:var(--ink)}.btn.g:hover{text-decoration:none;border-color:var(--accent)}
.muted{color:var(--muted);font-size:14px}
footer{max-width:760px;margin:0 auto;padding:24px 22px 60px;border-top:1px solid var(--line);
  color:var(--muted);font-size:14px}
"""


def page(title, body, user=None):
    right = (f"<a href='/auth/account'>Konto</a><a href='/auth/logout'>Abmelden</a>"
             if user else "<a href='/auth/login'>Anmelden</a>")
    return HTMLResponse(
        f"<!doctype html><html lang=de><head><meta charset=utf-8>"
        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{title} · TinySesam</title><style>{_SITE_CSS}</style></head><body>"
        f"<nav><a class=brand href='/'>🧙 <b>Tiny</b>Sesam</a>"
        f"<span class=links>{right}<a href='{REPO}'>GitHub</a></span></nav>"
        f"<main>{body}</main>"
        f"<footer>TinySesam-Showcase · <a href='{REPO}'>GitHub</a> · "
        f"<a href='{REPO}/blob/main/CHANGELOG.md'>Changelog</a> · MIT</footer>"
        f"</body></html>")


@app.get("/", response_class=HTMLResponse)
def landing():
    return page("Showcase", f"""
      <h1><span class=t>Tiny</span>Sesam — Showcase</h1>
      <p class=lead>Der Login-Layer für selbstgebaute Apps. Diese Seite läuft im selben Design wie die
        eingebauten Auth-Seiten — <b>eine Vorlage, die du direkt für deine App übernehmen kannst</b>.</p>
      <div class=chips>
        <span class=chip>🔐 Passwort</span><span class=chip>🔢 PIN</span>
        <span class=chip>✉️ Magic-Link</span><span class=chip>📱 TOTP</span>
        <span class=chip>🔑 Gäste-PIN</span><span class=chip>🛠️ Admin-Panel</span>
      </div>
      <ul class=solves>
        <li><span class=y>✓</span><span><b>Geschützter Bereich</b> — <a href='/app'>/app</a> (require_user)</span></li>
        <li><span class=y>✓</span><span><b>Sensibel / Step-up</b> — <a href='/sensibel'>/sensibel</a> (frische Bestätigung)</span></li>
        <li><span class=y>✓</span><span><b>Gäste-Bereich</b> — <a href='/gaeste'>/gaeste</a>, nur PIN <b>2468</b>, ganz ohne Konto</span></li>
        <li><span class=y>✓</span><span><b>Konto &amp; Admin</b> — <a href='/auth/account'>Konto</a> · <a href='/auth/admin'>Admin-Panel</a></span></li>
        <li><span class=y>✓</span><span><b>Themed Fehlerseiten</b> — <a href='/gibtsnicht'>404</a> · <a href='/boom'>500</a></span></li>
      </ul>
      <div class=bar><a class='btn p' href='/auth/login'>Anmelden</a>
        <a class='btn g' href='/auth/register'>Konto erstellen</a></div>
      <p class=muted style=margin-top:22px>Demo-Login: <b>admin / geheim123</b></p>""")


@app.get("/app", response_class=HTMLResponse)
def protected(user=Depends(auth.require_user)):
    return page("Bereich", f"""
      <h1>Hallo {user['username']} 👋</h1>
      <p class=lead>Eingeloggt — dieser Bereich ist per <code>require_user</code> geschützt.</p>
      <div class=bar><a class='btn p' href='/sensibel'>Sensibler Bereich</a>
        <a class='btn g' href='/auth/account'>Konto verwalten</a>
        <a class='btn g' href='/auth/admin'>Admin-Panel</a></div>""", user=user)


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(user=Depends(auth.require(mfa=True))):
    return page("Sensibel", f"""
      <h1>🔒 Sensibler Bereich</h1>
      <p class=lead>{user['username']}, du hast dich soeben frisch bestätigt (Step-up / Sudo-Frische).</p>
      <div class=bar><a class='btn g' href='/app'>← zurück</a></div>""", user=user)


@app.get("/gaeste", response_class=HTMLResponse)
def guests(_=Depends(auth.require_resource("gaeste"))):
    return page("Gäste", """
      <h1>🔑 Gäste-Bereich</h1>
      <p class=lead>Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.</p>
      <div class=bar><a class='btn g' href='/'>← Startseite</a></div>""")


@app.get("/boom", response_class=HTMLResponse)
def boom():
    raise RuntimeError("absichtlicher Fehler für die Demo")   # → themed 500-Seite
