"""Showcase: eine vorzeigbare Referenz-App, die viele TinySesam-Features zusammen zeigt und
demonstriert, dass das Frontend komplett austauschbar ist.

    pip install -e '.[all]'
    uvicorn examples.showcase:app --reload
    # → http://127.0.0.1:8000   (öffentliche Landing; admin / geheim123)

Zu sehen:
- öffentliche Landing-Seite (kein Login),
- geschützter Bereich (require_user),
- Step-up-geschützter Bereich (require(mfa=True)),
- eingebaute Konto-Seite (/auth/account) und Admin-Panel (/auth/admin),
- eine per set_template ERSETZTE Login-Seite (eigenes Aussehen),
- mehrere Login-Methoden inkl. persönlicher PIN + Magic-Link (Konsolen-Mailer),
- geteiltes Ressourcen-Geheimnis für einen Bereich ohne Benutzerkonto.
"""
from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse

from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="/tmp/tinysesam-showcase.db",
    rp_name="Showcase",
    lang="de",                      # eingebaute Seiten auf Deutsch (Default wäre "en")
    password_enabled=True,
    pin_enabled=True,               # persönliche PIN
    passkey_enabled=False,          # für lokalen HTTP-Test aus
    oidc_enabled=False,
    magiclink_enabled=True,         # Login-Link per E-Mail (hier: Konsolen-Mailer)
    allow_signup=True,              # Selbst-Registrierung offen
    resource_locks_enabled=True,    # geteiltes Ressourcen-Geheimnis
    cookie_secure=False,            # lokal ohne HTTPS
))
auth.ensure_admin("admin", "geheim123")

# Mailer, der Links einfach auf die Konsole schreibt (statt echtem SMTP)
auth.set_mailer(lambda to, subject, text, html=None: print(f"\n=== MAIL an {to}: {subject} ===\n{text}\n"))

# Ein Bereich, der nur mit einer geteilten PIN erreichbar ist (kein Benutzerkonto nötig)
auth.set_resource_secret("gaeste", "2468", kind="pin", label="Gäste-Bereich")


# --- Frontend austauschen: eigene Login-Seite (überschreibt die eingebaute) ---
def my_login(a, ctx):
    methods = a.cfg.enabled_methods()
    err = f"<p style='color:#c00'>{ctx.get('error')}</p>" if ctx.get("error") else ""
    # Wer das Login-Template ersetzt, muss bei aktivem CSRF (Default) das _csrf-Feld selbst einbauen:
    pw = ("<form method=post action='/auth/login'>"
          f"<input type=hidden name=next value='{ctx['next']}'>"
          f"<input type=hidden name=_csrf value='{ctx.get('csrf', '')}'>"
          "<input name=username placeholder=Benutzer><br><input name=password type=password placeholder=Passwort><br>"
          "<label><input type=checkbox name=remember value=1 checked> angemeldet bleiben</label><br>"
          "<button>Anmelden</button></form>") if "password" in methods else ""
    extra = "<p><a href='/auth/magic/request'>Login-Link per E-Mail</a> · <a href='/auth/register'>Konto erstellen</a></p>"
    return (f"<!doctype html><meta charset=utf-8><title>Anmelden</title>"
            f"<div style='font-family:system-ui;max-width:320px;margin:12vh auto'>"
            f"<h1>🔐 Showcase-Login</h1>{err}{pw}{extra}</div>")


# Standardmäßig die (gepflegte) eingebaute Login-Seite verwenden. Zum Ausprobieren der
# Frontend-Ersetzung einfach die nächste Zeile einkommentieren:
# auth.set_template("login", my_login)

app = FastAPI()
app.include_router(auth.router())

_SHELL_CSS = """
:root{color-scheme:dark}*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;margin:0;min-height:100vh;
  display:flex;align-items:center;justify-content:center;background:#0f1115;color:#e6e6e6;line-height:1.6}
main.card{width:520px;max-width:92vw;background:#161a22;border:1px solid #262b36;border-radius:16px;
  padding:32px 30px;margin:6vh 0}
h1{font-size:24px;margin:0 0 6px}p{color:#c3c8d2;margin:.5em 0}
a{color:#e0919c;text-decoration:none}a:hover{text-decoration:underline}
ul.links{list-style:none;padding:0;margin:18px 0 0;display:grid;gap:10px}
ul.links li{background:#0f1115;border:1px solid #262b36;border-radius:10px;padding:12px 14px}
ul.links a{font-weight:600}ul.links small{color:#8a90a0;display:block;font-weight:400}
.bar{margin-top:22px;display:flex;gap:14px;flex-wrap:wrap;font-size:14px}
.muted{color:#8a90a0;font-size:14px}
"""


def shell(title, body):
    return (f"<!doctype html><html lang=de><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{title} · TinySesam</title><style>{_SHELL_CSS}</style></head>"
            f"<body><main class=card>{body}</main></body></html>")


@app.get("/", response_class=HTMLResponse)
def landing():
    # öffentlich — kein Login
    return shell("Showcase", """
        <h1>🧙 TinySesam — Showcase</h1>
        <p class=muted>Öffentliche Startseite. Nichts hier ist geschützt — probier die Bereiche aus.</p>
        <ul class=links>
          <li><a href="/app">Geschützter Bereich</a><small>Login nötig (require_user)</small></li>
          <li><a href="/sensibel">Sensibler Bereich</a><small>Step-up — frische Bestätigung (require(mfa=True))</small></li>
          <li><a href="/gaeste">Gäste-Bereich</a><small>nur geteilte PIN, ganz ohne Konto — PIN: <b>2468</b></small></li>
          <li><a href="/auth/account">Mein Konto</a><small>Passwort, PIN, 2FA, Sitzungen</small></li>
          <li><a href="/auth/admin">Admin-Panel</a><small>Benutzer, Rollen, Sitzungen, Audit</small></li>
        </ul>
        <div class=bar><a href="/auth/login">Anmelden</a><a href="/auth/register">Registrieren</a></div>""")


@app.get("/app", response_class=HTMLResponse)
def protected(user=Depends(auth.require_user)):
    return shell("Bereich", f"""
        <h1>Hallo {user['username']} 👋</h1>
        <p>Du bist eingeloggt — dieser Bereich ist per <code>require_user</code> geschützt.</p>
        <div class=bar><a href="/auth/account">Konto verwalten</a><a href="/sensibel">sensibler Bereich</a>
          <a href="/auth/admin">Admin-Panel</a><a href="/auth/logout">Abmelden</a></div>""")


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(user=Depends(auth.require(mfa=True))):
    return shell("Sensibel", f"""
        <h1>🔒 Sensibler Bereich</h1>
        <p>{user['username']}, du hast dich soeben frisch bestätigt (Step-up / Sudo-Frische).</p>
        <div class=bar><a href="/app">← zurück</a></div>""")


@app.get("/gaeste", response_class=HTMLResponse)
def guests(_=Depends(auth.require_resource("gaeste"))):
    return shell("Gäste", """
        <h1>🔑 Gäste-Bereich</h1>
        <p>Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.</p>
        <div class=bar><a href="/">← Startseite</a></div>""")
