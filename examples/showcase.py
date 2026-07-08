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


auth.set_template("login", my_login)

app = FastAPI()
app.include_router(auth.router())


def shell(title, body):
    return (f"<!doctype html><meta charset=utf-8><title>{title}</title>"
            f"<div style='font-family:system-ui;max-width:640px;margin:8vh auto;line-height:1.6'>{body}</div>")


@app.get("/", response_class=HTMLResponse)
def landing():
    # öffentlich — kein Login
    return shell("Showcase", """
        <h1>TinySesam Showcase</h1>
        <p>Öffentliche Landing-Seite. Nichts hier ist geschützt.</p>
        <ul>
          <li><a href="/app">Geschützter Bereich</a> (Login nötig)</li>
          <li><a href="/sensibel">Sensibler Bereich</a> (Step-up / frische Bestätigung)</li>
          <li><a href="/gaeste">Gäste-Bereich</a> (nur geteilte PIN, kein Konto — PIN: 2468)</li>
          <li><a href="/auth/account">Mein Konto</a> · <a href="/auth/admin">Admin-Panel</a></li>
          <li><a href="/auth/login">Anmelden</a> · <a href="/auth/register">Registrieren</a></li>
        </ul>""")


@app.get("/app", response_class=HTMLResponse)
def protected(user=Depends(auth.require_user)):
    return shell("Bereich", f"""
        <h1>Hallo {user['username']}</h1>
        <p>Geschützter Bereich (require_user).</p>
        <p><a href="/auth/account">Konto verwalten</a> · <a href="/sensibel">sensibler Bereich</a>
           · <a href="/auth/logout">Abmelden</a></p>""")


@app.get("/sensibel", response_class=HTMLResponse)
def sensitive(user=Depends(auth.require(mfa=True))):
    return shell("Sensibel", f"""
        <h1>Sensibler Bereich</h1>
        <p>{user['username']}, du hast dich frisch bestätigt (Step-up).</p>
        <p><a href="/app">zurück</a></p>""")


@app.get("/gaeste", response_class=HTMLResponse)
def guests(_=Depends(auth.require_resource("gaeste"))):
    return shell("Gäste", """
        <h1>Gäste-Bereich</h1>
        <p>Freigeschaltet über die geteilte PIN — ganz ohne Benutzerkonto.</p>
        <p><a href="/">Startseite</a></p>""")
