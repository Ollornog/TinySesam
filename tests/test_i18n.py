"""E3: i18n — englische Default-Texte, Umschaltung auf de, auth.t()/add_messages."""
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def build(**kw):
    db = tempfile.mktemp(suffix=".db")
    auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, csrf_enabled=False, **kw))
    auth.ensure_admin("admin", "geheim123")
    app = FastAPI()
    app.include_router(auth.router())
    return db, auth, TestClient(app)


# ---------- Default: Englisch ----------
db, auth, c = build()   # lang default = "en"
assert auth.cfg.lang == "en"
html = c.get("/auth/login").text
assert "Username" in html and "Password" in html and "Sign in" in html
assert "lang=en" in html
assert "Benutzer" not in html
ok("Default-Sprache Englisch: Login-Seite auf Englisch")

# englische Fehlermeldung
r = c.post("/auth/login", data={"username": "admin", "password": "falsch"})
assert "Invalid credentials" in r.text
ok("Fehlermeldung auf Englisch (Invalid credentials)")
os.remove(db)

# ---------- Umschaltung auf Deutsch ----------
db, auth, c = build(lang="de")
html = c.get("/auth/login").text
assert "Benutzer" in html and "Passwort" in html and "Anmelden" in html and "lang=de" in html
r = c.post("/auth/login", data={"username": "admin", "password": "falsch"})
assert "Falsche Zugangsdaten" in r.text
ok("lang='de': Login-Seite + Fehlermeldung auf Deutsch")
os.remove(db)

# ---------- auth.t(): Platzhalter, Fallback, unbekannter Key ----------
db, auth, c = build(lang="en")
assert auth.t("err.pw_short", n=8) == "Password too short (min. 8)"
assert auth.t("login.user") == "Username"
assert auth.t("gibt.es.nicht") == "gibt.es.nicht"       # unbekannter Key → Key selbst
auth.cfg.lang = "de"
assert auth.t("login.user") == "Benutzer"
auth.cfg.lang = "fr"                                     # keine fr-Tabelle → Fallback en
assert auth.t("login.submit") == "Sign in"
ok("auth.t(): Platzhalter, de/en, Fallback auf en, Key-Fallback")

# ---------- add_messages: eigene Sprache/Überschreibung ----------
auth.add_messages("fr", {"login.submit": "Se connecter", "login.user": "Utilisateur"})
auth.cfg.lang = "fr"
assert auth.t("login.submit") == "Se connecter" and auth.t("login.user") == "Utilisateur"
assert auth.t("login.password") == "Password"           # nicht übersetzt → en-Fallback
ok("add_messages: eigene Sprache ergänzen (Rest fällt auf en zurück)")
os.remove(db)

print("\nI18N OK ✅")
