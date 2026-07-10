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

# ---------- Die Tabellen sind vollständig ----------
# Ein fehlender de-Schlüssel fiele stumm auf Englisch zurück: die Seite wirkt übersetzt,
# einzelne Wörter sind es nicht. Genau so blieb das Admin-Panel bis 0.13.1 unbemerkt deutsch.
from tinysesam.messages import MESSAGES                                     # noqa: E402
en, de = set(MESSAGES["en"]), set(MESSAGES["de"])
assert not en - de, f"nur auf Englisch: {sorted(en - de)}"
assert not de - en, f"nur auf Deutsch: {sorted(de - en)}"
assert all(v.strip() for v in MESSAGES["de"].values()), "leere Übersetzung"
ok(f"en/de decken dieselben {len(en)} Schlüssel ab")

# ---------- Das Admin-Panel übersetzt sich mit ----------
from tinysesam.admin import panel_texts, render_panel                        # noqa: E402
db, auth, c = build(lang="en")
assert set(panel_texts(auth)) >= {"tab.users", "hardening", "cancel", "logout", "locale"}
for lang, want, nope in (("en", "Hardening", "Härtung"), ("de", "Härtung", "Hardening")):
    auth.cfg.lang = lang
    html = render_panel(auth, "/auth/admin")
    assert f"lang={lang}" in html, lang
    assert want in html and nope not in html, (lang, want, nope)
    # `toLocaleString()` folgt der Sprache, sonst steht ein englisches Datum im deutschen Panel.
    assert ("en-GB" if lang == "en" else "de-DE") in html, lang

# Eigene Übersetzungen greifen auch im Panel — und `</script>` darf es nicht zerlegen.
auth.cfg.lang = "en"
auth.add_messages("en", {"admin.tab.users": "Accounts", "admin.save": "</script>x"})
html = render_panel(auth, "/auth/admin")
assert "Accounts" in html
assert html.count("</script>") == 1, "eigene Übersetzung darf den Skriptblock nicht beenden"
assert "\\u003c/script>x" in html
ok("Admin-Panel: de/en, Locale, add_messages, `<` maskiert")
os.remove(db)

print("\nI18N OK ✅")
