"""E3: i18n — English default texts, switching to de, auth.t()/add_messages."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def build(**kw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False, csrf_enabled=False, **kw))
    auth.ensure_admin("admin", "dummy123")
    app = FastAPI()
    app.include_router(auth.router())
    return db, auth, TestClient(app)


# ---------- Default: English ----------
db, auth, c = build()   # lang default = "en"
assert auth.cfg.lang == "en"
html = c.get("/auth/login").text
assert "Username" in html and "Password" in html and "Sign in" in html
assert "lang=en" in html
assert "Benutzer" not in html
ok("default language English: login page in English")

# English error message
r = c.post("/auth/login", data={"username": "admin", "password": "wrong"})
assert "Invalid credentials" in r.text
ok("error message in English (Invalid credentials)")
os.remove(db)

# ---------- Switching to German ----------
db, auth, c = build(lang="de")
html = c.get("/auth/login").text
assert "Benutzer" in html and "Passwort" in html and "Anmelden" in html and "lang=de" in html
r = c.post("/auth/login", data={"username": "admin", "password": "wrong"})
assert "Falsche Zugangsdaten" in r.text
ok("lang='de': login page + error message in German")
os.remove(db)

# ---------- auth.t(): placeholders, fallback, unknown key ----------
db, auth, c = build(lang="en")
assert auth.t("err.pw_short", n=8) == "Password too short (min. 8)"
assert auth.t("login.user") == "Username"
assert auth.t("does.not.exist") == "does.not.exist"       # unknown key → the key itself
auth.cfg.lang = "de"
assert auth.t("login.user") == "Benutzer"
auth.cfg.lang = "fr"                                     # no fr table → fallback en
assert auth.t("login.submit") == "Sign in"
ok("auth.t(): placeholders, de/en, fallback to en, key fallback")

# ---------- add_messages: own language/override ----------
auth.add_messages("fr", {"login.submit": "Se connecter", "login.user": "Utilisateur"})
auth.cfg.lang = "fr"
assert auth.t("login.submit") == "Se connecter" and auth.t("login.user") == "Utilisateur"
assert auth.t("login.password") == "Password"           # not translated → en fallback
ok("add_messages: add an own language (the rest falls back to en)")
os.remove(db)

# ---------- The tables are complete ----------
# A missing de key would silently fall back to English: the page looks translated,
# single words are not. This is exactly how the admin panel stayed unnoticed in German until 0.13.1.
from tinysesam.messages import MESSAGES                                     # noqa: E402
en, de = set(MESSAGES["en"]), set(MESSAGES["de"])
assert not en - de, f"only in English: {sorted(en - de)}"
assert not de - en, f"only in German: {sorted(de - en)}"
assert all(v.strip() for v in MESSAGES["de"].values()), "empty translation"
ok(f"en/de cover the same {len(en)} keys")

# ---------- The admin panel translates along ----------
from tinysesam.admin import panel_texts, render_panel                        # noqa: E402
db, auth, c = build(lang="en")
assert set(panel_texts(auth)) >= {"tab.users", "hardening", "cancel", "logout", "locale"}
for lang, want, nope in (("en", "Hardening", "Härtung"), ("de", "Härtung", "Hardening")):
    auth.cfg.lang = lang
    html = render_panel(auth, "/auth/admin")
    assert f"lang={lang}" in html, lang
    assert want in html and nope not in html, (lang, want, nope)
    # `toLocaleString()` follows the language, otherwise an English date appears in the German panel.
    assert ("en-GB" if lang == "en" else "de-DE") in html, lang

# Own translations also take effect in the panel — and `</script>` must not break it.
auth.cfg.lang = "en"
auth.add_messages("en", {"admin.tab.users": "Accounts", "admin.save": "</script>x"})
html = render_panel(auth, "/auth/admin")
assert "Accounts" in html
assert html.count("</script>") == 1, "own translation must not end the script block"
assert "\\u003c/script>x" in html
ok("Admin-Panel: de/en, Locale, add_messages, `<` escaped")
os.remove(db)

print("\nI18N OK ✅")
