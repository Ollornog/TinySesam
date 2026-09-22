"""Phase 7: Eingebaute Account-Seite (Selbstverwaltung) + Selbst-Passwortänderung + Override."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, pin_enabled=True))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

# nicht eingeloggt → Redirect zum Login
r = c.get("/auth/account", follow_redirects=False)
assert r.status_code == 303 and "/auth/login" in r.headers["location"]
ok("Account-Seite verlangt Login")

c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
html = c.get("/auth/account").text
assert "Konto · admin" in html
assert "Passwort" in html and "PIN" in html and "Zwei-Faktor" in html and "API-Keys" in html
assert "Admin-Panel" in html   # admin sieht den Link
ok("Account-Seite zeigt Abschnitte (Passwort/PIN/2FA/API-Keys) + Admin-Link")

# Passwort ändern: falsches aktuelles → 403
assert c.post("/auth/password", json={"current": "falsch", "new": "neuespasswort"}).status_code == 403
# zu kurz → 400
assert c.post("/auth/password", json={"current": "geheim123", "new": "x"}).status_code == 400
# korrekt → 200, danach neuer Login funktioniert
_pw = c.post("/auth/password", json={"current": "geheim123", "new": "neuespasswort"}).json()
# Die Antwort trägt seit 0.18.0 zusätzlich `api_keys_active`: API-Keys überleben den eigenen
# Passwortwechsel mit Absicht, und wer nach einem Einbruch das Passwort tauscht, soll sehen,
# dass da noch eine zweite Tür offen ist. Deshalb kein Gleichheitsvergleich mehr.
assert _pw["ok"] is True and _pw["api_keys_active"] == 0, _pw
c.get("/auth/logout")
assert c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False).status_code == 401
assert c.post("/auth/login", data={"username": "admin", "password": "neuespasswort"}, follow_redirects=False).status_code == 303
ok("Selbst-Passwortänderung (aktuelles Passwort nötig, Mindestlänge)")

# Robustheit: kaputter JSON-Body → 400 (nicht 500)
r = c.post("/auth/password", content="{kaputt}", headers={"Content-Type": "application/json"})
assert r.status_code == 400, r.status_code
ok("kaputter JSON-Body → 400 (nicht 500)")

# ---------- Die Lösch-Knöpfe prüfen die Antwort, bevor sie Erfolg melden (R3-3) ----------
# Beide Knöpfe der Konto-Seite meldeten UNBEDINGT „✓ entfernt" und luden neu — auch bei 403
# (abgelaufene Step-up-Frische, fehlendes CSRF-Token) oder 500. Der Nutzer sah „entfernt", der
# Faktor stand noch. Der CHANGELOG sagt das für BEIDE Knöpfe zu; gedeckt war nur `deltotp()`,
# und zwar im Browser-Test — der fährt eine Demo mit `pin_login=False` und zeigt die
# PIN-Sektion deshalb gar nicht. Mutation M32 (`delpin()` meldet wieder unbedingt Erfolg) lief
# mit 46/46 grün durch. Geprüft wird hier der Quelltext, den der Browser wirklich bekommt:
# billiger als ein zweiter Browser-Lauf und unabhängig davon, welche Sektion die Demo zeigt.
# Muss VOR dem Template-Override weiter unten stehen — danach liefert die Seite kein JS mehr.
import re as _re  # noqa: E402

# Beide Sektionen sichtbar machen: Die PIN-Sektion hängt an `pin_login`, die 2FA-Sektion an
# einem bestätigten Geheimnis. Genau daran ging die Browser-Abdeckung vorbei — die Demo fährt
# `pin_login=False` und zeigt den PIN-Knopf nie.
_uid = auth.store.get_user_by_name("admin")["id"]
auth.cfg.pin_login = True
auth.totp_begin(_uid)
auth.store.confirm_totp(_uid)
_js = c.get("/auth/account").text
auth.cfg.pin_login = False
_ERFOLG = "\u2713 entfernt"


def _funktion(quelle, name):
    """Der Körper von `async function <name>(){…}` bis zur nächsten Funktion."""
    _m = _re.search(r"async function " + name + r"\(\)\{(.*?)(?=\nasync function |\n</script>)",
                    quelle, _re.S)
    assert _m, f"{name}() steht nicht mehr im Konto-JS — sonst prüft dieser Wächter nichts"
    return _m.group(1)


for _knopf in ("delpin", "deltotp"):
    _koerper = _funktion(_js, _knopf)
    assert "r.ok" in _koerper, f"{_knopf}() sieht die Antwort gar nicht an"
    for _zeile in _koerper.splitlines():
        if _ERFOLG in _zeile:
            assert "r.ok?" in _zeile, \
                f"{_knopf}() meldet Erfolg unbedingt: {_zeile.strip()!r}"
        if "location.reload()" in _zeile:
            assert "if(r.ok)" in _zeile, \
                (f"{_knopf}() lädt unbedingt neu: {_zeile.strip()!r} — ein 403 sähe für den "
                 "Nutzer damit genauso aus wie ein Erfolg")
# Gegenprobe: Beide Knöpfe stehen auf der Seite — sonst misst der Wächter Text, den niemand
# bekommt, und der Erfolgspfad wäre nirgends belegt.
assert "data-act=delpin" in _js and "data-act=deltotp" in _js, "kein Lösch-Knopf auf der Seite"
assert _ERFOLG in _funktion(_js, "delpin"), "delpin() meldet gar keinen Erfolg mehr"
ok("Lösch-Knöpfe (PIN und 2FA) melden erst nach `r.ok` Erfolg")

# Template-Override der Account-Seite
auth.set_template("account", lambda a, ctx: f"<html>MEIN-KONTO {ctx['user']['username']}</html>")
assert "MEIN-KONTO admin" in c.get("/auth/account").text
ok("Account-Seite per set_template ersetzbar")

os.remove(db)
print("\nACCOUNT OK ✅")
