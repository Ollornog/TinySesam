"""Phase 7: Eingebaute Account-Seite (Selbstverwaltung) + Selbst-Passwortänderung + Override."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig
from tinysesam.errors import ConfigError


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

# ---------- Passwortregel an der Kontoseite (B2-5/H-17, R4-07) ----------
# Dieselbe Regel wie an jeder Setzstelle: bekannte Passwörter, triviale Folgen und Wörter aus dem
# Kontext (Benutzername, Dienstname) fallen durch, auch aufgehübscht; zu lange ebenso.
# (Mutationsprobe: `return None` an den Anfang von `passwords.passwort_mangel` → rot.)
for _schwach in ("password123", "Passwort2026!", "12345678", "qwertzuiop", "aaaaaaaaaa",
                 "Admin2026!", "test!Test1", "45678901"):
    _r = c.post("/auth/password", json={"current": "neuespasswort", "new": _schwach})
    assert _r.status_code == 400 and "leicht zu erraten" in _r.json()["detail"], (_schwach, _r.text)
# `test!Test1` → Kern `testtest` (Blockliste); `Test` ist der rp_name dieser Instanz.
_r = c.post("/auth/password", json={"current": "neuespasswort", "new": "Test-2026"})
assert _r.status_code == 400, "der Dienstname (rp_name) ist ein Kontextwort"
_r = c.post("/auth/password", json={"current": "neuespasswort", "new": "x" * 257})
assert _r.status_code == 400 and "zu lang" in _r.json()["detail"], _r.text
_r = c.post("/auth/password", json={"current": "neuespasswort", "new": "k" + "e1" * 127 + "!"})   # 256 Zeichen
assert _r.status_code == 200, "genau die Höchstlänge ist erlaubt"
_r = c.post("/auth/password", json={"current": "k" + "e1" * 127 + "!", "new": "neuespasswort"})
assert _r.status_code == 200, _r.text
ok("Kontoseite: Blockliste, Kontextwörter und Höchstlänge (256) greifen")

# Eigene Blockliste des Betreibers (`password_blocklist_file`) — ergänzt die eingebaute.
_liste = os.path.join(tempfile.mkdtemp(), "block.txt")
with open(_liste, "w", encoding="utf-8") as _f:
    _f.write("# Kommentar\nFirmenname2026\n")
_ab = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "b.db"), passkey_enabled=False,
                                password_blocklist_file=_liste))
assert _ab.passwort_mangel("firmenname2026") and _ab.passwort_mangel("Firmenname!!")
assert _ab.passwort_mangel("ein-ganz-eigenes-wort") is None
# Gegenprobe gegen Übereifer: keine Zusammensetzungsregeln (NIST), eine Ziffernfolge ohne Muster
# und eine Passphrase gehen durch.
for _gut in ("24681357", "correct horse battery", "9384756102"):
    assert _ab.passwort_mangel(_gut) is None, _gut
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "b.db"), passkey_enabled=False,
                              password_blocklist_file=_liste + ".fehlt"))
    raise AssertionError("fehlende Blockliste wurde still übergangen")
except ConfigError as _e:
    assert "password_blocklist_file" in str(_e)
ok("password_blocklist_file ergänzt die Liste; fehlt die Datei, bricht der Start ab")

# ---------- on_security_event (B2-2/H-6) ----------
# Jede Änderung an einem Anmeldefaktor erreicht den Hook — der Inhaber soll davon erfahren.
# (Mutationsprobe: `self.sicherheitsereignis("password_changed", …)` aus `set_password`
# streichen → rot; ebenso je Ereignis.)
_ereignisse = []
auth.on_security_event = lambda e, konto, d: _ereignisse.append((e, konto["username"], d))
_uid = auth.store.get_user_by_name("admin")["id"]
assert c.post("/auth/password", json={"current": "neuespasswort", "new": "wieder-ein-neues"}).status_code == 200
auth.set_pin(_uid, "24681357")
auth.disable_pin(_uid)
auth.create_api_key(_uid, name="ci")
_namen = [e for e, _, _ in _ereignisse]
assert _namen == ["password_changed", "pin_set", "pin_disabled", "api_key_created"], _ereignisse
assert all(n == "admin" for _, n, _ in _ereignisse)
assert set(_namen) <= set(auth.SICHERHEITSEREIGNISSE)
ok("on_security_event: Passwort, PIN setzen/entfernen und neuer API-Key melden sich")

# Jedes zugesagte Ereignis hat einen Aufrufer im Paket — auch die, die dieser Test nicht fährt
# (Passkey braucht das Extra). Per AST, nicht per Textsuche: ein Docstring zählt nicht.
import ast as _ast
import pathlib as _pl
import tinysesam as _ts
_gerufen = set()
for _datei in _pl.Path(_ts.__file__).parent.glob("*.py"):
    for _k in _ast.walk(_ast.parse(_datei.read_text(encoding="utf-8"))):
        if (isinstance(_k, _ast.Call) and isinstance(_k.func, _ast.Attribute)
                and _k.func.attr == "sicherheitsereignis" and _k.args
                and isinstance(_k.args[0], _ast.Constant)):
            _gerufen.add(_k.args[0].value)
assert _gerufen == set(auth.SICHERHEITSEREIGNISSE), (sorted(_gerufen), auth.SICHERHEITSEREIGNISSE)
ok("jedes Ereignis aus SICHERHEITSEREIGNISSE wird irgendwo ausgelöst (und kein anderes)")

# Ein kaputter Hook bricht nichts ab, bleibt aber nicht still.
import logging as _logging
from tinysesam import security as _sec
_zeilen = []
_h = _logging.Handler()
_h.emit = lambda rec: _zeilen.append(rec.getMessage())
_sec.seclog.addHandler(_h)


def _kaputt(*_a):
    raise RuntimeError("smtp weg")


auth.on_security_event = _kaputt
_r = c.post("/auth/password", json={"current": "wieder-ein-neues", "new": "neuespasswort"})
_sec.seclog.removeHandler(_h)
auth.on_security_event = None
assert _r.status_code == 200, "ein fehlschlagender Hook darf den Passwortwechsel nicht kippen"
assert any("on_security_event fehlgeschlagen" in z and "password_changed" in z for z in _zeilen), _zeilen
assert auth.check_password("admin", "neuespasswort")
ok("on_security_event: Fehler im Hook → Vorgang gilt, Zeile im Sicherheits-Log")

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
