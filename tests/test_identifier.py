"""Login-Kennung: Benutzername, E-Mail oder beides — plus E-Mail-Pflicht/Eindeutigkeit/Bestätigung."""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig
from tinysesam.store import norm_email, valid_email


def build(**over):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    cfg = TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                          passkey_enabled=False, **over)
    auth = TinySesam(cfg)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, TestClient(app), db


def login(c, ident, pw="geheim12345"):
    return c.post("/auth/login", data={"username": ident, "password": pw, "next": "/"},
                  follow_redirects=False)


# ---------- Normalisierung + Validierung ----------
assert norm_email("  Max@Example.COM ") == "max@example.com"
assert norm_email("") is None and norm_email(None) is None
assert valid_email("a@b.de") and valid_email("a.b+c@sub.example.co.uk")
assert not valid_email("ab.de") and not valid_email("a@b") and not valid_email("a b@c.de")
assert not valid_email("a@@b.de") and not valid_email("@b.de") and not valid_email("a@.de")
print("  norm_email/valid_email ok")

# ---------- Modus "both": Login mit beidem ----------
auth, c, db = build(login_identifier="both")
auth.create_user("max", password="geheim12345", email="Max@Example.com")
assert login(c, "max").status_code == 303, "Username-Login"
assert login(c, "max@example.com").status_code == 303, "E-Mail-Login"
assert login(c, "MAX@EXAMPLE.COM").status_code == 303, "E-Mail case-insensitiv"
assert login(c, "max", "falsch").status_code != 303
assert login(c, "gibtsnicht@example.com").status_code != 303
c.cookies.clear()          # sonst leitet /auth/login als Angemeldeter auf / um
assert "Benutzer oder E-Mail" in c.get("/auth/login").text
print("  both: Username + E-Mail + case-insensitiv ok")
os.unlink(db)

# ---------- Modus "username": E-Mail darf NICHT gehen ----------
auth, c, db = build(login_identifier="username")
auth.create_user("max", password="geheim12345", email="max@example.com")
assert login(c, "max").status_code == 303
assert login(c, "max@example.com").status_code != 303, "E-Mail darf im Username-Modus nicht greifen"
c.cookies.clear()
page = c.get("/auth/login").text
assert "Benutzer</label>" in page and "Benutzer oder E-Mail" not in page
os.unlink(db)

# ---------- Modus "email": Username darf NICHT gehen ----------
auth, c, db = build(login_identifier="email")
auth.create_user("max", password="geheim12345", email="max@example.com")
assert login(c, "max@example.com").status_code == 303
assert login(c, "max").status_code != 303, "Username darf im E-Mail-Modus nicht greifen"
c.cookies.clear()
assert "E-Mail</label>" in c.get("/auth/login").text
os.unlink(db)
print("  username-/email-only: jeweils nur die erlaubte Kennung ok")

# ---------- PIN nutzt dieselbe Kennung ----------
auth, c, db = build(login_identifier="both", pin_enabled=True)
uid = auth.create_user("max", password="geheim12345", email="max@example.com")
auth.set_pin(uid, "2468")
r = c.post("/auth/pin", data={"username": "max@example.com", "pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, "PIN-Login per E-Mail"
os.unlink(db)
print("  PIN akzeptiert dieselbe Kennung ok")

# ---------- E-Mail eindeutig ----------
auth, c, db = build()
auth.create_user("a", password="geheim12345", email="dup@example.com")
try:
    auth.create_user("b", password="geheim12345", email="DUP@example.com")
    raise AssertionError("Dublette wurde angenommen")
except ValueError:
    pass
assert auth.store.email_taken("dup@example.com")
assert not auth.store.email_taken("dup@example.com", exclude_id=auth.store.get_user_by_name("a")["id"])
os.unlink(db)
print("  E-Mail-Eindeutigkeit (case-insensitiv) ok")

# ---------- Registrierung: E-Mail Pflicht (Default) ----------
auth, c, db = build(allow_signup=True)
assert auth.cfg.signup_require_email is True, "Default = Pflicht"
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345", "next": "/"})
assert r.status_code == 400 and "E-Mail nötig" in r.text
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345", "email": "keine-mail", "next": "/"})
assert r.status_code == 400 and "gültige E-Mail" in r.text
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345",
                                   "email": "Neu@Example.com", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, r.text[:300]
assert auth.store.get_user_by_name("neu")["email"] == "neu@example.com", "kanonisch gespeichert"
r = c.post("/auth/register", data={"username": "neu2", "password": "geheim12345",
                                   "email": "NEU@example.com", "next": "/"})
assert r.status_code == 409 and "bereits registriert" in r.text
c.cookies.clear()
reg = c.get("/auth/register").text
email_tag = "<input name=email" + reg.split("<input name=email", 1)[1].split(">", 1)[0]
assert "required" in email_tag, "E-Mail-Feld als Pflicht markiert"
os.unlink(db)
print("  Registrierung: Pflicht + Format + Dublette ok")

# ---------- Registrierung folgt login_identifier ----------
auth, c, db = build(allow_signup=True, login_identifier="email")
page = c.get("/auth/register").text
assert "name=username" not in page, "im E-Mail-Modus kein Benutzernamen-Feld"
assert "name=email" in page and "required" in page
r = c.post("/auth/register", data={"password": "geheim12345", "email": "Solo@Example.com", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303, r.text[:300]
u = auth.store.get_user_by_email("solo@example.com")
assert u["username"] == "solo@example.com", "E-Mail ist die Kennung"
c.cookies.clear()
assert login(c, "solo@example.com").status_code == 303
os.unlink(db)

auth, c, db = build(allow_signup=True, login_identifier="username", signup_require_email=False)
page = c.get("/auth/register").text
assert "name=username" in page
if "<input name=email" in page:
    email_tag = "<input name=email" + page.split("<input name=email", 1)[1].split(">", 1)[0]
    assert "required" not in email_tag, "E-Mail darf hier nicht Pflicht sein"
os.unlink(db)
print("  Registrierung folgt login_identifier ok")

# ---------- Registrierung: E-Mail optional abschaltbar ----------
auth, c, db = build(allow_signup=True, signup_require_email=False)
r = c.post("/auth/register", data={"username": "ohne", "password": "geheim12345", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303
assert auth.store.get_user_by_name("ohne")["email"] is None
os.unlink(db)
print("  signup_require_email=False: Konto ohne E-Mail ok")

# ---------- E-Mail-Bestätigung (optional) ----------
sent = []
auth, c, db = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                    base_url="http://testserver")
auth.set_mailer(lambda to, subject, text, html=None: sent.append((to, text)))
r = c.post("/auth/register", data={"username": "verify", "password": "geheim12345",
                                   "email": "v@example.com", "next": "/"})
assert r.status_code == 200 and "Fast fertig" in r.text, r.text[:200]
u = auth.store.get_user_by_name("verify")
assert u["disabled"], "Konto bis zur Bestätigung gesperrt"
assert login(c, "v@example.com").status_code != 303, "gesperrtes Konto darf nicht rein"
assert sent and sent[0][0] == "v@example.com"
link = re.search(r"https?://\S+/auth/verify/(\S+)", sent[0][1]).group(1).rstrip(".,)")
c.get(f"/auth/verify/{link}", follow_redirects=False)
assert not auth.store.get_user_by_name("verify")["disabled"], "nach Bestätigung entsperrt"
assert login(c, "v@example.com").status_code == 303
os.unlink(db)
print("  signup_verify_email: gesperrt → Link → entsperrt → Login ok")

# ---------- Bestätigung an, aber kein Mailer → harter Fehler statt stiller Bypass ----------
# `base_url` steht hier, weil sie seit dieser Fassung Pflicht ist, sobald ein Mail-Weg an ist
# (sonst scheitert schon der Konstruktor). Geprüft wird die Lage danach: Basis ja, Mailer nein.
auth, c, db = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                    base_url="http://testserver")
r = c.post("/auth/register", data={"username": "x", "password": "geheim12345",
                                   "email": "x@example.com", "next": "/"})
assert r.status_code == 500 and "kein Mailer" in r.text
assert auth.store.get_user_by_name("x") is None, "kein halbfertiges Konto angelegt"
os.unlink(db)
print("  verify ohne Mailer: 500, kein Konto ok")

# ---------- Config-Sanity ----------
for bad in ("mail", "", "Username"):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei"), login_identifier=bad))
        raise AssertionError(f"login_identifier={bad!r} akzeptiert")
    except ValueError:
        pass
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei"), login_identifier="email",
                              allow_signup=True, signup_require_email=False))
    raise AssertionError("email-only ohne E-Mail-Pflicht akzeptiert")
except ValueError:
    pass
print("  Config-Sanity ok")

# ---------- Kreuz-Kollision: der ConfigError trägt Feld und Besitzer (R4-12) ----------
# Zugesagt im CHANGELOG unter „Für einbettende Apps": Der Meldungstext bleibt der von 0.18.x
# („… ist bereits vergeben"), damit ein Aufrufer, der den Text prüft, an diesem Fix nicht bricht
# — und unterscheiden lässt sich der Fall jetzt OHNE Textvergleich an `e.feld` und
# `e.besitzer_id`. Beide Hälften der Zusage waren von keiner einzigen Zeile gedeckt: Mutation
# M25 (die Attribute nicht mehr setzen) und M34 (Wortlaut zurück auf „… ist bereits als
# Login-Kennung vergeben") liefen je mit 46/46 grün durch. `grep -rn "besitzer_id" tests/` fand
# nichts. Genau die Zusage, die den Textvergleich ersetzen sollte, und genau der Textvergleich,
# den sie retten sollte.
from tinysesam import ConfigError  # noqa: E402

auth, c, db = build(login_identifier="both")
opfer_id = auth.create_user("opfer", password="geheim12345", email="chef@example.com")
for kennung, mail, feld in (("chef@example.com", None, "username"),   # Name == fremde E-Mail
                            ("neu", "chef@example.com", "email")):    # E-Mail == fremde E-Mail
    try:
        auth.create_user(kennung, email=mail)
        raise AssertionError(f"{feld}: die Kreuzprüfung greift nicht, das Konto entstand")
    except ConfigError as e:
        assert "bereits vergeben" in str(e), (
            f"{feld}: Wortlaut geändert ({str(e)!r}) — Aufrufer aus 0.18.x prüfen genau diesen "
            "Text, und der CHANGELOG sagt ihnen zu, dass er bleibt")
        assert getattr(e, "feld", None) == feld, (
            f"e.feld ist {getattr(e, 'feld', '<fehlt>')!r}, erwartet {feld!r} — ohne das Attribut "
            "bleibt der Textvergleich der einzige Weg, die beiden Fälle zu trennen")
        assert getattr(e, "besitzer_id", None) == opfer_id, (
            f"e.besitzer_id ist {getattr(e, 'besitzer_id', '<fehlt>')!r}, erwartet {opfer_id}")
# Gegenprobe: eine freie Kennung wirft nicht — sonst wäre „wirft immer" auch grün.
frei_id = auth.create_user("frei", email="frei@example.com")
assert frei_id and auth.store.get_user(frei_id)["username"] == "frei"
os.unlink(db)
print("  Kreuz-Kollision: Wortlaut bleibt, e.feld/e.besitzer_id benennen den Fall ok")

print("OK test_identifier")
