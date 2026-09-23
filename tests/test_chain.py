"""Phase 4.5: Faktor-Ketten-Engine — geordnete Kombinationen, global + per-Route, strict-Flag."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import time
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def fresh(chain=None, strict=True, **kw):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    cfg = TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                          cookie_secure=False, login_chain=chain or [], login_chain_strict=strict,
                          pin_enabled=True, **kw)
    auth = TinySesam(cfg)
    auth.ensure_admin("admin", "geheim123")
    uid = auth.store.get_user_by_name("admin")["id"]
    auth.set_pin(uid, "2468")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, uid, app


# ---------- Globale Kette ["pin","password"] strikt: Reihenfolge erzwungen ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=True)


@app.get("/area")
def area(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# Erstfaktor PIN → Sitzung unvollständig, noch kein Zugriff
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/login"), r.headers.get("location")
assert c.get("/area", headers=JSON).status_code == 401
ok("Kette pin→password: nach PIN erst Weiterleitung zu /auth/login, noch kein Zugriff")

# Zweiter Faktor Passwort → Kette erfüllt → Zugriff
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/area", r.headers.get("location")
assert c.get("/area", headers=JSON).json() == {"u": "admin"}
ok("Kette pin→password: nach Passwort vollständig eingeloggt")
os.remove(db)

# ---------- Strikt: falsche Reihenfolge gewährt KEINEN Zugriff ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=True)
c = TestClient(app)
# Passwort zuerst (falsche Reihenfolge) → wird zu /auth/pin geschickt, aber nie „fertig"
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/pin")
assert c.get("/geheim", headers=JSON).status_code == 401
ok("strikt: Passwort-vor-PIN erfüllt die Kette nicht (kein Zugriff)")
os.remove(db)

# ---------- Nicht-strikt: beliebige Reihenfolge genügt ----------
db, auth, uid, app = fresh(chain=["pin", "password"], strict=False)
c = TestClient(app)
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert c.get("/geheim", headers=JSON).status_code == 401   # nur ein Faktor
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("nicht-strikt: Passwort dann PIN (umgekehrte Reihenfolge) genügt")
os.remove(db)

# ---------- Globale Kette ["password","totp"] mit echtem TOTP ----------
db, auth, uid, app = fresh(chain=["password", "totp"], strict=True)
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))
c = TestClient(app)
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"].startswith("/auth/totp")
assert c.get("/geheim", headers=JSON).status_code == 401
r = c.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/geheim"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("Kette password→totp erfüllt")
os.remove(db)

# ---------- Per-Route-Override: Route verlangt zusätzlich einen bestimmten Faktor ----------
db, auth, uid, app = fresh(chain=[])   # global klassisch


@app.get("/pin-area")
def pin_area(u=Depends(auth.require(factors=["password", "pin"]))):
    return {"u": u["username"]}


c = TestClient(app)
# klassischer Passwort-Login (global vollständig, kein TOTP)
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}       # normale Route frei
r = c.get("/pin-area", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"].startswith("/auth/pin"), r.headers.get("location")
# PIN als Zusatzfaktor an die laufende Sitzung anhängen
r = c.post("/auth/pin", data={"username": "admin", "pin": "2468", "next": "/pin-area"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/pin-area"
assert c.get("/pin-area", headers=JSON).json() == {"u": "admin"}
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}       # normale Route weiterhin frei
ok("per-Route factors=[password,pin]: PIN als Zusatzfaktor, Sitzung bleibt gültig")
os.remove(db)

# ---------- R3-1: die Kette schützt auch Konten OHNE den Faktor ----------
# `login_chain=["password","totp"]` liest sich wie „ohne zweiten Faktor kommt niemand rein".
# Bis 0.18.x stimmte das nicht: Ein Konto ohne TOTP durfte es an genau dieser Stelle selbst
# einrichten — wer also nur das Passwort hatte, band seinen eigenen Authenticator ein und war
# voll drin. Die Kette schützte alle ausser denen, für die sie gedacht war.
import time as _zeit                                                      # noqa: E402
from tinysesam.errors import ConfigError as _ConfigError                  # noqa: E402


def _kette_ohne_totp(**kw):
    """Eine App mit Kette password+totp und einem Konto, das KEIN TOTP hat."""
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test",
                                     passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                     login_chain=["password", "totp"], **kw))
    uid = auth.create_user("neu", password="geheim123")
    app = FastAPI()
    app.include_router(auth.router())
    return db, auth, uid, app


def _bis_zum_zweiten_faktor(app):
    c = TestClient(app)
    c.post("/auth/login", data={"username": "neu", "password": "geheim123", "next": "/"},
           follow_redirects=False)
    return c


# Vorgabe „first_login": ein frisches Konto darf sich einrichten — sonst wäre jedes neue Konto
# eine Sackgasse und der Betreiber müsste an die Datenbank.
db_a, auth_a, uid_a, app_a = _kette_ohne_totp()
assert auth_a.darf_mfa_einrichten(uid_a) is True
c_a = _bis_zum_zweiten_faktor(app_a)
assert c_a.get("/auth/totp", headers={"Accept": "text/html"}, follow_redirects=False
               ).headers.get("location", "").startswith("/auth/totp/setup")
ok("R3-1: ein noch nie benutztes Konto richtet den zweiten Faktor selbst ein (Vorgabe)")

# …aber nur bis zum ersten vollständigen Login. Danach ist der Weg zu — genau der Fall, in dem
# jemand das Passwort eines BESTEHENDEN Kontos hat.
auth_a.store.mark_first_login(uid_a, int(_zeit.time()))
assert auth_a.darf_mfa_einrichten(uid_a) is False
c_a2 = _bis_zum_zweiten_faktor(app_a)
_ziel = c_a2.get("/auth/totp", headers={"Accept": "text/html"}, follow_redirects=False
                 ).headers.get("location", "")
assert not _ziel.startswith("/auth/totp/setup"), f"Einrichtung offen geblieben: {_ziel!r}"
assert auth_a.store.get_user(uid_a)["first_login_at"] is not None
ok("R3-1: nach dem ersten vollständigen Login ist die Selbst-Einrichtung zu")

# Und die Meldung darüber ist KEIN Fehlversuch: Wer hier scheitert, hat sein richtiges Passwort
# eingegeben. Trüge die Zeile das Ereigniswort der Login-Jail, sperrte fail2ban genau den, der
# sich gerade korrekt angemeldet hat. (Gefunden, weil CodeQL die Zeile als Passwort-Logging
# meldete — der Fehlalarm zeigte auf einen echten Fehler daneben.)
import io as _io, logging as _logging                                     # noqa: E402
from tinysesam import security as _security                               # noqa: E402

_puffer = _io.StringIO()
_haken = _logging.StreamHandler(_puffer)
_security.seclog.addHandler(_haken)
try:
    _bis_zum_zweiten_faktor(app_a).get("/auth/totp", headers={"Accept": "text/html"},
                                       follow_redirects=False)
finally:
    _security.seclog.removeHandler(_haken)
_text = _puffer.getvalue()
assert "mfa enrollment denied" in _text, f"keine Meldung: {_text[:200]!r}"
assert _security.log_ereignis("totp") not in _text, \
    f"die gesperrte Einrichtung trägt das Wort der Login-Jail: {_text[:200]!r}"
ok("R3-1: …die Meldung darüber trifft die fail2ban-Jail nicht (es ist kein Fehlversuch)")

# Der Betreiber kann ein Fenster öffnen — der Weg für „Gerät verloren" und für strict.
_bis = auth_a.grant_mfa_enrollment(uid_a, minutes=30)
assert _bis > int(_zeit.time())
assert auth_a.darf_mfa_einrichten(uid_a) is True
assert auth_a.darf_mfa_einrichten(uid_a, jetzt=_bis + 1) is False
auth_a.revoke_mfa_enrollment(uid_a)
assert auth_a.darf_mfa_einrichten(uid_a) is False
ok("R3-1: ein Einrichtungsfenster des Betreibers gewinnt — zeitlich begrenzt und rücknehmbar")

# „strict": nie von selbst, auch nicht beim ersten Mal.
db_s, auth_s, uid_s, app_s = _kette_ohne_totp(mfa_enrollment="strict")
assert auth_s.darf_mfa_einrichten(uid_s) is False
_ziel_s = _bis_zum_zweiten_faktor(app_s).get("/auth/totp", headers={"Accept": "text/html"},
                                             follow_redirects=False).headers.get("location", "")
assert not _ziel_s.startswith("/auth/totp/setup"), _ziel_s
assert auth_s.grant_mfa_enrollment(uid_s, minutes=5) and auth_s.darf_mfa_einrichten(uid_s) is True
ok("R3-1: mfa_enrollment='strict' verweigert auch dem frischen Konto — bis der Betreiber öffnet")

# „grace": eine Frist ab Kontoanlage, danach zu.
db_g, auth_g, uid_g, app_g = _kette_ohne_totp(mfa_enrollment="grace", mfa_enrollment_grace_days=7)
assert auth_g.darf_mfa_einrichten(uid_g) is True
assert auth_g.darf_mfa_einrichten(uid_g, jetzt=int(_zeit.time()) + 8 * 86400) is False
ok("R3-1: mfa_enrollment='grace' läuft nach der eingestellten Zahl Tage ab")

# Ohne Zwang bleibt alles beim Alten: Verlangt die Kette keinen zweiten Faktor, richtet ihn
# jeder Angemeldete jederzeit selbst ein.
db_o = os.path.join(tempfile.mkdtemp(), "t.db")
auth_o = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_o, rp_name="Test",
                                   passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                   mfa_enrollment="strict"))
uid_o = auth_o.create_user("frei", password="geheim123")
app_o = FastAPI()
app_o.include_router(auth_o.router())
c_o = TestClient(app_o)
c_o.post("/auth/login", data={"username": "frei", "password": "geheim123", "next": "/"},
         follow_redirects=False)
assert c_o.get("/auth/totp/setup", headers={"Accept": "text/html"}).status_code == 200, \
    "ohne Kettenzwang muss ein freiwilliges TOTP weiter einrichtbar sein"
ok("R3-1: ist MFA optional, gilt der Riegel nicht — freiwillig bleibt freiwillig")

# Eine unbekannte Betriebsart bricht beim Aufbau ab, statt still zu erlauben.
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                              passkey_enabled=False, mfa_enrollment="irgendwas"))
    raise AssertionError("unbekannte Betriebsart kam durch")
except _ConfigError:
    pass
ok("R3-1: ein Tippfehler in mfa_enrollment bricht den Aufbau ab")

for _d in (db_a, db_s, db_g, db_o):
    os.remove(_d)

print("\nFAKTOR-KETTEN OK ✅")
