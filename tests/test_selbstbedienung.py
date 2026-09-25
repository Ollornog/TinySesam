"""Selbstbedienung: Benutzername und E-Mail-Adresse ändern (PO-Entscheid 2026-09-25).

Jeder ändert beides selbst, mit frischem Step-up; die Adresse gilt erst nach dem Klick auf den Link
an die NEUE. Alles hängt an der Konto-ID — nach aussen trägt `Remote-Id` sie, stabil über jede
Änderung. Gemessen wird die Wirkung über die Routen, dazu die Riegel: fremde oder Allowlist-Namen,
Adressen als Namen, kein Orakel für vergebene Adressen, Kollision beim Bestätigen, alte Links.
"""
from __future__ import annotations

import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Selbstbedienung — Benutzername und Adresse ändern")
PW = "Selbst-Test-Pw15"
HTML = {"accept": "text/html"}


def _aufbau(**cfg):
    mails: list = []
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False, base_url="http://testserver", lang="de",
                 admin_identifiers=["chef-reserviert", "Boss@Example.com"], password_reset_enabled=True)
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    auth.set_mailer(lambda to, betreff, text, html=None: mails.append((to, betreff, text)))
    app = FastAPI()
    app.include_router(auth.router())
    ereignisse: list = []
    auth.on_security_event = lambda e, konto, d: ereignisse.append((e, d))
    return auth, app, mails, ereignisse


def _login(app, name):
    c = TestClient(app)
    c.post("/auth/login", data={"username": name, "password": PW}, follow_redirects=False)
    return c


def _altern(auth):
    auth.store._exec("UPDATE session SET mfa_at=?", (int(time.time()) - 100000,))


# ── Benutzername ─────────────────────────────────────────────────────────────────────────
auth, app, mails, ev = _aufbau()
uid = auth.create_user("anna", password=PW, email="anna@example.com")
auth.create_user("bert", password=PW, email="bert@example.com")
c = _login(app, "anna")
seite = c.get("/auth/account", headers=HTML).text
r.check("Konto-Seite bietet Benutzername und Adresse an", "data-act=setname" in seite and "data-act=setmail" in seite)
id_vorher = auth.forward_response_headers(auth.get_user(uid))["Remote-Id"]
a = c.post("/auth/account/username", json={"username": "anna.neu"})
r.check("Benutzername geändert (frisch angemeldet)", a.status_code == 200 and auth.get_user(uid)["username"] == "anna.neu",
        f"{a.status_code} {a.text[:120]}")
kopf = auth.forward_response_headers(auth.get_user(uid))
r.check("… Remote-Id bleibt die Konto-ID, Remote-User folgt dem neuen Namen",
        kopf["Remote-Id"] == id_vorher == str(uid) and kopf["Remote-User"] == "anna.neu")
r.check("… die Sitzung bleibt (sie hängt an der ID)", c.get("/auth/me").status_code == 200)
r.check("… Sicherheitsereignis und Audit-Zeile",
        ("username_changed", {"alt": "anna", "neu": "anna.neu"}) in ev
        and auth.store._one("SELECT 1 FROM audit WHERE event='username_changed'") is not None, str(ev))
r.check("… Anmelden mit dem neuen Namen geht, mit dem alten nicht",
        _login(app, "anna.neu").get("/auth/me").status_code == 200
        and _login(app, "anna").get("/auth/me").status_code == 401)
fehl = {n: c.post("/auth/account/username", json={"username": n}).status_code
        for n in ("bert", "bert@example.com", "fremd@example.com", "chef-reserviert", "CHEF-reserviert",
                  "zwei\x01", "", "x" * 151)}
r.check("vergeben, fremde Adresse, Allowlist-Name, Steuerzeichen, leer, zu lang → 400",
        set(fehl.values()) == {400} and auth.get_user(uid)["username"] == "anna.neu", str(fehl))
r.check("… die eigene BESTÄTIGTE Adresse als Name geht",
        c.post("/auth/account/username", json={"username": "anna@example.com"}).status_code == 200)
_altern(auth)
alt_ = c.post("/auth/account/username", json={"username": "anna3"})
r.check("ohne frischen Step-up → 403 mit Reauth-Hinweis", alt_.status_code == 403
        and alt_.headers.get("x-tinysesam-reauth"), f"{alt_.status_code} {dict(alt_.headers)}")
key = auth.create_api_key(uid, name="skript", kind="mensch")["key"]
mit_key = TestClient(app).post("/auth/account/username", json={"username": "per-key"},
                               headers={"Authorization": f"Bearer {key}"})
r.check("ein API-Key ändert keinen Namen", mit_key.status_code in (401, 403), str(mit_key.status_code))

auth_e, app_e, _, _ = _aufbau(login_identifier="email", signup_require_email=True)
auth_e.create_user("emil@example.com", password=PW, email="emil@example.com")
ce = _login(app_e, "emil@example.com")
r.check("Mail-Modus: kein eigener Namenswechsel (der Name folgt der Adresse), Seite bietet ihn nicht an",
        ce.post("/auth/account/username", json={"username": "emil"}).status_code == 400
        and "data-act=setname" not in ce.get("/auth/account", headers=HTML).text)

# ── Adresse ──────────────────────────────────────────────────────────────────────────────
auth, app, mails, ev = _aufbau()
uid = auth.create_user("carla", password=PW, email="carla@example.com")
auth.create_user("dora", password=PW, email="dora@example.com")
c = _login(app, "carla")
reset_alt = auth.create_magic_token("reset_password", user_id=uid, email="carla@example.com")
mails.clear()
a = c.post("/auth/account/email", json={"email": "Carla.Neu@Example.com"})
auth._hinweis_ausgang.abwarten()
r.check("Adresswechsel beantragt → Link an die NEUE Adresse, das Konto ändert sich noch nicht",
        a.status_code == 200 and a.json() == {"ok": True, "sent": True}
        and [m[0] for m in mails] == ["carla.neu@example.com"]
        and auth.get_user(uid)["email"] == "carla@example.com", f"{a.text} {mails}")
link = re.search(r"http://testserver(/auth/email/[^\s]+)", mails[0][2]).group(1) if mails else ""
seite = c.get(link, headers=HTML)
r.check("… der Link zeigt eine Bestätigungsseite (GET löst nichts ein)",
        seite.status_code == 200 and "<form" in seite.text and auth.get_user(uid)["email"] == "carla@example.com")
mails.clear()
fertig = TestClient(app).post(link, follow_redirects=False)       # auch aus einem anderen Browser
auth._hinweis_ausgang.abwarten()
konto = auth.get_user(uid)
r.check("… eingelöst: neue Adresse MIT Beleg, zurück zur Konto-Seite",
        fertig.status_code == 303 and fertig.headers["location"] == "/auth/account"
        and konto["email"] == "carla.neu@example.com" and konto["email_verified"], f"{fertig.status_code} {dict(konto)}")
r.check("… die alte Adresse bekommt einen Hinweis — ohne Link (nichts, dessen Basis zu prüfen wäre)",
        [m[0] for m in mails] == ["carla@example.com"] and "://" not in mails[0][2], str(mails))
r.check("… offene Links an die alte Adresse gelten nicht mehr",
        auth.peek_magic(reset_alt, purpose="reset_password") is None)
r.check("… Sicherheitsereignis mit alt/neu",
        ("email_changed", {"alt": "carla@example.com", "neu": "carla.neu@example.com"}) in ev, str(ev))
r.check("… derselbe Link ein zweites Mal: ungültig", TestClient(app).post(link).status_code == 400)

mails.clear()
vergeben = c.post("/auth/account/email", json={"email": "dora@example.com"})
auth._hinweis_ausgang.abwarten()
r.check("eine vergebene Adresse: dieselbe Antwort, aber kein Link (kein Orakel), Zeile im Audit-Log",
        vergeben.status_code == 200 and vergeben.json() == {"ok": True, "sent": True} and not mails
        and auth.store._one("SELECT 1 FROM audit WHERE event='email_change_taken'") is not None)
r.check("ungültige Adresse → 400", c.post("/auth/account/email", json={"email": "kaputt"}).status_code == 400)
# Allowlist-Adresse: Klickte ihr Inhaber den Link (auf einer Instanz ohne Admin), trüge das fremde
# Konto die belegte Adresse und wäre beim nächsten Login Erst-Admin.
mails.clear()
reserviert = c.post("/auth/account/email", json={"email": "boss@EXAMPLE.com"})
auth._hinweis_ausgang.abwarten()
r.check("eine Adresse aus admin_identifiers: dieselbe Antwort, kein Link, Zeile im Audit-Log",
        reserviert.status_code == 200 and reserviert.json() == {"ok": True, "sent": True} and not mails
        and auth.store._one("SELECT 1 FROM audit WHERE event='email_change_reserved'") is not None, str(mails))
mails.clear()
c.post("/auth/account/email", json={"email": "spaeter.boss@example.com"})
link3 = re.search(r"http://testserver(/auth/email/[^\s]+)", mails[0][2]).group(1)
auth.cfg.admin_identifiers.append("spaeter.boss@example.com")
r.check("… kommt sie erst nach dem Antrag in die Liste: 409 beim Einlösen, nichts geändert",
        TestClient(app).post(link3).status_code == 409 and auth.get_user(uid)["email"] == "carla.neu@example.com")
# Kollision beim Bestätigen: Zwischen Antrag und Klick belegt ein anderes Konto die Adresse.
mails.clear()
c.post("/auth/account/email", json={"email": "frei@example.com"})
link2 = re.search(r"http://testserver(/auth/email/[^\s]+)", mails[0][2]).group(1)
auth.create_user("frieda", password=PW, email="frei@example.com")
r.check("… wird die Adresse bis zum Klick vergeben: 409, nichts geändert",
        TestClient(app).post(link2).status_code == 409 and auth.get_user(uid)["email"] == "carla.neu@example.com")
_altern(auth)
r.check("ohne frischen Step-up → 403", c.post("/auth/account/email", json={"email": "x@example.com"}).status_code == 403)

# Mail-Modus: der Benutzername zieht mit.
auth_e, app_e, mails_e, _ = _aufbau(login_identifier="email", signup_require_email=True)
uid_e = auth_e.create_user("emil@example.com", password=PW, email="emil@example.com")
ce = _login(app_e, "emil@example.com")
ce.post("/auth/account/email", json={"email": "emil.neu@example.com"})
link_e = re.search(r"http://testserver(/auth/email/[^\s]+)", mails_e[-1][2]).group(1)
TestClient(app_e).post(link_e)
r.check("Mail-Modus: nach der Bestätigung ist der Benutzername die neue Adresse",
        auth_e.get_user(uid_e)["username"] == "emil.neu@example.com")

# Ohne Mailversand gibt es den Weg nicht (die Seite bietet ihn nicht an, die Route sagt 400).
auth_o, app_o, _, _ = _aufbau()
auth_o.set_mailer(None)
auth_o.create_user("otto", password=PW, email="otto@example.com")
co = _login(app_o, "otto")
r.check("ohne Mailer: kein Adresswechsel",
        "data-act=setmail" not in co.get("/auth/account", headers=HTML).text
        and co.post("/auth/account/email", json={"email": "o2@example.com"}).status_code == 400)
# (Mutationsproben: der Step-up in `_frisch_fuer_kennung` weg → „ohne frischen Step-up" rot; die
#  Allowlist-Prüfung weg → Allowlist-Name rot; die @-Regel weg → „fremde Adresse" rot; der
#  Kennungs-Abgleich beim Bestätigen weg → 409 rot; `revoke_user_magic_tokens` weg → „offene Links"
#  rot; `verified=True` weg → „MIT Beleg" rot; `Remote-Id` weg → Remote-Id rot.)

sys.exit(r.done())
