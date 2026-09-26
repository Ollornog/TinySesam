"""Selbstbedienung: Benutzername und E-Mail-Adresse ändern (PO-Entscheid 2026-09-25).

Jeder ändert beides selbst, mit frischem Step-up; die Adresse gilt erst nach dem Klick auf den Link
an die NEUE. Alles hängt an der Konto-ID — nach aussen trägt `Remote-Id` sie, stabil über jede
Änderung. Gemessen wird die Wirkung über die Routen, dazu die Riegel: fremde oder Allowlist-Namen,
Adressen als Namen, kein Orakel für vergebene Adressen, Kollision beim Bestätigen, alte Links.
Seit G12b (2026-09-26) heisst „kein Orakel" mehr als dieselbe Antwort: derselbe Hinweis an die
eigene Adresse, dasselbe Kontingent, dieselbe Kontoseite und dieselbe Arbeit der Datenbank.
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
        and [m[0] for m in mails if "/auth/email/" in m[2]] == ["carla.neu@example.com"]
        and auth.get_user(uid)["email"] == "carla@example.com", f"{a.text} {mails}")
r.check("… die Mail nennt das Konto, für das bestätigt wird",
        any(m[0] == "carla.neu@example.com" and "„carla“" in m[2] for m in mails), str(mails))
_antrag = [m for m in mails if m[0] == "carla@example.com"]
r.check("… schon der Antrag geht als Hinweis an die bisherige belegte Adresse — ohne Link",
        len(_antrag) == 1 and "carla.neu@example.com" in _antrag[0][2] and "://" not in _antrag[0][2],
        str(mails))
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

# Vergeben/reserviert: kein Link — aber der Hinweis an die eigene Adresse wie bei jedem Antrag
# (G12b; bis 2026-09-26 blieb er aus, und genau das verriet „vergeben").
_HINWEIS = ("carla.neu@example.com", "Änderung deiner E-Mail-Adresse beantragt")
mails.clear()
vergeben = c.post("/auth/account/email", json={"email": "dora@example.com"})
auth._hinweis_ausgang.abwarten()
r.check("eine vergebene Adresse: dieselbe Antwort, kein Link, nur der Hinweis an die eigene, Zeile im Audit-Log",
        vergeben.status_code == 200 and vergeben.json() == {"ok": True, "sent": True}
        and [m[:2] for m in mails] == [_HINWEIS]
        and auth.store._one("SELECT 1 FROM audit WHERE event='email_change_taken'") is not None, str(mails))
r.check("ungültige Adresse → 400", c.post("/auth/account/email", json={"email": "kaputt"}).status_code == 400)
# Allowlist-Adresse: Klickte ihr Inhaber den Link (auf einer Instanz ohne Admin), trüge das fremde
# Konto die belegte Adresse und wäre beim nächsten Login Erst-Admin.
mails.clear()
reserviert = c.post("/auth/account/email", json={"email": "boss@EXAMPLE.com"})
auth._hinweis_ausgang.abwarten()
r.check("eine Adresse aus admin_identifiers: dieselbe Antwort, kein Link, nur der Hinweis, Zeile im Audit-Log",
        reserviert.status_code == 200 and reserviert.json() == {"ok": True, "sent": True}
        and [m[:2] for m in mails] == [_HINWEIS]
        and auth.store._one("SELECT 1 FROM audit WHERE event='email_change_reserved'") is not None, str(mails))
# Beide Anträge haben das Kontingent des Kontos verbraucht wie ein freier (G12b) — für die
# folgenden Fälle ein frisches Fenster.
auth.rl = type(auth.rl)()
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
_carla = [e["event"] for e in auth.own_events(uid, limit=100)]
r.check("Kontoseite: jeder Antrag heisst email_change_requested (5), nur die Abweisung BEIM Bestätigen "
        "behält ihren Namen (die 409 hat sie ohnehin gesagt)",
        _carla.count("email_change_requested") == 5 and _carla.count("email_change_taken") == 1
        and _carla.count("email_change_reserved") == 1, str(_carla))
_altern(auth)
r.check("ohne frischen Step-up → 403", c.post("/auth/account/email", json={"email": "x@example.com"}).status_code == 403)

# ── Ein offener Wechsel überlebt keine Abwehr (Angriffsrunde, Fund 1) ─────────────────────
# Ein Eindringling mit frischer Sitzung beantragt den Wechsel auf SEINE Adresse; der Link liegt in
# seinem Postfach. Der Inhaber setzt das Passwort zurück, ändert es oder beendet Sitzungen — der
# Link muss damit fallen, sonst klickt der Eindringling danach, und der nächste Reset geht an ihn.
def _abwehr_aufbau():
    a, ap, post, _ = _aufbau()
    a.create_user("chefin", password=PW, email="chefin@example.com")
    a.store.set_admin(a.store.get_user_by_name("chefin")["id"], True)
    u = a.create_user("opfer", password=PW, email="opfer@example.com")
    return a, ap, post, u


def _eindringling_beantragt(a, ap, post):
    post.clear()
    _login(ap, "opfer").post("/auth/account/email", json={"email": "dieb@example.org"})
    a._hinweis_ausgang.abwarten()
    return re.search(r"http://testserver(/auth/email/[^\s]+)",
                     next(m[2] for m in post if m[0] == "dieb@example.org")).group(1)


def _reset(a, ap, u):
    roh = a.create_magic_token("reset_password", user_id=u, email="opfer@example.com")
    TestClient(ap).post("/auth/reset", data={"token": roh, "password": "Ganz-Neues-Pw15"})


def _pw_wechsel(a, ap, u):
    _login(ap, "opfer").post("/auth/password", json={"current": PW, "new": "Ganz-Neues-Pw15"})


def _alle_beenden(a, ap, u):
    _login(ap, "opfer").post("/auth/sessions/revoke", json={"scope": "all"})


def _andere_beenden(a, ap, u):
    _login(ap, "opfer").post("/auth/sessions/revoke", json={"scope": "others"})


def _admin_reset(a, ap, u):
    _login(ap, "chefin").post(f"/auth/admin/api/users/{u}/password", json={"password": "Admin-Setzt-Pw15"})


for titel, abwehr in (("Passwort-Reset", _reset), ("Passwortwechsel auf der Konto-Seite", _pw_wechsel),
                      ("alle Sitzungen beenden", _alle_beenden), ("andere Sitzungen beenden", _andere_beenden),
                      ("Passwort-Reset durch den Admin", _admin_reset)):
    a_, ap_, post_, u_ = _abwehr_aufbau()
    link_ = _eindringling_beantragt(a_, ap_, post_)
    abwehr(a_, ap_, u_)
    spaeter = TestClient(ap_).post(link_, follow_redirects=False)
    r.check(f"{titel}: der offene Wechsel-Link des Eindringlings gilt danach nicht mehr",
            spaeter.status_code == 400 and a_.get_user(u_)["email"] == "opfer@example.com",
            f"{spaeter.status_code} {a_.get_user(u_)['email']}")

# Streuen: Ein Konto schickt Wechsel-Mails nicht an beliebig viele fremde Adressen (Fund 3).
a_s, ap_s, post_s, _ = _aufbau()
a_s.create_user("streuer", password=PW, email="streuer@example.com")
c_s = _login(ap_s, "streuer")
for i in range(12):
    c_s.post("/auth/account/email", json={"email": f"ziel{i}@example.org"})
a_s._hinweis_ausgang.abwarten()
_ziele = {m[0] for m in post_s if "/auth/email/" in m[2]}
r.check("ein Konto erreicht mit Wechsel-Links höchstens so viele Adressen wie das Kontingent erlaubt",
        0 < len(_ziele) <= int(a_s.sec("mail_per_address_max"))
        and a_s.store._one("SELECT 1 FROM audit WHERE event='mail_ratelimit' AND detail LIKE 'email_change konto=%'")
        is not None, f"{len(_ziele)} Adressen")

# Gefaltet geprüft (Fund 3 LDAP/SAML-Runde): `＠` (U+FF20) ergäbe gefaltet zwei `@`.
r.check("eine Adresse, die erst gefaltet ungültig ist → 400",
        _login(ap_s, "streuer").post("/auth/account/email",
                                     json={"email": "x\uff20evil.example@example.com"}).status_code == 400)

# ── G12b: kein Orakel für vergebene Adressen ────────────────────────────────────────────────
# Gemessen bis 2026-09-26, bei wortgleicher Antwort: der Hinweis an die eigene Adresse nur bei
# einer freien, das Kontingent des Kontos nur von freien verbraucht, die Kontoseite nannte
# `email_change_taken`, und die Datenbank tat bei einer vergebenen eine Zeile weniger. Je Ziel ein
# frischer Aufbau — gleiche Ausgangslage, nur das Ziel unterscheidet sich.
ZIELE = (("vergeben", "bert@example.com"), ("reserviert", "boss@example.com"), ("frei", "neu@example.com"))


def _g12b_aufbau():
    a, ap, post, _ = _aufbau()
    konto = a.create_user("anna", password=PW, email="anna@example.com")
    a.create_user("bert", password=PW, email="bert@example.com")
    return a, ap, post, konto


def _form(sql):
    """Eine Anweisung ohne ihre Werte: Welche Tabelle, welche Spalten, welche Bedingung."""
    return re.sub(r"\b\d+\b", "?", re.sub(r"'(?:[^']|'')*'", "?", sql)).strip()


_g = {}
for art, ziel in ZIELE:
    a, ap, post, konto = _g12b_aufbau()
    c_g = _login(ap, "anna")
    post.clear()
    antw = c_g.post("/auth/account/email", json={"email": ziel})
    a._hinweis_ausgang.abwarten()
    _g[art] = {"auth": a, "antwort": (antw.status_code, antw.text),
               "eigene": [m[1] for m in post if m[0] == "anna@example.com"],
               "ziel": [m[1] for m in post if m[0] == ziel],
               "ereignisse": [e["event"] for e in a.own_events(konto, limit=50)],
               "seite": re.findall(r"email_change_\w+|federation_email_confirm",
                                   c_g.get("/auth/account", headers=HTML).text)}
r.check("G12b: dieselbe Antwort für vergeben, reserviert und frei",
        len({str(g["antwort"]) for g in _g.values()}) == 1, str({k: g["antwort"] for k, g in _g.items()}))
r.check("G12b: an die eigene Adresse in allen drei Fällen genau ein Hinweis",
        all(g["eigene"] == ["Änderung deiner E-Mail-Adresse beantragt"] for g in _g.values()),
        str({k: g["eigene"] for k, g in _g.items()}))
r.check("… an die vergebene und die reservierte nichts, an die freie der Link",
        _g["vergeben"]["ziel"] == [] and _g["reserviert"]["ziel"] == []
        and _g["frei"]["ziel"] == ["Neue E-Mail-Adresse bestätigen"], str({k: g["ziel"] for k, g in _g.items()}))
r.check("G12b: Kontoseite (own_events) in allen drei Fällen gleich, der Antrag als email_change_requested",
        _g["vergeben"]["ereignisse"] == _g["reserviert"]["ereignisse"] == _g["frei"]["ereignisse"]
        and "email_change_requested" in _g["frei"]["ereignisse"], str({k: g["ereignisse"] for k, g in _g.items()}))
r.check("… ebenso die gerenderte Konto-Seite",
        all(g["seite"] == ["email_change_requested"] for g in _g.values()), str({k: g["seite"] for k, g in _g.items()}))
r.check("… das Audit-Log des Betreibers behält die echten Namen",
        _g["vergeben"]["auth"].store._one("SELECT 1 FROM audit WHERE event='email_change_taken'") is not None
        and _g["reserviert"]["auth"].store._one("SELECT 1 FROM audit WHERE event='email_change_reserved'") is not None)

# Kontingent: Drei Anträge auf eine vergebene Adresse verbrauchen es wie drei auf freie — danach
# geht auch an eine eigene Kontrolladresse kein Link mehr. Vorher verriet genau das „vergeben".
_kontrolle = {}
for art, ziele in (("vergeben", ["bert@example.com"] * 3),
                   ("frei", ["x1@example.com", "x2@example.com", "x3@example.com"])):
    a, ap, post, _k = _g12b_aufbau()
    c_k = _login(ap, "anna")
    for z in ziele:
        c_k.post("/auth/account/email", json={"email": z})
    a._hinweis_ausgang.abwarten()
    post.clear()
    c_k.post("/auth/account/email", json={"email": "kontrolle@example.com"})
    a._hinweis_ausgang.abwarten()
    _kontrolle[art] = [m[0] for m in post if m[0] == "kontrolle@example.com"]
r.check("G12b: nach 3× vergeben wie nach 3× frei kein Link an die Kontrolladresse",
        _kontrolle == {"vergeben": [], "frei": []}, str(_kontrolle))

# Arbeit der Datenbank, ohne Stoppuhr: dieselbe Folge von Anweisungen (ohne ihre Werte), dieselbe
# Zahl geschriebener Zeilen — Token und Audit-Zeile in jedem Fall.
_spur = {}
for art, ziel in ZIELE:
    a, _ap, post, konto = _g12b_aufbau()
    befehle: list = []
    a.store._uhr_gesichert = time.monotonic()      # den Uhrstand nicht mitten hinein sichern
    vorher = a.store.db.total_changes
    a.store.db.set_trace_callback(befehle.append)
    try:
        senden = a.request_email_change(konto, ziel, "http://testserver")
    finally:
        a.store.db.set_trace_callback(None)
    geschrieben = a.store.db.total_changes - vorher
    _spur[art] = {"folge": [_form(b) for b in befehle], "zeilen": geschrieben,
                  "gesendet": senden() if senden else None, "auth": a, "konto": konto}
r.check("G12b: dieselbe Folge von Anweisungen für vergeben, reserviert und frei",
        _spur["vergeben"]["folge"] == _spur["reserviert"]["folge"] == _spur["frei"]["folge"]
        and any(f.startswith("INSERT INTO magic_token") for f in _spur["frei"]["folge"]),
        "\n".join(f"{k}: {v['folge']}" for k, v in _spur.items()))
r.check("… dieselbe Zahl geschriebener Zeilen (Token + Audit = 2)",
        [v["zeilen"] for v in _spur.values()] == [2, 2, 2], str([v["zeilen"] for v in _spur.values()]))
r.check("… immer ein Sender; er sagt, ob ein Link hinausging (False, False, True)",
        [v["gesendet"] for v in _spur.values()] == [False, False, True],
        str([v["gesendet"] for v in _spur.values()]))

# Scheitert der Versand des Links, kommt der Hinweis an die eigene Adresse trotzdem — sonst verriete
# ein Mailserver, der die freie Adresse abweist, wieder den Unterschied. Der Fehler bleibt sichtbar.
a_f, _ap_f, post_f, konto_f = _g12b_aufbau()


def _link_kaputt(to, betreff, text, html=None):
    if to == "neu@example.com":
        raise OSError("Mailserver weist ab")
    post_f.append((to, betreff))


a_f.set_mailer(_link_kaputt)
senden_f = a_f.request_email_change(konto_f, "neu@example.com", "http://testserver")
try:
    senden_f()
    _geworfen = False
except OSError:
    _geworfen = True
r.check("G12b: scheitert der Link, geht der Hinweis an die eigene Adresse trotzdem (der Fehler bleibt)",
        _geworfen and post_f == [("anna@example.com", "Änderung deiner E-Mail-Adresse beantragt")],
        f"{_geworfen} {post_f}")

# Der Wegwerf-Token ist harmlos: von Anfang an abgelaufen, kein offener Link, `gc()` räumt ihn.
_st = _spur["vergeben"]["auth"].store
_jetzt_s = int(time.time())
r.check("G12b: der Token zu „vergeben“ ist bei seiner Anlage schon abgelaufen, kein offener Link",
        _st._one("SELECT COUNT(*) AS n FROM magic_token WHERE email='bert@example.com'")["n"] == 1
        and _st._one("SELECT COUNT(*) AS n FROM magic_token WHERE email='bert@example.com' AND expires_at >= ?",
                     (_jetzt_s,))["n"] == 0
        and not _st.offener_token(_spur["vergeben"]["konto"], "email_change", "bert@example.com"))
_spur["vergeben"]["auth"].gc()
r.check("… und gc() räumt ihn weg",
        _st._one("SELECT COUNT(*) AS n FROM magic_token WHERE email='bert@example.com'")["n"] == 0)
_sf = _spur["frei"]["auth"].store
r.check("… während der Link an die freie Adresse gilt",
        _sf.offener_token(_spur["frei"]["konto"], "email_change", "neu@example.com"))

# Ohne base_url und mit fremdem Host: die Antwort sagt „kein Mailversand", nicht die Interna der
# Basis-Prüfung (CodeQL py/unreachable-except: `ConfigError` ist ein `ValueError`).
a_b, ap_b, post_b, _ = _aufbau(base_url="", password_reset_enabled=False)
a_b.create_user("ohnebasis", password=PW, email="ohnebasis@example.com")
_ohne = _login(ap_b, "ohnebasis").post("/auth/account/email", json={"email": "neu@example.com"},
                                       headers={"host": "evil.example"})
r.check("ohne base_url, fremder Host: 400 mit der Meldung „kein Mailversand“, kein Link",
        _ohne.status_code == 400 and _ohne.json().get("detail") == a_b.t("api.no_mail") and not post_b,
        f"{_ohne.status_code} {_ohne.text[:160]}")

# Mail-Modus: der Benutzername zieht mit.
auth_e, app_e, mails_e, _ = _aufbau(login_identifier="email", signup_require_email=True)
uid_e = auth_e.create_user("emil@example.com", password=PW, email="emil@example.com")
ce = _login(app_e, "emil@example.com")
ce.post("/auth/account/email", json={"email": "emil.neu@example.com"})
link_e = re.search(r"http://testserver(/auth/email/[^\s]+)", next(m[2] for m in mails_e if "/auth/email/" in m[2])).group(1)
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
#  rot; `verified=True` weg → „MIT Beleg" rot; `Remote-Id` weg → Remote-Id rot.
#  G12b: Hinweis nur ohne „nein" → Hinweis rot; Drossel des Kontos nur für freie →
#  Kontingent rot; Abbildung in `own_events` weg → Kontoseite rot; Wegwerf-Token weg → Folge rot;
#  Token mit echter Frist → „schon abgelaufen" rot.)

sys.exit(r.done())
