"""Kennungsraum: Benutzername und Adresse sind EIN Raum — von der Datenbank erzwungen (G12c).

`find_user` sucht in beiden Spalten, und der Zähl-Topf (`norm_kennung`) faltet gröber als NOCASE.
Bis 2026-09-26 prüfte das nur `identifier_taken` VOR dem Schreiben; die Datenbank kannte
`UNIQUE(username)` (BINARY) und `ux_users_email`. Zwei gleichzeitige Anfragen derselben Kennung —
eine als Name, eine als Adresse — kamen beide durch, oder eine endete mit einer 500. Gemessen wird:

A  der Store selbst weist jede neue Kollision ab und lässt das Vorgesehene durch;
B  der Wettlauf, deterministisch: Eine zweite Instanz auf derselben Datei legt an, NACHDEM die
   erste geprüft hat und BEVOR sie schreibt — jeder Weg antwortet fachlich, nie mit 500;
C  dasselbe echt parallel;
D  ein Bestand mit Kollisionen: Start, vollständige Meldung, auflösbar;
E  der Adresswechsel im Mail-Modus ist eine Transaktion;
F  eine Datei, auf der die Trigger nicht anzulegen sind, startet trotzdem;
G  die Prüfung kostet nicht mit der Zahl der Konten mehr (SQLite-Schritte).
"""
from __future__ import annotations

import html
import io
import logging
import re
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.store import Store, jetzt  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Kennungsraum — Name und Adresse, von der Datenbank erzwungen")
PW = "Kennung-Test-15"
BASIS = "http://testserver"
VERGEBEN = Store.KENNUNG_VERGEBEN


def _datei() -> str:
    return str(Path(tempfile.mkdtemp()) / "t.db")


def _abgewiesen(fn) -> str:
    """„durch", oder der Text des IntegrityError, mit dem die Datenbank abweist."""
    try:
        fn()
    except sqlite3.IntegrityError as e:
        return str(e)
    return "durch"


def _roh(store, name, mail=None) -> int:
    """Ein Konto per rohem INSERT ohne Topf — der Weg eines fremden Schreibers (ältere Fassung,
    sqlite3-Werkzeug), den die Kennungs-Trigger nicht sehen."""
    return store._exec("INSERT INTO users(username, display_name, email, created_at) VALUES (?,?,?,?)",
                       (name, name, mail, jetzt())).lastrowid


def _paar(**cfg):
    """Zwei Instanzen auf DERSELBEN Datei — zwei Worker (`uvicorn --workers 2`)."""
    grund = dict(db_path=_datei(), cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                 base_url=BASIS, lang="de")
    grund.update(cfg)
    a = TinySesam(TinySesamConfig(**grund))
    b = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(a.router())
    return a, b, app


def _dazwischen(auth, methode, vorher, nachher=None):
    """Einmalig: `vorher()` (die gleichzeitige Anfrage der ANDEREN Instanz) läuft, NACHDEM `auth`
    alle Prüfungen hinter sich hat und BEVOR sein Store schreibt. `nachher()` läuft direkt nach
    dem Schreiben (auch wenn es scheitert) — noch bevor der Manager den Fehler sieht. Ein Haken,
    den keine Anfrage ausgelöst hat, wird ersetzt, nicht verschachtelt."""
    auth.store.__dict__.pop(methode, None)
    original = getattr(auth.store, methode)

    def haken(*a, **k):
        auth.store.__dict__.pop(methode, None)
        vorher()
        try:
            return original(*a, **k)
        finally:
            if nachher:
                nachher()
    setattr(auth.store, methode, haken)


def _mitschreiben(logger_name: str, fn):
    puffer = io.StringIO()
    haken = logging.StreamHandler(puffer)
    log = logging.getLogger(logger_name)
    log.addHandler(haken)
    try:
        ergebnis = fn()
    finally:
        log.removeHandler(haken)
    return ergebnis, puffer.getvalue()


def _audit(auth, event):
    z = auth.store._one("SELECT detail FROM audit WHERE event=? ORDER BY id DESC LIMIT 1", (event,))
    return z["detail"] if z else None


def _link(post, an):
    for ziel, text in post:
        t = re.search(re.escape(BASIS) + r"(/auth/email/\S+)", text)
        if ziel == an and t:
            return t.group(1)
    return ""


# ── A: der Store weist jede neue Kollision ab ────────────────────────────────────────────────────
# (Mutationsproben: INSERT-Trigger nicht anlegen → rot; UPDATE-Trigger nicht anlegen → rot;
#  `id IS NOT NEW.id` streichen → rot beim Wechsel im Mail-Modus; die zweite Anweisung in
#  `_kennung_setzen`, die den Topf zurücksetzt, streichen → rot bei „B1 → b1".)
s = Store(_datei())
blockiert = {}
s.create_user("Alice")
blockiert["Alice / alice"] = _abgewiesen(lambda: s.create_user("alice"))
s.create_user("Émile")
blockiert["Émile / émile"] = _abgewiesen(lambda: s.create_user("émile"))
s.create_user("ｂｏｂ")
blockiert["ｂｏｂ (Vollbreite) / bob"] = _abgewiesen(lambda: s.create_user("bob"))
s.create_user("k1", email="x@example.com")
blockiert["Name = fremde Adresse"] = _abgewiesen(lambda: s.create_user("X@example.com"))
s.create_user("q@example.com")
blockiert["Adresse = fremder Name"] = _abgewiesen(lambda: s.create_user("q2", email="q@example.com"))
s.create_user("u1", email="u@bücher.example")
blockiert["Adresse in A-Label-Form"] = _abgewiesen(lambda: s.create_user("u2", email="u@xn--bcher-kva.example"))
a_id, b_id = s.create_user("a1"), s.create_user("b1")
s.set_email(a_id, "frei@example.com")
blockiert["set_email → fremde Adresse"] = _abgewiesen(lambda: s.set_email(b_id, "FREI@example.com"))
blockiert["set_email → fremder Name"] = _abgewiesen(lambda: s.set_email(b_id, "q@example.com"))
blockiert["set_username → fremde Adresse"] = _abgewiesen(lambda: s.set_username(b_id, "x@example.com"))
blockiert["set_username → Namensvetter"] = _abgewiesen(lambda: s.set_username(b_id, "ALICE"))
r.check("A: jede neue Kollision im Kennungsraum weist die Datenbank ab (IntegrityError)",
        set(blockiert.values()) == {VERGEBEN}, str(blockiert))
_b = s.get_user(b_id)
r.check("A: … dabei ändert sich nichts, und keine Transaktion bleibt offen",
        _b["username"] == "b1" and not _b["email"] and not s.db.in_transaction
        and len(s._all("SELECT id FROM users")) == 8, f"{dict(_b)} offen={s.db.in_transaction}")
durch = {}
durch["Name = eigene Adresse (E-Mail-Modus)"] = _abgewiesen(
    lambda: s.create_user("solo@example.com", email="solo@example.com"))
durch["dieselbe Adresse erneut setzen"] = _abgewiesen(lambda: s.set_email(a_id, "frei@example.com", verified=True))
durch["b1 → B1 (eigener Topf)"] = _abgewiesen(lambda: s.set_username(b_id, "B1"))
_e = s.create_user("em@example.com", email="em@example.com")
durch["Mail-Modus: Adresse und Name wechseln"] = _abgewiesen(
    lambda: s.adresse_wechseln(_e, "em2@example.com", name_folgt=True))
durch["die alte Adresse ist danach frei"] = _abgewiesen(lambda: s.create_user("em@example.com"))
r.check("A: … durch gehen Name = eigene Adresse, dieselbe Adresse erneut, ein Name im eigenen Topf, "
        "der Wechsel im Mail-Modus", set(durch.values()) == {"durch"}, str(durch))
_toepfe = tuple(s._one("SELECT topf_name, topf_mail FROM users WHERE id=?", (b_id,)))
r.check("A: … „B1“ behält seinen Topf (der Nachrechnen-Trigger setzt ihn sonst auf NULL), „b1“ bleibt vergeben",
        _toepfe == ("b1", "") and _abgewiesen(lambda: s.create_user("b1")) == VERGEBEN, str(_toepfe))
# Ein fremder Schreiber, der denselben Wert erneut setzt, nimmt dem Konto den Topf nicht (bis
# 2026-09-26 stand er danach bis zum nächsten Nachtrag auf NULL, und die Trigger sahen das Konto
# nicht). (Mutationsprobe: im Nachrechnen-Trigger `NEW.<spalte> IS NOT OLD.<spalte>` streichen → rot.)
s._exec("UPDATE users SET username=username, email=email WHERE id=?", (a_id,))
r.check("A: … ein UPDATE auf denselben Wert lässt den Topf stehen",
        tuple(s._one("SELECT topf_name, topf_mail FROM users WHERE id=?", (a_id,))) == ("a1", "frei@example.com"))
# Ein Trigger aus Schema 10 (die Fassung von 0.20.1) wird durch den heutigen ersetzt — mit
# `IF NOT EXISTS` allein stünde er für immer so da. (Mutationsprobe: jeden vorhandenen Trigger stehen
# lassen → rot.)
_alt_db = _datei()
_alt = Store(_alt_db)
_alt._exec("DROP TRIGGER trg_users_topf_name")
_alt._exec("CREATE TRIGGER trg_users_topf_name AFTER UPDATE OF username ON users WHEN NEW.topf_name "
           "IS OLD.topf_name BEGIN UPDATE users SET topf_name = NULL WHERE id = NEW.id; END")
_alt.db.close()
_neu = Store(_alt_db)
_sql = _neu._one("SELECT sql FROM sqlite_master WHERE name='trg_users_topf_name'")["sql"]
r.check("A: ein Trigger aus einer älteren Fassung wird beim Start ersetzt",
        "NEW.username IS NOT OLD.username" in _sql, _sql)

# ── B: Wettlauf, deterministisch ─────────────────────────────────────────────────────────────────
# (Mutationsproben: die Abbildung des IntegrityError in `create_user`, `confirm_email_change`,
#  `change_username`, im OIDC-Nachtrag, in `_adresse_aus_quelle_belegen` und in den Routen
#  `register`/Admin streichen → je rot, meist mit einer 500.)
a, b, _ = _paar()
_dazwischen(a, "create_user", lambda: b.create_user("rb", password=PW, email="race@example.com"))
try:
    a.create_user("race@example.com", password=PW)
    b1 = None
except ConfigError as fehler:
    b1 = (fehler.field, fehler.owner_id)
r.check("B1: Name gegen eine gleichzeitig angelegte Adresse → ConfigError, Feld und Besitzer stimmen",
        b1 == ("username", b.store.get_user_by_name("rb")["id"]), str(b1))
_dazwischen(a, "create_user", lambda: b.create_user("race2@example.com", password=PW))
try:
    a.create_user("rc", password=PW, email="race2@example.com")
    b1b = None
except ConfigError as fehler:
    b1b = (fehler.field, fehler.owner_id)
r.check("B1: … Adresse gegen einen gleichzeitig angelegten Namen → Feld „email“",
        b1b == ("email", b.store.get_user_by_name("race2@example.com")["id"]), str(b1b))
_dazwischen(a, "create_user", lambda: b.create_user("weg", password=PW),
            nachher=lambda: b.delete_user(b.store.get_user_by_name("weg")["id"]))
try:
    a.create_user("WEG", password=PW)
    b1c = None
except ConfigError as fehler:
    b1c = (fehler.field, fehler.owner_id, str(fehler))
r.check("B1: … ist das andere Konto schon wieder weg: ConfigError ohne Besitzer, nicht IntegrityError",
        b1c == ("username", None, "Benutzername ist bereits vergeben"), str(b1c))
r.check("B1: … keine Kollision in der Datenbank", a.store.topf_kollisionen() == [], str(a.store.topf_kollisionen()))

# B2: Adresswechsel gegen eine Registrierung mit Name = Adresse.
a, b, app_a = _paar()
post: list = []
a.set_mailer(lambda to, betreff, text, html=None: post.append((to, text)))
carla = a.create_user("carla", password=PW, email="carla@example.com")
a.request_email_change(carla, "neu@example.com", BASIS)()
_dazwischen(a, "adresse_wechseln", lambda: b.create_user("neu@example.com", password=PW))
b2 = TestClient(app_a, raise_server_exceptions=False).post(_link(post, "neu@example.com"), follow_redirects=False)
r.check("B2: confirm_email_change im Wettlauf → 409, die Adresse bleibt, Audit-Zeile mit wettlauf=1",
        b2.status_code == 409 and a.get_user(carla)["email"] == "carla@example.com"
        and "wettlauf=1" in (_audit(a, "email_change_taken") or "") and a.store.topf_kollisionen() == [],
        f"HTTP {b2.status_code}, {a.get_user(carla)['email']}, {_audit(a, 'email_change_taken')}")

# B3: Umbenennen auf der Konto-Seite.
a, b, app_a = _paar()
dora = a.create_user("dora", password=PW)
c = TestClient(app_a, raise_server_exceptions=False)
c.post("/auth/login", data={"username": "dora", "password": PW}, follow_redirects=False)
_dazwischen(a, "set_username", lambda: b.create_user("Zeta", password=PW))
b3 = c.post("/auth/account/username", json={"username": "zeta"})
r.check("B3: change_username im Wettlauf → 400 „existiert schon“, der Name bleibt",
        b3.status_code == 400 and b3.json().get("detail") == a.t("api.user_exists")
        and a.get_user(dora)["username"] == "dora" and a.store.topf_kollisionen() == [],
        f"HTTP {b3.status_code} {b3.text[:120]}")

# B4: Adresse nachtragen — aus LDAP/SAML …
a, b, _ = _paar()
lars = a.create_user("lars", password=PW)
_dazwischen(a, "set_email", lambda: b.create_user("lars2", password=PW, email="lars@example.com"))
a._adresse_aus_quelle_belegen(a.store.get_user(lars), "lars@example.com", True, "ldap")
r.check("B4: Adresse aus LDAP im Wettlauf → das Konto bleibt ohne, Audit-Zeile",
        not a.get_user(lars)["email"] and "wettlauf=1" in (_audit(a, "ldap_email_taken") or ""),
        f"{a.get_user(lars)['email']} {_audit(a, 'ldap_email_taken')}")

# … und aus OIDC (liefert der Provider den Beleg nach, kommt die Adresse ins Konto — H-3).
IDP = "https://idp.example.invalid"


class _Claims(dict):
    def validate(self, *args, **kw):
        pass


def _setze(auth, claims):
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


def _oidc_login(app):
    cl = TestClient(app, raise_server_exceptions=False)
    start = cl.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return cl.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)


a, b, app_a = _paar(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe", oidc_client_secret="geheim")
a.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize", "token_endpoint": IDP + "/token",
                "userinfo_endpoint": IDP + "/userinfo", "jwks_uri": IDP + "/jwks"}
from tinysesam.oidc import OIDCClient  # noqa: E402
a.oidc.userinfo = lambda at, erwartetes_sub="": OIDCClient.userinfo_pruefen({}, erwartetes_sub)
_setze(a, {"sub": "g12c-1", "preferred_username": "olga", "email": "olga@example.com"})
_oidc_login(app_a)
_setze(a, {"sub": "g12c-1", "preferred_username": "olga", "email": "olga@example.com", "email_verified": True})
_dazwischen(a, "set_email", lambda: b.create_user("olga@example.com", password=PW))
b4 = _oidc_login(app_a)
_olga = a.store.get_user_by_name("olga")
r.check("B4: Adresse aus OIDC im Wettlauf → kein 500, das Konto bleibt ohne, Audit-Zeile",
        b4.status_code == 303 and _olga is not None and not _olga["email"]
        and "wettlauf=1" in (_audit(a, "oidc_email_taken") or ""),
        f"HTTP {b4.status_code} {dict(_olga) if _olga else None} {_audit(a, 'oidc_email_taken')}")

# B5: die Routen — Registrierung und Admin-API antworten fachlich, nie mit 500.
def _registrieren(app, **daten):
    return TestClient(app, raise_server_exceptions=False).post(
        "/auth/register", data={"password": PW, "next": "/", **daten}, follow_redirects=False)


a, b, app_a = _paar(allow_signup=True)
_dazwischen(a, "create_user", lambda: b.create_user("Rennen", password=PW))
b5a = _registrieren(app_a, username="rennen", email="r1@example.com")
_dazwischen(a, "create_user", lambda: b.create_user("zweiter", password=PW, email="r2@example.com"))
b5b = _registrieren(app_a, username="rennen2", email="r2@example.com")
r.check("B5: Registrierung im Wettlauf ohne Bestätigung → 409 (Name vergeben / Adresse vergeben)",
        b5a.status_code == 409 and html.escape(a.t("err.username_taken")) in b5a.text
        and b5b.status_code == 409 and html.escape(a.t("err.email_taken")) in b5b.text
        and a.store.get_user_by_name("rennen2") is None,
        f"HTTP {b5a.status_code} / {b5b.status_code}")

a, b, app_a = _paar(allow_signup=True, signup_verify_email=True)
a.set_mailer(lambda *x, **k: True)
_dazwischen(a, "create_user", lambda: b.create_user("dritter", password=PW, email="r3@example.com"))
b5c = _registrieren(app_a, username="rennen3", email="r3@example.com")
r.check("B5: … mit Bestätigung: eine im Wettlauf vergebene Adresse bekommt die neutrale Seite (R4-03), "
        "Audit signup_taken wettlauf=1",
        b5c.status_code == 200 and html.escape(a.t("reg.verify")) in b5c.text
        and a.store.get_user_by_name("rennen3") is None
        and "wettlauf=1" in (_audit(a, "signup_taken") or ""),
        f"HTTP {b5c.status_code} {_audit(a, 'signup_taken')}")
a.create_user("inhaber", password=PW, email="besetzt@example.com")
_dazwischen(a, "create_user", lambda: b.create_user("platz", password=PW))
b5d = _registrieren(app_a, username="platz", email="besetzt@example.com")
r.check("B5: … der Platzhalter für eine vergebene Adresse, dessen Name im Wettlauf vergeben wird → 409",
        b5d.status_code == 409 and html.escape(a.t("err.username_taken")) in b5d.text, f"HTTP {b5d.status_code}")

a, b, app_a = _paar(allow_signup=True, signup_verify_email=True, login_identifier="email",
                    signup_require_email=True)
a.set_mailer(lambda *x, **k: True)
_dazwischen(a, "create_user", lambda: b.create_user("r4@example.com", password=PW, email="r4@example.com"))
b5e = _registrieren(app_a, email="r4@example.com")
r.check("B5: … im Mail-Modus (Name = Adresse): die neutrale Seite, kein „Name vergeben“, das die Adresse verriete",
        b5e.status_code == 200 and html.escape(a.t("reg.verify")) in b5e.text, f"HTTP {b5e.status_code}")

a, b, app_a = _paar()
chefin = a.create_user("chefin", password=PW, is_admin=True)
adm = TestClient(app_a, raise_server_exceptions=False)
adm.cookies.set(a.cfg.session_cookie, a.store.create_session(chefin, 3600, True, "password"))
_dazwischen(a, "create_user", lambda: b.create_user("svc-rennen", password=PW))
b5f = adm.post("/auth/admin/api/users", json={"username": "svc-rennen", "is_service": True})
_dazwischen(a, "create_user", lambda: b.create_user("x5", password=PW, email="adm@example.com"))
b5g = adm.post("/auth/admin/api/users", json={"username": "neu-adm", "email": "adm@example.com"})
r.check("B5: Admin-API im Wettlauf → 409 „existiert schon“ bzw. „E-Mail vergeben“",
        b5f.status_code == 409 and b5f.json().get("detail") == a.t("api.user_exists")
        and b5g.status_code == 409 and b5g.json().get("detail") == a.t("api.email_taken"),
        f"HTTP {b5f.status_code} {b5f.text[:80]} / {b5g.status_code} {b5g.text[:80]}")

# ── C: echt parallel ─────────────────────────────────────────────────────────────────────────────
# Zwei Worker, je 20 Threads, alle auf dieselbe Kennung — die Hälfte als Name, die andere als Adresse.
a, b, app_a = _paar(allow_signup=True)
app_b = FastAPI()
app_b.include_router(b.router())
for _x in (a, b):
    _x.set_security("rate_limit_max", 1000)
KENNUNG = "wett@example.com"
N = 40
schranke = threading.Barrier(N)
antworten: list = []


def _lauf(i):
    daten = ({"username": KENNUNG, "email": f"t{i}@example.org"} if i % 2 == 0
             else {"username": f"t{i}", "email": KENNUNG})
    cl = TestClient((app_a, app_b)[i // 2 % 2], raise_server_exceptions=False)
    try:
        schranke.wait(timeout=30)
        antworten.append(cl.post("/auth/register", data={"password": PW, "next": "/", **daten},
                                 follow_redirects=False).status_code)
    except Exception as fehler:        # ein Thread, der scheitert, darf nicht still fehlen
        antworten.append(repr(fehler))


_threads = [threading.Thread(target=_lauf, args=(i,)) for i in range(N)]
for _t in _threads:
    _t.start()
for _t in _threads:
    _t.join(timeout=120)
_halter = a.store._all("SELECT id FROM users WHERE topf_name=? OR topf_mail=?", (KENNUNG, KENNUNG))
r.check("C: 40 gleichzeitige Registrierungen derselben Kennung (Name und Adresse, zwei Worker): "
        "nur 303/409, genau ein Konto hält sie, keine Kollision",
        len(antworten) == N and set(antworten) <= {303, 409} and antworten.count(303) == 1
        and len(_halter) == 1 and a.store.topf_kollisionen() == [],
        f"{sorted(map(str, antworten))} Halter {len(_halter)} {a.store.topf_kollisionen()}")

# ── D: Bestand mit Kollisionen ───────────────────────────────────────────────────────────────────
# (Mutationsproben: `NEW IS NOT OLD` streichen → rot beim Umbenennen, der eigenen Adresse und dem
#  rohen UPDATE; den UPDATE-Trigger auf `OF topf_name, topf_mail` → rot, der Start scheitert am
#  Nachtrag; die Startmeldung zurück auf „Name = fremde Adresse“ per NOCASE → rot.)
_db_d = _datei()
_st = Store(_db_d)
oe1, oe2 = _roh(_st, "Özlem"), _roh(_st, "özlem")
chef, eve = _roh(_st, "chef", "chef@example.com"), _roh(_st, "chef@example.com")
ubu, uxn = _roh(_st, "ubu", "u@bücher.example"), _roh(_st, "uxn", "u@xn--bcher-kva.example")
_st.db.close()


def _start(pfad):
    return _mitschreiben("tinysesam", lambda: TinySesam(TinySesamConfig(db_path=pfad, cookie_secure=False)))


try:
    auth_d, text_d = _start(_db_d)
    start_d = "ok"
except Exception as fehler:
    auth_d, text_d, start_d = None, "", f"{type(fehler).__name__}: {fehler}"
r.check("D: ein Bestand mit Kollisionen startet, kein Topf bleibt leer",
        start_d == "ok" and auth_d.store._one("SELECT COUNT(*) AS n FROM users WHERE topf_name IS NULL "
                                              "OR topf_mail IS NULL")["n"] == 0, start_d)
_zeile = next((z for z in text_d.splitlines() if "Kennungs-Kollision" in z), "")
r.check("D: … die Startmeldung nennt alle drei (Namensvetter, Name = fremde Adresse, zwei Schreibweisen "
        "einer Adresse) mit ihren Konten",
        _zeile.startswith("3 Kennungs-Kollision")
        and all(f"user_id={i}" in _zeile for i in (oe1, oe2, chef, eve, ubu, uxn)), _zeile[:400])
if auth_d is not None:
    in_kollision = {
        "neues Konto „ÖZLEM“": _abgewiesen(lambda: auth_d.store.create_user("ÖZLEM")),
        "Name → belegter Topf": _abgewiesen(lambda: auth_d.store.set_username(chef, "özlem")),
    }
    r.check("D: … eine Kollision verschlimmert niemand mehr", set(in_kollision.values()) == {VERGEBEN},
            str(in_kollision))
    aufloesen = {
        "eigene Adresse erneut": _abgewiesen(lambda: auth_d.store.set_email(chef, "chef@example.com", verified=True)),
        "Konto mit belegter Adresse umbenennen": _abgewiesen(lambda: auth_d.store.set_username(ubu, "ubu-neu")),
        "change_username auf einen freien Namen": _abgewiesen(lambda: auth_d.change_username(oe2, "oezlem-zwei")),
        "set_email auf eine freie Adresse": _abgewiesen(lambda: auth_d.store.set_email(uxn, "u2@example.com")),
        "rohes UPDATE des Betreibers": _abgewiesen(
            lambda: auth_d.store._exec("UPDATE users SET username='eve-umbenannt' WHERE id=?", (eve,))),
    }
    r.check("D: … auflösen geht: umbenennen, die eigene Adresse neu setzen, eine freie Adresse, das rohe UPDATE",
            set(aufloesen.values()) == {"durch"}, str(aufloesen))
    _, text_d2 = _start(_db_d)
    r.check("D: … danach schweigt die Startmeldung", "Kennungs-Kollision" not in text_d2
            and auth_d.store.topf_kollisionen() == [], text_d2[:300])
    # Eine Zeile eines fremden Schreibers zählt, sobald jemand nachsieht — nicht erst beim Start.
    # (Mutationsprobe: in `topf_kollisionen` den Nachtrag streichen → rot.)
    _spaet = _roh(auth_d.store, "ANNA-Maria")
    _roh(auth_d.store, "anna-maria")
    r.check("D: … eine Kollision, die ein fremder Schreiber zur Laufzeit anlegt, nennt topf_kollisionen sofort",
            [z["kennung"] for z in auth_d.store.topf_kollisionen()] == ["anna-maria"], str(_spaet))

# ── E: der Adresswechsel im Mail-Modus ist eine Transaktion ──────────────────────────────────────
# Ein TEMP-Trigger lässt das Umbenennen scheitern. Getrennt geschrieben stand danach die neue
# Adresse neben dem alten Namen — und der alte Name hielt die alte Adresse besetzt.
# (Mutationsprobe: in `_umschreiben` nach jeder Anweisung committen → rot.)
a, _, app_a = _paar(login_identifier="email", signup_require_email=True)
post = []
a.set_mailer(lambda to, betreff, text, html=None: post.append((to, text)))
ella = a.create_user("ella@example.com", password=PW, email="ella@example.com")
a.request_email_change(ella, "ella2@example.com", BASIS)()
a.store.db.execute("CREATE TEMP TRIGGER t_probe_kaputt BEFORE UPDATE OF username ON users "
                   "BEGIN SELECT RAISE(ABORT, 'probe: name scheitert'); END")
e1 = TestClient(app_a, raise_server_exceptions=False).post(_link(post, "ella2@example.com"), follow_redirects=False)
_ella = a.get_user(ella)
r.check("E: scheitert im Mail-Modus das Umbenennen, bleibt auch die Adresse — kein 500, nichts halb",
        e1.status_code == 409 and _ella["email"] == "ella@example.com" and _ella["username"] == "ella@example.com"
        and not a.store.db.in_transaction, f"HTTP {e1.status_code} {dict(_ella)}")
a.store.db.execute("DROP TRIGGER temp.t_probe_kaputt")
post.clear()
a.request_email_change(ella, "ella3@example.com", BASIS)()
e2 = TestClient(app_a).post(_link(post, "ella3@example.com"), follow_redirects=False)
_ella = a.get_user(ella)
r.check("E: … ohne Störung wechseln Adresse und Name zusammen",
        e2.status_code == 303 and _ella["email"] == _ella["username"] == "ella3@example.com", str(dict(_ella)))

# ── F: eine Datei, auf der sich die Trigger nicht anlegen lassen ─────────────────────────────────
# (Mutationsprobe: das `try` um die Anlage streichen → rot, der Start scheitert.)
_setzen = Store._trigger_setzen


def _nicht_schreibbar(self):
    raise sqlite3.OperationalError("attempt to write a readonly database")


Store._trigger_setzen = _nicht_schreibbar
try:
    _f, text_f = _mitschreiben("tinysesam", lambda: Store(_datei()))
    start_f = "ok"
except Exception as fehler:
    text_f, start_f = "", f"{type(fehler).__name__}: {fehler}"
finally:
    Store._trigger_setzen = _setzen
r.check("F: lassen sich die Trigger nicht anlegen (nur lesbar), startet der Store trotzdem und sagt es",
        start_f == "ok" and "Kennungsraum erst nach einem Start mit Schreibzugriff" in text_f,
        f"{start_f} {text_f[:200]!r}")

# ── G: die Prüfung kostet nicht mit der Zahl der Konten mehr ─────────────────────────────────────
# Gezählt werden SQLite-Schritte (wie S-1 in tests/test_audit_runde2.py): Ein Scan über die Konten
# kostet mindestens einen Schritt je Zeile, ein Index-Zugriff einen, egal wie tief der Baum ist.
# (Mutationsprobe: im Trigger `topf_name || '' = …` statt `topf_name = …` — kein Index mehr → rot.)
def _schritte(st, fn) -> int:
    zaehler = [0]

    def schritt():
        zaehler[0] += 1
        return 0
    st.db.set_progress_handler(schritt, 1)
    try:
        fn()
    finally:
        st.db.set_progress_handler(None, 1)
    return zaehler[0]


def _messen(n: int) -> dict:
    st = Store(_datei())
    st.db.executemany("INSERT INTO users(username, email, created_at) VALUES (?, ?, 1)",
                      [(f"konto{i}", f"konto{i}@example.com") for i in range(n)])
    st.db.commit()
    st._toepfe_nachtragen()
    uid = st.create_user("probe")
    return {"anlegen": _schritte(st, lambda: st.create_user("neu", email="neu@example.org")),
            "umbenennen": _schritte(st, lambda: st.set_username(uid, "probe-neu")),
            "Adresse": _schritte(st, lambda: st.set_email(uid, "probe@example.org")),
            "abgewiesen": _schritte(st, lambda: _abgewiesen(lambda: st.create_user("KONTO7")))}


_klein, _gross = _messen(100), _messen(3000)
_waechst = {k: (_klein[k], _gross[k]) for k in _klein if abs(_gross[k] - _klein[k]) > 100}
r.check("G: Anlegen, Umbenennen, Adresse setzen und Abweisen kosten bei 3000 Konten nicht mehr als bei 100",
        not _waechst, f"wächst: {_waechst}\n100: {_klein}\n3000: {_gross}")

sys.exit(r.done())
