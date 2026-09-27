"""Der sichere Login-Baustein für eigene Seiten (0.22.0): `anmelden_passwort`, `anmelden_pin`, `anmelden_totp`.

PO-Befund 2026-09-26: Die README zeigte unter „Your own login page“ `check_password` +
`start_session` als Bausteine. Die inneren Prüfer drosseln nicht — Sperre, Fehlversuchszähler,
Serie, IP-Drossel und die Zeilen für fail2ban standen nur in den eingebauten Routen. Eine eigene
Route nach dem Muster liess Passwörter so schnell raten, wie der Server antwortet.

Jetzt ist der öffentliche Weg ein Baustein, der von sich aus drosselt, zählt und sperrt — und die
eingebauten Routen rufen DENSELBEN (eine Quelle, kein Drift). Gemessen wird deshalb zweierlei:
dass eine eigene Login-Seite über den Baustein geschützt ist, und dass sie sich Zeile für Zeile
verhält wie die eingebaute Route.

  (a) eigene Login-Seite: Sperre nach N Fehlversuchen, IP-Drossel, Serie
  (b) LDAP über den Baustein: Rückfall, Ausfall (503, Rücknahme bzw. Fehlversuch), eine Kennung, ein Konto
  (c) Gleichheit mit der eingebauten Route: Status, Audit-, Sicherheits-Log- und Zählerzeilen
  (d) PIN: Gästeweg, Kettenschritt (eigene Serien-Art), abgeschaltet
  (e) TOTP: zweiter Schritt, Einmal-Code, ohne Sitzung, Sperre
  (f) CSRF, fail-closed, der Ergebnistyp
  (g) Unerwartetes in der Prüfung zählt sofort als Fehlversuch
  (h) eine Quelle: die drei Routen rufen den Baustein und keinen inneren Prüfer
  (i) das Beispiel der README ist selbst geschützt
  (j) Test-Fakes: auf dem alten Namen wirkungslos und laut, auf dem neuen wirksam
"""
from __future__ import annotations

import ast
import dataclasses
import io
import logging
import re
import sys
import tempfile
import time
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import pyotp  # noqa: E402
from fastapi import Depends, FastAPI, Form, HTTPException, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import Anmeldung, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.ldap_ import VerzeichnisNichtErreichbar  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Der sichere Login-Baustein für eigene Seiten (anmelden_passwort/_pin/_totp, 0.22.0)")
PW = "Anmelde-Pw-2026"          # 15 Zeichen: das Passwort meldet allein an (B2-4)
PIN = "4711"
IP = ("203.0.113.9", 50000)
LOCKER = {"max_login_attempts": 1000, "rate_limit_max": 100000,
          "account_max_consecutive_failures": 100000, "pin_max_attempts": 100}


def _app(haertung=None, **cfg):
    """TinySesam mit eingebauten Routen UND eigenen Routen, die nur den Baustein rufen."""
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de",
                 passkey_enabled=False, oidc_enabled=False)
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    for k, v in {**LOCKER, **(haertung or {})}.items():
        auth.set_security(k, v)
    app = FastAPI()
    app.include_router(auth.router())

    def antwort(erg):
        # Das Muster der README: bei einem Misserfolg das eigene Formular (hier JSON) mit dem
        # Status der eingebauten Seite, bei Erfolg die Umleitung mit Cookie.
        if not erg:
            return JSONResponse({"grund": erg.grund, "meldung": erg.meldung, "weiter": erg.weiter,
                                 "naechster": erg.naechster}, status_code=erg.status)
        return erg.weiterleitung()

    @app.post("/eigen/login")
    def _eigen_login(request: Request, username: str = Form(""), password: str = Form(""),
                     next: str = Form(""), csrf: str = Form("", alias="_csrf"), bleiben: str = Form("")):
        return antwort(auth.anmelden_passwort(request, username, password, next=next, csrf=csrf,
                                              remember=True if bleiben else None))

    @app.post("/eigen/pin")
    def _eigen_pin(request: Request, pin: str = Form(""), username: str = Form(""),
                   next: str = Form(""), csrf: str = Form("", alias="_csrf")):
        return antwort(auth.anmelden_pin(request, pin, username, next=next, csrf=csrf))

    @app.post("/eigen/totp")
    def _eigen_totp(request: Request, code: str = Form(""), next: str = Form(""),
                    csrf: str = Form("", alias="_csrf")):
        return antwort(auth.anmelden_totp(request, code, next=next, csrf=csrf))

    @app.post("/eigen/json")
    def _eigen_json(request: Request, daten: dict):
        # Der JSON-Weg: kein `csrf`-Argument, das Token kommt im Header X-CSRF-Token.
        erg = auth.anmelden_passwort(request, daten.get("username", ""), daten.get("password", ""))
        if not erg:
            raise HTTPException(erg.status, erg.meldung)
        antwort_ = JSONResponse({"weiter": erg.weiter, "fertig": erg.fertig, "naechster": erg.naechster})
        erg.cookie_setzen(antwort_)
        return antwort_

    @app.get("/drin")
    def _drin(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return auth, app


def _client(app, ip=IP):
    return TestClient(app, client=ip)


def _post(client, pfad, **daten):
    return client.post(pfad, data={"next": "/drin", **daten}, follow_redirects=False)


def _grund(antwort):
    try:
        return antwort.json().get("grund")
    except ValueError:
        return None


def _sitzung(auth, antwort):
    return antwort.cookies.get(auth.session_cookie_name)


class Mitschnitt:
    """Das Sicherheits-Log im Format der ausgelieferten Datei, ohne Zeitstempel (wie fail2ban)."""

    def __enter__(self):
        self.puffer = io.StringIO()
        self.haken = logging.StreamHandler(self.puffer)
        self.haken.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        seclog.addHandler(self.haken)
        return self

    def __exit__(self, *_):
        seclog.removeHandler(self.haken)

    def zeilen(self, wort=""):
        return [z for z in self.puffer.getvalue().splitlines() if wort in z]


def _failregex():
    text = (ROOT / "deploy" / "fail2ban" / "tinysesam-filter.conf").read_text(encoding="utf-8")
    zeile = [z for z in text.splitlines() if z.startswith("failregex =")][0]
    return re.compile(zeile.split("=", 1)[1].strip().replace("<HOST>", r"(?P<host>\S+)"))


def _audit(auth):
    return [tuple(z) for z in auth.store._all("SELECT event, username, ip, detail FROM audit ORDER BY id")]


def _versuche(auth):
    return [tuple(z) for z in auth.store._all(
        "SELECT username, ip, success, method, offen FROM login_attempt ORDER BY id")]


def _serie(auth):
    return sorted(tuple(z) for z in auth.store._all("SELECT topf, art, anzahl FROM fehlserie"))


# ── (a) Eigene Login-Seite: Sperre, IP-Drossel, Serie ─────────────────────────────────────────────
# Genau der Befund: Eine eigene Route über `check_password` hätte hier fünfmal 401 gesagt und beim
# sechsten Versuch — dem richtigen Passwort — eine Sitzung aufgemacht. Über den Baustein sperrt sie
# nach der Grenze, und auch das richtige Passwort kommt dann nicht mehr durch.
# (Mutationsprobe: in `anmelden_passwort` die Abweisung `if versuch is None:` abschalten → vierte
# Antwort 401, das richtige Passwort 303 → rot.)
auth, app = _app(haertung={"max_login_attempts": 3})
auth.create_user("alice", password=PW)
c = _client(app)
with Mitschnitt() as log_a:
    folge_a = [_post(c, "/eigen/login", username="alice", password=f"falsch-{i}") for i in range(5)]
    richtig_a = _post(c, "/eigen/login", username="alice", password=PW)
r.check("(a) eigene Login-Seite: nach 3 Fehlversuchen 429 `gesperrt` — kein weiteres Raten",
        [a.status_code for a in folge_a] == [401, 401, 401, 429, 429]
        and [_grund(a) for a in folge_a] == ["falsch"] * 3 + ["gesperrt"] * 2
        and folge_a[3].json()["meldung"] == auth.t("err.locked"),
        f"{[a.status_code for a in folge_a]} {[_grund(a) for a in folge_a]}")
r.check("(a) … auch das richtige Passwort öffnet dann keine Sitzung (429, kein Cookie)",
        richtig_a.status_code == 429 and _sitzung(auth, richtig_a) is None,
        f"HTTP {richtig_a.status_code}, Cookie {_sitzung(auth, richtig_a)!r}")
_f2b = _failregex()
_treffer_a = [m.group("host") for m in (_f2b.match(z) for z in log_a.zeilen()) if m]
r.check("(a) … und jeder Fehlversuch wie jede Abweisung steht als fail2ban-Zeile im Sicherheits-Log",
        _treffer_a.count(IP[0]) == 6 and len(log_a.zeilen("reason=lockout_user")) == 3,
        f"{len(_treffer_a)} Treffer: {log_a.zeilen()[:4]}")
r.check("(a) … und im Audit-Log (login_fail je Versuch, mit Grund)",
        [e[0] for e in _audit(auth)].count("login_fail") == 3
        and all(e[3].startswith("password grund=") for e in _audit(auth) if e[0] == "login_fail"),
        str(_audit(auth)[-4:]))

# IP-Drossel: viele Konten von einer Adresse — der Baustein drosselt je IP, bevor er prüft.
auth, app = _app(haertung={"rate_limit_max": 4})
auth.create_user("bob", password=PW)
c = _client(app, ("198.51.100.44", 1))
_drossel = [_post(c, "/eigen/login", username=f"konto{i}", password="egal-egal-1") for i in range(6)]
_anderes_netz = _post(_client(app, ("198.51.100.45", 1)), "/eigen/login", username="bob", password=PW)
r.check("(a) IP-Drossel: nach rate_limit_max Anfragen 429 `ratelimit` mit dem Text der Drossel",
        [a.status_code for a in _drossel][-2:] == [429, 429] and _grund(_drossel[-1]) == "ratelimit"
        and _drossel[-1].json()["meldung"] == auth.t("err.rate"),
        f"{[(a.status_code, _grund(a)) for a in _drossel]}")
r.check("(a) … eine andere Adresse meldet sich weiter an (Gegenprobe: die Drossel gilt je IP)",
        _anderes_netz.status_code == 303 and _sitzung(auth, _anderes_netz), f"HTTP {_anderes_netz.status_code}")

# Serie (B2-6): langsames Raten unter jeder Fenstergrenze — nach N Fehlversuchen in Folge ist zu.
auth, app = _app(haertung={"account_max_consecutive_failures": 10})
auth.create_user("carol", password=PW)
_serie_folge = []
with Mitschnitt() as log_s:
    for i in range(11):    # jede Anfrage von einer anderen Adresse: kein Fenster greift
        _serie_folge.append(_post(_client(app, (f"192.0.2.{10 + i}", 1)), "/eigen/login",
                                  username="carol", password=f"falsch-{i}"))
    _serie_richtig = _post(_client(app, ("192.0.2.99", 1)), "/eigen/login", username="carol", password=PW)
r.check("(a) Serie: nach 10 Fehlversuchen in Folge 429 `gesperrt_serie` mit dem Text der Serien-Sperre",
        [a.status_code for a in _serie_folge] == [401] * 10 + [429]
        and _grund(_serie_folge[-1]) == "gesperrt_serie"
        and _serie_folge[-1].json()["meldung"] == auth.t("err.locked_serie"),
        f"{[(a.status_code, _grund(a)) for a in _serie_folge]}")
r.check("(a) … sie läuft nicht ab: auch das richtige Passwort von einer neuen Adresse bleibt draussen",
        _serie_richtig.status_code == 429 and _grund(_serie_richtig) == "gesperrt_serie",
        f"HTTP {_serie_richtig.status_code}")
r.check("(a) … Audit `lockout_serie` und die Logzeile für den Betreiber",
        any(e[0] == "lockout_serie" for e in _audit(auth))
        and log_s.zeilen("Anmeldung für user=carol gesperrt: 10 Fehlversuche in Folge"),
        f"{[e[0] for e in _audit(auth)]} {log_s.zeilen('gesperrt')[:2]}")

# Erfolg: Umleitung mit Cookie, Ergebnis vollständig, das Cookie trägt eine volle Sitzung.
auth, app = _app()
uid = auth.create_user("dora", password=PW)
c = _client(app)
_ok = _post(c, "/eigen/login", username="dora", password=PW)
r.check("(a) Erfolg: 303 nach next, Sitzungs-Cookie gesetzt, die Sitzung trägt /drin",
        _ok.status_code == 303 and _ok.headers["location"] == "/drin" and _sitzung(auth, _ok)
        and c.get("/drin").json() == {"u": "dora"},
        f"HTTP {_ok.status_code} {_ok.headers.get('location')}")
# „Angemeldet bleiben“ (F-05): ohne `remember` ein Sitzungs-Cookie (endet mit dem Browser), mit
# `remember=True` ein dauerhaftes — wie der Haken der eingebauten Seite.
_kurz = _post(_client(app, ("203.0.113.20", 1)), "/eigen/login", username="dora", password=PW)
_lang = _post(_client(app, ("203.0.113.21", 1)), "/eigen/login", username="dora", password=PW, bleiben="1")


def _max_age(antwort):
    return [z for z in antwort.headers.get_list("set-cookie")
            if z.startswith(auth.session_cookie_name + "=") and "Max-Age=" in z]


r.check("(a) remember: ohne Haken kein Max-Age am Sitzungs-Cookie, mit remember=True eines",
        _kurz.status_code == _lang.status_code == 303 and not _max_age(_kurz) and _max_age(_lang),
        f"{_kurz.headers.get_list('set-cookie')} | {_lang.headers.get_list('set-cookie')}")


# ── (b) LDAP über den Baustein ────────────────────────────────────────────────────────────────────
class Verzeichnis:
    """Attrappe des LDAP-Clients nach dem Bind; `weg=True` meldet einen Ausfall."""

    def __init__(self, eintraege, weg=False):
        self.eintraege, self.weg, self.fragen = eintraege, weg, 0

    def authenticate(self, username, password):
        self.fragen += 1
        if self.weg:
            raise VerzeichnisNichtErreichbar("LDAP-Verzeichnis ldap://dummy nicht benutzbar: Test")
        e = self.eintraege.get(username)
        if not e or e["pw"] != password:
            return None
        return {"username": username, "email": e.get("email"), "name": username, "groups": [],
                "id": e.get("id"), "email_verified": None}


LPW = "Verzeichnis-Pw1"
LDAP = dict(ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True, ldap_auto_create=True)
auth, app = _app(**LDAP)
auth.ldap = Verzeichnis({"lena": {"pw": LPW, "id": "uuid-lena"}})
c = _client(app)
_l_ok = _post(c, "/eigen/login", username="lena", password=LPW)
_l_uid = auth.store.get_user_by_name("lena")["id"] if auth.store.get_user_by_name("lena") else None
r.check("(b) LDAP-Rückfall über den Baustein: Konto aus dem Verzeichnis, Sitzung, Audit `login_ldap`",
        _l_ok.status_code == 303 and _l_uid and auth.store.get_federated_user("ldap", "uuid-lena") == _l_uid
        and any(e[0] == "login_ldap" and e[1] == "lena" for e in _audit(auth)),
        f"HTTP {_l_ok.status_code}, {[e[0] for e in _audit(auth)]}")
_l_falsch = _post(c, "/eigen/login", username="lena", password="falsch-falsch-1")
r.check("(b) … abgelehnt: 401 `falsch`, login_fail mit quelle=lokal+ldap (beide gefragt)",
        _l_falsch.status_code == 401 and _grund(_l_falsch) == "falsch"
        and any(e[0] == "login_fail" and "quelle=lokal+ldap" in (e[3] or "") for e in _audit(auth)),
        f"HTTP {_l_falsch.status_code}")

# Ausfall: ohne lokales Passwort wird die Vorbuchung zurückgenommen, mit lokalem zählt der Fehlversuch.
auth, app = _app(**LDAP)
auth.create_user("notfall", password=PW)
auth.create_user("verz")                                   # Verzeichnis-Konto ohne lokales Passwort
auth.ldap = Verzeichnis({}, weg=True)
c = _client(app)
with Mitschnitt() as log_b:
    _weg_verz = _post(c, "/eigen/login", username="verz", password="egal-egal-1")
    _weg_lokal = _post(c, "/eigen/login", username="notfall", password="falsch-falsch-1")
    _z = {u: [v for v in _versuche(auth) if v[0] == u] for u in ("verz", "notfall")}
    _weg_richtig = _post(c, "/eigen/login", username="notfall", password=PW)
r.check("(b) Verzeichnis weg: 503 `verzeichnis_weg` mit dem Text des Ausfalls",
        _weg_verz.status_code == 503 and _grund(_weg_verz) == "verzeichnis_weg"
        and _weg_verz.json()["meldung"] == auth.t("err.directory_down"),
        f"HTTP {_weg_verz.status_code} {_grund(_weg_verz)}")
r.check("(b) … ohne lokales Passwort ist es kein Fehlversuch: Vorbuchung zurückgenommen, kein `failed login`",
        _z["verz"] == [] and not [z for z in log_b.zeilen("failed login") if "user=verz" in z]
        and log_b.zeilen("LDAP nicht erreichbar user=verz"),
        f"{_z['verz']} {log_b.zeilen()[:3]}")
r.check("(b) … mit falschem lokalem Passwort zählt er (A-1), das lokale Notfallkonto meldet sich an",
        [v[2:] for v in _z["notfall"]] == [(0, "password", 0)] and _weg_lokal.status_code == 503
        and any(e[0] == "login_fail" and e[1] == "notfall" and "quelle=lokal" in (e[3] or "")
                for e in _audit(auth))
        and _weg_richtig.status_code == 303 and _sitzung(auth, _weg_richtig),
        f"{_z['notfall']} {_weg_lokal.status_code} {_weg_richtig.status_code}")

# Eine Kennung, ein Konto (Prüfrunde 2026-09-27): Mallory heisst lokal `alice.neu`, Alice im
# Verzeichnis auch — ihr LDAP-Passwort öffnet unter dieser Kennung über den Baustein nichts.
auth, app = _app(**LDAP)
auth.ldap = Verzeichnis({"alice": {"pw": LPW, "id": "uuid-alice"}})
_post(_client(app), "/eigen/login", username="alice", password=LPW)
_alice = auth.store.get_user_by_name("alice")["id"]
auth.create_user("alice.neu", password="Mallory-Pw-15xy")
auth.ldap = Verzeichnis({"alice.neu": {"pw": LPW, "id": "uuid-alice"}})
_fremd = _post(_client(app), "/eigen/login", username="alice.neu", password=LPW)
r.check("(b) eine Kennung, ein Konto: das LDAP-Passwort einer anderen Person öffnet unter einer lokal "
        "vergebenen Kennung keine Sitzung (401), Audit `ldap_kennung_abgewiesen`",
        _fremd.status_code == 401 and _sitzung(auth, _fremd) is None
        and any(e[0] == "ldap_kennung_abgewiesen" for e in _audit(auth)),
        f"HTTP {_fremd.status_code}, {[e[0] for e in _audit(auth)]}")


# ── (c) Gleichheit mit der eingebauten Route ──────────────────────────────────────────────────────
# Dieselbe Folge einmal über `POST /auth/login` (bzw. /auth/pin, /auth/totp), einmal über die eigene
# Route — jede in einer frischen Instanz. Gleich sein müssen: Status, Umleitungsziel, Audit-Zeilen,
# Sicherheits-Log, Versuchs- und Serientabelle. Das ist der Beleg für „eine Quelle“.
def _lauf(eingebaut: bool, schritte, aufbau):
    auth, app = aufbau()
    pfade = {"login": "/auth/login", "pin": "/auth/pin", "totp": "/auth/totp"} if eingebaut else \
        {"login": "/eigen/login", "pin": "/eigen/pin", "totp": "/eigen/totp"}
    c = _client(app)
    ergebnis = []
    with Mitschnitt() as log:
        for art, daten in schritte(auth):
            a = _post(c, pfade[art], **daten)
            ergebnis.append((a.status_code, a.headers.get("location")))
    return dict(status=ergebnis, audit=_audit(auth), log=log.zeilen(), versuche=_versuche(auth),
                serie=_serie(auth))


def _vergleich(name, schritte, aufbau):
    ein, eigen = _lauf(True, schritte, aufbau), _lauf(False, schritte, aufbau)
    abweichend = [k for k in ein if ein[k] != eigen[k]]
    r.check(f"(c) {name}: eingebaute und eigene Route — dieselben Status, Audit-, Log- und Zählerzeilen",
            not abweichend and len(ein["audit"]) >= 3 and ein["log"],
            "; ".join(f"{k}: eingebaut {ein[k]} ≠ eigen {eigen[k]}" for k in abweichend)[:900]
            or f"zu wenig gemessen: {ein}")
    return ein


def _aufbau_pw():
    auth, app = _app(haertung={"max_login_attempts": 3})
    auth.create_user("erika", password=PW)
    auth.create_user("fritz", password=PW)
    return auth, app


_c_pw = _vergleich("Passwort (falsch, leer, richtig, Sperre, unbekannter Name)", lambda a: [
    ("login", {"username": "erika", "password": "falsch-1"}),
    ("login", {"username": "erika", "password": ""}),
    ("login", {"username": "fritz", "password": PW}),
    ("login", {"username": "erika", "password": "falsch-2"}),
    ("login", {"username": "erika", "password": "falsch-3"}),
    ("login", {"username": "erika", "password": PW}),                # Paar gesperrt
    ("login", {"username": "niemand", "password": "falsch-4"}),
], _aufbau_pw)
r.check("(c) … die Folge hat Sperre und Erfolg gesehen (sonst verglich sie wenig)",
        [s for s, _ in _c_pw["status"]] == [401, 400, 303, 401, 401, 429, 401],
        str(_c_pw["status"]))


def _aufbau_ldap():
    auth, app = _app(**LDAP)
    auth.create_user("notfall", password=PW)
    auth.create_user("verz")
    auth.ldap = Verzeichnis({"lena": {"pw": LPW, "id": "uuid-lena"}})
    return auth, app


def _ldap_folge(auth):
    yield "login", {"username": "lena", "password": LPW}
    yield "login", {"username": "lena", "password": "falsch-falsch-1"}
    auth.ldap.weg = True
    yield "login", {"username": "verz", "password": "egal-egal-1"}
    yield "login", {"username": "notfall", "password": "falsch-falsch-1"}
    yield "login", {"username": "notfall", "password": PW}


_c_ldap = _vergleich("LDAP (Rückfall, abgelehnt, Ausfall mit und ohne lokales Passwort)", _ldap_folge,
                     _aufbau_ldap)
r.check("(c) … LDAP-Folge: 303, 401, 503, 503, 303",
        [s for s, _ in _c_ldap["status"]] == [303, 401, 503, 503, 303], str(_c_ldap["status"]))


def _aufbau_pin():
    auth, app = _app(pin_enabled=True, haertung={"pin_max_attempts": 3})
    uid = auth.create_user("gustav", password=PW)
    auth.set_pin(uid, PIN)
    return auth, app


_c_pin = _vergleich("PIN als Erstfaktor (falsch, Sperre des PIN-Topfs)", lambda a: [
    ("pin", {"username": "gustav", "pin": "0000"}),
    ("pin", {"username": "gustav", "pin": ""}),
    ("pin", {"username": "gustav", "pin": "0001"}),
    ("pin", {"username": "gustav", "pin": "0002"}),
    ("pin", {"username": "gustav", "pin": PIN}),
], _aufbau_pin)
r.check("(c) … PIN-Folge: 401, 400, 401, 401, 429", [s for s, _ in _c_pin["status"]] == [401, 400, 401, 401, 429],
        str(_c_pin["status"]))


# ── (d) PIN über den Baustein ─────────────────────────────────────────────────────────────────────
auth, app = _app(pin_enabled=True, pin_login=True)
uid = auth.create_user("hanna", password=PW)
auth.set_pin(uid, PIN)
c = _client(app)
_p_falsch = _post(c, "/eigen/pin", username="hanna", pin="0000")
_p_ok = _post(c, "/eigen/pin", username="hanna", pin=PIN)
r.check("(d) Gästeweg: falsche PIN 401 `falsch` (naechster None), richtige PIN 303 mit Sitzung",
        _p_falsch.status_code == 401 and _grund(_p_falsch) == "falsch" and _p_falsch.json()["naechster"] is None
        and _p_ok.status_code == 303 and c.get("/drin").json() == {"u": "hanna"},
        f"{_p_falsch.status_code} {_p_ok.status_code}")

auth, app = _app(pin_enabled=True, pin_login=False, login_chain=["password", "pin"])
uid = auth.create_user("ines", password=PW)
auth.set_pin(uid, PIN)
c = _client(app)
_k1 = _post(c, "/eigen/login", username="ines", password=PW)
_k_drin = c.get("/drin", headers={"Accept": "application/json"}, follow_redirects=False)
_k_falsch = _post(c, "/eigen/pin", pin="0000")
_k_serie = [(z["art"], z["anzahl"]) for z in auth.store._all(
    "SELECT art, anzahl FROM fehlserie WHERE topf='ines' AND anzahl > 0")]
_k_seite = c.post("/auth/pin", data={"pin": "0001", "next": "/drin"}, headers={"Accept": "text/html"},
                  follow_redirects=False)
_k_ok = _post(c, "/eigen/pin", pin=PIN)
_gast = _post(_client(app), "/eigen/pin", username="ines", pin=PIN)
r.check("(d) Kettenschritt: nach dem Passwort führt `weiter` auf /auth/pin, /drin noch zu",
        _k1.status_code == 303 and _k1.headers["location"].startswith("/auth/pin")
        and _k_drin.status_code != 200,
        f"{_k1.status_code} {_k1.headers.get('location')}")
r.check("(d) … falsche PIN im Kettenschritt: 401, `naechster` bleibt \"pin\", Serie unter eigener Art",
        _k_falsch.status_code == 401 and _k_falsch.json()["naechster"] == "pin"
        and _k_serie == [(TinySesam._SERIE_PIN_FOLGE, 1)],
        f"{_k_falsch.status_code} {_k_falsch.text[:120]} {_k_serie}")
r.check("(d) … die eingebaute Route zeigt dann wieder die PIN-Seite: ohne Namensfeld, mit dem Konto "
        "der Sitzung (401)",
        _k_seite.status_code == 401 and "name=pin " in _k_seite.text and "name=username" not in _k_seite.text
        and auth.t("reauth.hint", user="ines") in _k_seite.text, _k_seite.text[:200])
r.check("(d) … richtige PIN ohne Namensfeld: 303, Sitzung voll",
        _k_ok.status_code == 303 and c.get("/drin").json() == {"u": "ines"}, f"{_k_ok.status_code}")
r.check("(d) … ohne Sitzung ist die PIN hier kein Erstfaktor: 404 `abgeschaltet`",
        _gast.status_code == 404 and _grund(_gast) == "abgeschaltet", f"{_gast.status_code} {_gast.text[:80]}")

# Ohne `pin_enabled` gibt es die Route nicht — der Baustein sagt dasselbe, auch wenn noch ein
# PIN-Hash von früher in der Datenbank steht und auch auf einer vollen Sitzung.
# (Mutationsprobe: in `anmelden_pin` `not cfg.pin_enabled or` streichen → die volle Sitzung
# bestätigt die PIN → rot.)
auth, app = _app(pin_enabled=False)
uid = auth.create_user("jan", password=PW)
auth.set_pin(uid, PIN)
c = _client(app)
_p_aus = _post(c, "/eigen/pin", username="jan", pin=PIN)
_post(c, "/eigen/login", username="jan", password=PW)
_p_aus_voll = _post(c, "/eigen/pin", pin=PIN)
r.check("(d) ohne pin_enabled: `abgeschaltet` (404) — als Gast und auf voller Sitzung, trotz PIN-Hash",
        _p_aus.status_code == 404 and _grund(_p_aus) == "abgeschaltet"
        and _p_aus_voll.status_code == 404 and _grund(_p_aus_voll) == "abgeschaltet",
        f"{_p_aus.status_code} {_p_aus_voll.status_code}")


# ── (e) TOTP über den Baustein ────────────────────────────────────────────────────────────────────
auth, app = _app(haertung={"max_login_attempts": 3})
uid = auth.create_user("karl", password=PW)
geheim = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(geheim).at(time.time() - 30))
codes = auth.generate_recovery_codes(uid)
c = _client(app)
_t1 = _post(c, "/eigen/login", username="karl", password=PW)
_halb = _sitzung(auth, _t1)
_t_falsch = _post(c, "/eigen/totp", code="000000")
_t_ok = _post(c, "/eigen/totp", code=pyotp.TOTP(geheim).now())
r.check("(e) Passwort mit TOTP: 303 auf /auth/totp, halbe Sitzung (kein /drin)",
        _t1.status_code == 303 and _t1.headers["location"].startswith("/auth/totp") and _halb,
        f"{_t1.status_code} {_t1.headers.get('location')}")
r.check("(e) … falscher Code: 401 `falsch`, `naechster` bleibt \"totp\", Text des Codes",
        _t_falsch.status_code == 401 and _t_falsch.json()["naechster"] == "totp"
        and _t_falsch.json()["meldung"] == auth.t("err.code"), _t_falsch.text[:160])
r.check("(e) … richtiger Code: neues Token (Rechtewechsel), Sitzung voll, das halbe Token tot",
        _t_ok.status_code == 303 and _t_ok.headers["location"] == "/drin"
        and _sitzung(auth, _t_ok) not in (None, _halb) and c.get("/drin").json() == {"u": "karl"}
        and auth.store.get_session(_halb) is None, f"{_t_ok.status_code}")

_j = _client(app, ("203.0.113.12", 1)).post("/eigen/json", json={"username": "karl", "password": PW})
r.check("(e) das Ergebnis nach dem Passwort nennt den offenen Schritt: fertig False, naechster \"totp\", "
        "weiter auf /auth/totp",
        _j.status_code == 200 and _j.json()["fertig"] is False and _j.json()["naechster"] == "totp"
        and _j.json()["weiter"].startswith("/auth/totp"), _j.text[:200])

c2 = _client(app, ("203.0.113.10", 1))
_post(c2, "/eigen/login", username="karl", password=PW)
_rc = _post(c2, "/eigen/totp", code=codes[0])
r.check("(e) Einmal-Code statt TOTP: angenommen, wie /auth/totp", _rc.status_code == 303
        and c2.get("/drin").json() == {"u": "karl"}, f"{_rc.status_code}")

_ohne = _post(_client(app), "/eigen/totp", code="123456")
r.check("(e) ohne Sitzung: 401 `keine_sitzung`, `weiter` ist die Login-Seite",
        _ohne.status_code == 401 and _grund(_ohne) == "keine_sitzung"
        and _ohne.json()["weiter"] == "/auth/login", _ohne.text[:160])

c3 = _client(app, ("203.0.113.11", 1))
_post(c3, "/eigen/login", username="karl", password=PW)
_t_sperre = [_post(c3, "/eigen/totp", code=f"00000{i}") for i in range(4)]
r.check("(e) TOTP-Raten: nach 3 Fehlgriffen 429 `gesperrt` mit dem Text der Seite (err.retry)",
        [a.status_code for a in _t_sperre] == [401, 401, 401, 429] and _grund(_t_sperre[-1]) == "gesperrt"
        and _t_sperre[-1].json()["meldung"] == auth.t("err.retry"),
        f"{[(a.status_code, _grund(a)) for a in _t_sperre]}")


# Die TOTP-Folge braucht je Lauf das Geheimnis ihrer Instanz (jede würfelt ein eigenes).
_geheimnisse: dict = {}


def _aufbau_totp_mit():
    auth, app = _app(haertung={"max_login_attempts": 3})
    uid = auth.create_user("lotte", password=PW)
    g = auth.totp_begin(uid)["secret"]
    auth.totp_confirm(uid, pyotp.TOTP(g).at(time.time() - 30))
    _geheimnisse[id(auth)] = g
    return auth, app


def _totp_schritte(auth):
    g = _geheimnisse[id(auth)]
    yield "login", {"username": "lotte", "password": PW}
    yield "totp", {"code": "000000"}
    yield "totp", {"code": ""}
    yield "totp", {"code": pyotp.TOTP(g).now()}


_c_totp = _vergleich("TOTP (Passwort, falscher Code, leer, richtiger Code)", _totp_schritte, _aufbau_totp_mit)
r.check("(c) … TOTP-Folge: 303, 401, 400, 303", [s for s, _ in _c_totp["status"]] == [303, 401, 400, 303],
        str(_c_totp["status"]))


# ── (f) CSRF, fail-closed, der Ergebnistyp ────────────────────────────────────────────────────────
auth, app = _app(csrf_enabled=True)
auth.create_user("mia", password=PW)
c = _client(app)
c.get("/auth/login")                                          # setzt das CSRF-Cookie
tok = c.cookies.get(auth.csrf_cookie_name)
_ohne_tok = _post(c, "/eigen/login", username="mia", password=PW)
_mit_tok = _post(c, "/eigen/login", username="mia", password=PW, _csrf=tok)
r.check("(f) CSRF wie jede Anmelderoute: ohne Token 403, mit Token 303",
        _ohne_tok.status_code == 403 and _sitzung(auth, _ohne_tok) is None and _mit_tok.status_code == 303,
        f"{_ohne_tok.status_code} {_mit_tok.status_code}")
c = _client(app)
c.get("/auth/login")
tok = c.cookies.get(auth.csrf_cookie_name)
_json = c.post("/eigen/json", json={"username": "mia", "password": PW}, headers={"X-CSRF-Token": tok})
_json_ohne = _client(app).post("/eigen/json", json={"username": "mia", "password": PW})
# Mit frischem Token: Nach der Anmeldung oben hat `set_cookie` das CSRF-Token gedreht, ein altes
# Token wäre ohnehin falsch — dann prüfte die Probe nichts.
c_leer = _client(app)
c_leer.get("/auth/login")
_leer_arg = c_leer.post("/eigen/login", data={"username": "mia", "password": PW, "_csrf": ""},
                        headers={"X-CSRF-Token": c_leer.cookies.get(auth.csrf_cookie_name)},
                        follow_redirects=False)
r.check("(f) `csrf=None` nimmt den Header X-CSRF-Token (JSON-Weg), ohne ihn 403; ein leeres "
        "Formularfeld fällt NICHT auf den Header zurück (wie die Formular-Route)",
        _json.status_code == 200 and _json.json()["fertig"] is True and _sitzung(auth, _json)
        and _json_ohne.status_code == 403 and _leer_arg.status_code == 403,
        f"{_json.status_code} {_json_ohne.status_code} {_leer_arg.status_code}")

# Fail-closed: Ein Misserfolg trägt kein Token — wer ihn trotzdem „weiterleitet“, setzt kein Cookie.
auth, app = _app()
auth.create_user("nora", password=PW)
_ergebnisse = {}


@app.post("/eigen/roh")
def _roh(request: Request, username: str = Form(""), password: str = Form("")):
    erg = auth.anmelden_passwort(request, username, password, next="/drin")
    _ergebnisse[password] = erg
    return erg.weiterleitung()           # das Ergebnis ignoriert — der schlimmste Fall


c = _client(app)
_ign = c.post("/eigen/roh", data={"username": "nora", "password": "falsch-1"}, follow_redirects=False)
_ign_ziel = c.get("/drin", headers={"Accept": "application/json"})
r.check("(f) fail-closed: wer das Ergebnis ignoriert und weiterleitet, landet ohne Sitzung auf /drin (401)",
        _ign.status_code == 303 and "set-cookie" not in {k.lower() for k in _ign.headers}
        and _ign_ziel.status_code == 401, f"{_ign.status_code} {dict(_ign.headers)} {_ign_ziel.status_code}")
c.post("/eigen/roh", data={"username": "nora", "password": PW}, follow_redirects=False)
_erfolg = _ergebnisse[PW]
_felder = {f.name for f in dataclasses.fields(Anmeldung)}
r.check("(f) Ergebnistyp: bool = ok, das Token ist kein Feld und steht weder in repr() noch in asdict()",
        bool(_erfolg) and not bool(_ergebnisse["falsch-1"]) and _erfolg.fertig and _erfolg.user["username"] == "nora"
        and _ergebnisse["falsch-1"].user is None
        and _felder == {"ok", "grund", "status", "meldung", "weiter", "naechster", "fertig", "user"}
        and _erfolg._token and _erfolg._token not in repr(_erfolg)
        and _erfolg._token not in repr(dataclasses.asdict(_erfolg)),
        repr(_erfolg)[:200])
try:
    _erfolg.ok = False                   # type: ignore[misc]
    _eingefroren = False
except dataclasses.FrozenInstanceError:
    _eingefroren = True
_falsch_gebaut = []
for kw in ({"ok": False, "grund": "erfunden", "status": 400}, {"ok": True, "grund": "falsch", "status": 303},
           {"ok": False, "grund": "ok", "status": 303}):
    try:
        Anmeldung(**kw)
        _falsch_gebaut.append(kw)
    except ValueError:
        pass
r.check("(f) … eingefroren, und ein Grund ausserhalb von GRUENDE oder ein ok gegen den Grund wirft",
        _eingefroren and not _falsch_gebaut, f"{_eingefroren} {_falsch_gebaut}")
_ersetzt = dataclasses.replace(_erfolg)
_antwort = JSONResponse({})
_ersetzt.cookie_setzen(_antwort)
r.check("(f) … eine Kopie per dataclasses.replace trägt kein Token (setzt kein Cookie)",
        "set-cookie" not in {k.lower() for k in _antwort.headers}, str(dict(_antwort.headers)))
r.check("(f) jeder Grund, den der Baustein liefert, steht in GRUENDE (auch die gemessenen)",
        {"ok", "leer", "falsch", "gesperrt", "gesperrt_serie", "ratelimit", "verzeichnis_weg", "abgeschaltet",
         "keine_sitzung"} == set(Anmeldung.GRUENDE), str(Anmeldung.GRUENDE))


# ── (g) Unerwartetes in der Prüfung zählt sofort ──────────────────────────────────────────────────
# Eine Ausnahme mitten in der Prüfung (Datenbank weg, Schlüssel fehlt) darf den vorgebuchten Versuch
# nicht offen liegen lassen: Er wird sofort zum Fehlversuch, auch seine Vorbuchung in der Serie ist
# abgeschlossen. Bis 0.21.0 galt das nur für das Passwort — seit dem Baustein für alle drei Schritte.
# (Mutationsprobe: in `anmelden_totp` bzw. `anmelden_pin` den `except BaseException`-Zweig streichen → rot.)
def _kaputt(*_a, **_k):
    raise RuntimeError("Prüfung kaputt (Test)")


for art in ("totp", "pin"):
    auth, app = _app(pin_enabled=True, pin_login=True, login_chain=["password", "totp"] if art == "totp" else [])
    uid = auth.create_user("otto", password=PW)
    if art == "totp":
        g = auth.totp_begin(uid)["secret"]
        auth.totp_confirm(uid, pyotp.TOTP(g).at(time.time() - 30))
    else:
        auth.set_pin(uid, PIN)
    c = TestClient(app, client=IP, raise_server_exceptions=False)
    if art == "totp":
        _post(c, "/eigen/login", username="otto", password=PW)
        auth._verify_totp = _kaputt
        _k = _post(c, "/eigen/totp", code="123456")
    else:
        auth._check_pin = _kaputt
        _k = _post(c, "/eigen/pin", username="otto", pin=PIN)
    _zeile = [v for v in _versuche(auth) if v[3] == art]
    r.check(f"(g) {art}: Ausnahme in der Prüfung → 500, der Versuch ist als Fehlversuch abgeschlossen, "
            "keine Serien-Vorbuchung bleibt liegen",
            _k.status_code == 500 and _zeile and _zeile[-1][2:] == (0, art, 0) and not auth._serie_vorbuchungen,
            f"{_k.status_code} {_zeile} {auth._serie_vorbuchungen}")


# ── (h) Eine Quelle: die Routen rufen den Baustein, keinen inneren Prüfer ─────────────────────────
# Stünde die Prüfung zweimal da — in der Route und im Baustein —, liefe sie auseinander, und der
# Baustein wäre der schwächere Weg. Die Routen dürfen den Baustein rufen und das Ergebnis rendern;
# jeder Name der Buchhaltung ist ihnen verboten.
# (Mutationsprobe: in `login_submit` wieder `auth._check_password(...)` rufen → rot.)
INNERE = {"_check_password", "_check_pin", "_check_ldap", "_verify_totp", "_verify_recovery_code",
          "_verify_user_pin", "_versuch_beginnen", "_versuch_gescheitert", "_versuch_zuruecknehmen",
          "_record_login", "_rate_ok", "_serie_voll", "apply_factor", "complete_totp", "set_cookie",
          "start_session", "_login_redirect_after", "_pin_kettenschritt"}
ROUTEN = {"login_submit": "anmelden_passwort", "pin_submit": "anmelden_pin", "totp_submit": "anmelden_totp"}


def _routen_befunde(quelltext):
    befunde, gefunden = [], set()
    for fn in ast.walk(ast.parse(quelltext)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name not in ROUTEN:
            continue
        gefunden.add(fn.name)
        namen = {k.attr for k in ast.walk(fn) if isinstance(k, ast.Attribute)}
        if ROUTEN[fn.name] not in namen:
            befunde.append(f"{fn.name} ruft {ROUTEN[fn.name]} nicht")
        befunde += [f"{fn.name} ruft {n} selbst" for n in sorted(namen & INNERE)]
    befunde += [f"{n} fehlt im Router" for n in sorted(set(ROUTEN) - gefunden)]
    return befunde


_router = (ROOT / "tinysesam" / "router.py").read_text(encoding="utf-8")
_selbst = {
    "sauber": ("def login_submit(r):\n    erg = auth.anmelden_passwort(r, 'a', 'b')\n    return erg.weiterleitung()\n"
               "def pin_submit(r):\n    return auth.anmelden_pin(r, '1')\n"
               "def totp_submit(r):\n    return auth.anmelden_totp(r, '1')\n", []),
    "doppelt": ("def login_submit(r):\n    auth._check_password('a', 'b')\n    return auth.anmelden_passwort(r, 'a', 'b')\n"
                "def pin_submit(r):\n    return auth.anmelden_pin(r, '1')\n"
                "def totp_submit(r):\n    return auth.anmelden_totp(r, '1')\n", ["login_submit ruft _check_password selbst"]),
    "vorbei": ("def login_submit(r):\n    return auth._versuch_beginnen('a', 'b', 'password')\n"
               "def pin_submit(r):\n    return auth.anmelden_pin(r, '1')\n", None),
}
for _probe, (_text, _erwartet) in _selbst.items():
    _b = _routen_befunde(_text)
    if _erwartet is None:
        assert any("ruft anmelden_passwort nicht" in x for x in _b) and any("totp_submit fehlt" in x for x in _b), _b
    else:
        assert _b == _erwartet, (_probe, _b)
_befunde_h = _routen_befunde(_router)
r.check("(h) eine Quelle: login_submit, pin_submit, totp_submit rufen ihren Baustein und keinen "
        "inneren Prüfer, keine Buchhaltung, keine Sitzungsanlage selbst (AST, 3 Selbstproben)",
        not _befunde_h, "; ".join(_befunde_h))


# ── (i) Das Beispiel der README ist selbst geschützt ──────────────────────────────────────────────
# Der Befund kam aus der README. Deshalb läuft ihr Beispiel hier wörtlich — mit der Vorgabe-
# Konfiguration (CSRF an, Secure-Cookies, fünf Fehlversuche je Paar): Es muss nach der Grenze
# sperren und mit dem richtigen Passwort anmelden. `test_repo.py` führt den Block nur aus.
# (Mutationsprobe: im README-Beispiel `auth.anmelden_passwort(…)` durch das alte Muster
# `auth._check_password` + `start_session` ersetzen → keine 429 → rot.)
def _readme_beispiel(datei, kopf):
    text = (ROOT / datei).read_text(encoding="utf-8")
    abschnitt = text.split(kopf, 1)[1].split("\n## ", 1)[0]
    bloecke = re.findall(r"```python\n(.*?)```", abschnitt, re.S)
    return bloecke[0] if bloecke else ""


for _datei, _kopf in (("README.md", "## Your own login page\n"), ("i18n/README.de.md", "## Eigene Login-Seite\n")):
    _quelle = _readme_beispiel(_datei, _kopf)
    _db = str(Path(tempfile.mkdtemp()) / "app.db")
    _ns: dict = {"__name__": "readme_beispiel"}
    exec(compile(_quelle.replace('db_path="app.db"', f"db_path={_db!r}"), _datei, "exec"), _ns)   # noqa: S102
    _auth, _app_r = _ns.get("auth"), _ns.get("app")
    _auth.create_user("quentin", password=PW)
    _c = TestClient(_app_r, base_url="https://testserver", client=IP)
    _c.get("/auth/login")
    _tok = _c.cookies.get(_auth.csrf_cookie_name)
    _grenze = _auth.all_security()["max_login_attempts"]
    _folge = [_c.post("/login", data={"username": "quentin", "password": f"falsch-{i}", "_csrf": _tok},
                      follow_redirects=False).status_code for i in range(_grenze + 1)]
    _gesperrt = _c.post("/login", data={"username": "quentin", "password": PW, "_csrf": _tok},
                        follow_redirects=False)
    _c2 = TestClient(_app_r, base_url="https://testserver", client=("203.0.113.77", 1))
    _c2.get("/auth/login")
    _frei = _c2.post("/login", data={"username": "quentin", "password": PW, "next": "/auth/me",
                                     "_csrf": _c2.cookies.get(_auth.csrf_cookie_name)}, follow_redirects=False)
    _ohne_csrf = TestClient(_app_r, base_url="https://testserver").post(
        "/login", data={"username": "quentin", "password": PW}, follow_redirects=False)
    r.check(f"(i) {_datei}: das Beispiel „eigene Login-Route“ sperrt nach {_grenze} Fehlversuchen (429), "
            "meldet von anderer Adresse an (303, Cookie) und verlangt CSRF (403)",
            "anmelden_passwort" in _quelle and _folge == [401] * _grenze + [429]
            and _gesperrt.status_code == 429 and _frei.status_code == 303
            and _frei.cookies.get(_auth.session_cookie_name) and _ohne_csrf.status_code == 403,
            f"{_folge} {_gesperrt.status_code} {_frei.status_code} {_ohne_csrf.status_code}")


# ── (j) Test-Fakes: auf dem alten Namen wirkungslos, deshalb laut ─────────────────────────────────
# Befund der Gegenprüfung 2026-09-27: `auth.check_password = fake` wurde 0-mal gerufen, der Login
# ergab 303 — und niemand warnte. Die Routen rufen `_check_password` (über `anmelden_passwort`).
# Seitdem warnt die Zuweisung (RuntimeWarning, `Veraltet.__set__`) und nennt das Ziel; ein Fake
# auf dem neuen Namen wirkt wie vorher einer auf dem alten.
# (Mutationsprobe: `__set__`/`__delete__` in `tinysesam/_veraltet.py` streichen → keine Warnung → rot.)
auth, app = _app()
auth.create_user("fritz", password=PW)
_aufrufe = []


def _fake(*a, **k):
    _aufrufe.append(a)
    return None


with warnings.catch_warnings(record=True) as _w_alt:
    warnings.simplefilter("always")
    auth.check_password = _fake
_s_alt = [_post(_client(app), pfad, username="fritz", password=PW).status_code
          for pfad in ("/auth/login", "/eigen/login")]
r.check("(j) Fake auf dem alten Namen (`auth.check_password = fake`): genau eine RuntimeWarning, "
        "sie nennt `_check_password` und zeigt auf die Zuweisung; der Fake wird nie gerufen (303, 303)",
        [w.category for w in _w_alt] == [RuntimeWarning] and "`_check_password`" in str(_w_alt[0].message)
        and Path(_w_alt[0].filename).resolve() == Path(__file__).resolve()
        and _s_alt == [303, 303] and not _aufrufe,
        f"{[(w.category.__name__, str(w.message)[:80]) for w in _w_alt]} {_s_alt} {_aufrufe}")
del auth.check_password

with warnings.catch_warnings(record=True) as _w_mock:
    warnings.simplefilter("always")
    with mock.patch.object(auth, "rate_ok", return_value=False) as _m:
        _s_mock = _post(_client(app, ("203.0.113.10", 1)), "/auth/login", username="fritz",
                        password=PW).status_code
_nachher = "rate_ok" in vars(auth)
r.check("(j) `mock.patch.object(auth, \"rate_ok\", …)`: warnt (RuntimeWarning mit `_rate_ok`), "
        "drosselt nicht (303, 0 Aufrufe) und räumt beim Verlassen auf",
        [w.category for w in _w_mock] == [RuntimeWarning] and "`_rate_ok`" in str(_w_mock[0].message)
        and _s_mock == 303 and _m.call_count == 0 and not _nachher,
        f"{[w.category.__name__ for w in _w_mock]} {_s_mock} {_m.call_count} {_nachher}")

with warnings.catch_warnings(record=True) as _w_neu:
    warnings.simplefilter("always")
    auth._check_password = _fake
    _s_neu = _post(_client(app, ("203.0.113.11", 1)), "/auth/login", username="fritz",
                   password=PW).status_code
r.check("(j) derselbe Fake auf dem neuen Namen (`auth._check_password = fake`) wirkt: gerufen, 401, "
        "keine Warnung",
        _aufrufe and _s_neu == 401 and not _w_neu, f"{_aufrufe} {_s_neu} {[str(w.message) for w in _w_neu]}")

sys.exit(r.done())
