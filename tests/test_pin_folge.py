"""G7 — die Stellung der PIN: Erstfaktor oder Folgefaktor, gemessen am Weg, nicht an der Konfiguration.

Die Serie der Fehlversuche in Folge (B2-6) zählt je Art. Ein Selbstbedienungs-Reset räumt die Anteile
der ersten Faktoren — Passwort und PIN, die kann jeder erzeugen, auch ohne ein Geheimnis (R2-2) —,
TOTP-Fehlgriffe bleiben: Die erzeugt nur, wer das Passwort schon hat. Bis 2026-09-26 war die Art die
Methode, und eine PIN HINTER dem Passwort (Kette `password → pin`) buchte wie ein Erstfaktor. Wer
Postfach und Passwort hatte, bekam je Reset eine frische Serie gegen die PIN.

Jetzt bucht eine PIN hinter einem schon erbrachten Faktor (halbe Sitzung im Kettenschritt, volle in
einer Route-Kette) unter `SERIE_PIN_FOLGE`. Dazu zwei Nebenbefunde am selben Weg:

  N1  `pin_login=False` mit einer Kette `password → pin` war eine Sackgasse: Der PIN-Schritt lief über
      den Gästeweg, und der ist bei `pin_login=False` zu (404).
  N2  In einer strikten Kette `password → pin` erfüllt eine zuerst eingegebene PIN die Kette nie. Der
      Gästeweg nützte nur Ratenden (falsche PIN 401, richtige 303 — ohne Passwort).

Seit der Prüfrunde 2026-09-27 (p2 F1) gilt die halbe Sitzung nur, wenn die PIN ihr Kettenschritt ist
(`_pin_kettenschritt`, Block j), und der Ausweg aus der Serie richtet sich nach deren Art (letzter Block).
"""
from __future__ import annotations

import io
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import konfigpruefung  # noqa: E402
from tinysesam.__main__ import main as _cli  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("G7 — PIN als Erst- oder Folgefaktor (Serie, Kettenschritt, Gästeweg)")
PW = "Folge-Pin-Pw-15"          # 15 Zeichen: das Passwort meldet hier ggf. allein an (B2-4)
NEU = "Neues-Pw-G7-123"
PIN = "4711"
FOLGE = TinySesam._SERIE_PIN_FOLGE
HTML = {"Accept": "text/html"}


def _app(**cfg):
    mails: list = []
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 base_url="http://testserver", lang="de", passkey_enabled=False, pin_enabled=True)
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000), ("pin_max_attempts", 100),
                 ("account_max_consecutive_failures", 10)):
        auth.set_security(k, v)
    auth.set_mailer(lambda to, betreff, text, html=None: mails.append((to, betreff, text)))
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/drin")
    def _drin(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    @app.get("/pinbereich")
    def _pinbereich(u=Depends(auth.require(factors=["password", "pin"]))):
        return {"u": u["username"]}

    return auth, app, mails


def _konto(auth, name, email=None):
    uid = auth.create_user(name, password=PW, email=email or f"{name}@example.com")
    auth.set_pin(uid, PIN)
    return uid


def _passwort(client, name, pw=PW):
    return client.post("/auth/login", data={"username": name, "password": pw, "next": "/drin"},
                       follow_redirects=False)


def _pin(client, pin, **extra):
    return client.post("/auth/pin", data={"pin": pin, "next": "/drin", **extra}, follow_redirects=False)


def _arten(auth, kennung):
    return {z["art"]: z["anzahl"] for z in auth.store._all("SELECT art, anzahl FROM fehlserie WHERE topf=?",
                                                            (kennung,)) if z["anzahl"]}


def _unlock(auth, kennung):
    code = 0
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        try:
            _cli(["unlock", "--db", auth.cfg.db_path, kennung])
        except SystemExit as e:        # sonst endete der Test hier mit Exit 0 (Skip ist kein Grün)
            code = e.code or 0
    return code


# ── (a) Kettenschritt nach dem Passwort: Fehlgriffe der Art pin_folge, der Reset räumt sie nicht ──
auth, app, _ = _app(login_chain=["password", "pin"], password_reset_enabled=True)
uid = _konto(auth, "kette")
c = TestClient(app)
_nach_pw = _passwort(c, "kette")
for i in range(5):
    _pin(c, f"000{i}")
r.check("(a) nach dem Passwort führt die Kette auf /auth/pin; fünf falsche PINs im Kettenschritt "
        "buchen unter pin_folge, nicht unter pin",
        _nach_pw.headers.get("location", "").startswith("/auth/pin") and _arten(auth, "kette") == {FOLGE: 5},
        f"{_nach_pw.headers.get('location')}, {_arten(auth, 'kette')}")
# (Mutationsprobe: `serie_art` in `login_pin` weglassen → {'pin': 5}, der Reset räumt → rot.)
auth.lift_lockout(uid, methods=("password",))                  # der Weg des Selbstbedienungs-Resets
r.check("(a) der Selbstbedienungs-Reset (lift_lockout mit password) lässt sie stehen, wie TOTP",
        auth.store.fehlserie("kette") == 5, str(_arten(auth, "kette")))
_tok = auth.create_magic_token("reset_password", user_id=uid, email="kette@example.com")
_reset = TestClient(app).post("/auth/reset", data={"token": _tok, "password": NEU}, follow_redirects=False)
r.check("(a) … auch über den echten POST /auth/reset",
        _reset.status_code == 303 and auth.store.fehlserie("kette") == 5 and auth._check_password("kette", NEU),
        f"HTTP {_reset.status_code}, {_arten(auth, 'kette')}")
# Eigene PIN-Seiten schicken den Namen oft mit — auch mit der Adresse des eigenen Kontos bleibt es der
# Kettenschritt der halben Sitzung (vorher: der Gästeweg, als Erstfaktor gebucht).
c = TestClient(app)
_passwort(c, "kette", NEU)
_pin(c, "0009", username="kette@example.com")
_pin(c, "0008", username="kette")
r.check("(a) mit Namen oder Adresse des eigenen Kontos im Formular bleibt es der Kettenschritt",
        _arten(auth, "kette") == {FOLGE: 7}, str(_arten(auth, "kette")))

# ── (b) R2-2 bleibt: eine Gast-PIN (Erstfaktor) räumt der Reset ─────────────────────────────────
auth_b, app_b, _ = _app()
uid_b = _konto(auth_b, "gast")
for i in range(5):
    _pin(TestClient(app_b), f"000{i}", username="gast")
_vorher_b = _arten(auth_b, "gast")
auth_b.lift_lockout(uid_b, methods=("password",))
# (Mutationsprobe: 'pin' aus `_SERIE_RESET_ARTEN` → 5 bleiben → rot.)
r.check("(b) R2-2: Fehlgriffe über den Gästeweg buchen unter pin, und der Reset räumt sie",
        _vorher_b == {"pin": 5} and auth_b.store.fehlserie("gast") == 0,
        f"{_vorher_b} → {_arten(auth_b, 'gast')}")

# ── (c) volle Anmeldung, Panel-Reset und `tinysesam unlock` räumen auch pin_folge ─────────────────
auth_c, app_c, _ = _app(login_chain=["password", "pin"])
uid_c = _konto(auth_c, "voll")
cc = TestClient(app_c)
_passwort(cc, "voll")
for i in range(4):
    _pin(cc, f"000{i}")
_vorher_c = _arten(auth_c, "voll")
_fertig = _pin(cc, PIN)
# (Mutationsprobe: in `lift_lockout` ohne `methoden` nur `_SERIE_RESET_ARTEN` räumen → 4 → rot.)
r.check("(c) die volle Anmeldung (richtige PIN im Kettenschritt) beendet die Serie ganz",
        _vorher_c == {FOLGE: 4} and _fertig.headers.get("location") == "/drin"
        and cc.get("/drin").status_code == 200 and auth_c.store.fehlserie("voll") == 0,
        f"{_vorher_c}, {_fertig.headers.get('location')}, {_arten(auth_c, 'voll')}")
auth_c.create_user("chefin", password=PW, is_admin=True)
auth_c.set_pin(auth_c.store.get_user_by_name("chefin")["id"], PIN)
ca = TestClient(app_c)
_passwort(ca, "chefin")
_pin(ca, PIN)
cv = TestClient(app_c)
_passwort(cv, "voll")
for i in range(4):
    _pin(cv, f"000{i}")
_panel = ca.post(f"/auth/admin/api/users/{uid_c}/password", json={"password": NEU})
# (Mutationsprobe: `_serie_beenden` räumt nur `_SERIE_RESET_ARTEN` → rot.)
r.check("(c) der Passwort-Reset im Panel räumt pin_folge (der Betreiber entscheidet)",
        _panel.status_code == 200 and auth_c.store.fehlserie("voll") == 0,
        f"HTTP {_panel.status_code}, {_arten(auth_c, 'voll')}")
cv = TestClient(app_c)
_passwort(cv, "voll", NEU)
for i in range(4):
    _pin(cv, f"000{i}")
_vorher_u = auth_c.store.fehlserie("voll")
_rc = _unlock(auth_c, "voll")
# (Mutationsprobe: `unlock` räumt die Serie nur mit `arten=("password", "pin")` → rot.)
r.check("(c) `tinysesam unlock` räumt pin_folge", _vorher_u == 4 and _rc == 0 and auth_c.store.fehlserie("voll") == 0,
        f"{_vorher_u}, rc {_rc}, {_arten(auth_c, 'voll')}")

# ── (d)+(g) Route-Kette mit voller Sitzung; eine richtige PIN nimmt nur ihre Vorbuchung zurück ────
auth_d, app_d, _ = _app()                                          # klassisch: Passwort = volle Sitzung
uid_d = _konto(auth_d, "route")
cd = TestClient(app_d)
_passwort(cd, "route")
_umweg = cd.get("/pinbereich", headers=HTML, follow_redirects=False)
for i in range(3):
    _pin(cd, f"000{i}")
_nach_falsch = _arten(auth_d, "route")
_richtig = _pin(cd, PIN)
r.check("(d) Route-Kette factors=[password, pin] mit voller Sitzung: die Fehlgriffe buchen unter pin_folge",
        _umweg.headers.get("location", "").startswith("/auth/pin") and _nach_falsch == {FOLGE: 3},
        f"{_umweg.headers.get('location')}, {_nach_falsch}")
# (Mutationsprobe: die Vorbuchung merkt sich `method` statt `serie[1]` → senken trifft die Art pin,
#  die Vorbuchung unter pin_folge bleibt → 4 → rot.)
r.check("(g) eine richtige PIN nimmt ihre Vorbuchung unter pin_folge zurück — die Serie davor bleibt",
        _richtig.status_code == 303 and cd.get("/pinbereich").status_code == 200
        and _arten(auth_d, "route") == {FOLGE: 3}, f"HTTP {_richtig.status_code}, {_arten(auth_d, 'route')}")

# ── (e) N1: pin_login=False mit Kette password → pin ist keine Sackgasse mehr ────────────────────
auth_e, app_e, _ = _app(login_chain=["password", "pin"], pin_login=False)
_konto(auth_e, "ohnelogin")
ce = TestClient(app_e)
_start = _passwort(ce, "ohnelogin")
_seite = ce.get("/auth/pin?next=/drin", headers=HTML, follow_redirects=False)
# (Mutationsprobe: in `pin_page` die halbe Sitzung nicht lesen → 303 zurück zur Anmeldung → rot.)
r.check("(e) N1: nach dem Passwort zeigt GET /auth/pin das PIN-Formular — ohne Namensfeld",
        _start.headers.get("location", "").startswith("/auth/pin") and _seite.status_code == 200
        and "name=pin" in _seite.text and "name=username" not in _seite.text,
        f"HTTP {_seite.status_code} {_seite.headers.get('location')}")
_ziel = _pin(ce, PIN)
# (Mutationsprobe: in `login_pin` `halb = None` → 404 → rot.)
r.check("(e) N1: … und die richtige PIN macht die Sitzung voll (/drin 200)",
        _ziel.status_code == 303 and _ziel.headers.get("location") == "/drin" and ce.get("/drin").status_code == 200,
        f"HTTP {_ziel.status_code} {_ziel.headers.get('location')}")
r.check("(e) N1: die Login-Seite bietet die PIN nicht an, der Gästeweg bleibt zu (pin_login=False)",
        "/auth/pin" not in TestClient(app_e).get("/auth/login").text
        and _pin(TestClient(app_e), PIN, username="ohnelogin").status_code == 404)

# ── (f) N2: strikte Kette password → pin — der Gästeweg ist zu, kein Orakel ohne Passwort ─────────
auth_f, app_f, _ = _app(login_chain=["password", "pin"])
_konto(auth_f, "orakel")
_falsch_f = _pin(TestClient(app_f), "0000", username="orakel")
_richtig_f = _pin(TestClient(app_f), PIN, username="orakel")
_zeilen_f = auth_f.store._one("SELECT COUNT(*) AS n FROM login_attempt")["n"]
# (Mutationsprobe: in `login_pin` wieder `cfg.pin_login` statt `pin_as_first_factor()` → 401/303 → rot.)
r.check("(f) N2: Gast-PIN ohne Passwort → 404, ob falsch oder richtig, und keine Zeile in login_attempt",
        _falsch_f.status_code == 404 and _richtig_f.status_code == 404 and _zeilen_f == 0,
        f"falsch {_falsch_f.status_code}, richtig {_richtig_f.status_code}, Zeilen {_zeilen_f}")
_login_f = TestClient(app_f).get("/auth/login").text
_get_f = TestClient(app_f).get("/auth/pin", headers=HTML, follow_redirects=False)
# (Mutationsprobe: `enabled_methods` wieder mit `pin_login` → PIN-Feld auf der Login-Seite → rot.)
r.check("(f) N2: die Login-Seite hat kein PIN-Feld, GET /auth/pin leitet Gäste zur Anmeldung",
        "/auth/pin" not in _login_f and "name=password" in _login_f and _get_f.status_code == 303
        and _get_f.headers.get("location", "").startswith("/auth/login"), f"GET {_get_f.status_code}")
auth_f2, app_f2, _ = _app(login_chain=["pin", "password"])
_konto(auth_f2, "vorne")
cf2 = TestClient(app_f2)
_erst = _pin(cf2, PIN, username="vorne")
_dann = _passwort(cf2, "vorne")
r.check("(f) Kette pin → password (strikt): der Gästeweg bleibt offen, die PIN ist dort Erstfaktor",
        "/auth/pin" in TestClient(app_f2).get("/auth/login").text and _erst.status_code == 303
        and _dann.headers.get("location") == "/drin" and cf2.get("/drin").status_code == 200,
        f"PIN {_erst.status_code}, Passwort {_dann.headers.get('location')}")
auth_f3, app_f3, _ = _app(login_chain=["password", "pin"], login_chain_strict=False)
_konto(auth_f3, "locker")
r.check("(f) nicht strikt (password, pin): die PIN bleibt mit pin_login Erstfaktor (Konfigprüfung warnt)",
        "/auth/pin" in TestClient(app_f3).get("/auth/login").text
        and _pin(TestClient(app_f3), PIN, username="locker").status_code == 303)

# ── (h) Identitätswechsel: halbe Sitzung A, Formular nennt B ──────────────────────────────────────
auth_h, app_h, _ = _app(login_chain=["password", "pin"], login_chain_strict=False)
_konto(auth_h, "anna")
uid_hb = _konto(auth_h, "bert")
ch = TestClient(app_h)
_passwort(ch, "anna")
_halb_a = ch.cookies.get(auth_h.cfg.session_cookie)
_fehl_h = _pin(ch, "0000", username="bert")
_wechsel = _pin(ch, PIN, username="bert")
_neu = auth_h.store.get_session(ch.cookies.get(auth_h.cfg.session_cookie))
r.check("(h) Gästetür offen: die PIN von B mit halber Sitzung A ist ein Identitätswechsel (neue Sitzung B, "
        "Fehlgriffe als Erstfaktor gebucht)",
        _fehl_h.status_code == 401 and _wechsel.status_code == 303
        and ch.cookies.get(auth_h.cfg.session_cookie) != _halb_a
        and _neu is not None and _neu["user_id"] == uid_hb and _arten(auth_h, "bert") == {"pin": 1}
        and _arten(auth_h, "anna") == {}, f"HTTP {_fehl_h.status_code}/{_wechsel.status_code}, "
        f"{dict(_neu) if _neu else None}, {_arten(auth_h, 'bert')}, {_arten(auth_h, 'anna')}")
auth_h2, app_h2, _ = _app(login_chain=["password", "pin"])
uid_ha2 = _konto(auth_h2, "anna")
_konto(auth_h2, "bert")
ch2 = TestClient(app_h2)
_passwort(ch2, "anna")
_halb_a2 = ch2.cookies.get(auth_h2.cfg.session_cookie)
_zu = _pin(ch2, PIN, username="bert")
_s_h2 = auth_h2.store.get_session(_halb_a2)
r.check("(h) Gästetür zu (strikte Kette): 404, die halbe Sitzung A bleibt, wie sie war",
        _zu.status_code == 404 and ch2.cookies.get(auth_h2.cfg.session_cookie) == _halb_a2
        and _s_h2 is not None and _s_h2["user_id"] == uid_ha2 and not _s_h2["mfa_ok"],
        f"HTTP {_zu.status_code}")

# ── (i) Konfigurationsprüfung: Warnung genau bei nicht strikt + PIN hinten + pin_login ─────────────
def _warnt(**cfg):
    _, warnungen = konfigpruefung.pruefe(TinySesamConfig(db_path=":memory:", **{"pin_enabled": True, **cfg}))
    return any("Folgefaktor" in w and "pin_login=False" in w for w in warnungen)


_faelle = {
    "nicht strikt, password → pin, pin_login": (dict(login_chain=["password", "pin"], login_chain_strict=False), True),
    "strikt, password → pin": (dict(login_chain=["password", "pin"]), False),
    "nicht strikt, pin_login=False": (dict(login_chain=["password", "pin"], login_chain_strict=False,
                                           pin_login=False), False),
    "nicht strikt, pin vorne": (dict(login_chain=["pin", "password"], login_chain_strict=False), False),
    "ohne Kette": (dict(), False),
    "nicht strikt, PIN aus": (dict(login_chain=["password", "pin"], login_chain_strict=False,
                                   pin_enabled=False), False),
}
_ist = {name: _warnt(**cfg) for name, (cfg, _) in _faelle.items()}
r.check("(i) die Konfigurationsprüfung warnt genau bei nicht strikter Kette mit PIN hinten und pin_login",
        all(_ist[name] is soll for name, (_, soll) in _faelle.items()), str(_ist))

# ── (j) p2 F1: die halbe Sitzung prüft die PIN nur, wenn sie ihr Kettenschritt ist ────────────────
# Bis 2026-09-27 genügte jede halbe Sitzung. Im klassischen Modus mit pin_login=False war das ein
# Orakel für jeden mit dem Passwort (auf 0.20.x: 404); in einer strikten Kette password → totp → pin
# stand die PIN vor dem TOTP in der Sitzung, die danach nie mehr voll wurde.
import time as _zeit  # noqa: E402

import pyotp as _pyotp  # noqa: E402


def _mit_totp(auth, name):
    uid = _konto(auth, name)
    geheim = auth.totp_begin(uid)["secret"]
    auth.totp_confirm(uid, _pyotp.TOTP(geheim).at(_zeit.time() - 30))
    return uid, geheim


def _pin_zeilen(auth):
    return auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE method='pin'")["n"]


auth_j, app_j, _ = _app(pin_login=False)
_mit_totp(auth_j, "klassik")
cj = TestClient(app_j)
_start_j = _passwort(cj, "klassik")
_falsch_j, _richtig_j = _pin(cj, "0000"), _pin(cj, PIN)
_get_j = cj.get("/auth/pin?next=/drin", headers=HTML, follow_redirects=False)
# (Mutationsprobe: in `login_pin` wieder `self.pending_user(request)` → 401/303 → rot.)
r.check("(j) Fall 1 klassisch, pin_login=False, Konto mit TOTP: die halbe Sitzung (nächster Schritt TOTP) "
        "bekommt auf falsche und richtige PIN 404, ohne Zeile in Serie und login_attempt",
        _start_j.headers.get("location", "").startswith("/auth/totp")
        and _falsch_j.status_code == 404 and _richtig_j.status_code == 404
        and FOLGE not in _arten(auth_j, "klassik") and _pin_zeilen(auth_j) == 0,
        f"falsch {_falsch_j.status_code}, richtig {_richtig_j.status_code}, {_arten(auth_j, 'klassik')}, "
        f"Zeilen {_pin_zeilen(auth_j)}")
# (Mutationsprobe: in `pin_page` wieder `self.pending_user(request)` → 200 mit PIN-Formular → rot.)
r.check("(j) Fall 1: GET /auth/pin zeigt der halben Sitzung kein PIN-Formular, sondern leitet zur Anmeldung",
        _get_j.status_code == 303 and _get_j.headers.get("location", "").startswith("/auth/login"),
        f"GET {_get_j.status_code} {_get_j.headers.get('location')}")

auth_j2, app_j2, _ = _app(login_chain=["password", "totp", "pin"])
_, _geheim_j2 = _mit_totp(auth_j2, "strikt")
cj2 = TestClient(app_j2)
_passwort(cj2, "strikt")
_vor_totp = (_pin(cj2, "0000").status_code, _pin(cj2, PIN).status_code)
_zeilen_vor = _pin_zeilen(auth_j2)
_nach_totp = cj2.post("/auth/totp", data={"code": _pyotp.TOTP(_geheim_j2).now(), "next": "/drin"},
                      follow_redirects=False)
_pin_j2 = _pin(cj2, PIN)
# (Mutationsprobe: in `_pin_kettenschritt` die Bedingung „nächster Schritt" streichen → 401/303 vor
#  dem TOTP, danach /drin 401 → rot.)
r.check("(j) Fall 2 strikt password → totp → pin: vor dem TOTP 404 (falsch wie richtig, keine Zeile); "
        "nach dem TOTP macht die PIN die Sitzung voll (/drin 200)",
        _vor_totp == (404, 404) and _zeilen_vor == 0
        and _nach_totp.headers.get("location", "").startswith("/auth/pin")
        and _pin_j2.status_code == 303 and _pin_j2.headers.get("location") == "/drin"
        and cj2.get("/drin").status_code == 200,
        f"vor TOTP {_vor_totp}, Zeilen {_zeilen_vor}, TOTP → {_nach_totp.headers.get('location')}, "
        f"PIN {_pin_j2.status_code} {_pin_j2.headers.get('location')}")
_zweit_j2 = _pin(cj2, "0000")
r.check("(j) … und mit voller Sitzung ist /auth/pin wieder der Route-Faktor (kein 404)",
        _zweit_j2.status_code == 401, f"HTTP {_zweit_j2.status_code}")

auth_j3, app_j3, _ = _app(login_chain=["password", "totp", "pin"], login_chain_strict=False, pin_login=False)
_, _geheim_j3 = _mit_totp(auth_j3, "locker")
cj3 = TestClient(app_j3)
_passwort(cj3, "locker")
_pin_j3 = _pin(cj3, PIN)
_totp_j3 = cj3.post("/auth/totp", data={"code": _pyotp.TOTP(_geheim_j3).now(), "next": "/drin"},
                    follow_redirects=False)
# (Mutationsprobe: `strict` in `_pin_kettenschritt` nicht beachten → 404 → rot.)
r.check("(j) nicht strikt password → totp → pin: die PIN vor dem TOTP bleibt erlaubt, danach ist die Sitzung voll",
        _pin_j3.status_code == 303 and _pin_j3.headers.get("location", "").startswith("/auth/totp")
        and _totp_j3.headers.get("location") == "/drin" and cj3.get("/drin").status_code == 200,
        f"PIN {_pin_j3.status_code} {_pin_j3.headers.get('location')}, TOTP {_totp_j3.headers.get('location')}")
_doppelt = TestClient(app_j3)
_passwort(_doppelt, "locker")
_pin(_doppelt, PIN)
_wieder = _pin(_doppelt, "0000")
# (Mutationsprobe: `"pin" in done` in `_pin_kettenschritt` streichen → 401 → rot.)
r.check("(j) nicht strikt: ist die PIN der halben Sitzung schon erbracht, prüft /auth/pin keine weitere (404)",
        _wieder.status_code == 404, f"HTTP {_wieder.status_code}")

# ── Die Konto-Seite behält ihre PIN-Sektion, wo die Login-Seite die PIN nicht mehr anbietet ────────
auth_k, app_k, _ = _app(login_chain=["password", "pin"])
_konto(auth_k, "konto")
ck = TestClient(app_k)
_passwort(ck, "konto")
_pin(ck, PIN)
auth_k2, app_k2, _ = _app(login_chain=["password", "pin"], pin_login=False)
_konto(auth_k2, "konto")
ck2 = TestClient(app_k2)
_passwort(ck2, "konto")
_pin(ck2, PIN)
auth_k3, app_k3, _ = _app(pin_login=False)
_konto(auth_k3, "konto")
ck3 = TestClient(app_k3)
_passwort(ck3, "konto")
# (Mutationsprobe: in `account_page` wieder `methods=cfg.enabled_methods()` → erste Prüfung rot.)
r.check("Konto-Seite: PIN-Sektion unter strikter Kette password → pin (auch mit pin_login=False), "
        "ohne Kette mit pin_login=False weiter nicht",
        "data-act=setpin" in ck.get("/auth/account").text and "data-act=setpin" in ck2.get("/auth/account").text
        and "data-act=setpin" not in ck3.get("/auth/account").text)

# ── Sperrhinweis: die Mail nennt bei der Serie auch den Betreiber ────────────────────────────────
auth_m, app_m, post_m = _app()
auth_m.create_user("hinweis", password=PW, email="hinweis@example.com")
for _ in range(10):
    _passwort(TestClient(app_m), "hinweis", "falsch-falsch-1")
_passwort(TestClient(app_m), "hinweis")
auth_m._hinweis_ausgang.abwarten()
_text_m = post_m[0][2] if post_m else ""
r.check("Sperrhinweis bei der Serie: „bis du dein Passwort zurücksetzt oder der Betreiber sie freigibt“",
        "oder der Betreiber sie freigibt" in _text_m, _text_m[:200])

# ── Prüfrunde 2026-09-27: der Ausweg aus der Serie je nach Art ──────────────────────────────────
# Der Selbstbedienungs-Reset räumt TOTP und die PIN im Kettenschritt nicht (G7). Stand die Serie
# allein aus solchen Fehlgriffen an der Grenze, nannten Sperrhinweis und Sicherheits-Log trotzdem den
# Reset als Ausweg — der Inhaber setzte sein Passwort zurück und blieb gesperrt. Die Anmeldeseite
# zeigt jedem denselben Text: Er darf nicht verraten, dass unter einer Kennung jemand am zweiten
# Faktor rät (und es das Konto also gibt).
import logging as _logging  # noqa: E402

from tinysesam.security import seclog as _seclog  # noqa: E402


class _Log:
    def __enter__(self):
        self.puffer = io.StringIO()
        self.haken = _logging.StreamHandler(self.puffer)
        _seclog.addHandler(self.haken)
        return self

    def __exit__(self, *_):
        _seclog.removeHandler(self.haken)

    def gesperrt(self):
        return [z for z in self.puffer.getvalue().splitlines() if "gesperrt:" in z]


def _serie_ausweg(art):
    """(Seite der nächsten Anmeldung, Sperrhinweis, Log-Zeile) nach einer Serie der Art `art`."""
    kette = ["password", "pin"] if art == FOLGE else None
    auth_x, app_x, post_x = _app(**({"login_chain": kette} if kette else {}))
    uid_x = _konto(auth_x, "ausweg")
    name = auth_x.get_user(uid_x)["username"]
    with _Log() as log_x:
        if art == "password":
            for _ in range(10):
                _passwort(TestClient(app_x), name, "falsch-falsch-1")
        elif art == "totp":
            geheim = auth_x.totp_begin(uid_x)["secret"]
            auth_x.totp_confirm(uid_x, _pyotp.TOTP(geheim).at(_zeit.time() - 30))
            cx = TestClient(app_x)
            _passwort(cx, name)
            for i in range(10):
                cx.post("/auth/totp", data={"code": f"00000{i}", "next": "/drin"}, follow_redirects=False)
        else:
            cx = TestClient(app_x)
            _passwort(cx, name)
            for i in range(10):
                _pin(cx, f"000{i}")
        seite = _passwort(TestClient(app_x), name)
        auth_x._hinweis_ausgang.abwarten()
    return seite, (post_x[0][2] if post_x else ""), (log_x.gesperrt() or [""])[0], _arten(auth_x, name)


_aus = {art: _serie_ausweg(art) for art in ("password", "totp", FOLGE)}
_reset_de = "bis du dein Passwort zurücksetzt"
# (Mutationsprobe: `_serie_reset_hilft` immer True → TOTP/pin_folge nennen den Reset → rot.)
r.check("Sperrhinweis: bei einer Serie aus TOTP bzw. PIN im Kettenschritt kein Reset als Ausweg, "
        "sondern der Betreiber — bei einer Passwort-Serie weiter der Reset",
        _reset_de in _aus["password"][1] and all(
            _reset_de not in _aus[a][1] and "bis der Betreiber sie freigibt" in _aus[a][1]
            and "Passwort-Reset hebt diese Sperre nicht auf" in _aus[a][1] for a in ("totp", FOLGE)),
        str({a: (v[3], v[1][:160]) for a, v in _aus.items()}))
r.check("Sicherheits-Log: „Aufheben: Passwort-Reset, …“ nur bei einer Passwort-Serie",
        "Aufheben: Passwort-Reset," in _aus["password"][2]
        and all(_aus[a][2] and "Aufheben: Passwort-Reset" not in _aus[a][2] and "tinysesam unlock" in _aus[a][2]
                for a in ("totp", FOLGE)), str({a: v[2][-160:] for a, v in _aus.items()}))
# (Mutationsprobe: `err.locked_serie` wieder „Passwort zurücksetzen oder den Betreiber …“ → rot.)
r.check("Anmeldeseite: für jede Art derselbe Text (kein Orakel), er nennt den Betreiber zuerst und den "
        "Reset nur bedingt — deutsch und englisch",
        all(v[0].status_code == 429 for v in _aus.values())
        and len({auth_m.t("err.locked_serie") in v[0].text for v in _aus.values()}) == 1
        and auth_m.t("err.locked_serie") in _aus["totp"][0].text
        and auth_m.t("err.locked_serie").startswith("Zu viele Fehlversuche in Folge — die Anmeldung ist gesperrt. "
                                                    "Den Betreiber um Freigabe bitten")
        and "Ask the operator to unlock it; if the failed attempts were password attempts"
        in TinySesam(TinySesamConfig(db_path=":memory:", lang="en")).t("err.locked_serie"),
        str([v[0].status_code for v in _aus.values()]))

sys.exit(r.done())
