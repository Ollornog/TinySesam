"""The secure login block for custom pages (0.22.0): `login_password`, `login_pin`, `login_totp`.

PO finding 2026-09-26: the README showed `check_password` +
`start_session` as building blocks under "Your own login page". The inner verifiers do not throttle — lock, failed-attempt counter,
series, IP throttle and the lines for fail2ban existed only in the built-in routes. A custom
route following the pattern let passwords be guessed as fast as the server answers.

Now the public way is a block that throttles, counts and locks by itself — and the
built-in routes call the SAME one (one source, no drift). Two things are therefore measured:
that a custom login page is protected via the block, and that it behaves line for line
like the built-in route.

The names are English (PO decision 2026-09-27, renamed before the release, without alias): (k)
asserts that no German word is on the tier-A surface of the block and that each
of its names carries tier A.

  (a) custom login page: lock after N failed attempts, IP throttle, series
  (b) LDAP via the block: fallback, outage (503, rollback resp. failed attempt), one identifier, one account
  (c) equality with the built-in route: status, audit, security-log and counter rows
  (d) PIN: guest path, chain step (own series kind), switched off
  (e) TOTP: second step, one-time code, without session, lock
  (f) CSRF, fail-closed, the result type
  (g) the unexpected in the check counts immediately as a failed attempt
  (h) one source: the three routes call the block and no inner verifier
  (i) the README example is itself protected
  (j) test fakes: ineffective and loud on the old name, effective on the new one
  (k) the names: English, each one in tier A
"""
from __future__ import annotations

import ast
import dataclasses
import inspect
import io
import json
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

from tinysesam import LoginResult, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.ldap_ import VerzeichnisNichtErreichbar  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("The secure sign-in building block for custom pages (login_password/_pin/_totp, 0.22.0)")
PW = "Anmelde-Pw-2026"          # 15 characters: the password signs in alone (B2-4)
PIN = "4711"
IP = ("203.0.113.9", 50000)
LOCKER = {"max_login_attempts": 1000, "rate_limit_max": 100000,
          "account_max_consecutive_failures": 100000, "pin_max_attempts": 100}


def _app(haertung=None, **cfg):
    """TinySesam with built-in routes AND custom routes that only call the block."""
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
        # The README pattern: on failure the custom form (JSON here) with the status of the
        # built-in page, on success the redirect with cookie.
        if not erg:
            return JSONResponse({"reason": erg.reason, "message": erg.message, "next_url": erg.next_url,
                                 "next_factor": erg.next_factor}, status_code=erg.status)
        return erg.redirect()

    @app.post("/eigen/login")
    def _eigen_login(request: Request, username: str = Form(""), password: str = Form(""),
                     next: str = Form(""), csrf: str = Form("", alias="_csrf"), bleiben: str = Form("")):
        return antwort(auth.login_password(request, username, password, next=next, csrf=csrf,
                                              remember=True if bleiben else None))

    @app.post("/eigen/pin")
    def _eigen_pin(request: Request, pin: str = Form(""), username: str = Form(""),
                   next: str = Form(""), csrf: str = Form("", alias="_csrf")):
        return antwort(auth.login_pin(request, pin, username, next=next, csrf=csrf))

    @app.post("/eigen/totp")
    def _eigen_totp(request: Request, code: str = Form(""), next: str = Form(""),
                    csrf: str = Form("", alias="_csrf")):
        return antwort(auth.login_totp(request, code, next=next, csrf=csrf))

    @app.post("/eigen/json")
    def _eigen_json(request: Request, daten: dict):
        # The JSON path: no `csrf` argument, the token comes in the X-CSRF-Token header.
        erg = auth.login_password(request, daten.get("username", ""), daten.get("password", ""))
        if not erg:
            raise HTTPException(erg.status, erg.message)
        antwort_ = JSONResponse({"next_url": erg.next_url, "done": erg.done, "next_factor": erg.next_factor})
        erg.set_cookie(antwort_)
        return antwort_

    @app.get("/drin")
    def _drin(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return auth, app


def _client(app, ip=IP):
    return TestClient(app, client=ip)


def _post(client, pfad, **daten):
    return client.post(pfad, data={"next": "/drin", **daten}, follow_redirects=False)


def _reason(antwort):
    try:
        return antwort.json().get("reason")
    except ValueError:
        return None


def _sitzung(auth, antwort):
    return antwort.cookies.get(auth.session_cookie_name)


class Mitschnitt:
    """The security log in the format of the shipped file, without timestamp (like fail2ban)."""

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


# ── (a) Custom login page: lock, IP throttle, series ──────────────────────────────────────────
# Exactly the finding: a custom route via `check_password` would have said 401 five times here and on the
# sixth attempt — the correct password — opened a session. Via the block it locks
# after the limit, and even the correct password no longer gets through.
# (Mutation probe: switch off the rejection `if versuch is None:` in `login_password` → fourth
# response 401, the correct password 303 → red.)
auth, app = _app(haertung={"max_login_attempts": 3})
auth.create_user("alice", password=PW)
c = _client(app)
with Mitschnitt() as log_a:
    folge_a = [_post(c, "/eigen/login", username="alice", password=f"falsch-{i}") for i in range(5)]
    richtig_a = _post(c, "/eigen/login", username="alice", password=PW)
r.check("(a) custom login page: after 3 failed attempts 429 `locked` — no further guessing",
        [a.status_code for a in folge_a] == [401, 401, 401, 429, 429]
        and [_reason(a) for a in folge_a] == ["invalid"] * 3 + ["locked"] * 2
        and folge_a[3].json()["message"] == auth.t("err.locked"),
        f"{[a.status_code for a in folge_a]} {[_reason(a) for a in folge_a]}")
r.check("(a) … even the correct password then opens no session (429, no cookie)",
        richtig_a.status_code == 429 and _sitzung(auth, richtig_a) is None,
        f"HTTP {richtig_a.status_code}, Cookie {_sitzung(auth, richtig_a)!r}")
_f2b = _failregex()
_treffer_a = [m.group("host") for m in (_f2b.match(z) for z in log_a.zeilen()) if m]
r.check("(a) … and every failed attempt like every rejection is in the security log as a fail2ban line",
        _treffer_a.count(IP[0]) == 6 and len(log_a.zeilen("reason=lockout_user")) == 3,
        f"{len(_treffer_a)} Treffer: {log_a.zeilen()[:4]}")
r.check("(a) … and in the audit log (login_fail per attempt, with reason)",
        [e[0] for e in _audit(auth)].count("login_fail") == 3
        and all(e[3].startswith("password reason=") for e in _audit(auth) if e[0] == "login_fail"),
        str(_audit(auth)[-4:]))

# IP throttle: many accounts from one address — the block throttles per IP before it checks.
auth, app = _app(haertung={"rate_limit_max": 4})
auth.create_user("bob", password=PW)
c = _client(app, ("198.51.100.44", 1))
_drossel = [_post(c, "/eigen/login", username=f"konto{i}", password="egal-egal-1") for i in range(6)]
_anderes_netz = _post(_client(app, ("198.51.100.45", 1)), "/eigen/login", username="bob", password=PW)
r.check("(a) IP throttle: after rate_limit_max requests 429 `ratelimit` with the text of the throttle",
        [a.status_code for a in _drossel][-2:] == [429, 429] and _reason(_drossel[-1]) == "ratelimit"
        and _drossel[-1].json()["message"] == auth.t("err.rate"),
        f"{[(a.status_code, _reason(a)) for a in _drossel]}")
r.check("(a) … another address still signs in (counter-check: the throttle applies per IP)",
        _anderes_netz.status_code == 303 and _sitzung(auth, _anderes_netz), f"HTTP {_anderes_netz.status_code}")

# Series (B2-6): slow guessing under every window limit — after N failed attempts in a row it is closed.
auth, app = _app(haertung={"account_max_consecutive_failures": 10})
auth.create_user("carol", password=PW)
_serie_folge = []
with Mitschnitt() as log_s:
    for i in range(11):    # every request from a different address: no window applies
        _serie_folge.append(_post(_client(app, (f"192.0.2.{10 + i}", 1)), "/eigen/login",
                                  username="carol", password=f"falsch-{i}"))
    _serie_richtig = _post(_client(app, ("192.0.2.99", 1)), "/eigen/login", username="carol", password=PW)
r.check("(a) series: after 10 failed attempts in a row 429 `locked_series` with the text of the series lock",
        [a.status_code for a in _serie_folge] == [401] * 10 + [429]
        and _reason(_serie_folge[-1]) == "locked_series"
        and _serie_folge[-1].json()["message"] == auth.t("err.locked_serie"),
        f"{[(a.status_code, _reason(a)) for a in _serie_folge]}")
r.check("(a) … it does not expire: even the correct password from a new address stays out",
        _serie_richtig.status_code == 429 and _reason(_serie_richtig) == "locked_series",
        f"HTTP {_serie_richtig.status_code}")
r.check("(a) … audit `lockout_series` and the log line for the operator",
        any(e[0] == "lockout_series" for e in _audit(auth))
        and log_s.zeilen("Sign-in for user=carol locked: 10 failed attempts in a row"),
        f"{[e[0] for e in _audit(auth)]} {log_s.zeilen('locked')[:2]}")

# Success: redirect with cookie, result complete, the cookie carries a full session.
auth, app = _app()
auth.create_user("dora", password=PW)
c = _client(app)
_ok = _post(c, "/eigen/login", username="dora", password=PW)
r.check("(a) success: 303 to next, session cookie set, the session carries /drin",
        _ok.status_code == 303 and _ok.headers["location"] == "/drin" and _sitzung(auth, _ok)
        and c.get("/drin").json() == {"u": "dora"},
        f"HTTP {_ok.status_code} {_ok.headers.get('location')}")
# “Stay signed in” (F-05): without `remember` a session cookie (ends with the browser), with
# `remember=True` a persistent one — like the checkbox of the built-in page.
_kurz = _post(_client(app, ("203.0.113.20", 1)), "/eigen/login", username="dora", password=PW)
_lang = _post(_client(app, ("203.0.113.21", 1)), "/eigen/login", username="dora", password=PW, bleiben="1")


def _max_age(antwort):
    return [z for z in antwort.headers.get_list("set-cookie")
            if z.startswith(auth.session_cookie_name + "=") and "Max-Age=" in z]


r.check("(a) remember: without the checkbox no Max-Age on the session cookie, with remember=True one",
        _kurz.status_code == _lang.status_code == 303 and not _max_age(_kurz) and _max_age(_lang),
        f"{_kurz.headers.get_list('set-cookie')} | {_lang.headers.get_list('set-cookie')}")


# ── (b) LDAP via the block ────────────────────────────────────────────────────────────────────
class Verzeichnis:
    """Dummy of the LDAP client after the bind; `weg=True` reports an outage."""

    def __init__(self, eintraege, weg=False):
        self.eintraege, self.weg, self.fragen = eintraege, weg, 0

    def authenticate(self, username, password):
        self.fragen += 1
        if self.weg:
            raise VerzeichnisNichtErreichbar("LDAP directory ldap://dummy unusable: Test")
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
r.check("(b) LDAP fallback via the block: account from the directory, session, audit `login_ldap`",
        _l_ok.status_code == 303 and _l_uid and auth.store.get_federated_user("ldap", "uuid-lena") == _l_uid
        and any(e[0] == "login_ldap" and e[1] == "lena" for e in _audit(auth)),
        f"HTTP {_l_ok.status_code}, {[e[0] for e in _audit(auth)]}")
_l_falsch = _post(c, "/eigen/login", username="lena", password="falsch-falsch-1")
r.check("(b) … rejected: 401 `invalid`, login_fail with source=local+ldap (both asked)",
        _l_falsch.status_code == 401 and _reason(_l_falsch) == "invalid"
        and any(e[0] == "login_fail" and "source=local+ldap" in (e[3] or "") for e in _audit(auth)),
        f"HTTP {_l_falsch.status_code}")

# Outage: without a local password the pre-booking is rolled back, with a local one the failed attempt counts.
auth, app = _app(**LDAP)
auth.create_user("notfall", password=PW)
auth.create_user("verz")                                   # directory account without local password
auth.ldap = Verzeichnis({}, weg=True)
c = _client(app)
with Mitschnitt() as log_b:
    _weg_verz = _post(c, "/eigen/login", username="verz", password="egal-egal-1")
    _weg_lokal = _post(c, "/eigen/login", username="notfall", password="falsch-falsch-1")
    _z = {u: [v for v in _versuche(auth) if v[0] == u] for u in ("verz", "notfall")}
    _weg_richtig = _post(c, "/eigen/login", username="notfall", password=PW)
r.check("(b) directory gone: 503 `directory_down` with the text of the outage",
        _weg_verz.status_code == 503 and _reason(_weg_verz) == "directory_down"
        and _weg_verz.json()["message"] == auth.t("err.directory_down"),
        f"HTTP {_weg_verz.status_code} {_reason(_weg_verz)}")
r.check("(b) … without a local password it is no failed attempt: pre-booking rolled back, no `failed login`",
        _z["verz"] == [] and not [z for z in log_b.zeilen("failed login") if "user=verz" in z]
        and log_b.zeilen("LDAP unreachable user=verz"),
        f"{_z['verz']} {log_b.zeilen()[:3]}")
r.check("(b) … with a wrong local password it counts (A-1), the local emergency account signs in",
        [v[2:] for v in _z["notfall"]] == [(0, "password", 0)] and _weg_lokal.status_code == 503
        and any(e[0] == "login_fail" and e[1] == "notfall" and "source=local" in (e[3] or "")
                for e in _audit(auth))
        and _weg_richtig.status_code == 303 and _sitzung(auth, _weg_richtig),
        f"{_z['notfall']} {_weg_lokal.status_code} {_weg_richtig.status_code}")

# One identifier, one account (review round 2026-09-27): Mallory is called `alice.neu` locally, Alice in the
# directory too — her LDAP password opens nothing under this identifier via the block.
auth, app = _app(**LDAP)
auth.ldap = Verzeichnis({"alice": {"pw": LPW, "id": "uuid-alice"}})
_post(_client(app), "/eigen/login", username="alice", password=LPW)
_alice = auth.store.get_user_by_name("alice")["id"]
auth.create_user("alice.neu", password="Mallory-Pw-15xy")
auth.ldap = Verzeichnis({"alice.neu": {"pw": LPW, "id": "uuid-alice"}})
_fremd = _post(_client(app), "/eigen/login", username="alice.neu", password=LPW)
r.check("(b) one identifier, one account: the LDAP password of another person opens no session under a locally "
        "assigned identifier (401), audit `ldap_identifier_rejected` names Alice's account "
        "as owner of the directory entry",
        _fremd.status_code == 401 and _sitzung(auth, _fremd) is None
        and any(e[0] == "ldap_identifier_rejected" and f"directory={_alice}" in (e[3] or "")
                for e in _audit(auth)),
        f"HTTP {_fremd.status_code}, {[(e[0], e[3]) for e in _audit(auth)][-3:]}")


# ── (c) Equality with the built-in route ──────────────────────────────────────────────────────
# The same sequence once via `POST /auth/login` (resp. /auth/pin, /auth/totp), once via the custom
# route — each in a fresh instance. Must be equal: status, redirect target, audit rows,
# security log, attempts and series table. This is the proof for "one source".
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
    r.check(f"(c) {name}: built-in and custom route — the same status, audit, log and counter rows",
            not abweichend and len(ein["audit"]) >= 3 and ein["log"],
            "; ".join(f"{k}: eingebaut {ein[k]} ≠ eigen {eigen[k]}" for k in abweichend)[:900]
            or f"zu wenig gemessen: {ein}")
    return ein


def _aufbau_pw():
    auth, app = _app(haertung={"max_login_attempts": 3})
    auth.create_user("erika", password=PW)
    auth.create_user("fritz", password=PW)
    return auth, app


_c_pw = _vergleich("Password (wrong, empty, correct, lockout, unknown name)", lambda a: [
    ("login", {"username": "erika", "password": "falsch-1"}),
    ("login", {"username": "erika", "password": ""}),
    ("login", {"username": "fritz", "password": PW}),
    ("login", {"username": "erika", "password": "falsch-2"}),
    ("login", {"username": "erika", "password": "falsch-3"}),
    ("login", {"username": "erika", "password": PW}),                # pair locked
    ("login", {"username": "niemand", "password": "falsch-4"}),
], _aufbau_pw)
r.check("(c) … the sequence saw lock and success (otherwise it compared little)",
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


_c_ldap = _vergleich("LDAP (fallback, rejected, outage with and without local password)", _ldap_folge,
                     _aufbau_ldap)
r.check("(c) … LDAP sequence: 303, 401, 503, 503, 303",
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
r.check("(c) … PIN sequence: 401, 400, 401, 401, 429", [s for s, _ in _c_pin["status"]] == [401, 400, 401, 401, 429],
        str(_c_pin["status"]))


# ── (d) PIN via the block ─────────────────────────────────────────────────────────────────────
auth, app = _app(pin_enabled=True, pin_login=True)
uid = auth.create_user("hanna", password=PW)
auth.set_pin(uid, PIN)
c = _client(app)
_p_falsch = _post(c, "/eigen/pin", username="hanna", pin="0000")
_p_ok = _post(c, "/eigen/pin", username="hanna", pin=PIN)
r.check("(d) guest path: wrong PIN 401 `invalid` (next_factor None), correct PIN 303 with session",
        _p_falsch.status_code == 401 and _reason(_p_falsch) == "invalid" and _p_falsch.json()["next_factor"] is None
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
r.check("(d) chain step: after the password `next_url` leads to /auth/pin, /drin still closed",
        _k1.status_code == 303 and _k1.headers["location"].startswith("/auth/pin")
        and _k_drin.status_code != 200,
        f"{_k1.status_code} {_k1.headers.get('location')}")
r.check("(d) … wrong PIN in the chain step: 401, `next_factor` stays \"pin\", series under its own kind",
        _k_falsch.status_code == 401 and _k_falsch.json()["next_factor"] == "pin"
        and _k_serie == [(TinySesam._PIN_CHAIN_SERIES, 1)],
        f"{_k_falsch.status_code} {_k_falsch.text[:120]} {_k_serie}")
r.check("(d) … the built-in route then shows the PIN page again: without name field, with the account "
        "of the session (401)",
        _k_seite.status_code == 401 and "name=pin " in _k_seite.text and "name=username" not in _k_seite.text
        and auth.t("reauth.hint", user="ines") in _k_seite.text, _k_seite.text[:200])
r.check("(d) … correct PIN without name field: 303, full session",
        _k_ok.status_code == 303 and c.get("/drin").json() == {"u": "ines"}, f"{_k_ok.status_code}")
r.check("(d) … without a session the PIN is no first factor here: 404 `method_disabled`",
        _gast.status_code == 404 and _reason(_gast) == "method_disabled", f"{_gast.status_code} {_gast.text[:80]}")

# Without `pin_enabled` the route does not exist — the block says the same, even if a PIN hash
# from earlier is still in the database, and also on a full session.
# (Mutation probe: delete `not cfg.pin_enabled or` in `login_pin` → the full session
# confirms the PIN → red.)
auth, app = _app(pin_enabled=False)
uid = auth.create_user("jan", password=PW)
auth.set_pin(uid, PIN)
c = _client(app)
_p_aus = _post(c, "/eigen/pin", username="jan", pin=PIN)
_post(c, "/eigen/login", username="jan", password=PW)
_p_aus_voll = _post(c, "/eigen/pin", pin=PIN)
r.check("(d) without pin_enabled: `method_disabled` (404) — as guest and on a full session, despite PIN hash",
        _p_aus.status_code == 404 and _reason(_p_aus) == "method_disabled"
        and _p_aus_voll.status_code == 404 and _reason(_p_aus_voll) == "method_disabled",
        f"{_p_aus.status_code} {_p_aus_voll.status_code}")


# ── (e) TOTP via the block ────────────────────────────────────────────────────────────────────
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
r.check("(e) password with TOTP: 303 to /auth/totp, half session (no /drin)",
        _t1.status_code == 303 and _t1.headers["location"].startswith("/auth/totp") and _halb,
        f"{_t1.status_code} {_t1.headers.get('location')}")
r.check("(e) … wrong code: 401 `invalid`, `next_factor` stays \"totp\", text of the code",
        _t_falsch.status_code == 401 and _t_falsch.json()["next_factor"] == "totp"
        and _t_falsch.json()["message"] == auth.t("err.code"), _t_falsch.text[:160])
r.check("(e) … correct code: new token (privilege change), session full, the half token dead",
        _t_ok.status_code == 303 and _t_ok.headers["location"] == "/drin"
        and _sitzung(auth, _t_ok) not in (None, _halb) and c.get("/drin").json() == {"u": "karl"}
        and auth.store.get_session(_halb) is None, f"{_t_ok.status_code}")

_j = _client(app, ("203.0.113.12", 1)).post("/eigen/json", json={"username": "karl", "password": PW})
r.check("(e) the result after the password names the open step: done False, next_factor \"totp\", "
        "next_url to /auth/totp",
        _j.status_code == 200 and _j.json()["done"] is False and _j.json()["next_factor"] == "totp"
        and _j.json()["next_url"].startswith("/auth/totp"), _j.text[:200])

c2 = _client(app, ("203.0.113.10", 1))
_post(c2, "/eigen/login", username="karl", password=PW)
_rc = _post(c2, "/eigen/totp", code=codes[0])
r.check("(e) one-time code instead of TOTP: accepted, like /auth/totp", _rc.status_code == 303
        and c2.get("/drin").json() == {"u": "karl"}, f"{_rc.status_code}")

_ohne = _post(_client(app), "/eigen/totp", code="123456")
r.check("(e) without a session: 401 `no_session`, `next_url` is the login page",
        _ohne.status_code == 401 and _reason(_ohne) == "no_session"
        and _ohne.json()["next_url"] == "/auth/login", _ohne.text[:160])

c3 = _client(app, ("203.0.113.11", 1))
_post(c3, "/eigen/login", username="karl", password=PW)
_t_sperre = [_post(c3, "/eigen/totp", code=f"00000{i}") for i in range(4)]
r.check("(e) TOTP guessing: after 3 misses 429 `locked` with the text of the page (err.retry)",
        [a.status_code for a in _t_sperre] == [401, 401, 401, 429] and _reason(_t_sperre[-1]) == "locked"
        and _t_sperre[-1].json()["message"] == auth.t("err.retry"),
        f"{[(a.status_code, _reason(a)) for a in _t_sperre]}")


# The TOTP sequence needs the secret of its instance per run (each one rolls its own).
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
r.check("(c) … TOTP sequence: 303, 401, 400, 303", [s for s, _ in _c_totp["status"]] == [303, 401, 400, 303],
        str(_c_totp["status"]))


# ── (f) CSRF, fail-closed, the result type ────────────────────────────────────────────────────
auth, app = _app(csrf_enabled=True)
auth.create_user("mia", password=PW)
c = _client(app)
c.get("/auth/login")                                          # sets the CSRF cookie
tok = c.cookies.get(auth.csrf_cookie_name)
_ohne_tok = _post(c, "/eigen/login", username="mia", password=PW)
_mit_tok = _post(c, "/eigen/login", username="mia", password=PW, _csrf=tok)
r.check("(f) CSRF like every sign-in route: without token 403, with token 303",
        _ohne_tok.status_code == 403 and _sitzung(auth, _ohne_tok) is None and _mit_tok.status_code == 303,
        f"{_ohne_tok.status_code} {_mit_tok.status_code}")
c = _client(app)
c.get("/auth/login")
tok = c.cookies.get(auth.csrf_cookie_name)
_json = c.post("/eigen/json", json={"username": "mia", "password": PW}, headers={"X-CSRF-Token": tok})
_json_ohne = _client(app).post("/eigen/json", json={"username": "mia", "password": PW})
# With a fresh token: after the sign-in above `set_cookie` rotated the CSRF token, an old
# token would be wrong anyway — then the probe would check nothing.
c_leer = _client(app)
c_leer.get("/auth/login")
_leer_arg = c_leer.post("/eigen/login", data={"username": "mia", "password": PW, "_csrf": ""},
                        headers={"X-CSRF-Token": c_leer.cookies.get(auth.csrf_cookie_name)},
                        follow_redirects=False)
r.check("(f) `csrf=None` takes the X-CSRF-Token header (JSON path), without it 403; an empty "
        "form field does NOT fall back to the header (like the form route)",
        _json.status_code == 200 and _json.json()["done"] is True and _sitzung(auth, _json)
        and _json_ohne.status_code == 403 and _leer_arg.status_code == 403,
        f"{_json.status_code} {_json_ohne.status_code} {_leer_arg.status_code}")

# Fail-closed: a failure carries no token — whoever "forwards" it anyway sets no cookie.
auth, app = _app()
auth.create_user("nora", password=PW)
_ergebnisse = {}


@app.post("/eigen/roh")
def _roh(request: Request, username: str = Form(""), password: str = Form("")):
    erg = auth.login_password(request, username, password, next="/drin")
    _ergebnisse[password] = erg
    return erg.redirect()                # the result ignored — the worst case


c = _client(app)
_ign = c.post("/eigen/roh", data={"username": "nora", "password": "falsch-1"}, follow_redirects=False)
_ign_ziel = c.get("/drin", headers={"Accept": "application/json"})
r.check("(f) fail-closed: whoever ignores the result and redirects ends up on /drin without a session (401)",
        _ign.status_code == 303 and "set-cookie" not in {k.lower() for k in _ign.headers}
        and _ign_ziel.status_code == 401, f"{_ign.status_code} {dict(_ign.headers)} {_ign_ziel.status_code}")
c.post("/eigen/roh", data={"username": "nora", "password": PW}, follow_redirects=False)
_erfolg = _ergebnisse[PW]
_felder = {f.name for f in dataclasses.fields(LoginResult)}
r.check("(f) result type: bool = ok, the token is no field and appears neither in repr() nor in asdict()",
        bool(_erfolg) and not bool(_ergebnisse["falsch-1"]) and _erfolg.done and _erfolg.user["username"] == "nora"
        and _ergebnisse["falsch-1"].user is None
        and _felder == {"ok", "reason", "status", "message", "next_url", "next_factor", "done", "user"}
        and _erfolg._token and _erfolg._token not in repr(_erfolg)
        and _erfolg._token not in repr(dataclasses.asdict(_erfolg)),
        repr(_erfolg)[:200])
try:
    _erfolg.ok = False                   # type: ignore[misc]
    _eingefroren = False
except dataclasses.FrozenInstanceError:
    _eingefroren = True
_falsch_gebaut = []
for kw in ({"ok": False, "reason": "erfunden", "status": 400}, {"ok": True, "reason": "invalid", "status": 303},
           {"ok": False, "reason": "ok", "status": 303}):
    try:
        LoginResult(**kw)
        _falsch_gebaut.append(kw)
    except ValueError:
        pass  # expected: the constructor rejects the combination
r.check("(f) … frozen, and a reason outside REASONS or an ok contradicting the reason raises",
        _eingefroren and not _falsch_gebaut, f"{_eingefroren} {_falsch_gebaut}")
_ersetzt = dataclasses.replace(_erfolg)
_antwort = JSONResponse({})
_ersetzt.set_cookie(_antwort)
r.check("(f) … a copy via dataclasses.replace carries no token (sets no cookie)",
        "set-cookie" not in {k.lower() for k in _antwort.headers}, str(dict(_antwort.headers)))
r.check("(f) every reason the block returns is in REASONS (also the measured ones)",
        {"ok", "missing", "invalid", "locked", "locked_series", "ratelimit", "directory_down", "method_disabled",
         "no_session"} == set(LoginResult.REASONS), str(LoginResult.REASONS))


# ── (g) The unexpected in the check counts immediately ────────────────────────────────────────
# An exception in the middle of the check (database gone, key missing) must not leave the pre-booked
# attempt open: it immediately becomes a failed attempt, its pre-booking in the series is also
# closed. Until 0.21.0 this held only for the password — since the block for all three steps.
# (Mutation probe: delete the `except BaseException` branch in `login_totp` resp. `login_pin` → red.)
def _kaputt(*_a, **_k):
    raise RuntimeError("check broken (test)")


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
    r.check(f"(g) {art}: exception in the check → 500, the attempt is closed as a failed attempt, "
            "no series pre-booking is left over",
            _k.status_code == 500 and _zeile and _zeile[-1][2:] == (0, art, 0) and not auth._serie_vorbuchungen,
            f"{_k.status_code} {_zeile} {auth._serie_vorbuchungen}")


# ── (h) One source: the routes call the block, no inner verifier ──────────────────────────────
# If the check were there twice — in the route and in the block —, it would drift apart, and the
# block would be the weaker path. The routes may call the block and render the result;
# every name of the bookkeeping is forbidden to them.
# (Mutation probe: call `auth._check_password(...)` again in `login_submit` → red.)
INNERE = {"_check_password", "_check_pin", "_check_ldap", "_verify_totp", "_verify_recovery_code",
          "_verify_user_pin", "_begin_attempt", "_versuch_gescheitert", "_versuch_zuruecknehmen",
          "_record_login", "_rate_ok", "_serie_voll", "apply_factor", "complete_totp", "set_cookie",
          "start_session", "_login_redirect_after", "_pin_kettenschritt"}
ROUTEN = {"login_submit": "login_password", "pin_submit": "login_pin", "totp_submit": "login_totp"}


def _routen_befunde(quelltext):
    befunde, gefunden = [], set()
    for fn in ast.walk(ast.parse(quelltext)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name not in ROUTEN:
            continue
        gefunden.add(fn.name)
        namen = {k.attr for k in ast.walk(fn) if isinstance(k, ast.Attribute)}
        if ROUTEN[fn.name] not in namen:
            befunde.append(f"{fn.name} does not call {ROUTEN[fn.name]}")
        befunde += [f"{fn.name} calls {n} itself" for n in sorted(namen & INNERE)]
    befunde += [f"{n} missing in the router" for n in sorted(set(ROUTEN) - gefunden)]
    return befunde


_router = (ROOT / "tinysesam" / "router.py").read_text(encoding="utf-8")
_selbst = {
    "sauber": ("def login_submit(r):\n    erg = auth.login_password(r, 'a', 'b')\n    return erg.redirect()\n"
               "def pin_submit(r):\n    return auth.login_pin(r, '1')\n"
               "def totp_submit(r):\n    return auth.login_totp(r, '1')\n", []),
    "doppelt": ("def login_submit(r):\n    auth._check_password('a', 'b')\n    return auth.login_password(r, 'a', 'b')\n"
                "def pin_submit(r):\n    return auth.login_pin(r, '1')\n"
                "def totp_submit(r):\n    return auth.login_totp(r, '1')\n", ["login_submit calls _check_password itself"]),
    "vorbei": ("def login_submit(r):\n    return auth._begin_attempt('a', 'b', 'password')\n"
               "def pin_submit(r):\n    return auth.login_pin(r, '1')\n", None),
}
for _probe, (_text, _erwartet) in _selbst.items():
    _b = _routen_befunde(_text)
    if _erwartet is None:
        assert any("does not call login_password" in x for x in _b) and any("totp_submit missing" in x for x in _b), _b
    else:
        assert _b == _erwartet, (_probe, _b)
_befunde_h = _routen_befunde(_router)
r.check("(h) one source: login_submit, pin_submit, totp_submit call their block and no "
        "inner verifier, no bookkeeping, no session creation themselves (AST, 3 self-probes)",
        not _befunde_h, "; ".join(_befunde_h))


# ── (i) The README example is itself protected ────────────────────────────────────────────────
# The finding came from the README. That is why its example runs here verbatim — with the default
# configuration (CSRF on, secure cookies, five failed attempts per pair): it must lock
# after the limit and sign in with the correct password. `test_repo.py` only executes the block.
# (Mutation probe: replace `auth.login_password(…)` in the README example with the old pattern
# `auth._check_password` + `start_session` → no 429 → red.)
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
    r.check(f"(i) {_datei}: the example “custom login route” locks after {_grenze} failed attempts (429), "
            "signs in from another address (303, cookie) and requires CSRF (403)",
            "login_password" in _quelle and _folge == [401] * _grenze + [429]
            and _gesperrt.status_code == 429 and _frei.status_code == 303
            and _frei.cookies.get(_auth.session_cookie_name) and _ohne_csrf.status_code == 403,
            f"{_folge} {_gesperrt.status_code} {_frei.status_code} {_ohne_csrf.status_code}")


# ── (j) Test fakes: ineffective on the old name, therefore loud ───────────────────────────────
# Finding of the counter-check 2026-09-27: `auth.check_password = fake` was called 0 times, the login
# gave 303 — and nobody warned. The routes call `_check_password` (via `login_password`).
# Since then the assignment warns (RuntimeWarning, `Deprecated.__set__`) and names the target; a fake
# on the new name works as one on the old name used to.
# (Mutation probe: delete `__set__`/`__delete__` in `tinysesam/_deprecated.py` → no warning → red.)
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
r.check("(j) fake on the old name (`auth.check_password = fake`): exactly one RuntimeWarning, "
        "it names `_check_password` and points to the assignment; the fake is never called (303, 303)",
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
r.check("(j) `mock.patch.object(auth, \"rate_ok\", …)`: warns (RuntimeWarning with `_rate_ok`), "
        "does not throttle (303, 0 calls) and cleans up on exit",
        [w.category for w in _w_mock] == [RuntimeWarning] and "`_rate_ok`" in str(_w_mock[0].message)
        and _s_mock == 303 and _m.call_count == 0 and not _nachher,
        f"{[w.category.__name__ for w in _w_mock]} {_s_mock} {_m.call_count} {_nachher}")

with warnings.catch_warnings(record=True) as _w_neu:
    warnings.simplefilter("always")
    auth._check_password = _fake
    _s_neu = _post(_client(app, ("203.0.113.11", 1)), "/auth/login", username="fritz",
                   password=PW).status_code
r.check("(j) the same fake on the new name (`auth._check_password = fake`) works: called, 401, "
        "no warning",
        _aufrufe and _s_neu == 401 and not _w_neu, f"{_aufrufe} {_s_neu} {[str(w.message) for w in _w_neu]}")

# ── (k) The names: English, each one in tier A ────────────────────────────────────────────────
# PO decision 2026-09-27: the block is named in English like the rest of the tier-A surface — renamed
# before the release, without alias (`anmelden_*`/`Anmeldung` were never published). So that no
# German word comes back (a new field, a new reason, a further step), the
# guard measures the surface on the live object instead of a list: every public method of
# `TinySesam` that returns a `LoginResult`, with its parameter names; name and module of the
# type, its fields, public methods and constants; the values of `REASONS`. Each name is
# split into words (`_`, `.` and CamelCase) and held against a short list of German words.
# In addition each of these names carries tier A in `tests/api_surface.json` — a name that silently
# slips into B would lose the 1.0 promise. Not meant: audit and log lines (`login_fail … reason=`,
# fail2ban) — they are no names of the block and stay as they are.
# Since the second PO decision of 2026-09-27 (the whole surface of tiers
# A and B English, without alias) the word list is the ONE from `tests/test_api_surface.py` (`deutsch_in`: whole
# words, stems also in the middle of a word, umlauts). There the guard measures the whole surface —
# names, parameters, configuration fields, attributes of the error types; what remains here is what only the
# block has: every method that returns a `LoginResult` (also one still without a tier), and the
# values of `REASONS`.
# (Mutation probes, each individually: append a reason "gesperrt" to `LoginResult.REASONS` → red;
# set `LoginResult.done` to tier "B" in `api_surface.json` → red; a method
# `anmelden_passkey(self, request) -> LoginResult` in `TinySesam` → red.)
from test_api_surface import deutsch_in  # noqa: E402


def _baustein(klasse, typ) -> tuple:
    """(methods, [(where, name)]) — the tier-A surface of the block, measured on the object."""
    methoden = sorted(n for n, f in vars(klasse).items()
                      if inspect.isfunction(f) and not n.startswith("_")
                      and inspect.signature(f).return_annotation in (typ, typ.__name__))
    namen = {("tinysesam", typ.__name__), ("Modul", typ.__module__)}
    for n in methoden:
        namen.add((klasse.__name__, n))
        namen |= {(f"{klasse.__name__}.{n}()", p) for p in inspect.signature(vars(klasse)[n]).parameters
                  if p != "self"}
    namen |= {(typ.__name__, f.name) for f in dataclasses.fields(typ)}
    namen |= {(typ.__name__, n) for n in vars(typ) if not n.startswith("_")}
    namen |= {(f"{typ.__name__}.REASONS", w) for w in getattr(typ, "REASONS", ())}
    return methoden, sorted(namen)


def _deutsch(namen) -> list:
    return [f"{wo}: {name!r} ({', '.join(sorted(deutsch_in(name)))})"
            for wo, name in namen if deutsch_in(name)]


def _stufe_befunde(methoden, typ, ablage) -> list:
    """Every name of the block is in the guard's store, and in tier A."""
    befunde = []
    oeffentlich = {f.name for f in dataclasses.fields(typ)} | {n for n in vars(typ) if not n.startswith("_")}
    for bereich, namen in (("TinySesam", methoden), ("exporte", [typ.__name__]),
                           (typ.__name__, sorted(oeffentlich))):
        for n in namen:
            stufe = ablage.get(bereich, {}).get(n, {}).get("stufe")
            if stufe != "A":
                befunde.append(f"{bereich}.{n}: Stufe {stufe!r} statt 'A'")
    return befunde


# Self-probes: a German field, a German reason, a German step, a parameter —
# each must stand out; an English twin must not. A list that finds nothing would look
# exactly like a clean surface.
@dataclasses.dataclass(frozen=True)
class ProbeErgebnis:
    ok: bool
    grund: str = ""
    locked_series: bool = False                   # “series” is not “serie” — whole words
    REASONS = ("ok", "gesperrt")


class ProbeKlasse:
    def anmelden_passkey(self, request, kennung) -> ProbeErgebnis:     # noqa: ARG002
        return ProbeErgebnis(ok=True)

    def login_other(self, request) -> ProbeErgebnis:                   # noqa: ARG002
        return ProbeErgebnis(ok=True)

    def hilfe_ohne_ergebnis(self, weiter):                            # no block: not measured
        return weiter


_p_methoden, _p_namen = _baustein(ProbeKlasse, ProbeErgebnis)
_p_funde = {name for wo, name in _p_namen if deutsch_in(name)}
assert _p_methoden == ["anmelden_passkey", "login_other"], _p_methoden
assert _p_funde == {"anmelden_passkey", "kennung", "grund", "gesperrt", "ProbeErgebnis"}, _p_funde
assert _stufe_befunde(["login_other"], ProbeErgebnis,
                      {"TinySesam": {"login_other": {"stufe": "B"}}}) [:1] == [
    "TinySesam.login_other: Stufe 'B' statt 'A'"], "tier B must stand out"

_methoden_k, _namen_k = _baustein(TinySesam, LoginResult)
_ablage_k = json.loads((ROOT / "tests" / "api_surface.json").read_text(encoding="utf-8"))
_deutsch_k = _deutsch(_namen_k)
_stufe_k = _stufe_befunde(_methoden_k, LoginResult, _ablage_k)
r.check(f"(k) the tier-A surface of the block is English: {len(_namen_k)} names "
        f"({', '.join(_methoden_k)}, `{LoginResult.__name__}` with fields, methods, reasons), "
        "no German word; every name in tier A (4 self-probes)",
        {"login_password", "login_pin", "login_totp"} <= set(_methoden_k) and len(_namen_k) >= 35
        and len(LoginResult.REASONS) >= 9 and not _deutsch_k and not _stufe_k,
        "; ".join(_deutsch_k + _stufe_k) or f"zu wenig gemessen: {_methoden_k} {len(_namen_k)}")


sys.exit(r.done())
