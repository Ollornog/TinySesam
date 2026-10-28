"""G7 — the position of the PIN: first factor or follow-up factor, measured by the path, not by the configuration.

The series of consecutive failed attempts (B2-6) counts per kind. A self-service reset clears the shares
of the first factors — password and PIN, which anyone can produce, even without a secret (R2-2) —,
TOTP slips remain: only whoever already has the password produces them. Until 2026-09-26 the kind was the
method, and a PIN BEHIND the password (chain `password → pin`) booked like a first factor. Whoever
had mailbox and password got a fresh series against the PIN with every reset.

Now a PIN behind an already provided factor (half session in the chain step, full session in
a route chain) books under `PIN_CHAIN_SERIES`. Plus two side findings on the same path:

  N1  `pin_login=False` with a chain `password → pin` was a dead end: the PIN step went via
      the guest path, and that is closed with `pin_login=False` (404).
  N2  In a strict chain `password → pin` a PIN entered first never satisfies the chain. The
      guest path only served guessers (wrong PIN 401, correct 303 — without password).

Since the review round 2026-09-27 (p2 F1) the half session applies only if the PIN is its chain step
(`_pin_kettenschritt`, block j), and the way out of the series depends on its kind (last block).
"""
from __future__ import annotations

import itertools as _itertools
import io
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
_FALSCH = _itertools.count()   # always NEW wrong passwords: a repetition has counted only once since 0.24.9

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import config_check  # noqa: E402
from tinysesam.__main__ import main as _cli  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("G7 — PIN als Erst- oder Folgefaktor (Serie, Kettenschritt, Gästeweg)")
PW = "Folge-Pin-Pw-15"          # 15 characters: the password may sign in on its own here (B2-4)
NEU = "Neues-Pw-G7-123"
PIN = "4711"
FOLGE = TinySesam._PIN_CHAIN_SERIES
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
        except SystemExit as e:        # otherwise the test would end here with exit 0 (skip is not green)
            code = e.code or 0
    return code


# ── (a) Chain step after the password: slips of kind pin_folge, the reset does not clear them ──
auth, app, _ = _app(login_chain=["password", "pin"], password_reset_enabled=True)
uid = _konto(auth, "kette")
c = TestClient(app)
_nach_pw = _passwort(c, "kette")
for i in range(5):
    _pin(c, f"000{i}")
r.check("(a) after the password the chain leads to /auth/pin; five wrong PINs in the chain step "
        "book under pin_folge, not under pin",
        _nach_pw.headers.get("location", "").startswith("/auth/pin") and _arten(auth, "kette") == {FOLGE: 5},
        f"{_nach_pw.headers.get('location')}, {_arten(auth, 'kette')}")
# (Mutation probe: omit `series_kind` in `login_pin` → {'pin': 5}, the reset clears → red.)
auth.lift_lockout(uid, methods=("password",))                  # the path of the self-service reset
r.check("(a) the self-service reset (lift_lockout with password) leaves them standing, like TOTP",
        auth.store.fehlserie("kette") == 5, str(_arten(auth, "kette")))
_tok = auth.create_magic_token("reset_password", user_id=uid, email="kette@example.com")
_reset = TestClient(app).post("/auth/reset", data={"token": _tok, "password": NEU}, follow_redirects=False)
r.check("(a) … also via the real POST /auth/reset",
        _reset.status_code == 303 and auth.store.fehlserie("kette") == 5 and auth._check_password("kette", NEU),
        f"HTTP {_reset.status_code}, {_arten(auth, 'kette')}")
# Custom PIN pages often send the name along — even with the address of the own account it remains the
# chain step of the half session (before: the guest path, booked as first factor).
c = TestClient(app)
_passwort(c, "kette", NEU)
_pin(c, "0009", username="kette@example.com")
_pin(c, "0008", username="kette")
r.check("(a) with name or address of the own account in the form it remains the chain step",
        _arten(auth, "kette") == {FOLGE: 7}, str(_arten(auth, "kette")))

# ── (b) R2-2 stays: a guest PIN (first factor) is cleared by the reset ─────────────────────────
auth_b, app_b, _ = _app()
uid_b = _konto(auth_b, "gast")
for i in range(5):
    _pin(TestClient(app_b), f"000{i}", username="gast")
_vorher_b = _arten(auth_b, "gast")
auth_b.lift_lockout(uid_b, methods=("password",))
# (Mutation probe: 'pin' from `_SERIE_RESET_ARTEN` → 5 remain → red.)
r.check("(b) R2-2: slips via the guest path book under pin, and the reset clears them",
        _vorher_b == {"pin": 5} and auth_b.store.fehlserie("gast") == 0,
        f"{_vorher_b} → {_arten(auth_b, 'gast')}")

# ── (c) full sign-in, panel reset and `tinysesam unlock` also clear pin_folge ─────────────────
auth_c, app_c, _ = _app(login_chain=["password", "pin"])
uid_c = _konto(auth_c, "voll")
cc = TestClient(app_c)
_passwort(cc, "voll")
for i in range(4):
    _pin(cc, f"000{i}")
_vorher_c = _arten(auth_c, "voll")
_fertig = _pin(cc, PIN)
# (Mutation probe: in `lift_lockout` without `methoden` clear only `_SERIE_RESET_ARTEN` → 4 → red.)
r.check("(c) the full sign-in (correct PIN in the chain step) ends the series completely",
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
# (Mutation probe: `_serie_beenden` clears only `_SERIE_RESET_ARTEN` → red.)
r.check("(c) the password reset in the panel clears pin_folge (the operator decides)",
        _panel.status_code == 200 and auth_c.store.fehlserie("voll") == 0,
        f"HTTP {_panel.status_code}, {_arten(auth_c, 'voll')}")
cv = TestClient(app_c)
_passwort(cv, "voll", NEU)
for i in range(4):
    _pin(cv, f"000{i}")
_vorher_u = auth_c.store.fehlserie("voll")
_rc = _unlock(auth_c, "voll")
# (Mutation probe: `unlock` clears the series only with `arten=("password", "pin")` → red.)
r.check("(c) `tinysesam unlock` clears pin_folge", _vorher_u == 4 and _rc == 0 and auth_c.store.fehlserie("voll") == 0,
        f"{_vorher_u}, rc {_rc}, {_arten(auth_c, 'voll')}")

# ── (d)+(g) Route chain with full session; a correct PIN withdraws only its own pre-booking ────
auth_d, app_d, _ = _app()                                          # klassisch: Passwort = volle Sitzung
uid_d = _konto(auth_d, "route")
cd = TestClient(app_d)
_passwort(cd, "route")
_umweg = cd.get("/pinbereich", headers=HTML, follow_redirects=False)
for i in range(3):
    _pin(cd, f"000{i}")
_nach_falsch = _arten(auth_d, "route")
_richtig = _pin(cd, PIN)
r.check("(d) route chain factors=[password, pin] with full session: the slips book under pin_folge",
        _umweg.headers.get("location", "").startswith("/auth/pin") and _nach_falsch == {FOLGE: 3},
        f"{_umweg.headers.get('location')}, {_nach_falsch}")
# (Mutation probe: the pre-booking remembers `method` instead of `serie[1]` → lowering hits the kind pin,
#  the pre-booking under pin_folge remains → 4 → red.)
r.check("(g) a correct PIN withdraws its pre-booking under pin_folge — the series before it remains",
        _richtig.status_code == 303 and cd.get("/pinbereich").status_code == 200
        and _arten(auth_d, "route") == {FOLGE: 3}, f"HTTP {_richtig.status_code}, {_arten(auth_d, 'route')}")

# ── (e) N1: pin_login=False with chain password → pin is no longer a dead end ────────────────
auth_e, app_e, _ = _app(login_chain=["password", "pin"], pin_login=False)
_konto(auth_e, "ohnelogin")
ce = TestClient(app_e)
_start = _passwort(ce, "ohnelogin")
_seite = ce.get("/auth/pin?next=/drin", headers=HTML, follow_redirects=False)
# (Mutation probe: in `pin_page` do not read the half session → 303 back to the sign-in → red.)
r.check("(e) N1: after the password GET /auth/pin shows the PIN form — without name field",
        _start.headers.get("location", "").startswith("/auth/pin") and _seite.status_code == 200
        and "name=pin" in _seite.text and "name=username" not in _seite.text,
        f"HTTP {_seite.status_code} {_seite.headers.get('location')}")
_ziel = _pin(ce, PIN)
# (Mutationsprobe: in `login_pin` `halb = None` → 404 → rot.)
r.check("(e) N1: … and the correct PIN makes the session full (/drin 200)",
        _ziel.status_code == 303 and _ziel.headers.get("location") == "/drin" and ce.get("/drin").status_code == 200,
        f"HTTP {_ziel.status_code} {_ziel.headers.get('location')}")
r.check("(e) N1: the login page does not offer the PIN, the guest path stays closed (pin_login=False)",
        "/auth/pin" not in TestClient(app_e).get("/auth/login").text
        and _pin(TestClient(app_e), PIN, username="ohnelogin").status_code == 404)

# ── (f) N2: strict chain password → pin — the guest path is closed, no oracle without a password ─
auth_f, app_f, _ = _app(login_chain=["password", "pin"])
_konto(auth_f, "orakel")
_falsch_f = _pin(TestClient(app_f), "0000", username="orakel")
_richtig_f = _pin(TestClient(app_f), PIN, username="orakel")
_zeilen_f = auth_f.store._one("SELECT COUNT(*) AS n FROM login_attempt")["n"]
# (Mutation probe: in `login_pin` again `cfg.pin_login` instead of `pin_as_first_factor()` → 401/303 → red.)
r.check("(f) N2: guest PIN without password → 404, wrong or correct, and no row in login_attempt",
        _falsch_f.status_code == 404 and _richtig_f.status_code == 404 and _zeilen_f == 0,
        f"falsch {_falsch_f.status_code}, richtig {_richtig_f.status_code}, Zeilen {_zeilen_f}")
_login_f = TestClient(app_f).get("/auth/login").text
_get_f = TestClient(app_f).get("/auth/pin", headers=HTML, follow_redirects=False)
# (Mutation probe: `enabled_methods` again with `pin_login` → PIN field on the login page → red.)
r.check("(f) N2: the login page has no PIN field, GET /auth/pin redirects guests to the sign-in",
        "/auth/pin" not in _login_f and "name=password" in _login_f and _get_f.status_code == 303
        and _get_f.headers.get("location", "").startswith("/auth/login"), f"GET {_get_f.status_code}")
auth_f2, app_f2, _ = _app(login_chain=["pin", "password"])
_konto(auth_f2, "vorne")
cf2 = TestClient(app_f2)
_erst = _pin(cf2, PIN, username="vorne")
_dann = _passwort(cf2, "vorne")
r.check("(f) chain pin → password (strict): the guest path stays open, the PIN is the first factor there",
        "/auth/pin" in TestClient(app_f2).get("/auth/login").text and _erst.status_code == 303
        and _dann.headers.get("location") == "/drin" and cf2.get("/drin").status_code == 200,
        f"PIN {_erst.status_code}, Passwort {_dann.headers.get('location')}")
auth_f3, app_f3, _ = _app(login_chain=["password", "pin"], login_chain_strict=False)
_konto(auth_f3, "locker")
r.check("(f) not strict (password, pin): the PIN stays first factor with pin_login (config check warns)",
        "/auth/pin" in TestClient(app_f3).get("/auth/login").text
        and _pin(TestClient(app_f3), PIN, username="locker").status_code == 303)

# ── (h) Identity switch: half session A, form names B ─────────────────────────────────────────
auth_h, app_h, _ = _app(login_chain=["password", "pin"], login_chain_strict=False)
_konto(auth_h, "anna")
uid_hb = _konto(auth_h, "bert")
ch = TestClient(app_h)
_passwort(ch, "anna")
_halb_a = ch.cookies.get(auth_h.cfg.session_cookie)
_fehl_h = _pin(ch, "0000", username="bert")
_wechsel = _pin(ch, PIN, username="bert")
_neu = auth_h.store.get_session(ch.cookies.get(auth_h.cfg.session_cookie))
r.check("(h) guest door open: the PIN of B with half session A is an identity switch (new session B, "
        "slips booked as first factor)",
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
r.check("(h) guest door closed (strict chain): 404, the half session A stays as it was",
        _zu.status_code == 404 and ch2.cookies.get(auth_h2.cfg.session_cookie) == _halb_a2
        and _s_h2 is not None and _s_h2["user_id"] == uid_ha2 and not _s_h2["mfa_ok"],
        f"HTTP {_zu.status_code}")

# ── (i) Configuration check: warning exactly for not strict + PIN last + pin_login ─────────────
def _warnt(**cfg):
    _, warnungen = config_check.check_config(TinySesamConfig(db_path=":memory:", **{"pin_enabled": True, **cfg}))
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
r.check("(i) the configuration check warns exactly for a non-strict chain with PIN last and pin_login",
        all(_ist[name] is soll for name, (_, soll) in _faelle.items()), str(_ist))

# ── (j) p2 F1: the half session checks the PIN only if it is its chain step ───────────────────
# Until 2026-09-27 any half session sufficed. In classic mode with pin_login=False that was an
# oracle for anyone with the password (on 0.20.x: 404); in a strict chain password → totp → pin
# the PIN stood in the session before the TOTP, which then never became full.
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
r.check("(j) case 1 classic, pin_login=False, account with TOTP: the half session (next step TOTP) "
        "gets 404 for wrong and correct PIN, without a row in series and login_attempt",
        _start_j.headers.get("location", "").startswith("/auth/totp")
        and _falsch_j.status_code == 404 and _richtig_j.status_code == 404
        and FOLGE not in _arten(auth_j, "klassik") and _pin_zeilen(auth_j) == 0,
        f"falsch {_falsch_j.status_code}, richtig {_richtig_j.status_code}, {_arten(auth_j, 'klassik')}, "
        f"Zeilen {_pin_zeilen(auth_j)}")
# (Mutation probe: in `pin_page` again `self.pending_user(request)` → 200 with PIN form → red.)
r.check("(j) case 1: GET /auth/pin shows the half session no PIN form but redirects to the sign-in",
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
# (Mutation probe: remove the condition "next step" in `_pin_kettenschritt` → 401/303 before
#  the TOTP, afterwards /drin 401 → red.)
r.check("(j) case 2 strict password → totp → pin: before the TOTP 404 (wrong as well as correct, no row); "
        "after the TOTP the PIN makes the session full (/drin 200)",
        _vor_totp == (404, 404) and _zeilen_vor == 0
        and _nach_totp.headers.get("location", "").startswith("/auth/pin")
        and _pin_j2.status_code == 303 and _pin_j2.headers.get("location") == "/drin"
        and cj2.get("/drin").status_code == 200,
        f"before TOTP {_vor_totp}, Zeilen {_zeilen_vor}, TOTP → {_nach_totp.headers.get('location')}, "
        f"PIN {_pin_j2.status_code} {_pin_j2.headers.get('location')}")
_zweit_j2 = _pin(cj2, "0000")
r.check("(j) … and with a full session /auth/pin is the route factor again (no 404)",
        _zweit_j2.status_code == 401, f"HTTP {_zweit_j2.status_code}")

auth_j3, app_j3, _ = _app(login_chain=["password", "totp", "pin"], login_chain_strict=False, pin_login=False)
_, _geheim_j3 = _mit_totp(auth_j3, "locker")
cj3 = TestClient(app_j3)
_passwort(cj3, "locker")
_pin_j3 = _pin(cj3, PIN)
_totp_j3 = cj3.post("/auth/totp", data={"code": _pyotp.TOTP(_geheim_j3).now(), "next": "/drin"},
                    follow_redirects=False)
# (Mutation probe: ignore `strict` in `_pin_kettenschritt` → 404 → red.)
r.check("(j) not strict password → totp → pin: the PIN before the TOTP stays allowed, afterwards the session is full",
        _pin_j3.status_code == 303 and _pin_j3.headers.get("location", "").startswith("/auth/totp")
        and _totp_j3.headers.get("location") == "/drin" and cj3.get("/drin").status_code == 200,
        f"PIN {_pin_j3.status_code} {_pin_j3.headers.get('location')}, TOTP {_totp_j3.headers.get('location')}")
_doppelt = TestClient(app_j3)
_passwort(_doppelt, "locker")
_pin(_doppelt, PIN)
_wieder = _pin(_doppelt, "0000")
# (Mutationsprobe: `"pin" in done` in `_pin_kettenschritt` streichen → 401 → rot.)
r.check("(j) not strict: if the PIN of the half session has already been provided, /auth/pin checks no further one (404)",
        _wieder.status_code == 404, f"HTTP {_wieder.status_code}")

# ── The account page keeps its PIN section where the login page no longer offers the PIN ────
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
# (Mutation probe: in `account_page` again `methods=cfg.enabled_methods()` → first check red.)
r.check("account page: PIN section under strict chain password → pin (also with pin_login=False), "
        "without chain with pin_login=False still not",
        "data-act=setpin" in ck.get("/auth/account").text and "data-act=setpin" in ck2.get("/auth/account").text
        and "data-act=setpin" not in ck3.get("/auth/account").text)

# ── Lockout notice: for the series the mail also names the operator ─────────────────────────
auth_m, app_m, post_m = _app()
auth_m.create_user("hinweis", password=PW, email="hinweis@example.com")
for _ in range(10):
    _passwort(TestClient(app_m), "hinweis", f"falsch-falsch-1-{next(_FALSCH)}")
_passwort(TestClient(app_m), "hinweis")
auth_m._hinweis_ausgang.abwarten()
_text_m = post_m[0][2] if post_m else ""
r.check("lockout notice for the series: “until you reset your password or the operator releases it”",
        "oder der Betreiber sie freigibt" in _text_m, _text_m[:200])

# ── Review round 2026-09-27: the way out of the series depending on the kind ──────────────────
# The self-service reset does not clear TOTP and the PIN in the chain step (G7). If the series
# stood at the limit from such slips alone, the lockout notice and security log still named the
# reset as the way out — the owner reset the password and stayed locked. The sign-in page
# shows everyone the same text: it must not reveal that under an identifier someone is guessing at the second
# factor (and that the account therefore exists).
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
    """(page of the next sign-in, lockout notice, log line) after a series of kind `art`."""
    kette = ["password", "pin"] if art == FOLGE else None
    auth_x, app_x, post_x = _app(**({"login_chain": kette} if kette else {}))
    uid_x = _konto(auth_x, "ausweg")
    name = auth_x.get_user(uid_x)["username"]
    with _Log() as log_x:
        if art == "password":
            for _ in range(10):
                _passwort(TestClient(app_x), name, f"falsch-falsch-{next(_FALSCH)}")
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
# (Mutation probe: `_serie_reset_hilft` always True → TOTP/pin_folge name the reset → red.)
r.check("lockout notice: for a series of TOTP or PIN in the chain step no reset as a way out, "
        "but the operator — for a password series still the reset",
        _reset_de in _aus["password"][1] and all(
            _reset_de not in _aus[a][1] and "bis der Betreiber sie freigibt" in _aus[a][1]
            and "Passwort-Reset hebt diese Sperre nicht auf" in _aus[a][1] for a in ("totp", FOLGE)),
        str({a: (v[3], v[1][:160]) for a, v in _aus.items()}))
r.check("security log: “Lifting: password reset, …” only for a password series",
        "Aufheben: Passwort-Reset," in _aus["password"][2]
        and all(_aus[a][2] and "Aufheben: Passwort-Reset" not in _aus[a][2] and "tinysesam unlock" in _aus[a][2]
                for a in ("totp", FOLGE)), str({a: v[2][-160:] for a, v in _aus.items()}))
# (Mutation probe: `err.locked_serie` again “reset the password or the operator …” → red.)
r.check("sign-in page: the same text for every kind (no oracle), it names the operator first and the "
        "reset only conditionally — German and English",
        all(v[0].status_code == 429 for v in _aus.values())
        and len({auth_m.t("err.locked_serie") in v[0].text for v in _aus.values()}) == 1
        and auth_m.t("err.locked_serie") in _aus["totp"][0].text
        and auth_m.t("err.locked_serie").startswith("Zu viele Fehlversuche in Folge — die Anmeldung ist gesperrt. "
                                                    "Den Betreiber um Freigabe bitten")
        and "Ask the operator to unlock it; if the failed attempts were password attempts"
        in TinySesam(TinySesamConfig(db_path=":memory:", lang="en")).t("err.locked_serie"),
        str([v[0].status_code for v in _aus.values()]))

sys.exit(r.done())
