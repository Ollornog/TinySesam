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
(`_pin_chain_step`, block j), and the way out of the series depends on its kind (last block).
"""
from __future__ import annotations

import itertools as _itertools
import io
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
_WRONG = _itertools.count()   # always NEW wrong passwords: a repetition has counted only once since 0.24.9

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import config_check  # noqa: E402
from tinysesam.__main__ import main as _cli  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("G7 — PIN as first or follow-up factor (series, chain step, guest path)")
PW = "Folge-Pin-Pw-15"          # 15 characters: the password may sign in on its own here (B2-4)
NEW = "Neues-Pw-G7-123"
PIN = "4711"
SEQUENCE = TinySesam._PIN_CHAIN_SERIES
HTML = {"Accept": "text/html"}


def _app(**cfg):
    mails: list = []
    reason = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 base_url="http://testserver", lang="de", passkey_enabled=False, pin_enabled=True)
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000), ("pin_max_attempts", 100),
                 ("account_max_consecutive_failures", 10)):
        auth.set_security(k, v)
    auth.set_mailer(lambda to, subject, text, html=None: mails.append((to, subject, text)))
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/drin")
    def _inside(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    @app.get("/pinbereich")
    def _pin_area(u=Depends(auth.require(factors=["password", "pin"]))):
        return {"u": u["username"]}

    return auth, app, mails


def _account(auth, name, email=None):
    uid = auth.create_user(name, password=PW, email=email or f"{name}@example.com")
    auth.set_pin(uid, PIN)
    return uid


def _password(client, name, pw=PW):
    return client.post("/auth/login", data={"username": name, "password": pw, "next": "/drin"},
                       follow_redirects=False)


def _pin(client, pin, **extra):
    return client.post("/auth/pin", data={"pin": pin, "next": "/drin", **extra}, follow_redirects=False)


def _kinds(auth, identifier):
    return {z["kind"]: z["count"] for z in auth.store._all("SELECT kind, count FROM failure_series WHERE folded=?",
                                                            (identifier,)) if z["count"]}


def _unlock(auth, identifier):
    code = 0
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        try:
            _cli(["unlock", "--db", auth.cfg.db_path, identifier])
        except SystemExit as e:        # otherwise the test would end here with exit 0 (skip is not green)
            code = e.code or 0
    return code


# ── (a) Chain step after the password: slips of kind `pin_folge`, the reset does not clear them ──
auth, app, _ = _app(login_chain=["password", "pin"], password_reset_enabled=True)
uid = _account(auth, "kette")
c = TestClient(app)
_after_pw = _password(c, "kette")
for i in range(5):
    _pin(c, f"000{i}")
r.check("(a) after the password the chain leads to /auth/pin; five wrong PINs in the chain step "
        "book under pin_folge, not under pin",
        _after_pw.headers.get("location", "").startswith("/auth/pin") and _kinds(auth, "kette") == {SEQUENCE: 5},
        f"{_after_pw.headers.get('location')}, {_kinds(auth, 'kette')}")
# (Mutation probe: omit `series_kind` in `login_pin` → {'pin': 5}, the reset clears → red.)
auth.lift_lockout(uid, methods=("password",))                  # the path of the self-service reset
r.check("(a) the self-service reset (lift_lockout with password) leaves them standing, like TOTP",
        auth.store.failure_series("kette") == 5, str(_kinds(auth, "kette")))
_tok = auth.create_magic_token("reset_password", user_id=uid, email="kette@example.com")
_reset = TestClient(app).post("/auth/reset", data={"token": _tok, "password": NEW}, follow_redirects=False)
r.check("(a) … also via the real POST /auth/reset",
        _reset.status_code == 303 and auth.store.failure_series("kette") == 5 and auth._check_password("kette", NEW),
        f"HTTP {_reset.status_code}, {_kinds(auth, 'kette')}")
# Custom PIN pages often send the name along — even with the address of the own account it remains the
# chain step of the half session (before: the guest path, booked as first factor).
c = TestClient(app)
_password(c, "kette", NEW)
_pin(c, "0009", username="kette@example.com")
_pin(c, "0008", username="kette")
r.check("(a) with name or address of the own account in the form it remains the chain step",
        _kinds(auth, "kette") == {SEQUENCE: 7}, str(_kinds(auth, "kette")))

# ── (b) R2-2 stays: a guest PIN (first factor) is cleared by the reset ─────────────────────────
auth_b, app_b, _ = _app()
uid_b = _account(auth_b, "gast")
for i in range(5):
    _pin(TestClient(app_b), f"000{i}", username="gast")
_before_b = _kinds(auth_b, "gast")
auth_b.lift_lockout(uid_b, methods=("password",))
# (Mutation probe: 'pin' from `_SERIES_RESET_KINDS` → 5 remain → red.)
r.check("(b) R2-2: slips via the guest path book under pin, and the reset clears them",
        _before_b == {"pin": 5} and auth_b.store.failure_series("gast") == 0,
        f"{_before_b} → {_kinds(auth_b, 'gast')}")

# ── (c) full sign-in, panel reset and `tinysesam unlock` also clear `pin_folge` ─────────────────
auth_c, app_c, _ = _app(login_chain=["password", "pin"])
uid_c = _account(auth_c, "voll")
cc = TestClient(app_c)
_password(cc, "voll")
for i in range(4):
    _pin(cc, f"000{i}")
_before_c = _kinds(auth_c, "voll")
_done = _pin(cc, PIN)
# (Mutation probe: in `lift_lockout` without `methods` clear only `_SERIES_RESET_KINDS` → 4 → red.)
r.check("(c) the full sign-in (correct PIN in the chain step) ends the series completely",
        _before_c == {SEQUENCE: 4} and _done.headers.get("location") == "/drin"
        and cc.get("/drin").status_code == 200 and auth_c.store.failure_series("voll") == 0,
        f"{_before_c}, {_done.headers.get('location')}, {_kinds(auth_c, 'voll')}")
auth_c.create_user("chefin", password=PW, is_admin=True)
auth_c.set_pin(auth_c.store.get_user_by_name("chefin")["id"], PIN)
ca = TestClient(app_c)
_password(ca, "chefin")
_pin(ca, PIN)
cv = TestClient(app_c)
_password(cv, "voll")
for i in range(4):
    _pin(cv, f"000{i}")
_panel = ca.post(f"/auth/admin/api/users/{uid_c}/password", json={"password": NEW})
# (Mutation probe: `_end_series` clears only `_SERIES_RESET_KINDS` → red.)
r.check("(c) the password reset in the panel clears pin_folge (the operator decides)",
        _panel.status_code == 200 and auth_c.store.failure_series("voll") == 0,
        f"HTTP {_panel.status_code}, {_kinds(auth_c, 'voll')}")
cv = TestClient(app_c)
_password(cv, "voll", NEW)
for i in range(4):
    _pin(cv, f"000{i}")
_before_u = auth_c.store.failure_series("voll")
_rc = _unlock(auth_c, "voll")
# (Mutation probe: `unlock` clears the series only with `kinds=("password", "pin")` → red.)
r.check("(c) `tinysesam unlock` clears pin_folge", _before_u == 4 and _rc == 0 and auth_c.store.failure_series("voll") == 0,
        f"{_before_u}, rc {_rc}, {_kinds(auth_c, 'voll')}")

# ── (d)+(g) Route chain with full session; a correct PIN withdraws only its own pre-booking ────
auth_d, app_d, _ = _app()                                          # classic: password = full session
uid_d = _account(auth_d, "route")
cd = TestClient(app_d)
_password(cd, "route")
_detour = cd.get("/pinbereich", headers=HTML, follow_redirects=False)
for i in range(3):
    _pin(cd, f"000{i}")
_after_wrong = _kinds(auth_d, "route")
_correct = _pin(cd, PIN)
r.check("(d) route chain factors=[password, pin] with full session: the slips book under pin_folge",
        _detour.headers.get("location", "").startswith("/auth/pin") and _after_wrong == {SEQUENCE: 3},
        f"{_detour.headers.get('location')}, {_after_wrong}")
# (Mutation probe: the pre-booking remembers `method` instead of `series[1]` → lowering hits the kind pin,
#  the pre-booking under `pin_folge` remains → 4 → red.)
r.check("(g) a correct PIN withdraws its pre-booking under pin_folge — the series before it remains",
        _correct.status_code == 303 and cd.get("/pinbereich").status_code == 200
        and _kinds(auth_d, "route") == {SEQUENCE: 3}, f"HTTP {_correct.status_code}, {_kinds(auth_d, 'route')}")

# ── (e) N1: pin_login=False with chain password → pin is no longer a dead end ────────────────
auth_e, app_e, _ = _app(login_chain=["password", "pin"], pin_login=False)
_account(auth_e, "ohnelogin")
ce = TestClient(app_e)
_start = _password(ce, "ohnelogin")
_page_html = ce.get("/auth/pin?next=/drin", headers=HTML, follow_redirects=False)
# (Mutation probe: in `pin_page` do not read the half session → 303 back to the sign-in → red.)
r.check("(e) N1: after the password GET /auth/pin shows the PIN form — without name field",
        _start.headers.get("location", "").startswith("/auth/pin") and _page_html.status_code == 200
        and "name=pin" in _page_html.text and "name=username" not in _page_html.text,
        f"HTTP {_page_html.status_code} {_page_html.headers.get('location')}")
_destination = _pin(ce, PIN)
# (Mutation probe: in `login_pin` `half = None` → 404 → red.)
r.check("(e) N1: … and the correct PIN makes the session full (/drin 200)",
        _destination.status_code == 303 and _destination.headers.get("location") == "/drin" and ce.get("/drin").status_code == 200,
        f"HTTP {_destination.status_code} {_destination.headers.get('location')}")
r.check("(e) N1: the login page does not offer the PIN, the guest path stays closed (pin_login=False)",
        "/auth/pin" not in TestClient(app_e).get("/auth/login").text
        and _pin(TestClient(app_e), PIN, username="ohnelogin").status_code == 404)

# ── (f) N2: strict chain password → pin — the guest path is closed, no oracle without a password ─
auth_f, app_f, _ = _app(login_chain=["password", "pin"])
_account(auth_f, "orakel")
_wrong_f = _pin(TestClient(app_f), "0000", username="orakel")
_correct_f = _pin(TestClient(app_f), PIN, username="orakel")
_lines_f = auth_f.store._one("SELECT COUNT(*) AS n FROM login_attempt")["n"]
# (Mutation probe: in `login_pin` again `cfg.pin_login` instead of `pin_as_first_factor()` → 401/303 → red.)
r.check("(f) N2: guest PIN without password → 404, wrong or correct, and no row in login_attempt",
        _wrong_f.status_code == 404 and _correct_f.status_code == 404 and _lines_f == 0,
        f"wrong {_wrong_f.status_code}, correct {_correct_f.status_code}, rows {_lines_f}")
_login_f = TestClient(app_f).get("/auth/login").text
_get_f = TestClient(app_f).get("/auth/pin", headers=HTML, follow_redirects=False)
# (Mutation probe: `enabled_methods` again with `pin_login` → PIN field on the login page → red.)
r.check("(f) N2: the login page has no PIN field, GET /auth/pin redirects guests to the sign-in",
        "/auth/pin" not in _login_f and "name=password" in _login_f and _get_f.status_code == 303
        and _get_f.headers.get("location", "").startswith("/auth/login"), f"GET {_get_f.status_code}")
auth_f2, app_f2, _ = _app(login_chain=["pin", "password"])
_account(auth_f2, "vorne")
cf2 = TestClient(app_f2)
_first = _pin(cf2, PIN, username="vorne")
_then = _password(cf2, "vorne")
r.check("(f) chain pin → password (strict): the guest path stays open, the PIN is the first factor there",
        "/auth/pin" in TestClient(app_f2).get("/auth/login").text and _first.status_code == 303
        and _then.headers.get("location") == "/drin" and cf2.get("/drin").status_code == 200,
        f"PIN {_first.status_code}, password {_then.headers.get('location')}")
auth_f3, app_f3, _ = _app(login_chain=["password", "pin"], login_chain_strict=False)
_account(auth_f3, "locker")
r.check("(f) not strict (password, pin): the PIN stays first factor with pin_login (config check warns)",
        "/auth/pin" in TestClient(app_f3).get("/auth/login").text
        and _pin(TestClient(app_f3), PIN, username="locker").status_code == 303)

# ── (h) Identity switch: half session A, form names B ─────────────────────────────────────────
auth_h, app_h, _ = _app(login_chain=["password", "pin"], login_chain_strict=False)
_account(auth_h, "anna")
uid_hb = _account(auth_h, "bert")
ch = TestClient(app_h)
_password(ch, "anna")
_half_a = ch.cookies.get(auth_h.cfg.session_cookie)
_fail_h = _pin(ch, "0000", username="bert")
_change = _pin(ch, PIN, username="bert")
_new = auth_h.store.get_session(ch.cookies.get(auth_h.cfg.session_cookie))
r.check("(h) guest door open: the PIN of B with half session A is an identity switch (new session B, "
        "slips booked as first factor)",
        _fail_h.status_code == 401 and _change.status_code == 303
        and ch.cookies.get(auth_h.cfg.session_cookie) != _half_a
        and _new is not None and _new["user_id"] == uid_hb and _kinds(auth_h, "bert") == {"pin": 1}
        and _kinds(auth_h, "anna") == {}, f"HTTP {_fail_h.status_code}/{_change.status_code}, "
        f"{dict(_new) if _new else None}, {_kinds(auth_h, 'bert')}, {_kinds(auth_h, 'anna')}")
auth_h2, app_h2, _ = _app(login_chain=["password", "pin"])
uid_ha2 = _account(auth_h2, "anna")
_account(auth_h2, "bert")
ch2 = TestClient(app_h2)
_password(ch2, "anna")
_half_a2 = ch2.cookies.get(auth_h2.cfg.session_cookie)
_to = _pin(ch2, PIN, username="bert")
_s_h2 = auth_h2.store.get_session(_half_a2)
r.check("(h) guest door closed (strict chain): 404, the half session A stays as it was",
        _to.status_code == 404 and ch2.cookies.get(auth_h2.cfg.session_cookie) == _half_a2
        and _s_h2 is not None and _s_h2["user_id"] == uid_ha2 and not _s_h2["mfa_ok"],
        f"HTTP {_to.status_code}")

# ── (i) Configuration check: warning exactly for not strict + PIN last + pin_login ─────────────
def _warns(**cfg):
    _, warnings = config_check.check_config(TinySesamConfig(db_path=":memory:", **{"pin_enabled": True, **cfg}))
    return any("follow-up factor" in w and "pin_login=False" in w for w in warnings)


_cases = {
    "nicht strikt, password → pin, pin_login": (dict(login_chain=["password", "pin"], login_chain_strict=False), True),
    "strikt, password → pin": (dict(login_chain=["password", "pin"]), False),
    "nicht strikt, pin_login=False": (dict(login_chain=["password", "pin"], login_chain_strict=False,
                                           pin_login=False), False),
    "nicht strikt, pin vorne": (dict(login_chain=["pin", "password"], login_chain_strict=False), False),
    "ohne Kette": (dict(), False),
    "nicht strikt, PIN aus": (dict(login_chain=["password", "pin"], login_chain_strict=False,
                                   pin_enabled=False), False),
}
_is = {name: _warns(**cfg) for name, (cfg, _) in _cases.items()}
r.check("(i) the configuration check warns exactly for a non-strict chain with PIN last and pin_login",
        all(_is[name] is should for name, (_, should) in _cases.items()), str(_is))

# ── (j) p2 F1: the half session checks the PIN only if it is its chain step ───────────────────
# Until 2026-09-27 any half session sufficed. In classic mode with pin_login=False that was an
# oracle for anyone with the password (on 0.20.x: 404); in a strict chain password → totp → pin
# the PIN stood in the session before the TOTP, which then never became full.
import time as _when  # noqa: E402

import pyotp as _pyotp  # noqa: E402


def _with_totp(auth, name):
    uid = _account(auth, name)
    secret_text = auth.totp_begin(uid)["secret"]
    auth.totp_confirm(uid, _pyotp.TOTP(secret_text).at(_when.time() - 30))
    return uid, secret_text


def _pin_lines(auth):
    return auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE method='pin'")["n"]


auth_j, app_j, _ = _app(pin_login=False)
_with_totp(auth_j, "klassik")
cj = TestClient(app_j)
_start_j = _password(cj, "klassik")
_wrong_j, _correct_j = _pin(cj, "0000"), _pin(cj, PIN)
_get_j = cj.get("/auth/pin?next=/drin", headers=HTML, follow_redirects=False)
# (Mutation probe: in `login_pin` restore `self.pending_user(request)` → 401/303 → red.)
r.check("(j) case 1 classic, pin_login=False, account with TOTP: the half session (next step TOTP) "
        "gets 404 for wrong and correct PIN, without a row in series and login_attempt",
        _start_j.headers.get("location", "").startswith("/auth/totp")
        and _wrong_j.status_code == 404 and _correct_j.status_code == 404
        and SEQUENCE not in _kinds(auth_j, "klassik") and _pin_lines(auth_j) == 0,
        f"wrong {_wrong_j.status_code}, correct {_correct_j.status_code}, {_kinds(auth_j, 'klassik')}, "
        f"rows {_pin_lines(auth_j)}")
# (Mutation probe: in `pin_page` again `self.pending_user(request)` → 200 with PIN form → red.)
r.check("(j) case 1: GET /auth/pin shows the half session no PIN form but redirects to the sign-in",
        _get_j.status_code == 303 and _get_j.headers.get("location", "").startswith("/auth/login"),
        f"GET {_get_j.status_code} {_get_j.headers.get('location')}")

auth_j2, app_j2, _ = _app(login_chain=["password", "totp", "pin"])
_, _secret_text_j2 = _with_totp(auth_j2, "strikt")
cj2 = TestClient(app_j2)
_password(cj2, "strikt")
_prior_totp = (_pin(cj2, "0000").status_code, _pin(cj2, PIN).status_code)
_lines_prior = _pin_lines(auth_j2)
_after_totp = cj2.post("/auth/totp", data={"code": _pyotp.TOTP(_secret_text_j2).now(), "next": "/drin"},
                      follow_redirects=False)
_pin_j2 = _pin(cj2, PIN)
# (Mutation probe: remove the condition "next step" in `_pin_chain_step` → 401/303 before
#  the TOTP, afterwards `/drin` 401 → red.)
r.check("(j) case 2 strict password → totp → pin: before the TOTP 404 (wrong as well as correct, no row); "
        "after the TOTP the PIN makes the session full (/drin 200)",
        _prior_totp == (404, 404) and _lines_prior == 0
        and _after_totp.headers.get("location", "").startswith("/auth/pin")
        and _pin_j2.status_code == 303 and _pin_j2.headers.get("location") == "/drin"
        and cj2.get("/drin").status_code == 200,
        f"before TOTP {_prior_totp}, rows {_lines_prior}, TOTP → {_after_totp.headers.get('location')}, "
        f"PIN {_pin_j2.status_code} {_pin_j2.headers.get('location')}")
_second_j2 = _pin(cj2, "0000")
r.check("(j) … and with a full session /auth/pin is the route factor again (no 404)",
        _second_j2.status_code == 401, f"HTTP {_second_j2.status_code}")

auth_j3, app_j3, _ = _app(login_chain=["password", "totp", "pin"], login_chain_strict=False, pin_login=False)
_, _secret_text_j3 = _with_totp(auth_j3, "locker")
cj3 = TestClient(app_j3)
_password(cj3, "locker")
_pin_j3 = _pin(cj3, PIN)
_totp_j3 = cj3.post("/auth/totp", data={"code": _pyotp.TOTP(_secret_text_j3).now(), "next": "/drin"},
                    follow_redirects=False)
# (Mutation probe: ignore `strict` in `_pin_chain_step` → 404 → red.)
r.check("(j) not strict password → totp → pin: the PIN before the TOTP stays allowed, afterwards the session is full",
        _pin_j3.status_code == 303 and _pin_j3.headers.get("location", "").startswith("/auth/totp")
        and _totp_j3.headers.get("location") == "/drin" and cj3.get("/drin").status_code == 200,
        f"PIN {_pin_j3.status_code} {_pin_j3.headers.get('location')}, TOTP {_totp_j3.headers.get('location')}")
_double = TestClient(app_j3)
_password(_double, "locker")
_pin(_double, PIN)
_again = _pin(_double, "0000")
# (Mutation probe: remove `"pin" in done` in `_pin_chain_step` → 401 → red.)
r.check("(j) not strict: if the PIN of the half session has already been provided, /auth/pin checks no further one (404)",
        _again.status_code == 404, f"HTTP {_again.status_code}")

# ── The account page keeps its PIN section where the login page no longer offers the PIN ────
auth_k, app_k, _ = _app(login_chain=["password", "pin"])
_account(auth_k, "konto")
ck = TestClient(app_k)
_password(ck, "konto")
_pin(ck, PIN)
auth_k2, app_k2, _ = _app(login_chain=["password", "pin"], pin_login=False)
_account(auth_k2, "konto")
ck2 = TestClient(app_k2)
_password(ck2, "konto")
_pin(ck2, PIN)
auth_k3, app_k3, _ = _app(pin_login=False)
_account(auth_k3, "konto")
ck3 = TestClient(app_k3)
_password(ck3, "konto")
# (Mutation probe: in `account_page` again `methods=cfg.enabled_methods()` → first check red.)
r.check("account page: PIN section under strict chain password → pin (also with pin_login=False), "
        "without chain with pin_login=False still not",
        "data-act=setpin" in ck.get("/auth/account").text and "data-act=setpin" in ck2.get("/auth/account").text
        and "data-act=setpin" not in ck3.get("/auth/account").text)

# ── Lockout notice: for the series the mail also names the operator ─────────────────────────
auth_m, app_m, post_m = _app()
auth_m.create_user("hinweis", password=PW, email="hinweis@example.com")
for _ in range(10):
    _password(TestClient(app_m), "hinweis", f"falsch-falsch-1-{next(_WRONG)}")
_password(TestClient(app_m), "hinweis")
auth_m._notice_outcome.wait()
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
        self.buffer = io.StringIO()
        self.check = _logging.StreamHandler(self.buffer)
        _seclog.addHandler(self.check)
        return self

    def __exit__(self, *_):
        _seclog.removeHandler(self.check)

    def locked(self):
        return [z for z in self.buffer.getvalue().splitlines() if "locked:" in z]


def _series_way_out(kind):
    """(page of the next sign-in, lockout notice, log line) after a series of kind `art`."""
    chain = ["password", "pin"] if kind == SEQUENCE else None
    auth_x, app_x, post_x = _app(**({"login_chain": chain} if chain else {}))
    uid_x = _account(auth_x, "ausweg")
    name = auth_x.get_user(uid_x)["username"]
    with _Log() as log_x:
        if kind == "password":
            for _ in range(10):
                _password(TestClient(app_x), name, f"falsch-falsch-{next(_WRONG)}")
        elif kind == "totp":
            secret_text = auth_x.totp_begin(uid_x)["secret"]
            auth_x.totp_confirm(uid_x, _pyotp.TOTP(secret_text).at(_when.time() - 30))
            cx = TestClient(app_x)
            _password(cx, name)
            for i in range(10):
                cx.post("/auth/totp", data={"code": f"00000{i}", "next": "/drin"}, follow_redirects=False)
        else:
            cx = TestClient(app_x)
            _password(cx, name)
            for i in range(10):
                _pin(cx, f"000{i}")
        page_html = _password(TestClient(app_x), name)
        auth_x._notice_outcome.wait()
    return page_html, (post_x[0][2] if post_x else ""), (log_x.locked() or [""])[0], _kinds(auth_x, name)


_out = {kind: _series_way_out(kind) for kind in ("password", "totp", SEQUENCE)}
_reset_de = "bis du dein Passwort zurücksetzt"
# (Mutation probe: `_series_reset_helps` always True → TOTP/`pin_folge` name the reset → red.)
r.check("lockout notice: for a series of TOTP or PIN in the chain step no reset as a way out, "
        "but the operator — for a password series still the reset",
        _reset_de in _out["password"][1] and all(
            _reset_de not in _out[a][1] and "bis der Betreiber sie freigibt" in _out[a][1]
            and "Passwort-Reset hebt diese Sperre nicht auf" in _out[a][1] for a in ("totp", SEQUENCE)),
        str({a: (v[3], v[1][:160]) for a, v in _out.items()}))
r.check("security log: “Lift: password reset, …” only for a password series",
        "Lift: password reset," in _out["password"][2]
        and all(_out[a][2] and "Lift: password reset" not in _out[a][2] and "tinysesam unlock" in _out[a][2]
                for a in ("totp", SEQUENCE)), str({a: v[2][-160:] for a, v in _out.items()}))
# (Mutation probe: `err.locked_series` again “reset the password or the operator …” → red.)
r.check("sign-in page: the same text for every kind (no oracle), it names the operator first and the "
        "reset only conditionally — German and English",
        all(v[0].status_code == 429 for v in _out.values())
        and len({auth_m.t("err.locked_series") in v[0].text for v in _out.values()}) == 1
        and auth_m.t("err.locked_series") in _out["totp"][0].text
        and auth_m.t("err.locked_series").startswith("Zu viele Fehlversuche in Folge — die Anmeldung ist gesperrt. "
                                                    "Den Betreiber um Freigabe bitten")
        and "Ask the operator to unlock it; if the failed attempts were password attempts"
        in TinySesam(TinySesamConfig(db_path=":memory:", lang="en")).t("err.locked_series"),
        str([v[0].status_code for v in _out.values()]))

sys.exit(r.done())
